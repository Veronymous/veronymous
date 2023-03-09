use crate::config::RouterAgentConfig;
use crate::error::AgentError;
use crate::error::AgentError::{DeserializationError, ServiceError};
use crate::token_issuer::grpc::token_service::veronymous_token_info_service_client::VeronymousTokenInfoServiceClient;
use crate::token_issuer::grpc::token_service::TokenInfo as RpcTokenInfo;
use crate::token_issuer::grpc::token_service::TokenInfoRequest;
use ps_signatures::keys::{PsParams, PsPublicKey};
use ps_signatures::serde::Serializable;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::Instant;
use tonic::transport::{Channel, Endpoint};
use veronymous_token::token::{get_current_epoch, get_now_u64};

const UPDATE_INTERVAL: u64 = 3;

pub struct TokenService {
    key_lifetime: u64,

    epoch_buffer: u64,

    client: VeronymousTokenInfoServiceClient<Channel>,

    current_token_info: Option<TokenInfo>,

    next_token_info: Option<TokenInfo>,

    current_epoch: Option<u64>,
}

impl TokenService {
    pub async fn create(
        config: &RouterAgentConfig,
    ) -> Result<Arc<RwLock<TokenService>>, AgentError> {
        // Tls config
        let ca = fs::read(&config.token_info_endpoint_ca).unwrap();
        let ca = tonic::transport::Certificate::from_pem(ca);

        // TLS authentication credentials
        let auth_cert = fs::read(&config.token_info_endpoint_auth_cert).unwrap();
        let auth_cert_key = fs::read(&config.token_info_endpoint_auth_key).unwrap();

        let auth_id = tonic::transport::Identity::from_pem(&auth_cert, &auth_cert_key);

        let tls_config = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(ca)
            .identity(auth_id);

        let endpoint = Endpoint::from_str(&config.token_info_endpoint)
            .unwrap()
            .tls_config(tls_config.clone())
            .unwrap();

        let client = VeronymousTokenInfoServiceClient::connect(endpoint)
            .await
            .map_err(|e| {
                AgentError::InitializationError(format!(
                    "Could not connect to token_issuer service. {:?}",
                    e
                ))
            })?;

        let mut service = Self {
            key_lifetime: config.key_lifetime,
            epoch_buffer: config.epoch_buffer,
            client,
            current_token_info: None,
            next_token_info: None,
            current_epoch: None,
        };

        service.load_token_info().await?;

        let service = Arc::new(RwLock::new(service));

        // Schedule token refresh
        Self::schedule_token_refresh(service.clone()).await;

        Ok(service)
    }

    pub fn get_token_params(&self) -> (PsParams, PsPublicKey, u64) {
        if self.is_in_buffer() {
            debug!("In the buffer, using next keys...");
            // Return next key
            let token_info = self.next_token_info.as_ref().unwrap().clone();

            (
                token_info.params,
                token_info.public_key,
                self.current_epoch.as_ref().unwrap().clone(),
            )
        } else {
            let token_info = self.current_token_info.as_ref().unwrap().clone();
            debug!("Not in buffer, using current keys...");

            (
                token_info.params,
                token_info.public_key,
                self.current_epoch.as_ref().unwrap().clone(),
            )
        }
    }

    // Check that in buffer at the end of key lifetime
    fn is_in_buffer(&self) -> bool {
        let now = get_now_u64();

        // Calculate time left in the epoch
        let remainder = now % self.key_lifetime;
        let time_left = self.key_lifetime - remainder;

        // If in the buffer
        self.epoch_buffer > time_left
    }

    fn get_current_token_info(&self) -> TokenInfo {
        self.current_token_info.as_ref().unwrap().clone()
    }

    async fn load_token_info(&mut self) -> Result<(), AgentError> {
        info!("Loading token_issuer info...");

        let current_token_info = self.fetch_token_info().await?;
        let next_token_info = self.fetch_next_token_info().await?;

        self.current_epoch = Some(get_current_epoch(
            get_now_u64(),
            current_token_info.key_lifetime,
            0,
        ));
        self.current_token_info = Some(current_token_info);
        self.next_token_info = Some(next_token_info);

        Ok(())
    }

    // Get the next update
    pub async fn update_token_info(&mut self) -> Result<(), AgentError> {
        info!("Updating token_issuer info...");

        loop {
            info!("Fetching token_issuer info update...");

            let current_token_info = match self.fetch_token_info().await {
                Ok(token_info) => token_info,
                Err(e) => {
                    error!("Could not fetch token_issuer info. {:?}", e);

                    // Sleep for 3 seconds and try again
                    std::thread::sleep(Duration::from_secs(UPDATE_INTERVAL));

                    continue;
                }
            };

            // Bad update if current token_issuer info hasn't changed
            if self.current_token_info.as_ref().unwrap().clone() == current_token_info {
                error!("Bad update. Will try again in {}s.", UPDATE_INTERVAL);

                // Sleep for 3 seconds and try again
                std::thread::sleep(Duration::from_secs(UPDATE_INTERVAL));

                continue;
            }

            // Set the current token_issuer info
            self.current_epoch = Some(get_current_epoch(
                get_now_u64(),
                current_token_info.key_lifetime,
                0,
            ));
            self.current_token_info = Some(current_token_info);
            // Set the new next_token_info.
            self.next_token_info = Some(self.fetch_next_token_info().await.unwrap());

            break;
        }

        Ok(())
    }

    // Set current token_issuer info to next token_issuer info
    //self.current_token_info = self.next_token_info.clone();
    async fn fetch_token_info(&mut self) -> Result<TokenInfo, AgentError> {
        let request = TokenInfoRequest {};

        let rpc_token_info = self
            .client
            .get_token_info(tonic::Request::new(request))
            .await
            .map_err(|e| ServiceError(format!("Could not get token_issuer info: {:?}", e)))?
            .into_inner();

        let token_info = rpc_token_info.try_into()?;

        Ok(token_info)
    }

    async fn fetch_next_token_info(&mut self) -> Result<TokenInfo, AgentError> {
        let request = TokenInfoRequest {};

        let rpc_token_info = self
            .client
            .get_next_token_info(tonic::Request::new(request))
            .await
            .map_err(|e| ServiceError(format!("Could not get token_issuer info: {:?}", e)))?
            .into_inner();

        let token_info = rpc_token_info.try_into()?;

        Ok(token_info)
    }

    fn calculate_next_key_update(key_lifetime: u64) -> Instant {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let now_instant = Instant::now();

        let current_epoch = now - (now % key_lifetime);
        let next_epoch = current_epoch + key_lifetime;

        // Get next epoch as instant
        let time_until_next_epoch = next_epoch - now;
        let next_epoch = now_instant + Duration::from_secs(time_until_next_epoch);

        next_epoch
    }

    async fn schedule_token_refresh(service: Arc<RwLock<TokenService>>) {
        info!("Scheduling token_issuer info refresh...");

        let service_lock = service.clone();
        let service_lock = service_lock.read().await;

        let token_info = service_lock.get_current_token_info();

        let key_lifetime = token_info.key_lifetime;

        let next_key_update = TokenService::calculate_next_key_update(key_lifetime);
        let key_lifetime = Duration::from_secs(key_lifetime);

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval_at(next_key_update, key_lifetime);

            loop {
                interval_timer.tick().await;

                let mut service_lock = service.write().await;

                service_lock.update_token_info().await.unwrap();
            }
        });
    }
}

#[derive(Clone, PartialEq)]
pub struct TokenInfo {
    pub params: PsParams,

    pub public_key: PsPublicKey,

    pub key_lifetime: u64,
}

impl TryFrom<RpcTokenInfo> for TokenInfo {
    type Error = AgentError;

    fn try_from(token_info: RpcTokenInfo) -> Result<Self, Self::Error> {
        let params = PsParams::deserialize(&token_info.params).map_err(|e| {
            DeserializationError(format!("Could not deserialize ps params. {:?}", e))
        })?;

        let public_key = PsPublicKey::deserialize(&token_info.public_key).map_err(|e| {
            DeserializationError(format!("Could not deserialize ps public key. {:?}", e))
        })?;

        Ok(Self {
            params,
            public_key,
            key_lifetime: token_info.key_lifetime,
        })
    }
}
