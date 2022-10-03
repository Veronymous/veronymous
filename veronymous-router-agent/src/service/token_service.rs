use crate::service::grpc::token_service::veronymous_token_info_service_client::VeronymousTokenInfoServiceClient;
use crate::service::grpc::token_service::TokenInfo as RpcTokenInfo;
use crate::service::grpc::token_service::TokenInfoRequest;
use crate::{AgentError, VeronymousAgentConfig};
use ps_signatures::keys::{PsParams, PsPublicKey};
use ps_signatures::serde::Serializable;
use std::fs;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;
use tonic::transport::{Channel, Endpoint};
use veronymous_token::token::{get_current_epoch, get_now_u64};

const UPDATE_INTERVAL: u64 = 3;

// Use rwlock?
pub struct TokenService {
    client: VeronymousTokenInfoServiceClient<Channel>,

    current_token_info: Option<TokenInfo>,

    next_token_info: Option<TokenInfo>,

    current_epoch: Option<u64>,
}

impl TokenService {
    pub async fn create(config: &VeronymousAgentConfig) -> Result<Self, AgentError> {
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
                    "Could not connect to token service. {:?}",
                    e
                ))
            })?;

        let mut service = Self {
            client,
            current_token_info: None,
            next_token_info: None,
            current_epoch: None,
        };

        service.load_token_info().await?;

        Ok(service)
    }

    pub fn get_token_params(&self) -> (PsParams, PsPublicKey, u64) {
        let token_info = self.current_token_info.as_ref().unwrap().clone();

        (
            token_info.params,
            token_info.public_key,
            self.current_epoch.as_ref().unwrap().clone(),
        )
    }

    pub fn get_current_token_info(&self) -> TokenInfo {
        self.current_token_info.as_ref().unwrap().clone()
    }

    async fn load_token_info(&mut self) -> Result<(), AgentError> {
        info!("Loading token info...");

        let current_token_info = self.fetch_token_info().await?;
        let next_token_info = self.fetch_next_token_info().await?;

        self.current_epoch = Some(get_current_epoch(
            get_now_u64(),
            current_token_info.key_lifetime * 60,
            0,
        ));
        self.current_token_info = Some(current_token_info);
        self.next_token_info = Some(next_token_info);

        Ok(())
    }

    // Get the next update
    pub async fn update_token_info(&mut self) -> Result<(), AgentError> {
        info!("Updating token info...");

        loop {
            info!("Fetching token info update...");

            let current_token_info = match self.fetch_token_info().await {
                Ok(token_info) => token_info,
                Err(e) => {
                    error!("Could not fetch token info. {:?}", e);

                    // Sleep for 3 seconds and try again
                    std::thread::sleep(Duration::from_secs(UPDATE_INTERVAL));

                    continue;
                }
            };

            // Bad update if current token info hasn't changed
            if self.current_token_info.as_ref().unwrap().clone() == current_token_info {
                error!("Bad update. Will try again in {}s.", UPDATE_INTERVAL);

                // Sleep for 3 seconds and try again
                std::thread::sleep(Duration::from_secs(UPDATE_INTERVAL));

                continue;
            }

            // Set the current token info
            self.current_epoch = Some(get_current_epoch(
                get_now_u64(),
                current_token_info.key_lifetime * 60,
                0,
            ));
            self.current_token_info = Some(current_token_info);
            // Set the new next_token_info.
            self.next_token_info = Some(self.fetch_next_token_info().await.unwrap());

            break;
        }

        Ok(())
    }

    // Set current token info to next token info
    //self.current_token_info = self.next_token_info.clone();
    async fn fetch_token_info(&mut self) -> Result<TokenInfo, AgentError> {
        let request = TokenInfoRequest {};

        let rpc_token_info = self
            .client
            .get_token_info(tonic::Request::new(request))
            .await
            .map_err(|e| AgentError::ServiceError(format!("Could not get token info: {:?}", e)))?
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
            .map_err(|e| AgentError::ServiceError(format!("Could not get token info: {:?}", e)))?
            .into_inner();

        let token_info = rpc_token_info.try_into()?;

        Ok(token_info)
    }

    pub fn calculate_next_key_update(key_lifetime: u64) -> Instant {
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
            AgentError::DeserializationError(format!("Could not deserialize ps params. {:?}", e))
        })?;

        let public_key = PsPublicKey::deserialize(&token_info.public_key).map_err(|e| {
            AgentError::DeserializationError(format!(
                "Could not deserialize ps public key. {:?}",
                e
            ))
        })?;

        Ok(Self {
            params,
            public_key,
            key_lifetime: token_info.key_lifetime,
        })
    }
}
