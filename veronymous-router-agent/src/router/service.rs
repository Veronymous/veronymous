use crate::config::RouterAgentConfig;
use crate::connections::service::ConnectionsService;
use crate::db::token_ids_db::redis::RedisTokenIDsDB;
use crate::db::token_ids_db::TokenIDsDB;
use crate::error::AgentError;
use crate::error::AgentError::Unauthorized;
use crate::token_issuer::service::TokenService;
use crate::wireguard::WGKey;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::RwLock;
use veronymous_token::token::{get_current_epoch, get_now_u64, VeronymousToken};

pub struct RouterService {
    epoch_length: u64,

    epoch_buffer: u64,

    token_domain: Vec<u8>,

    connections_service: Arc<RwLock<ConnectionsService>>,

    token_service: Arc<RwLock<TokenService>>,

    token_ids_db: RedisTokenIDsDB,
}

impl RouterService {
    pub fn new(
        config: &RouterAgentConfig,
        connections_service: Arc<RwLock<ConnectionsService>>,
        token_service: Arc<RwLock<TokenService>>,
        token_ids_db: RedisTokenIDsDB,
    ) -> Self {
        Self {
            epoch_length: config.epoch_length,
            epoch_buffer: config.epoch_buffer,
            token_domain: Vec::from(config.token_domain.as_bytes()),
            connections_service,
            token_service,
            token_ids_db,
        }
    }

    pub async fn create_connection(
        &mut self,
        token: VeronymousToken,
        wg_key: WGKey,
    ) -> Result<(Ipv4Addr, Ipv6Addr), AgentError> {
        // Get epoch and next epoch
        let now = get_now_u64();
        let epoch = self.get_current_epoch(now);
        let next_epoch = epoch + self.epoch_length;

        // Verify the token
        self.verify_token(&token, now, epoch).await?;

        // Add the connection
        let mut connections = self.connections_service.write().await;
        let (ipv4_addr, ipv6_addr) = connections
            .add_connection(&wg_key, epoch, next_epoch)
            .await?;

        Ok((ipv4_addr, ipv6_addr))
    }

    /*
     * Verify the access token
     */
    async fn verify_token(
        &mut self,
        token: &VeronymousToken,
        now: u64,
        epoch: u64,
    ) -> Result<(), AgentError> {
        let token_service = self.token_service.read().await;
        let (params, public_key, _) = token_service.get_token_params();

        // Verify the token
        let result = token
            .verify(&self.token_domain, epoch, &public_key, &params)
            .map_err(|e| Unauthorized(format!("Token verification failed. {:?}", e)))?;

        if !result {
            return Err(Unauthorized(format!("Invalid auth token_issuer.")));
        }

        // Trace the serial number
        let serial_number = &token.serial_number().unwrap();

        if self
            .token_ids_db
            .trace_token(epoch, self.epoch_length, now, serial_number)?
        {
            return Err(Unauthorized(format!("Attempted token_issuer id reuse.")));
        }

        Ok(())
    }

    fn get_current_epoch(&self, now: u64) -> u64 {
        get_current_epoch(now, self.epoch_length, self.epoch_buffer)
    }
}
