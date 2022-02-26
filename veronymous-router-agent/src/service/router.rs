use crate::db::token_ids_db::redis::RedisTokenIDsDB;
use crate::db::token_ids_db::TokenIDsDB;
use crate::service::connections::RouterConnectionsService;
use crate::service::token_service::TokenService;
use crate::{AgentError, VeronymousAgentConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use veronymous_connection::model::{
    ConnectMessage, ConnectRequest, ConnectResponse, SerializableMessage,
};
use veronymous_token::token::{get_current_epoch, get_now_u64};

pub struct VeronymousRouterAgentService {
    token_service: Arc<RwLock<TokenService>>,

    token_domain: Vec<u8>,

    connections: RouterConnectionsService,

    token_ids_db: RedisTokenIDsDB,

    epoch_length: u64,

    epoch_buffer: u64,
}

impl VeronymousRouterAgentService {
    pub async fn create(config: &VeronymousAgentConfig) -> Result<Self, AgentError> {
        let service = Self {
            token_service: Arc::new(RwLock::new(TokenService::create(config).await?)),
            token_domain: Vec::from(config.token_domain.as_bytes()),
            connections: RouterConnectionsService::create(config).await?,
            token_ids_db: RedisTokenIDsDB::create(config)?,
            epoch_length: config.epoch_length * 60,
            epoch_buffer: config.epoch_buffer * 60,
        };

        service.schedule_token_info_refresh().await;

        Ok(service)
    }

    pub async fn handle_connect_request(
        &mut self,
        request: &ConnectRequest,
        socket: &mut TcpStream,
    ) -> Result<(), AgentError> {
        debug!("Handling connection request...");

        let now = get_now_u64();
        let epoch = self.get_current_epoch(now);

        // Verify the connect request
        self.verify_connect_request(request, now, epoch).await?;

        // Add the connection
        let peer_address = self
            .connections
            .add_connection(&request.public_key, epoch)
            .await?;

        // Construct the response
        let response = ConnectResponse::new(true, peer_address);
        let response = ConnectMessage::ConnectResponse(response);

        // Send the response
        socket.write_all(&response.to_bytes()).await.map_err(|e| {
            AgentError::IpError(format!("Could not send response. {}", e.to_string()))
        })?;

        Ok(())
    }

    pub async fn clear_connections(&mut self) -> Result<(), AgentError> {
        let now = get_now_u64();
        let previous_epoch = self.get_previous_epoch(now);

        debug!("Clearing connections for epoch {}...", previous_epoch);

        self.connections.clear_connections(previous_epoch).await
    }

    async fn schedule_token_info_refresh(&self) {
        info!("Scheduling token info refresh...");

        let token_info = self
            .token_service
            .clone()
            .read()
            .await
            .get_current_token_info();

        // Convert minutes to seconds
        let key_lifetime = token_info.key_lifetime * 60;

        let next_key_update = TokenService::calculate_next_key_update(key_lifetime);
        let key_lifetime = Duration::from_secs(key_lifetime);

        let token_service = self.token_service.clone();

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval_at(next_key_update, key_lifetime);

            loop {
                interval_timer.tick().await;

                let mut token_service = token_service.write().await;

                // TODO: Catch error or panic?
                token_service.update_token_info().await.unwrap();
            }
        });
    }

    async fn verify_connect_request(
        &mut self,
        request: &ConnectRequest,
        now: u64,
        epoch: u64,
    ) -> Result<(), AgentError> {
        let token_service = self.token_service.read().await;
        let (params, public_key, _) = token_service.get_token_params();

        // Verify the token
        let result = request
            .token
            .verify(&self.token_domain, epoch, &public_key, &params)
            .map_err(|e| AgentError::Unauthorized(format!("Token verification failed. {:?}", e)))?;

        if !result {
            return Err(AgentError::Unauthorized(format!("Invalid auth token.")));
        }

        // Trace the serial number
        let serial_number = request.token.serial_number().unwrap();

        if self
            .token_ids_db
            .trace_token(epoch, self.epoch_length, now, &serial_number)?
        {
            return Err(AgentError::Unauthorized(format!(
                "Attempted token id reuse."
            )));
        }

        Ok(())
    }

    // returns epoch, now
    fn get_current_epoch(&self, now: u64) -> u64 {
        get_current_epoch(now, self.epoch_length, self.epoch_buffer)
    }

    fn get_previous_epoch(&self, now: u64) -> u64 {
        get_current_epoch(now, self.epoch_length, 0) - self.epoch_length
    }
}
