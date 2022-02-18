use crate::service::connections::RouterConnectionsService;
use crate::service::token_service::{TokenService, TOKEN_DOMAIN};
use crate::{AgentError, VeronymousAgentConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use veronymous_connection::model::{
    ConnectMessage, ConnectRequest, ConnectResponse, SerializableMessage,
};

pub struct VeronymousRouterAgentService {
    token_service: Arc<RwLock<TokenService>>,

    connections: RouterConnectionsService,
}

impl VeronymousRouterAgentService {
    pub async fn create(config: &VeronymousAgentConfig) -> Result<Self, AgentError> {
        let service = Self {
            token_service: Arc::new(RwLock::new(TokenService::create(config).await?)),
            connections: RouterConnectionsService::create(config).await?,
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

        // Verify the connect request
        if !self.verify_connect_request(request).await? {
            return Err(AgentError::Unauthorized(format!(
                "Connection request verification failed."
            )));
        }

        // Add the connection
        let peer_address = self.connections.add_connection(&request.public_key).await?;

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
        self.connections.clear_connections().await
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

    // TODO: Create authentication service
    // TODO: Track serial id
    async fn verify_connect_request(&self, request: &ConnectRequest) -> Result<bool, AgentError> {
        let token_service = self.token_service.read().await;
        let (params, public_key, epoch) = token_service.get_token_params();

        let result = request
            .token
            .verify(TOKEN_DOMAIN, epoch, &public_key, &params)
            .map_err(|e| AgentError::Unauthorized(format!("Token verification failed. {:?}", e)))?;

        Ok(result)
    }
}
