use crate::service::connections::RouterConnectionsService;
use crate::{AgentError, VeronymousAgentConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use veronymous_connection::model::{
    ConnectMessage, ConnectRequest, ConnectResponse, SerializableMessage,
};

pub struct VeronymousRouterAgentService {
    connections: RouterConnectionsService,
}

impl VeronymousRouterAgentService {
    pub async fn create(config: &VeronymousAgentConfig) -> Result<Self, AgentError> {
        Ok(Self {
            connections: RouterConnectionsService::create(config).await?,
        })
    }

    pub async fn handle_connect_request(
        &mut self,
        request: &ConnectRequest,
        socket: &mut TcpStream,
    ) -> Result<(), AgentError> {
        debug!("Handling connection request...");

        // Verify the connect request
        if !self.verify_connect_request(request)? {
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

    // TODO: Take in specific parameters instead of the full request object
    fn verify_connect_request(&self, _request: &ConnectRequest) -> Result<bool, AgentError> {
        // TODO
        Ok(true)
    }
}
