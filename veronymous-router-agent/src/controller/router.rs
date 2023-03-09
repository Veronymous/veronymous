use crate::error::AgentError;
use crate::grpc::router_agent_service::router_agent_service_server::RouterAgentService;
use crate::grpc::router_agent_service::{ConnectionRequest, ConnectionResponse};
use crate::router::service::RouterService;
use crate::wireguard::WGKey;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Code, Request, Response, Status};
use veronymous_token::serde::Serializable;
use veronymous_token::token::VeronymousToken;

pub struct RouterAgentController {
    service: Arc<Mutex<RouterService>>,
}

impl RouterAgentController {
    pub fn new(service: Arc<Mutex<RouterService>>) -> Self {
        Self { service }
    }
}

#[tonic::async_trait]
impl RouterAgentService for RouterAgentController {
    async fn create_connection(
        &self,
        request: Request<ConnectionRequest>,
    ) -> Result<Response<ConnectionResponse>, Status> {
        debug!("Got 'create_connection' request.");

        let request = request.into_inner();

        // Decode the request values
        let token = VeronymousToken::deserialize(&request.token)
            .map_err(|_| Status::new(Code::InvalidArgument, "Invalid token."))?;
        let wg_key: WGKey = request
            .wg_key
            .try_into()
            .map_err(|_| Status::new(Code::InvalidArgument, "Invalid wireguard public key."))?;

        let mut service = self.service.lock().await;

        // Create the connection
        let (ipv4_address, ipv6_address) = match service.create_connection(token, wg_key).await {
            Ok(connection) => connection,
            Err(err) => {
                return match err {
                    AgentError::DeserializationError(e) => {
                        debug!("{:?}", e);
                        Err(Status::invalid_argument("Received an invalid argument"))
                    }
                    AgentError::Unauthorized(e) => {
                        debug!("{:?}", e);
                        Err(Status::unauthenticated("Token verification failed."))
                    }
                    _ => {
                        debug!("{:?}", err);
                        Err(Status::aborted("Something went wrong"))
                    }
                }
            }
        };

        // Create the response
        let connection_response = Response::new(ConnectionResponse {
            ipv4_address: Vec::from(ipv4_address.octets()),
            ipv6_address: Vec::from(ipv6_address.octets()),
        });

        Ok(connection_response)
    }
}
