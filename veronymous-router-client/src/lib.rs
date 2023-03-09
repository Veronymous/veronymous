use crate::error::RouterClientError;
use crate::error::RouterClientError::{ConnectError, GrpcError};
use crate::grpc::router_agent_service::router_agent_service_client::RouterAgentServiceClient;
use crate::grpc::router_agent_service::ConnectionRequest;
use crate::model::Connection;
use std::str::FromStr;
use tonic::transport::{Channel, Endpoint};
use veronymous_token::serde::Serializable;
use veronymous_token::token::VeronymousToken;

pub mod error;
mod grpc;
pub mod model;

const KEY_SIZE: usize = 32;

pub type PublicKey = [u8; KEY_SIZE];

pub struct VeronymousRouterClient {
    client: RouterAgentServiceClient<Channel>,
}

impl VeronymousRouterClient {
    // TODO: Tls
    pub async fn new(endpoint: &String, tls_ca: &[u8]) -> Result<Self, RouterClientError> {
        // Encryption
        let tls_ca = tonic::transport::Certificate::from_pem(tls_ca);

        let tls_config = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tls_ca);

        let endpoint = Endpoint::from_str(endpoint.as_str())
            .map_err(|e| GrpcError(format!("Could not parse endpoint. {:?}", e)))?
            .tls_config(tls_config)
            .map_err(|e| GrpcError(format!("Could not add CA certificate. {:?}", e)))?;

        let client = RouterAgentServiceClient::connect(endpoint)
            .await
            .map_err(|e| GrpcError(format!("Could not connect to router agent. {:?}", e)))?;

        Ok(Self { client })
    }

    pub async fn connect(
        &mut self,
        wg_key: PublicKey,
        token: VeronymousToken,
    ) -> Result<Connection, RouterClientError> {
        // Assemble the request
        let request = tonic::Request::new(ConnectionRequest {
            wg_key: wg_key.to_vec(),
            token: token.serialize(),
        });

        // Send the connection request
        let response = self
            .client
            .create_connection(request)
            .await
            .map_err(|e| ConnectError(format!("Could not connect. {:?}", e)))?;

        Ok(response.into_inner().try_into()?)
    }
}
