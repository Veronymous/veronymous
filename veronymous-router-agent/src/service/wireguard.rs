use std::net::Ipv4Addr;
use std::str::FromStr;
use tonic::transport::{Channel, Endpoint};
use veronymous_connection::model::{Ipv4Address, PublicKey};
use wg_manager_service_common::wg_manager_service::wireguard_manager_service_client::WireguardManagerServiceClient;
use wg_manager_service_common::wg_manager_service::AddPeerRequest;

use crate::{AgentError, VeronymousAgentConfig};

pub struct WireguardService {
    client: WireguardManagerServiceClient<Channel>,
}

impl WireguardService {
    pub async fn create(config: &VeronymousAgentConfig) -> Result<Self, AgentError> {
        info!("Connecting to wireguard server: {}", config.wg_address);

        let endpoint = Endpoint::from_str(&config.wg_address).unwrap();

        let client = WireguardManagerServiceClient::connect(endpoint)
            .await
            .map_err(|e| {
                AgentError::InitializationError(format!(
                    "Could not connect to wireguard server ({})",
                    config.address
                ))
            })?;

        Ok(Self::new(client))
    }

    pub fn new(client: WireguardManagerServiceClient<Channel>) -> Self {
        Self { client }
    }

    pub async fn add_peer(
        &mut self,
        public_key: &PublicKey,
        address: Ipv4Address,
    ) -> Result<(), AgentError> {
        // Assemble the request
        let public_key = base64::encode(public_key);
        let addresses = vec![Ipv4Addr::from(address).to_string()];

        let request = tonic::Request::new(AddPeerRequest {
            public_key,
            addresses,
        });

        self.client
            .add_peer(request)
            .await
            .map_err(|e| AgentError::WireguardError(format!("{:?}", e)))?;

        Ok(())
    }

    pub async fn remove_peer(&self, public_key: &PublicKey) {}
}
