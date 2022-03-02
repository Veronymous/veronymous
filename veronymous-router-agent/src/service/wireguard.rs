use std::fs;
use std::net::Ipv4Addr;
use std::str::FromStr;
use tonic::transport::{Channel, Endpoint};
use veronymous_connection::model::{Ipv4Address, PublicKey};
use wg_manager_service_common::wg_manager_service::wireguard_manager_service_client::WireguardManagerServiceClient;
use wg_manager_service_common::wg_manager_service::{AddPeerRequest, RemovePeerRequest};

use crate::AgentError::InitializationError;
use crate::{AgentError, VeronymousAgentConfig};

pub struct WireguardService {
    clients: Vec<WireguardManagerServiceClient<Channel>>,
}

impl WireguardService {
    pub async fn create(config: &VeronymousAgentConfig) -> Result<Self, AgentError> {
        let mut clients = Vec::with_capacity(config.address.len());

        // Configure CA
        let mut tls_config = None;

        // TLS Certificate authority
        if let Some(ca) = &config.wg_tls_ca {
            let ca = fs::read(ca).unwrap();
            let ca = tonic::transport::Certificate::from_pem(ca);

            let tls = tonic::transport::ClientTlsConfig::new().ca_certificate(ca);
            tls_config = Some(tls);
        }

        // Client cert for authentication
        if config.wg_client_cert.is_some() {
            info!("Loading client certificate...");
            let cert = fs::read(config.wg_client_cert.as_ref().unwrap()).unwrap();
            let key = fs::read(config.wg_client_key.as_ref().unwrap()).unwrap();

            let id = tonic::transport::Identity::from_pem(cert, key);

            if let Some(tls) = tls_config {
                tls_config = Some(tls.identity(id));
            } else {
                let tls = tonic::transport::ClientTlsConfig::new().identity(id);
                tls_config = Some(tls);
            }
        }

        for address in &config.wg_addresses {
            info!("Connecting to wireguard server: {}", address);

            let mut channel = Endpoint::from_str(&address).unwrap();

            // Configure the tls certificate authority
            if let Some(tls_config) = &tls_config {
                info!("Configuring certificate authority for wireguard client...");
                channel = channel.tls_config(tls_config.clone()).map_err(|e| {
                    InitializationError(format!("Could not configure tls. {:?}", e))
                })?;
            }

            let client = WireguardManagerServiceClient::connect(channel)
                .await
                .map_err(|err| {
                    AgentError::InitializationError(format!(
                        "Could not connect to wireguard server {}. {:?}",
                        address, err
                    ))
                })?;

            clients.push(client);
        }
        Ok(Self { clients })
    }

    pub async fn add_peer(
        &mut self,
        public_key: &PublicKey,
        address: Ipv4Address,
    ) -> Result<(), AgentError> {
        // Assemble the request
        let public_key = base64::encode(public_key);
        let addresses = vec![Ipv4Addr::from(address).to_string()];

        let request = AddPeerRequest {
            public_key,
            addresses,
        };

        for client in self.clients.iter_mut() {
            match client.add_peer(tonic::Request::new(request.clone())).await {
                Ok(_) => {}
                Err(err) => error!("Could not add peer to wireguard server. {:?}", err),
            };
        }

        Ok(())
    }

    pub async fn remove_peer(&mut self, public_key: &PublicKey) -> Result<(), AgentError> {
        let public_key = base64::encode(public_key);

        let request = RemovePeerRequest { public_key };

        for client in self.clients.iter_mut() {
            match client
                .remove_peer(tonic::Request::new(request.clone()))
                .await
            {
                Ok(_) => {}
                Err(err) => error!("Could not remove peer from wireguard server. {:?}", err),
            };
        }

        Ok(())
    }
}
