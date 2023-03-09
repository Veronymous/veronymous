use crate::config::RouterAgentConfig;
use crate::error::AgentError;
use crate::error::AgentError::InitializationError;
use crate::wireguard::WGKey;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use tonic::transport::{Channel, Endpoint};
use wg_manager_service_common::wg_manager_service::wireguard_manager_service_client::WireguardManagerServiceClient;
use wg_manager_service_common::wg_manager_service::{AddPeerRequest, RemovePeerRequest};

pub struct WireguardService {
    clients: Vec<WireguardManagerServiceClient<Channel>>,
}

impl WireguardService {
    // TODO: Tls config should be mandatory
    pub async fn create(config: &RouterAgentConfig) -> Result<Self, AgentError> {
        let mut clients = Vec::with_capacity(config.wg_addresses.len());

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

            let mut endpoint = Endpoint::from_str(&address).unwrap();

            // Configure the tls certificate authority
            if let Some(tls_config) = &tls_config {
                info!("Configuring certificate authority for wireguard client...");
                endpoint = endpoint.tls_config(tls_config.clone()).map_err(|e| {
                    InitializationError(format!("Could not configure tls. {:?}", e))
                })?;
            }

            let client = WireguardManagerServiceClient::connect(endpoint)
                .await
                .map_err(|err| {
                    InitializationError(format!(
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
        public_key: &WGKey,
        ipv4_address: Ipv4Addr,
        ipv6_address: Ipv6Addr,
    ) -> Result<(), AgentError> {
        // Assemble the request
        let public_key = base64::encode(public_key);

        let addresses = vec![ipv4_address.to_string(), ipv6_address.to_string()];

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

    pub async fn remove_peer(&mut self, public_key: &WGKey) -> Result<(), AgentError> {
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
