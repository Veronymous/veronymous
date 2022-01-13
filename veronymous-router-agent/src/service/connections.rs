use crate::service::wireguard::WireguardService;
use crate::{AgentError, VeronymousAgentConfig};
use std::collections::HashMap;
use veronymous_connection::model::{Ipv4Address, PublicKey};

/*
* TODO: Store users in REDIS
*/

// TODO: IP Address assignment needs some more work
// TODO: This might have to be configurable
// TODO: Might also want to set the range or support ranges
const BASE_ADDRESS: [u8; 4] = [10, 8, 0, 1];

pub struct RouterConnectionsService {
    peers: HashMap<PublicKey, Ipv4Address>,

    last_address: Ipv4Address,

    wg_service: WireguardService,
}

impl RouterConnectionsService {
    pub async fn create(config: &VeronymousAgentConfig) -> Result<Self, AgentError> {
        Ok(Self {
            peers: HashMap::new(),
            last_address: Ipv4Address::from(BASE_ADDRESS),
            wg_service: WireguardService::create(config).await?,
        })
    }

    pub fn new(
        peers: HashMap<PublicKey, Ipv4Address>,
        last_address: Ipv4Address,
        wg_service: WireguardService,
    ) -> Self {
        Self {
            peers,
            last_address,
            wg_service,
        }
    }

    pub async fn add_connection(
        &mut self,
        public_key: &PublicKey,
    ) -> Result<Ipv4Address, AgentError> {
        let address = self.assign_address()?;

        debug!(
            "Connecting peer: PEER_ID {} ADDRESS {:?}",
            base64::encode(&public_key),
            address
        );

        // Add wireguard connection
        self.wg_service
            .add_peer(&public_key, address.clone())
            .await?;

        self.peers.insert(public_key.clone(), address);

        Ok(address)
    }

    pub async fn clear_connections(&mut self) -> Result<(), AgentError> {
        for key in self.peers.clone().keys() {
            match self.wg_service.remove_peer(key).await {
                Ok(()) => {
                    self.peers.remove(key);
                }
                Err(err) => {
                    error!("{:?}", err);
                }
            }
        }

        Ok(())
    }

    // TODO: Check if address exists
    fn assign_address(&mut self) -> Result<Ipv4Address, AgentError> {
        let host_id = self.last_address[3];

        let mut new_address = self.last_address.clone();

        if host_id >= 255 {
            // Host id
            new_address[3] = 1;
            new_address[2] = self.last_address[2] + 1;

            if new_address[2] > 255 {
                // TODO: Handle this
                return Err(AgentError::IpError(format!("IP address out of range.")));
            }
        } else {
            // Increase the host id
            new_address[3] = self.last_address[3] + 1;
        }

        self.last_address = new_address.clone();

        Ok(new_address)
    }
}
