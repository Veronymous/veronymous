use crate::db::connections_db::redis::RedisConnectionsDB;
use crate::db::connections_db::ConnectionsDB;
use crate::service::wireguard::WireguardService;
use crate::{AgentError, VeronymousAgentConfig};
use std::collections::{HashMap, HashSet};
use veronymous_connection::model::{Ipv4Address, PublicKey};

// TODO: IP Address assignment needs some more work
// TODO: This might have to be configurable
// TODO: Might also want to set the range or support ranges
// TODO: Cache assigned ip in redis
const BASE_ADDRESS: [u8; 4] = [10, 8, 0, 1];

pub struct RouterConnectionsService {
    //peers: HashSet<PublicKey>,
    last_address: Ipv4Address,

    wg_service: WireguardService,

    connections_db: RedisConnectionsDB,
}

impl RouterConnectionsService {
    pub async fn create(config: &VeronymousAgentConfig) -> Result<Self, AgentError> {
        Ok(Self {
            //peers: HashSet::new(),
            last_address: Ipv4Address::from(BASE_ADDRESS),
            wg_service: WireguardService::create(config).await?,
            connections_db: RedisConnectionsDB::create(&config.redis_address)?,
        })
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

        self.connections_db.store_connection(public_key)?;

        Ok(address)
    }

    pub async fn clear_connections(&mut self) -> Result<(), AgentError> {
        // Get the existing connections
        let connections = self.connections_db.get_connections()?;

        debug!("Removing connections: {:?}", connections);

        // Remove the connections from wireguard
        for key in connections {
            match self.wg_service.remove_peer(&key).await {
                Ok(()) => {}
                Err(err) => {
                    error!("{:?}", err);
                }
            }
        }

        // Remove the connections from the database
        self.connections_db.clear_connections()?;

        // Reset the ip address
        self.last_address = BASE_ADDRESS;

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
