use veronymous_connection::model::{Ipv4Address, PublicKey};

use crate::db::connections_db::redis::RedisConnectionsDB;
use crate::db::connections_db::ConnectionsDB;
use crate::db::connections_state_db::redis::RedisConnectionsStateDB;
use crate::db::connections_state_db::ConnectionsStateDB;
use crate::service::wireguard::WireguardService;
use crate::{AgentError, VeronymousAgentConfig};

// TODO: IP Address assignment needs some more work
// TODO: This might have to be configurable
// TODO: Might also want to set the range or support ranges
const BASE_ADDRESS: [u8; 4] = [10, 8, 0, 2];

pub struct RouterConnectionsService {
    wg_service: WireguardService,

    connections_db: RedisConnectionsDB,

    connections_state_db: RedisConnectionsStateDB,
}

impl RouterConnectionsService {
    pub async fn create(config: &VeronymousAgentConfig) -> Result<Self, AgentError> {
        let mut connections_state_db =
            RedisConnectionsStateDB::create(&config.connections_state_redis_address, BASE_ADDRESS)?;

        connections_state_db.init()?;

        Ok(Self {
            wg_service: WireguardService::create(config).await?,
            connections_db: RedisConnectionsDB::create(&config.connections_redis_address)?,
            connections_state_db,
        })
    }

    pub async fn add_connection(
        &mut self,
        public_key: &PublicKey,
    ) -> Result<Ipv4Address, AgentError> {
        let address = self.connections_state_db.next_ip_address()?;

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
        self.connections_state_db.reset_state()?;

        Ok(())
    }
}
