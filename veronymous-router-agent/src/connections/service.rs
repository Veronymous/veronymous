use crate::config::RouterAgentConfig;
use crate::db::connections_db::redis::RedisConnectionsDB;
use crate::db::connections_db::ConnectionsDB;
use crate::db::connections_state_db::redis::RedisConnectionsStateDB;
use crate::db::connections_state_db::ConnectionsStateDB;
use crate::error::AgentError;
use crate::wireguard::service::WireguardService;
use crate::wireguard::WGKey;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::Instant;
use veronymous_token::token::{get_current_epoch, get_now_u64};

pub struct ConnectionsService {
    wg_service: WireguardService,

    connections_db: RedisConnectionsDB,

    connections_state_db: RedisConnectionsStateDB,

    epoch_length: u64,

    epoch_buffer: u64,
}

// TODO: Schedule periodic clear connections
impl ConnectionsService {
    pub async fn create(
        config: &RouterAgentConfig,
        wg_service: WireguardService,
        connections_db: RedisConnectionsDB,
    ) -> Result<Arc<RwLock<Self>>, AgentError> {
        // Connect to redis
        let connections_state_db = RedisConnectionsStateDB::create(&config)?;

        let mut connections_service = Self {
            wg_service,
            connections_db,
            connections_state_db,
            epoch_length: config.epoch_length,
            epoch_buffer: config.epoch_buffer,
        };

        // Clear old connections
        connections_service.clear_old_connections().await?;

        let connections_service = Arc::new(RwLock::new(connections_service));

        // Schedule the connections cleaner
        Self::schedule_connection_cleaner(connections_service.clone()).await;

        Ok(connections_service)
    }

    pub async fn add_connection(
        &mut self,
        public_key: &WGKey,
        epoch: u64,
        next_epoch: u64,
    ) -> Result<(Ipv4Addr, Ipv6Addr), AgentError> {
        debug!(
            "Adding connection. EPOCH {}, NEXT EPOCH {}",
            epoch, next_epoch
        );

        let (ipv4_address, ipv6_address) = self.connections_state_db.assign_address(next_epoch)?;

        debug!(
            "Connecting peer: PEER_ID {} ADDRESS {:?}, {:?}",
            base64::encode(&public_key),
            ipv4_address,
            ipv6_address
        );

        // Add wireguard connection
        self.wg_service
            .add_peer(&public_key, ipv4_address.clone(), ipv6_address.clone())
            .await?;

        self.connections_db.store_connection(public_key, epoch)?;

        Ok((ipv4_address, ipv6_address))
    }

    // Clear connections that might of been missed
    // Clear the connections that do not belong to the active epochs
    async fn clear_old_connections(&mut self) -> Result<(), AgentError> {
        // Get the epochs
        let current_epoch = self.get_current_epoch(get_now_u64());
        let next_epoch = current_epoch + self.epoch_length;

        // Get the stored epochs
        let stored_epochs = self.connections_db.get_stored_epochs()?;

        // Find the expired epochs (not current or next epoch)
        for stored_epoch in stored_epochs {
            if stored_epoch != current_epoch && stored_epoch != next_epoch {
                self.clear_connections(stored_epoch).await?;
            }
        }

        Ok(())
    }

    async fn clear_connections(&mut self, epoch: u64) -> Result<(), AgentError> {
        // Get the existing connections
        let connections = self.connections_db.get_connections(epoch)?;

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
        self.connections_db.clear_connections(epoch)?;

        Ok(())
    }

    fn get_current_epoch(&self, now: u64) -> u64 {
        get_current_epoch(now, self.epoch_length, self.epoch_buffer)
    }

    pub fn next_epoch(&self) -> Instant {
        let now = SystemTime::now();
        let now_instant = Instant::now();

        let now = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Get the current epoch start
        let current_epoch = now - (now % self.epoch_length);
        let next_epoch = current_epoch + self.epoch_length;

        let time_until_next_epoch = next_epoch - now;

        now_instant + Duration::from_secs(time_until_next_epoch)
    }

    async fn schedule_connection_cleaner(service: Arc<RwLock<ConnectionsService>>) {
        info!("Scheduling connection cleaner");

        let service_cloned = service.clone();
        let lock = service_cloned.read().await;

        let next_epoch = lock.next_epoch();
        let epoch_duration = Duration::from_secs(lock.epoch_length);

        info!("Next epoch: {:?}", next_epoch);
        info!("Epoch duration: {}s", epoch_duration.as_secs());

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval_at(next_epoch, epoch_duration);
            loop {
                interval_timer.tick().await;
                info!("Clearing connections...");

                match service.write().await.clear_old_connections().await {
                    Ok(_) => info!("Connections cleared!"),
                    Err(err) => error!("Got error while clearing connections. {:?}", err),
                }
            }
        });
    }
}
