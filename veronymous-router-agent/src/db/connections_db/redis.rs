use crate::db::connections_db::ConnectionsDB;
use crate::error::AgentError;
use crate::error::AgentError::{DBError, InitializationError};
use crate::wireguard::WGKey;
use redis::{Commands, Connection};

pub struct RedisConnectionsDB {
    connection: Connection,
}

impl RedisConnectionsDB {
    pub fn create(address: &String) -> Result<Self, AgentError> {
        let client = redis::Client::open(address.as_str())
            .map_err(|err| InitializationError(format!("Could not connect to redis. {:?}", err)))?;

        let connection = client
            .get_connection()
            .map_err(|err| InitializationError(format!("Could not connect to redis. {:?}", err)))?;

        Ok(Self { connection })
    }
}

impl ConnectionsDB for RedisConnectionsDB {
    fn store_connection(&mut self, public_key: &WGKey, epoch: u64) -> Result<(), AgentError> {
        let _: () = self
            .connection
            .lpush(epoch, public_key)
            .map_err(|err| DBError(format!("Could not store connection. {:?}", err)))?;

        Ok(())
    }

    fn get_connections(&mut self, epoch: u64) -> Result<Vec<WGKey>, AgentError> {
        let raw_public_keys: Vec<Vec<u8>> = self
            .connection
            .lrange(epoch, 0, u32::MAX as isize)
            .map_err(|err| DBError(format!("Could not read connections. {:?}", err)))?;

        let mut public_keys = Vec::with_capacity(raw_public_keys.len());

        for raw_public_key in raw_public_keys {
            let public_key = match raw_public_key.try_into() {
                Ok(key) => key,
                Err(err) => {
                    // Doesn't throw error because other connections would not be removed
                    error!("Could not decode public key. {:?}", err);
                    continue;
                }
            };

            public_keys.push(public_key);
        }

        Ok(public_keys)
    }

    fn clear_connections(&mut self, epoch: u64) -> Result<(), AgentError> {
        // Delete the list
        self.connection
            .del(epoch)
            .map_err(|err| DBError(format!("Could not remove connections. {:?}", err)))?;

        Ok(())
    }

    fn get_stored_epochs(&mut self) -> Result<Vec<u64>, AgentError> {
        let epochs: Vec<u64> = self
            .connection
            .keys("*")
            .map_err(|err| DBError(format!("Could not find stored epochs. {:?}", err)))?;

        Ok(epochs)
    }
}
