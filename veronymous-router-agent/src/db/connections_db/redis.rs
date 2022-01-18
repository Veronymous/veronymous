use crate::db::connections_db::ConnectionsDB;
use crate::AgentError;
use redis::{Commands, Connection};
use veronymous_connection::model::PublicKey;

pub struct RedisConnectionsDB {
    connection: Connection,
}

impl RedisConnectionsDB {
    pub fn create(address: &String) -> Result<Self, AgentError> {
        let client = redis::Client::open(address.as_str()).map_err(|err| {
            AgentError::InitializationError(format!("Could not connect to redis. {:?}", err))
        })?;

        let connection = client.get_connection().map_err(|err| {
            AgentError::InitializationError(format!("Could not connect to redis. {:?}", err))
        })?;

        Ok(Self { connection })
    }
}

impl ConnectionsDB for RedisConnectionsDB {
    fn store_connection(&mut self, public_key: &PublicKey) -> Result<(), AgentError> {
        let _: () = self
            .connection
            .set(public_key, true)
            .map_err(|err| AgentError::DBError(format!("Could not store connection. {:?}", err)))?;

        Ok(())
    }

    fn get_connections(&mut self) -> Result<Vec<PublicKey>, AgentError> {
        let raw_public_keys: Vec<Vec<u8>> = self
            .connection
            .keys("*")
            .map_err(|err| AgentError::DBError(format!("Could not read connections. {:?}", err)))?;

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

    fn clear_connections(&mut self) -> Result<(), AgentError> {
        let _: () = redis::cmd("FLUSHDB")
            .query(&mut self.connection)
            .map_err(|err| {
                AgentError::DBError(format!("Could not remove connections. {:?}", err))
            })?;

        Ok(())
    }
}
