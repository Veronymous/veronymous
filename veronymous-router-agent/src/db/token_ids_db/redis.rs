use crate::db::token_ids_db::TokenIDsDB;
use crate::{AgentError, VeronymousAgentConfig};
use redis::{Commands, Connection};
use veronymous_token::token::get_next_epoch;
use veronymous_token::SerialNumber;

pub struct RedisTokenIDsDB {
    connection: Connection,
}

impl RedisTokenIDsDB {
    pub fn create(config: &VeronymousAgentConfig) -> Result<Self, AgentError> {
        let client =
            redis::Client::open(config.token_ids_redis_address.as_str()).map_err(|err| {
                AgentError::InitializationError(format!("Could not connect to redis. {:?}", err))
            })?;

        let connection = client.get_connection().map_err(|err| {
            AgentError::InitializationError(format!("Could not connect to redis. {:?}", err))
        })?;

        Ok(Self { connection })
    }
}

impl TokenIDsDB for RedisTokenIDsDB {
    fn trace_token(
        &mut self,
        epoch: u64,
        epoch_length: u64,
        now: u64,
        token_id: &SerialNumber,
    ) -> Result<bool, AgentError> {
        let token_id_entry = Self::create_token_id_entry(epoch, token_id);

        debug!("Tracing token id: {}", token_id_entry);

        let exists: bool = self
            .connection
            .exists(&token_id_entry)
            .map_err(|e| AgentError::DBError(format!("Could not query token id entry. {:?}", e)))?;

        if exists {
            debug!("Token id traced!");
            return Ok(true);
        }

        debug!("Saving token id...");

        // Set the key
        self.connection
            .set(&token_id_entry, true)
            .map_err(|e| AgentError::DBError(format!("Could not save token id. {:?}", e)))?;

        // Set expiration
        let next_epoch = get_next_epoch(now, epoch_length);
        self.connection
            .expire_at(&token_id_entry, next_epoch as usize)
            .map_err(|e| {
                AgentError::DBError(format!("Could not set token id expiration time. {:?}", e))
            })?;

        Ok(false)
    }
}
