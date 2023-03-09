pub mod redis;

use crate::error::AgentError;
use crate::wireguard::WGKey;

pub trait ConnectionsDB {
    fn store_connection(&mut self, public_key: &WGKey, epoch: u64) -> Result<(), AgentError>;

    fn get_connections(&mut self, epoch: u64) -> Result<Vec<WGKey>, AgentError>;

    fn clear_connections(&mut self, epoch: u64) -> Result<(), AgentError>;

    fn get_stored_epochs(&mut self) -> Result<Vec<u64>, AgentError>;
}
