pub mod redis;

use veronymous_connection::model::PublicKey;

use crate::AgentError;

pub trait ConnectionsDB {
    fn store_connection(&mut self, public_key: &PublicKey) -> Result<(), AgentError>;

    fn get_connections(&mut self) -> Result<Vec<PublicKey>, AgentError>;

    fn clear_connections(&mut self) -> Result<(), AgentError>;
}
