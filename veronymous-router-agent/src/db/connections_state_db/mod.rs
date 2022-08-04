pub mod redis;

use crate::AgentError;
use veronymous_connection::model::Ipv4Address;

pub trait ConnectionsStateDB {
    fn assign_address(&mut self, expiry: u64) -> Result<Ipv4Address, AgentError>;
}
