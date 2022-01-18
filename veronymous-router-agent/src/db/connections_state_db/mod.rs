pub mod redis;

use crate::AgentError;
use veronymous_connection::model::Ipv4Address;

pub trait ConnectionsStateDB {
    fn init(&mut self) -> Result<(), AgentError>;

    fn next_ip_address(&mut self) -> Result<Ipv4Address, AgentError>;

    fn reset_state(&mut self) -> Result<(), AgentError>;
}
