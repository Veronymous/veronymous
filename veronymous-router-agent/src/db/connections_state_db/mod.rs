pub mod redis;

use crate::AgentError;
use veronymous_connection::model::{Ipv4Address, Ipv6Address};

pub trait ConnectionsStateDB {
    fn assign_address(&mut self, expiry: u64) -> Result<(Ipv4Address, Ipv6Address), AgentError>;
}
