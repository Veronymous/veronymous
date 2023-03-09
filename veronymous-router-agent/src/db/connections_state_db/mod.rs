pub mod redis;

use crate::error::AgentError;
use std::net::{Ipv4Addr, Ipv6Addr};

pub trait ConnectionsStateDB {
    fn assign_address(&mut self, expiry: u64) -> Result<(Ipv4Addr, Ipv6Addr), AgentError>;
}
