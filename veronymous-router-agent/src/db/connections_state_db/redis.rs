use crate::db::connections_state_db::ConnectionsStateDB;
use crate::{AgentError, VeronymousAgentConfig};
use redis::{Commands, Connection};
use std::net::Ipv4Addr;
use veronymous_connection::model::Ipv4Address;

const NEXT_IP_ADDRESS_KEY: &[u8; 12] = b"next_address";

pub struct RedisConnectionsStateDB {
    base_addresses: Vec<Ipv4Address>,

    base_address_index: usize,

    connection: Connection,
}

impl RedisConnectionsStateDB {
    pub fn create(config: &VeronymousAgentConfig) -> Result<Self, AgentError> {
        // TODO: Make sure addresses are unique (Indexed hash set)
        let mut base_addresses = Vec::with_capacity(config.private_addresses.len());

        for address in &config.private_addresses {
            let address: Ipv4Addr = address.parse().unwrap();
            base_addresses.push(address.octets());
        }

        let client = redis::Client::open(config.connections_state_redis_address.as_str()).map_err(
            |err| AgentError::InitializationError(format!("Could not connect to redis. {:?}", err)),
        )?;

        let connection = client.get_connection().map_err(|err| {
            AgentError::InitializationError(format!("Could not connect to redis. {:?}", err))
        })?;

        Ok(Self {
            base_addresses,
            base_address_index: 0,
            connection,
        })
    }
}

impl ConnectionsStateDB for RedisConnectionsStateDB {
    fn init(&mut self) -> Result<(), AgentError> {
        let address: Vec<u8> = self.connection.get(NEXT_IP_ADDRESS_KEY).map_err(|err| {
            AgentError::DBError(format!("Could not get next ip address: {:?}", err))
        })?;

        if address.is_empty() {
            self.set_next_ip_address(&self.base_addresses[0].clone())?;
        }
        Ok(())
    }

    fn next_ip_address(&mut self) -> Result<Ipv4Address, AgentError> {
        let address: Vec<u8> = self.connection.get(NEXT_IP_ADDRESS_KEY).map_err(|err| {
            AgentError::DBError(format!("Could not get next ip address: {:?}", err))
        })?;

        let address: Ipv4Address = address.try_into().map_err(|err| {
            AgentError::ParsingError(format!("Could not parse ipv4 address. {:?}", err))
        })?;

        let next_address = self.increase_ip_address(&address)?;

        self.set_next_ip_address(&next_address)?;

        Ok(address)
    }

    fn reset_state(&mut self) -> Result<(), AgentError> {
        self.set_next_ip_address(&self.base_addresses[0].clone())?;

        self.base_address_index = 0;

        Ok(())
    }
}

impl RedisConnectionsStateDB {
    fn set_next_ip_address(&mut self, address: &Ipv4Address) -> Result<(), AgentError> {
        let _: () = self
            .connection
            .set(NEXT_IP_ADDRESS_KEY, address)
            .map_err(|err| {
                AgentError::DBError(format!("Could not set next ip address. {:?}", err))
            })?;

        Ok(())
    }

    fn increase_ip_address(&mut self, address: &Ipv4Address) -> Result<Ipv4Address, AgentError> {
        let host_id = address[3];
        let mut new_address;

        if host_id >= 255 {
            if self.base_address_index >= (self.base_addresses.len() - 1) {
                // No more ip addresses available
                return Err(AgentError::IpError(format!("IP address out of range.")));
            }

            self.base_address_index += 1;
            new_address = self.base_addresses[self.base_address_index].clone();
        } else {
            // Increase the host id
            new_address = address.clone();
            new_address[3] = address[3] + 1;
        }

        Ok(new_address)
    }
}
