use crate::db::connections_state_db::ConnectionsStateDB;
use crate::AgentError;
use redis::{Commands, Connection};
use veronymous_connection::model::Ipv4Address;

const NEXT_IP_ADDRESS_KEY: &[u8; 12] = b"next_address";

pub struct RedisConnectionsStateDB {
    connection: Connection,

    base_address: Ipv4Address,
}

impl RedisConnectionsStateDB {
    pub fn create(redis_address: &String, base_address: Ipv4Address) -> Result<Self, AgentError> {
        let client = redis::Client::open(redis_address.as_str()).map_err(|err| {
            AgentError::InitializationError(format!("Could not connect to redis. {:?}", err))
        })?;

        let connection = client.get_connection().map_err(|err| {
            AgentError::InitializationError(format!("Could not connect to redis. {:?}", err))
        })?;

        Ok(Self {
            connection,
            base_address,
        })
    }
}

impl ConnectionsStateDB for RedisConnectionsStateDB {
    fn init(&mut self) -> Result<(), AgentError> {
        let _: () = self
            .connection
            .set(NEXT_IP_ADDRESS_KEY, &self.base_address)
            .map_err(|err| {
                AgentError::DBError(format!("Could not set base ip address. {:?}", err))
            })?;

        Ok(())
    }

    fn next_ip_address(&mut self) -> Result<Ipv4Address, AgentError> {
        let address: Vec<u8> = self.connection.get(NEXT_IP_ADDRESS_KEY).map_err(|err| {
            AgentError::DBError(format!("Could not get next ip address: {:?}", err))
        })?;

        let address: Ipv4Address = address.try_into().map_err(|err| {
            AgentError::ParsingError(format!("Could not parse ipv4 address. {:?}", err))
        })?;

        let next_address = increase_ip_address(&address)?;

        let _: () = self
            .connection
            .set(NEXT_IP_ADDRESS_KEY, &next_address)
            .map_err(|err| {
                AgentError::DBError(format!("Could not set next ip address. {:?}", err))
            })?;

        Ok(address)
    }

    fn reset_state(&mut self) -> Result<(), AgentError> {
        let _: () = self
            .connection
            .set(NEXT_IP_ADDRESS_KEY, &self.base_address)
            .map_err(|err| {
                AgentError::DBError(format!("Could not set base ip address. {:?}", err))
            })?;

        Ok(())
    }
}

// TODO: Scale/fix this
fn increase_ip_address(address: &Ipv4Address) -> Result<Ipv4Address, AgentError> {
    let host_id = address[3];
    let mut new_address = address.clone();

    if host_id >= 255 {
        // TODO: Fix to another range
        return Err(AgentError::IpError(format!("IP address out of range.")));
        // Host id
        /*new_address[3] = 1;
        new_address[2] = address[2] + 1;*/
    } else {
        // Increase the host id
        new_address[3] = address[3] + 1;
    }

    Ok(new_address)
}
