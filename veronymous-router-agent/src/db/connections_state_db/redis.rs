use crate::db::connections_state_db::ConnectionsStateDB;
use crate::{AgentError, VeronymousAgentConfig};
use rand::Rng;
use redis::{Commands, Connection};
use std::net::Ipv4Addr;
use veronymous_connection::model::Ipv4Address;

/*
* subnet mask for ipv4 is 16 bit
*/
pub struct RedisConnectionsStateDB {
    gateway_ipv4: Ipv4Address,

    connection: Connection,
}

impl RedisConnectionsStateDB {
    pub fn create(config: &VeronymousAgentConfig) -> Result<Self, AgentError> {
        let gateway_ipv4: Ipv4Addr = config.wg_gateway_ipv4.parse().unwrap();
        let gateway_ipv4: Ipv4Address = gateway_ipv4.octets();

        let client = redis::Client::open(config.connections_state_redis_address.as_str()).map_err(
            |err| AgentError::InitializationError(format!("Could not connect to redis. {:?}", err)),
        )?;

        let connection = client.get_connection().map_err(|err| {
            AgentError::InitializationError(format!("Could not connect to redis. {:?}", err))
        })?;

        Ok(Self {
            gateway_ipv4,
            connection,
        })
    }
}

impl ConnectionsStateDB for RedisConnectionsStateDB {
    /*
     * NOTE: Possible race condition: If two agents create an address at the exact same time,
     * one connection address will be overridden
     */
    fn assign_address(&mut self, expire_at: u64) -> Result<Ipv4Address, AgentError> {
        // Select random ip address between 0.1 and 255.254
        let mut address = self.random_address();
        let mut find_address_attempts: u8 = 0;

        // Assign another if it already exists
        // Maximum 10 attempts
        while self.address_exist(&address)? {
            address = self.random_address();
            find_address_attempts += 1;

            if find_address_attempts >= 20 {
                return Err(AgentError::IpError("Could not find IP address.".to_string()));
            }
        }

        // Assign the address
        self.store_address(&address, expire_at)?;

        debug!("Assigned address: {:?}", address);

        Ok(address)
    }
}

impl RedisConnectionsStateDB {
    // Generate host id between 0.1 and 255.255
    fn random_address(&self) -> Ipv4Address {
        let mut rng = rand::thread_rng();

        // Between 2 and 255
        let host_id_1: u8 = rng.gen_range(2, 255);
        // Between 0 and 254
        let host_id_2: u8 = rng.gen_range(0, 254);

        let address = [
            self.gateway_ipv4[0],
            self.gateway_ipv4[1],
            host_id_1,
            host_id_2,
        ];

        address
    }

    // Check whether an address exist in REDIS
    fn address_exist(&mut self, address: &Ipv4Address) -> Result<bool, AgentError> {
        let address_exist = self.connection.exists(address).map_err(|err| {
            AgentError::DBError(format!("Could not query address state. {:?}", err))
        })?;

        Ok(address_exist)
    }

    fn store_address(&mut self, address: &Ipv4Address, expire_at: u64) -> Result<(), AgentError> {
        // Store the address
        let _: () = self
            .connection
            .set(address, true)
            .map_err(|err| AgentError::DBError(format!("Could not store ip address. {:?}", err)))?;

        // Set the expiration
        let _: () = self
            .connection
            .expire_at(address, expire_at as usize)
            .map_err(|err| AgentError::DBError(format!("Could address expiration. {:?}", err)))?;

        Ok(())
    }
}
