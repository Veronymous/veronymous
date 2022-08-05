use crate::db::connections_state_db::ConnectionsStateDB;
use crate::{AgentError, VeronymousAgentConfig};
use rand::Rng;
use redis::{Commands, Connection};
use std::net::{Ipv4Addr, Ipv6Addr};
use veronymous_connection::model::{Ipv4Address, Ipv6Address};

/*
* Subnet mask for ipv4 is 16 bit.
* Subnet mask 112 for ipv6.
* Ipv6 same number of network ids (16 bit) as ipv4.
* NOTE: Assigns same 2 bytes host id for ipv6 and ipv4
*/
pub struct RedisConnectionsStateDB {
    gateway_ipv4: Ipv4Address,

    gateway_ipv6: Ipv6Address,

    connection: Connection,
}

impl RedisConnectionsStateDB {
    pub fn create(config: &VeronymousAgentConfig) -> Result<Self, AgentError> {
        // Parse the gateway addresses
        let gateway_ipv4: Ipv4Addr = config.wg_gateway_ipv4.parse().unwrap();
        let gateway_ipv4: Ipv4Address = gateway_ipv4.octets();

        let gateway_ipv6: Ipv6Addr = config.wg_gateway_ipv6.parse().unwrap();
        let gateway_ipv6: Ipv6Address = gateway_ipv6.octets();

        let client = redis::Client::open(config.connections_state_redis_address.as_str()).map_err(
            |err| AgentError::InitializationError(format!("Could not connect to redis. {:?}", err)),
        )?;

        let connection = client.get_connection().map_err(|err| {
            AgentError::InitializationError(format!("Could not connect to redis. {:?}", err))
        })?;

        Ok(Self {
            gateway_ipv4,
            gateway_ipv6,
            connection,
        })
    }
}

impl ConnectionsStateDB for RedisConnectionsStateDB {
    /*
     * NOTE: Possible race condition: If two agents create an address at the exact same time,
     * one connection address will be overridden
     */
    fn assign_address(&mut self, expire_at: u64) -> Result<(Ipv4Address, Ipv6Address), AgentError> {
        // Select random ip address
        let mut addresses = self.random_ip_addresses();
        let mut host_id: [u8; 2] = [addresses.0[2], addresses.0[3]];
        let mut find_address_attempts: u8 = 0;

        // Assign another if it already exists
        // Maximum 10 attempts
        while self.host_id_exist(&host_id)? {
            addresses = self.random_ip_addresses();
            host_id = [addresses.0[2], addresses.0[3]];

            find_address_attempts += 1;

            if find_address_attempts >= 20 {
                return Err(AgentError::IpError(
                    "Could not find IP address.".to_string(),
                ));
            }
        }

        // Assign the address
        self.store_host_id(&host_id, expire_at)?;

        Ok((addresses.0, addresses.1))
    }
}

impl RedisConnectionsStateDB {
    fn random_ip_addresses(&self) -> (Ipv4Address, Ipv6Address) {
        let host_id = Self::random_host_id();

        // Ipv4
        let ipv4_address = [
            self.gateway_ipv4[0],
            self.gateway_ipv4[1],
            host_id[0],
            host_id[1],
        ];

        // Ipv6
        let mut ipv6_address: [u8; 16] = [0; 16];

        // Network id
        ipv6_address[0..13].clone_from_slice(&self.gateway_ipv6[..13]);
        // Host id
        ipv6_address[14..16].clone_from_slice(&host_id);

        (ipv4_address, ipv6_address)
    }

    fn host_id_exist(&mut self, host_id: &[u8; 2]) -> Result<bool, AgentError> {
        let host_id_exist = self.connection.exists(host_id).map_err(|err| {
            AgentError::DBError(format!("Could not query host id state. {:?}", err))
        })?;

        Ok(host_id_exist)
    }

    fn store_host_id(&mut self, host_id: &[u8; 2], expire_at: u64) -> Result<(), AgentError> {
        // Store the address
        let _: () = self
            .connection
            .set(host_id, true)
            .map_err(|err| AgentError::DBError(format!("Could not store ip address. {:?}", err)))?;

        // Set the expiration
        let _: () = self
            .connection
            .expire_at(host_id, expire_at as usize)
            .map_err(|err| AgentError::DBError(format!("Could address expiration. {:?}", err)))?;

        Ok(())
    }

    fn random_host_id() -> [u8; 2] {
        let mut rng = rand::thread_rng();

        // [2-255, 0-255]
        [rng.gen_range(2, 255), rng.gen_range(0, 255)]
    }
}
