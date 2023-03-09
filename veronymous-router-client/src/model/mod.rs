use crate::error::RouterClientError;
use crate::error::RouterClientError::DecodingError;
use crate::grpc::router_agent_service::ConnectionResponse;
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct Connection {
    pub ipv4_address: Ipv4Addr,

    pub ipv6_address: Ipv6Addr,
}

impl TryFrom<ConnectionResponse> for Connection {
    type Error = RouterClientError;

    fn try_from(connection_response: ConnectionResponse) -> Result<Self, RouterClientError> {
        let ipv4_address: [u8; 4] = connection_response
            .ipv4_address
            .try_into()
            .map_err(|e| DecodingError(format!("Could not decode ipv4 address. {:?}", e)))?;
        let ipv4_address = Ipv4Addr::from(ipv4_address);

        let ipv6_address: [u8; 16] = connection_response
            .ipv6_address
            .try_into()
            .map_err(|e| DecodingError(format!("Could not decode ipv4 address. {:?}", e)))?;
        let ipv6_address = Ipv6Addr::from(ipv6_address);

        Ok(Self {
            ipv4_address,
            ipv6_address,
        })
    }
}
