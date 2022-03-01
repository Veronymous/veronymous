pub mod error;

use crate::error::ClientError;
use crate::ClientError::{ConnectionError, InvalidResponse, IoError};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use veronymous_connection::model::{
    ConnectMessage, ConnectRequest, ConnectResponse, PublicKey, SerializableMessage,
    CONNECT_RESPONSE_SIZE,
};
use veronymous_token::token::VeronymousToken;

pub struct VeronymousRouterClient {
    address: SocketAddr,
}

impl VeronymousRouterClient {
    pub fn new(address: SocketAddr) -> Self {
        Self { address }
    }
}

impl VeronymousRouterClient {
    pub async fn connect(
        &self,
        public_key: PublicKey,
        token: VeronymousToken,
    ) -> Result<ConnectResponse, ClientError> {
        // 1) Assemble the connection request
        let connect_request =
            ConnectMessage::ConnectRequest(ConnectRequest::new(public_key, token));

        // 2) Request to bytes
        let request_bytes = connect_request.to_bytes();

        match TcpStream::connect(self.address) {
            Ok(mut stream) => {
                // Send the request
                stream
                    .write(&request_bytes)
                    .map_err(|e| IoError(format!("Could not send request. {:?}", e)))?;

                let mut buffer = [0; CONNECT_RESPONSE_SIZE + 1];
                stream
                    .read(&mut buffer)
                    .map_err(|e| IoError(format!("Could not read response: {:?}", e)))?;

                let response = ConnectResponse::from_bytes(&buffer)
                    .map_err(|e| InvalidResponse(format!("{:?}", e)))?;

                Ok(response)
            }
            Err(e) => return Err(ConnectionError(format!("Could not connect. {:?}", e))),
        }
    }
}