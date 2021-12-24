// TODO: Add start connection request? To make sure router is not at capacity

use crate::error::ConnectionError;

const KEY_SIZE: usize = 32;

pub const CONNECT_REQUEST_SIZE: usize = KEY_SIZE;
pub const CONNECT_RESPONSE_SIZE: usize = 1;

/*
* TODO: Make sure all big-endian
*/
pub trait SerializableMessage {
    fn to_bytes(&self) -> Vec<u8>;

    fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectionError>
    where
        Self: Sized;
}
#[derive(Clone, Debug, PartialEq)]
pub struct ConnectRequest {
    pub public_key: [u8; KEY_SIZE],
    // TODO
}

impl ConnectRequest {
    pub fn new(public_key: [u8; 32]) -> Self {
        Self { public_key }
    }
}

impl SerializableMessage for ConnectRequest {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CONNECT_REQUEST_SIZE);
        bytes.extend_from_slice(&self.public_key);

        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectionError>
    where
        Self: Sized,
    {
        if bytes.len() != CONNECT_REQUEST_SIZE {
            return Err(ConnectionError::DeserializationError(format!(
                "Byte string is of invalid length. Expected length: {}, length of byte string: {}",
                CONNECT_REQUEST_SIZE,
                bytes.len()
            )));
        }

        Ok(Self {
            public_key: bytes.try_into().unwrap(),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConnectResponse {
    pub accepted: bool,
    // TODO
}

impl ConnectResponse {
    pub fn new(accepted: bool) -> Self {
        Self { accepted }
    }
}

impl SerializableMessage for ConnectResponse {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CONNECT_RESPONSE_SIZE);
        bytes.push((self.accepted as u8).to_be());

        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectionError>
    where
        Self: Sized,
    {
        if bytes.len() != CONNECT_RESPONSE_SIZE {
            return Err(ConnectionError::DeserializationError(format!(
                "Byte string is of invalid length. Expected length: {}, length of byte string: {}",
                CONNECT_RESPONSE_SIZE,
                bytes.len()
            )));
        }

        let accepted = match bytes[0] {
            0 => false,
            1 => true,
            _ => {
                return Err(ConnectionError::DeserializationError(format!(
                    "Invalid boolean. Must be 1 or 0"
                )));
            }
        };

        Ok(Self { accepted })
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{ConnectRequest, ConnectResponse, SerializableMessage};

    #[test]
    fn serialization_tests() {
        let connect_request = connect_request();

        // Serialize
        let serialized = connect_request.to_bytes();

        // Deserialize
        let result = ConnectRequest::from_bytes(&serialized);
        assert!(result.is_ok());

        let deserialized = result.unwrap();
        assert_eq!(connect_request, deserialized);

        let connect_response = connect_response();

        // Serialize
        let serialized = connect_response.to_bytes();

        // Deserialize
        let result = ConnectResponse::from_bytes(&serialized);
        assert!(result.is_ok());

        let deserialized = result.unwrap();
        assert_eq!(connect_response, deserialized);

        // Connection response with accepted = false
        let mut connect_response = connect_response.clone();
        connect_response.accepted = false;

        // Serialize
        let serialized = connect_response.to_bytes();

        // Deserialize
        let result = ConnectResponse::from_bytes(&serialized);
        assert!(result.is_ok());

        let deserialized = result.unwrap();
        assert_eq!(connect_response, deserialized)
    }

    fn connect_request() -> ConnectRequest {
        ConnectRequest {
            public_key: [
                148, 59, 217, 215, 192, 60, 91, 222, 49, 113, 226, 92, 207, 79, 18, 57, 42, 23, 23,
                8, 64, 149, 105, 64, 85, 86, 121, 15, 13, 212, 3, 65,
            ],
        }
    }

    fn connect_response() -> ConnectResponse {
        ConnectResponse { accepted: true }
    }
}
