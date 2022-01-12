use crate::error::ConnectionError;

const KEY_SIZE: usize = 32;
const IPV4_ADDRESS_SIZE: usize = 4;

//pub const CONNECT_REQUEST_SIZE: usize = KEY_SIZE + (IPV4_ADDRESS_SIZE * 2);
pub const CONNECT_REQUEST_SIZE: usize = KEY_SIZE;
pub const CONNECT_RESPONSE_SIZE: usize = 1 + IPV4_ADDRESS_SIZE;

pub const MIN_CONNECT_MESSAGE_SIZE: usize = 1;

pub const CONNECT_REQUEST_ID: u8 = 1;
pub const CONNECT_RESPONSE_ID: u8 = 2;

// TODO: Add start connection request? To make sure router is not at capacity
/*
* TODO: Make sure all big-endian
*/

pub type PublicKey = [u8; KEY_SIZE];
pub type Ipv4Address = [u8; IPV4_ADDRESS_SIZE];

pub trait SerializableMessage {
    fn to_bytes(&self) -> Vec<u8>;

    fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectionError>
        where
            Self: Sized;
}

#[derive(Clone, Debug, PartialEq)]
pub enum ConnectMessage {
    ConnectRequest(ConnectRequest),

    ConnectResponse(ConnectResponse),
}

impl SerializableMessage for ConnectMessage {
    fn to_bytes(&self) -> Vec<u8> {
        let (id, mut message_bytes) = match self {
            ConnectMessage::ConnectRequest(message) => (CONNECT_REQUEST_ID, message.to_bytes()),
            ConnectMessage::ConnectResponse(message) => (CONNECT_RESPONSE_ID, message.to_bytes())
        };

        message_bytes.insert(0, id);

        message_bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectionError> where Self: Sized {
        if bytes.len() < MIN_CONNECT_MESSAGE_SIZE {
            return Err(ConnectionError::DeserializationError(format!(
                "Byte string is of invalid length. Minimum length expected: {}, length of byte string: {}",
                MIN_CONNECT_MESSAGE_SIZE,
                bytes.len()
            )));
        }

        let id = bytes[0];

        let message = match id {
            CONNECT_REQUEST_ID => Self::ConnectRequest(ConnectRequest::from_bytes(&bytes[1..])?),
            CONNECT_RESPONSE_ID => Self::ConnectResponse(ConnectResponse::from_bytes(&bytes[1..])?),
            _ => return Err(ConnectionError::DeserializationError(format!("Invalid identifier: {}", id)))
        };

        Ok(message)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConnectRequest {
    // The client's Wireguard public key
    pub public_key: PublicKey,
}

impl ConnectRequest {
    pub fn new(
        public_key: [u8; KEY_SIZE],
    ) -> Self {
        Self {
            public_key,
        }
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

        let public_key = &bytes[0..KEY_SIZE];

        Ok(Self {
            public_key: public_key.try_into().unwrap(),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConnectResponse {
    pub accepted: bool,
    pub address: Ipv4Address,
}

impl ConnectResponse {
    pub fn new(accepted: bool, address: Ipv4Address) -> Self {
        Self { accepted, address }
    }
}

impl SerializableMessage for ConnectResponse {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CONNECT_RESPONSE_SIZE);
        bytes.push((self.accepted as u8).to_be());
        bytes.extend_from_slice(&self.address);

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

        let address = &bytes[1..5];

        Ok(Self { accepted, address: address.try_into().unwrap() })
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{ConnectMessage, ConnectRequest, ConnectResponse, SerializableMessage};

    #[test]
    fn serialization_tests() {
        let connect_request = connect_request();

        // Serialize
        let serialized = connect_request.to_bytes();

        // Deserialize
        let result = ConnectMessage::from_bytes(&serialized);
        assert!(result.is_ok());

        let deserialized = result.unwrap();
        assert_eq!(connect_request, deserialized);

        let connect_response = connect_response();

        // Serialize
        let serialized = connect_response.to_bytes();

        // Deserialize
        let result = ConnectMessage::from_bytes(&serialized);
        assert!(result.is_ok());

        let deserialized = result.unwrap();
        assert_eq!(connect_response, deserialized);
    }

    fn connect_request() -> ConnectMessage {
        ConnectMessage::ConnectRequest(
            ConnectRequest {
                public_key: [
                    148, 59, 217, 215, 192, 60, 91, 222, 49, 113, 226, 92, 207, 79, 18, 57, 42, 23, 23,
                    8, 64, 149, 105, 64, 85, 86, 121, 15, 13, 212, 3, 65,
                ],
            }
        )
    }

    fn connect_response() -> ConnectMessage {
        ConnectMessage::ConnectResponse(
            ConnectResponse {
                accepted: true,
                address: [10, 0, 8, 1],
            }
        )
    }
}
