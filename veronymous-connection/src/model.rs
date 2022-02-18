use crate::error::ConnectionError;
use ps_signatures::keys::{PsParams, PsPublicKey};
use std::io::{Cursor, Read};
use veronymous_token::serde::Serializable;
use veronymous_token::token::VeronymousToken;

const KEY_SIZE: usize = 32;
const IPV4_ADDRESS_SIZE: usize = 4;

const SERIALIZED_TOKEN_SIZE: usize = 544;

pub const CONNECT_REQUEST_SIZE: usize = KEY_SIZE + SERIALIZED_TOKEN_SIZE;
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
            ConnectMessage::ConnectResponse(message) => (CONNECT_RESPONSE_ID, message.to_bytes()),
        };

        message_bytes.insert(0, id);

        message_bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectionError>
        where
            Self: Sized,
    {
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
            _ => {
                return Err(ConnectionError::DeserializationError(format!(
                    "Invalid identifier: {}",
                    id
                )));
            }
        };

        Ok(message)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConnectRequest {
    // The client's Wireguard public key
    pub public_key: PublicKey,

    pub token: VeronymousToken,
}

impl ConnectRequest {
    pub fn new(public_key: [u8; KEY_SIZE], token: VeronymousToken) -> Self {
        Self { public_key, token }
    }

    // TODO: Return serial number
    pub fn verify(
        &self,
        domain: &[u8],
        epoch: u64,
        public_key: &PsPublicKey,
        params: &PsParams,
    ) -> Result<bool, ConnectionError> {
        let result = self.token
            .verify(domain, epoch, public_key, params)
            .map_err(|e| {
                ConnectionError::VerificationError(format!("Could not verify token. {:?}", e))
            })?;

        Ok(result)
    }
}

impl SerializableMessage for ConnectRequest {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CONNECT_REQUEST_SIZE);
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.token.serialize());

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

        let mut cursor = Cursor::new(bytes);

        // Extract the public key
        let mut public_key: [u8; KEY_SIZE] = [0; KEY_SIZE];
        cursor.read_exact(&mut public_key).unwrap();

        // Extract the token
        let mut token: [u8; SERIALIZED_TOKEN_SIZE] = [0; SERIALIZED_TOKEN_SIZE];
        cursor.read_exact(&mut token).unwrap();

        // Decode the token
        let token = VeronymousToken::deserialize(&token).map_err(|e| {
            ConnectionError::DeserializationError(format!("Could not decode token. {:?}", e))
        })?;

        Ok(Self {
            public_key: public_key.try_into().unwrap(),
            token,
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

        Ok(Self {
            accepted,
            address: address.try_into().unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{ConnectMessage, ConnectRequest, ConnectResponse, SerializableMessage};
    use veronymous_token::serde::Serializable;
    use veronymous_token::token::VeronymousToken;

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
        ConnectMessage::ConnectRequest(ConnectRequest {
            public_key: [
                148, 59, 217, 215, 192, 60, 91, 222, 49, 113, 226, 92, 207, 79, 18, 57, 42, 23, 23,
                8, 64, 149, 105, 64, 85, 86, 121, 15, 13, 212, 3, 65,
            ],
            token: VeronymousToken::deserialize(&[
                148, 45, 172, 184, 183, 56, 246, 125, 113, 152, 133, 174, 140, 156, 101, 23, 128,
                7, 109, 168, 153, 173, 45, 189, 16, 26, 131, 124, 77, 232, 139, 26, 241, 19, 20,
                66, 38, 132, 119, 142, 26, 136, 224, 31, 64, 145, 229, 129, 18, 102, 91, 213, 125,
                155, 149, 238, 232, 136, 169, 203, 126, 73, 150, 62, 121, 137, 104, 5, 125, 125,
                190, 76, 151, 78, 60, 139, 19, 138, 102, 89, 235, 94, 66, 248, 155, 4, 226, 72,
                149, 179, 35, 143, 112, 243, 192, 125, 149, 90, 79, 112, 236, 113, 156, 6, 77, 45,
                176, 105, 12, 21, 6, 203, 230, 91, 16, 224, 132, 24, 27, 123, 10, 89, 234, 211,
                121, 170, 152, 231, 229, 92, 67, 171, 132, 193, 163, 241, 75, 13, 210, 176, 50,
                124, 173, 243, 25, 127, 241, 219, 78, 254, 173, 19, 68, 145, 97, 85, 170, 118, 78,
                242, 88, 118, 116, 20, 0, 225, 167, 161, 231, 241, 110, 221, 118, 93, 187, 148,
                176, 145, 124, 252, 41, 54, 147, 167, 42, 75, 202, 82, 193, 44, 229, 231, 35, 208,
                53, 176, 149, 250, 126, 122, 93, 22, 103, 90, 0, 141, 149, 17, 80, 218, 23, 225,
                114, 244, 200, 107, 148, 150, 122, 35, 22, 224, 52, 72, 138, 175, 68, 254, 228,
                153, 194, 176, 237, 90, 202, 101, 175, 50, 126, 238, 17, 218, 225, 206, 57, 100,
                35, 248, 163, 11, 233, 23, 190, 188, 24, 35, 92, 82, 15, 99, 6, 176, 37, 152, 167,
                158, 127, 241, 81, 250, 188, 71, 141, 167, 208, 65, 49, 2, 19, 196, 55, 218, 53,
                215, 12, 237, 235, 138, 69, 167, 159, 195, 32, 244, 57, 200, 10, 222, 52, 109, 86,
                50, 48, 45, 22, 20, 48, 36, 170, 5, 134, 165, 14, 207, 18, 128, 170, 187, 201, 212,
                135, 201, 236, 50, 207, 239, 99, 242, 39, 255, 229, 203, 104, 215, 101, 111, 175,
                49, 85, 58, 112, 216, 96, 99, 156, 246, 189, 62, 138, 8, 151, 122, 208, 63, 243,
                143, 246, 208, 156, 85, 181, 131, 128, 207, 242, 145, 72, 64, 5, 167, 251, 80, 255,
                124, 87, 198, 74, 225, 230, 42, 12, 68, 32, 255, 99, 13, 141, 37, 223, 162, 34,
                194, 42, 185, 177, 50, 191, 72, 191, 159, 118, 43, 220, 205, 165, 191, 213, 221,
                117, 2, 100, 72, 82, 83, 163, 132, 142, 138, 128, 227, 45, 175, 106, 144, 48, 173,
                173, 210, 198, 41, 241, 151, 5, 219, 79, 180, 182, 247, 35, 166, 243, 51, 77, 83,
                192, 145, 222, 109, 239, 159, 157, 129, 125, 235, 236, 59, 109, 127, 56, 20, 138,
                66, 113, 204, 15, 18, 62, 215, 166, 171, 164, 220, 215, 11, 141, 246, 44, 68, 123,
                141, 251, 238, 73, 70, 51, 121, 80, 132, 185, 209, 28, 0, 99, 51, 95, 71, 139, 66,
                245, 26, 178, 139, 60, 125, 192, 102, 67, 97, 139, 124, 101, 210, 22, 211, 5, 144,
                191, 114, 176, 17, 164, 112, 132, 121, 108, 153, 216, 152, 183, 27, 107, 174, 2,
                105, 133, 249, 69, 238, 16, 81, 226, 255, 133, 61,
            ])
                .unwrap(),
        })
    }

    fn connect_response() -> ConnectMessage {
        ConnectMessage::ConnectResponse(ConnectResponse {
            accepted: true,
            address: [10, 0, 8, 1],
        })
    }
}
