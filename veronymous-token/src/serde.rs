use crate::error::VeronymousTokenError;

pub trait Serializable {
    fn serialize(&self) -> Vec<u8>;

    fn deserialize(bytes: &[u8]) -> Result<Self, VeronymousTokenError>
    where
        Self: Sized;
}
