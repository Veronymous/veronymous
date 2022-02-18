use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum ConnectionError {
    #[error("Deserialization error. {0}")]
    DeserializationError(String),

    #[error("IO error. {0}")]
    IoError(String),

    #[error("Bad request. {0}")]
    BadRequestError(String),

    #[error("Verification error. {0}")]
    VerificationError(String),
}
