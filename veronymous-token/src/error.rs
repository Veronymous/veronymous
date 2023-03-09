use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum VeronymousTokenError {
    #[error("Invalid argument. {0}")]
    InvalidArgumentError(String),

    #[error("Proof error. {0}")]
    ProofError(String),

    #[error("Verification error. {0}")]
    VerificationError(String),

    #[error("Invalid token_issuer. {0}")]
    InvalidToken(String),

    #[error("Signing error. {0}")]
    SigningError(String),

    #[error("Deserialization error. {0}")]
    DeserializationError(String),

    #[error("Serialization error. {0}")]
    SerializationError(String),
}
