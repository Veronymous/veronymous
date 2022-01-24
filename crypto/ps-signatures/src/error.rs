use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum PsSignatureError {
    #[error("Invalid argument. {0}")]
    InvalidArgumentError(String),

    #[error("Signing error. {0}")]
    SigningError(String),
}
