use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum CommitmentError {
    #[error("Invalid argument. {0}")]
    InvalidArgumentError(String),
}
