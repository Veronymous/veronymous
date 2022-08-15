use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum ClientError {
    #[error("Connection error. {0}")]
    ConnectionError(String),

    #[error("IO Error. {0}")]
    IoError(String),

    #[error("Invalid response. {0}")]
    InvalidResponse(String),

    #[error("Configuration error. {0}")]
    ConfigError(String),
}
