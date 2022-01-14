use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum AgentError {
    #[error("Configuration error. {0}")]
    ConfigError(String),

    #[error("Initialization error. {0}")]
    InitializationError(String),

    #[error("IO error. {0}")]
    IoError(String),

    #[error("Bad request. {0}")]
    BadRequest(String),

    #[error("Unauthorized. {0}")]
    Unauthorized(String),

    #[error("IP error. {0}")]
    IpError(String),

    #[error("Wireguard error. {0}")]
    WireguardError(String),

    #[error("Database error. {0}")]
    DBError(String),
}
