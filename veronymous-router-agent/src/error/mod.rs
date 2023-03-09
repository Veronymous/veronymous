use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum AgentError {
    #[error("Config error. {0}")]
    ConfigError(String),

    #[error("Initialization error. {0}")]
    InitializationError(String),

    #[error("DB error. {0}")]
    DBError(String),

    #[error("IP error. {0}")]
    IpError(String),

    #[error("Service error. {0}")]
    ServiceError(String),

    #[error("Deserialization error. {0}")]
    DeserializationError(String),

    #[error("Unauthorized. {0}")]
    Unauthorized(String),
}
