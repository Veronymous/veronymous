use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum AgentError {
    #[error("Configuration error. {0}")]
    ConfigError(String),

    #[error("Initialization error. {0}")]
    InitializationError(String),
}
