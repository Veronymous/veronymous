use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum TokenServiceException {
    #[error("DB Error. {0}")]
    DBError(String),

    #[error("Illegal state. {0}")]
    IllegalStateError(String),

    #[error("Serialization error. {0}")]
    SerializationError(String),

    #[error("Deserialization error. {0}")]
    DeserializationError(String),

    #[error("Not found. {0}")]
    NotFoundError(String),

    #[error("Token error. {0}")]
    TokenError(String),
}
