use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum RouterClientError {
    #[error("GRPC error. {0}")]
    GrpcError(String),

    #[error("Connect error. {0}")]
    ConnectError(String),

    #[error("Decoding error. {0}")]
    DecodingError(String),
}
