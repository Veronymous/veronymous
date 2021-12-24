use super::PROTOCOL_CONNECT_DEV;
use crate::model::{ConnectRequest, ConnectResponse, SerializableMessage, CONNECT_RESPONSE_SIZE};
use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::core::ProtocolName;
use libp2p::request_response::RequestResponseCodec;

#[derive(Debug, Clone)]
pub struct ConnectionClientProtocol();

#[derive(Clone)]
pub struct ConnectionClientCodec();

impl ProtocolName for ConnectionClientProtocol {
    fn protocol_name(&self) -> &[u8] {
        PROTOCOL_CONNECT_DEV
    }
}

#[async_trait]
impl RequestResponseCodec for ConnectionClientCodec {
    type Protocol = ConnectionClientProtocol;
    type Request = ConnectRequest;
    type Response = ConnectResponse;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        _: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut response_payload = [0u8; CONNECT_RESPONSE_SIZE];
        io.read_exact(&mut response_payload).await?;

        let response = ConnectResponse::from_bytes(&response_payload)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;

        Ok(response)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&request.to_bytes()).await?;
        io.flush().await?;
        io.close().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        _: Self::Response,
    ) -> std::io::Result<()>
    where
        T: AsyncWriteExt + AsyncWrite + Unpin + Send,
    {
        io.close().await?;
        // TODO: Close socket?
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}
