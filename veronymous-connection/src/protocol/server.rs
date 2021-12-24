use super::PROTOCOL_CONNECT_DEV;
use crate::model::{ConnectRequest, ConnectResponse, SerializableMessage, CONNECT_REQUEST_SIZE};
use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::core::ProtocolName;
use libp2p::request_response::RequestResponseCodec;

#[derive(Debug, Clone)]
pub struct ConnectionServerProtocol();

#[derive(Clone)]
pub struct ConnectionServerCodec();

impl ProtocolName for ConnectionServerProtocol {
    fn protocol_name(&self) -> &[u8] {
        PROTOCOL_CONNECT_DEV
    }
}

#[async_trait]
impl RequestResponseCodec for ConnectionServerCodec {
    type Protocol = ConnectionServerProtocol;
    type Request = ConnectRequest;
    type Response = ConnectResponse;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut request_payload = [0u8; CONNECT_REQUEST_SIZE];
        io.read_exact(&mut request_payload).await?;

        let request = ConnectRequest::from_bytes(&request_payload)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;

        Ok(request)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        _: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        _: Self::Request,
    ) -> std::io::Result<()>
    where
        T: AsyncWriteExt + AsyncWrite + Unpin + Send,
    {
        io.close().await?;
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&response.to_bytes()).await?;
        io.flush().await?;
        io.close().await?;

        Ok(())
    }
}
