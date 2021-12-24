use crate::error::ConnectionError;
use crate::model::{
    ConnectRequest, ConnectResponse, ConnectionMessage, SerializableMessage, CONNECT_REQUEST_SIZE,
    CONNECT_RESPONSE_SIZE,
};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, future};
use libp2p::core::UpgradeInfo;
use std::iter;
use libp2p::{InboundUpgrade, OutboundUpgrade};
use libp2p::swarm::NegotiatedSubstream;
use void::Void;

pub const VERONYMOUS_CONNECTION_DEV: &[u8; 37] = b"/veronymous/router/connection/0.1.dev";

#[derive(Default, Debug, Copy, Clone)]
pub struct VeronymousConnection;

impl UpgradeInfo for VeronymousConnection {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(VERONYMOUS_CONNECTION_DEV)
    }
}

impl InboundUpgrade<NegotiatedSubstream> for VeronymousConnection {
    type Output = NegotiatedSubstream;
    type Error = Void;
    type Future =  future::Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, stream: NegotiatedSubstream, _info: Self::Info) -> Self::Future {
        future::ok(stream)
    }
}

impl OutboundUpgrade<NegotiatedSubstream> for VeronymousConnection {
    type Output = NegotiatedSubstream;
    type Error = Void;
    type Future = future::Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, stream: NegotiatedSubstream, _info: Self::Info) -> Self::Future {
        future::ok(stream)
    }
}

pub struct ConnectionClient {}

impl ConnectionClient {
    pub async fn send_connect_request<S>(
        connect_request: &ConnectRequest,
        mut stream: S,
    ) -> Result<(ConnectResponse, S), ConnectionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Construct the request
        let message = ConnectionMessage::ConnectRequest(connect_request.clone());
        let payload = message.to_bytes();

        // Send the request
        stream
            .write_all(&payload)
            .await
            .map_err(|e| ConnectionError::IoError(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| ConnectionError::IoError(e.to_string()))?;

        // Read the response
        let mut payload = [0u8; CONNECT_RESPONSE_SIZE + 1];

        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| ConnectionError::IoError(e.to_string()))?;

        // Decode the payload
        let connection_message = ConnectionMessage::from_bytes(&payload)?;

        let connect_response =
            if let ConnectionMessage::ConnectResponse(message) = connection_message {
                message
            } else {
                return Err(ConnectionError::BadRequestError(format!(
                    "Bad request. Message must be a 'connect_response'"
                )));
            };

        Ok((connect_response, stream))
    }
}

pub struct ConnectionServer {}

impl ConnectionServer {
    async fn receive_connection_message<S>(mut stream: S) -> Result<([u8; 32], S), ConnectionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Read bytes from the stream
        let mut payload = [0u8; CONNECT_REQUEST_SIZE + 1];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| ConnectionError::IoError(e.to_string()))?;

        // Decode the bytes
        let connection_message = ConnectionMessage::from_bytes(&payload)?;

        let connect_request = if let ConnectionMessage::ConnectRequest(message) = connection_message
        {
            message
        } else {
            return Err(ConnectionError::BadRequestError(format!(
                "Bad request. Message must be a 'connect_request'"
            )));
        };

        // TODO: Process request
        // Construct the response
        let response_message = ConnectionMessage::ConnectResponse(ConnectResponse::new(true));

        // Send the response
        stream
            .write_all(&response_message.to_bytes())
            .await
            .map_err(|e| ConnectionError::IoError(e.to_string()))?;

        Ok((connect_request.public_key, stream))
    }
}

/*
* Inspired by Example: https://github.com/libp2p/rust-libp2p/blob/master/protocols/ping/src/protocol.rs
*/
#[cfg(test)]
mod tests {
    //use crate::client;
    use crate::model::ConnectRequest;
    use crate::protocol::{ConnectionClient, ConnectionServer};
    use futures::{FutureExt, StreamExt};
    use libp2p::core::transport::memory::Channel;
    use libp2p::core::transport::{memory::MemoryTransport, ListenerEvent, Transport};
    use libp2p::multiaddr::multiaddr;
    use rand::{thread_rng, Rng};

    #[actix_rt::test]
    async fn connect() {
        let mem_addr = multiaddr!(Memory(thread_rng().gen::<u64>()));
        let mut listener = MemoryTransport.listen_on(mem_addr).unwrap();

        let listener_addr =
            if let Some(Some(Ok(ListenerEvent::NewAddress(a)))) = listener.next().now_or_never() {
                a
            } else {
                panic!("MemoryTransport not listening on an address!");
            };

        // Test the server
        async_std::task::spawn(async move {
            let listener_event = listener.next().await.unwrap();

            let (listener_upgrade, _) = listener_event.unwrap().into_upgrade().unwrap();
            let conn = listener_upgrade.await.unwrap();

            let (peer, _) = ConnectionServer::receive_connection_message(conn)
                .await
                .unwrap();

            assert_eq!(connect_request_object().public_key, peer);
        });

        async {
            let channel: Channel<Vec<u8>> =
                MemoryTransport.dial(listener_addr).unwrap().await.unwrap();

            let connect_request = connect_request_object();

            let (response, _) = ConnectionClient::send_connect_request(&connect_request, channel)
                .await
                .unwrap();

            assert!(response.accepted);
        }
        .await;
    }

    fn connect_request_object() -> ConnectRequest {
        ConnectRequest::new([
            148, 59, 217, 215, 192, 60, 91, 222, 49, 113, 226, 92, 207, 79, 18, 57, 42, 23, 23, 8,
            64, 149, 105, 64, 85, 86, 121, 15, 13, 212, 3, 65,
        ])
    }
}
