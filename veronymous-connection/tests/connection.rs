/*use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport;
use libp2p::core::transport::upgrade;
use libp2p::noise::{Keypair, NoiseConfig, X25519Spec};
use libp2p::request_response::{
    ProtocolSupport, RequestResponse, RequestResponseConfig, RequestResponseEvent,
    RequestResponseMessage,
};
use libp2p::swarm::SwarmEvent;
use libp2p::tcp::TcpConfig;
use libp2p::{identity, Multiaddr, PeerId, Transport};
use libp2p::{mplex, Swarm};
use std::iter;
use veronymous_connection::model::{ConnectRequest, ConnectResponse};
use veronymous_connection::protocol::client::{ConnectionClientCodec, ConnectionClientProtocol};
use veronymous_connection::protocol::server::{ConnectionServerCodec, ConnectionServerProtocol};

#[test]
fn connection_protocol() {
    let config = RequestResponseConfig::default();

    let client_protocols = iter::once((ConnectionClientProtocol(), ProtocolSupport::Full));

    // Setup the client
    let (client_peer_id, transport) = mk_transport();
    let client_proto = RequestResponse::new(
        ConnectionClientCodec(),
        client_protocols.clone(),
        config.clone(),
    );
    let mut client_swarm = Swarm::new(transport, client_proto, client_peer_id);

    // Setup the server
    let server_protocols = iter::once((ConnectionServerProtocol(), ProtocolSupport::Full));

    let (server_peer_id, transport) = mk_transport();
    let server_proto = RequestResponse::new(ConnectionServerCodec(), server_protocols, config);
    let mut server_swarm = Swarm::new(transport, server_proto, server_peer_id);

    let (mut tx, mut rx) = mpsc::channel::<Multiaddr>(1);
    let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    server_swarm.listen_on(addr).unwrap();

    let connect_request = connect_request_object();
    let connect_response = connect_response_object();

    let server = async move {
        loop {
            match server_swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => tx.send(address).await.unwrap(),
                SwarmEvent::Behaviour(RequestResponseEvent::Message {
                    peer,
                    message:
                        RequestResponseMessage::Request {
                            request, channel, ..
                        },
                }) => {
                    assert_eq!(&connect_request, &request);
                    assert_eq!(&client_peer_id, &peer);

                    server_swarm
                        .behaviour_mut()
                        .send_response(channel, connect_response.clone())
                        .unwrap();
                }
                SwarmEvent::Behaviour(RequestResponseEvent::ResponseSent { peer, .. }) => {
                    assert_eq!(peer, client_peer_id)
                }
                SwarmEvent::Behaviour(e) => panic!("Server: Unexpected event: {:?}", e),
                _ => {}
            }
        }
    };

    let client = async move {
        let addr = rx.next().await.unwrap();
        client_swarm
            .behaviour_mut()
            .add_address(&server_peer_id, addr.clone());
        let req_id = client_swarm
            .behaviour_mut()
            .send_request(&server_peer_id, connect_request_object());
        assert!(client_swarm
            .behaviour()
            .is_pending_outbound(&server_peer_id, &req_id));

        loop {
            match client_swarm.select_next_some().await {
                SwarmEvent::Behaviour(RequestResponseEvent::Message {
                    peer,
                    message:
                        RequestResponseMessage::Response {
                            request_id,
                            response,
                        },
                }) => {
                    assert_eq!(response, connect_response_object());
                    assert_eq!(peer, server_peer_id);
                    assert_eq!(req_id, request_id);

                    return;
                }
                _ => {}
            }
        }
    };

    async_std::task::spawn(Box::pin(server));
    let () = async_std::task::block_on(client);
}

fn mk_transport() -> (PeerId, transport::Boxed<(PeerId, StreamMuxerBox)>) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = id_keys.public().to_peer_id();
    let noise_keys = Keypair::<X25519Spec>::new()
        .into_authentic(&id_keys)
        .unwrap();
    (
        peer_id,
        TcpConfig::new()
            .nodelay(true)
            .upgrade(upgrade::Version::V1)
            .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(mplex::MplexConfig::new())
            .boxed(),
    )
}

fn connect_request_object() -> ConnectRequest {
    ConnectRequest::new(
        [
            148, 59, 217, 215, 192, 60, 91, 222, 49, 113, 226, 92, 207, 79, 18, 57, 42, 23, 23, 8,
            64, 149, 105, 64, 85, 86, 121, 15, 13, 212, 3, 65,
        ],
        [13, 15, 34, 54],
        [36, 129, 234, 11],
    )
}

fn connect_response_object() -> ConnectResponse {
    ConnectResponse::new(true)
}
*/