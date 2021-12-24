// TODO: Investigate tokio:sync:mpsc

use std::error::Error;
use crate::protocol;
use libp2p::swarm::protocols_handler::{InboundUpgradeSend, OutboundUpgradeSend};
use libp2p::swarm::{
    KeepAlive, NegotiatedSubstream, ProtocolsHandler, ProtocolsHandlerEvent,
    ProtocolsHandlerUpgrErr, SubstreamProtocol,
};
use libp2p::OutboundUpgrade;
use std::fmt;
use std::fmt::{format, Formatter};
use std::task::{Context, Poll};
use libp2p::core::upgrade::NegotiationError;
use libp2p::core::UpgradeError;
use serde_json::ser::State;
use void::Void;

struct ConnectionHandler {}

#[derive(Debug)]
pub enum ConnectionEvent {
    ClientConnectionAccepted([u8; 32]),

    ServerAcceptedConnection(),
}

#[derive(Debug)]
pub enum ConnectionFailure {
    Timeout,

    Unsupported,

    Other {
        error: Box<dyn std::error::Error + Send + 'static>,
    },
}

impl fmt::Display for ConnectionFailure {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionFailure::Timeout => write!(f, "Connection timeout."),
            ConnectionFailure::Unsupported => write!(f, "Connection protocol unsupported."),
            ConnectionFailure::Other { error } => write!(f, "Connection error {}", error),
        }
    }
}

impl Error for ConnectionFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ConnectionFailure::Timeout => None,
            ConnectionFailure::Unsupported => None,
            ConnectionFailure::Other { error } => Some(&**error)
        }
    }
}

/*
* CODE: Inspired by https://github.com/libp2p/rust-libp2p/blob/master/protocols/ping/src/handler.rs.
* TODO: There are probably more things to do here, e.g., protocol upgrade
* TODO: Might want to separate server protocol from client protocol
*/
impl ProtocolsHandler for ConnectionHandler {
    type InEvent = Void;
    type OutEvent = ();
    type Error = ConnectionFailure;
    type InboundProtocol = protocol::VeronymousConnection;
    type OutboundProtocol = protocol::VeronymousConnection;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        todo!()
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        stream: NegotiatedSubstream,
        info: Self::InboundOpenInfo,
    ) {
        todo!()
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        stream: NegotiatedSubstream,
        info: Self::OutboundOpenInfo,
    ) {
        todo!()
    }

    fn inject_event(&mut self, event: Self::InEvent) {
        todo!()
    }

    // TODO: Proper upgrade. See https://github.com/libp2p/rust-libp2p/blob/master/protocols/identify/src/handler.rs
    // and https://github.com/libp2p/rust-libp2p/blob/master/protocols/identify/src/protocol.rs
    fn inject_dial_upgrade_error(
        &mut self,
        _info: Self::OutboundOpenInfo,
        error: ProtocolsHandlerUpgrErr<Void>,
    ) {

        let error = match error {
            ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(NegotiationError::Failed)) => {
                //debug_assert_eq!(self.state, State::Active);

                //self.state = State::Inactive { reported: false };
                //return;
                ConnectionFailure::Unsupported
            }
            // Note: This timeout only covers protocol negotiation.
            ProtocolsHandlerUpgrErr::Timeout => ConnectionFailure::Timeout,
            e => ConnectionFailure::Other { error: Box::new(e) },
        };

        // self.pending_errors.push_front(error);
        todo!()
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        todo!()
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ProtocolsHandlerEvent<
            Self::OutboundProtocol,
            Self::OutboundOpenInfo,
            Self::OutEvent,
            Self::Error,
        >,
    > {
        todo!()
    }
}
