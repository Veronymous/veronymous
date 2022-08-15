pub mod error;

use crate::error::ClientError;
use crate::ClientError::{ConnectionError, InvalidResponse, IoError};
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use tokio_rustls::webpki::TrustAnchor;
use tokio_rustls::TlsConnector;
use veronymous_connection::model::{
    ConnectMessage, ConnectRequest, ConnectResponse, PublicKey, SerializableMessage,
    CONNECT_RESPONSE_SIZE,
};
use veronymous_token::token::VeronymousToken;

pub struct VeronymousRouterClient {
    address: SocketAddr,

    domain: ServerName,

    tls_connector: TlsConnector,
}

impl VeronymousRouterClient {
    pub fn new(
        address: SocketAddr,
        domain: &str,
        root_certs: &[Vec<u8>],
    ) -> Result<Self, ClientError> {
        Ok(Self {
            tls_connector: create_tls_connector(root_certs)?,
            domain: ServerName::try_from(domain).map_err(|e| {
                ClientError::ConfigError(format!("Could not parse domain. {:?}", e))
            })?,
            address,
        })
    }
}

impl VeronymousRouterClient {
    pub async fn connect(
        &self,
        public_key: PublicKey,
        token: VeronymousToken,
    ) -> Result<ConnectResponse, ClientError> {
        // 1) Assemble the connection request
        let connect_request =
            ConnectMessage::ConnectRequest(ConnectRequest::new(public_key, token));

        // 2) Request to bytes
        let request_bytes = connect_request.to_bytes();

        // Create the tcp connection
        match TcpStream::connect(self.address).await {
            Ok(stream) => {
                // Create tls connection
                let mut stream = self
                    .tls_connector
                    .connect(self.domain.clone(), stream)
                    .await
                    .map_err(|e| {
                        ClientError::ConnectionError(format!(
                            "Could not create tls connection. {:?}",
                            e
                        ))
                    })?;

                // Send the request
                stream
                    .write(&request_bytes)
                    .await
                    .map_err(|e| IoError(format!("Could not send request. {:?}", e)))?;

                // Read the response
                let mut buffer = [0; CONNECT_RESPONSE_SIZE + 1];
                stream
                    .read(&mut buffer)
                    .await
                    .map_err(|e| IoError(format!("Could not read response: {:?}", e)))?;

                let response = ConnectMessage::from_bytes(&buffer)
                    .map_err(|e| InvalidResponse(format!("{:?}", e)))?;

                if let ConnectMessage::ConnectResponse(response) = response {
                    Ok(response)
                } else {
                    return Err(InvalidResponse(format!("Bad response.")));
                }
            }
            Err(e) => return Err(ConnectionError(format!("Could not connect. {:?}", e))),
        }
    }
}

fn create_tls_connector(root_certs: &[Vec<u8>]) -> Result<TlsConnector, ClientError> {
    let config = create_tls_config(root_certs)?;

    let tls_connector = TlsConnector::from(Arc::new(config));

    Ok(tls_connector)
}

fn create_tls_config(root_certs: &[Vec<u8>]) -> Result<ClientConfig, ClientError> {
    // Load root certs
    let root_certs = load_root_cert_store(root_certs)?;

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_certs)
        .with_no_client_auth();

    Ok(config)
}

/*
* Example at https://github.com/tokio-rs/tls/blob/87ecfe7c01aff6d96874d6e4e496bc0f2706ecac/tokio-rustls/examples/client/src/main.rs
*TODO: Fix this
*/
fn load_root_cert_store(root_certs: &[Vec<u8>]) -> Result<RootCertStore, ClientError> {
    let mut root_cert_store = RootCertStore::empty();

    let mut trust_anchors = Vec::with_capacity(root_certs.len());

    for root_cert in root_certs {
        let root_cert = rustls_pemfile::certs(&mut BufReader::new(root_cert.as_slice()))
            .map_err(|e| ClientError::ConfigError(format!("Could not load root certs. {:?}", e)))?
            .remove(0);

        let root_cert = TrustAnchor::try_from_cert_der(&root_cert)
            .map_err(|e| ClientError::ConfigError(format!("Could not parse root cer. {:?}", e)))?;

        let trust_anchor = OwnedTrustAnchor::from_subject_spki_name_constraints(
            root_cert.subject,
            root_cert.spki,
            root_cert.name_constraints,
        );

        trust_anchors.push(trust_anchor);
    }


    root_cert_store.add_server_trust_anchors(trust_anchors.into_iter());

    Ok(root_cert_store)

}
