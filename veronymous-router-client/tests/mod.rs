mod test_client;

use rand::thread_rng;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};
use test_client::TestClient;
use veronymous_connection::model::{
    ConnectMessage, ConnectRequest, SerializableMessage, CONNECT_RESPONSE_SIZE,
};
use veronymous_token::token::get_current_epoch;

const DOMAIN: &[u8; 10] = b"dev_domain";
const EPOCH_LENGTH: u64 = 10;
const EPOCH_BUFFER: u64 = 1;

const ROUTER_ADDRESS: &str = "127.0.0.1:7777";

const CLIENT_PUBLIC_KEY: [u8; 32] = [
    148, 59, 217, 215, 192, 60, 91, 222, 49, 113, 226, 92, 207, 79, 18, 57, 42, 23, 23, 8, 64, 149,
    105, 64, 85, 86, 121, 15, 13, 212, 3, 65,
];

// Temporary for development
#[tokio::test]
async fn client_test() {
    let mut test_client = TestClient::create().await;

    // Get the root token
    // TODO: Issue next token for buffer
    let (params, public_key, root_token) = test_client.create_root_token().await;

    // Derive the auth token
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let epoch_timestamp = get_current_epoch(now, EPOCH_LENGTH * 60, EPOCH_BUFFER);

    let auth_token = root_token
        .derive_token(
            DOMAIN.as_slice(),
            epoch_timestamp,
            &public_key,
            &params,
            &mut thread_rng(),
        )
        .unwrap();

    let connect_request = ConnectMessage::ConnectRequest(ConnectRequest {
        public_key: CLIENT_PUBLIC_KEY,
        token: auth_token,
    });

    match TcpStream::connect(ROUTER_ADDRESS) {
        Ok(mut stream) => {
            println!("Successfully connected to: {}", ROUTER_ADDRESS);

            // Send the request message
            let request_bytes = connect_request.to_bytes();

            stream.write(&request_bytes).unwrap();

            let mut buffer = [0; CONNECT_RESPONSE_SIZE + 1];
            stream.read(&mut buffer).unwrap();

            println!("Got response: {:?}", buffer);
        }
        Err(err) => {
            println!("Failed to connect: {}", err);
        }
    }
}
