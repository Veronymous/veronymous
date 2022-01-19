use std::io::{Read, Write};
use std::net::TcpStream;
use veronymous_connection::model::{CONNECT_RESPONSE_SIZE, ConnectMessage, ConnectRequest, SerializableMessage};

const ROUTER_ADDRESS: &str = "127.0.0.1:7777";

fn main() {
    println!("Running Veronymous client test...");

    // Connect
    match TcpStream::connect(ROUTER_ADDRESS) {
        Ok(mut stream) => {
            println!("Successfully connected to: {}", ROUTER_ADDRESS);

            // Send the request message
            let request = connect_request_message();
            let request_bytes = request.to_bytes();

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

fn connect_request_message() -> ConnectMessage {
    ConnectMessage::ConnectRequest(
        ConnectRequest {
            public_key: [
                148, 59, 217, 215, 192, 60, 91, 222, 49, 113, 226, 92, 207, 79, 18, 57, 42, 23, 23,
                8, 64, 149, 105, 64, 85, 86, 121, 15, 13, 212, 3, 65,
            ],
        }
    )
}