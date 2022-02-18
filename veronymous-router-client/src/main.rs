use crypto_common::rand_non_zero_fr;
use pairing_plus::serdes::SerDes;
use ps_signatures::keys::{PsParams, PsPublicKey};
use ps_signatures::serde::Serializable as PsSerializable;
use rand::thread_rng;
use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use veronymous_connection::model::{
    ConnectMessage, ConnectRequest, SerializableMessage, CONNECT_RESPONSE_SIZE,
};
use veronymous_token::root::RootVeronymousToken;
use veronymous_token::root_exchange::{
    complete_root_token, create_root_token_request, RootTokenRequest, RootTokenResponse,
};
use veronymous_token::serde::Serializable;
use veronymous_token::{RootTokenId, TokenBlinding};

const ROUTER_ADDRESS: &str = "127.0.0.1:7777";

const TOKEN_PARAMS: [u8; 144] = [
    166, 101, 159, 0, 234, 209, 144, 111, 231, 198, 94, 98, 31, 234, 31, 161, 215, 214, 254, 239,
    220, 243, 239, 98, 223, 136, 86, 252, 77, 141, 79, 218, 10, 208, 2, 249, 54, 77, 132, 188, 4,
    199, 246, 236, 72, 60, 245, 17, 173, 82, 147, 163, 222, 213, 76, 237, 177, 106, 12, 110, 178,
    2, 29, 11, 207, 44, 36, 225, 19, 116, 49, 46, 45, 52, 66, 18, 224, 118, 75, 228, 168, 54, 33,
    18, 240, 120, 18, 85, 177, 34, 244, 64, 37, 21, 178, 252, 22, 92, 129, 12, 24, 147, 212, 177,
    220, 221, 162, 62, 77, 125, 193, 156, 52, 12, 166, 185, 183, 63, 230, 156, 216, 137, 37, 176,
    76, 92, 29, 27, 136, 217, 149, 10, 228, 109, 184, 228, 82, 36, 211, 109, 105, 58, 59, 105,
];

const TOKEN_KEY: [u8; 241] = [
    177, 174, 216, 147, 65, 129, 45, 181, 9, 135, 81, 48, 251, 159, 59, 34, 132, 9, 232, 128, 212,
    79, 195, 186, 160, 155, 28, 60, 14, 117, 181, 37, 243, 96, 220, 154, 48, 95, 198, 127, 64, 157,
    39, 254, 13, 83, 156, 96, 25, 188, 186, 3, 243, 133, 2, 125, 183, 7, 130, 144, 196, 248, 131,
    240, 112, 165, 207, 125, 53, 140, 160, 169, 70, 180, 187, 100, 139, 156, 12, 159, 73, 128, 142,
    143, 159, 151, 41, 17, 79, 46, 216, 240, 130, 182, 92, 215, 1, 183, 193, 16, 178, 122, 22, 173,
    112, 71, 86, 183, 57, 93, 31, 240, 155, 136, 36, 157, 68, 167, 203, 213, 244, 64, 42, 226, 88,
    166, 245, 208, 233, 121, 246, 192, 95, 15, 117, 153, 67, 112, 227, 93, 95, 160, 209, 52, 217,
    179, 82, 129, 187, 180, 245, 19, 8, 240, 216, 126, 49, 208, 0, 184, 20, 232, 68, 171, 57, 186,
    20, 143, 28, 205, 227, 171, 104, 174, 250, 1, 195, 215, 0, 127, 99, 171, 240, 254, 155, 20, 66,
    88, 233, 87, 197, 187, 158, 7, 12, 205, 67, 236, 254, 114, 196, 131, 123, 120, 41, 20, 249,
    216, 207, 228, 234, 130, 81, 27, 196, 191, 96, 86, 138, 36, 74, 77, 245, 20, 240, 112, 111, 54,
    144, 15, 231, 145, 231, 219, 14, 106, 42, 241, 180, 189, 167,
];

fn create_token_request() {
    // Parse the params
    let params = PsParams::deserialize(&TOKEN_PARAMS).unwrap();
    let public_key = PsPublicKey::deserialize(&TOKEN_KEY).unwrap();

    // Create the token request
    let mut rng = thread_rng();

    let token_id = rand_non_zero_fr(&mut rng);
    let blinding = rand_non_zero_fr(&mut rng);

    let request = create_root_token_request(&token_id, &blinding, &public_key, &params).unwrap();
    let request = request.serialize();

    let mut token_id_serialized = Vec::new();
    token_id.serialize(&mut token_id_serialized, true);

    let mut blinding_serialized = Vec::new();
    blinding.serialize(&mut blinding_serialized, true);

    println!("{:?}", token_id_serialized);
    println!("{:?}", blinding_serialized);
    println!("{:?}", request);
}

fn complete_token() -> RootVeronymousToken {
    // Parse the params
    let params = PsParams::deserialize(&TOKEN_PARAMS).unwrap();
    let public_key = PsPublicKey::deserialize(&TOKEN_KEY).unwrap();

    let token_id_bytes: [u8; 32] = [
        10, 26, 60, 214, 106, 8, 123, 153, 213, 149, 3, 42, 36, 205, 2, 87, 197, 144, 34, 148, 221,
        91, 107, 234, 194, 175, 142, 15, 26, 98, 201, 160,
    ];

    let blinding_bytes: [u8; 32] = [
        72, 121, 127, 50, 79, 254, 121, 150, 17, 22, 29, 210, 141, 36, 43, 75, 12, 123, 31, 57,
        254, 129, 15, 77, 8, 129, 32, 172, 185, 244, 75, 206,
    ];

    let token_response: [u8; 96] = [
        180, 70, 72, 128, 11, 220, 85, 16, 198, 126, 252, 202, 155, 174, 192, 34, 71, 207, 102,
        106, 251, 80, 196, 253, 120, 91, 135, 244, 238, 55, 31, 82, 243, 58, 20, 7, 186, 224, 195,
        162, 205, 103, 112, 138, 193, 243, 190, 79, 171, 1, 31, 192, 70, 208, 4, 11, 153, 21, 98,
        96, 221, 8, 178, 220, 119, 28, 197, 10, 215, 247, 162, 117, 161, 18, 212, 9, 15, 194, 8,
        220, 186, 23, 236, 60, 94, 208, 129, 25, 73, 34, 95, 200, 84, 233, 123, 8,
    ];

    let mut token_id_cursor = Cursor::new(&token_id_bytes);
    let token_id = RootTokenId::deserialize(&mut token_id_cursor, true).unwrap();

    let mut blinding_cursor = Cursor::new(&blinding_bytes);
    let blinding = TokenBlinding::deserialize(&mut blinding_cursor, true).unwrap();

    let token_response = RootTokenResponse::deserialize(&token_response).unwrap();

    complete_root_token(&token_response, &token_id, &blinding, &public_key, &params).unwrap()
}

fn main() {
    /*println!("Running Veronymous client test...");

    //create_token_request();
    let root_token = complete_token();

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
    }*/
}

/*
fn connect_request_message() -> ConnectMessage {
    ConnectMessage::ConnectRequest(ConnectRequest {
        public_key: [
            148, 59, 217, 215, 192, 60, 91, 222, 49, 113, 226, 92, 207, 79, 18, 57, 42, 23, 23, 8,
            64, 149, 105, 64, 85, 86, 121, 15, 13, 212, 3, 65,
        ],
    })
}*/