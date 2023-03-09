use std::fs;
use crate::common::token_issuer::TokenManager;
use tokio::test;
use veronymous_router_client::model::Connection;
use veronymous_router_client::{PublicKey, VeronymousRouterClient};

const ROUTER_AGENT_ENDPOINT: &str = "http://localhost.veronymous.io:7777";

const WG_KEY_1: &str = "GjBsuq9qjCvWihTZEBjH8wpxA5DD8w75iB4xAHFyTh0=";
const WG_KEY_2: &str = "yYoLRO9c5NrONB330mmJZcyJtq7+NQGsnxSWAHhh5kw=";

const TLS_CA: &str = "../veronymous-router-agent/certs/tls/ca.pem";

#[test]
async fn create_connection() {
    // Setup
    let mut token_issuer = TokenManager::create().await;

    // Get the tls ca
    let tls_ca = fs::read(TLS_CA).unwrap();

    // Connect to the client
    println!("Establishing connection...");
    let mut client = VeronymousRouterClient::new(&ROUTER_AGENT_ENDPOINT.to_string(), &tls_ca)
        .await
        .unwrap();

    // Issue an authentication token_issuer
    let auth_token = token_issuer.get_auth_token(1).await.remove(0);

    // Wireguard key
    let wg_key: PublicKey = base64::decode(WG_KEY_1).unwrap().try_into().unwrap();

    // Create a connection
    let connection: Connection = client.connect(wg_key, auth_token).await.unwrap();

    println!("Connection created!");
    println!(
        "Connection IPV4 ADDRESS - {}, IPV6_ADDRESS - {}",
        connection.ipv4_address.to_string(),
        connection.ipv6_address.to_string()
    );
}

// Derive two auth tokens in a single epoch
#[test]
async fn connect_token_reuse() {
    // Setup
    let mut token_issuer = TokenManager::create().await;

    // Get the tls ca
    let tls_ca = fs::read(TLS_CA).unwrap();

    // Connect to the client
    println!("Establishing connection...");
    let mut client = VeronymousRouterClient::new(&ROUTER_AGENT_ENDPOINT.to_string(), &tls_ca)
        .await
        .unwrap();

    // Issue an authentication token_issuer
    let mut auth_tokens = token_issuer.get_auth_token(2).await;
    let auth_token_1 = auth_tokens.remove(0);
    let auth_token_2 = auth_tokens.remove(0);

    // Wireguard key
    let wg_key: PublicKey = base64::decode(WG_KEY_2).unwrap().try_into().unwrap();

    // Create a connection
    let connection: Connection = client.connect(wg_key.clone(), auth_token_1).await.unwrap();

    println!("Connection created!");
    println!(
        "Connection IPV4 ADDRESS - {}, IPV6_ADDRESS - {}",
        connection.ipv4_address.to_string(),
        connection.ipv6_address.to_string()
    );

    // Try authenticating again
    // Create a connection
    let result = client.connect(wg_key.clone(), auth_token_2).await;
    assert!(result.is_err());
}
