use std::fs;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::thread_rng;
use tonic::Request;
use tonic::transport::{Channel, Endpoint};
use crypto_common::rand_non_zero_fr;
use ps_signatures::keys::{PsParams, PsPublicKey};
use ps_signatures::serde::Serializable;
use veronymous_token::root_exchange::{complete_root_token, create_root_token_request, RootTokenResponse};
use veronymous_token::serde::Serializable as TokenSerializable;
use veronymous_token::token::{get_current_epoch, get_now_u64, VeronymousToken};
use crate::common::token_issuer::grpc::veronymous_token_info_service::TokenInfoRequest;
use crate::common::token_issuer::grpc::veronymous_token_info_service::veronymous_token_info_service_client::VeronymousTokenInfoServiceClient;
use crate::common::token_issuer::grpc::veronymous_token_service::TokenRequest;
use crate::common::token_issuer::grpc::veronymous_token_service::veronymous_token_service_client::VeronymousTokenServiceClient;

mod grpc;

const CLIENT_CERT: &str = "./certs/token-issuer/client.pem";
const CLIENT_CERT_KEY: &str = "./certs/token-issuer/client.key";

const TLS_CA: &str = "./certs/token-issuer/tls_ca.pem";

const TOKEN_ISSUER_ENDPOINT: &str = "https://localhost.veronymous.io:30041";

const AUTH_DOMAIN: &str = "dev_domain";

// 10 minutes
const EPOCH_LENGTH: u64 = 600;
// 1 minute
const EPOCH_BUFFER: u64 = 60;
// 10 minutes
const KEY_LIFETIME: u64 = 600;

pub struct TokenManager {
    token_info_service: VeronymousTokenInfoServiceClient<Channel>,

    token_service: VeronymousTokenServiceClient<Channel>,
}

impl TokenManager {
    pub async fn create() -> Self {
        // TLS Encryption ca
        let tls_ca = fs::read(TLS_CA).unwrap();
        let tls_ca = tonic::transport::Certificate::from_pem(tls_ca);

        // TLS authentication credentials
        let auth_cert = fs::read(CLIENT_CERT).unwrap();
        let auth_cert_key = fs::read(CLIENT_CERT_KEY).unwrap();

        let auth_id = tonic::transport::Identity::from_pem(&auth_cert, &auth_cert_key);

        // TLS Config
        let tls_config = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tls_ca)
            .identity(auth_id);

        // Token issuer endpoint
        let endpoint = Endpoint::from_str(TOKEN_ISSUER_ENDPOINT)
            .unwrap()
            .tls_config(tls_config)
            .unwrap();

        // Create the clients
        let token_info_service = VeronymousTokenInfoServiceClient::connect(endpoint.clone())
            .await
            .unwrap();
        let token_service = VeronymousTokenServiceClient::connect(endpoint.clone())
            .await
            .unwrap();

        Self {
            token_info_service,
            token_service,
        }
    }

    // Issues a root token_issuer and derives an auth token_issuer from it
    pub async fn get_auth_token(&mut self, num_tokens: usize) -> Vec<VeronymousToken> {
        // Get the issuer info
        // let issuer_info = self
        //     .token_info_service
        //     .get_token_info(Request::new(TokenInfoRequest {}))
        //     .await
        //     .unwrap();
        let issuer_info = match Self::is_in_buffer() {
            true => self
                .token_info_service
                .get_next_token_info(Request::new(TokenInfoRequest {}))
                .await
                .unwrap(),
            false => self
                .token_info_service
                .get_token_info(Request::new(TokenInfoRequest {}))
                .await
                .unwrap()
        };

        let issuer_info = issuer_info.into_inner();

        let ps_params = PsParams::deserialize(&issuer_info.params).unwrap();
        let public_key = PsPublicKey::deserialize(&issuer_info.public_key).unwrap();

        // Generate the secret key
        let mut rng = thread_rng();

        let token_id = rand_non_zero_fr(&mut rng);
        let blinding = rand_non_zero_fr(&mut rng);

        // Create the root token_issuer request
        let token_request =
            create_root_token_request(&token_id, &blinding, &public_key, &ps_params).unwrap();
        let token_request = token_request.serialize();

        // Send the root token_issuer request
        let token_response = match Self::is_in_buffer() {
            true => self.token_service
                .issue_next_token(Request::new(TokenRequest { token_request }))
                .await
                .unwrap(),
            false => self.token_service
                .issue_token(Request::new(TokenRequest { token_request }))
                .await
                .unwrap()
        };

        let token_response =
            RootTokenResponse::deserialize(&token_response.into_inner().token_response).unwrap();

        // Complete the root token_issuer

        let root_token = complete_root_token(
            &token_response,
            &token_id,
            &blinding,
            &public_key,
            &ps_params,
        )
            .unwrap();

        // Get now
        let now = SystemTime::now();
        let now = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let epoch = get_current_epoch(now, EPOCH_LENGTH, EPOCH_BUFFER);

        let mut auth_tokens = Vec::with_capacity(num_tokens);

        for _ in 0..num_tokens {
            // Derive an authentication token_issuer
            let auth_token = root_token
                .derive_token(
                    AUTH_DOMAIN.as_bytes(),
                    epoch,
                    &public_key,
                    &ps_params,
                    &mut rng,
                )
                .unwrap();

            auth_tokens.push(auth_token);
        }

        auth_tokens
    }


    fn is_in_buffer() -> bool {
        let now = get_now_u64();

        // Calculate time left in the epoch
        let remainder = now % KEY_LIFETIME;
        let time_left = KEY_LIFETIME - remainder;

        // If in the buffer
        EPOCH_BUFFER > time_left
    }
}
