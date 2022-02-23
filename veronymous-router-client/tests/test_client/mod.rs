mod grpc;

use crypto_common::rand_non_zero_fr;
use ps_signatures::keys::{PsParams, PsPublicKey};
use ps_signatures::serde::Serializable;
use rand::thread_rng;
use std::str::FromStr;
use tonic::transport::{Channel, Endpoint};
use veronymous_token::root::RootVeronymousToken;
use veronymous_token::root_exchange::{
    complete_root_token, create_root_token_request, RootTokenResponse,
};
use veronymous_token::serde::Serializable as _;

use crate::test_client::grpc::token_info_service::veronymous_token_info_service_client::VeronymousTokenInfoServiceClient;
use crate::test_client::grpc::token_info_service::TokenInfoRequest;

use crate::test_client::grpc::token_service::veronymous_token_service_client::VeronymousTokenServiceClient;
use crate::test_client::grpc::token_service::TokenRequest;

const TOKEN_SERVICE_ENDPOINT: &str = "http://127.0.0.1:50051";

pub struct TestClient {
    token_info_client: VeronymousTokenInfoServiceClient<Channel>,

    token_client: VeronymousTokenServiceClient<Channel>,
}

impl TestClient {
    pub async fn create() -> Self {
        let endpoint = Endpoint::from_str(TOKEN_SERVICE_ENDPOINT).unwrap();

        let token_info_client = VeronymousTokenInfoServiceClient::connect(endpoint.clone())
            .await
            .unwrap();

        let token_client = VeronymousTokenServiceClient::connect(endpoint)
            .await
            .unwrap();

        Self {
            token_info_client,
            token_client,
        }
    }

    pub async fn create_root_token(&mut self) -> (PsParams, PsPublicKey, RootVeronymousToken) {
        // Get the token info
        let (params, public_key) = self.get_token_info().await;

        // Create the token request
        let mut rng = thread_rng();

        let token_id = rand_non_zero_fr(&mut rng);
        let blinding = rand_non_zero_fr(&mut rng);

        let request =
            create_root_token_request(&token_id, &blinding, &public_key, &params).unwrap();
        let token_request = request.serialize();

        let token_request = TokenRequest { token_request };

        let token_response = self
            .token_client
            .issue_token(tonic::Request::new(token_request))
            .await
            .unwrap()
            .into_inner()
            .token_response;

        let token_response = RootTokenResponse::deserialize(&token_response).unwrap();

        let root_token =
            complete_root_token(&token_response, &token_id, &blinding, &public_key, &params)
                .unwrap();

        (params, public_key, root_token)
    }

    async fn get_token_info(&mut self) -> (PsParams, PsPublicKey) {
        let request = TokenInfoRequest {};

        let token_info = self
            .token_info_client
            .get_token_info(tonic::Request::new(request))
            .await
            .unwrap()
            .into_inner();

        let params = PsParams::deserialize(&token_info.params).unwrap();
        let public_key = PsPublicKey::deserialize(&token_info.public_key).unwrap();

        (params, public_key)
    }
}
