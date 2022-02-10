use crate::grpc::veronymous_token_service::veronymous_token_service_server::VeronymousTokenService;
use crate::grpc::veronymous_token_service::{TokenRequest, TokenResponse};
use crate::TokenService;
use tonic::{Response, Status};
use veronymous_token::root_exchange::RootTokenRequest;
use veronymous_token::serde::Serializable;

pub struct VeronymousTokenServiceController {
    service: TokenService,
}

impl VeronymousTokenServiceController {
    pub fn create(service: TokenService) -> Self {
        Self { service }
    }
}

#[tonic::async_trait]
impl VeronymousTokenService for VeronymousTokenServiceController {
    async fn issue_token(
        &self,
        request: tonic::Request<TokenRequest>,
    ) -> Result<tonic::Response<TokenResponse>, tonic::Status> {
        let request = request.into_inner();

        debug!("Got 'issue_token' request: {:?}", request);

        let token_request = request.token_request;

        // parse the token request
        let token_request = match RootTokenRequest::deserialize(&token_request) {
            Ok(request) => request,
            Err(e) => {
                debug!("Could not decode veronymous root token request. {:?}", e);

                return Err(Status::invalid_argument("Invalid token request."));
            }
        };

        let token_response = match self.service.issue_token(&token_request) {
            Ok(response) => response,
            Err(e) => {
                debug!("Could not issue token response. {:?}", e);

                return Err(Status::aborted("Could not issue token"));
            }
        };

        let response = TokenResponse {
            token_response
        };

        Ok(Response::new(response))
    }
}
