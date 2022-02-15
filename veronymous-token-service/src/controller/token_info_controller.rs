use crate::grpc::veronymous_token_info_service::veronymous_token_info_service_server::VeronymousTokenInfoService;
use crate::grpc::veronymous_token_info_service::{TokenInfo, TokenInfoRequest};
use crate::{KeyManagementService, VeronymousTokenServiceConfig};
use std::sync::{Arc, Mutex};
use tonic::{Response, Status};
use ps_signatures::serde::Serializable;

pub struct VeronymousTokenInfoServiceController {
    kms: Arc<Mutex<KeyManagementService>>,

    key_lifetime: u64,
}

impl VeronymousTokenInfoServiceController {
    pub fn new(kms: Arc<Mutex<KeyManagementService>>, config: &VeronymousTokenServiceConfig) -> Self {
        Self {
            kms,
            key_lifetime: config.key_lifetime,
        }
    }
}

#[tonic::async_trait]
impl VeronymousTokenInfoService for VeronymousTokenInfoServiceController {
    async fn get_token_info(
        &self,
        _: tonic::Request<TokenInfoRequest>,
    ) -> Result<tonic::Response<TokenInfo>, tonic::Status> {
        debug!("Got 'get_token_info' request.");

        let kms = self.kms.lock().unwrap();

        let (params, public_key) = kms.get_current_public_key();

        let params = match params.serialize() {
            Ok(params) => params,
            Err(e) => {
                error!("Could not serialize ps params. {:?}", e);
                return Err(Status::internal("Could not serialize ps params"));
            }
        };

        let public_key = match public_key.serialize() {
            Ok(public_key) => public_key,
            Err(e) => {
                error!("Could not serialize public key. {:?}", e);
                return Err(Status::internal("Could not serialize public key"));
            }
        };

        let token_info = TokenInfo {
            params,
            public_key,
            key_lifetime: self.key_lifetime,
        };

        Ok(Response::new(token_info))
    }

    async fn get_next_token_info(
        &self,
        _: tonic::Request<TokenInfoRequest>,
    ) -> Result<tonic::Response<TokenInfo>, tonic::Status> {
        debug!("Got 'get_next_token_info' request");

        let kms = self.kms.lock().unwrap();

        let (params, public_key) = kms.get_next_public_key();

        let params = match params.serialize() {
            Ok(params) => params,
            Err(e) => {
                error!("Could not serialize ps params. {:?}", e);
                return Err(Status::internal("Could not serialize ps params"));
            }
        };

        let public_key = match public_key.serialize() {
            Ok(public_key) => public_key,
            Err(e) => {
                error!("Could not serialize public key. {:?}", e);
                return Err(Status::internal("Could not serialize public key"));
            }
        };

        let token_info = TokenInfo {
            params,
            public_key,
            key_lifetime: self.key_lifetime,
        };

        Ok(Response::new(token_info))
    }
}