#[macro_use]
extern crate log;

mod config;
mod controller;
mod error;
mod grpc;
mod service;

use grpc::veronymous_token_info_service::veronymous_token_info_service_server::VeronymousTokenInfoServiceServer;
use grpc::veronymous_token_service::veronymous_token_service_server::VeronymousTokenServiceServer;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tonic::transport::Server;

use crate::config::VeronymousTokenServiceConfig;
use crate::controller::token_controller::VeronymousTokenServiceController;
use crate::controller::token_info_controller::VeronymousTokenInfoServiceController;
use crate::service::key_management_service::KeyManagementService;
use crate::service::token_service::TokenService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("Loading Veronymous Token Service...");
    let config = VeronymousTokenServiceConfig::load().unwrap();

    // Setup the services
    let kms = KeyManagementService::create(&config);
    let kms = Arc::new(Mutex::new(kms));

    let token_service = TokenService::create(kms.clone(), &config);

    // Setup the controllers
    let token_controller =
        VeronymousTokenServiceServer::new(VeronymousTokenServiceController::create(token_service));

    let token_info_controller = VeronymousTokenInfoServiceServer::new(
        VeronymousTokenInfoServiceController::new(kms.clone(), &config),
    );

    info!("Starting server on {}:{}", config.host, config.port);

    Server::builder()
        .add_service(token_controller)
        .add_service(token_info_controller)
        .serve(SocketAddr::new(config.host, config.port))
        .await?;

    Ok(())
}
