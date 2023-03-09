#[macro_use]
extern crate log;

use crate::config::RouterAgentConfig;
use crate::connections::service::ConnectionsService;
use crate::controller::router::RouterAgentController;
use crate::db::connections_db::redis::RedisConnectionsDB;
use crate::db::token_ids_db::redis::RedisTokenIDsDB;
use crate::grpc::router_agent_service::router_agent_service_server::RouterAgentServiceServer;
use crate::router::service::RouterService;
use crate::token_issuer::service::TokenService;
use crate::wireguard::service::WireguardService;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::Server;

mod config;
mod connections;
mod controller;
mod db;
mod error;
mod grpc;
mod router;
mod token_issuer;
mod wireguard;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("Loading server...");

    // Configuration
    let config = RouterAgentConfig::load().unwrap();

    // Services

    let connections_db = RedisConnectionsDB::create(&config.connections_redis_address).unwrap();

    let wireguard_service = WireguardService::create(&config).await.unwrap();

    let connections_service =
        ConnectionsService::create(&config, wireguard_service, connections_db)
            .await
            .unwrap();

    let token_service = TokenService::create(&config).await.unwrap();

    let token_ids_db = RedisTokenIDsDB::create(&config).unwrap();

    let router_service =
        RouterService::new(&config, connections_service, token_service, token_ids_db);
    let router_service = Arc::new(Mutex::new(router_service));

    // Controller
    let router_agent_controller =
        RouterAgentServiceServer::new(RouterAgentController::new(router_service));

    // TLS encryption
    let cert = fs::read(&config.tls_cert).unwrap();
    let key = fs::read(&config.tls_key).unwrap();

    let id = tonic::transport::Identity::from_pem(cert, key);
    let tls_config = tonic::transport::ServerTlsConfig::new().identity(id);

    info!("Starting server on {}:{}", config.host, config.port);

    Server::builder()
        .tls_config(tls_config)
        .unwrap()
        .add_service(router_agent_controller)
        .serve(SocketAddr::new(config.host, config.port))
        .await?;

    Ok(())
}
