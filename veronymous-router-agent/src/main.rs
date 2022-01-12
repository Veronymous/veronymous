mod config;
mod error;
mod server;
mod service;

#[macro_use]
extern crate log;

use env_logger;

use crate::config::VeronymousAgentConfig;
use crate::error::AgentError;

use crate::server::VeronymousRouterAgentServer;

#[tokio::main]
async fn main() -> Result<(), AgentError> {
    env_logger::init();

    info!("Loading configuration files...");

    let mut server = VeronymousRouterAgentServer::create().await.unwrap();
    server.start().await?;

    Ok(())
}
