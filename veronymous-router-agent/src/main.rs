mod config;
mod error;
mod server;

#[macro_use]
extern crate log;

use crate::config::VeronymousAgentConfig;
use crate::error::AgentError;
use crate::server::VeronymousRouterAgentServer;
use env_logger;

#[tokio::main]
async fn main() -> Result<(), AgentError> {
    env_logger::init();

    info!("Loading configuration files...");

    let config = VeronymousAgentConfig::load()?;

    info!("Starting server...");
    VeronymousRouterAgentServer::start(&config.address).await?;

    Ok(())
}
