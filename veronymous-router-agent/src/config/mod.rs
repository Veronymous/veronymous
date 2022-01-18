use std::collections::HashSet;
use crate::error::AgentError;

use config::{Config, File};
use serde::Deserialize;

const CONFIG_ENV_VAR: &str = "VERONYMOUS_ROUTER_AGENT_CONFIG";
const DEFAULT_CONFIG_LOCATION: &str = "veronymous_router_agent.yml";

#[derive(Clone, Debug, Deserialize)]
pub struct VeronymousAgentConfig {
    pub address: String,

    pub wg_addresses: HashSet<String>,

    pub epoch_length: u64,

    pub connections_redis_address: String,

    pub connections_state_redis_address: String,
}

impl VeronymousAgentConfig {
    pub fn load() -> Result<Self, AgentError> {
        let config_location =
            std::env::var(CONFIG_ENV_VAR).unwrap_or(DEFAULT_CONFIG_LOCATION.into());

        let mut config = Config::new();
        config
            .merge(File::with_name(&config_location))
            .map_err(|e| AgentError::ConfigError(e.to_string()))?;

        let config = config
            .try_into()
            .map_err(|e| AgentError::ConfigError(e.to_string()))?;

        Ok(config)
    }
}
