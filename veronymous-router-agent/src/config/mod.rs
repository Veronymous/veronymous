use crate::error::AgentError;
use std::collections::HashSet;

use config::{Config, File};
use serde::Deserialize;

const CONFIG_ENV_VAR: &str = "VERONYMOUS_ROUTER_AGENT_CONFIG";
const DEFAULT_CONFIG_LOCATION: &str = "veronymous_router_agent.yml";

/*
* TODO: Re-organize to contain sub-components
*/
#[derive(Clone, Debug, Deserialize)]
pub struct VeronymousAgentConfig {
    pub address: String,

    pub wg_addresses: HashSet<String>,

    pub wg_tls_ca: Option<String>,

    pub wg_client_cert: Option<String>,

    pub wg_client_key: Option<String>,

    pub tls_cert: String,

    pub tls_cert_key: String,

    pub token_info_endpoint: String,

    pub token_info_endpoint_ca: String,

    pub token_info_endpoint_auth_cert: String,

    pub token_info_endpoint_auth_key: String,

    pub token_domain: String,

    pub epoch_length: u64,

    pub epoch_buffer: u64,

    pub connections_redis_address: String,

    pub connections_state_redis_address: String,

    pub token_ids_redis_address: String,

    // Subnet mask is 16; 0.0.0.0/16
    pub wg_gateway_ipv4: String,

    // Subnet mask is 112
    pub wg_gateway_ipv6: String,
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
