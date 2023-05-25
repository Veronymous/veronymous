use crate::error::AgentError;
use crate::error::AgentError::ConfigError;
use config::{Config, File};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;

const CONFIG_ENV_VAR: &str = "VERONYMOUS_ROUTER_AGENT_CONFIG";
const DEFAULT_CONFIG_LOCATION: &str = "veronymous_router_agent_config.yml";

#[derive(Clone, Debug, Deserialize)]
pub struct RouterAgentConfig {
    pub host: IpAddr,

    pub port: u16,

    pub epoch_length: u64,

    pub epoch_buffer: u64,

    pub key_lifetime: u64,

    pub wg_addresses: HashSet<String>,

    // TODO: Make required
    pub wg_tls_ca: Option<String>,

    // TODO: Make required
    pub wg_client_cert: Option<String>,

    // TODO: Make required
    pub wg_client_key: Option<String>,

    // Subnet mask is 16; 0.0.0.0/16
    pub wg_gateway_ipv4: String,

    // Subnet mask is 112
    pub wg_gateway_ipv6: String,

    pub connections_redis_address: String,

    pub connections_state_redis_address: String,

    pub token_ids_redis_address: String,

    pub token_info_endpoint: String,

    pub token_info_endpoint_ca: String,

    pub token_info_endpoint_auth_cert: String,

    pub token_info_endpoint_auth_key: String,

    pub token_domain: String,

    pub tls_cert: Option<String>,

    pub tls_key: Option<String>,
}

impl RouterAgentConfig {
    pub fn load() -> Result<Self, AgentError> {
        // Get the config location
        let config_location =
            std::env::var(CONFIG_ENV_VAR).unwrap_or_else(|_| DEFAULT_CONFIG_LOCATION.into());

        // Load the config
        let mut config = Config::new();
        config
            .merge(File::with_name(&config_location))
            .map_err(|e| ConfigError(format!("{:?}", e)))?;

        Ok(config
            .try_into()
            .map_err(|e| ConfigError(format!("{:?}", e)))?)
    }
}
