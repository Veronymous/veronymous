use config::{Config, ConfigError, File};
use serde::Deserialize;
use std::net::IpAddr;

const CONFIG_ENV_VAR: &str = "VERONYMOUS_TOKEN_SERVICE_CONFIG";
const DEFAULT_CONFIG_LOCATION: &str = "veronymous_token_service.yml";

#[derive(Clone, Debug, Deserialize)]
pub struct VeronymousTokenServiceConfig {
    pub host: IpAddr,

    pub port: u16,

    pub key_file: String,

    pub key_lifetime: u64,
}

impl VeronymousTokenServiceConfig {
    pub fn load() -> Result<Self, ConfigError> {
        // Get the config location
        let config_location =
            std::env::var(CONFIG_ENV_VAR).unwrap_or_else(|_| DEFAULT_CONFIG_LOCATION.into());

        // Load the config
        let mut config = Config::new();
        config.merge(File::with_name(&config_location))?;

        Ok(config.try_into()?)
    }
}
