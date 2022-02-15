use crate::error::TokenServiceException;
use crate::error::TokenServiceException::TokenError;
use crate::{KeyManagementService, VeronymousTokenServiceConfig};
use rand::thread_rng;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;
use veronymous_token::root_exchange::{issue_root_token, RootTokenRequest};
use veronymous_token::serde::Serializable as TokenSerializable;

pub struct TokenService {
    kms: Arc<Mutex<KeyManagementService>>,
}

impl TokenService {
    pub fn create(
        kms: Arc<Mutex<KeyManagementService>>,
        config: &VeronymousTokenServiceConfig,
    ) -> Self {
        let token_service = Self { kms };

        token_service.schedule_key_updates(config.key_lifetime);

        token_service
    }

    pub fn issue_token(
        &self,
        token_request: &RootTokenRequest,
    ) -> Result<Vec<u8>, TokenServiceException> {
        // Get the signing key
        let kms = self.kms.lock().unwrap();

        let signing_key = kms.get_current_signing_key();
        let (key_params, public_key) = kms.get_current_public_key();

        let mut rng = thread_rng();

        // Issue the token
        let token_response = issue_root_token(
            token_request,
            &signing_key,
            &public_key,
            &key_params,
            &mut rng,
        )
            .map_err(|e| TokenError(format!("Could not issue root token. {:?}", e)))?;

        // Serialize
        let token_response = token_response.serialize();

        Ok(token_response)
    }

    fn schedule_key_updates(&self, key_lifetime: u64) {
        info!("Scheduling key updates...");
        // Convert minutes to seconds
        let key_lifetime = key_lifetime * 60;

        let next_key_update = calculate_next_key_update(key_lifetime);
        let key_lifetime = Duration::from_secs(key_lifetime);

        let kms = self.kms.clone();

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval_at(next_key_update, key_lifetime);

            loop {
                interval_timer.tick().await;

                let mut kms = kms.lock().unwrap();

                // TODO: Catch error or panic?
                kms.load_keys().unwrap();
            }
        });
    }
}

fn calculate_next_key_update(key_lifetime: u64) -> Instant {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now_instant = Instant::now();

    let current_epoch = now - (now % key_lifetime);
    let next_epoch = current_epoch + key_lifetime;

    // Get next epoch as instant
    let time_until_next_epoch = next_epoch - now;
    let next_epoch = now_instant + Duration::from_secs(time_until_next_epoch);

    next_epoch
}