use crate::VeronymousAgentConfig;

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

// TODO: Unit tests
// TODO: Buffer epoch

pub struct EpochService {
    epoch_length: u64,
}

impl EpochService {
    pub fn create(config: &VeronymousAgentConfig) -> Self {
        Self {
            // Convert minutes to seconds
            epoch_length: config.epoch_length * 60,
        }
    }

    pub fn epoch_duration(&self) -> Duration {
        Duration::from_secs(self.epoch_length)
    }

    pub fn next_epoch(&self) -> Instant {
        let now = SystemTime::now();
        let now_instant = Instant::now();

        let now = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Get the current epoch start
        let current_epoch = now - (now % self.epoch_length);
        let next_epoch = current_epoch + self.epoch_length;

        let time_until_next_epoch = next_epoch - now;

        now_instant + Duration::from_secs(time_until_next_epoch)
    }
}
