pub mod redis;

use crate::error::AgentError;
use veronymous_token::SerialNumber;

pub trait TokenIDsDB {
    fn create_token_id_entry(epoch: u64, token_id: &SerialNumber) -> String {
        format!(
            "{}:{}",
            epoch,
            base64::encode_config(token_id, base64::URL_SAFE_NO_PAD)
        )
    }

    fn trace_token(
        &mut self,
        epoch: u64,
        epoch_length: u64,
        now: u64,
        token_id: &SerialNumber,
    ) -> Result<bool, AgentError>;
}
