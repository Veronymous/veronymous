use crate::error::PsSignatureError;
use crate::keys::{Params, PublicKey};
use crypto_common::multi_scalar_mul_const_time;
use pairing_plus::bls12_381::Bls12;
use pairing_plus::bls12_381::{Fr, G1};
use pairing_plus::{CurveProjective, Engine};

#[derive(Clone, Debug)]
pub struct Signature {
    pub sigma_1: G1,
    pub sigma_2: G1,
}

impl Signature {
    pub fn verify(
        &self,
        messages: &[Fr],
        public_key: &PublicKey,
        params: &Params,
    ) -> Result<bool, PsSignatureError> {
        // 1) Check the initial parameters
        Self::check_verification_params(messages, public_key)?;

        // 2) sigma_1 != 1
        // TODO: eq() might not work as expected
        if self.sigma_1.eq(&G1::one()) {
            return Ok(false);
        }

        // 3) (sigma_1, x * y_0..y_i ^ m)
        let mut x_y_m = multi_scalar_mul_const_time(&public_key.y_cap_tilde, messages);
        x_y_m.add_assign(&public_key.x_cap_tilde);

        // 4) Pairing 1 = e(sigma_1, y_m)
        let pairing_1 = Bls12::pairing(self.sigma_1, x_y_m);

        // 5) Pairing 2 = e(sigma_2, g_tilde)
        let pairing_2 = Bls12::pairing(self.sigma_2, params.g_tilde);

        // 6) pairing_1 == pairing_2
        Ok(pairing_1.eq(&pairing_2))
    }

    fn check_verification_params(
        messages: &[Fr],
        public_key: &PublicKey,
    ) -> Result<(), PsSignatureError> {
        if messages.len() != public_key.y_cap_tilde.len() {
            return Err(PsSignatureError::InvalidArgumentError(format!(
                "Invalid number of messages."
            )));
        }

        Ok(())
    }
}
