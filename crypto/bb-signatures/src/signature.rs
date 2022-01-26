use pairing_plus::bls12_381::{Bls12, Fr, G1};
use pairing_plus::{CurveProjective, Engine};
use ff_zeroize::Field;
use crate::keys::{BbParams, BbPublicKey, BbSigningKey};

#[derive(Clone, Debug)]
pub struct BbSignature(G1);

impl BbSignature {
    pub fn new(message: &Fr, key: &BbSigningKey, params: &BbParams) -> Self {
        // 1) 1 / (m + s)
        let mut ms = *message;
        ms.add_assign(&key.0);
        let ms = ms.inverse().unwrap();

        let mut signature = params.g1.clone();
        signature.mul_assign(ms);

        Self(signature)
    }

    pub fn verify(&self, message: &Fr, public_key: &BbPublicKey, params: &BbParams) -> bool {
        // Pairing 1 = e(signature, g2 ^ m * public_key) = e(g1, g2)
        let mut g_m_p = params.g2.clone();
        g_m_p.mul_assign(*message);
        g_m_p.add_assign(&public_key.0);

        let pairing_1 = Bls12::pairing(self.0, g_m_p);

        // pairing_2 = e(g1, g2)
        let pairing_2 = Bls12::pairing(params.g1, params.g2);

        pairing_1.eq(&pairing_2)
    }
}

#[cfg(test)]
mod tests {
    use pairing_plus::bls12_381::Fr;
    use rand::thread_rng;
    use ff_zeroize::Field;
    use crate::keys::{BbParams, BbSigningKey};
    use crate::signature::BbSignature;

    #[test]
    fn test_bb_signature() {
        let mut rng = thread_rng();

        // Setup
        let params = BbParams::generate(&mut rng);

        let signing_key = BbSigningKey::generate(&mut rng);
        let public_key = signing_key.derive_public_key(&params);

        // Sign a message
        let message = Fr::random(&mut rng);
        let signature = BbSignature::new(&message, &signing_key, &params);

        // Verify the signature
        let verification_result = signature.verify(&message, &public_key, &params);

        assert!(verification_result);

        // Verify bad message
        let bad_message = Fr::random(&mut rng);
        let verification_result = signature.verify(&bad_message, &public_key, &params);

        assert_eq!(false, verification_result);
    }
}