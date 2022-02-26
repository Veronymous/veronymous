use crypto_common::rand_non_zero_fr;
use pairing_plus::bls12_381::{Fr, G1, G2};
use pairing_plus::CurveProjective;
use rand::CryptoRng;

#[derive(Clone, Debug)]
pub struct BbParams {
    pub g1: G1,
    pub g2: G2,
}

impl BbParams {
    pub fn generate<C: CryptoRng + rand::RngCore>(rng: &mut C) -> Self {
        Self {
            g1: G1::random(rng),
            g2: G2::random(rng),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BbSigningKey(pub Fr);

impl BbSigningKey {
    pub fn generate<C: CryptoRng + rand::RngCore>(rng: &mut C) -> Self {
        Self(rand_non_zero_fr(rng))
    }

    pub fn derive_public_key(&self, params: &BbParams) -> BbPublicKey {
        let mut g = params.g2.clone();
        g.mul_assign(self.0.clone());

        BbPublicKey(g)
    }
}

#[derive(Clone, Debug)]
pub struct BbPublicKey(pub G2);

#[cfg(test)]
mod tests {
    use crate::keys::{BbParams, BbSigningKey};
    use rand::thread_rng;

    #[test]
    fn generate_key_pair_test() {
        let mut rng = thread_rng();

        // 1) Generate the parameters
        let params = BbParams::generate(&mut rng);

        // 2) Generate the secret key
        let secret_key = BbSigningKey::generate(&mut rng);

        // 3) Derive public key
        let _public_key = secret_key.derive_public_key(&params);
    }
}
