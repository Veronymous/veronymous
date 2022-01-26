use crypto_common::rand_non_zero_fr;
use ff_zeroize::Field;
use pairing_plus::bls12_381::Fr;
use pairing_plus::bls12_381::{G1, G2};
use pairing_plus::CurveProjective;
use rand::CryptoRng;

/*
* TODO: Verification key different from PublicKey?
*/

#[derive(Clone, Debug)]
pub struct PsParams {
    pub g: G1,
    pub g_tilde: G2,
}

impl PsParams {
    pub fn generate<C: CryptoRng + rand::RngCore>(rng: &mut C) -> Self {
        Self {
            g: G1::random(rng),
            g_tilde: G2::random(rng),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PsSigningKey {
    pub x: Fr,
    pub y: Vec<Fr>,
    pub x_cap: G1,
}

impl PsSigningKey {
    pub fn generate<C: CryptoRng + rand::RngCore>(
        message_count: usize,
        params: &PsParams,
        rng: &mut C,
    ) -> Self {
        // 1) Generate x
        let x = rand_non_zero_fr(rng);

        // 2) Generate y
        let mut y = Vec::with_capacity(message_count);

        for _ in 0..message_count {
            y.push(Fr::random(rng));
        }

        // 3) Generate X =  g ^ x
        let mut x_cap = params.g.clone();
        x_cap.mul_assign(x);

        Self { x, y, x_cap }
    }

    pub fn derive_public_key(&self, params: &PsParams) -> PsPublicKey {
        // 1) Derive Y and Y-tilde X
        let mut y_cap = Vec::with_capacity(self.y.len());
        let mut y_cap_tilde = Vec::with_capacity(self.y.len());

        for y in &self.y {
            // Y Cap
            let mut point = params.g.clone();
            point.mul_assign(y.clone());
            y_cap.push(point);

            let mut point_tilde = params.g_tilde.clone();
            point_tilde.mul_assign(y.clone());
            y_cap_tilde.push(point_tilde);
        }

        // 2) Derive X-tilde
        let mut x_cap_tilde = params.g_tilde.clone();
        x_cap_tilde.mul_assign(self.x.clone());

        PsPublicKey {
            y_cap,
            x_cap_tilde,
            y_cap_tilde,
        }
    }
}

// For blind signature and verification
#[derive(Clone, Debug)]
pub struct PsPublicKey {
    pub y_cap: Vec<G1>,
    pub x_cap_tilde: G2,
    pub y_cap_tilde: Vec<G2>,
}

#[cfg(test)]
mod tests {
    use crate::keys::{PsParams, PsSigningKey};

    #[test]
    fn generate_key_pair_test() {
        let mut rng = rand::thread_rng();

        let params = PsParams::generate(&mut rng);

        let signing_key = PsSigningKey::generate(5, &params, &mut rng);

        let _public_key = signing_key.derive_public_key(&params);
    }
}
