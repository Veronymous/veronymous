use ff_zeroize::Field;
use pairing_plus::bls12_381::Fr;
use pairing_plus::bls12_381::{G1, G2};
use pairing_plus::CurveProjective;
use rand::CryptoRng;

/*
* TODO: Verification key different from PublicKey?
*/

#[derive(Clone, Debug)]
pub struct Params {
    pub g: G1,
    pub g_tilde: G2,
}

impl Params {
    pub fn generate<C: CryptoRng + rand::RngCore>(rng: &mut C) -> Self {
        Self {
            g: G1::random(rng),
            g_tilde: G2::random(rng),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SigningKey {
    pub x: Fr,
    pub y: Vec<Fr>,
    pub x_cap: G1,
}

impl SigningKey {
    pub fn generate<C: CryptoRng + rand::RngCore>(
        message_count: usize,
        params: &Params,
        rng: &mut C,
    ) -> Self {
        // 1) Generate x
        let x = Fr::random(rng);

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

    pub fn derive_public_key(&self, params: &Params) -> PublicKey {
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

        PublicKey {
            y_cap,
            x_cap_tilde,
            y_cap_tilde,
        }
    }
}

// For blind signature and verification
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub y_cap: Vec<G1>,
    pub x_cap_tilde: G2,
    pub y_cap_tilde: Vec<G2>,
}

#[cfg(test)]
mod tests {
    use crate::keys::{Params, SigningKey};

    #[test]
    fn generate_key_pair_test() {
        let mut rng = rand::thread_rng();

        let params = Params::generate(&mut rng);

        let signing_key = SigningKey::generate(5, &params, &mut rng);

        let _public_key = signing_key.derive_public_key(&params);
    }
}
