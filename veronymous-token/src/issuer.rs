use ps_signatures::keys::{PsParams, PsPublicKey, PsSigningKey};
use rand::CryptoRng;

#[derive(Clone, Debug)]
pub struct TokenIssuer {
    pub signing_key: PsSigningKey,

    pub public_key: PsPublicKey,

    pub params: PsParams,
}

impl TokenIssuer {
    pub fn new(signing_key: PsSigningKey, public_key: PsPublicKey, params: PsParams) -> Self {
        Self {
            signing_key,
            public_key,
            params,
        }
    }

    pub fn generate<R: CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        let params = PsParams::generate(rng);

        let signing_key = PsSigningKey::generate(1, &params, rng);

        let public_key = signing_key.derive_public_key(&params);

        Self {
            signing_key,
            public_key,
            params,
        }
    }
}
