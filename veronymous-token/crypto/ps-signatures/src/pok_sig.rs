use crate::keys::{PsParams, PsPublicKey};
use crate::signature::PsSignature;
use ff_zeroize::Field;
use pairing_plus::bls12_381::{Bls12, Fr, G1, G2};
use pairing_plus::{CurveProjective, Engine};
use rand::CryptoRng;

/*
* Signature proof of knowledge.
* Note: Payload proof outside the scope of this module
*/
#[derive(Clone, Debug)]
pub struct PsPokOfSignatureProof {
    pub sigma_1: G1,
    pub sigma_2: G1,
}

impl PsPokOfSignatureProof {
    // Create signature proof of knowledge
    pub fn new<R: CryptoRng + rand::RngCore>(
        signature: &PsSignature,
        blinding_t: Option<Fr>,
        rng: &mut R,
    ) -> Self {
        // 1) Select random t, r
        let blinding_t = match blinding_t {
            None => Fr::random(rng),
            Some(blinding_t) => blinding_t,
        };
        let blinding_r = Fr::random(rng);

        // 2) sigma_1' = sigma_1 ^ r
        let mut sigma_1_prime = signature.sigma_1;
        sigma_1_prime.mul_assign(blinding_r);

        // 3) sigma_2' = (sigma_2 * sigma_1 ^ t) ^ r
        let mut sigma_1_t = signature.sigma_1;
        sigma_1_t.mul_assign(blinding_t);

        let mut sigma_2_prime = signature.sigma_2;
        sigma_2_prime.add_assign(&sigma_1_t);
        sigma_2_prime.mul_assign(blinding_r);

        Self {
            sigma_1: sigma_1_prime,
            sigma_2: sigma_2_prime,
        }
    }

    pub fn verify(
        &self,
        public_key: &PsPublicKey,
        params: &PsParams,
        payload_commitment: impl Into<G2>,
    ) -> bool {
        // Pairing 1 = e(sigma_1, X_tilde + (Y_prime ^ m_0..m_i))
        let mut pairing_1_point_2 = payload_commitment.into();
        pairing_1_point_2.add_assign(&public_key.x_cap_tilde);

        let pairing_1 = Bls12::pairing(self.sigma_1, pairing_1_point_2);

        // Pairing 2 = e(sigma_2, g_tilde)
        let pairing_2 = Bls12::pairing(self.sigma_2, params.g_tilde);

        pairing_1.eq(&pairing_2)
    }
}

#[cfg(test)]
mod tests {
    use crate::blind_signature::PsBlindSignature;
    use crate::keys::{PsParams, PsPublicKey, PsSigningKey};
    use crate::pok_sig::PsPokOfSignatureProof;
    use crate::signature::PsSignature;
    use commitments::pedersen_commitment::PedersenCommitmentCommitting;
    use crypto_common::rand_non_zero_fr;
    use ff_zeroize::Field;
    use pairing_plus::bls12_381::Fr;
    use rand::thread_rng;

    #[test]
    fn test_pok_sig() {
        // Setup
        let (public_key, params, signature, messages) = gen_signature_values();

        let mut rng = thread_rng();

        // 1) Select shared t
        let blinding_t = Fr::random(&mut rng);

        // 2) Start the payload pedersen commitment
        let mut payload_committing = PedersenCommitmentCommitting::new(
            Some(public_key.y_cap_tilde.clone()),
            Some(messages.clone()),
        )
        .unwrap();

        // 3) Add blinding to payload committing
        payload_committing.commit(params.g_tilde, blinding_t.clone());

        // 4) Finish the payload commitment
        let payload_commitment = payload_committing.finish();

        // 5) Create PokOfSignatureProof
        let signature_proof = PsPokOfSignatureProof::new(&signature, Some(blinding_t), &mut rng);

        let verification_result = signature_proof.verify(&public_key, &params, &payload_commitment);

        assert!(verification_result);

        // Bad commitment
        let mut bad_messages = messages.clone();
        bad_messages[0] = Fr::random(&mut rng);
        let mut payload_committing = PedersenCommitmentCommitting::new(
            Some(public_key.y_cap_tilde.clone()),
            Some(bad_messages.clone()),
        )
        .unwrap();

        payload_committing.commit(params.g_tilde, blinding_t.clone());

        let bad_payload_commitment = payload_committing.finish();

        let verification_result =
            signature_proof.verify(&public_key, &params, &bad_payload_commitment);

        assert_eq!(false, verification_result);
    }

    fn gen_signature_values() -> (PsPublicKey, PsParams, PsSignature, Vec<Fr>) {
        // Setup
        let mut rng = thread_rng();

        let params = PsParams::generate(&mut rng);
        let signing_key = PsSigningKey::generate(5, &params, &mut rng);
        let public_key = signing_key.derive_public_key(&params);

        let hidden_messages = vec![Fr::random(&mut rng), Fr::random(&mut rng)];
        let revealed_messages = vec![
            Fr::random(&mut rng),
            Fr::random(&mut rng),
            Fr::random(&mut rng),
        ];

        // 1) Create the hidden messages commitment
        let mut committing = PedersenCommitmentCommitting::new(None, None).unwrap();

        // Commit the hidden messages
        for i in 0..hidden_messages.len() {
            let hidden_message = &hidden_messages[i];
            let gen = &public_key.y_cap[i];
            committing.commit(*gen, *hidden_message);
        }

        // Add the blinding factor
        let blinding_factor = rand_non_zero_fr(&mut rng);
        committing.commit(*&params.g, blinding_factor.clone());

        // NOTE: Commitment proof-of-knowledge is outside the scope of this test
        let hidden_messages_commitment = committing.finish();

        // Blind sign
        let blind_signature: PsSignature = PsBlindSignature::new(
            hidden_messages_commitment,
            &revealed_messages,
            &signing_key,
            &public_key,
            &params,
            &mut rng,
        )
        .unwrap();

        // Unblind the signature
        let signature = PsBlindSignature::unblind(&blind_signature, &blinding_factor);

        // Verify the signature
        let mut all_messages = vec![];
        all_messages.extend_from_slice(&hidden_messages);
        all_messages.extend_from_slice(&revealed_messages);

        (public_key, params, signature, all_messages)
    }
}
