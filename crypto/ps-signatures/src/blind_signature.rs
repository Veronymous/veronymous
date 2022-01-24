use crate::error::PsSignatureError;
use crate::keys::{Params, PublicKey, SigningKey};
use crate::signature::Signature;
use commitments::pedersen_commitment::PedersenCommitmentCommitting;
use ff_zeroize::Field;
use pairing_plus::bls12_381::{Fr, G1};
use pairing_plus::CurveProjective;
use rand::CryptoRng;

pub struct BlindSignature {}

impl BlindSignature {
    // Note: Hidden messages are not verified by this function
    pub fn new<R: CryptoRng + rand::RngCore>(
        commitment: impl Into<G1>,
        messages: &[Fr],
        signing_key: &SigningKey,
        public_key: &PublicKey,
        params: &Params,
        rng: &mut R,
    ) -> Result<Signature, PsSignatureError> {
        // Initial validation
        if messages.len() > public_key.y_cap.len() {
            return Err(PsSignatureError::InvalidArgumentError(format!(
                "Unsupported number of messages"
            )));
        }

        // Select random u
        let u = Fr::random(rng);

        // Sigma 1 = g ^ u
        let mut sigma_1 = params.g.clone();
        sigma_1.mul_assign(u);

        // Add the revealed messages to the commitment
        let mut commitment = commitment.into();

        Self::add_messages_to_commitment(&mut commitment, messages, &public_key)?;

        // Sigma 2 = (XC) ^ u
        let mut sigma_2 = signing_key.x_cap.clone();
        sigma_2.add_assign(&commitment);
        sigma_2.mul_assign(u);

        Ok(Signature { sigma_1, sigma_2 })
    }

    pub fn unblind(signature: &Signature, blinding: &Fr) -> Signature {
        // signature = (sigma_1, sigma_2 / (sigma_1 ^ t))
        let mut sigma_1_t = signature.sigma_1;
        sigma_1_t.mul_assign(*blinding);

        let mut sigma_2 = signature.sigma_2;
        sigma_2.sub_assign(&sigma_1_t);

        Signature {
            sigma_1: signature.sigma_1,
            sigma_2,
        }
    }

    fn add_messages_to_commitment(
        hidden_messages: &mut G1,
        messages: &[Fr],
        public_key: &PublicKey,
    ) -> Result<(), PsSignatureError> {
        let offset = public_key.y_cap.len() - messages.len();

        let gens = Vec::from(&public_key.y_cap[offset..public_key.y_cap.len()]);

        let committing = PedersenCommitmentCommitting::new(Some(gens), Some(messages.into()))
            .map_err(|e| PsSignatureError::SigningError(format!("{:?}", e)))?;

        let commitment = committing.finish();
        let commitment: G1 = commitment.into();

        hidden_messages.add_assign(&commitment);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::blind_signature::BlindSignature;
    use crate::keys::{Params, SigningKey};
    use crate::signature::Signature;
    use commitments::pedersen_commitment::PedersenCommitmentCommitting;
    use crypto_common::rand_non_zero_fr;
    use ff_zeroize::Field;
    use pairing_plus::bls12_381::Fr;
    use rand::thread_rng;

    #[test]
    fn test_blind_signature() {
        // Setup
        let mut rng = thread_rng();

        let params = Params::generate(&mut rng);
        let signing_key = SigningKey::generate(5, &params, &mut rng);
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
        let blinding_factor = rand_non_zero_fr();
        committing.commit(*&params.g, blinding_factor.clone());

        // NOTE: Commitment proof-of-knowledge is outside the scope of this test
        let hidden_messages_commitment = committing.finish();

        // Blind sign
        let blind_signature: Signature = BlindSignature::new(
            hidden_messages_commitment,
            &revealed_messages,
            &signing_key,
            &public_key,
            &params,
            &mut rng,
        )
            .unwrap();

        // Unblind the signature
        let signature = BlindSignature::unblind(&blind_signature, &blinding_factor);

        // Verify the signature
        let mut all_messages = vec![];
        all_messages.extend_from_slice(&hidden_messages);
        all_messages.extend_from_slice(&revealed_messages);

        let verification_result = signature
            .verify(&all_messages, &public_key, &params)
            .unwrap();

        assert!(verification_result);

        // Verify signature with invalid hidden message;
        let mut bad_messages = all_messages.clone();
        bad_messages[0] = Fr::random(&mut rng);

        let verification_result = signature
            .verify(&bad_messages, &public_key, &params)
            .unwrap();
        assert_eq!(false, verification_result);

        // Verify signature with valid message
        let mut bad_messages = all_messages.clone();
        bad_messages[3] = Fr::random(&mut rng);

        let verification_result = signature
            .verify(&bad_messages, &public_key, &params)
            .unwrap();
        assert_eq!(false, verification_result);
    }

    #[test]
    fn test_g1() {}
}
