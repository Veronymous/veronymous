use crate::error::VeronymousTokenError;
use crate::error::VeronymousTokenError::ProofError;
use crate::token::{
    compute_serial_number_generator, ProofRootToken, ProofSerialNumber, VeronymousToken,
};
use commitments::pedersen_commitment::PedersenCommitmentCommitting;
use commitments::pok_pedersen_commitment::ProverCommitting;
use crypto_common::{hash_to_fr, rand_non_zero_fr};
use pairing_plus::bls12_381::{Fr, G2};
use pairing_plus::serdes::SerDes;
use pairing_plus::CurveProjective;
use ps_signatures::keys::{PsParams, PsPublicKey};
use ps_signatures::pok_sig::PsPokOfSignatureProof;
use ps_signatures::signature::PsSignature;
use rand::CryptoRng;

// TODO: Expiration
#[derive(Clone, Debug)]
pub struct RootVeronymousToken {
    pub token_id: Fr,

    pub signature: PsSignature,
}

impl RootVeronymousToken {
    pub fn verify(
        &self,
        public_key: &PsPublicKey,
        params: &PsParams,
    ) -> Result<bool, VeronymousTokenError> {
        // Verify the signature
        let signature_valid = self
            .signature
            .verify(&[self.token_id], &public_key, &params)
            .map_err(|e| {
                VeronymousTokenError::VerificationError(format!(
                    "Could not verify token signature. {:?}",
                    e
                ))
            })?;

        Ok(signature_valid)
    }

    // TODO: Find Epoch instead of timestamp
    // TODO: Expiration
    // Derive a veronymous token
    pub fn derive_token<R: CryptoRng + rand::RngCore>(
        &self,
        domain: &[u8],
        timestamp: u64,
        public_key: &PsPublicKey,
        params: &PsParams,
        rng: &mut R,
    ) -> Result<VeronymousToken, VeronymousTokenError> {
        if public_key.y_cap.len() < 1 {
            return Err(VeronymousTokenError::InvalidArgumentError(format!(
                "Public key must have at least 1 Y."
            )));
        }

        // 1) Hidden root
        let blinding_t = rand_non_zero_fr(rng);

        // hidden_root = (g ^ token_id)(g ^ blinding_t)
        let root_commitment = PedersenCommitmentCommitting::new(
            Some(vec![public_key.y_cap_tilde[0], params.g_tilde]),
            Some(vec![self.token_id.clone(), blinding_t.clone()]),
        )
        .map_err(|e| {
            VeronymousTokenError::ProofError(format!("Could not create commitment. {:?}", e))
        })?
        .finish();

        // 2) Signature proof
        let root_signature =
            PsPokOfSignatureProof::new(&self.signature, Some(blinding_t.clone()), rng);

        // 3) Derive the serial number
        let serial_number_generator = compute_serial_number_generator(domain, timestamp);
        let serial_number = self.derive_serial_number(&serial_number_generator);

        // 4) Create the proof of knowledge
        let root_blinding_factor = rand_non_zero_fr(rng);

        let mut prover_committing = ProverCommitting::new();
        prover_committing.commit(
            public_key.y_cap_tilde[0],
            Some(root_blinding_factor.clone()),
        );
        prover_committing.commit(params.g_tilde, Some(blinding_t));

        let prover_committed = prover_committing.finish();

        // Serial number randomness commitment
        let mut serial_number_commitment = serial_number_generator;
        serial_number_commitment.mul_assign(root_blinding_factor);

        // Create the challenge hash(|g1|g2|randomness_commitment|g3^blinding_t|root_commitment)
        let mut challenge_bytes = prover_committed.challenge_bytes();
        root_commitment
            .0
            .serialize(&mut challenge_bytes, false)
            .unwrap();
        serial_number_generator
            .serialize(&mut challenge_bytes, false)
            .unwrap();
        serial_number_commitment
            .serialize(&mut challenge_bytes, false)
            .unwrap();

        let challenge = hash_to_fr(challenge_bytes);

        // Generate the proof of knowledge
        let mut pok = prover_committed
            .generate_proof(&challenge, &[self.token_id.clone(), blinding_t])
            .map_err(|e| ProofError(format!("Could not generate proof of knowledge. {:?}", e)))?;

        let root_token_response = pok.responses.remove(0);
        let blinding_response = pok.responses.remove(0);

        let proof_root_token = ProofRootToken {
            root: root_commitment,
            randomness_commitment: pok.commitment,
            blinding_response,
        };

        let proof_serial_number = ProofSerialNumber {
            serial_number,
            randomness_commitment: serial_number_commitment,
        };

        Ok(VeronymousToken {
            root: proof_root_token,
            root_signature,
            serial_number: proof_serial_number,
            root_token_response,
        })
    }

    // TODO: Put derive generator in common function
    fn derive_serial_number(&self, generator: &G2) -> G2 {
        // Serial number = hash_to_curve(domain, timestamp) ^ token_id
        let mut serial_number = *generator;
        serial_number.mul_assign(self.token_id.clone());

        serial_number
    }
}
