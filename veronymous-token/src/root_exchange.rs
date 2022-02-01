use commitments::pedersen_commitment::PedersenCommitmentCommitting;
use commitments::pok_pedersen_commitment::{CommitmentProof, ProverCommitting};
use crypto_common::hash_to_fr;
use pairing_plus::bls12_381::{Fr, G1};
use pairing_plus::serdes::SerDes;
use ps_signatures::blind_signature::PsBlindSignature;
use ps_signatures::keys::{PsParams, PsPublicKey, PsSigningKey};
use ps_signatures::signature::PsSignature;
use rand::CryptoRng;
use crate::error::VeronymousTokenError;
use crate::root::RootVeronymousToken;
use crate::{RootTokenId, TokenBlinding};

#[derive(Clone, Debug)]
pub struct RootTokenRequest {
    pub token_id_commitment: G1,

    pub randomness_commitment: G1,

    pub token_id_response: Fr,

    pub blinding_factor_response: Fr,
}

impl RootTokenRequest {
    pub fn verify(
        &self,
        public_key: &PsPublicKey,
        params: &PsParams,
    ) -> Result<bool, VeronymousTokenError> {
        if public_key.y_cap.len() < 1 {
            return Err(VeronymousTokenError::InvalidArgumentError(format!(
                "Public key must have at least 1 Y."
            )));
        }

        let proof = CommitmentProof {
            commitment: self.randomness_commitment,
            responses: vec![self.token_id_response, self.blinding_factor_response],
        };

        let gens = vec![public_key.y_cap[0], params.g];

        // Get the challenge
        let mut challenge_bytes = proof.challenge_bytes(&gens);
        self.token_id_commitment
            .serialize(&mut challenge_bytes, false)
            .unwrap();

        let challenge = hash_to_fr(&challenge_bytes);
        let result = proof
            .verify(&gens, &self.token_id_commitment, &challenge)
            .map_err(|e| {
                VeronymousTokenError::VerificationError(format!("Could not verify proof. {:?}", e))
            })?;

        Ok(result)
    }
}

#[derive(Clone, Debug)]
pub struct RootTokenResponse {
    pub signature: PsSignature,
}

pub fn create_root_token_request(
    token_id: &RootTokenId,
    blinding: &TokenBlinding,
    public_key: &PsPublicKey,
    params: &PsParams,
) -> Result<RootTokenRequest, VeronymousTokenError> {
    if public_key.y_cap.len() < 1 {
        return Err(VeronymousTokenError::InvalidArgumentError(format!(
            "Public key must have at least 1 Y."
        )));
    }

    // 1) Create the token_id commitment
    let mut committing = PedersenCommitmentCommitting::new(None, None).unwrap();
    committing.commit(public_key.y_cap[0], *token_id);
    committing.commit(params.g, *blinding);

    let commitment = committing.finish();

    // 2) Create the commitment proof

    // Commit to randomness
    let mut prover_committing = ProverCommitting::new();

    prover_committing.commit(public_key.y_cap[0], None);
    prover_committing.commit(params.g, None);

    let prover_committed = prover_committing.finish();

    // Get the challenge bytes
    let mut challenge_bytes = prover_committed.challenge_bytes();
    commitment.0.serialize(&mut challenge_bytes, false).unwrap();

    let challenge = hash_to_fr(&challenge_bytes);

    // Generate the proof of knowledge
    let mut proof = prover_committed
        .generate_proof(&challenge, &[*token_id, *blinding])
        .map_err(|e| {
            VeronymousTokenError::ProofError(format!(
                "Could not generate commitment proof. {:?}",
                e
            ))
        })?;

    let token_id_response = proof.responses.remove(0);
    let blinding_factor_response = proof.responses.remove(0);

    Ok(RootTokenRequest {
        token_id_commitment: commitment.0,
        randomness_commitment: proof.commitment,
        token_id_response,
        blinding_factor_response,
    })
}

pub fn issue_root_token<R: CryptoRng + rand::RngCore>(
    token_request: &RootTokenRequest,
    signing_key: &PsSigningKey,
    public_key: &PsPublicKey,
    params: &PsParams,
    rng: &mut R,
) -> Result<RootTokenResponse, VeronymousTokenError> {
    // 1) Verify the token
    if !token_request.verify(&public_key, &params)? {
        return Err(VeronymousTokenError::VerificationError(format!(
            "Token proof verification failed."
        )));
    }

    // 2) Sign the token
    let blind_signature = PsBlindSignature::new(
        token_request.token_id_commitment,
        &[],
        &signing_key,
        &public_key,
        &params,
        rng,
    )
        .map_err(|e| VeronymousTokenError::SigningError(format!("Could not sign token. {:?}", e)))?;

    Ok(RootTokenResponse {
        signature: blind_signature,
    })
}

pub fn complete_root_token(
    token_response: &RootTokenResponse,
    token_id: &RootTokenId,
    blinding: &TokenBlinding,
    public_key: &PsPublicKey,
    params: &PsParams,
) -> Result<RootVeronymousToken, VeronymousTokenError> {
    // Unblind the signature
    let signature = PsBlindSignature::unblind(&token_response.signature, blinding);

    let root_token = RootVeronymousToken {
        token_id: *token_id,
        signature,
    };

    // Verify the signature
    if !root_token.verify(&public_key, &params)? {
        return Err(VeronymousTokenError::InvalidToken(format!(
            "Signature is invalid"
        )));
    }

    Ok(root_token)
}

#[cfg(test)]
mod tests {
    use crate::issuer::TokenIssuer;
    use crate::root_exchange::{complete_root_token, create_root_token_request, issue_root_token};
    use crypto_common::rand_non_zero_fr;
    use ff_zeroize::Field;
    use pairing_plus::bls12_381::Fr;
    use rand::thread_rng;

    #[test]
    fn test_root_token_exchange() {
        let mut rng = thread_rng();

        // Create a token issuer
        let issuer = TokenIssuer::generate(&mut rng);

        let token_id = rand_non_zero_fr(&mut rng);
        let blinding = rand_non_zero_fr(&mut rng);

        let token_request =
            create_root_token_request(&token_id, &blinding, &issuer.public_key, &issuer.params)
                .unwrap();

        // Verify the token request
        let verification_result = token_request
            .verify(&issuer.public_key, &issuer.params)
            .unwrap();
        assert!(verification_result);

        // Issuer issues the token
        let token_response = issue_root_token(
            &token_request,
            &issuer.signing_key,
            &issuer.public_key,
            &issuer.params,
            &mut rng,
        )
            .unwrap();

        let mut root_token = complete_root_token(
            &token_response,
            &token_id,
            &blinding,
            &issuer.public_key,
            &issuer.params,
        )
            .unwrap();

        // Veronymous token
        let domain = "test".as_bytes();
        let now = 1643629600u64;

        let veronymous_token_1 = root_token
            .derive_token(domain, now, &issuer.public_key, &issuer.params, &mut rng)
            .unwrap();

        let veronymous_token_2 = root_token
            .derive_token(domain, now, &issuer.public_key, &issuer.params, &mut rng)
            .unwrap();

        // Serial number for token 1 and 2 must be the same
        assert_eq!(
            veronymous_token_1.serial_number.serial_number,
            veronymous_token_2.serial_number.serial_number
        );

        let result = veronymous_token_1
            .verify(domain, now, &issuer.public_key, &issuer.params)
            .unwrap();

        assert!(result);

        // Test bad id
        root_token.token_id = Fr::random(&mut rng);

        let veronymous_token = root_token
            .derive_token(domain, now, &issuer.public_key, &issuer.params, &mut rng)
            .unwrap();

        let result = veronymous_token
            .verify(domain, now, &issuer.public_key, &issuer.params)
            .unwrap();
        assert!(!result)
    }
}
