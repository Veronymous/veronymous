use std::time::{SystemTime, UNIX_EPOCH};
use crate::error::VeronymousTokenError;
use commitments::pedersen_commitment::PedersenCommitment;
use commitments::pok_pedersen_commitment::CommitmentProof;
use crypto_common::hash_to_fr;
use pairing_plus::bls12_381::{Fr, G2};
use pairing_plus::hash_to_curve::HashToCurve;
use pairing_plus::hash_to_field::ExpandMsgXmd;
use pairing_plus::serdes::SerDes;
use ps_signatures::keys::{PsParams, PsPublicKey};
use ps_signatures::pok_sig::PsPokOfSignatureProof;

const DST: &[u8] = b"BLS12381G2_XMD:BLAKE2B_SERIAL_NUMBER_GENERATOR:1_0_0";

#[derive(Clone, Debug)]
pub struct ProofRootToken {
    pub root: PedersenCommitment<G2>,

    pub randomness_commitment: G2,

    pub blinding_response: Fr,
}

#[derive(Clone, Debug)]
pub struct ProofSerialNumber {
    pub serial_number: G2,

    pub randomness_commitment: G2,
}

#[derive(Clone, Debug)]
pub struct VeronymousToken {
    // Hidden root token
    pub root: ProofRootToken,

    // Issuer ps signature
    pub root_signature: PsPokOfSignatureProof,

    // The serial number
    pub serial_number: ProofSerialNumber,

    // Links serial number and root together
    pub root_token_response: Fr,
}

impl VeronymousToken {
    pub fn verify(
        &self,
        domain: &[u8],
        timestamp: u64,
        public_key: &PsPublicKey,
        params: &PsParams,
    ) -> Result<bool, VeronymousTokenError> {
        if public_key.y_cap.len() < 1 {
            return Err(VeronymousTokenError::InvalidArgumentError(format!(
                "Public key must have at least 1 Y."
            )));
        }

        let token_proof = CommitmentProof::new(
            self.root.randomness_commitment,
            vec![
                self.root_token_response.clone(),
                self.root.blinding_response.clone(),
            ],
        );

        let serial_number_proof = CommitmentProof::new(
            self.serial_number.randomness_commitment,
            vec![self.root_token_response.clone()],
        );

        let serial_number_generator = compute_serial_number_generator(domain, timestamp);

        // Get the challenge
        let mut challenge_bytes =
            token_proof.challenge_bytes(&[public_key.y_cap_tilde[0], params.g_tilde]);
        self.root
            .root
            .0
            .serialize(&mut challenge_bytes, false)
            .unwrap();
        serial_number_generator
            .serialize(&mut challenge_bytes, false)
            .unwrap();
        self.serial_number
            .randomness_commitment
            .serialize(&mut challenge_bytes, false)
            .unwrap();

        let challenge = hash_to_fr(challenge_bytes);

        // Verify root token
        if !token_proof
            .verify(
                &[public_key.y_cap_tilde[0], params.g_tilde],
                &self.root.root.0,
                &challenge,
            )
            .map_err(|e| {
                VeronymousTokenError::VerificationError(format!(
                    "Could not verify token pok. {:?}",
                    e
                ))
            })?
        {
            return Ok(false);
        }

        // Verify serial number
        if !serial_number_proof
            .verify(
                &[serial_number_generator],
                &self.serial_number.serial_number,
                &challenge,
            )
            .map_err(|e| {
                VeronymousTokenError::VerificationError(format!(
                    "Could not verify token pok. {:?}",
                    e
                ))
            })?
        {
            return Ok(false);
        }

        // Verify root signature
        if !self
            .root_signature
            .verify(&public_key, &params, &self.root.root)
        {
            return Ok(false);
        }

        Ok(true)
    }
}

pub fn get_now_u64() -> u64 {
    let now = SystemTime::now();

    now.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn get_current_epoch(now: u64, epoch_length: u64) -> u64 {
    now - (now % epoch_length)
}

pub fn get_next_epoch(now: u64, epoch_length: u64) -> u64 {
    // Get the current epoch start
    let current_epoch = now - (now % epoch_length);
    let next_epoch = current_epoch + epoch_length;

    let time_until_next_epoch = next_epoch - now;

    now + time_until_next_epoch
}

pub fn compute_serial_number_generator(domain: &[u8], timestamp: u64) -> G2 {
    let timestamp_bytes = timestamp.to_be_bytes();

    let mut input_bytes = Vec::with_capacity(domain.len() + timestamp_bytes.len());
    input_bytes.extend_from_slice(domain);
    input_bytes.extend_from_slice(&timestamp_bytes);

    <G2 as HashToCurve<ExpandMsgXmd<blake2::Blake2b>>>::hash_to_curve(input_bytes, DST)
}

#[cfg(test)]
mod tests {
    use crate::token::{get_current_epoch, get_next_epoch};

    #[test]
    fn test_get_next_epoch() {
        let now = 1643715498;
        let next_epoch = get_next_epoch(now, 10 * 60);
        assert_eq!(1643715600, next_epoch);
    }

    #[test]
    fn test_get_current_epoch() {
        let now = 1643715498;
        let current_epoch = get_current_epoch(now, 10 * 60);
        assert_eq!(1643715000, current_epoch);
    }
}