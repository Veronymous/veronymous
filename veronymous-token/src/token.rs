use crate::error::VeronymousTokenError;
use crate::error::VeronymousTokenError::{DeserializationError, SerializationError};
use crate::serde::Serializable;
use crate::utils::{read_fr, read_g1_point, read_g2_point};
use commitments::pedersen_commitment::PedersenCommitment;
use commitments::pok_pedersen_commitment::CommitmentProof;
use crypto_common::hash_to_fr;
use pairing_plus::bls12_381::{Fr, G2};
use pairing_plus::hash_to_curve::HashToCurve;
use pairing_plus::hash_to_field::ExpandMsgXmd;
use pairing_plus::serdes::SerDes;
use ps_signatures::keys::{PsParams, PsPublicKey};
use ps_signatures::pok_sig::PsPokOfSignatureProof;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::Sha256;
use sha2::Digest;
use crate::SerialNumber;

const DST: &[u8] = b"BLS12381G2_XMD:BLAKE2B_SERIAL_NUMBER_GENERATOR:1_0_0";

const SERIALIZED_TOKEN_SIZE: usize = 544;

#[derive(Clone, Debug, PartialEq)]
pub struct ProofRootToken {
    pub root: PedersenCommitment<G2>,

    pub randomness_commitment: G2,

    pub blinding_response: Fr,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProofSerialNumber {
    pub serial_number: G2,

    pub randomness_commitment: G2,
}

impl ProofSerialNumber {
    pub fn serial_number_bytes(&self) -> Result<Vec<u8>, VeronymousTokenError> {
        let mut serial_number_bytes = Vec::with_capacity(96);
        self.serial_number.serialize(&mut serial_number_bytes, true)
            .map_err(|e| SerializationError(format!("Could not serialize serial number. {:?}", e)))?;

        Ok(serial_number_bytes)
    }
}

#[derive(Clone, Debug, PartialEq)]
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

    // TODO: Might want to name something else
    pub fn serial_number(&self) -> Result<SerialNumber, VeronymousTokenError> {
        let bytes = self.serial_number.serial_number_bytes()?;

        let mut hasher = Sha256::new();
        hasher.update(&bytes);

        Ok(hasher.finalize().into())
    }
}

impl Serializable for VeronymousToken {
    fn serialize(&self) -> Vec<u8> {
        // TODO: Vec with capacity
        let mut bytes = Vec::with_capacity(SERIALIZED_TOKEN_SIZE);

        self.root.root.0.serialize(&mut bytes, true).unwrap();
        self.root
            .randomness_commitment
            .serialize(&mut bytes, true)
            .unwrap();
        self.root
            .blinding_response
            .serialize(&mut bytes, true)
            .unwrap();

        self.root_signature
            .sigma_1
            .serialize(&mut bytes, true)
            .unwrap();
        self.root_signature
            .sigma_2
            .serialize(&mut bytes, true)
            .unwrap();

        self.serial_number
            .serial_number
            .serialize(&mut bytes, true)
            .unwrap();
        self.serial_number
            .randomness_commitment
            .serialize(&mut bytes, true)
            .unwrap();

        self.root_token_response
            .serialize(&mut bytes, true)
            .unwrap();

        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, VeronymousTokenError>
    where
        Self: Sized,
    {
        if bytes.len() != SERIALIZED_TOKEN_SIZE {
            return Err(DeserializationError(format!(
                "Serialized token must have {} bytes",
                SERIALIZED_TOKEN_SIZE
            )));
        }

        let mut cursor = Cursor::new(bytes);

        let root = ProofRootToken {
            root: PedersenCommitment(read_g2_point(&mut cursor)?),
            randomness_commitment: read_g2_point(&mut cursor)?,
            blinding_response: read_fr(&mut cursor)?,
        };

        let root_signature = PsPokOfSignatureProof {
            sigma_1: read_g1_point(&mut cursor)?,
            sigma_2: read_g1_point(&mut cursor)?,
        };

        let serial_number = ProofSerialNumber {
            serial_number: read_g2_point(&mut cursor)?,
            randomness_commitment: read_g2_point(&mut cursor)?,
        };

        let root_token_response = read_fr(&mut cursor)?;

        Ok(Self {
            root,
            root_signature,
            serial_number,
            root_token_response,
        })
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
