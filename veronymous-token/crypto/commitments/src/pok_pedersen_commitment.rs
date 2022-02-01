/*
* Schnorr proof-of-knowledge for a vector pedersen commitment
* https://github.com/hyperledger/ursa-rfcs/tree/main/text/pok-vpc
*/

use crate::error::CommitmentError;
use crypto_common::multi_scalar_mul_const_time;
use ff_zeroize::{Field, PrimeField};
use pairing_plus::bls12_381::Fr;
use pairing_plus::serdes::SerDes;
use pairing_plus::CurveProjective;
use rand::thread_rng;

#[derive(Clone, Debug)]
pub struct ProverCommitting<C: CurveProjective + SerDes> {
    gens: Vec<C>,
    blinding_factors: Vec<Fr>,
}

impl<C: CurveProjective + SerDes> ProverCommitting<C> {
    pub fn new() -> Self {
        Self {
            gens: vec![],
            blinding_factors: vec![],
        }
    }

    // Add generator and blinding factor
    pub fn commit(&mut self, gen: C, blinding_factor: Option<Fr>) {
        let blinding_factor = match blinding_factor {
            Some(blinding_factor) => blinding_factor,
            None => Fr::random(&mut thread_rng()),
        };

        self.gens.push(gen);
        self.blinding_factors.push(blinding_factor);
    }

    pub fn finish(self) -> ProverCommitted<C> {
        let commitment = multi_scalar_mul_const_time(&self.gens, &self.blinding_factors);
        ProverCommitted {
            gens: self.gens,
            blinding_factors: self.blinding_factors,
            commitment,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProverCommitted<C: CurveProjective + SerDes> {
    gens: Vec<C>,
    blinding_factors: Vec<Fr>,
    commitment: C, // Randomness commitment
}

impl<C: CurveProjective + SerDes> ProverCommitted<C> {
    // Challenge bytes for fiat-shamir heuristic
    pub fn challenge_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        for gen in &self.gens {
            gen.serialize(&mut bytes, false).unwrap();
        }
        self.commitment.serialize(&mut bytes, false).unwrap();

        bytes
    }

    /// For each secret, generate a response as self.blinding_factors[i] - challenge*secrets[i].
    pub fn generate_proof(
        self,
        challenge: &Fr,
        secrets: &[Fr],
    ) -> Result<CommitmentProof<C>, CommitmentError> {
        if secrets.len() != self.gens.len() && secrets.len() != self.blinding_factors.len() {
            return Err(CommitmentError::InvalidArgumentError(format!(
                "Length of secrets({}) and blinding factors({}) must be the same.",
                secrets.len(),
                self.blinding_factors.len()
            )));
        }

        let mut responses: Vec<Fr> = Vec::with_capacity(secrets.len());

        for i in 0..self.gens.len() {
            let mut c = challenge.clone();
            c.mul_assign(&secrets[i]);
            let mut s = self.blinding_factors[i].clone();
            s.sub_assign(&c);
            responses.push(s);
        }

        Ok(CommitmentProof {
            commitment: self.commitment,
            responses,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CommitmentProof<C: CurveProjective + SerDes> {
    // Randomness commitment
    pub responses: Vec<Fr>,
    pub commitment: C,
}

impl<C: CurveProjective + SerDes> CommitmentProof<C> {
    pub fn new(commitment: C, responses: Vec<Fr>) -> Self {
        Self {
            commitment,
            responses,
        }
    }

    pub fn challenge_bytes(&self, gens: &[C]) -> Vec<u8> {
        let mut bytes = Vec::new();

        for gen in gens {
            gen.serialize(&mut bytes, false).unwrap();
        }
        self.commitment.serialize(&mut bytes, false).unwrap();

        bytes
    }

    pub fn verify(
        &self,
        gens: &[C],
        commitment: &C,
        challenge: &Fr,
    ) -> Result<bool, CommitmentError>
    where
        <<C as CurveProjective>::Scalar as PrimeField>::Repr: From<Fr>,
    {
        if gens.len() != self.responses.len() {
            return Err(CommitmentError::InvalidArgumentError(format!(
                "Number of generators({}) must be equal to the number of responses ({})",
                gens.len(),
                self.responses.len()
            )));
        }

        let mut points: Vec<C> = Vec::from(gens);
        let mut scalars = self.responses.clone();

        points.push(*commitment);
        scalars.push(*challenge);

        let mut calculated_commitment = multi_scalar_mul_const_time(points, scalars);
        calculated_commitment.sub_assign(&self.commitment);

        Ok(calculated_commitment.is_zero())
    }
}

#[cfg(test)]
mod tests {
    use crate::pedersen_commitment::PedersenCommitmentCommitting;
    use crate::pok_pedersen_commitment::ProverCommitting;
    use crypto_common::hash_to_fr;
    use ff_zeroize::Field;
    use pairing_plus::bls12_381::{Fr, G1};
    use pairing_plus::serdes::SerDes;
    use pairing_plus::CurveProjective;
    use rand::thread_rng;

    #[test]
    fn verify_valid_proof() {
        let mut rng = &mut thread_rng();

        // 1) Commitment values
        let gens = vec![
            G1::random(&mut rng),
            G1::random(&mut rng),
            G1::random(&mut rng),
            G1::random(&mut rng),
        ];
        let scalars = vec![
            Fr::random(&mut rng),
            Fr::random(&mut rng),
            Fr::random(&mut rng),
            Fr::random(&mut rng),
        ];

        // 2) Create the pedersen commitment
        let committing =
            PedersenCommitmentCommitting::new(Some(gens.clone()), Some(scalars.clone())).unwrap();

        let commitment = committing.finish();

        // 3) Prover committing
        let mut prover_committing = ProverCommitting::new();

        for i in 0..gens.len() {
            let gen = gens[i].clone();

            // Commit generator + blinding factor
            prover_committing.commit(gen, None);
        }

        // 4) Prover committed
        let prover_committed = prover_committing.finish();

        // Get the challenge
        let mut challenge_bytes = prover_committed.challenge_bytes();
        commitment.0.serialize(&mut challenge_bytes, false).unwrap();

        let challenge = hash_to_fr(challenge_bytes);

        // 5) Generate the proof
        let proof = prover_committed
            .generate_proof(&challenge, &scalars)
            .unwrap();

        // 6) Verify the proof
        let mut challenge_bytes = proof.challenge_bytes(&gens);
        commitment.0.serialize(&mut challenge_bytes, false).unwrap();

        let challenge = hash_to_fr(challenge_bytes);

        let verification_result = proof.verify(&gens, &commitment.0, &challenge).unwrap();

        assert!(verification_result)
    }

    #[test]
    fn verify_proof_wrong_commitment() {
        let mut rng = &mut thread_rng();

        // 1) Commitment values
        let gens = vec![
            G1::random(&mut rng),
            G1::random(&mut rng),
            G1::random(&mut rng),
            G1::random(&mut rng),
        ];
        let mut scalars = vec![
            Fr::random(&mut rng),
            Fr::random(&mut rng),
            Fr::random(&mut rng),
            Fr::random(&mut rng),
        ];

        // 2) Create the pedersen commitment
        let committing =
            PedersenCommitmentCommitting::new(Some(gens.clone()), Some(scalars.clone())).unwrap();

        let commitment = committing.finish();

        // 3) Prover committing
        let mut prover_committing = ProverCommitting::new();

        for i in 0..gens.len() {
            let gen = gens[i].clone();

            // Commit generator + blinding factor
            prover_committing.commit(gen, None);
        }

        // 4) Prover committed
        let prover_committed = prover_committing.finish();

        // Get the challenge
        let mut challenge_bytes = prover_committed.challenge_bytes();
        commitment.0.serialize(&mut challenge_bytes, false).unwrap();

        let challenge = hash_to_fr(challenge_bytes);

        // 5) Generate the proof
        let proof = prover_committed
            .generate_proof(&challenge, &scalars)
            .unwrap();

        // 6) Verify the proof
        let mut challenge_bytes = proof.challenge_bytes(&gens);
        commitment.0.serialize(&mut challenge_bytes, false).unwrap();

        let challenge = hash_to_fr(challenge_bytes);

        // Bad commitment
        scalars[3] = Fr::random(&mut rng);
        let committing =
            PedersenCommitmentCommitting::new(Some(gens.clone()), Some(scalars.clone())).unwrap();

        let commitment = committing.finish();

        let verification_result = proof.verify(&gens, &commitment.0, &challenge).unwrap();

        assert_eq!(false, verification_result)
    }

    #[test]
    fn verify_proof_wrong_scalar() {
        let mut rng = &mut thread_rng();

        // 1) Commitment values
        let gens = vec![
            G1::random(&mut rng),
            G1::random(&mut rng),
            G1::random(&mut rng),
            G1::random(&mut rng),
        ];
        let mut scalars = vec![
            Fr::random(&mut rng),
            Fr::random(&mut rng),
            Fr::random(&mut rng),
            Fr::random(&mut rng),
        ];

        // 2) Create the pedersen commitment
        let committing =
            PedersenCommitmentCommitting::new(Some(gens.clone()), Some(scalars.clone())).unwrap();

        let commitment = committing.finish();

        // 3) Prover committing
        let mut prover_committing = ProverCommitting::new();

        for i in 0..gens.len() {
            let gen = gens[i].clone();

            // Commit generator + blinding factor
            prover_committing.commit(gen, None);
        }

        // 4) Prover committed
        let prover_committed = prover_committing.finish();

        // Get the challenge
        let mut challenge_bytes = prover_committed.challenge_bytes();
        commitment.0.serialize(&mut challenge_bytes, false).unwrap();

        let challenge = hash_to_fr(challenge_bytes);

        // Bad scalar
        scalars[2] = Fr::random(&mut rng);

        // 5) Generate the proof
        let proof = prover_committed
            .generate_proof(&challenge, &scalars)
            .unwrap();

        // 6) Verify the proof
        let mut challenge_bytes = proof.challenge_bytes(&gens);
        commitment.0.serialize(&mut challenge_bytes, false).unwrap();

        let challenge = hash_to_fr(challenge_bytes);

        let verification_result = proof.verify(&gens, &commitment.0, &challenge).unwrap();

        assert_eq!(false, verification_result)
    }

    #[test]
    fn verify_proof_wrong_gen() {
        let mut rng = &mut thread_rng();

        // 1) Commitment values
        let mut gens = vec![
            G1::random(&mut rng),
            G1::random(&mut rng),
            G1::random(&mut rng),
            G1::random(&mut rng),
        ];
        let mut scalars = vec![
            Fr::random(&mut rng),
            Fr::random(&mut rng),
            Fr::random(&mut rng),
            Fr::random(&mut rng),
        ];

        // 2) Create the pedersen commitment
        let committing =
            PedersenCommitmentCommitting::new(Some(gens.clone()), Some(scalars.clone())).unwrap();

        let commitment = committing.finish();

        // 3) Prover committing
        let mut prover_committing = ProverCommitting::new();

        for i in 0..gens.len() {
            let gen = gens[i].clone();

            // Commit generator + blinding factor
            prover_committing.commit(gen, None);
        }

        // 4) Prover committed
        let prover_committed = prover_committing.finish();

        // Get the challenge
        let mut challenge_bytes = prover_committed.challenge_bytes();
        commitment.0.serialize(&mut challenge_bytes, false).unwrap();

        let challenge = hash_to_fr(challenge_bytes);

        // Bad scalar
        scalars[2] = Fr::random(&mut rng);

        // 5) Generate the proof
        let proof = prover_committed
            .generate_proof(&challenge, &scalars)
            .unwrap();

        // 6) Verify the proof
        let mut challenge_bytes = proof.challenge_bytes(&gens);
        commitment.0.serialize(&mut challenge_bytes, false).unwrap();

        let challenge = hash_to_fr(challenge_bytes);

        gens[3] = G1::random(&mut rng);
        let verification_result = proof.verify(&gens, &commitment.0, &challenge).unwrap();

        assert_eq!(false, verification_result)
    }
}
