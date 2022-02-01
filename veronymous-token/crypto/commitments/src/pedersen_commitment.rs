/*
* Vector pedersen commitment
* C = g_1 ^ m_1 * g_2 ^ m_2 ... g_i ^ m_i
*/

use crypto_common::multi_scalar_mul_const_time;
use pairing_plus::bls12_381::{Fr, G1, G2};
use pairing_plus::CurveProjective;

use crate::error::CommitmentError;

pub type RandomFactor = Fr;

#[derive(Clone, Debug)]
pub struct PedersenCommitmentCommitting<C: CurveProjective> {
    gens: Vec<C>,
    scalars: Vec<Fr>,
}

impl<C: CurveProjective> PedersenCommitmentCommitting<C> {
    pub fn new(gens: Option<Vec<C>>, scalars: Option<Vec<Fr>>) -> Result<Self, CommitmentError> {
        let gens = match gens {
            Some(gens) => gens,
            None => Vec::new(),
        };

        let scalars = match scalars {
            Some(scalars) => scalars,
            None => Vec::new(),
        };

        if gens.len() != scalars.len() {
            return Err(CommitmentError::InvalidArgumentError(format!(
                "Size of gens({}) must be equal to the length of scalars({}).",
                gens.len(),
                scalars.len()
            )));
        }

        Ok(Self { gens, scalars })
    }

    pub fn commit(&mut self, gen: C, scalar: Fr) {
        self.gens.push(gen);
        self.scalars.push(scalar);
    }

    pub fn finish(self) -> PedersenCommitment<C> {
        PedersenCommitment(multi_scalar_mul_const_time(self.gens, self.scalars))
    }
}

#[derive(Debug, Clone)]
pub struct PedersenCommitment<C: CurveProjective>(pub C);

impl<C: CurveProjective> PedersenCommitment<C> {
    pub fn new(commitment: C) -> Self {
        Self(commitment)
    }

    pub fn verify(&self, gens: Vec<C>, scalars: Vec<Fr>) -> Result<bool, CommitmentError> {
        // Create the commitment from the gens and scalars
        let committing = PedersenCommitmentCommitting::new(Some(gens), Some(scalars))?;
        let commitment = committing.finish();

        Ok(self.0 == commitment.0)
    }
}

impl Into<G1> for PedersenCommitment<G1> {
    fn into(self) -> G1 {
        self.0
    }
}

impl Into<G1> for &PedersenCommitment<G1> {
    fn into(self) -> G1 {
        self.0
    }
}

impl Into<G2> for PedersenCommitment<G2> {
    fn into(self) -> G2 {
        self.0
    }
}

impl Into<G2> for &PedersenCommitment<G2> {
    fn into(self) -> G2 {
        self.0
    }
}


#[cfg(test)]
mod tests {
    use crate::pedersen_commitment::PedersenCommitmentCommitting;
    use ff_zeroize::Field;
    use pairing_plus::bls12_381::{Fr, G1};
    use pairing_plus::CurveProjective;
    use rand::thread_rng;

    #[test]
    fn test_vector_pedersen_commitment() {
        // Create the committing object
        let mut committing = PedersenCommitmentCommitting::new(None, None).unwrap();

        let mut rng = thread_rng();

        let mut gens = vec![];
        let mut scalars = vec![];

        // Commit random messages
        for _ in 0..10 {
            let gen = G1::random(&mut rng);
            let scalar = Fr::random(&mut rng);

            gens.push(gen.clone());
            scalars.push(scalar.clone());

            committing.commit(gen, scalar);
        }

        // Finish the commitment
        let commitment = committing.finish();

        // Verify the commitment
        let result = commitment.verify(gens.clone(), scalars.clone()).unwrap();
        assert!(result);

        scalars[0] = Fr::random(&mut rng);

        let result = commitment.verify(gens.clone(), scalars.clone()).unwrap();
        assert_eq!(false, result);
    }
}
