/*
* Inspired by
*/

use blake2::digest::generic_array::GenericArray;
use blake2::digest::{Input, VariableOutput};
use ff_zeroize::{Field, PrimeField};
use pairing_plus::bls12_381::Fr;
use pairing_plus::hash_to_field::BaseFromRO;
use pairing_plus::{CurveAffine, CurveProjective};
use rand::CryptoRng;

pub const FR_UNCOMPRESSED_SIZE: usize = 48;

pub fn rand_non_zero_fr<R: CryptoRng + rand::RngCore>(rng: &mut R) -> Fr {
    let mut r = Fr::random(rng);
    loop {
        if !r.is_zero() {
            return r;
        }
        r = Fr::random(rng);
    }
}

pub fn multi_scalar_mul_const_time<G: AsRef<[C]>, S: AsRef<[Fr]>, C: CurveProjective>(
    bases: G,
    scalars: S,
) -> C {
    let bases: Vec<_> = bases.as_ref().iter().map(|b| b.into_affine()).collect();
    let scalars: Vec<[u64; 4]> = scalars
        .as_ref()
        .iter()
        .map(|s| {
            let mut t = [0u64; 4];
            t.clone_from_slice(s.into_repr().as_ref());
            t
        })
        .collect();
    // Annoying step to keep the borrow checker happy
    let s: Vec<&[u64; 4]> = scalars.iter().map(|u| u).collect();
    C::Affine::sum_of_products(bases.as_slice(), s.as_slice())
}

pub fn hash_to_fr<I: AsRef<[u8]>>(data: I) -> Fr {
    let mut res = GenericArray::default();
    let mut hasher = blake2::VarBlake2b::new(FR_UNCOMPRESSED_SIZE).unwrap();
    hasher.input(data.as_ref());
    hasher.variable_result(|out| {
        res.copy_from_slice(out);
    });
    Fr::from_okm(&res)
}
