use pairing_plus::bls12_381::Fr;

// TODO: Zeroize

pub type Blinding = Fr;

pub mod blind_signature;
pub mod error;
pub mod keys;
pub mod signature;
