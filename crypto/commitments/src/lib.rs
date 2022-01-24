/*#[cfg(all(feature = "G1", feature = "G2"))]
compile_error!("features `PS_Signature_G2` and `PS_Signature_G1` are mutually exclusive");

#[cfg(feature = "G1")]
pub type Group = G1;*/

/*
#[cfg(feature = "G2")]
pub type Group = G2;*/

// TODO: Constant timing?
// TODO: Support both G1 and G2
// TODO: Zeroize

pub mod error;
pub mod pedersen_commitment;
pub mod pok_pedersen_commitment;
