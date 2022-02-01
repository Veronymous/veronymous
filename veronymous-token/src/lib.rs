extern crate ps_signatures;
/*
* TODO: Review visibility
*/

pub mod error;
pub mod issuer;
pub mod root;
pub mod root_exchange;
pub mod token;

use pairing_plus::bls12_381::Fr;

pub type RootTokenId = Fr;
pub type TokenBlinding = Fr;
