use crate::error::VeronymousTokenError;
use crate::error::VeronymousTokenError::DeserializationError;
use pairing_plus::bls12_381::{Fr, G1, G2};
use pairing_plus::serdes::SerDes;
use std::io::Cursor;

pub fn read_g1_point(bytes: &mut Cursor<&[u8]>) -> Result<G1, VeronymousTokenError> {
    match G1::deserialize(bytes, true) {
        Ok(point) => Ok(point),
        Err(err) => Err(DeserializationError(format!(
            "Could not decode G1 point. {:?}",
            err
        ))),
    }
}

pub fn read_g2_point(bytes: &mut Cursor<&[u8]>) -> Result<G2, VeronymousTokenError> {
    match G2::deserialize(bytes, true) {
        Ok(point) => Ok(point),
        Err(err) => Err(DeserializationError(format!(
            "Could not decode G2 point. {:?}",
            err
        ))),
    }
}

pub fn read_fr(bytes: &mut Cursor<&[u8]>) -> Result<Fr, VeronymousTokenError> {
    match Fr::deserialize(bytes, true) {
        Ok(field) => Ok(field),
        Err(err) => Err(DeserializationError(format!(
            "Could not decode Fr. {:?}",
            err
        ))),
    }
}
