use byteorder::ReadBytesExt;
use crypto_common::rand_non_zero_fr;
use ff_zeroize::Field;
use pairing_plus::bls12_381::Fr;
use pairing_plus::bls12_381::{G1, G2};
use pairing_plus::serdes::SerDes;
use pairing_plus::CurveProjective;
use rand::CryptoRng;
use serde::de::Visitor;
use serde::ser::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;
use std::io::Cursor;

use crate::error::PsSignatureError;
use crate::error::PsSignatureError::{DeserializationError, SerializationError};
use crate::serde::{read_fr, read_g1_point, read_g2_point, Serializable};

const SERIALIZED_G1_LENGTH: usize = 48;
const SERIALIZED_G2_LENGTH: usize = 96;

const SERIALIZED_FR_LENGTH: usize = 32;

const SERIALIZED_PARAMS_LENGTH: usize = SERIALIZED_G1_LENGTH + SERIALIZED_G2_LENGTH;

// TODO: Enforce consistent network order (Big-endian)

#[derive(Clone, Debug, PartialEq)]
pub struct PsParams {
    pub g: G1,
    pub g_tilde: G2,
}

impl PsParams {
    pub fn generate<C: CryptoRng + rand::RngCore>(rng: &mut C) -> Self {
        Self {
            g: G1::random(rng),
            g_tilde: G2::random(rng),
        }
    }
}

impl Serializable for PsParams {
    fn serialize(&self) -> Result<Vec<u8>, PsSignatureError> {
        let mut vec = Vec::with_capacity(SERIALIZED_PARAMS_LENGTH);

        self.g
            .serialize(&mut vec, true)
            .map_err(|e| SerializationError(format!("Could not serialize g. {:?}", e)))?;

        self.g_tilde
            .serialize(&mut vec, true)
            .map_err(|e| SerializationError(format!("Could not serialize g. {:?}", e)))?;

        Ok(vec)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, PsSignatureError> {
        if bytes.len() != SERIALIZED_PARAMS_LENGTH {
            return Err(DeserializationError(format!(
                "Invalid number of bytes. Got {} but expected {}",
                bytes.len(),
                SERIALIZED_PARAMS_LENGTH
            )));
        }

        let mut cursor = Cursor::new(bytes);

        let g = read_g1_point(&mut cursor).map_err(|e| DeserializationError(format!("{:?}", e)))?;
        let g_tilde =
            read_g2_point(&mut cursor).map_err(|e| DeserializationError(format!("{:?}", e)))?;

        Ok(Self { g, g_tilde })
    }
}

impl Serialize for PsParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes =
            Serializable::serialize(self).map_err(|e| S::Error::custom(format!("{:?}", e)))?;

        serializer.serialize_bytes(&bytes)
    }
}

struct PsParamsVisitor;

impl<'de> Visitor<'de> for PsParamsVisitor {
    type Value = PsParams;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("Expecting a byte array.")
    }

    fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        <PsParams as Serializable>::deserialize(bytes).map_err(|e| E::custom(format!("{:?}", e)))
    }
}

impl<'de> Deserialize<'de> for PsParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PsParamsVisitor)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PsSigningKey {
    pub x: Fr,
    pub y: Vec<Fr>,
    pub x_cap: G1,
}

impl PsSigningKey {
    pub fn generate<C: CryptoRng + rand::RngCore>(
        message_count: usize,
        params: &PsParams,
        rng: &mut C,
    ) -> Self {
        // 1) Generate x
        let x = rand_non_zero_fr(rng);

        // 2) Generate y
        let mut y = Vec::with_capacity(message_count);

        for _ in 0..message_count {
            y.push(Fr::random(rng));
        }

        // 3) Generate X =  g ^ x
        let mut x_cap = params.g.clone();
        x_cap.mul_assign(x);

        Self { x, y, x_cap }
    }

    pub fn derive_public_key(&self, params: &PsParams) -> PsPublicKey {
        // 1) Derive Y and Y-tilde X
        let mut y_cap = Vec::with_capacity(self.y.len());
        let mut y_cap_tilde = Vec::with_capacity(self.y.len());

        for y in &self.y {
            // Y Cap
            let mut point = params.g.clone();
            point.mul_assign(y.clone());
            y_cap.push(point);

            let mut point_tilde = params.g_tilde.clone();
            point_tilde.mul_assign(y.clone());
            y_cap_tilde.push(point_tilde);
        }

        // 2) Derive X-tilde
        let mut x_cap_tilde = params.g_tilde.clone();
        x_cap_tilde.mul_assign(self.x.clone());

        PsPublicKey {
            y_cap,
            x_cap_tilde,
            y_cap_tilde,
        }
    }
}

impl Serializable for PsSigningKey {
    // |x_cap|x|y|
    fn serialize(&self) -> Result<Vec<u8>, PsSignatureError> {
        let mut bytes =
            Vec::with_capacity(SERIALIZED_FR_LENGTH * (self.y.len() + 1) + SERIALIZED_G1_LENGTH);

        // Serialize x_cap
        self.x_cap
            .serialize(&mut bytes, true)
            .map_err(|_| SerializationError(format!("Could not serialize x_cap.")))?;

        // Serialize x
        self.x
            .serialize(&mut bytes, true)
            .map_err(|e| SerializationError(format!("Could not serialize x. {:?}", e)))?;

        for y in &self.y {
            y.serialize(&mut bytes, true).unwrap();
        }

        Ok(bytes)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, PsSignatureError>
    where
        Self: Sized,
    {
        let mut cursor = Cursor::new(bytes);

        // Decode x_cap
        let x_cap = read_g1_point(&mut cursor)
            .map_err(|e| DeserializationError(format!("Could not read x_cap. {:?}", e)))?;

        // Decode x
        let x = read_fr(&mut cursor)
            .map_err(|e| DeserializationError(format!("Could not read x. {:?}", e)))?;

        // Validate length of bytes
        let bytes_left = bytes.len() - cursor.position() as usize;
        if bytes_left % SERIALIZED_FR_LENGTH != 0 {
            return Err(DeserializationError(format!("Invalid number of bytes.")));
        }

        // Decode y
        let y_count = bytes_left / SERIALIZED_FR_LENGTH;
        let mut y = Vec::with_capacity(y_count);

        for _ in 0..y_count {
            y.push(
                read_fr(&mut cursor)
                    .map_err(|e| DeserializationError(format!("Could not read x. {:?}", e)))?,
            );
        }

        Ok(Self { x, y, x_cap })
    }
}

// For blind signature and verification
#[derive(Clone, Debug, PartialEq)]
pub struct PsPublicKey {
    pub y_cap: Vec<G1>,
    pub x_cap_tilde: G2,
    pub y_cap_tilde: Vec<G2>,
}

impl Serializable for PsPublicKey {
    // |y_cap|x_cap_tilde|y_cap_tilde
    fn serialize(&self) -> Result<Vec<u8>, PsSignatureError> {
        let serialized_length = SERIALIZED_G2_LENGTH
            + (SERIALIZED_G1_LENGTH * self.y_cap.len())
            + (SERIALIZED_G2_LENGTH * self.y_cap_tilde.len());

        let mut bytes = Vec::with_capacity(serialized_length);

        // Serialize x_cap_tilde
        self.x_cap_tilde
            .serialize(&mut bytes, true)
            .map_err(|e| SerializationError(format!("Could not serialize x_cap_tilde. {:?}", e)))?;

        // Add the y count count
        if self.y_cap.len() > u8::MAX as usize {
            return Err(SerializationError(format!(
                "Cannot serialize key with y length larger than {}",
                u8::MAX
            )));
        }
        bytes.push(self.y_cap.len() as u8);

        // Serialize y_cap
        for y_cap in &self.y_cap {
            y_cap
                .serialize(&mut bytes, true)
                .map_err(|e| SerializationError(format!("Could not serialize y_cap. {:?}", e)))?;
        }

        // Serialize y_cap_tilde
        for y_cap_tilde in &self.y_cap_tilde {
            y_cap_tilde.serialize(&mut bytes, true).map_err(|e| {
                SerializationError(format!("Could not serialize y_cap_tilde. {:?}", e))
            })?;
        }

        Ok(bytes)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, PsSignatureError>
    where
        Self: Sized,
    {
        let mut cursor = Cursor::new(bytes);

        // Decode x_cap_tilde
        let x_cap_tilde = read_g2_point(&mut cursor)
            .map_err(|e| DeserializationError(format!("Could not decode x_cap_tilde. {:?}", e)))?;

        // Get the length of y
        let y_count = cursor
            .read_u8()
            .map_err(|e| DeserializationError(format!("Could not read y_count. {:?}", e)))?;

        let mut y_cap = Vec::with_capacity(y_count as usize);
        let mut y_cap_tilde = Vec::with_capacity(y_count as usize);

        // Read y_cap
        for _ in 0..y_count {
            y_cap.push(
                read_g1_point(&mut cursor).map_err(|e| {
                    DeserializationError(format!("Could not decode y_cap. {:?}", e))
                })?,
            );
        }

        // Read y_cap_tilde
        for _ in 0..y_count {
            y_cap_tilde.push(read_g2_point(&mut cursor).map_err(|e| {
                DeserializationError(format!("Could not decode y_cap_tilde. {:?}", e))
            })?);
        }

        Ok(Self {
            y_cap,
            x_cap_tilde,
            y_cap_tilde,
        })
    }
}

impl Serialize for PsPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes =
            Serializable::serialize(self).map_err(|e| S::Error::custom(format!("{:?}", e)))?;

        serializer.serialize_bytes(&bytes)
    }
}

struct PsPublicKeyVisitor;

impl<'de> Visitor<'de> for PsPublicKeyVisitor {
    type Value = PsPublicKey;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("Expecting a byte array.")
    }

    fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        <PsPublicKey as Serializable>::deserialize(bytes).map_err(|e| E::custom(format!("{:?}", e)))
    }
}

impl<'de> Deserialize<'de> for PsPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PsPublicKeyVisitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::{PsParams, PsPublicKey, PsSigningKey};
    use crate::serde::Serializable;

    #[test]
    fn generate_key_pair_test() {
        let mut rng = rand::thread_rng();

        let params = PsParams::generate(&mut rng);

        let params_serialized = params.serialize().unwrap();
        let params_deserialized = PsParams::deserialize(&params_serialized).unwrap();

        assert_eq!(params, params_deserialized);

        let signing_key = PsSigningKey::generate(5, &params, &mut rng);

        let signing_key_serialized = signing_key.serialize().unwrap();
        let signing_key_deserialized = PsSigningKey::deserialize(&signing_key_serialized).unwrap();

        assert_eq!(signing_key, signing_key_deserialized);

        let public_key = signing_key.derive_public_key(&params);

        let public_key_serialized = public_key.serialize().unwrap();
        let public_key_deserialized = PsPublicKey::deserialize(&public_key_serialized).unwrap();

        assert_eq!(public_key, public_key_deserialized);
    }
}
