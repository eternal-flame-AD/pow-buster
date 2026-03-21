//! Altcha specific protocol structures.
use std::num::NonZeroU32;

use crate::adapter::FixedHexString;

#[derive(serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
/// Altcha supported algorithms.
pub enum Algorithm {
    #[serde(rename = "SHA-256")]
    /// Nested SHA-256
    SHA256Nest,
    #[serde(rename = "PBKDF2/SHA-256")]
    /// PBKDF SHA-256
    SHA256Pbkdf2,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// Altcha challenge descriptor
pub struct ChallengeDescriptor {
    pub(crate) algorithm: Algorithm,
    pub(crate) nonce: FixedHexString<16>,
    pub(crate) salt: FixedHexString<16>,
    pub(crate) cost: NonZeroU32,
    pub(crate) key_length: NonZeroU32,
}
