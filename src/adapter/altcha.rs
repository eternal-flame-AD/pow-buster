use std::num::NonZeroU32;

use crate::adapter::FixedHexString;

#[derive(serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    #[serde(rename = "SHA-256")]
    SHA256Nest,
    #[serde(rename = "PBKDF2/SHA-256")]
    SHA256Pbkdf2,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeDescriptor {
    pub algorithm: Algorithm,
    pub nonce: FixedHexString<16>,
    pub salt: FixedHexString<16>,
    pub key_prefix: FixedHexString<4>,
    pub cost: NonZeroU32,
    // truncate output bytes
    pub key_length: NonZeroU32,
}
