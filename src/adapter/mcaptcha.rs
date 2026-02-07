//! mCaptcha specific protocol structures.

use alloc::string::String;

/// The API endpoint for getting a mCaptcha PoW configuration.
pub const API_POW_CONFIG: &str = "api/v1/pow/config";
/// The API endpoint for verifying a mCaptcha PoW.
pub const API_POW_VERIFY: &str = "api/v1/pow/verify";

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
/// mCaptcha PoW configuration
pub struct PoWConfig {
    /// the string to hash  
    pub string: String,
    /// the difficulty factor
    pub difficulty_factor: u32,
    /// the salt
    pub salt: String,
}

#[derive(Clone, serde::Serialize, Debug)]
/// mCaptcha PoW work unit definition
pub struct Work<'a> {
    /// the string to hash
    pub string: String,
    /// the result
    pub result: String,
    /// the nonce
    pub nonce: u64,
    /// the key
    pub key: &'a str,
}

#[derive(Clone, serde::Deserialize, Debug)]
/// mCaptcha PoW response token.
pub struct TokenResponse {
    /// the token
    pub token: String,
}
