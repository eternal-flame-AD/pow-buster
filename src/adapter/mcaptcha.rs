//! mCaptcha specific protocol structures.
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
