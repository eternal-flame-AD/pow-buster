//! Cerberus specific protocol structures.
use crate::{compute_mask_cerberus, message::CerberusMessage};

#[derive(serde::Deserialize, Debug)]
/// A Cerberus PoW challenge descriptor.
pub struct ChallengeDescriptor {
    challenge: String,
    difficulty: core::num::NonZeroU8,
    nonce: u64,
    ts: u64,
    signature: String,
}

impl ChallengeDescriptor {
    /// Build a pre-formatted message for the challenge.
    pub fn build_msg(&self, working_set: u32) -> Option<CerberusMessage> {
        let buf = format!(
            "{}|{}|{}|{}|",
            self.challenge, self.nonce, self.ts, self.signature
        );

        CerberusMessage::new(buf.as_bytes(), working_set)
    }

    /// Return the estimated workload.
    pub fn estimated_workload(&self) -> u64 {
        4u64.saturating_pow(self.difficulty.get().try_into().unwrap())
    }

    /// Return the mask.
    pub fn mask(&self) -> u64 {
        compute_mask_cerberus(self.difficulty)
    }

    /// Get the nonce of a Cerberus PoW.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Get the timestamp of a Cerberus PoW.
    pub fn ts(&self) -> u64 {
        self.ts
    }

    /// Get the signature of a Cerberus PoW.
    pub fn signature(&self) -> &str {
        &self.signature
    }
}
