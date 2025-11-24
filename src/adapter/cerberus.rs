//! Cerberus specific protocol structures.
use crate::{
    compute_mask_cerberus,
    message::{CerberusBinaryMessage, CerberusDecimalMessage, CerberusMessage},
    solver::Solver,
};

use alloc::{format, string::String};
use semver::{BuildMetadata, Prerelease};

#[derive(serde::Deserialize, Debug)]
/// A Cerberus PoW challenge descriptor.
pub struct ChallengeDescriptor {
    challenge: String,
    difficulty: core::num::NonZeroU8,
    nonce: u64,
    ts: u64,
    signature: String,
    version: MaybeSemver,
}

#[derive(Debug)]
enum MaybeSemver {
    Yes(semver::Version),
    Unknown,
}

impl<'de> serde::Deserialize<'de> for MaybeSemver {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match semver::Version::deserialize(deserializer) {
            Ok(v) => Ok(MaybeSemver::Yes(v)),
            Err(_) => Ok(MaybeSemver::Unknown),
        }
    }
}

impl ChallengeDescriptor {
    /// Build a pre-formatted message for the challenge.
    pub fn build_msg(&self, working_set: u32) -> Option<CerberusMessage> {
        let buf = format!(
            "{}|{}|{}|{}|",
            self.challenge, self.nonce, self.ts, self.signature
        );

        const VERSION_FOR_BINARY: semver::Version = semver::Version {
            major: 0,
            minor: 4,
            patch: 6,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        };

        Some(
            if let MaybeSemver::Yes(version) = &self.version
                && *version < VERSION_FOR_BINARY
            {
                CerberusMessage::Decimal(CerberusDecimalMessage::new(buf.as_bytes(), working_set)?)
            } else {
                CerberusMessage::Binary(CerberusBinaryMessage::new(buf.as_bytes(), working_set))
            },
        )
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

    /// Solve a Cerberus PoW.
    pub fn solve(&self) -> (Option<(u64, [u32; 8])>, u64) {
        self.solve_with_limit(u64::MAX)
    }

    /// Solve a Cerberus PoW with a limit.
    pub fn solve_with_limit(&self, limit: u64) -> (Option<(u64, [u32; 8])>, u64) {
        let mask = compute_mask_cerberus(self.difficulty);

        let mut result = None;
        let mut attempted_nonces = 0;
        let mut remaining_limit = limit;
        for search_bank in 0.. {
            let Some(message) = self.build_msg(search_bank) else {
                break;
            };
            let mut solver = crate::CerberusSolver::from(message);
            solver.set_limit(remaining_limit);
            result = solver.solve::<{ crate::solver::SOLVE_TYPE_MASK }>(0, mask);
            attempted_nonces += solver.get_attempted_nonces();
            remaining_limit = remaining_limit.saturating_sub(solver.get_attempted_nonces());
            if result.is_some() || remaining_limit == 0 {
                break;
            }
        }

        (result, attempted_nonces)
    }
}
