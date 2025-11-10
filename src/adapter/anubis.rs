//! Anubis specific protocol structures.
use sha2::Digest;

use crate::{
    compute_mask_anubis,
    message::DecimalMessage,
    solver::{SOLVE_TYPE_MASK, Solver},
};

#[derive(serde::Deserialize, Debug)]
/// Anubis PoW challenge descriptor.
pub struct ChallengeDescriptor {
    challenge: ChallengeForm,
    rules: AnubisRules,
}

#[derive(serde::Deserialize, Debug)]
#[serde(untagged)]
/// Anubis PoW challenge form.
pub enum ChallengeForm {
    /// Plain challenge.
    Plain(String),
    /// Id wrapped challenge.
    #[serde(rename_all = "camelCase")]
    IdWrapped {
        /// The id.
        id: String,
        /// The random data.
        random_data: String,
    },
}

impl ChallengeForm {
    /// Get the id of an Anubis PoW challenge.
    pub fn id(&self) -> Option<&str> {
        match self {
            ChallengeForm::Plain(_) => None,
            ChallengeForm::IdWrapped { id, .. } => Some(id),
        }
    }
}

/// As reference to a string.
impl AsRef<str> for ChallengeForm {
    fn as_ref(&self) -> &str {
        match self {
            ChallengeForm::Plain(s) => s,
            ChallengeForm::IdWrapped { random_data, .. } => random_data,
        }
    }
}

impl ChallengeDescriptor {
    /// Estimate the workload of an Anubis PoW.
    pub fn estimated_workload(&self) -> u64 {
        if self.rules.algorithm == "preact" {
            return 1u64;
        }
        16u64.saturating_pow(self.rules.difficulty.try_into().unwrap())
    }

    /// Get the rules of an Anubis PoW.
    pub fn rules(&self) -> &AnubisRules {
        &self.rules
    }

    /// Get the hash result key of an Anubis PoW.
    pub fn hash_result_key(&self) -> &str {
        if self.rules.algorithm == "preact" {
            "result"
        } else {
            "response"
        }
    }

    /// Get the challenge of an Anubis PoW.
    pub fn challenge(&self) -> &ChallengeForm {
        &self.challenge
    }

    /// If the Anubis PoW is supported.
    pub fn supported(&self) -> bool {
        self.rules.algorithm == "fast"
            || self.rules.algorithm == "slow"
            || self.rules.algorithm == "preact"
    }

    /// Solve an Anubis PoW.
    pub fn solve(&self) -> (Option<(u64, [u32; 8])>, u64) {
        self.solve_with_limit(u64::MAX)
    }

    /// Delay to hold the solution before it will be accepted.
    pub fn delay(&self) -> u64 {
        if self.rules.algorithm == "preact" {
            self.rules.difficulty as u64 * 100
        } else {
            0
        }
    }

    /// Solve an Anubis PoW with a limit.
    pub fn solve_with_limit(&self, limit: u64) -> (Option<(u64, [u32; 8])>, u64) {
        if self.rules.algorithm == "preact" {
            let hash = sha2::Sha256::digest(self.challenge.as_ref().as_bytes());
            let mut hash_arr = [0u32; 8];
            for i in 0..8 {
                hash_arr[i] = u32::from_be_bytes(hash[i * 4..i * 4 + 4].try_into().unwrap());
            }
            return (Some((0, hash_arr)), 0);
        }
        let mask = compute_mask_anubis(self.rules.difficulty.try_into().unwrap());

        let mut result = None;
        let mut attempted_nonces = 0;
        let mut remaining_limit = limit;
        for search_bank in 0.. {
            let Some(message) =
                DecimalMessage::new(self.challenge.as_ref().as_bytes(), search_bank)
            else {
                break;
            };
            let mut solver = crate::DecimalSolver::from(message);
            solver.set_limit(remaining_limit);
            result = solver.solve::<{ SOLVE_TYPE_MASK }>(0, mask);
            attempted_nonces += solver.get_attempted_nonces();
            remaining_limit = remaining_limit.saturating_sub(solver.get_attempted_nonces());
            if result.is_some() || remaining_limit == 0 {
                break;
            }
        }

        (result, attempted_nonces)
    }
}

#[derive(serde::Deserialize, Debug)]
/// Anubis PoW challenge rules.
pub struct AnubisRules {
    /// The algorithm. (JSON key: `algorithm`)
    algorithm: String,
    difficulty: u8,
}

impl AnubisRules {
    /// If the instant is instantly or almost instantly solved and not worth task spawning.
    pub fn instant(&self) -> bool {
        return self.algorithm == "preact" || self.difficulty < 4;
    }

    /// Get the algorithm of an Anubis PoW.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
}
