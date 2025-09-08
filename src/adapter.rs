use core::num::NonZeroU8;

use crate::{
    compute_target_anubis, compute_target_goaway,
    message::{DecimalMessage, GoAwayMessage},
    solver::Solver,
};
use alloc::string::String;
use sha2::Digest;

#[derive(serde::Deserialize, Debug)]
pub struct AnubisChallengeDescriptor {
    challenge: ChallengeForm,
    rules: AnubisRules,
}

#[derive(serde::Deserialize, Debug)]
#[serde(untagged)]
pub enum ChallengeForm {
    Plain(String),
    #[serde(rename_all = "camelCase")]
    IdWrapped {
        id: String,
        random_data: String,
    },
}

impl ChallengeForm {
    pub fn id(&self) -> Option<&str> {
        match self {
            ChallengeForm::Plain(_) => None,
            ChallengeForm::IdWrapped { id, .. } => Some(id),
        }
    }
}

impl AsRef<str> for ChallengeForm {
    fn as_ref(&self) -> &str {
        match self {
            ChallengeForm::Plain(s) => s,
            ChallengeForm::IdWrapped { random_data, .. } => random_data,
        }
    }
}

impl AnubisChallengeDescriptor {
    pub fn estimated_workload(&self) -> u64 {
        16u64.pow(self.rules.difficulty.try_into().unwrap())
    }

    pub fn rules(&self) -> &AnubisRules {
        &self.rules
    }

    pub fn hash_result_key(&self) -> &str {
        if self.rules.algorithm == "preact" {
            "result"
        } else {
            "response"
        }
    }

    pub fn challenge(&self) -> &ChallengeForm {
        &self.challenge
    }

    pub fn supported(&self) -> bool {
        self.rules.algorithm == "fast"
            || self.rules.algorithm == "slow"
            || self.rules.algorithm == "preact"
    }

    pub fn solve(&self) -> (Option<(u64, [u32; 8])>, u64) {
        self.solve_with_limit(u64::MAX)
    }

    // delay to hold the solution before it will be accepted
    pub fn delay(&self) -> u64 {
        if self.rules.algorithm == "preact" {
            self.rules.difficulty as u64 * 100
        } else {
            0
        }
    }

    pub fn solve_with_limit(&self, limit: u64) -> (Option<(u64, [u32; 8])>, u64) {
        if self.rules.algorithm == "preact" {
            let hash = sha2::Sha256::digest(self.challenge.as_ref().as_bytes());
            let mut hash_arr = [0u32; 8];
            for i in 0..8 {
                hash_arr[i] = u32::from_be_bytes(hash[i * 4..i * 4 + 4].try_into().unwrap());
            }
            return (Some((0, hash_arr)), 0);
        }
        let target = compute_target_anubis(self.rules.difficulty.try_into().unwrap());
        let target_bytes = target.to_be_bytes();
        let target_u32s = core::array::from_fn(|i| {
            u32::from_be_bytes([
                target_bytes[i * 4],
                target_bytes[i * 4 + 1],
                target_bytes[i * 4 + 2],
                target_bytes[i * 4 + 3],
            ])
        });

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
            result = solver.solve::<false>(target_u32s);
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
pub struct AnubisRules {
    algorithm: String,
    difficulty: u8,
}

impl AnubisRules {
    // if the instant is instantly or almost instantly solved and not worth task spawning
    pub fn instant(&self) -> bool {
        return self.algorithm == "preact" || self.difficulty < 4;
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
}

#[derive(serde::Deserialize, Debug)]
pub struct GoAwayConfig {
    challenge: String,
    // target: String,
    difficulty: NonZeroU8,
}

impl GoAwayConfig {
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    pub fn difficulty(&self) -> NonZeroU8 {
        self.difficulty
    }

    pub fn estimated_workload(&self) -> u64 {
        2u64.pow(self.difficulty.get().try_into().unwrap())
    }

    pub fn solve(&self) -> (Option<(u64, [u32; 8])>, u64) {
        self.solve_with_limit(u64::MAX)
    }

    pub fn solve_with_limit(&self, limit: u64) -> (Option<(u64, [u32; 8])>, u64) {
        let target = compute_target_goaway(self.difficulty);
        let target_bytes = target.to_be_bytes();
        let target_u32s = core::array::from_fn(|i| {
            u32::from_be_bytes([
                target_bytes[i * 4],
                target_bytes[i * 4 + 1],
                target_bytes[i * 4 + 2],
                target_bytes[i * 4 + 3],
            ])
        });

        let Some(message) = self
            .challenge
            .as_bytes()
            .try_into()
            .ok()
            .and_then(GoAwayMessage::new_hex)
        else {
            return (None, 0);
        };
        let mut solver = crate::GoAwaySolver::from(message);
        solver.set_limit(limit);

        (
            solver.solve::<false>(target_u32s),
            solver.get_attempted_nonces(),
        )
    }
}
