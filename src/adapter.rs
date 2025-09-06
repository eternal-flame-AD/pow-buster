use crate::{Solver, compute_target_anubis};
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
        if let Some(mut solver) =
            crate::SingleBlockSolver::new((), self.challenge.as_ref().as_bytes())
        {
            solver.set_limit(limit);
            let result = solver.solve::<false>(target_u32s);
            let attempted_nonces = solver.get_attempted_nonces();
            (result, attempted_nonces)
        } else {
            let mut solver =
                crate::DoubleBlockSolver::new((), self.challenge.as_ref().as_bytes()).unwrap();
            let result = solver.solve::<false>(target_u32s);
            let attempted_nonces = solver.get_attempted_nonces();
            (result, attempted_nonces)
        }
    }
}

#[derive(serde::Deserialize, Debug)]
pub struct AnubisRules {
    algorithm: String,
    difficulty: u8,
}

impl AnubisRules {
    // if the instant is instantly solved and not worth task spawning
    pub fn instant(&self) -> bool {
        return self.algorithm == "preact";
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
}
