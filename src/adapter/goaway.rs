//! GoAway specific protocol structures.

use alloc::string::String;

use crate::{
    compute_mask_goaway,
    message::GoAwayMessage,
    solver::{SOLVE_TYPE_MASK, Solver},
};

#[derive(serde::Deserialize, Debug)]
/// GoAway "js-pow-sha256" PoW challenge configuration.
pub struct GoAwayConfig {
    /// The challenge. (JSON key: `challenge`)
    challenge: String,
    /// The target. (JSON key: `target`)
    // target: String,
    difficulty: core::num::NonZeroU8,
}

impl GoAwayConfig {
    /// Get the challenge of a GoAway "js-pow-sha256" PoW.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Get the difficulty of a GoAway "js-pow-sha256" PoW.
    pub fn difficulty(&self) -> core::num::NonZeroU8 {
        self.difficulty
    }

    /// Estimate the workload of a GoAway "js-pow-sha256" PoW.
    pub fn estimated_workload(&self) -> u64 {
        2u64.pow(self.difficulty.get().try_into().unwrap())
    }

    /// Solve a GoAway "js-pow-sha256" PoW.
    pub fn solve(&self) -> (Option<(u64, [u32; 8])>, u64) {
        self.solve_with_limit(u64::MAX)
    }

    /// Solve a GoAway "js-pow-sha256" PoW with a limit.
    pub fn solve_with_limit(&self, limit: u64) -> (Option<(u64, [u32; 8])>, u64) {
        let mask = compute_mask_goaway(self.difficulty);

        let Some(mut message) = self
            .challenge
            .as_bytes()
            .try_into()
            .ok()
            .and_then(|x| GoAwayMessage::new_hex(x, 0))
        else {
            return (None, 0);
        };

        let mut attempted_nonces = 0;

        for high_word in 0.. {
            message.set_high_word(high_word);

            let mut solver = crate::GoAwaySolver::from(message.clone());
            solver.set_limit(limit.saturating_sub(attempted_nonces));

            let res = solver.solve::<{ SOLVE_TYPE_MASK }>(0, mask);
            attempted_nonces += solver.get_attempted_nonces();

            if let Some(res) = res {
                return (Some(res), attempted_nonces);
            }

            if limit <= attempted_nonces {
                break;
            }
        }

        (None, attempted_nonces)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_goaway_solver_terminates() {
        let config = GoAwayConfig {
            challenge: String::from("abc"),
            difficulty: core::num::NonZeroU8::new(20).unwrap(),
        };

        let (result, attempted_nonces) = config.solve_with_limit(1000);
        assert!(result.is_none());
        assert!(attempted_nonces < 2000);
    }
}
