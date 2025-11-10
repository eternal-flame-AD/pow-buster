//! GoAway specific protocol structures.
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
            solver.solve::<{ SOLVE_TYPE_MASK }>(0, mask),
            solver.get_attempted_nonces(),
        )
    }
}
