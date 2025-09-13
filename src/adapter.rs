use core::num::NonZeroU8;

use crate::{
    DecimalSolver, compute_target_anubis, compute_target_goaway,
    message::{CapJSEmitter, DecimalMessage, GoAwayMessage},
    solver::{SOLVE_TYPE_LT, Solver},
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
        16u64.saturating_pow(self.rules.difficulty.try_into().unwrap())
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
            result = solver.solve::<{ SOLVE_TYPE_LT }>(target, !0);
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
            solver.solve::<{ SOLVE_TYPE_LT }>(target, !0),
            solver.get_attempted_nonces(),
        )
    }
}

#[derive(serde::Deserialize, Debug, Clone, Copy)]
pub struct CapJsChallengeRules {
    #[serde(rename = "c")]
    pub count: usize,
    #[serde(rename = "s")]
    pub salt_length: usize,
    #[serde(rename = "d")]
    pub difficulty: u8,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct CapJsChallengeDescriptor {
    #[serde(rename = "challenge")]
    rules: CapJsChallengeRules,
    pub token: String,
}

#[derive(serde::Serialize, Debug, Clone, Copy)]
pub struct SolveCapJsResponseMeta {
    #[cfg(feature = "std")]
    #[serde(rename = "elapsed_us")]
    elapsed: u64,
    attempted_nonces: u64,
    #[cfg(feature = "std")]
    hashrate: u64,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct SolveCapJsResponse {
    #[serde(rename = "_meta")]
    pub meta: SolveCapJsResponseMeta,
    pub token: String,
    pub solutions: Vec<f64>,
}

impl CapJsChallengeDescriptor {
    pub fn rules(&self) -> &CapJsChallengeRules {
        &self.rules
    }

    pub fn solve(self) -> (Option<SolveCapJsResponse>, u64) {
        self.solve_with_limit(u64::MAX)
    }

    pub fn estimated_workload(&self) -> u64 {
        16u64
            .saturating_pow(self.rules.difficulty as u32)
            .saturating_mul(self.rules.count as u64)
    }

    #[cfg(feature = "rayon")]
    pub fn solve_with_limit_parallel(
        self,
        pool: &rayon::ThreadPool,
        limit_per_challenge: u64,
    ) -> (Option<SolveCapJsResponse>, u64) {
        let emitter = CapJSEmitter::new(self.token.as_bytes());
        let attempted_nonces = core::sync::atomic::AtomicU64::new(0);
        let mut response = SolveCapJsResponse {
            meta: SolveCapJsResponseMeta {
                elapsed: 0,
                attempted_nonces: 0,
                hashrate: 0,
            },
            token: self.token,
            solutions: vec![0f64; self.rules.count],
        };
        let elapsed = pool.install(|| {
            use rayon::prelude::*;
            let start = std::time::Instant::now();
            response.solutions.par_iter_mut().enumerate().for_each(
                |(i, solution): (usize, &mut f64)| {
                    let mut salt_buf = vec![0u8; self.rules.salt_length];
                    let mut targets = [0; 2];
                    emitter.emit(&mut salt_buf, &mut targets, i as u32 + 1);
                    let mask = !0 << (64 - self.rules.difficulty as u64 * 4);
                    let (message, fixup_prefix) =
                        DecimalMessage::new_f64(&salt_buf, 0).expect("solver is None");
                    let mut solver = DecimalSolver::from(message);
                    solver.set_limit(limit_per_challenge);
                    let Some((nonce, _hash)) = solver.solve::<{ crate::solver::SOLVE_TYPE_MASK }>(
                        (targets[0] as u64) << 32 | targets[1] as u64,
                        mask,
                    ) else {
                        return;
                    };
                    attempted_nonces.fetch_add(
                        solver.get_attempted_nonces(),
                        core::sync::atomic::Ordering::Relaxed,
                    );
                    let nonce_f64 = fixup_prefix
                        .map(|x| x.fixup(nonce as u64))
                        .unwrap_or(nonce as f64);
                    *solution = nonce_f64;
                },
            );
            start.elapsed()
        });
        let attempted_nonces = attempted_nonces.load(core::sync::atomic::Ordering::Relaxed);
        response.meta.elapsed = elapsed.as_micros() as u64;
        response.meta.attempted_nonces = attempted_nonces;
        response.meta.hashrate =
            attempted_nonces as u64 * 1000 * 1000 / response.meta.elapsed as u64;
        (Some(response), attempted_nonces)
    }

    pub fn solve_with_limit(self, limit: u64) -> (Option<SolveCapJsResponse>, u64) {
        let emitter = CapJSEmitter::new(self.token.as_bytes());
        let mut attempted_nonces = 0;
        let mut response = SolveCapJsResponse {
            meta: SolveCapJsResponseMeta {
                #[cfg(feature = "std")]
                elapsed: 0,
                attempted_nonces,
                hashrate: 0,
            },
            token: self.token,
            solutions: Vec::with_capacity(self.rules.count),
        };
        #[cfg(feature = "std")]
        let start = std::time::Instant::now();
        for i in 0..self.rules.count {
            if limit.saturating_sub(attempted_nonces) == 0 {
                break;
            }
            let mut salt_buf = vec![0u8; self.rules.salt_length];
            let mut targets = [0; 2];
            emitter.emit(&mut salt_buf, &mut targets, i as u32 + 1);
            let mask = !0 << (64 - self.rules.difficulty as u64 * 4);
            let (message, fixup_prefix) =
                DecimalMessage::new_f64(&salt_buf, 0).expect("solver is None");
            let mut solver = DecimalSolver::from(message);
            solver.set_limit(limit.saturating_sub(attempted_nonces));
            let Some((nonce, _hash)) = solver.solve::<{ crate::solver::SOLVE_TYPE_MASK }>(
                (targets[0] as u64) << 32 | targets[1] as u64,
                mask,
            ) else {
                return (None, attempted_nonces);
            };
            attempted_nonces += solver.get_attempted_nonces();
            response.solutions.push(
                fixup_prefix
                    .map(|x| x.fixup(nonce as u64))
                    .unwrap_or(nonce as f64),
            );
        }
        #[cfg(feature = "std")]
        {
            response.meta.elapsed = start.elapsed().as_micros() as u64;
            response.meta.hashrate =
                attempted_nonces as u64 * 1000 * 1000 / response.meta.elapsed as u64;
        }
        response.meta.attempted_nonces = attempted_nonces;
        (Some(response), attempted_nonces)
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
#[serde(untagged)]
pub enum CapJsResponse {
    Solutions(CapJsRedeemedToken),
    Error { error: String },
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct CapJsRedeemedToken {
    pub token: String,
    pub expires: u64,
}
