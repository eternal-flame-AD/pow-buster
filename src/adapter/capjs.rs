//! Cap.js specific protocol structures.
use crate::{
    message::{CapJSEmitter, DecimalMessage},
    solver::Solver,
};

use alloc::{string::String, vec::Vec};

#[derive(serde::Deserialize, Debug, Clone, Copy)]
/// Cap.js PoW challenge rules.
pub struct ChallengeRules {
    #[serde(rename = "c")]
    /// The count. (JSON key: `c`)
    pub count: usize,
    #[serde(rename = "s")]
    /// The salt length. (JSON key: `s`)
    pub salt_length: usize,
    #[serde(rename = "d")]
    /// The difficulty. (JSON key: `d`)
    pub difficulty: u8,
}

#[derive(serde::Deserialize, Debug, Clone)]
/// Cap.js PoW challenge descriptor.
pub struct ChallengeDescriptor {
    #[serde(rename = "challenge")]
    /// The rules. (JSON key: `challenge`)
    rules: ChallengeRules,
    /// The challenge token.
    pub token: String,
}

#[derive(serde::Serialize, Debug, Clone, Copy)]
/// Cap.js PoW response meta data.
pub struct SolveCapJsResponseMeta {
    #[cfg(feature = "std")]
    #[serde(rename = "elapsed_us")]
    elapsed: u64,
    attempted_nonces: u64,
    #[cfg(feature = "std")]
    hashrate: u64,
}

#[derive(serde::Serialize, Debug, Clone)]
/// Cap.js PoW response.
pub struct SolveCapJsResponse {
    #[serde(rename = "_meta")]
    /// The meta data.
    pub meta: SolveCapJsResponseMeta,
    /// The token.
    pub token: String,
    /// The solutions.
    pub solutions: Vec<f64>,
}

impl ChallengeDescriptor {
    /// Get the rules of a Cap.js PoW.
    pub fn rules(&self) -> &ChallengeRules {
        &self.rules
    }

    /// Solve a Cap.js PoW.
    pub fn solve(self) -> (Option<SolveCapJsResponse>, u64) {
        self.solve_with_limit(u64::MAX)
    }

    /// Estimate the workload of a Cap.js PoW.
    pub fn estimated_workload(&self) -> u64 {
        16u64
            .saturating_pow(self.rules.difficulty as u32)
            .saturating_mul(self.rules.count as u64)
    }

    /// Solve a Cap.js PoW with a limit in parallel.
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
                    let mut solver = crate::DecimalSolver::from(message);
                    solver.set_limit(limit_per_challenge);
                    let Some(nonce) = solver
                        .solve_nonce_only::<{ crate::solver::SOLVE_TYPE_MASK }>(
                            (targets[0] as u64) << 32 | targets[1] as u64,
                            mask,
                        )
                    else {
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

    /// Solve a Cap.js PoW with a limit.
    pub fn solve_with_limit(self, limit: u64) -> (Option<SolveCapJsResponse>, u64) {
        let emitter = CapJSEmitter::new(self.token.as_bytes());
        let mut attempted_nonces = 0;
        let mut response = SolveCapJsResponse {
            meta: SolveCapJsResponseMeta {
                #[cfg(feature = "std")]
                elapsed: 0,
                attempted_nonces,
                #[cfg(feature = "std")]
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
            let mut salt_buf = alloc::vec![0u8; self.rules.salt_length];
            let mut targets = [0; 2];
            emitter.emit(&mut salt_buf, &mut targets, i as u32 + 1);
            let mask = !0 << (64 - self.rules.difficulty as u64 * 4);
            let (message, fixup_prefix) =
                DecimalMessage::new_f64(&salt_buf, 0).expect("solver is None");
            let mut solver = crate::DecimalSolver::from(message);
            solver.set_limit(limit.saturating_sub(attempted_nonces));
            let Some(nonce) = solver.solve_nonce_only::<{ crate::solver::SOLVE_TYPE_MASK }>(
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
/// Cap.js PoW response.
#[serde(untagged)]
pub enum CapJsResponse {
    /// The solutions response.
    Solutions(CapJsRedeemedToken),
    /// The error response.
    Error {
        /// The error message.
        error: String,
    },
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
/// Cap.js PoW redeemed token.
pub struct CapJsRedeemedToken {
    /// The redeemed token.
    pub token: String,
    /// The expiration time.
    pub expires: u64,
}
