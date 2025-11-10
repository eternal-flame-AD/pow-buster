use core::num::NonZeroU8;

use crate::{
    DecimalSolver, compute_mask_cerberus, compute_target_anubis, compute_target_goaway,
    message::{CapJSEmitter, CerberusMessage, DecimalMessage, GoAwayMessage},
    solver::{SOLVE_TYPE_LT, Solver},
};
use alloc::{format, string::String, vec::Vec};
use sha2::Digest;

#[derive(serde::Deserialize, Debug)]
/// A Cerberus PoW challenge descriptor.
pub struct CerberusChallengeDescriptor {
    challenge: String,
    difficulty: NonZeroU8,
    nonce: u64,
    ts: u64,
    signature: String,
}

impl CerberusChallengeDescriptor {
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
    pub fn mask(&self) -> u32 {
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

#[derive(serde::Deserialize, Debug)]
/// Anubis PoW challenge descriptor.
pub struct AnubisChallengeDescriptor {
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

impl AnubisChallengeDescriptor {
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

#[derive(serde::Deserialize, Debug)]
/// GoAway "js-pow-sha256" PoW challenge configuration.
pub struct GoAwayConfig {
    /// The challenge. (JSON key: `challenge`)
    challenge: String,
    /// The target. (JSON key: `target`)
    // target: String,
    difficulty: NonZeroU8,
}

impl GoAwayConfig {
    /// Get the challenge of a GoAway "js-pow-sha256" PoW.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Get the difficulty of a GoAway "js-pow-sha256" PoW.
    pub fn difficulty(&self) -> NonZeroU8 {
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
/// Cap.js PoW challenge rules.
pub struct CapJsChallengeRules {
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
pub struct CapJsChallengeDescriptor {
    #[serde(rename = "challenge")]
    /// The rules. (JSON key: `challenge`)
    rules: CapJsChallengeRules,
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

impl CapJsChallengeDescriptor {
    /// Get the rules of a Cap.js PoW.
    pub fn rules(&self) -> &CapJsChallengeRules {
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
                    let mut solver = DecimalSolver::from(message);
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
            let mut solver = DecimalSolver::from(message);
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
