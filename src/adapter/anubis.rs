//! Anubis specific protocol structures.
use sha2::Digest;

use crate::{
    compute_mask_bits, compute_mask_nibbles,
    message::{BinaryMessage, DecimalMessage},
    solver::{SOLVE_TYPE_MASK, Solver},
};
use alloc::string::String;

#[cfg(feature = "hashx")]
fn make_hashx(data_slice: &[u8]) -> ::hashx::HashX {
    if let Ok(h) = ::hashx::HashX::new(data_slice) {
        return h;
    }

    let mut seed = Vec::with_capacity(data_slice.len() + 4);
    let mut counter: u32 = 0;
    loop {
        seed.clear();
        seed.extend_from_slice(data_slice);
        seed.extend_from_slice(&counter.to_le_bytes());
        if let Ok(h) = ::hashx::HashX::new(&seed) {
            return h;
        }
        counter = counter.wrapping_add(1);
    }
}

#[cfg(all(feature = "hashx", feature = "jit-infra", target_arch = "x86_64"))]
fn make_hashx_vendor(data_slice: &[u8]) -> crate::hashx::hashx_vendor::HashX {
    if let Ok(h) = crate::hashx::hashx_vendor::HashX::new(data_slice) {
        return h;
    }

    let mut seed = Vec::with_capacity(data_slice.len() + 4);
    let mut counter: u32 = 0;
    loop {
        seed.clear();
        seed.extend_from_slice(data_slice);
        seed.extend_from_slice(&counter.to_le_bytes());
        if let Ok(h) = crate::hashx::hashx_vendor::HashX::new(&seed) {
            return h;
        }
        counter = counter.wrapping_add(1);
    }
}

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
        if self.rules.algorithm == "fast" || self.rules.algorithm == "slow" {
            return 16u64.saturating_pow(self.rules.difficulty.try_into().unwrap());
        }
        2u64.saturating_pow(self.rules.difficulty.try_into().unwrap())
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
            || self.rules.algorithm == "sha256"
            || (cfg!(feature = "hashx") && self.rules.algorithm == "hashx")
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

        match self.rules.algorithm.as_str() {
            #[cfg(all(feature = "hashx", feature = "jit-infra", target_arch = "x86_64"))]
            // AVX512DQ vectorized sifter solution
            "hashx" if crate::hashx::hashx_avx512dq::cpuid_check() => {
                use crate::{compute_mask_hashx, hashx::hashx_avx512dq::*};
                let Ok(salt) = ::hex::decode(self.challenge.as_ref()) else {
                    return (None, limit);
                };

                let h = make_hashx_vendor(&salt);

                struct SolveCtx {
                    map: crate::jit::exec_map::ExecMap,
                    data: Box<DataBuffer>,
                }

                thread_local! {
                    static SOLVE_CTX: std::cell::RefCell<SolveCtx> = {
                        let map = crate::jit::exec_map::ExecMap::new(CompiledSifter::WANTED_SIZE).unwrap();
                        let data = unsafe { Box::<DataBuffer>::new_zeroed().assume_init() };
                        std::cell::RefCell::new(SolveCtx { map, data })
                    };
                }

                SOLVE_CTX.with_borrow_mut(|SolveCtx { map, data }| {
                    let sifter =
                        CompiledSifter::new_ex(map, data, &h, crate::hashx::TestMode::Mask, false);

                    let mask = compute_mask_hashx(self.rules.difficulty.try_into().unwrap());

                    let mut input_offset = 0;
                    let mut hit_mask = 0;
                    while hit_mask == 0 {
                        if input_offset >= limit {
                            return (None, limit);
                        }
                        hit_mask = sifter.sift(mask, &mut input_offset);
                    }
                    let nonce = input_offset + hit_mask.trailing_zeros() as u64;
                    let hash = h.hash_to_bytes(nonce);

                    let output = core::array::from_fn(|i| {
                        u32::from_be_bytes(hash[i * 4..][..4].try_into().unwrap())
                    });

                    (Some((nonce, output)), nonce as _)
                })
            }
            #[cfg(feature = "hashx")]
            // official amd64, a64 JIT and interpreter solution
            "hashx" => {
                let Ok(salt) = ::hex::decode(self.challenge.as_ref()) else {
                    return (None, limit);
                };
                let h = make_hashx(&salt);

                for nonce in 0..limit {
                    let hash = h.hash_to_bytes(nonce as u64);

                    if u32::from_be_bytes(hash[..4].try_into().unwrap()).leading_zeros()
                        >= self.rules.difficulty as _
                    {
                        let output = core::array::from_fn(|i| {
                            u32::from_be_bytes(hash[i * 4..][..4].try_into().unwrap())
                        });

                        return (Some((nonce, output)), nonce as _);
                    }
                }

                (None, limit)
            }
            "sha256" => {
                let Ok(salt) = ::hex::decode(self.challenge.as_ref()) else {
                    return (None, limit);
                };
                let mask = compute_mask_bits(self.rules.difficulty.try_into().unwrap());

                let use_le = salt.as_slice().last().copied().unwrap_or(0) >= 128;

                let message = BinaryMessage::new(&salt, 4.try_into().unwrap());

                let mut solver = crate::BinarySolver::from(message);
                solver.set_limit(limit);
                let result = solver
                    .solve::<{ SOLVE_TYPE_MASK }>(0, mask)
                    .map(|(nonce, hash)| {
                        let mut n32: u32 = nonce.try_into().unwrap();

                        if !use_le {
                            n32 = n32.swap_bytes()
                        }

                        (n32 as _, hash)
                    });

                (result, solver.get_attempted_nonces())
            }
            "fast" | "slow" => {
                let mask = compute_mask_nibbles(self.rules.difficulty.try_into().unwrap());
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
            _ => (None, 0),
        }
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
        return self.algorithm == "preact"
            || self.difficulty < 4
            || (self.algorithm != "fast" && self.algorithm != "slow" && self.difficulty < 16);
    }

    /// Get the algorithm of an Anubis PoW.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "hashx")]
    fn test_anubis_solve_hashx() {
        fn validate(hash: &[u8], difficulty: u32) -> bool {
            let mut remaining = difficulty;
            for &byte in hash {
                // If we're out of bits to check, exit. This is all good.
                if remaining == 0 {
                    break;
                }

                // If there are more than 8 bits remaining, the entire byte should be a
                // zero. This fast-path compares the byte to 0 and if it matches, subtract
                // 8 bits.
                if remaining >= 8 {
                    if byte != 0 {
                        return false;
                    }
                    remaining -= 8;
                } else {
                    // Otherwise mask off individual bits and check against them.
                    let mask = 0xFF << (8 - remaining);
                    if (byte & mask) != 0 {
                        return false;
                    }
                    remaining = 0;
                }
            }
            true
        }

        let salt = "test";
        let descriptor = ChallengeDescriptor {
            challenge: ChallengeForm::Plain(hex::encode(salt.as_bytes())),
            rules: AnubisRules {
                algorithm: "hashx".to_string(),
                difficulty: 13,
            },
        };
        let (result, nonce) = descriptor.solve();
        assert!(result.is_some());

        let mut output = [0; _];
        crate::encode_hex(&mut output, result.unwrap().1);
        let output = String::from_utf8(output.into()).unwrap();

        let h = make_hashx(salt.as_bytes());
        let expected = h.hash_to_bytes(nonce);
        let got_difficulty = u32::from_be_bytes(expected[..4].try_into().unwrap()).leading_zeros();
        assert!(got_difficulty >= 13);
        assert!(validate(&expected, 13));
        let mut expected_hex = String::new();
        for b in expected {
            expected_hex.push_str(&format!("{:02x}", b));
        }
        eprintln!("expected_hex: {}", expected_hex);
        assert_eq!(output, expected_hex);
    }
}
