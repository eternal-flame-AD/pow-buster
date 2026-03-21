/// AVX-512 solver
#[cfg(target_arch = "x86_64")]
pub mod avx512;

/// AVX2 solver
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub mod avx2;

/// SIMD128 solver
#[cfg(target_arch = "wasm32")]
pub mod simd128;

/// Safe solver
pub mod safe;

/// Less than test (such as Anubis and GoAway)
pub const SOLVE_TYPE_LT: u8 = 1;
/// Greater than test (such as mCaptcha)
pub const SOLVE_TYPE_GT: u8 = 2;
/// Mask test (such as Cap.js)
pub const SOLVE_TYPE_MASK: u8 = 4;

pub(crate) const HMAC_IPAD: u8 = 0x36;
pub(crate) const HMAC_IPAD32: u32 = u32::from_be_bytes([HMAC_IPAD; 4]);
pub(crate) const HMAC_OPAD: u8 = 0x5c;
pub(crate) const HMAC_OPAD32: u32 = u32::from_be_bytes([HMAC_OPAD; 4]);

/// A token for checking CPU features
pub trait CpuIDToken: Default + Copy + Clone + 'static {
    /// Get the CPU feature status
    fn get() -> bool;
}

/// A solver router that can take a solver or a fallback solver based on the CPU features
#[derive(Debug, Copy, Clone)]
#[allow(missing_docs)]
#[cfg_attr(not(feature = "runtime-dispatch"), repr(transparent))]
pub enum SolverRouter<T: CpuIDToken, M, S: Solver + From<M>, F: Solver + From<M>> {
    #[cfg(feature = "runtime-dispatch")]
    Taken {
        solver: S,
        _marker: core::marker::PhantomData<(S, F, T, M)>,
    },
    Fallback {
        solver: F,
        _marker: core::marker::PhantomData<(S, F, T, M)>,
    },
}

impl<T: CpuIDToken, M, S: Solver + From<M>, F: Solver + From<M>> From<M>
    for SolverRouter<T, M, S, F>
{
    fn from(value: M) -> Self {
        #[cfg(feature = "runtime-dispatch")]
        if T::get() {
            return Self::Taken {
                solver: value.into(),
                _marker: core::marker::PhantomData,
            };
        }
        Self::Fallback {
            solver: value.into(),
            _marker: core::marker::PhantomData,
        }
    }
}

impl<O: Copy, T: CpuIDToken, M, S: Solver<Output = O> + From<M>, F: Solver<Output = O> + From<M>>
    Solver for SolverRouter<T, M, S, F>
{
    type Output = O;

    fn set_limit(&mut self, limit: u64) {
        match self {
            #[cfg(feature = "runtime-dispatch")]
            Self::Taken { solver, .. } => solver.set_limit(limit),
            Self::Fallback { solver, .. } => solver.set_limit(limit),
        }
    }
    fn get_attempted_nonces(&self) -> u64 {
        match self {
            #[cfg(feature = "runtime-dispatch")]
            Self::Taken { solver, .. } => solver.get_attempted_nonces(),
            Self::Fallback { solver, .. } => solver.get_attempted_nonces(),
        }
    }

    #[inline]
    fn solve_nonce_only<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<u64> {
        match self {
            #[cfg(feature = "runtime-dispatch")]
            Self::Taken { solver, .. } => solver.solve_nonce_only::<TYPE>(target, mask),
            Self::Fallback { solver, .. } => solver.solve_nonce_only::<TYPE>(target, mask),
        }
    }

    #[inline]
    fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, Self::Output)> {
        match self {
            #[cfg(feature = "runtime-dispatch")]
            Self::Taken { solver, .. } => solver.solve::<TYPE>(target, mask),
            Self::Fallback { solver, .. } => solver.solve::<TYPE>(target, mask),
        }
    }
}

/// A generic solver trait
pub trait Solver {
    /// The output type
    type Output: Copy;

    /// Returns a valid nonce and its corresponding hash value.
    ///
    /// Supported schemes:
    ///
    /// - `SOLVE_TYPE_LT`: Less than test (such as Anubis and GoAway)
    /// - `SOLVE_TYPE_GT`: Greater than test (such as mCaptcha)
    /// - `SOLVE_TYPE_MASK`: Mask test (such as Cap.js)
    ///
    /// Currently bitmasking `SOLVE_TYPE_MASK` with `SOLVE_TYPE_GT` or `SOLVE_TYPE_LT` is not supported and may result in unexpected behavior.
    ///
    /// Returns None when the solver cannot solve the prefix.
    ///
    /// Failure is usually because the key space is exhausted (or presumed exhausted).
    /// It should by design happen extremely rarely for common difficulty settings.
    fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, Self::Output)>;

    /// Returns a valid nonce without the actual hash.
    ///
    /// A trivial implementation is provided by default.
    #[inline]
    fn solve_nonce_only<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<u64> {
        self.solve::<TYPE>(target, mask).map(|(nonce, _)| nonce)
    }

    /// Set the limit.
    fn set_limit(&mut self, limit: u64);

    /// Get the attempted nonces.
    fn get_attempted_nonces(&self) -> u64;
}

/// A dyn-dispatching wrapper for Solver
pub trait SolverDyn {
    /// The output type
    type Output: Copy;

    /// A dynamic dispatching wrapper for solve
    fn solve_dyn(&mut self, target: u64, ty: u8, mask: u64) -> Option<(u64, Self::Output)>;
    /// A dynamic dispatching wrapper for solve_nonce_only
    fn solve_nonce_only_dyn(&mut self, target: u64, ty: u8, mask: u64) -> Option<u64>;
}

impl<S: Solver> SolverDyn for S {
    type Output = S::Output;

    // A dynamic dispatching wrapper for solve
    fn solve_dyn(&mut self, target: u64, ty: u8, mask: u64) -> Option<(u64, Self::Output)> {
        match ty {
            SOLVE_TYPE_LT => self.solve::<SOLVE_TYPE_LT>(target, mask),
            SOLVE_TYPE_GT => self.solve::<SOLVE_TYPE_GT>(target, mask),
            _ => self.solve::<SOLVE_TYPE_MASK>(target, mask),
        }
    }

    // A dynamic dispatching wrapper for solve_nonce_only
    fn solve_nonce_only_dyn(&mut self, target: u64, ty: u8, mask: u64) -> Option<u64> {
        match ty {
            SOLVE_TYPE_LT => self.solve_nonce_only::<SOLVE_TYPE_LT>(target, mask),
            SOLVE_TYPE_GT => self.solve_nonce_only::<SOLVE_TYPE_GT>(target, mask),
            _ => self.solve_nonce_only::<SOLVE_TYPE_MASK>(target, mask),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use core::num::NonZeroU8;
    use std::io::Write;

    use pbkdf2::hmac::Hmac;
    use sha2::{Digest, Sha256};

    mod pow_sha256;

    use crate::{
        compute_mask_anubis, compute_mask_cerberus, compute_mask_goaway, compute_target_mcaptcha,
        extract128_be, message::IEEE754LosslessFixupPrefix,
    };

    use super::*;

    /// Extract top 64 bits from a 64-bit word array
    const fn extract64_be(inp: [u32; 8]) -> u64 {
        (inp[0] as u64) << 32 | (inp[1] as u64)
    }

    pub(crate) fn test_decimal_validator<
        S: Solver<Output = [u32; 8]>,
        F: for<'a> FnMut(&'a [u8], u32) -> Option<S>,
    >(
        mut factory: F,
    ) {
        for phrase_len in 0..64 {
            let mut concatenated_prefix = b"abc".to_vec();
            let phrase_str = String::from_iter(std::iter::repeat('a').take(phrase_len));
            concatenated_prefix.extend_from_slice(&bincode::serialize(&phrase_str).unwrap());

            let config = pow_sha256::Config {
                salt: String::from("abc"),
            };
            const DIFFICULTY: u32 = 100_000;
            const ANUBIS_DIFFICULTY: NonZeroU8 = NonZeroU8::new(4).unwrap();

            for search_space in [0, 1, 9, 10, 11] {
                let Some(mut solver) = factory(&concatenated_prefix, search_space) else {
                    assert_ne!(
                        search_space, 0,
                        "solver is None for search_space: {}",
                        search_space
                    );
                    break;
                };
                let Some(mut anubis_solver) = factory(&concatenated_prefix, search_space) else {
                    assert_ne!(
                        search_space, 0,
                        "anubis solver is None for search_space: {}",
                        search_space
                    );
                    break;
                };
                let Some(mut eq_solver) = factory(&concatenated_prefix, search_space) else {
                    assert_ne!(
                        search_space, 0,
                        "eq solver is None for search_space: {}",
                        search_space
                    );
                    break;
                };

                let target_bytes = compute_target_mcaptcha(DIFFICULTY as u64).to_be_bytes();
                let target_u64 = u64::from_be_bytes(target_bytes[..8].try_into().unwrap());
                let mask_anubis = compute_mask_anubis(ANUBIS_DIFFICULTY);
                let (nonce, result) = solver
                    .solve::<SOLVE_TYPE_GT>(target_u64, !0)
                    .expect("solver failed");
                let result_u128 = extract128_be(result);
                let (anubis_nonce, anubis_result) = anubis_solver
                    .solve::<SOLVE_TYPE_MASK>(0, mask_anubis)
                    .expect("solver failed");
                let anubis_result_u64 = extract64_be(anubis_result);
                let anubis_expected_hash = {
                    let mut msg = concatenated_prefix.clone();
                    write!(msg, "{}", anubis_nonce).unwrap();
                    sha2::Sha256::digest(msg.as_slice())
                };
                let anubis_result_bytes = anubis_result_u64.to_be_bytes();
                assert_eq!(anubis_expected_hash[..8], anubis_result_bytes);
                assert_eq!(
                    ((anubis_result[0] as u64) << 32 | (anubis_result[1] as u64)) & mask_anubis,
                    0,
                    "[{}] anubis_result: {:016x} & mask_anubis: {:016x} == 0 (solver: {}, search_space: {})",
                    core::any::type_name::<S>(),
                    anubis_result_u64,
                    mask_anubis,
                    core::any::type_name::<S>(),
                    search_space
                );

                let test_response = pow_sha256::PoW::new(nonce, result_u128.to_string());
                assert_eq!(
                    config.calculate(&test_response, &phrase_str).unwrap(),
                    result_u128,
                    "test_response: {:?} (solver: {}, search_space: {})",
                    test_response,
                    core::any::type_name::<S>(),
                    search_space
                );

                assert!(
                    config.is_valid_proof(&test_response, &phrase_str),
                    "{} is not valid proof (solver: {})",
                    result_u128,
                    core::any::type_name::<S>()
                );

                assert!(
                    config.is_sufficient_difficulty(&test_response, DIFFICULTY),
                    "{:016x} is not sufficient difficulty, expected {:016x} (solver: {})",
                    result_u128,
                    compute_target_mcaptcha(DIFFICULTY as u64),
                    core::any::type_name::<S>()
                );

                // based on proof-of-work.mjs
                for i in 0..ANUBIS_DIFFICULTY.get() as usize {
                    let byte_index = i / 2;
                    let nibble_index = (1 - i % 2) as u8;

                    let nibble = (anubis_result_bytes[byte_index] >> (nibble_index * 4)) & 0x0f;
                    assert_eq!(
                        nibble,
                        0,
                        "{:08x} is not valid anubis proof (solver: {}, nibble: {})",
                        anubis_result_u64,
                        core::any::type_name::<S>(),
                        i
                    );
                }

                let u64_target = 0b10111 << (64 - 5);

                let (_, eq_result) = eq_solver
                    .solve::<{ SOLVE_TYPE_MASK }>(u64_target, !0 << (64 - 5))
                    .expect("solver failed");
                let eq_solver_result_u128 = extract128_be(eq_result);
                assert_eq!(
                    eq_solver_result_u128 >> (128 - 5),
                    0b10111,
                    "eq_solver_result_u128: {:016x} (solver: {}, search_space: {})",
                    eq_solver_result_u128,
                    core::any::type_name::<S>(),
                    search_space
                );

                #[cfg(all(feature = "compare-64bit", target_arch = "x86_64"))]
                {
                    // test that the target can be placed in the second register and it still works
                    let u64_target = 0b10111 << (32 - 5);
                    let u64_mask = 0b11111 << (32 - 5);
                    let (_, eq_result) = eq_solver
                        .solve::<{ SOLVE_TYPE_MASK }>(u64_target, u64_mask)
                        .expect("solver failed");
                    let eq_solver_result_u64 = extract64_be(eq_result);
                    assert_eq!(
                        eq_solver_result_u64 & u64_mask,
                        u64_target,
                        "eq_solver_result_u64: {:016x} (solver: {}, search_space: {})",
                        eq_solver_result_u64,
                        core::any::type_name::<S>(),
                        search_space
                    );
                }
            }
        }
    }

    pub(crate) fn test_binary_validator<
        S: Solver<Output = [u32; 8]>,
        F: for<'a> FnMut(&'a [u8], NonZeroU8) -> S,
    >(
        mut factory: F,
    ) {
        for nonce_byte_count in [4, 5, 8] {
            for prefix_len in 0..64 {
                let mut msg = Vec::from_iter(b"abc".iter().cloned().cycle().take(prefix_len));
                let mut solver = factory(&msg, NonZeroU8::new(nonce_byte_count).unwrap());
                const DIFFICULTY: u64 = 100_000;
                let target = compute_target_mcaptcha(DIFFICULTY as u64);
                let (nonce, result) = solver
                    .solve::<SOLVE_TYPE_GT>(target, !0)
                    .expect("solver failed");
                msg.extend_from_slice(&nonce.to_le_bytes()[..nonce_byte_count as usize]);
                let expected_digest = sha2::Sha256::digest(&msg);
                let mut got_digest = [0; 32];
                for i in 0..8 {
                    got_digest[i * 4..][..4].copy_from_slice(&result[i].to_be_bytes());
                }
                assert_eq!(
                    expected_digest.as_slice(),
                    got_digest.as_slice(),
                    "nonce: {}, prefix_len: {}",
                    nonce,
                    prefix_len,
                );
                let got_difficulty = u64::from_be_bytes(got_digest[..8].try_into().unwrap());
                assert!(
                    got_difficulty >= target,
                    "got_difficulty: {:016x} < target: {:016x} (nonce: {}, prefix_len: {})",
                    got_difficulty,
                    target,
                    nonce,
                    prefix_len,
                );
            }
        }
    }

    pub(crate) fn test_decimal_validator_f64_safe<
        S: Solver<Output = [u32; 8]>,
        F: for<'a> FnMut(&'a [u8], u32) -> Option<(S, Option<IEEE754LosslessFixupPrefix>)>,
    >(
        mut factory: F,
    ) {
        use std::io::Write;
        for c in b'a'..=b'c' {
            let salts = [c; 64];
            for len in 1..=64 {
                let u64_target = 0b10111 << (64 - 5);
                let u64_mask = !0 << (64 - 5);
                let (mut solver, fixup_prefix) = factory(&salts[..len], 0).unwrap();

                let (nonce, result) = solver
                    .solve::<SOLVE_TYPE_MASK>(u64_target, u64_mask)
                    .expect("solver failed");
                let mut final_message = salts[..len].to_vec();
                let mut final_message_f64 = final_message.clone();
                let mut final_nonce = nonce as f64;
                if let Some(ref fixup_prefix) = fixup_prefix {
                    final_message.extend_from_slice(fixup_prefix.as_ref());
                    final_nonce = fixup_prefix.fixup(nonce);
                }
                if fixup_prefix.is_some() {
                    assert_ne!(nonce % 10, 0);
                }
                write!(final_message, "{:09}", nonce).unwrap();
                write!(final_message_f64, "{}", final_nonce).unwrap();
                assert_eq!(
                    final_message_f64,
                    final_message,
                    "final_nonce: {}, final_nonce_f64: {} (fixup_prefix: {:?})",
                    String::from_utf8_lossy(&final_message),
                    String::from_utf8_lossy(&final_message_f64),
                    fixup_prefix,
                );
                let hash_result = sha2::Sha256::digest(&final_message);
                let hash_result_u64 = u64::from_be_bytes(hash_result[..8].try_into().unwrap());
                assert_eq!(
                    hash_result_u64 & u64_mask,
                    u64_target,
                    "hash_result_u64: {:016x} (solver: {}, len: {}, message: {:?})",
                    hash_result_u64,
                    core::any::type_name::<S>(),
                    len,
                    String::from_utf8_lossy(&final_message)
                );
                assert_eq!(
                    hash_result_u64,
                    ((result[0] as u64) << 32 | (result[1] as u64))
                );
            }
        }
    }

    pub(crate) fn test_cerberus_decimal_validator<
        S: Solver<Output = [u32; 8]>,
        F: for<'a> FnMut(&'a [u8]) -> Option<S>,
    >(
        mut factory: F,
    ) {
        use std::io::Write;

        for df in (5..=7).chain(core::iter::once(9)) {
            let mask = compute_mask_cerberus(df.try_into().unwrap());
            eprintln!("mask: {:08x}", mask);

            let test_seed: [u8; 128] = core::array::from_fn(|i| b'a'.wrapping_add(i as u8));

            for seed_len in 0..128 {
                let Some(mut solver) = factory(&test_seed[..seed_len]) else {
                    if seed_len < 64 {
                        eprintln!("solver is None for seed_len: {}", seed_len);
                    }
                    continue;
                };

                let (nonce, hash) = solver
                    .solve::<{ crate::solver::SOLVE_TYPE_MASK }>(0, mask as u64)
                    .unwrap();
                let mut msg = test_seed[..seed_len].to_vec();
                write!(&mut msg, "{}", nonce).unwrap();

                fn check_small(hash: &[u8; 32], n: usize) -> bool {
                    // https://github.com/sjtug/cerberus/blob/ee8f903f1311da7022aec68c8686739b40f4a168/pow/src/check_dubit.rs
                    let first_word: u32 = (hash[0] as u32) << 24
                        | (hash[1] as u32) << 16
                        | (hash[2] as u32) << 8
                        | (hash[3] as u32);
                    first_word.leading_zeros() >= (n as u32 * 2)
                }

                let mut ref_hasher = blake3::Hasher::new();
                ref_hasher.update(msg.as_slice());
                let ref_hash = ref_hasher.finalize();
                let ref_hash_bytes = ref_hash.as_bytes();
                let ref_hash = core::array::from_fn(|i| {
                    u32::from_le_bytes([
                        ref_hash_bytes[i * 4],
                        ref_hash_bytes[i * 4 + 1],
                        ref_hash_bytes[i * 4 + 2],
                        ref_hash_bytes[i * 4 + 3],
                    ])
                });
                let hit = ((ref_hash[0] as u64) << 32 | (ref_hash[1] as u64)) & mask == 0;
                assert_eq!(
                    hash, ref_hash,
                    "incorrect output: {} (seed_len: {})",
                    nonce, seed_len
                );
                assert!(hit);
                assert!(check_small(&ref_hash_bytes, df as usize));
            }
        }
    }

    pub(crate) fn test_cerberus_binary_validator<
        S: Solver<Output = [u32; 8]>,
        F: for<'a> FnMut(&'a [u8]) -> Option<S>,
    >(
        mut factory: F,
    ) {
        for seed in [b"a", b"b"] {
            let seed_hash = ::blake3::hash(seed).to_hex();

            for df in (5..=7).chain(core::iter::once(9)) {
                let mask = compute_mask_cerberus(df.try_into().unwrap());
                eprintln!("mask: {:08x}", mask);

                let Some(mut solver) = factory(seed) else {
                    panic!("solver is None for seed: {:?}", seed);
                };

                let (nonce, hash) = solver
                    .solve::<{ crate::solver::SOLVE_TYPE_MASK }>(0, mask as u64)
                    .unwrap();
                let mut msg = seed_hash.as_bytes().to_vec();
                msg.extend_from_slice(nonce.rotate_right(32).to_le_bytes().as_slice());

                fn check_small(hash: &[u8; 32], n: usize) -> bool {
                    // https://github.com/sjtug/cerberus/blob/ee8f903f1311da7022aec68c8686739b40f4a168/pow/src/check_dubit.rs
                    let first_word: u32 = (hash[0] as u32) << 24
                        | (hash[1] as u32) << 16
                        | (hash[2] as u32) << 8
                        | (hash[3] as u32);
                    first_word.leading_zeros() >= (n as u32 * 2)
                }

                let mut ref_hasher = blake3::Hasher::new();
                ref_hasher.update(msg.as_slice());
                let ref_hash = ref_hasher.finalize();
                let ref_hash_bytes = ref_hash.as_bytes();
                let ref_hash = core::array::from_fn(|i| {
                    u32::from_le_bytes([
                        ref_hash_bytes[i * 4],
                        ref_hash_bytes[i * 4 + 1],
                        ref_hash_bytes[i * 4 + 2],
                        ref_hash_bytes[i * 4 + 3],
                    ])
                });
                let hit = ((ref_hash[0] as u64) << 32 | (ref_hash[1] as u64)) & mask == 0;
                assert_eq!(hash, ref_hash, "incorrect output: {}", nonce);
                assert!(hit);
                assert!(check_small(&ref_hash_bytes, df as usize));
            }
        }
    }

    pub(crate) fn test_goaway_validator<
        S: Solver<Output = [u32; 8]>,
        F: for<'a> FnMut(&'a [u8; 32]) -> S,
    >(
        mut factory: F,
    ) {
        const DIFFICULTY: NonZeroU8 = NonZeroU8::new(10).unwrap();
        let mask = compute_mask_goaway(DIFFICULTY);
        let test_prefix = core::array::from_fn(|i| i as u8);

        let mut solver = factory(&test_prefix);
        let mut eq_solver = factory(&test_prefix);

        let (nonce, result) = solver
            .solve::<SOLVE_TYPE_MASK>(0, mask)
            .expect("solver failed");
        assert!(result[0].leading_zeros() >= DIFFICULTY.get() as u32);

        let mut hasher = Sha256::default();
        hasher.update(&test_prefix);
        hasher.update(&nonce.to_be_bytes());
        let hash = hasher.finalize();
        assert!(u128::from_be_bytes(hash[..16].try_into().unwrap()) >= DIFFICULTY.get() as _);

        let eq_target = 0b10111 << (64 - 5);
        let eq_mask = !0 << (64 - 5);
        let (_, eq_result) = eq_solver
            .solve::<{ SOLVE_TYPE_MASK }>(eq_target, eq_mask)
            .expect("solver failed");
        let eq_result_u128 = extract128_be(eq_result);
        assert_eq!(
            eq_result_u128 >> (128 - 5),
            0b10111,
            "eq_result: {:016x} (solver: {})",
            eq_result_u128,
            core::any::type_name::<S>()
        );

        #[cfg(all(feature = "compare-64bit", target_arch = "x86_64"))]
        {
            let eq_target = 0b10111 << (32 - 5);
            let eq_mask = 0b11111 << (32 - 5);
            let (_, eq_result) = eq_solver
                .solve::<{ SOLVE_TYPE_MASK }>(eq_target, eq_mask)
                .expect("solver failed");
            let eq_result_u64 = extract64_be(eq_result);
            assert_eq!(
                eq_result_u64 & eq_mask,
                eq_target,
                "eq_result_u64: {:016x} (solver: {})",
                eq_result_u64,
                core::any::type_name::<S>()
            );
        }
    }

    pub(crate) fn test_altcha_validator<
        S: Solver<Output = [u32; 8]>,
        F: for<'a> FnMut(crate::message::AltchaMessage) -> Option<S>,
    >(
        mut factory: F,
    ) {
        // known answer tests
        let msg = crate::message::AltchaMessage {
            nonce: [
                0xf0, 0xc5, 0x9c, 0x5f, 0x4b, 0x3a, 0xeb, 0x1f, 0xf3, 0x4d, 0x44, 0xab, 0xd1, 0x5f,
                0x0f, 0x15,
            ],
            salt: [
                0x7f, 0x49, 0x8a, 0x9e, 0xb9, 0x4b, 0xb8, 0x4f, 0x3c, 0xc2, 0xa6, 0xb4, 0x8b, 0x6e,
                0xe6, 0x14,
            ],
            cost: 2000.try_into().unwrap(),
            pbkdf2: true,
            key_length: 32.try_into().unwrap(),
        };
        let expected_derived = [
            0x0058b155, 0x1f526b2e, 0xa17487e5, 0xf6f7edd0, 0x35ca3847, 0x8030a59d, 0x7b7bee49,
            0xb090c58e,
        ];

        let mut solver = factory(msg.clone()).unwrap();
        let (nonce, hash) = solver
            .solve::<{ crate::solver::SOLVE_TYPE_MASK }>(
                0,
                crate::compute_mask_anubis(2.try_into().unwrap()),
            )
            .unwrap();
        assert_eq!(nonce, 78);
        assert_eq!(hash, expected_derived);

        let msg = crate::message::AltchaMessage {
            nonce: [
                0xd9, 0x8d, 0x4a, 0x93, 0x45, 0x8a, 0x69, 0x7d, 0x4c, 0xc0, 0xe8, 0x29, 0x6b, 0x0d,
                0x73, 0xc2,
            ],
            salt: [
                0xdd, 0xd2, 0x93, 0x34, 0xb7, 0x49, 0xfd, 0x0a, 0xd5, 0x4d, 0x6d, 0x00, 0xc5, 0xcc,
                0x48, 0x0a,
            ],
            cost: 2000.try_into().unwrap(),
            pbkdf2: false,
            key_length: 32.try_into().unwrap(),
        };
        let expected_derived = [
            0x00641b3e, 0x3f8db108, 0xd345552e, 0x8d9f78fe, 0x67a7d0ae, 0x0faa2ea0, 0x701a0432,
            0x0c407bb7,
        ];
        let mut solver = factory(msg.clone()).unwrap();
        let (nonce, hash) = solver
            .solve::<{ crate::solver::SOLVE_TYPE_MASK }>(
                0,
                crate::compute_mask_anubis(2.try_into().unwrap()),
            )
            .unwrap();
        assert_eq!(nonce, 128);
        assert_eq!(hash, expected_derived);

        for q in 0..5 {
            for r in 0..5 {
                for pbkdf2 in [false, true] {
                    let msg = crate::message::AltchaMessage {
                        nonce: [
                            q, 0xc5, 0x9c, 0x5f, 0x4b, 0x3a, 0xeb, 0x1f, 0xf3, 0x4d, 0x44, 0xab,
                            0xd1, 0x5f, 0x0f, 0x15,
                        ],
                        salt: [
                            r, 0x49, 0x8a, 0x9e, 0xb9, 0x4b, 0xb8, 0x4f, 0x3c, 0xc2, 0xa6, 0xb4,
                            0x8b, 0x6e, 0xe6, 0x14,
                        ],
                        cost: 64.try_into().unwrap(),
                        pbkdf2,
                        key_length: 32.try_into().unwrap(),
                    };

                    let mut solver = factory(msg.clone()).unwrap();
                    let mask = crate::compute_mask_anubis(3.try_into().unwrap());
                    let (nonce, hash) = solver
                        .solve::<{ crate::solver::SOLVE_TYPE_MASK }>(0, mask)
                        .unwrap();
                    assert_eq!(nonce >> 32, 0);
                    let nonce = nonce as u32;
                    assert_eq!(hash[0] & (mask >> 32) as u32, 0);

                    let mut expected_hash = [0; 32];
                    if pbkdf2 {
                        let mut password = [0; 16 + 4];
                        password[..16].copy_from_slice(&msg.nonce);
                        password[16..16 + 4].copy_from_slice(&nonce.to_be_bytes());
                        ::pbkdf2::pbkdf2::<Hmac<Sha256>>(
                            &password,
                            &msg.salt,
                            64,
                            &mut expected_hash,
                        )
                        .unwrap();
                    } else {
                        let mut password = [0; 16 * 2 + 4];
                        password[..16].copy_from_slice(&msg.salt);
                        password[16..32].copy_from_slice(&msg.nonce);
                        password[32..32 + 4].copy_from_slice(&nonce.to_be_bytes());
                        let mut data = password.as_slice();
                        let mut digest;
                        for _ in 0..64 {
                            digest = ::sha2::Sha256::digest(data);
                            data = digest.as_slice();
                        }
                        expected_hash = data.try_into().unwrap();
                    }

                    let expected_hash_u32 = core::array::from_fn(|i| {
                        u32::from_be_bytes(expected_hash[i * 4..][..4].try_into().unwrap())
                    });
                    assert_eq!(hash, expected_hash_u32);
                }
            }
        }
    }
}
