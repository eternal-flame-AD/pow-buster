use alloc::string::ToString;
use sha2::Digest;

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
pub mod avx512;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    target_feature = "sha"
))]
pub mod sha_ni;

#[cfg(target_arch = "wasm32")]
pub mod simd128;

pub mod safe;

// Less than test (such as Anubis and GoAway)
pub const SOLVE_TYPE_LT: u8 = 1;
/// Greater than test (such as MCaptcha)
pub const SOLVE_TYPE_GT: u8 = 2;
/// Mask test (such as Cap.js)
pub const SOLVE_TYPE_MASK: u8 = 3;

pub trait Solver {
    // returns a valid nonce and "result" value
    //
    // mCaptcha uses an upwards comparison, Anubis uses a downwards comparison
    //
    // returns None when the solver cannot solve the prefix
    // failure is usually because the key space is exhausted (or presumed exhausted)
    // it should by design happen extremely rarely for common difficulty settings
    fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, [u32; 8])>;

    // A dynamic dispatching wrapper for solve
    #[inline(never)]
    fn solve_dyn(&mut self, target: u64, ty: u8, mask: u64) -> Option<(u64, [u32; 8])> {
        match ty {
            SOLVE_TYPE_LT => self.solve::<SOLVE_TYPE_LT>(target, mask),
            SOLVE_TYPE_GT => self.solve::<SOLVE_TYPE_GT>(target, mask),
            _ => self.solve::<SOLVE_TYPE_MASK>(target, mask),
        }
    }
}

pub trait Validator {
    fn validate(&self, nonce: u64, result: Option<&[u32; 8]>) -> bool;
}

pub struct HashcashValidator<'a> {
    prefix: &'a [u8],
    target: u64,
    decimal: bool,
}

impl<'a> HashcashValidator<'a> {
    pub fn new_decimal(prefix: &'a [u8], target: u64) -> Self {
        Self {
            prefix,
            target,
            decimal: true,
        }
    }

    pub fn new_bin(prefix: &'a [u8], target: u64) -> Self {
        Self {
            prefix,
            target,
            decimal: false,
        }
    }
}

impl<'a> Validator for HashcashValidator<'a> {
    fn validate(&self, nonce: u64, result: Option<&[u32; 8]>) -> bool {
        let mut hasher = sha2::Sha256::default();
        hasher.update(&self.prefix);
        if self.decimal {
            let nonce_str = nonce.to_string();
            hasher.update(&nonce_str.as_bytes());
        } else {
            hasher.update(&nonce.to_be_bytes());
        }
        let hash = hasher.finalize();
        let hash_u64 = u64::from_be_bytes(hash.as_slice()[..8].try_into().unwrap());
        if let Some(result) = result {
            let actual_output = core::array::from_fn(|i| {
                u32::from_be_bytes([
                    hash[i * 4],
                    hash[i * 4 + 1],
                    hash[i * 4 + 2],
                    hash[i * 4 + 3],
                ])
            });
            if actual_output != *result {
                return false;
            }
        }
        hash_u64 < self.target
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use core::num::NonZeroU8;

    use sha2::Sha256;

    use crate::{
        compute_target, compute_target_anubis, compute_target_goaway, extract64_be, extract128_be,
        message::IEEE754LosslessFixupPrefix,
    };

    use super::*;

    pub(crate) fn test_decimal_validator<
        S: Solver,
        F: for<'a> FnMut(&'a [u8], u32) -> Option<S>,
    >(
        mut factory: F,
    ) {
        #[cfg(debug_assertions)]
        let salts = [b'A'];
        #[cfg(not(debug_assertions))]
        let salts = *b"Ax_?"; // test a variety of salts in optimized builds
        for salt in salts {
            for phrase_len in 0..64 {
                let mut concatenated_prefix = vec![salt];
                let phrase_str = String::from_iter(std::iter::repeat('a').take(phrase_len));
                concatenated_prefix.extend_from_slice(&bincode::serialize(&phrase_str).unwrap());

                let config = pow_sha256::Config {
                    salt: String::from_utf8(vec![salt]).unwrap(),
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
                    let Some(mut anubis_solver) = factory(&concatenated_prefix, search_space)
                    else {
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

                    let target_bytes = compute_target(DIFFICULTY).to_be_bytes();
                    let target_u64 = u64::from_be_bytes(target_bytes[..8].try_into().unwrap());
                    let target_anubis = compute_target_anubis(ANUBIS_DIFFICULTY);
                    let target_anubis_bytes = target_anubis.to_be_bytes();
                    let target_anubis_u64 =
                        u64::from_be_bytes(target_anubis_bytes[..8].try_into().unwrap());
                    let (nonce, result) = solver
                        .solve::<SOLVE_TYPE_GT>(target_u64, !0)
                        .expect("solver failed");
                    let result_u128 = extract128_be(result);
                    let (anubis_nonce, anubis_result) = anubis_solver
                        .solve::<SOLVE_TYPE_LT>(target_anubis_u64, !0)
                        .expect("solver failed");
                    let anubis_result_u64 = extract64_be(anubis_result);
                    let anubis_result_bytes = anubis_result_u64.to_be_bytes();
                    assert!(
                        target_anubis > anubis_result_u64,
                        "[{}] target_anubis: {:016x} <= anubis_result: {:016x} (solver: {}, search_space: {})",
                        core::any::type_name::<S>(),
                        target_anubis,
                        anubis_result_u64,
                        core::any::type_name::<S>(),
                        search_space
                    );

                    let test_response = pow_sha256::PoWBuilder::default()
                        .nonce(nonce)
                        .result(result_u128.to_string())
                        .build()
                        .unwrap();
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
                        compute_target(DIFFICULTY),
                        core::any::type_name::<S>()
                    );

                    let anubis_test_response =
                        HashcashValidator::new_decimal(&concatenated_prefix, target_anubis);

                    assert!(anubis_test_response.validate(anubis_nonce, Some(&anubis_result)));

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
    }

    pub(crate) fn test_decimal_validator_f64_safe<
        S: Solver,
        F: for<'a> FnMut(&'a [u8], u32) -> Option<(S, Option<IEEE754LosslessFixupPrefix>)>,
    >(
        mut factory: F,
    ) {
        use std::io::Write;
        for c in b'a'..=b'z' {
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

    pub(crate) fn test_goaway_validator<S: Solver, F: for<'a> FnMut(&'a [u8; 32]) -> S>(
        mut factory: F,
    ) {
        const DIFFICULTY: NonZeroU8 = NonZeroU8::new(12).unwrap();
        let target = compute_target_goaway(DIFFICULTY).to_be_bytes();
        let target_u64 = u64::from_be_bytes(target[..8].try_into().unwrap());
        let test_prefix = core::array::from_fn(|i| i as u8);

        let mut solver = factory(&test_prefix);
        let mut eq_solver = factory(&test_prefix);

        let (nonce, result) = solver
            .solve::<SOLVE_TYPE_LT>(target_u64, !0)
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
}
