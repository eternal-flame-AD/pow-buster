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

pub trait Solver {
    // returns a valid nonce and "result" value
    //
    // mCaptcha uses an upwards comparison, Anubis uses a downwards comparison
    //
    // returns None when the solver cannot solve the prefix
    // failure is usually because the key space is exhausted (or presumed exhausted)
    // it should by design happen extremely rarely for common difficulty settings
    fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])>;

    // A dynamic dispatching wrapper for solve
    #[inline(never)]
    fn solve_dyn(&mut self, target: [u32; 4], upwards: bool) -> Option<(u64, [u32; 8])> {
        if upwards {
            self.solve::<true>(target)
        } else {
            self.solve::<false>(target)
        }
    }
}

pub trait Validator {
    fn validate(&self, nonce: u64, result: Option<&[u32; 8]>) -> bool;
}

pub struct HashcashValidator<'a> {
    prefix: &'a [u8],
    target: u128,
    decimal: bool,
}

impl<'a> HashcashValidator<'a> {
    pub fn new_decimal(prefix: &'a [u8], target: u128) -> Self {
        Self {
            prefix,
            target,
            decimal: true,
        }
    }

    pub fn new_bin(prefix: &'a [u8], target: u128) -> Self {
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
        let hash_u128 = u128::from_be_bytes(hash.as_slice()[..16].try_into().unwrap());
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
        hash_u128 < self.target
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use core::num::NonZeroU8;

    use sha2::Sha256;

    use crate::{compute_target, compute_target_anubis, compute_target_goaway, extract128_be};

    use super::*;

    pub(crate) fn test_decimal_validator<
        S: Solver,
        F: for<'a> FnMut(&'a [u8], u32) -> Option<S>,
    >(
        mut factory: F,
    ) {
        const SALT: &str = "z";

        for phrase_len in 0..64 {
            let mut concatenated_prefix = SALT.as_bytes().to_vec();
            let phrase_str = String::from_iter(std::iter::repeat('a').take(phrase_len));
            concatenated_prefix.extend_from_slice(&bincode::serialize(&phrase_str).unwrap());

            let config = pow_sha256::Config { salt: SALT.into() };
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

                let target_bytes = compute_target(DIFFICULTY).to_be_bytes();
                let target_u32s = core::array::from_fn(|i| {
                    u32::from_be_bytes([
                        target_bytes[i * 4],
                        target_bytes[i * 4 + 1],
                        target_bytes[i * 4 + 2],
                        target_bytes[i * 4 + 3],
                    ])
                });
                let target_anubis = compute_target_anubis(ANUBIS_DIFFICULTY);
                let target_anubis_bytes = target_anubis.to_be_bytes();
                let target_anubis_u32s = core::array::from_fn(|i| {
                    u32::from_be_bytes([
                        target_anubis_bytes[i * 4],
                        target_anubis_bytes[i * 4 + 1],
                        target_anubis_bytes[i * 4 + 2],
                        target_anubis_bytes[i * 4 + 3],
                    ])
                });
                let (nonce, result) = solver.solve::<true>(target_u32s).expect("solver failed");
                let result_128 = extract128_be(result);
                let (anubis_nonce, anubis_result) = anubis_solver
                    .solve::<false>(target_anubis_u32s)
                    .expect("solver failed");
                let anubis_result_128 = extract128_be(anubis_result);
                let anubis_result_bytes = anubis_result_128.to_be_bytes();
                assert!(
                    target_anubis > anubis_result_128,
                    "[{}] target_anubis: {:016x} <= anubis_result: {:016x} (solver: {}, search_space: {})",
                    core::any::type_name::<S>(),
                    target_anubis,
                    anubis_result_128,
                    core::any::type_name::<S>(),
                    search_space
                );

                let test_response = pow_sha256::PoWBuilder::default()
                    .nonce(nonce)
                    .result(result_128.to_string())
                    .build()
                    .unwrap();
                assert_eq!(
                    config.calculate(&test_response, &phrase_str).unwrap(),
                    result_128,
                    "test_response: {:?} (solver: {}, search_space: {})",
                    test_response,
                    core::any::type_name::<S>(),
                    search_space
                );

                assert!(
                    config.is_valid_proof(&test_response, &phrase_str),
                    "{} is not valid proof (solver: {})",
                    result_128,
                    core::any::type_name::<S>()
                );

                assert!(
                    config.is_sufficient_difficulty(&test_response, DIFFICULTY),
                    "{:016x} is not sufficient difficulty, expected {:016x} (solver: {})",
                    result_128,
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
                        anubis_result_128,
                        core::any::type_name::<S>(),
                        i
                    );
                }
            }
        }
    }

    pub(crate) fn test_goaway_validator<S: Solver, F: for<'a> FnMut(&'a [u8; 32]) -> S>(
        mut factory: F,
    ) {
        const DIFFICULTY: NonZeroU8 = NonZeroU8::new(12).unwrap();
        let target = compute_target_goaway(DIFFICULTY).to_be_bytes();
        let target_u32s = core::array::from_fn(|i| {
            u32::from_be_bytes([
                target[i * 4],
                target[i * 4 + 1],
                target[i * 4 + 2],
                target[i * 4 + 3],
            ])
        });
        let test_prefix = core::array::from_fn(|i| i as u8);

        let mut solver = factory(&test_prefix);

        let (nonce, result) = solver.solve::<false>(target_u32s).expect("solver failed");
        assert!(result[0].leading_zeros() >= DIFFICULTY.get() as u32);

        let mut hasher = Sha256::default();
        hasher.update(&test_prefix);
        hasher.update(&nonce.to_be_bytes());
        let hash = hasher.finalize();
        assert!(u128::from_be_bytes(hash[..16].try_into().unwrap()) >= DIFFICULTY.get() as _);
    }
}
