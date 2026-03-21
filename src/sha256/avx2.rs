//! Multi-way sha256 implementation extracted from `sha2` crate for AVX2.
use core::arch::x86_64::*;

use super::*;

#[macro_use]
#[path = "loop_macros.rs"]
mod loop_macros;

macro_rules! mm256_ror_epi32 {
    ($x:expr, $shift:literal) => {
        _mm256_xor_si256(
            _mm256_srli_epi32($x, $shift),
            _mm256_slli_epi32($x, 32 - $shift),
        )
    };
}

/// Do a 16-way SHA-256 compression function without adding back the saved state, without feedback
///
/// This is useful for making state share registers with a-h when caller has the previous state recalled cheaply from elsewhere after the fact
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn multiway_arx<const BEGIN_ROUND: usize>(
    state: &mut [__m256i; 8],
    block: &mut [__m256i; 16],
) {
    unsafe {
        let [a, b, c, d, e, f, g, h] = &mut *state;

        repeat64!(i, {
            if i >= BEGIN_ROUND {
                let w = if i < 16 {
                    block[i]
                } else {
                    let w15 = block[(i - 15) % 16];
                    let s0 = _mm256_xor_si256(
                        _mm256_xor_si256(mm256_ror_epi32!(w15, 7), mm256_ror_epi32!(w15, 18)),
                        _mm256_srli_epi32(w15, 3),
                    );
                    let w2 = block[(i - 2) % 16];
                    let s1 = _mm256_xor_si256(
                        _mm256_xor_si256(mm256_ror_epi32!(w2, 17), mm256_ror_epi32!(w2, 19)),
                        _mm256_srli_epi32(w2, 10),
                    );
                    block[i % 16] = _mm256_add_epi32(block[i % 16], s0);
                    block[i % 16] = _mm256_add_epi32(block[i % 16], block[(i - 7) % 16]);
                    block[i % 16] = _mm256_add_epi32(block[i % 16], s1);
                    block[i % 16]
                };

                let s1 = _mm256_xor_si256(
                    _mm256_xor_si256(mm256_ror_epi32!(*e, 6), mm256_ror_epi32!(*e, 11)),
                    mm256_ror_epi32!(*e, 25),
                );
                let ch = _mm256_xor_si256(_mm256_and_si256(*e, *f), _mm256_andnot_si256(*e, *g));
                let mut t1 = s1;
                t1 = _mm256_add_epi32(t1, ch);
                t1 = _mm256_add_epi32(t1, _mm256_set1_epi32(K32[i] as _));
                t1 = _mm256_add_epi32(t1, w);
                t1 = _mm256_add_epi32(t1, *h);

                let s0 = _mm256_xor_si256(
                    _mm256_xor_si256(mm256_ror_epi32!(*a, 2), mm256_ror_epi32!(*a, 13)),
                    mm256_ror_epi32!(*a, 22),
                );
                let maj = _mm256_xor_si256(
                    _mm256_xor_si256(_mm256_and_si256(*a, *b), _mm256_and_si256(*a, *c)),
                    _mm256_and_si256(*b, *c),
                );
                let mut t2 = s0;
                t2 = _mm256_add_epi32(t2, maj);

                *h = *g;
                *g = *f;
                *f = *e;
                *e = _mm256_add_epi32(*d, t1);
                *d = *c;
                *c = *b;
                *b = *a;
                *a = _mm256_add_epi32(t1, t2);
            }
        });
    }
}

/// Do a 16-way SHA-256 compression function using broadcasted message schedule, without feedback
///
/// You can skip loading the first couple words by passing a non-zero value for `LeadingZeroes`
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn bcst_multiway_arx<const LEAD_ZEROES: usize>(
    state: &mut [__m256i; 8],
    w_k: &[u32; 64],
) {
    unsafe {
        let [a, b, c, d, e, f, g, h] = &mut *state;

        repeat64!(i, {
            let w = if i < LEAD_ZEROES {
                _mm256_set1_epi32(K32[i] as _)
            } else {
                _mm256_set1_epi32(w_k[i] as _)
            };

            let s1 = _mm256_xor_si256(
                _mm256_xor_si256(mm256_ror_epi32!(*e, 6), mm256_ror_epi32!(*e, 11)),
                mm256_ror_epi32!(*e, 25),
            );
            let ch = _mm256_xor_si256(_mm256_and_si256(*e, *f), _mm256_andnot_si256(*e, *g));
            let mut t1 = s1;
            t1 = _mm256_add_epi32(t1, ch);
            t1 = _mm256_add_epi32(t1, w);
            t1 = _mm256_add_epi32(t1, *h);

            let s0 = _mm256_xor_si256(
                _mm256_xor_si256(mm256_ror_epi32!(*a, 2), mm256_ror_epi32!(*a, 13)),
                mm256_ror_epi32!(*a, 22),
            );
            let maj = _mm256_xor_si256(
                _mm256_xor_si256(_mm256_and_si256(*a, *b), _mm256_and_si256(*a, *c)),
                _mm256_and_si256(*b, *c),
            );
            let mut t2 = s0;
            t2 = _mm256_add_epi32(t2, maj);

            *h = *g;
            *g = *f;
            *f = *e;
            *e = _mm256_add_epi32(*d, t1);
            *d = *c;
            *c = *b;
            *b = *a;
            *a = _mm256_add_epi32(t1, t2);
        });
    }
}

#[cfg(target_feature = "avx2")]
#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};

    use super::*;

    #[test]
    fn test_digest_block_equivalence() {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(1);
        let mut states: [[u32; 8]; 8] =
            core::array::from_fn(|_| core::array::from_fn(|_| rng.random()));
        let mut state_avx2: [__m256i; 8] = core::array::from_fn(|i| unsafe {
            _mm256_setr_epi32(
                states[0][i] as _,
                states[1][i] as _,
                states[2][i] as _,
                states[3][i] as _,
                states[4][i] as _,
                states[5][i] as _,
                states[6][i] as _,
                states[7][i] as _,
            )
        });
        let states_avx2_save = state_avx2.clone();
        let blocks: [[u32; 16]; 8] =
            core::array::from_fn(|_| core::array::from_fn(|_| rng.random()));
        let mut block_avx2: [__m256i; 16] = core::array::from_fn(|i| unsafe {
            _mm256_setr_epi32(
                blocks[0][i] as _,
                blocks[1][i] as _,
                blocks[2][i] as _,
                blocks[3][i] as _,
                blocks[4][i] as _,
                blocks[5][i] as _,
                blocks[6][i] as _,
                blocks[7][i] as _,
            )
        });

        for i in 0..8 {
            digest_block(&mut states[i], &blocks[i]);
        }
        multiway_arx::<0>(&mut state_avx2, &mut block_avx2);
        for i in 0..8 {
            state_avx2[i] = unsafe { _mm256_add_epi32(state_avx2[i], states_avx2_save[i]) };
        }

        let mut output_state_simd_soa: [[u32; 8]; 8] = unsafe { core::mem::zeroed() };
        for i in 0..8 {
            unsafe {
                _mm256_storeu_si256(
                    output_state_simd_soa[i].as_mut_ptr() as *mut _,
                    state_avx2[i],
                );
            }
        }
        let output_state_simd: [[u32; 8]; 8] =
            core::array::from_fn(|i| core::array::from_fn(|j| output_state_simd_soa[j][i]));

        assert_eq!(states, output_state_simd);
    }

    #[test]
    fn test_sha256_single_block() {
        // Test vector from NIST FIPS 180-4
        // Input: "abc"
        let input = [
            0x61626380, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000018,
        ];

        // Initial hash values (H0)
        let mut state = IV;

        // Process the block
        digest_block(&mut state, &input);

        // Expected output hash for "abc"
        let expected = [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ];

        assert_eq!(state, expected, "SHA-256 hash mismatch");
    }

    #[test]
    fn test_sha256_avx2_single_block() {
        // Test vector from NIST FIPS 180-4
        // Input: "abc" repeated 16 times
        let input_block = [
            0x61626380, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000018,
        ];

        // Create 16 identical blocks for AVX-512 processing
        let mut block_avx2: [__m256i; 16] =
            unsafe { core::array::from_fn(|i| _mm256_set1_epi32(input_block[i] as _)) };

        // Initial hash values (H0) for 16 parallel hashes
        let state_avx2: [__m256i; 8] =
            core::array::from_fn(|i| unsafe { _mm256_set1_epi32(IV[i] as _) });

        // Process the blocks
        let mut state = state_avx2;
        multiway_arx::<0>(&mut state, &mut block_avx2);
        for i in 0..8 {
            state[i] = unsafe { _mm256_add_epi32(state[i], state_avx2[i]) };
        }

        // Expected output hash for "abc"
        let expected = [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ];

        let mut results: [[u32; 8]; 8] = unsafe { core::mem::zeroed() };
        for i in 0..8 {
            unsafe {
                _mm256_storeu_si256(results[i].as_mut_ptr() as *mut _, state[i]);
            }
        }

        // Verify all 16 results match the expected hash
        for i in 0..8 {
            let result = [
                results[0][i],
                results[1][i],
                results[2][i],
                results[3][i],
                results[4][i],
                results[5][i],
                results[6][i],
                results[7][i],
            ];
            assert_eq!(
                result, expected,
                "SHA-256 AVX-512 hash mismatch at index {}",
                i
            );
        }
    }

    #[test]
    fn test_sha256_avx2_bcst_without_feedback() {
        let mut block = [0; 64];
        block[0] = u32::from_be_bytes([0x61, 0x62, 0x63, 0x80]);
        block[15] = u32::from_be_bytes([0x00, 0x00, 0x00, 3 * 8]);
        do_message_schedule_k_w(&mut block);
        let mut state_avx2: [__m256i; 8] =
            core::array::from_fn(|i| unsafe { _mm256_set1_epi32(IV[i] as _) });

        bcst_multiway_arx::<0>(&mut state_avx2, &block);
        for i in 0..8 {
            state_avx2[i] =
                unsafe { _mm256_add_epi32(state_avx2[i], _mm256_set1_epi32(IV[i] as _)) };
        }

        let expected = [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ];

        let mut results: [[u32; 8]; 8] = unsafe { core::mem::zeroed() };
        for i in 0..8 {
            unsafe {
                _mm256_storeu_si256(results[i].as_mut_ptr() as *mut _, state_avx2[i]);
            }
        }

        for i in 0..8 {
            for j in 0..8 {
                assert_eq!(results[i][j], expected[i]);
            }
        }
    }
}
