use core::arch::x86_64::*;

pub(crate) const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Round constants for SHA-256 family of digests
static K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[rustfmt::skip]
macro_rules! repeat64 {
    ($i:ident, $b:block) => {
        let $i = 0; $b; let $i = 1; $b; let $i = 2; $b; let $i = 3; $b;
        let $i = 4; $b; let $i = 5; $b; let $i = 6; $b; let $i = 7; $b;
        let $i = 8; $b; let $i = 9; $b; let $i = 10; $b; let $i = 11; $b;
        let $i = 12; $b; let $i = 13; $b; let $i = 14; $b; let $i = 15; $b;
        let $i = 16; $b; let $i = 17; $b; let $i = 18; $b; let $i = 19; $b;
        let $i = 20; $b; let $i = 21; $b; let $i = 22; $b; let $i = 23; $b;
        let $i = 24; $b; let $i = 25; $b; let $i = 26; $b; let $i = 27; $b;
        let $i = 28; $b; let $i = 29; $b; let $i = 30; $b; let $i = 31; $b;
        let $i = 32; $b; let $i = 33; $b; let $i = 34; $b; let $i = 35; $b;
        let $i = 36; $b; let $i = 37; $b; let $i = 38; $b; let $i = 39; $b;
        let $i = 40; $b; let $i = 41; $b; let $i = 42; $b; let $i = 43; $b;
        let $i = 44; $b; let $i = 45; $b; let $i = 46; $b; let $i = 47; $b;
        let $i = 48; $b; let $i = 49; $b; let $i = 50; $b; let $i = 51; $b;
        let $i = 52; $b; let $i = 53; $b; let $i = 54; $b; let $i = 55; $b;
        let $i = 56; $b; let $i = 57; $b; let $i = 58; $b; let $i = 59; $b;
        let $i = 60; $b; let $i = 61; $b; let $i = 62; $b; let $i = 63; $b;
    };
}

/// pre-compute the message schedule for a single block
///
/// The first 16 words are the input block, the rest are computed from them
#[inline(always)]
pub(crate) const fn do_message_schedule(w: &mut [u32; 64]) {
    let w_tmp = [
        w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9], w[10], w[11], w[12], w[13],
        w[14], w[15],
    ];
    repeat64!(i, {
        if i >= 16 {
            let w15 = w[(i - 15) % 16];
            let s0 = (w15.rotate_right(7)) ^ (w15.rotate_right(18)) ^ (w15 >> 3);
            let w2 = w[(i - 2) % 16];
            let s1 = (w2.rotate_right(17)) ^ (w2.rotate_right(19)) ^ (w2 >> 10);
            w[i % 16] = w[i % 16].wrapping_add(s0);
            w[i % 16] = w[i % 16].wrapping_add(w[(i - 7) % 16]);
            w[i % 16] = w[i % 16].wrapping_add(s1);
            w[i] = w[i % 16];
        }
    });
    w[0] = w_tmp[0];
    w[1] = w_tmp[1];
    w[2] = w_tmp[2];
    w[3] = w_tmp[3];
    w[4] = w_tmp[4];
    w[5] = w_tmp[5];
    w[6] = w_tmp[6];
    w[7] = w_tmp[7];
    w[8] = w_tmp[8];
    w[9] = w_tmp[9];
    w[10] = w_tmp[10];
    w[11] = w_tmp[11];
    w[12] = w_tmp[12];
    w[13] = w_tmp[13];
    w[14] = w_tmp[14];
    w[15] = w_tmp[15];
}

/// A reference software implementation of SHA-256 compression function from sha2 crate
#[inline(always)]
pub(crate) fn compress_block_reference(state: &mut [u32; 8], block: &[u32; 16]) {
    let mut tmp = sha2::digest::generic_array::GenericArray::<u8, _>::default();
    for i in 0..16 {
        tmp[i * 4..][..4].copy_from_slice(&block[i].to_be_bytes());
    }
    sha2::compress256(state, &[tmp]);
}

// taken verbatim from sha2 crate
#[inline(always)]
pub(crate) fn ingest_message_prefix<const LENGTH: usize>(state: &mut [u32; 8], w: [u32; LENGTH]) {
    let [a, b, c, d, e, f, g, h] = &mut *state;

    for i in 0..LENGTH {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (*e & *f) ^ ((!*e) & *g);
        let t1 = s1
            .wrapping_add(ch)
            .wrapping_add(K32[i])
            .wrapping_add(w[i])
            .wrapping_add(*h);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (*a & *b) ^ (*a & *c) ^ (*b & *c);
        let t2 = s0.wrapping_add(maj);

        *h = *g;
        *g = *f;
        *f = *e;
        *e = d.wrapping_add(t1);
        *d = *c;
        *c = *b;
        *b = *a;
        *a = t1.wrapping_add(t2);
    }
}

// disable inline because without hardware AVX-512 this will explode in complexity and cause comptime to skyrocket
// disable inline for debug_assertions because no one wants to wait for 5 minutes to run a unit test
#[cfg_attr(all(not(debug_assertions), target_feature = "avx512f"), inline(always))]
/// Do a 16-way SHA-256 compression function without adding back the saved state, without feedback
///
/// This is useful for making state share registers with a-h when caller has the previous state recalled cheaply from elsewhere after the fact
pub(crate) fn compress_16block_avx512_without_feedback<const BEGIN_ROUND: usize>(
    state: &mut [__m512i; 8],
    block: &mut [__m512i; 16],
) {
    unsafe {
        let [a, b, c, d, e, f, g, h] = &mut *state;

        repeat64!(i, {
            if i >= BEGIN_ROUND {
                let w = if i < 16 {
                    block[i]
                } else {
                    let w15 = block[(i - 15) % 16];
                    let s0 = _mm512_xor_si512(
                        _mm512_xor_si512(_mm512_ror_epi32(w15, 7), _mm512_ror_epi32(w15, 18)),
                        _mm512_srli_epi32(w15, 3),
                    );
                    let w2 = block[(i - 2) % 16];
                    let s1 = _mm512_xor_si512(
                        _mm512_xor_si512(_mm512_ror_epi32(w2, 17), _mm512_ror_epi32(w2, 19)),
                        _mm512_srli_epi32(w2, 10),
                    );
                    block[i % 16] = _mm512_add_epi32(block[i % 16], s0);
                    block[i % 16] = _mm512_add_epi32(block[i % 16], block[(i - 7) % 16]);
                    block[i % 16] = _mm512_add_epi32(block[i % 16], s1);
                    block[i % 16]
                };

                let s1 = _mm512_xor_si512(
                    _mm512_xor_si512(_mm512_ror_epi32(*e, 6), _mm512_ror_epi32(*e, 11)),
                    _mm512_ror_epi32(*e, 25),
                );
                let ch = _mm512_xor_si512(_mm512_and_si512(*e, *f), _mm512_andnot_si512(*e, *g));
                let mut t1 = s1;
                t1 = _mm512_add_epi32(t1, ch);
                t1 = _mm512_add_epi32(t1, _mm512_set1_epi32(K32[i] as _));
                t1 = _mm512_add_epi32(t1, w);
                t1 = _mm512_add_epi32(t1, *h);

                let s0 = _mm512_xor_si512(
                    _mm512_xor_si512(_mm512_ror_epi32(*a, 2), _mm512_ror_epi32(*a, 13)),
                    _mm512_ror_epi32(*a, 22),
                );
                let maj = _mm512_xor_si512(
                    _mm512_xor_si512(_mm512_and_si512(*a, *b), _mm512_and_si512(*a, *c)),
                    _mm512_and_si512(*b, *c),
                );
                let mut t2 = s0;
                t2 = _mm512_add_epi32(t2, maj);

                *h = *g;
                *g = *f;
                *f = *e;
                *e = _mm512_add_epi32(*d, t1);
                *d = *c;
                *c = *b;
                *b = *a;
                *a = _mm512_add_epi32(t1, t2);
            }
        });
    }
}

/// Do a 16-way SHA-256 compression function using broadcasted message schedule, without feedback
///
/// You can skip loading the first couple words by passing a non-zero value for `LeadingZeroes`
#[cfg_attr(all(not(debug_assertions), target_feature = "avx512f"), inline(always))]
pub(crate) fn compress_16block_avx512_bcst_without_feedback<const LEAD_ZEROES: usize>(
    state: &mut [__m512i; 8],
    block: &[u32; 64],
) {
    unsafe {
        let [a, b, c, d, e, f, g, h] = &mut *state;

        repeat64!(i, {
            let w = if i < LEAD_ZEROES {
                debug_assert_eq!(block[i], 0, "block[{i}] is not zero");
                _mm512_setzero_si512()
            } else {
                _mm512_set1_epi32(block[i] as _)
            };

            let s1 = _mm512_xor_si512(
                _mm512_xor_si512(_mm512_ror_epi32(*e, 6), _mm512_ror_epi32(*e, 11)),
                _mm512_ror_epi32(*e, 25),
            );
            let ch = _mm512_xor_si512(_mm512_and_si512(*e, *f), _mm512_andnot_si512(*e, *g));
            let mut t1 = s1;
            t1 = _mm512_add_epi32(t1, ch);
            t1 = _mm512_add_epi32(t1, _mm512_set1_epi32(K32[i] as _));
            t1 = _mm512_add_epi32(t1, w);
            t1 = _mm512_add_epi32(t1, *h);

            let s0 = _mm512_xor_si512(
                _mm512_xor_si512(_mm512_ror_epi32(*a, 2), _mm512_ror_epi32(*a, 13)),
                _mm512_ror_epi32(*a, 22),
            );
            let maj = _mm512_xor_si512(
                _mm512_xor_si512(_mm512_and_si512(*a, *b), _mm512_and_si512(*a, *c)),
                _mm512_and_si512(*b, *c),
            );
            let mut t2 = s0;
            t2 = _mm512_add_epi32(t2, maj);

            *h = *g;
            *g = *f;
            *f = *e;
            *e = _mm512_add_epi32(*d, t1);
            *d = *c;
            *c = *b;
            *b = *a;
            *a = _mm512_add_epi32(t1, t2);
        });
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};

    use super::*;

    #[test]
    fn test_compress_block_reference_equivalence() {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(1);
        let mut states: [[u32; 8]; 16] =
            core::array::from_fn(|_| core::array::from_fn(|_| rng.random()));
        let mut state_avx512: [__m512i; 8] = core::array::from_fn(|i| unsafe {
            _mm512_setr_epi32(
                states[0][i] as _,
                states[1][i] as _,
                states[2][i] as _,
                states[3][i] as _,
                states[4][i] as _,
                states[5][i] as _,
                states[6][i] as _,
                states[7][i] as _,
                states[8][i] as _,
                states[9][i] as _,
                states[10][i] as _,
                states[11][i] as _,
                states[12][i] as _,
                states[13][i] as _,
                states[14][i] as _,
                states[15][i] as _,
            )
        });
        let states_avx512_save = state_avx512.clone();
        let blocks: [[u32; 16]; 16] =
            core::array::from_fn(|_| core::array::from_fn(|_| rng.random()));
        let mut block_avx512: [__m512i; 16] = core::array::from_fn(|i| unsafe {
            _mm512_setr_epi32(
                blocks[0][i] as _,
                blocks[1][i] as _,
                blocks[2][i] as _,
                blocks[3][i] as _,
                blocks[4][i] as _,
                blocks[5][i] as _,
                blocks[6][i] as _,
                blocks[7][i] as _,
                blocks[8][i] as _,
                blocks[9][i] as _,
                blocks[10][i] as _,
                blocks[11][i] as _,
                blocks[12][i] as _,
                blocks[13][i] as _,
                blocks[14][i] as _,
                blocks[15][i] as _,
            )
        });

        for i in 0..16 {
            compress_block_reference(&mut states[i], &blocks[i]);
        }
        compress_16block_avx512_without_feedback::<0>(&mut state_avx512, &mut block_avx512);
        for i in 0..8 {
            state_avx512[i] = unsafe { _mm512_add_epi32(state_avx512[i], states_avx512_save[i]) };
        }

        let mut output_state_simd_soa: [[u32; 16]; 8] = unsafe { core::mem::zeroed() };
        for i in 0..8 {
            unsafe {
                _mm512_storeu_si512(
                    output_state_simd_soa[i].as_mut_ptr() as *mut _,
                    state_avx512[i],
                );
            }
        }
        let output_state_simd: [[u32; 8]; 16] =
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
        compress_block_reference(&mut state, &input);

        // Expected output hash for "abc"
        let expected = [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ];

        assert_eq!(state, expected, "SHA-256 hash mismatch");
    }

    #[test]
    fn test_sha256_avx512_single_block() {
        // Test vector from NIST FIPS 180-4
        // Input: "abc" repeated 16 times
        let input_block = [
            0x61626380, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000018,
        ];

        // Create 16 identical blocks for AVX-512 processing
        let mut block_avx512: [__m512i; 16] = unsafe {
            core::array::from_fn(|i| {
                let mut arr = [0u32; 16];
                arr.fill(input_block[i]);
                _mm512_loadu_si512(arr.as_ptr() as *const _)
            })
        };

        // Initial hash values (H0) for 16 parallel hashes
        let state_avx512: [__m512i; 8] =
            core::array::from_fn(|i| unsafe { _mm512_set1_epi32(IV[i] as _) });

        // Process the blocks
        let mut state = state_avx512;
        compress_16block_avx512_without_feedback::<0>(&mut state, &mut block_avx512);
        for i in 0..8 {
            state[i] = unsafe { _mm512_add_epi32(state[i], state_avx512[i]) };
        }

        // Expected output hash for "abc"
        let expected = [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ];

        // Extract results from AVX-512 state
        let mut results: [[u32; 16]; 8] = unsafe { core::mem::zeroed() };
        for i in 0..8 {
            unsafe {
                _mm512_storeu_si512(results[i].as_mut_ptr() as *mut _, state[i]);
            }
        }

        // Verify all 16 results match the expected hash
        for i in 0..16 {
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
    fn test_sha256_avx512_bcst_without_feedback() {
        let mut block = [0; 64];
        block[0] = u32::from_be_bytes([0x61, 0x62, 0x63, 0x80]);
        block[15] = u32::from_be_bytes([0x00, 0x00, 0x00, 3 * 8]);
        do_message_schedule(&mut block);
        let mut state_avx512: [__m512i; 8] =
            core::array::from_fn(|i| unsafe { _mm512_set1_epi32(IV[i] as _) });

        compress_16block_avx512_bcst_without_feedback::<0>(&mut state_avx512, &block);
        for i in 0..8 {
            state_avx512[i] =
                unsafe { _mm512_add_epi32(state_avx512[i], _mm512_set1_epi32(IV[i] as _)) };
        }

        let expected = [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ];

        let mut results: [[u32; 16]; 8] = unsafe { core::mem::zeroed() };
        for i in 0..8 {
            unsafe {
                _mm512_storeu_si512(results[i].as_mut_ptr() as *mut _, state_avx512[i]);
            }
        }

        for i in 0..8 {
            for j in 0..16 {
                assert_eq!(results[i][j], expected[i]);
            }
        }
    }
}
