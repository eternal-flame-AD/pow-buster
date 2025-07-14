//! Multi-way sha256 implementation extracted from `sha2` crate for simd128.
use super::*;
use core::arch::wasm32::*;

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/local_macros.rs"));

#[inline(always)]
fn u32x4_ror(x: v128, shift: u32) -> v128 {
    unsafe { v128_or(u32x4_shr(x, shift), u32x4_shl(x, 32 - shift)) }
}

pub(crate) fn multiway_arx<const BEGIN_ROUND: usize>(
    state: &mut [v128; 8],
    block: &mut [v128; 16],
) {
    unsafe {
        let [a, b, c, d, e, f, g, h] = &mut *state;

        repeat64!(i, {
            if i >= BEGIN_ROUND {
                let w = if i < 16 {
                    block[i]
                } else {
                    let w15 = block[(i - 15) % 16];
                    let s0 = v128_xor(
                        v128_xor(u32x4_ror(w15, 7), u32x4_ror(w15, 18)),
                        u32x4_shr(w15, 3),
                    );
                    let w2 = block[(i - 2) % 16];
                    let s1 = v128_xor(
                        v128_xor(u32x4_ror(w2, 17), u32x4_ror(w2, 19)),
                        u32x4_shr(w2, 10),
                    );
                    block[i % 16] = u32x4_add(block[i % 16], s0);
                    block[i % 16] = u32x4_add(block[i % 16], block[(i - 7) % 16]);
                    block[i % 16] = u32x4_add(block[i % 16], s1);
                    block[i % 16]
                };

                let s1 = v128_xor(
                    v128_xor(u32x4_ror(*e, 6), u32x4_ror(*e, 11)),
                    u32x4_ror(*e, 25),
                );
                let ch = v128_xor(v128_and(*e, *f), v128_andnot(*g, *e));
                let mut t1 = s1;
                t1 = u32x4_add(t1, ch);
                t1 = u32x4_add(t1, u32x4_splat(K32[i] as _));
                t1 = u32x4_add(t1, w);
                t1 = u32x4_add(t1, *h);

                let s0 = v128_xor(
                    v128_xor(u32x4_ror(*a, 2), u32x4_ror(*a, 13)),
                    u32x4_ror(*a, 22),
                );
                let maj = v128_xor(
                    v128_xor(v128_and(*a, *b), v128_and(*a, *c)),
                    v128_and(*b, *c),
                );
                let mut t2 = s0;
                t2 = u32x4_add(t2, maj);

                *h = *g;
                *g = *f;
                *f = *e;
                *e = u32x4_add(*d, t1);
                *d = *c;
                *c = *b;
                *b = *a;
                *a = u32x4_add(t1, t2);
            }
        });
    }
}

pub(crate) fn bcst_multiway_arx<const LEAD_ZEROES: usize>(state: &mut [v128; 8], w_k: &[u32; 64]) {
    unsafe {
        let [a, b, c, d, e, f, g, h] = &mut *state;

        repeat64!(i, {
            let w = if i < LEAD_ZEROES {
                u32x4_splat(K32[i] as _)
            } else {
                u32x4_splat(w_k[i] as _)
            };
            let s1 = v128_xor(
                v128_xor(u32x4_ror(*e, 6), u32x4_ror(*e, 11)),
                u32x4_ror(*e, 25),
            );
            let ch = v128_xor(v128_and(*e, *f), v128_andnot(*g, *e));
            let mut t1 = s1;
            t1 = u32x4_add(t1, ch);
            t1 = u32x4_add(t1, w);
            t1 = u32x4_add(t1, *h);

            let s0 = v128_xor(
                v128_xor(u32x4_ror(*a, 2), u32x4_ror(*a, 13)),
                u32x4_ror(*a, 22),
            );
            let maj = v128_xor(
                v128_xor(v128_and(*a, *b), v128_and(*a, *c)),
                v128_and(*b, *c),
            );
            let mut t2 = s0;
            t2 = u32x4_add(t2, maj);

            *h = *g;
            *g = *f;
            *f = *e;
            *e = u32x4_add(*d, t1);
            *d = *c;
            *c = *b;
            *b = *a;
            *a = u32x4_add(t1, t2);
        });
    }
}

#[cfg(feature = "wasm-bindgen")]
#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    #[wasm_bindgen_test]
    fn test_simd128_ror() {
        unsafe {
            for amount in 0..32 {
                let input = [0x12345678, 0x9abcdef0, 0x0c0c0c0c, 0xffffeeee];
                let x = u32x4(input[0], input[1], input[2], input[3]);
                let y = u32x4_ror(x, amount);
                let mut ys = [0u32; 4];
                v128_store(ys.as_mut_ptr().cast(), y);
                let expected = core::array::from_fn(|i| input[i].rotate_right(amount));
                assert_eq!(
                    ys, expected,
                    "amount: {}, x: {:08x?}, y: {:08x?}",
                    amount, input, y
                );
            }
        }
    }

    #[wasm_bindgen_test]
    fn test_sha256_simd128_single_block() {
        // Test vector from NIST FIPS 180-4
        // Input: "abc" repeated 16 times
        let input_block = [
            0x61626380, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000018,
        ];

        // Create 16 identical blocks for SIMD128 processing
        let mut block_simd128: [v128; 16] =
            unsafe { core::array::from_fn(|i| u32x4_splat(input_block[i])) };
        let state_save: [v128; 8] = core::array::from_fn(|i| unsafe { u32x4_splat(IV[i]) });

        // Process the blocks
        let mut state = state_save;
        multiway_arx::<0>(&mut state, &mut block_simd128);
        for i in 0..8 {
            state[i] = unsafe { u32x4_add(state_save[i], state[i]) };
        }

        // Expected output hash for "abc"
        let expected = [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ];

        let mut results: [[u32; 4]; 8] = unsafe { core::mem::zeroed() };
        for i in 0..8 {
            unsafe {
                v128_store(results[i].as_mut_ptr().cast(), state[i]);
            }
        }

        // Verify all 4 results match the expected hash
        for i in 0..4 {
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
                "SHA-256 SIMD128 hash mismatch at index {}",
                i
            );
        }
    }
}
