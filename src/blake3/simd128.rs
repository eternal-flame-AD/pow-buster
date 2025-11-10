use super::*;
use core::arch::wasm32::*;

#[macro_use]
#[path = "loop_macros.rs"]
mod loop_macros;

#[inline(always)]
fn u32x4_ror(x: v128, shift: u32) -> v128 {
    v128_or(u32x4_shr(x, shift), u32x4_shl(x, 32 - shift))
}

#[inline(always)]
fn g4(va: &mut v128, vb: &mut v128, vc: &mut v128, vd: &mut v128, x: v128, y: v128) {
    *va = u32x4_add(*va, u32x4_add(*vb, x));
    *vd = v128_xor(*vd, *va);
    *vd = u32x4_ror(*vd, 16);
    *vc = u32x4_add(*vc, *vd);
    *vb = v128_xor(*vb, *vc);
    *vb = u32x4_ror(*vb, 12);
    *va = u32x4_add(*va, u32x4_add(*vb, y));
    *vd = v128_xor(*vd, *va);
    *vd = u32x4_ror(*vd, 8);
    *vc = u32x4_add(*vc, *vd);
    *vb = v128_xor(*vb, *vc);
    *vb = u32x4_ror(*vb, 7);
}

#[inline(always)]
pub(crate) fn compress_mb4<const CONSTANT_WORD_COUNT: usize, const PATCH_1: usize>(
    v: &mut [v128; 16],
    block_template: &[u32; 16],
    patch_1: v128,
) {
    /*

    FUNCTION BLAKE3_COMPRESS( h[0..7], m[0..15], t, len, flags )
           FUNCTION BLAKE3_COMPRESS( h[0..7], m[0..15], t, len, flags )
       |
       |   // Initialize local 16-word array v[0..15]
       |   v[0..7] := h[0..7]              // 8 words from the state.
       |   v[8..11] := IV[0..3]            // 4 words from the IV.
       |
       |   v[12] :=  t[0]                  // Low word of the counter.
       |   v[13] :=  t[1]                  // High word of the counter.
       |   v[14] :=  len                   // Application data length.
       |   v[15] :=  flags                 // Flags.
       |
       |   // Cryptographic mixing
       |   FOR i = 0 TO 6 DO               // 7 rounds.
       |   |
       |   |   v := G( v, 0, 4,  8, 12, m[ 0], m[ 1] )
       |   |   v := G( v, 1, 5,  9, 13, m[ 2], m[ 3] )
       |   |   v := G( v, 2, 6, 10, 14, m[ 4], m[ 5] )
       |   |   v := G( v, 3, 7, 11, 15, m[ 6], m[ 7] )
       |   |
       |   |   v := G( v, 0, 5, 10, 15, m[ 8], m[ 9] )
       |   |   v := G( v, 1, 6, 11, 12, m[10], m[11] )
       |   |   v := G( v, 2, 7,  8, 13, m[12], m[13] )
       |   |   v := G( v, 3, 4,  9, 14, m[14], m[15] )
       |   |
       |   |   PERMUTE(m)                  // Apply the permutation.
       |   |
       |   END FOR
       |
       |   // Compute the output state (untruncated)
       |   FOR i = 0 TO 7 DO
       |   |   v[i] := v[i] ^ v[i + 8]
       |   |   v[i + 8] := v[i + 8] ^ h[i]
       |   END FOR.
       |
       |   RETURN v
       |
       END FUNCTION.

    |
    END FUNCTION. */
    unsafe {
        repeat7!(i, {
            macro_rules! g4 {
                ($f:ident; $a:literal, $b:literal, $c:literal, $d:literal, $x:literal, $y:literal) => {{
                    let [va, vb, vc, vd] = v.get_disjoint_unchecked_mut([$a, $b, $c, $d]);
                    let ix = MESSAGE_SCHEDULE[i][$x];
                    let iy = MESSAGE_SCHEDULE[i][$y];
                    $f(
                        va,
                        vb,
                        vc,
                        vd,
                        if ix == PATCH_1 {
                            patch_1
                        } else {
                            u32x4_splat(block_template[ix])
                        },
                        if iy == PATCH_1 {
                            patch_1
                        } else {
                            u32x4_splat(block_template[iy])
                        },
                    );
                }};
                ($a:literal, $b:literal, $c:literal, $d:literal, $x:literal, $y:literal) => {{
                    g4!(g4; $a, $b, $c, $d, $x, $y);
                }};
            }
            if i > 0 || CONSTANT_WORD_COUNT < 2 {
                g4!(0, 4, 8, 12, 0, 1);
            }
            if i > 0 || CONSTANT_WORD_COUNT < 4 {
                g4!(1, 5, 9, 13, 2, 3);
            }
            if i > 0 || CONSTANT_WORD_COUNT < 6 {
                g4!(2, 6, 10, 14, 4, 5);
            }
            if i > 0 || CONSTANT_WORD_COUNT < 8 {
                g4!(3, 7, 11, 15, 6, 7);
            }
            if i > 0 || CONSTANT_WORD_COUNT < 10 {
                g4!(0, 5, 10, 15, 8, 9);
            }
            if i > 0 || CONSTANT_WORD_COUNT < 12 {
                g4!(1, 6, 11, 12, 10, 11);
            }
            if i > 0 || CONSTANT_WORD_COUNT < 14 {
                g4!(2, 7, 8, 13, 12, 13);
            }
            if i > 0 || CONSTANT_WORD_COUNT < 16 {
                g4!(3, 4, 9, 14, 14, 15);
            }
        });

        repeat8!(i, {
            v[i] = v128_xor(v[i], v[i + 8]);
        });
    }
}

#[cfg(test)]
mod tests {
    use blake3::Hasher;

    use super::*;

    #[test]
    fn test_g_function() {
        let mut state = core::array::from_fn(|i| crate::sha256::IV[i % 8].wrapping_add(i as u32));
        let mut state_v: [_; 16] = core::array::from_fn(|i| u32x4_splat(state[i] as _));
        g(
            &mut state,
            0,
            4,
            8,
            12,
            crate::sha256::IV[0],
            crate::sha256::IV[1],
        );
        let [va, vb, vc, vd] = state_v.get_disjoint_mut([0, 4, 8, 12]).unwrap();
        g4(
            va,
            vb,
            vc,
            vd,
            u32x4_splat(crate::sha256::IV[0] as _),
            u32x4_splat(crate::sha256::IV[1] as _),
        );

        for i in 0..16 {
            assert_eq!(
                u32x4_extract_lane::<0>(state_v[i]) as u32,
                state[i],
                "word {}: expected: {:08x}, results: {:08x}",
                i,
                state[i],
                u32x4_extract_lane::<0>(state_v[i]) as u32
            );
        }
    }

    #[test]
    fn test_compress_mb4() {
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&crate::blake3::IV);
        v[8..12].copy_from_slice(&crate::blake3::IV[..4]);
        v[12] = 0;
        v[13] = 0;
        v[14] = 4;
        v[15] = 0x0b;
        let mut v = core::array::from_fn(|i| u32x4_splat(v[i] as _));
        let mut block = [0u32; 16];
        block[0] = u32::from_le_bytes(*b"IETF");
        compress_mb4::<0, 4>(&mut v, &block, u32x4_splat(0));
        let expected = [
            0x1edea283, 0xabe6f4e6, 0x24896868, 0xcfc04e8f, 0x9470c54c, 0xff82a646, 0xd6b4cbd1,
            0xe2815116,
        ];
        let mut results = [0u32; 8];
        for i in 0..8 {
            results[i] = u32x4_extract_lane::<0>(v[i]) as u32;
        }
        assert_eq!(
            results, expected,
            "expected: {:08x?}, results: {:08x?}",
            expected, results
        );
        let mut hasher = Hasher::new();
        hasher.update(b"IETF");
        let hash = hasher.finalize();
        let hash = hash.as_bytes();
        let mut expected = [0u32; 8];
        for i in 0..8 {
            expected[i] = u32::from_le_bytes(hash[i * 4..i * 4 + 4].try_into().unwrap());
        }
        assert_eq!(results, expected);
    }
}
