use super::*;
use core::arch::x86_64::*;

#[macro_use]
#[path = "loop_macros.rs"]
mod loop_macros;

#[inline(always)]
fn g4(
    va: &mut __m512i,
    vb: &mut __m512i,
    vc: &mut __m512i,
    vd: &mut __m512i,
    x: __m512i,
    y: __m512i,
) {
    /*
        FUNCTION G( v[0..15], a, b, c, d, x, y )
    |
    |   v[a] := (v[a] + v[b] + x) mod 2**32
    |   v[d] := (v[d] ^ v[a]) >>> 16
    |   v[c] := (v[c] + v[d])     mod 2**32
    |   v[b] := (v[b] ^ v[c]) >>> 12
    |   v[a] := (v[a] + v[b] + y) mod 2**32
    |   v[d] := (v[d] ^ v[a]) >>> 8
    |   v[c] := (v[c] + v[d])     mod 2**32
    |   v[b] := (v[b] ^ v[c]) >>> 7
    |
    |   RETURN v[0..15]
    |
    END FUNCTION. */
    unsafe {
        *va = _mm512_add_epi32(*va, _mm512_add_epi32(*vb, x));
        *vd = _mm512_xor_si512(*vd, *va);
        *vd = _mm512_ror_epi32(*vd, 16);
        *vc = _mm512_add_epi32(*vc, *vd);
        *vb = _mm512_xor_si512(*vb, *vc);
        *vb = _mm512_ror_epi32(*vb, 12);
        *va = _mm512_add_epi32(*va, _mm512_add_epi32(*vb, y));
        *vd = _mm512_xor_si512(*vd, *va);
        *vd = _mm512_ror_epi32(*vd, 8);
        *vc = _mm512_add_epi32(*vc, *vd);
        *vb = _mm512_xor_si512(*vb, *vc);
        *vb = _mm512_ror_epi32(*vb, 7);
    }
}

#[inline(always)]
pub(crate) fn compress_mb16<const CONSTANT_WORD_COUNT: usize, const PATCH_1: usize>(
    v: &mut [__m512i; 16],
    block_template: &[u32; 16],
    patch_1: __m512i,
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
                            _mm512_set1_epi32(block_template[ix] as _)
                        },
                        if iy == PATCH_1 {
                            patch_1
                        } else {
                            _mm512_set1_epi32(block_template[iy] as _)
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
            v[i] = _mm512_xor_si512(v[i], v[i + 8]);
        });
    }
}

#[cfg(target_feature = "avx512f")]
#[cfg(test)]
mod tests {
    use blake3::Hasher;

    use super::*;

    #[test]
    fn test_g_function() {
        let mut state = core::array::from_fn(|i| crate::sha256::IV[i % 8].wrapping_add(i as u32));
        let mut state_v: [_; 16] =
            core::array::from_fn(|i| unsafe { _mm512_set1_epi32(state[i] as _) });
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
            unsafe { _mm512_set1_epi32(crate::sha256::IV[0] as _) },
            unsafe { _mm512_set1_epi32(crate::sha256::IV[1] as _) },
        );

        for i in 0..16 {
            assert_eq!(
                unsafe { _mm_extract_epi32(_mm512_castsi512_si128(state_v[i]), 0) as u32 },
                state[i],
                "word {}: expected: {:08x}, results: {:08x}",
                i,
                state[i],
                unsafe { _mm_extract_epi32(_mm512_castsi512_si128(state_v[i]), 0) as u32 }
            );
        }
    }

    #[test]
    fn test_compress_mb16() {
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&crate::blake3::IV);
        v[8..12].copy_from_slice(&crate::blake3::IV[..4]);
        v[12] = 0;
        v[13] = 0;
        v[14] = 4;
        v[15] = 0x0b;
        let mut v = core::array::from_fn(|i| unsafe { _mm512_set1_epi32(v[i] as _) });
        let mut block = [0u32; 16];
        block[0] = u32::from_le_bytes(*b"IETF");
        compress_mb16::<0, 16>(&mut v, &block, unsafe { _mm512_setzero_epi32() });
        let expected = [
            0x1edea283, 0xabe6f4e6, 0x24896868, 0xcfc04e8f, 0x9470c54c, 0xff82a646, 0xd6b4cbd1,
            0xe2815116,
        ];
        let mut results = [0u32; 8];
        for i in 0..8 {
            unsafe {
                results[i] = _mm_extract_epi32(_mm512_castsi512_si128(v[i]), 0) as u32;
            }
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
