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
fn g4_a_only(
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
    }
}

#[inline(always)]
#[allow(unused, reason = "Left in for fallback")]
pub(crate) fn compress_mb16(
    v: &mut [__m512i; 8],
    block: &[__m512i; 16],
    t: u32,
    len: u32,
    flags: u32,
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
        let mut aux = [
            _mm512_set1_epi32(IV[0] as _),
            _mm512_set1_epi32(IV[1] as _),
            _mm512_set1_epi32(IV[2] as _),
            _mm512_set1_epi32(IV[3] as _),
            _mm512_set1_epi32(t as _),
            _mm512_setzero_si512(),
            _mm512_set1_epi32(len as _),
            _mm512_set1_epi32(flags as _),
        ];

        repeat7!(i, {
            macro_rules! g4 {
                ($a:literal, $b:literal, $c:literal, $d:literal, $x:literal, $y:literal) => {{
                    let [va, vb] = v.get_disjoint_unchecked_mut([$a, $b]);
                    let [vc, vd] = aux.get_disjoint_unchecked_mut([$c - 8, $d - 8]);
                    g4(
                        va,
                        vb,
                        vc,
                        vd,
                        block[super::MESSAGE_SCHEDULE[i][$x]],
                        block[super::MESSAGE_SCHEDULE[i][$y]],
                    );
                }};
            }
            g4!(0, 4, 8, 12, 0, 1);
            g4!(1, 5, 9, 13, 2, 3);
            g4!(2, 6, 10, 14, 4, 5);
            g4!(3, 7, 11, 15, 6, 7);
            g4!(0, 5, 10, 15, 8, 9);
            g4!(1, 6, 11, 12, 10, 11);
            g4!(2, 7, 8, 13, 12, 13);
            g4!(3, 4, 9, 14, 14, 15);
        });
        for i in 0..8 {
            v[i] = _mm512_xor_si512(v[i], aux[i]);
        }
    }
}

#[inline(always)]
/// Reduced strength BLAKE3 that only gives the first word of the hash.
pub(crate) fn compress_mb16_reduced<const CONSTANT_WORD_COUNT: usize, const PATCH_1: usize>(
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
                if i < 6 {
                    g4!(0, 5, 10, 15, 8, 9);
                } else {
                    g4!(g4_a_only; 0, 5, 10, 15, 8, 9);
                }
            }
            if i < 6 && (i > 0 || CONSTANT_WORD_COUNT < 12) {
                g4!(1, 6, 11, 12, 10, 11);
            }
            if i > 0 || CONSTANT_WORD_COUNT < 14 {
                g4!(2, 7, 8, 13, 12, 13);
            }
            if i < 6 && (i > 0 || CONSTANT_WORD_COUNT < 16) {
                g4!(3, 4, 9, 14, 14, 15);
            }
        });

        v[0] = _mm512_xor_si512(v[0], v[8]);
    }
}

#[cfg(test)]
mod tests {
    use blake3::Hasher;
    use sha2::Digest;

    use super::*;

    // The mixing function, G, which mixes either a column or a diagonal.
    fn gref(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    #[test]
    fn test_g_function() {
        let mut state = core::array::from_fn(|i| crate::sha256::IV[i % 8].wrapping_add(i as u32));
        let mut state_v: [_; 16] =
            core::array::from_fn(|i| unsafe { _mm512_set1_epi32(state[i] as _) });
        gref(
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
        let mut v =
            core::array::from_fn(|i| unsafe { _mm512_set1_epi32(crate::blake3::IV[i] as _) });
        let mut block = core::array::from_fn(|i| unsafe {
            if i == 0 {
                _mm512_set1_epi32(0x46544549u32 as _)
            } else {
                _mm512_setzero_epi32()
            }
        });
        compress_mb16(&mut v, &mut block, 0, 4, 0x0b);
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

    #[test]
    fn test_compress_mb16_reduced() {
        let block_template = core::array::from_fn(|i| i as u32);
        let prepared_state = ingest_message_prefix(
            crate::blake3::IV,
            &block_template[..4],
            0,
            64,
            FLAG_CHUNK_START | FLAG_CHUNK_END | FLAG_ROOT,
        );

        unsafe {
            let mut v = core::array::from_fn(|i| _mm512_set1_epi32(prepared_state[i] as _));
            let patch = _mm512_setr_epi32(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
            compress_mb16_reduced::<4, 15>(&mut v, &block_template, patch);

            let mut extract_h0 = [0u32; 16];
            _mm512_storeu_si512(extract_h0.as_mut_ptr().cast(), v[0]);
            for validate_val in 0..16 {
                let mut equiv_msg = block_template.clone();
                equiv_msg[15] = validate_val + 1;
                let mut ref_hasher = Hasher::new();
                for j in 0..16 {
                    ref_hasher.update(&equiv_msg[j].to_le_bytes());
                }
                let ref_hash = ref_hasher.finalize();
                let ref_hash = ref_hash.as_bytes();
                let ref_hash_h0 = u32::from_le_bytes(ref_hash[..4].try_into().unwrap());
                assert_eq!(extract_h0[validate_val as usize], ref_hash_h0);
            }
        }
    }

    #[test]
    fn test_compress_mb16_256() {
        let mut msg = Vec::new();
        let mut ctr = 0usize;
        while msg.len() < 256 {
            let hash = ::sha2::Sha256::digest(ctr.to_le_bytes());
            msg.extend_from_slice(&hash);
            ctr = ctr.wrapping_add(1);
        }
        assert_eq!(msg.len(), 256);
        let mut hasher = Hasher::new();
        hasher.update(&msg);
        let hash = hasher.finalize();
        let hash = hash.as_bytes();

        let count_chunks = msg.len().div_ceil(64);
        let mut chunks = msg.chunks_exact(64);

        ctr = 0;
        let mut v =
            core::array::from_fn(|i| unsafe { _mm512_set1_epi32(crate::blake3::IV[i] as _) });
        while let Some(chunk) = chunks.next() {
            let mut block = core::array::from_fn(|i| unsafe {
                _mm512_set1_epi32(
                    u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap()) as _,
                )
            });
            compress_mb16(
                &mut v,
                &mut block,
                0,
                64,
                if ctr == 0 { FLAG_CHUNK_START } else { 0 }
                    | if count_chunks == ctr + 1 {
                        FLAG_CHUNK_END | FLAG_ROOT
                    } else {
                        0
                    },
            );
            ctr += 1;
        }

        let mut output = [0u32; 8];
        let mut expected = [0u32; 8];
        for i in 0..8 {
            unsafe {
                output[i] = _mm_extract_epi32(_mm512_castsi512_si128(v[i]), 0) as u32;
            }
            expected[i] = u32::from_le_bytes(hash[i * 4..i * 4 + 4].try_into().unwrap());
        }
        assert_eq!(output, expected);
    }
}
