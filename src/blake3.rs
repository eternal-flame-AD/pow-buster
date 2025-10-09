#[cfg(all(target_arch = "x86_64", any(doc, target_feature = "avx512f")))]
pub mod avx512;

/// Initial hash values for BLAKE3
pub(crate) const IV: [u32; 8] = crate::sha256::IV;

pub(crate) const FLAG_CHUNK_START: u32 = 0x01;
pub(crate) const FLAG_CHUNK_END: u32 = 0x02;
#[expect(unused, reason = "TODO, maybe never going to need this")]
pub(crate) const FLAG_PARENT: u32 = 0x04;
pub(crate) const FLAG_ROOT: u32 = 0x08;

const PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const MESSAGE_SCHEDULE: [[usize; 16]; 7] = {
    let mut ix = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut out = [ix; 7];

    let mut i = 1;
    while i < 7 {
        let mut j = 0;
        let mut new_ix = [0; 16];
        while j < 16 {
            new_ix[j] = ix[PERMUTATION[j]];
            j += 1;
        }
        ix = new_ix;
        out[i] = new_ix;
        i += 1;
    }

    out
};

// The mixing function, G, which mixes either a column or a diagonal.
#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

#[inline(always)]
fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    // Mix the columns.
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    // Mix the diagonals.
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

#[inline(always)]
pub fn round_gated(state: &mut [u32; 16], m: &[u32]) {
    debug_assert!(m.len() <= 16);
    // Mix the columns.
    if m.len() >= 2 {
        g(state, 0, 4, 8, 12, m[0], m[1]);
    }
    if m.len() >= 4 {
        g(state, 1, 5, 9, 13, m[2], m[3]);
    }
    if m.len() >= 6 {
        g(state, 2, 6, 10, 14, m[4], m[5]);
    }
    if m.len() >= 8 {
        g(state, 3, 7, 11, 15, m[6], m[7]);
    }
    // Mix the diagonals.
    if m.len() >= 10 {
        g(state, 0, 5, 10, 15, m[8], m[9]);
    }
    if m.len() >= 12 {
        g(state, 1, 6, 11, 12, m[10], m[11]);
    }
    if m.len() >= 14 {
        g(state, 2, 7, 8, 13, m[12], m[13]);
    }
    if m.len() == 16 {
        g(state, 3, 4, 9, 14, m[14], m[15]);
    }
}

pub fn ingest_message_prefix(
    state: [u32; 8],
    m: &[u32],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut full_state = [
        state[0],
        state[1],
        state[2],
        state[3],
        state[4],
        state[5],
        state[6],
        state[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        0,
        block_len,
        flags,
    ];
    round_gated(&mut full_state, m);
    full_state
}

#[inline(always)]
fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0; 16];
    for i in 0..16 {
        permuted[i] = m[PERMUTATION[i]];
    }
    *m = permuted;
}

#[inline(always)]
pub fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let counter_low = counter as u32;
    let counter_high = (counter >> 32) as u32;
    #[rustfmt::skip]
    let mut state = [
        chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
        chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
        IV[0],             IV[1],             IV[2],             IV[3],
        counter_low,       counter_high,      block_len,         flags,
    ];
    let mut block = *block_words;

    round(&mut state, &block); // round 1
    permute(&mut block);
    round(&mut state, &block); // round 2
    permute(&mut block);
    round(&mut state, &block); // round 3
    permute(&mut block);
    round(&mut state, &block); // round 4
    permute(&mut block);
    round(&mut state, &block); // round 5
    permute(&mut block);
    round(&mut state, &block); // round 6
    permute(&mut block);
    round(&mut state, &block); // round 7

    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

#[cfg(test)]
mod tests {
    use sha2::Digest;

    use super::*;

    #[test]
    fn test_compress_unchained() {
        for blockc in 1..=4 {
            let mut chaining_value = IV;

            let mut msg = Vec::new();
            let mut ctr = 0usize;
            while msg.len() < 64 * blockc {
                let hash = ::sha2::Sha256::digest(ctr.to_le_bytes());
                msg.extend_from_slice(&hash);
                ctr = ctr.wrapping_add(1);
            }
            assert_eq!(msg.len(), 64 * blockc);

            let mut hasher = blake3::Hasher::new();
            hasher.update(&msg);
            let hash = hasher.finalize();
            let hash = hash.as_bytes();

            let count_chunks = msg.len().div_ceil(64);
            ctr = 0;
            let mut chunks = msg.chunks_exact(64);
            let mut output = [0u32; 16];
            while let Some(chunk) = chunks.next() {
                let block = core::array::from_fn(|i| {
                    u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap())
                });

                let this_flag = if ctr == 0 { FLAG_CHUNK_START } else { 0 }
                    | if count_chunks == ctr + 1 {
                        FLAG_CHUNK_END | FLAG_ROOT
                    } else {
                        0
                    };
                output = compress(&chaining_value, &block, 0, 64, this_flag);
                for i in 0..8 {
                    chaining_value[i] = output[i];
                }
                ctr += 1;
            }

            let output: [u32; 8] = output[..8].try_into().unwrap();
            let mut expected = [0u32; 8];
            for i in 0..8 {
                expected[i] = u32::from_le_bytes(hash[i * 4..i * 4 + 4].try_into().unwrap());
            }
            assert_eq!(output, expected, "output mismatch (blockc: {})", blockc);
        }
    }
}
