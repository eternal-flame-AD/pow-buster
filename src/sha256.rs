#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
pub mod avx512;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    target_feature = "sha"
))]
pub mod sha_ni;

#[cfg(target_arch = "wasm32")]
pub mod simd128;

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/local_macros.rs"));

// Initial hash values for SHA-256
pub(crate) const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// pre-compute the message schedule for a single block
///
/// The first 16 words are the input block, the rest are computed from them
#[inline(always)]
pub(crate) const fn do_message_schedule(w: &mut [u32; 64]) {
    repeat64!(i, {
        if i >= 16 {
            let w15 = w[i - 15];
            let s0 = (w15.rotate_right(7)) ^ (w15.rotate_right(18)) ^ (w15 >> 3);
            let w2 = w[i - 2];
            let s1 = (w2.rotate_right(17)) ^ (w2.rotate_right(19)) ^ (w2 >> 10);
            w[i] = w[i].wrapping_add(s0);
            w[i] = w[i].wrapping_add(w[i - 7]);
            w[i] = w[i].wrapping_add(s1);
            w[i] = w[i].wrapping_add(w[i - 16]);
        }
    });
}

/// pre-compute the message schedule for a single block, adding corresponding round constants
#[inline(always)]
pub(crate) const fn do_message_schedule_k_w(w: &mut [u32; 64]) {
    do_message_schedule(w);
    repeat64!(i, {
        w[i] = w[i].wrapping_add(K32[i]);
    });
}

/// A reference software implementation of SHA-256 compression function from sha2 crate
#[inline(always)]
pub(crate) fn digest_block(state: &mut [u32; 8], block: &[u32; 16]) {
    let mut tmp = sha2::digest::generic_array::GenericArray::<u8, _>::default();
    for i in 0..16 {
        tmp[i * 4..][..4].copy_from_slice(&block[i].to_be_bytes());
    }
    sha2::compress256(state, &[tmp]);
}

/// ingest a message prefix into the state
#[inline(always)]
pub(crate) fn ingest_message_prefix<const LEN: usize>(state: &mut [u32; 8], w: [u32; LEN]) {
    sha2_arx::<0>(state, &w);
}

/// scalar sha2 rounds for hotstart taken verbatim from sha2 crate
#[inline(always)]
pub(crate) fn sha2_arx<const START: usize>(state: &mut [u32; 8], w: &[u32]) {
    let [a, b, c, d, e, f, g, h] = &mut *state;

    for i in 0..w.len() {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (*e & *f) ^ ((!*e) & *g);
        let t1 = s1
            .wrapping_add(ch)
            .wrapping_add(K32[START + i])
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

/// scalar sha2 rounds for hotstart taken verbatim from sha2 crate, but without constants
#[inline(always)]
pub(crate) fn sha2_arx_without_constants<const START: usize, const LEN: usize>(
    state: &mut [u32; 8],
    w: [u32; LEN],
) {
    let [a, b, c, d, e, f, g, h] = &mut *state;

    for i in 0..LEN {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (*e & *f) ^ ((!*e) & *g);
        let t1 = s1.wrapping_add(ch).wrapping_add(w[i]).wrapping_add(*h);
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
