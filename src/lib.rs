#![doc = include_str!("../README.md")]
#![feature(stdarch_x86_avx512)]
use core::arch::x86_64::*;
use std::ops::{Deref, DerefMut};

#[cfg(feature = "client")]
pub mod client;

mod sha256;

const SWAP_DWORD_BYTE_ORDER: [usize; 64] = [
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 19, 18, 17, 16, 23, 22, 21, 20, 27, 26,
    25, 24, 31, 30, 29, 28, 35, 34, 33, 32, 39, 38, 37, 36, 43, 42, 41, 40, 47, 46, 45, 44, 51, 50,
    49, 48, 55, 54, 53, 52, 59, 58, 57, 56, 63, 62, 61, 60,
];

#[repr(align(64))]
struct Align64<T>(T);

impl Deref for Align64<[u32; 16]> {
    type Target = [u32; 16];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Align64<[u32; 16]> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub fn build_prefix<W: std::io::Write>(
    out: &mut W,
    string: &str,
    salt: &str,
) -> std::io::Result<()> {
    out.write_all(salt.as_bytes())?;
    match bincode::serialize_into(out, string) {
        Ok(_) => (),
        Err(e) => match *e {
            bincode::ErrorKind::Io(e) => return Err(e),
            _ => unreachable!(),
        },
    };
    Ok(())
}

pub const fn decompose_blocks_mut(inp: &mut [u32; 16]) -> &mut [u8; 64] {
    unsafe { core::mem::transmute(inp) }
}

#[allow(unused)]
fn dbg_dump_u32x16(inp: __m512i) {
    let mut tmp: Align64<[u32; 16]> = Align64([0; 16]);
    unsafe {
        _mm512_store_si512(tmp.as_mut_ptr().cast(), inp);
    }
    eprint!("{:04x?}", tmp.0);
}

pub fn compute_target(difficulty_factor: u32) -> u128 {
    u128::max_value() - u128::max_value() / difficulty_factor as u128
}

pub trait Solver {
    // construct a new solver instance from a prefix
    // prefix is the message that precedes the N in the single block of SHA-256 message
    // in mCaptcha it is the bincode serialized message then immediately the salt
    //
    // returns None when this solver cannot solve the prefix
    fn new(prefix: &[u8]) -> Option<Self>
    where
        Self: Sized;

    // returns a valid nonce and "result" value
    //
    // returns None when the solver cannot solve the prefix
    // failure is usually because the key space is exhausted (or presumed exhausted) and happens extremely rarely for common difficulty settings
    fn solve(&mut self, target: [u32; 4]) -> Option<(u64, u128)>;
}

// Solves an mCaptcha SHA256 PoW where the SHA-256 message is a single block (512 bytes minus padding).
//
// There are currently 6 out of 64 possible message length remainders that cross block boundaries,
// this is a limitation of the current implementation, but the other >90% of the cases are covered.
//
// This is an adversarial implementation, so the only metric is throughput.
#[derive(Debug, Clone)]
pub struct SingleBlockSolver {
    // the SHA-256 state A-H for all prefix bytes
    prefix_state: [u32; 8],

    // the message template for the final block
    message: [u32; 16],

    digit_index: usize,

    nonce_addend: u64,
}

impl Solver for SingleBlockSolver {
    fn new(mut prefix: &[u8]) -> Option<Self> {
        // construct the message buffer
        let mut prefix_state = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut nonce_addend = 0u64;
        let mut complete_blocks_before = 0;

        // first consume all full blocks, this is shared so use scalar reference implementation
        while prefix.len() >= 64 {
            sha256::compress_block_reference(
                &mut prefix_state,
                core::array::from_fn(|i| {
                    u32::from_be_bytes([
                        prefix[i * 4],
                        prefix[i * 4 + 1],
                        prefix[i * 4 + 2],
                        prefix[i * 4 + 3],
                    ])
                }),
            );
            prefix = &prefix[64..];
            complete_blocks_before += 1;
        }
        // if there is not enough room for 9 bytes of padding, '1's and then start a new block whenever possible
        // this avoids having to hash 2 blocks per iteration a naive solution would do
        if prefix.len() + 9 + 9 > 64 {
            let mut tmp_block = [0; 64];
            tmp_block[..prefix.len()].copy_from_slice(prefix);
            tmp_block[prefix.len()..].iter_mut().for_each(|b| {
                nonce_addend *= 10;
                nonce_addend += 1;
                *b = b'1';
            });
            nonce_addend = nonce_addend.checked_mul(1_000_000_000)?;
            complete_blocks_before += 1;
            prefix = &[];
            sha256::compress_block_reference(
                &mut prefix_state,
                core::array::from_fn(|i| {
                    u32::from_be_bytes([
                        tmp_block[i * 4],
                        tmp_block[i * 4 + 1],
                        tmp_block[i * 4 + 2],
                        tmp_block[i * 4 + 3],
                    ])
                }),
            );
        }

        let mut message: [u8; 64] = [0; 64];
        let mut ptr = 0;
        message[..prefix.len()].copy_from_slice(prefix);
        ptr += prefix.len();
        let digit_index = ptr;

        // skip 9 zeroes, this is the part we will interpolate N into
        // the first 2 digits are used as the lane index (10 + (0..16)*(0..4), offset to avoid leading zeroes), this also keeps our proof plausible
        // the rest are randomly generated then broadcasted to all lanes
        // this gives us about 16e7 * 4 possible attempts, likely enough for any realistic deployment even on the highest difficulty
        // the fail rate would be pgeom(keySpace, 1/difficulty, lower=F) in R
        ptr += 9;

        // set up padding
        message[ptr] = 0x80;
        message[(64 - 8)..]
            .copy_from_slice(&((complete_blocks_before * 64 + ptr) as u64 * 8).to_be_bytes());

        Some(Self {
            prefix_state,
            message: core::array::from_fn(|i| {
                u32::from_be_bytes([
                    message[i * 4],
                    message[i * 4 + 1],
                    message[i * 4 + 2],
                    message[i * 4 + 3],
                ])
            }),
            digit_index,
            nonce_addend,
        })
    }

    fn solve(&mut self, target: [u32; 4]) -> Option<(u64, u128)> {
        // the official default difficulty is 5e6, so we design for 5e7
        // pgeom(64e7, 1/5e7, lower=F) = 2.76e-06
        // pgeom(16e7, 1/5e7, lower=F) = 0.0608, which is too much so we need the prefix to change as well
        const KEYSPACE_SIZE: u64 = 64 * 10u64.pow(7);

        // pre-compute an OR to apply to the message to add the lane ID
        let lane_id_0_word_idx = self.digit_index / 4;
        let lane_id_0_byte_idx = self.digit_index % 4;
        let lane_id_1_word_idx = (self.digit_index + 1) / 4;
        let lane_id_1_byte_idx = (self.digit_index + 1) % 4;
        // this string is longer than we need but good enough for all intents and purposes
        let lane_id_0_or_value: [u32; 4 * 16] = core::array::from_fn(|i| {
            (b"111111111122222222223333333333444444444455555555556666666666777777777788888888889999999999"[i] as u32) << ((3 - lane_id_0_byte_idx) * 8) as u32
        });
        let lane_id_0_or_value_v: [__m512i; 4] = core::array::from_fn(|i| unsafe {
            _mm512_loadu_epi32(lane_id_0_or_value.as_ptr().add(i * 16).cast())
        });
        let lane_id_1_or_value: [u32; 4 * 16] = core::array::from_fn(|i| {
            (b"012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"[i] as u32) << ((3 - lane_id_1_byte_idx) * 8) as u32
        });
        let lane_id_1_or_value_v: [__m512i; 4] = core::array::from_fn(|i| unsafe {
            _mm512_loadu_epi32(lane_id_1_or_value.as_ptr().add(i * 16).cast())
        });

        let mut blocks: [__m512i; 16] = core::array::from_fn(|_| unsafe { _mm512_setzero_epi32() });

        for key in 0..KEYSPACE_SIZE {
            unsafe {
                let mut key_copy = key;
                let prefix_set_index = key_copy % 4;
                key_copy /= 4;
                {
                    let message_bytes = decompose_blocks_mut(&mut self.message);

                    for i in 0..7 {
                        let output = key_copy % 10;
                        key_copy /= 10;
                        *message_bytes.get_unchecked_mut(
                            *SWAP_DWORD_BYTE_ORDER.get_unchecked(self.digit_index + i + 2),
                        ) = output as u8 + b'0';
                    }
                }
                debug_assert_eq!(key_copy, 0);

                let mut state =
                    core::array::from_fn(|i| _mm512_set1_epi32(self.prefix_state[i] as _));
                for i in 0..16 {
                    blocks[i] = _mm512_set1_epi32(self.message[i] as _);
                }
                blocks[lane_id_0_word_idx] = _mm512_or_epi32(
                    *blocks.get_unchecked(lane_id_0_word_idx),
                    lane_id_0_or_value_v[prefix_set_index as usize],
                );
                blocks[lane_id_1_word_idx] = _mm512_or_epi32(
                    *blocks.get_unchecked(lane_id_1_word_idx),
                    lane_id_1_or_value_v[prefix_set_index as usize],
                );
                sha256::compress_16block_avx512_without_saved_state(&mut state, &mut blocks);

                // the target is big endian interpretation of the first 16 bytes of the hash (A-D) >= target
                // however, the largest 32-bit digits is unlikely to be all ones (otherwise a legitimate challenger needs on average >2^(128-32) attempts)
                // so we can reduce this into simply testing H[0]
                // it would miss about 1/2^32 valid solutions but we don't care, speed and register pressure is everything
                let a_is_greater = _mm512_cmpgt_epu32_mask(
                    _mm512_add_epi32(state[0], _mm512_set1_epi32(self.prefix_state[0] as _)),
                    _mm512_set1_epi32(target[0] as _),
                );
                if a_is_greater != 0 {
                    let success_lane_idx = _tzcnt_u32(a_is_greater as _) as usize;

                    // reconstruct the actual nonce for this lane
                    let mut nonce_tail = 0u64;
                    for i in 0..7 {
                        nonce_tail *= 10;
                        let message_bytes = decompose_blocks_mut(&mut self.message);
                        nonce_tail +=
                            (message_bytes[SWAP_DWORD_BYTE_ORDER[self.digit_index + i + 2]] as u64)
                                - b'0' as u64;
                    }

                    let nonce = (10 + 16 * prefix_set_index + success_lane_idx as u64)
                        * 10u64.pow(7)
                        + nonce_tail;

                    let mut result = 0u128;
                    let mut tmp: Align64<[u32; 16]> = Align64([0; 16]);
                    for i in 0..4 {
                        _mm512_store_si512(tmp.as_mut_ptr().cast(), state[i]);
                        result <<= 32;
                        result |=
                            (tmp[success_lane_idx].wrapping_add(self.prefix_state[i])) as u128;
                    }
                    return Some((nonce + self.nonce_addend, result));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solve() {
        const SALT: &str = "z";

        let mut cannot_solve = 0;
        for phrase_len in 0..64 {
            let mut concatenated_prefix = SALT.as_bytes().to_vec();
            let phrase_str = String::from_iter(std::iter::repeat('a').take(phrase_len));
            concatenated_prefix.extend_from_slice(&bincode::serialize(&phrase_str).unwrap());

            let config = pow_sha256::Config { salt: SALT.into() };
            const DIFFICULTY: u32 = 5000;

            let solver = SingleBlockSolver::new(&concatenated_prefix);
            let Some(mut solver) = solver else {
                eprintln!("solver is None for phrase_len: {}", phrase_len);
                cannot_solve += 1;
                continue;
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
            let (nonce, result) = solver.solve(target_u32s).expect("solver failed");

            /*
            let mut expected_message = concatenated_prefix.clone();
            let nonce_string = nonce.to_string();
            expected_message.extend_from_slice(nonce_string.as_bytes());
            let mut hasher = sha2::Sha256::default();
            hasher.update(&expected_message);
            let expected_hash = hasher.finalize();
            */

            let test_response = pow_sha256::PoWBuilder::default()
                .nonce(nonce)
                .result(result.to_string())
                .build()
                .unwrap();
            assert_eq!(
                config.calculate(&test_response, &phrase_str).unwrap(),
                result
            );

            assert!(config.is_valid_proof(&test_response, &phrase_str));
        }

        println!(
            "cannot_solve: {} out of 64 lengths (success rate: {:.2}%)",
            cannot_solve,
            (64 - cannot_solve) as f64 / 64.0 * 100.0
        );
    }
}
