#![doc = include_str!("../README.md")]
#![feature(stdarch_x86_avx512)]
use core::arch::x86_64::*;
use core::hint::unreachable_unchecked;
use std::ops::{Deref, DerefMut};

use generic_array::typenum::{
    U0, U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12, U13, U14, U15, Unsigned,
};

#[cfg(feature = "client")]
pub mod client;

mod sha256;

#[cfg(feature = "wgpu")]
pub mod wgpu;

const SWAP_DWORD_BYTE_ORDER: [usize; 64] = [
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 19, 18, 17, 16, 23, 22, 21, 20, 27, 26,
    25, 24, 31, 30, 29, 28, 35, 34, 33, 32, 39, 38, 37, 36, 43, 42, 41, 40, 47, 46, 45, 44, 51, 50,
    49, 48, 55, 54, 53, 52, 59, 58, 57, 56, 63, 62, 61, 60,
];

#[repr(align(64))]
struct Align64<T>(T);

impl<T> Deref for Align64<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Align64<T> {
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

pub const fn decompose_blocks(inp: &[u32; 16]) -> &[u8; 64] {
    unsafe { core::mem::transmute(inp) }
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
    type Ctx;

    // construct a new solver instance from a prefix
    // prefix is the message that precedes the N in the single block of SHA-256 message
    // in mCaptcha it is the bincode serialized message then immediately the salt
    //
    // returns None when this solver cannot solve the prefix
    fn new(ctx: Self::Ctx, prefix: &[u8]) -> Option<Self>
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
// The main limitations are:
// 1. No AVX2 fallback for more common hardware
// 2. Doesn't handle ~10% of cases where message crosses block boundaries,
// this is a periodic problem, using longer salt do not automatically mean immunity.
#[derive(Debug, Clone)]
pub struct SingleBlockSolver {
    // the SHA-256 state A-H for all prefix bytes
    pub(crate) prefix_state: [u32; 8],

    // the message template for the final block
    pub(crate) message: [u32; 16],

    pub(crate) digit_index: usize,

    pub(crate) nonce_addend: u64,
}

impl Solver for SingleBlockSolver {
    type Ctx = ();

    fn new(_ctx: Self::Ctx, mut prefix: &[u8]) -> Option<Self> {
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
        // the official default difficulty is 5e6, so we design for 1e8
        // and there should almost always be a valid solution within our supported solution space
        // pgeom(5 * 16e7, 1/5e7, lower=F) = 0.03%
        // pgeom(16e7, 1/5e7, lower=F) = 20%, which is too much so we need the prefix to change as well

        // pre-compute an OR to apply to the message to add the lane ID
        let lane_id_0_word_idx = self.digit_index / 4;
        let lane_id_1_word_idx = (self.digit_index + 1) / 4;

        // make sure there are no runtime "register indexing" logic
        fn solve_inner<DigitWordIdx0: Unsigned, DigitWordIdx1: Unsigned>(
            this: &mut SingleBlockSolver,
            target: u32,
        ) -> Option<(u64, u128)> {
            let lane_id_0_byte_idx = this.digit_index % 4;
            let lane_id_1_byte_idx = (this.digit_index + 1) % 4;
            // pre-compute the lane index OR mask to "stamp" onto each lane for each try
            // this string is longer than we need but good enough for all intents and purposes
            let lane_id_0_or_value: [u32; 5 * 16] = core::array::from_fn(|i| {
                (b"111111111122222222223333333333444444444455555555556666666666777777777788888888889999999999"[i] as u32) << ((3 - lane_id_0_byte_idx) * 8) as u32
            });

            let lane_id_1_or_value: [u32; 5 * 16] = core::array::from_fn(|i| {
                (b"012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"[i] as u32) << ((3 - lane_id_1_byte_idx) * 8) as u32
            });

            let mut blocks: [__m512i; 16] =
                core::array::from_fn(|_| unsafe { _mm512_setzero_epi32() });

            for prefix_set_index in 0..5 {
                let lane_id_0_or_value_v = unsafe {
                    _mm512_loadu_epi32(
                        lane_id_0_or_value
                            .as_ptr()
                            .add(prefix_set_index as usize * 16)
                            .cast(),
                    )
                };
                let lane_id_1_or_value_v = unsafe {
                    _mm512_loadu_epi32(
                        lane_id_1_or_value
                            .as_ptr()
                            .add(prefix_set_index as usize * 16)
                            .cast(),
                    )
                };
                for inner_key in 0..10_000_000 {
                    unsafe {
                        let mut key_copy = inner_key;
                        {
                            let message_bytes = decompose_blocks_mut(&mut this.message);

                            for i in 0..7 {
                                let output = key_copy % 10;
                                key_copy /= 10;
                                *message_bytes.get_unchecked_mut(
                                    *SWAP_DWORD_BYTE_ORDER.get_unchecked(this.digit_index + i + 2),
                                ) = output as u8 + b'0';
                            }
                        }
                        debug_assert_eq!(key_copy, 0);

                        let mut state =
                            core::array::from_fn(|i| _mm512_set1_epi32(this.prefix_state[i] as _));
                        for i in 0..16 {
                            blocks[i] = _mm512_set1_epi32(this.message[i] as _);
                        }
                        blocks[DigitWordIdx0::USIZE] = _mm512_or_epi32(
                            *blocks.get_unchecked(DigitWordIdx0::USIZE),
                            lane_id_0_or_value_v,
                        );
                        blocks[DigitWordIdx1::USIZE] = _mm512_or_epi32(
                            *blocks.get_unchecked(DigitWordIdx1::USIZE),
                            lane_id_1_or_value_v,
                        );
                        // do 16-way SHA-256 without adding back the saved state so as not to force the compiler to save 8 registers
                        sha256::compress_16block_avx512_without_saved_state(
                            &mut state,
                            &mut blocks,
                        );

                        // the target is big endian interpretation of the first 16 bytes of the hash (A-D) >= target
                        // however, the largest 32-bit digits is unlikely to be all ones (otherwise a legitimate challenger needs on average >2^32 attempts)
                        // so we can reduce this into simply testing H[0]
                        // the number of acceptable u32 values (for us) is u32::MAX / difficulty
                        // so the "inefficiency" this creates is about (u32::MAX / difficulty) * (1 / 2), because for approx. half of the "edge case" do we actually have an acceptable solution,
                        // which for 1e8 is about 1%, but we get to save the one broadcast add,
                        // a vectorized comparison, and a scalar logic evaluation
                        // which I feel is about 1% of the instructions needed per iteration anyways just more registers used so let's not bother
                        let a_is_greater = _mm512_cmpgt_epu32_mask(
                            _mm512_add_epi32(
                                state[0],
                                _mm512_set1_epi32(this.prefix_state[0] as _),
                            ),
                            _mm512_set1_epi32(target as _),
                        );
                        if a_is_greater != 0 {
                            let success_lane_idx = _tzcnt_u32(a_is_greater as _) as usize;

                            // reconstruct the actual nonce for this lane
                            let mut nonce_tail = 0u64;
                            for i in 0..7 {
                                nonce_tail *= 10;
                                let message_bytes = decompose_blocks_mut(&mut this.message);
                                nonce_tail += (*message_bytes.get_unchecked(
                                    *SWAP_DWORD_BYTE_ORDER.get_unchecked(this.digit_index + i + 2),
                                ) as u64)
                                    - b'0' as u64;
                            }

                            // the nonce is the 7 digits in the message, plus the first two digits recomputed from the lane index
                            let nonce = (10 + 16 * prefix_set_index + success_lane_idx as u64)
                                * 10u64.pow(7)
                                + nonce_tail;

                            // the resulting hash is the A-H in registers, plus the saved state
                            let mut result = 0u128;
                            let mut tmp: Align64<[u32; 16]> = Align64([0; 16]);
                            for i in 0..4 {
                                _mm512_store_si512(tmp.as_mut_ptr().cast(), state[i]);
                                result <<= 32;
                                result |= (tmp[success_lane_idx].wrapping_add(this.prefix_state[i]))
                                    as u128;
                            }

                            debug_assert!(result > (target as u128) << 96, "result is too small");

                            return Some((nonce + this.nonce_addend, result));
                        }
                    }
                }
            }
            None
        }

        macro_rules! dispatch {
            ($idx0:ty) => {
                match lane_id_1_word_idx {
                    0 => solve_inner::<$idx0, U0>(self, target[0]),
                    1 => solve_inner::<$idx0, U1>(self, target[0]),
                    2 => solve_inner::<$idx0, U2>(self, target[0]),
                    3 => solve_inner::<$idx0, U3>(self, target[0]),
                    4 => solve_inner::<$idx0, U4>(self, target[0]),
                    5 => solve_inner::<$idx0, U5>(self, target[0]),
                    6 => solve_inner::<$idx0, U6>(self, target[0]),
                    7 => solve_inner::<$idx0, U7>(self, target[0]),
                    8 => solve_inner::<$idx0, U8>(self, target[0]),
                    9 => solve_inner::<$idx0, U9>(self, target[0]),
                    10 => solve_inner::<$idx0, U10>(self, target[0]),
                    11 => solve_inner::<$idx0, U11>(self, target[0]),
                    12 => solve_inner::<$idx0, U12>(self, target[0]),
                    13 => solve_inner::<$idx0, U13>(self, target[0]),
                    14 => solve_inner::<$idx0, U14>(self, target[0]),
                    15 => solve_inner::<$idx0, U15>(self, target[0]),
                    _ => unreachable_unchecked(),
                }
            };
        }

        unsafe {
            match lane_id_0_word_idx {
                0 => dispatch!(U0),
                1 => dispatch!(U1),
                2 => dispatch!(U2),
                3 => dispatch!(U3),
                4 => dispatch!(U4),
                5 => dispatch!(U5),
                6 => dispatch!(U6),
                7 => dispatch!(U7),
                8 => dispatch!(U8),
                9 => dispatch!(U9),
                10 => dispatch!(U10),
                11 => dispatch!(U11),
                12 => dispatch!(U12),
                13 => dispatch!(U13),
                14 => dispatch!(U14),
                15 => dispatch!(U15),
                _ => unreachable_unchecked(),
            }
        }
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
            const DIFFICULTY: u32 = 50_000;

            let solver = SingleBlockSolver::new((), &concatenated_prefix);
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
