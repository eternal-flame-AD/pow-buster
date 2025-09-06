#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![doc = include_str!("../README.md")]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[cfg(target_arch = "wasm32")]
use core::arch::wasm32::*;

#[cfg(feature = "wasm-bindgen")]
use wasm_bindgen::prelude::*;

use core::num::NonZeroU8;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "client")]
/// Web client for solving mCaptcha PoW
pub mod client;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "wasm-bindgen")]
mod wasm_ffi;

/// String manipulation functions
mod strings;

/// SHA-256 primitives
mod sha256;

/// Implementations considered "safe" for production use
pub mod safe;

#[cfg(feature = "adapter")]
mod adapter;

#[cfg(all(not(doc), not(target_arch = "x86_64"), not(target_arch = "wasm32")))]
compile_error!("Only x86_64 and wasm32 are supported");

#[cfg(all(not(doc), target_arch = "wasm32", feature = "compare-64bit"))]
compile_error!("compare-64bit is only supported on x86_64 architectures");

#[cfg(all(
    not(doc),
    target_arch = "x86_64",
    not(feature = "ignore-target-feature-checks"),
    not(any(target_feature = "avx512f", target_feature = "sha"))
))]
compile_error!(concat!(
    "AVX512F or SHA is required for performance. Compile with -Ctarget-feature=+avx512f or -Ctarget-feature=+sha, ",
    "alternatively pass --features ignore-target-feature-checks to build a slow reference implementation."
));

#[cfg(all(
    not(doc),
    target_arch = "wasm32",
    not(feature = "ignore-target-feature-checks"),
    not(target_feature = "simd128")
))]
compile_error!(concat!(
    "SIMD128 extensions required. Compile with -Ctarget-feature=+simd128, ",
    "alternatively pass --features ignore-target-feature-checks to build a slow reference implementation."
));

#[repr(align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Align16<T>(T);

impl<T> core::ops::Deref for Align16<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> core::ops::DerefMut for Align16<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[repr(align(64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Align64<T>(T);

//Ref downcast to Align16
impl<'a, T> Into<&'a Align16<T>> for &'a Align64<T> {
    fn into(self) -> &'a Align16<T> {
        unsafe { core::mem::transmute(self) }
    }
}

//Ref downcast to Align16
impl<'a, T> Into<&'a mut Align16<T>> for &'a mut Align64<T> {
    fn into(self) -> &'a mut Align16<T> {
        unsafe { core::mem::transmute(self) }
    }
}

impl<T> core::ops::Deref for Align64<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> core::ops::DerefMut for Align64<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cold]
fn unlikely() {}

#[cfg(feature = "wasm-bindgen")]
#[wasm_bindgen]
pub fn prefix_offset_to_lane_position(offset: usize) -> usize {
    PREFIX_OFFSET_TO_LANE_POSITION[offset]
}

const PREFIX_OFFSET_TO_LANE_POSITION: [usize; 64] = [
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9, 9,
    8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 13, 13, 13, 13, 13, 13, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1,
];

const SWAP_DWORD_BYTE_ORDER: [usize; 64] = [
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 19, 18, 17, 16, 23, 22, 21, 20, 27, 26,
    25, 24, 31, 30, 29, 28, 35, 34, 33, 32, 39, 38, 37, 36, 43, 42, 41, 40, 47, 46, 45, 44, 51, 50,
    49, 48, 55, 54, 53, 52, 59, 58, 57, 56, 63, 62, 61, 60,
];

static LANE_ID_MSB_STR: Align16<[u8; 5 * 16]> =
    Align16(*b"11111111112222222222333333333344444444445555555555666666666677777777778888888888");

static LANE_ID_LSB_STR: Align16<[u8; 5 * 16]> =
    Align16(*b"01234567890123456789012345678901234567890123456789012345678901234567890123456789");

#[cfg(feature = "compare-64bit")]
const INDEX_REMAP_PUNPCKLDQ: [usize; 16] = [0, 1, 4, 5, 8, 9, 12, 13, 2, 3, 6, 7, 10, 11, 14, 15];

#[inline(always)]
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
fn load_lane_id_epi32(src: &Align16<[u8; 5 * 16]>, set_idx: usize) -> __m512i {
    debug_assert!(set_idx < 5);
    unsafe { _mm512_cvtepi8_epi32(_mm_load_si128(src.as_ptr().add(set_idx * 16).cast())) }
}

#[inline(always)]
#[cfg(target_arch = "wasm32")]
fn load_lane_id_epi32(src: &Align16<[u8; 5 * 16]>, set_idx: usize) -> v128 {
    unsafe {
        u32x4(
            src[set_idx * 4] as _,
            src[set_idx * 4 + 1] as _,
            src[set_idx * 4 + 2] as _,
            src[set_idx * 4 + 3] as _,
        )
    }
}

pub fn build_prefix<E: Extend<u8>>(out: &mut E, string: &str, salt: &str) {
    out.extend(salt.as_bytes().iter().copied());
    out.extend((string.len() as u64).to_le_bytes());
    out.extend(string.as_bytes().iter().copied());
}

pub const fn decompose_blocks(inp: &[u32; 16]) -> &[u8; 64] {
    unsafe { core::mem::transmute(inp) }
}

pub const fn decompose_blocks_mut(inp: &mut [u32; 16]) -> &mut [u8; 64] {
    unsafe { core::mem::transmute(inp) }
}

/// Compute the target for an mCaptcha PoW
pub const fn compute_target(difficulty_factor: u32) -> u128 {
    u128::MAX - u128::MAX / difficulty_factor as u128
}

/// Compute the target for an Anubis PoW
pub const fn compute_target_anubis(difficulty_factor: NonZeroU8) -> u128 {
    1u128 << (128 - difficulty_factor.get() * 4)
}

/// Compute the target for a GoAway PoW
pub const fn compute_target_goaway(difficulty_factor: NonZeroU8) -> u128 {
    1u128 << (128 - difficulty_factor.get())
}

/// Extract top 128 bits from a 64-bit word array
pub const fn extract128_be(inp: [u32; 8]) -> u128 {
    (inp[0] as u128) << 96 | (inp[1] as u128) << 64 | (inp[2] as u128) << 32 | (inp[3] as u128)
}

pub const fn is_supported_lane_position(lane_position: usize) -> bool {
    match lane_position {
        0 => cfg!(feature = "lane-position-0"),
        1 => cfg!(feature = "lane-position-1"),
        2 => cfg!(feature = "lane-position-2"),
        3 => cfg!(feature = "lane-position-3"),
        4 => cfg!(feature = "lane-position-4"),
        5 => cfg!(feature = "lane-position-5"),
        6 => cfg!(feature = "lane-position-6"),
        7 => cfg!(feature = "lane-position-7"),
        8 => cfg!(feature = "lane-position-8"),
        9 => cfg!(feature = "lane-position-9"),
        10 => cfg!(feature = "lane-position-10"),
        11 => cfg!(feature = "lane-position-11"),
        12 => cfg!(feature = "lane-position-12"),
        13 => cfg!(feature = "lane-position-13"),
        14 => cfg!(feature = "lane-position-14"),
        15 => cfg!(feature = "lane-position-15"),
        _ => false,
    }
}

#[cfg(feature = "wasm-bindgen")]
#[wasm_bindgen(js_name = "is_supported_lane_position")]
pub fn is_supported_lane_position_wasm(lane_position: usize) -> bool {
    is_supported_lane_position(lane_position)
}

/// Encode a sha-256 hash into hex
pub fn encode_hex(out: &mut [u8; 64], inp: [u32; 8]) {
    for w in 0..8 {
        let be_bytes = inp[w].to_be_bytes();
        be_bytes.iter().enumerate().for_each(|(i, b)| {
            let high_nibble = b >> 4;
            let low_nibble = b & 0xf;
            out[w * 8 + i * 2] = if high_nibble < 10 {
                high_nibble + b'0'
            } else {
                high_nibble + b'a' - 10
            };
            out[w * 8 + i * 2 + 1] = if low_nibble < 10 {
                low_nibble + b'0'
            } else {
                low_nibble + b'a' - 10
            };
        });
    }
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

    // if possible, switch to a new search space
    // returns false when there are no more search spaces available
    fn next_search_space(&mut self) -> bool {
        false
    }

    // returns a valid nonce and "result" value
    //
    // mCaptcha uses an upwards comparison, Anubis uses a downwards comparison
    //
    // returns None when the solver cannot solve the prefix
    // failure is usually because the key space is exhausted (or presumed exhausted)
    // it should by design happen extremely rarely for common difficulty settings
    fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])>;

    // A dynamic dispatching wrapper for solve
    #[inline(never)]
    fn solve_dyn(&mut self, target: [u32; 4], upwards: bool) -> Option<(u64, [u32; 8])> {
        if upwards {
            self.solve::<true>(target)
        } else {
            self.solve::<false>(target)
        }
    }
}

// Solves an mCaptcha/Anubis SHA256 PoW where the SHA-256 message is a single block (512 bytes minus padding).
//
// Construct: Proof := (prefix || ASCII_DECIMAL(nonce))
//
// There is currently no AVX2 fallback for more common hardware
#[derive(Debug, Clone)]
pub struct SingleBlockSolver {
    // the message template for the final block
    message: Align64<[u32; 16]>,

    // the SHA-256 state A-H for all prefix bytes
    prefix_state: [u32; 8],

    digit_index: usize,

    nonce_addend: u64,

    attempted_nonces: u64,

    limit: u64,
}

impl SingleBlockSolver {
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    pub fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }
}

impl Solver for SingleBlockSolver {
    type Ctx = ();

    fn new(_ctx: Self::Ctx, mut prefix: &[u8]) -> Option<Self> {
        // construct the message buffer
        let mut prefix_state = sha256::IV;
        let mut nonce_addend = 0u64;
        let mut complete_blocks_before = 0;

        // first consume all full blocks, this is shared so use scalar reference implementation
        while prefix.len() >= 64 {
            sha256::digest_block(
                &mut prefix_state,
                &core::array::from_fn(|i| {
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

        let mut is_fitst_digit = true;
        let mut pop_padding_digit = || {
            if is_fitst_digit {
                is_fitst_digit = false;
                1u8
            } else {
                0u8
            }
        };

        // greedy padding logic

        // priority 0: if there is not enough room for 9 bytes of padding, pad with '1's and then start a new block whenever possible
        // this avoids having to hash 2 blocks per iteration a naive solution would do
        if prefix.len() + 9 + 9 > 64 {
            let mut tmp_block = [0; 64];
            tmp_block[..prefix.len()].copy_from_slice(prefix);
            tmp_block[prefix.len()..].iter_mut().for_each(|b| {
                let pad = pop_padding_digit();
                nonce_addend *= 10;
                nonce_addend += pad as u64;
                *b = b'0' + pad;
            });
            nonce_addend.checked_mul(1_000_000_000)?; // make sure we still have enough headroom
            complete_blocks_before += 1;
            prefix = &[];
            sha256::digest_block(
                &mut prefix_state,
                &core::array::from_fn(|i| {
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

        // we used to not do these more subtle optimizations as it is not typical for mCaptcha
        // but all Anubis deployments start at offset 0, so there is very good incentive to micro-optimize
        if ptr < 32 {
            // priority 1: try to pad to an even position to minimize the need to poke 2 words for the lane ID
            if ptr % 2 == 1 {
                if nonce_addend.checked_mul(10_000_000_000 * 2).is_some() {
                    nonce_addend *= 10;
                    let pad = pop_padding_digit();
                    nonce_addend += pad as u64;
                    message[ptr] = b'0' + pad;
                    ptr += 1;
                }
            }
            // priority 2: try to pad such that the inner nonce is at a register boundary and PSHUFD shortcut can be used (minus the lane ID)
            while (ptr + 2) % 4 != 0 {
                if nonce_addend.checked_mul(10_000_000_000 * 2).is_some() {
                    nonce_addend *= 10;
                    let pad = pop_padding_digit();
                    nonce_addend += pad as u64;
                    message[ptr] = b'0' + pad;
                    ptr += 1;
                } else {
                    break;
                }
            }
            // priority 3: try to move the mutating part into later part of the final block to skim a couple rounds
            // times 2 because for some reason anubis uses signed nonces ... I wonder if we can send negative nonces
            while nonce_addend
                .checked_mul(10000 * 1_000_000_000 * 2)
                .is_some()
            {
                let pad0 = pop_padding_digit();
                let pad1 = pop_padding_digit();
                let pad2 = pop_padding_digit();
                let pad3 = pop_padding_digit();
                nonce_addend *= 10000;
                nonce_addend +=
                    pad0 as u64 * 1000 + pad1 as u64 * 100 + pad2 as u64 * 10 + pad3 as u64;
                message[ptr] = b'0' + pad0;
                message[ptr + 1] = b'0' + pad1;
                message[ptr + 2] = b'0' + pad2;
                message[ptr + 3] = b'0' + pad3;
                ptr += 4;
            }
        }
        // a double block solver must be used because not enough digits can bridge the 9 byte overhead
        nonce_addend = nonce_addend.checked_mul(1_000_000_000)?;

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

        if !is_supported_lane_position(digit_index / 4) {
            return None;
        }

        Some(Self {
            message: Align64(core::array::from_fn(|i| {
                u32::from_be_bytes([
                    message[i * 4],
                    message[i * 4 + 1],
                    message[i * 4 + 2],
                    message[i * 4 + 3],
                ])
            })),
            prefix_state,
            digit_index,
            nonce_addend,
            attempted_nonces: 0,
            limit: u64::MAX,
        })
    }

    fn next_search_space(&mut self) -> bool {
        if self.digit_index == 0 || self.nonce_addend == 0 {
            return false;
        }

        self.nonce_addend = match self.nonce_addend.checked_add(1_000_000_000) {
            Some(nonce_addend) => nonce_addend,
            None => return false,
        };

        let mut addend_copy = self.nonce_addend / 1_000_000_000;
        let mut i = self.digit_index - 1;
        let mut last_digit = 0;
        while addend_copy > 0 {
            let idx = SWAP_DWORD_BYTE_ORDER[i];

            let message = decompose_blocks_mut(&mut self.message);
            last_digit = (addend_copy % 10) as u8;
            addend_copy /= 10;
            message[idx] = b'0' + last_digit;
            if i > 0 {
                i -= 1;
            } else {
                break;
            }
        }

        // make sure no carry propagates to blocks that are already committed
        while addend_copy > 0 {
            last_digit = (addend_copy % 10) as u8;
            addend_copy /= 10;
            if last_digit != 0 {
                break;
            }
        }
        last_digit == 1 && addend_copy == 0
    }

    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))] {
            #[inline(never)]
            fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
                // the official default difficulty is 5e6, so we design for 1e8
                // and there should almost always be a valid solution within our supported solution space
                // pgeom(5 * 16e7, 1/5e7, lower=F) = 0.03%
                // pgeom(16e7, 1/5e7, lower=F) = 20%, which is too much so we need the prefix to change as well

                // pre-compute an OR to apply to the message to add the lane ID
                let lane_id_0_word_idx = self.digit_index / 4;
                if !is_supported_lane_position(lane_id_0_word_idx) {
                    return None;
                }
                let lane_id_1_word_idx = (self.digit_index + 1) / 4;

                // zero out the nonce portion to prevent incorrect results if solvers are reused
                for i in (self.digit_index..).take(9) {
                    let message = decompose_blocks_mut(&mut self.message);
                    message[SWAP_DWORD_BYTE_ORDER[i]] = b'0';
                }

                // make sure there are no runtime "register indexing" logic
                fn solve_inner<
                    const DIGIT_WORD_IDX0: usize,
                    const DIGIT_WORD_IDX1_INCREMENT: bool,
                    const UPWARDS: bool,
                    const ON_REGISTER_BOUNDARY: bool,
                >(
                    this: &mut SingleBlockSolver,
                    #[cfg(not(feature = "compare-64bit"))]
                    target: u32,
                    #[cfg(feature = "compare-64bit")]
                    target: u64,
                ) -> Option<u64> {
                    let mut partial_state = this.prefix_state;
                    sha256::ingest_message_prefix::<DIGIT_WORD_IDX0>(
                        &mut partial_state,
                        core::array::from_fn(|i| this.message[i]),
                    );

                    let mut remaining_limit = this.limit.saturating_sub(this.attempted_nonces);
                    if remaining_limit == 0 {
                        return None;
                    }

                    let lane_id_0_byte_idx = this.digit_index % 4;
                    let lane_id_1_byte_idx = (this.digit_index + 1) % 4;
                    let mut inner_key_buf = Align16(*b"0000\x80000");
                    for prefix_set_index in 0..5 {
                        unsafe {
                            let lane_id_0_or_value = _mm512_sll_epi32(
                                load_lane_id_epi32(&LANE_ID_MSB_STR, prefix_set_index),
                                _mm_set1_epi64x(((3 - lane_id_0_byte_idx) * 8) as _),
                            );
                            let lane_id_1_or_value = _mm512_sll_epi32(
                                load_lane_id_epi32(&LANE_ID_LSB_STR, prefix_set_index),
                                _mm_set1_epi64x(((3 - lane_id_1_byte_idx) * 8) as _),
                            );

                            let lane_id_0_or_value_v = if !DIGIT_WORD_IDX1_INCREMENT {
                                _mm512_or_epi32(lane_id_0_or_value, lane_id_1_or_value)
                            } else {
                                lane_id_0_or_value
                            };

                            let inner_iteration_end = if remaining_limit < 10_000_000 { remaining_limit as u32 } else { 10_000_000 };
                            remaining_limit -= inner_iteration_end as u64;

                            // soft pipeline this to compute the new message after the hash
                            // LLVM seems to handle cases where high register pressure work happens first better
                            // so this prevents some needless register spills
                            // doesn't seem to affect performance on my Zen4 but dirty so avoid
                            // on the last iteration simd_itoa(10_000_000) is unit-tested to convert to 0000\x80000
                            // so no fixup is needed-saves a branch on LLVM codegen
                            for next_inner_key in 1..=inner_iteration_end {
                                macro_rules! fetch_msg {
                                    ($idx:expr) => {
                                        if $idx == DIGIT_WORD_IDX0 {
                                            _mm512_or_epi32(
                                                _mm512_set1_epi32(this.message[$idx] as _),
                                                lane_id_0_or_value_v,
                                            )
                                        } else if DIGIT_WORD_IDX1_INCREMENT && $idx == DIGIT_WORD_IDX0 + 1 {
                                            _mm512_or_epi32(
                                                _mm512_set1_epi32(this.message[$idx] as _),
                                                lane_id_1_or_value,
                                            )
                                        } else if ON_REGISTER_BOUNDARY && $idx == DIGIT_WORD_IDX0 + 1 {
                                            _mm512_set1_epi32((inner_key_buf.as_ptr().cast::<u32>().read()) as _)
                                        } else if ON_REGISTER_BOUNDARY && $idx == DIGIT_WORD_IDX0 + 2 {
                                            _mm512_set1_epi32((inner_key_buf.as_ptr().add(4).cast::<u32>().read()) as _)
                                        } else {
                                            _mm512_set1_epi32(this.message[$idx] as _)
                                        }
                                    }
                                }
                                let mut blocks = [
                                    fetch_msg!(0),
                                    fetch_msg!(1),
                                    fetch_msg!(2),
                                    fetch_msg!(3),
                                    fetch_msg!(4),
                                    fetch_msg!(5),
                                    fetch_msg!(6),
                                    fetch_msg!(7),
                                    fetch_msg!(8),
                                    fetch_msg!(9),
                                    fetch_msg!(10),
                                    fetch_msg!(11),
                                    fetch_msg!(12),
                                    fetch_msg!(13),
                                    fetch_msg!(14),
                                    fetch_msg!(15),
                                ];

                                let mut state =
                                    core::array::from_fn(|i| _mm512_set1_epi32(partial_state[i] as _));

                                // do 16-way SHA-256 without feedback so as not to force the compiler to save 8 registers
                                // we already have them in scalar form, this allows more registers to be reused in the next iteration
                                sha256::avx512::multiway_arx::<DIGIT_WORD_IDX0>(&mut state, &mut blocks);

                                state[0] = _mm512_add_epi32(state[0], _mm512_set1_epi32(this.prefix_state[0] as _));

                                #[cfg(feature = "compare-64bit")]
                                {
                                    state[1] = _mm512_add_epi32(state[1], _mm512_set1_epi32(this.prefix_state[1] as _));
                                }

                                #[cfg(feature = "compare-64bit")]
                                let result_ab_lo = _mm512_unpacklo_epi32(state[1], state[0]);
                                #[cfg(feature = "compare-64bit")]
                                let result_ab_hi = _mm512_unpackhi_epi32(state[1], state[0]);

                                // the target is big endian interpretation of the first 16 bytes of the hash (A-D) >= target
                                // however, the largest 32-bit digits is unlikely to be all ones (otherwise a legitimate challenger needs on average >2^32 attempts)
                                // so we can reduce this into simply testing H[0]
                                // the number of acceptable u32 values (for us) is u32::MAX / difficulty
                                // so the "inefficiency" this creates is about (u32::MAX / difficulty) * (1 / 2), because for approx. half of the "edge case" do we actually have an acceptable solution,
                                // which for 1e8 is about 1%, but we get to save the one broadcast add,
                                // a vectorized comparison, and a scalar logic evaluation
                                // which I feel is about 1% of the instructions needed per iteration anyways just more registers used so let's not bother
                                //
                                // A 64-bit compare solution is provided for completeness but almost never needed for realistic challenges.

                                #[cfg(not(feature = "compare-64bit"))]
                                let cmp_fn = if UPWARDS {
                                    _mm512_cmpgt_epu32_mask
                                } else {
                                    _mm512_cmplt_epu32_mask
                                };

                                #[cfg(feature = "compare-64bit")]
                                let cmp64_fn = if UPWARDS {
                                    _mm512_cmpgt_epu64_mask
                                } else {
                                    _mm512_cmplt_epu64_mask
                                };

                                #[cfg(not(feature = "compare-64bit"))]
                                let met_target = cmp_fn(state[0], _mm512_set1_epi32(target as _));

                                #[cfg(feature = "compare-64bit")]
                                let met_target = {
                                    let ab_met_target_lo =
                                        cmp64_fn(result_ab_lo, _mm512_set1_epi64(target as _)) as u16;

                                    let ab_met_target_high =
                                        cmp64_fn(result_ab_hi, _mm512_set1_epi64(target as _)) as u16;

                                    ab_met_target_high << 8 | ab_met_target_lo
                                };

                                if met_target != 0 {
                                    unlikely();

                                    let success_lane_idx = _tzcnt_u16(met_target) as usize;

                                    // remap the indices according to unpacking order
                                    #[cfg(feature = "compare-64bit")]
                                    let success_lane_idx = INDEX_REMAP_PUNPCKLDQ[success_lane_idx];

                                    let nonce_prefix = 10 + 16 * prefix_set_index + success_lane_idx;

                                    if ON_REGISTER_BOUNDARY {
                                        this.message[DIGIT_WORD_IDX0 + 1] = inner_key_buf.as_ptr().cast::<u32>().read();
                                        this.message[DIGIT_WORD_IDX0 + 2] = inner_key_buf.as_ptr().add(4).cast::<u32>().read();
                                    }

                                    // stamp the lane ID back onto the message
                                    {
                                        let message_bytes = decompose_blocks_mut(&mut this.message);
                                        *message_bytes.get_unchecked_mut(
                                            *SWAP_DWORD_BYTE_ORDER.get_unchecked(this.digit_index),
                                        ) = (nonce_prefix / 10) as u8 + b'0';
                                        *message_bytes.get_unchecked_mut(
                                            *SWAP_DWORD_BYTE_ORDER.get_unchecked(this.digit_index + 1),
                                        ) = (nonce_prefix % 10) as u8 + b'0';
                                    }

                                    // the nonce is the 7 digits in the message, plus the first two digits recomputed from the lane index
                                    return Some(nonce_prefix as u64 * 10u64.pow(7) + next_inner_key as u64 - 1);
                                }

                                this.attempted_nonces += 1;

                                if ON_REGISTER_BOUNDARY {
                                    strings::simd_itoa8::<7, true, 0x80>(&mut inner_key_buf, next_inner_key);
                                } else {
                                    let message_bytes = decompose_blocks_mut(&mut this.message);
                                    let mut key_copy = next_inner_key;

                                    for i in (0..7).rev() {
                                        let output = key_copy % 10;
                                        key_copy /= 10;
                                        *message_bytes.get_unchecked_mut(
                                            *SWAP_DWORD_BYTE_ORDER.get_unchecked(this.digit_index + i + 2),
                                        ) = output as u8 + b'0';
                                    }

                                    // hint at LLVM that the modulo ends in 0
                                    if key_copy != 0 {
                                        debug_assert_eq!(key_copy, 0);
                                        core::hint::unreachable_unchecked();
                                    }
                                }
                            }
                        }
                    }

                    unlikely();
                    None
                }

                #[cfg(not(feature = "compare-64bit"))]
                let compact_target = target[0];

                #[cfg(feature = "compare-64bit")]
                let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

                macro_rules! dispatch {
                    ($idx0:literal, $idx1_inc:literal) => {
                        if self.digit_index % 4 == 2 {
                            solve_inner::<$idx0, $idx1_inc, UPWARDS, true>(self, compact_target)
                        } else {
                            solve_inner::<$idx0, $idx1_inc, UPWARDS, false>(self, compact_target)
                        }
                    };
                    ($idx0:literal) => {
                        if lane_id_0_word_idx == lane_id_1_word_idx {
                            dispatch!($idx0, false)
                        } else {
                            dispatch!($idx0, true)
                        }
                    };
                }

                let nonce = loop {
                    unsafe {
                        match match lane_id_0_word_idx {
                            0 => dispatch!(0),
                            1 => dispatch!(1),
                            2 => dispatch!(2),
                            3 => dispatch!(3),
                            4 => dispatch!(4),
                            5 => dispatch!(5),
                            6 => dispatch!(6),
                            7 => dispatch!(7),
                            8 => dispatch!(8),
                            9 => dispatch!(9),
                            10 => dispatch!(10),
                            11 => dispatch!(11),
                            12 => dispatch!(12),
                            13 => dispatch!(13),
                            _ => core::hint::unreachable_unchecked(),
                        } {
                            Some(nonce) => break nonce,
                            None => if !self.next_search_space() {
                                return None;
                            },
                        }
                    }
                };

                self.attempted_nonces *= 16;

                // recompute the hash from the beginning
                // this prevents the compiler from having to compute the final B-H registers alive in tight loops
                let mut final_sha_state = self.prefix_state;
                sha256::digest_block(&mut final_sha_state, &self.message);

                Some((nonce + self.nonce_addend, final_sha_state))
            }
        } else if #[cfg(all(target_arch = "x86_64", target_feature = "sha"))] {
            #[inline(never)]
            fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
                let lane_id_0_word_idx = self.digit_index / 4;
                if !is_supported_lane_position(lane_id_0_word_idx) {
                    return None;
                }

                for i in (self.digit_index as usize..).take(9) {
                    let message = decompose_blocks_mut(&mut self.message);
                    message[SWAP_DWORD_BYTE_ORDER[i]] = b'0';
                }

                let lane_id_1_word_idx = (self.digit_index + 1) / 4;

                fn solve_inner<
                    const DIGIT_WORD_IDX0_DIV_4_TIMES_4: usize,
                    const DIGIT_WORD_IDX0_DIV_4: usize,
                    const DIGIT_WORD_IDX0_MOD_4: usize,
                    const DIGIT_WORD_IDX1: usize,
                    const UPWARDS: bool,
                >(
                    this: &mut SingleBlockSolver,
                    target: u64,
                ) -> Option<u64> {
                    let mut partial_state = Align16(this.prefix_state);
                    sha256::ingest_message_prefix::<{ DIGIT_WORD_IDX0_DIV_4_TIMES_4 }>(
                        &mut partial_state,
                        core::array::from_fn(|i| this.message[i]),
                    );
                    let prepared_state = sha256::sha_ni::prepare_state(&partial_state);
                    let lane_id_0_byte_idx = this.digit_index % 4;
                    let lane_id_1_byte_idx = (this.digit_index + 1) % 4;

                    // move AB into position for feedback
                    let feedback_ab = unsafe {
                        let lows = _mm_cvtsi64x_si128(((this.prefix_state[0] as u64) << 32 | this.prefix_state[1] as u64) as _);

                        _mm_shuffle_epi32(lows, 0b01001010)
                    };

                    for nonce_prefix_start in (10u32..=96).step_by(4) {
                        unsafe {
                            const fn to_ascii_u32(input: u32) -> u32 {
                                let high_digit = input / 10;
                                let low_digit = input % 10;
                                u32::from_be_bytes([0, 0, high_digit as u8 + b'0', low_digit as u8 + b'0'])
                            }
                            let lane_index_values = [
                                to_ascii_u32(nonce_prefix_start),
                                to_ascii_u32(nonce_prefix_start + 1),
                                to_ascii_u32(nonce_prefix_start + 2),
                                to_ascii_u32(nonce_prefix_start + 3),
                            ];

                            let lane_id_1_or_value = core::array::from_fn(|i| {
                                (lane_index_values[i] & 0xff) << ((3 - lane_id_1_byte_idx) * 8)
                            });

                            let lane_id_0_or_value = core::array::from_fn(|i| {
                                let mut r = (lane_index_values[i] >> 8) << ((3 - lane_id_0_byte_idx) * 8);
                                if DIGIT_WORD_IDX0_DIV_4 * 4 + DIGIT_WORD_IDX0_MOD_4 == DIGIT_WORD_IDX1 {
                                    r |= lane_id_1_or_value[i]
                                }
                                r
                            });

                            struct LaneIdPlucker<
                                'a,
                                const DIGIT_WORD_IDX0_DIV_4: usize,
                                const DIGIT_WORD_IDX0_MOD_4: usize,
                                const DIGIT_WORD_IDX1: usize,
                            > {
                                lane_0_or_value: &'a [u32; 4],
                                lane_1_or_value: &'a [u32; 4],
                            }

                            impl<
                                'a,
                                const DIGIT_WORD_IDX0_DIV_4: usize,
                                const DIGIT_WORD_IDX0_MOD_4: usize,
                                const DIGIT_WORD_IDX1: usize,
                            >
                                LaneIdPlucker<
                                    'a,
                                    DIGIT_WORD_IDX0_DIV_4,
                                    DIGIT_WORD_IDX0_MOD_4,
                                    DIGIT_WORD_IDX1,
                                >
                            {
                                #[inline(always)]
                                fn fetch_msg_or(&self, idx: usize, lane: usize) -> u32 {
                                    if idx == DIGIT_WORD_IDX0_DIV_4 * 4 + DIGIT_WORD_IDX0_MOD_4 {
                                        self.lane_0_or_value[lane]
                                    } else if idx == DIGIT_WORD_IDX1 {
                                        self.lane_1_or_value[lane]
                                    } else {
                                        0
                                    }
                                }
                            }

                            impl<
                                'a,
                                const DIGIT_WORD_IDX0_DIV_4: usize,
                                const DIGIT_WORD_IDX0_MOD_4: usize,
                                const DIGIT_WORD_IDX1: usize,
                            > sha256::sha_ni::Plucker
                                for LaneIdPlucker<
                                    'a,
                                    DIGIT_WORD_IDX0_DIV_4,
                                    DIGIT_WORD_IDX0_MOD_4,
                                    DIGIT_WORD_IDX1,
                                >
                            {
                                #[inline(always)]
                                fn pluck_qword0(&mut self, lane: usize, w: &mut __m128i) {
                                    unsafe {
                                        *w = _mm_or_si128(
                                            *w,
                                            _mm_setr_epi32(
                                                self.fetch_msg_or(0, lane) as _,
                                                self.fetch_msg_or(1, lane) as _,
                                                self.fetch_msg_or(2, lane) as _,
                                                self.fetch_msg_or(3, lane) as _,
                                            ),
                                        );
                                    }
                                }
                                #[inline(always)]
                                fn pluck_qword1(&mut self, lane: usize, w: &mut __m128i) {
                                    unsafe {
                                        *w = _mm_or_si128(
                                            *w,
                                            _mm_setr_epi32(
                                                self.fetch_msg_or(4, lane) as _,
                                                self.fetch_msg_or(5, lane) as _,
                                                self.fetch_msg_or(6, lane) as _,
                                                self.fetch_msg_or(7, lane) as _,
                                            ),
                                        );
                                    }
                                }
                                #[inline(always)]
                                fn pluck_qword2(&mut self, lane: usize, w: &mut __m128i) {
                                    unsafe {
                                        *w = _mm_or_si128(
                                            *w,
                                            _mm_setr_epi32(
                                                self.fetch_msg_or(8, lane) as _,
                                                self.fetch_msg_or(9, lane) as _,
                                                self.fetch_msg_or(10, lane) as _,
                                                self.fetch_msg_or(11, lane) as _,
                                            ),
                                        );
                                    }
                                }
                                #[inline(always)]
                                fn pluck_qword3(&mut self, lane: usize, w: &mut __m128i) {
                                    unsafe {
                                        *w = _mm_or_si128(
                                            *w,
                                            _mm_setr_epi32(
                                                self.fetch_msg_or(12, lane) as _,
                                                self.fetch_msg_or(13, lane) as _,
                                                self.fetch_msg_or(14, lane) as _,
                                                self.fetch_msg_or(15, lane) as _,
                                            ),
                                        );
                                    }
                                }
                            }

                            for inner_key in 0..10_000_000 {
                                let mut key_copy = inner_key;
                                {
                                    let message_bytes = decompose_blocks_mut(&mut this.message);

                                    for i in (0..7).rev() {
                                        let output = key_copy % 10;
                                        key_copy /= 10;
                                        *message_bytes.get_unchecked_mut(
                                            *SWAP_DWORD_BYTE_ORDER.get_unchecked(this.digit_index + i + 2),
                                        ) = output as u8 + b'0';
                                    }
                                }

                                let mut state0 = prepared_state;
                                let mut state1 = prepared_state;
                                let mut state2 = prepared_state;
                                let mut state3 = prepared_state;

                                sha256::sha_ni::multiway_arx_abef_cdgh::<{ DIGIT_WORD_IDX0_DIV_4 }, 4, _>(
                                    [&mut state0, &mut state1, &mut state2, &mut state3],
                                    (&this.message).into(),
                                    LaneIdPlucker::<
                                        DIGIT_WORD_IDX0_DIV_4,
                                        DIGIT_WORD_IDX0_MOD_4,
                                        DIGIT_WORD_IDX1,
                                    > {
                                        lane_0_or_value: &lane_id_0_or_value,
                                        lane_1_or_value: &lane_id_1_or_value,
                                    },
                                );

                                // paddd is basically free on modern CPUs so do the feedback uncondtionally
                                state0[0] = _mm_add_epi32(state0[0], feedback_ab);
                                state1[0] = _mm_add_epi32(state1[0], feedback_ab);
                                state2[0] = _mm_add_epi32(state2[0], feedback_ab);
                                state3[0] = _mm_add_epi32(state3[0], feedback_ab);

                                let success_lane_idx = {
                                    let result_abs = [
                                        _mm_extract_epi64(state0[0], 1) as u64,
                                        _mm_extract_epi64(state1[0], 1) as u64,
                                        _mm_extract_epi64(state2[0], 1) as u64,
                                        _mm_extract_epi64(state3[0], 1) as u64,
                                    ];

                                    result_abs
                                        .iter()
                                        .position(|x| if UPWARDS { *x > target } else { *x < target })
                                };

                                if let Some(success_lane_idx) = success_lane_idx {
                                    unlikely();

                                    let nonce_prefix = nonce_prefix_start + success_lane_idx as u32;

                                    // stamp the lane ID back onto the message
                                    {
                                        let message_bytes = decompose_blocks_mut(&mut this.message);
                                        *message_bytes.get_unchecked_mut(
                                            *SWAP_DWORD_BYTE_ORDER.get_unchecked(this.digit_index),
                                        ) = (nonce_prefix / 10) as u8 + b'0';
                                        *message_bytes.get_unchecked_mut(
                                            *SWAP_DWORD_BYTE_ORDER.get_unchecked(this.digit_index + 1),
                                        ) = (nonce_prefix % 10) as u8 + b'0';
                                    }

                                    return Some(nonce_prefix as u64 * 10u64.pow(7) + inner_key);
                                }

                                this.attempted_nonces += 4;
                                if this.attempted_nonces >= this.limit {
                                    return None;
                                }
                            }
                        }
                    }
                    None
                }

                let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

                macro_rules! dispatch {
                    ($idx0_0:literal, $idx0_1:literal, $idx0_2:literal) => {
                        match lane_id_1_word_idx {
                            0 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 0, UPWARDS>(
                                self, compact_target,
                            ),
                            1 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 1, UPWARDS>(
                                self, compact_target,
                            ),
                            2 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 2, UPWARDS>(
                                self, compact_target,
                            ),
                            3 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 3, UPWARDS>(
                                self, compact_target,
                            ),
                            4 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 4, UPWARDS>(
                                self, compact_target,
                            ),
                            5 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 5, UPWARDS>(
                                self, compact_target,
                            ),
                            6 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 6, UPWARDS>(
                                self, compact_target,
                            ),
                            7 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 7, UPWARDS>(
                                self, compact_target,
                            ),
                            8 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 8, UPWARDS>(
                                self, compact_target,
                            ),
                            9 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 9, UPWARDS>(
                                self, compact_target,
                            ),
                            10 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 10, UPWARDS>(
                                self, compact_target,
                            ),
                            11 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 11, UPWARDS>(
                                self, compact_target,
                            ),
                            12 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 12, UPWARDS>(
                                self, compact_target,
                            ),
                            13 => solve_inner::<{ $idx0_0 }, { $idx0_1 }, { $idx0_2 }, 13, UPWARDS>(
                                self, compact_target,
                            ),
                            _ => core::hint::unreachable_unchecked(),
                        }
                    };
                }

                let nonce = loop {
                    unsafe {
                        match match lane_id_0_word_idx {
                            0 => dispatch!(0, 0, 0),
                            1 => dispatch!(0, 0, 1),
                            2 => dispatch!(0, 0, 2),
                            3 => dispatch!(0, 0, 3),
                            4 => dispatch!(4, 1, 0),
                            5 => dispatch!(4, 1, 1),
                            6 => dispatch!(4, 1, 2),
                            7 => dispatch!(4, 1, 3),
                            8 => dispatch!(8, 2, 0),
                            9 => dispatch!(8, 2, 1),
                            10 => dispatch!(8, 2, 2),
                            11 => dispatch!(8, 2, 3),
                            12 => dispatch!(12, 3, 0),
                            13 => dispatch!(12, 3, 1),
                            _ => core::hint::unreachable_unchecked(),
                        } {
                            Some(nonce) => break nonce,
                            None => if !self.next_search_space() {
                                return None;
                            },
                        }
                    }
                };

                let mut final_sha_state = self.prefix_state;
                sha256::digest_block(&mut final_sha_state, &self.message);

                Some((nonce + self.nonce_addend, final_sha_state))
            }
        } else if #[cfg(target_arch = "wasm32")] {
            #[inline(never)]
            fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
                let lane_id_0_word_idx = self.digit_index / 4;
                if !is_supported_lane_position(lane_id_0_word_idx) {
                    return None;
                }
                let lane_id_1_word_idx = (self.digit_index + 1) / 4;

                for i in (self.digit_index as usize..).take(9) {
                    let message = decompose_blocks_mut(&mut self.message);
                    message[SWAP_DWORD_BYTE_ORDER[i]] = b'0';
                }

                let mut hotstart_state = self.prefix_state;
                sha256::sha2_arx_slice::<0>(&mut hotstart_state, &self.message[..lane_id_0_word_idx]);

                fn solve_inner<
                    const LANE_ID_0_WORD_IDX: usize,
                    const LANE_ID_1_INCREMENT: bool,
                    const UPWARDS: bool,
                >(
                    this: &mut SingleBlockSolver,
                    hotstart_state: [u32; 8],
                    target: u32,
                ) -> Option<u64> {
                    unsafe {
                        let mut remaining_limit = this.limit.saturating_sub(this.attempted_nonces);
                        if remaining_limit == 0 {
                            return None;
                        }

                        let lane_id_0_byte_idx = this.digit_index % 4;
                        let lane_id_1_byte_idx = (this.digit_index + 1) % 4;

                        for prefix_set_index in 0..((100 - 10) / 4) {
                            let mut lane_id_0_or_value = u32x4_shl(
                                load_lane_id_epi32(&LANE_ID_MSB_STR, prefix_set_index),
                                ((3 - lane_id_0_byte_idx) * 8) as _,
                            );
                            let lane_id_1_or_value = u32x4_shl(
                                load_lane_id_epi32(&LANE_ID_LSB_STR, prefix_set_index),
                                ((3 - lane_id_1_byte_idx) * 8) as _,
                            );

                            if !LANE_ID_1_INCREMENT {
                                lane_id_0_or_value = v128_or(lane_id_1_or_value, lane_id_0_or_value);
                            }

                            for inner_key in 0..(10_000_000.min(this.limit.div_ceil(4))) {
                                {
                                    let message_bytes = decompose_blocks_mut(&mut this.message);
                                    let mut key_copy = inner_key;
                                    for i in (0..7).rev() {
                                        let output = key_copy % 10;
                                        key_copy /= 10;
                                        *message_bytes.get_unchecked_mut(
                                            *SWAP_DWORD_BYTE_ORDER.get_unchecked(this.digit_index + i + 2),
                                        ) = output as u8 + b'0';
                                    }

                                    if key_copy != 0 {
                                        debug_assert_eq!(key_copy, 0);
                                        core::hint::unreachable_unchecked();
                                    }
                                }

                                let mut blocks = core::array::from_fn(|i| u32x4_splat(this.message[i]));
                                blocks[LANE_ID_0_WORD_IDX] =
                                    v128_or(blocks[LANE_ID_0_WORD_IDX], lane_id_0_or_value);

                                if LANE_ID_1_INCREMENT {
                                    blocks[LANE_ID_0_WORD_IDX + LANE_ID_1_INCREMENT as usize] =
                                        v128_or(blocks[LANE_ID_0_WORD_IDX + LANE_ID_1_INCREMENT as usize], lane_id_1_or_value);
                                }

                                let mut state = core::array::from_fn(|i| u32x4_splat(hotstart_state[i]));
                                sha256::simd128::multiway_arx::<LANE_ID_0_WORD_IDX>(&mut state, &mut blocks);

                                let result_a = u32x4_add(state[0], u32x4_splat(this.prefix_state[0]));

                                let cmp_fn = if UPWARDS { u32x4_le } else { u32x4_ge };

                                let a_not_met_target = cmp_fn(result_a, u32x4_splat(target));

                                if !u32x4_all_true(a_not_met_target) {
                                    unlikely();

                                    let mut extract = [0u32; 4];
                                    v128_store(extract.as_mut_ptr().cast(), result_a);
                                    let success_lane_idx = extract
                                        .iter()
                                        .position(|x| {
                                            if UPWARDS {
                                                *x > target
                                            } else {
                                                *x < target
                                            }
                                        })
                                        .unwrap();
                                    let nonce_prefix = 10 + 4 * prefix_set_index + success_lane_idx;

                                    // stamp the lane ID back onto the message
                                    {
                                        let message_bytes = decompose_blocks_mut(&mut this.message);
                                        *message_bytes.get_unchecked_mut(
                                            *SWAP_DWORD_BYTE_ORDER.get_unchecked(this.digit_index),
                                        ) = (nonce_prefix / 10) as u8 + b'0';
                                        *message_bytes.get_unchecked_mut(
                                            *SWAP_DWORD_BYTE_ORDER.get_unchecked(this.digit_index + 1),
                                        ) = (nonce_prefix % 10) as u8 + b'0';
                                    }

                                    // the nonce is the 7 digits in the message, plus the first two digits recomputed from the lane index
                                    return Some(
                                        nonce_prefix as u64 * 10u64.pow(7) + inner_key as u64 + this.nonce_addend,
                                    );
                                }

                                this.attempted_nonces += 4;
                            }
                        }
                    }

                    None
                }


                macro_rules! dispatch {
                    ($idx0_words:literal) => {
                        if lane_id_0_word_idx == lane_id_1_word_idx {
                            solve_inner::<{ $idx0_words }, false, UPWARDS>(self, hotstart_state, target[0])
                        } else {
                            solve_inner::<{ $idx0_words }, true, UPWARDS>(self, hotstart_state, target[0])
                        }
                    };
                }

                let nonce = loop {
                    unsafe {
                        match match lane_id_0_word_idx {
                            0 => dispatch!(0),
                            1 => dispatch!(1),
                            2 => dispatch!(2),
                            3 => dispatch!(3),
                            4 => dispatch!(4),
                            5 => dispatch!(5),
                            6 => dispatch!(6),
                            7 => dispatch!(7),
                            8 => dispatch!(8),
                            9 => dispatch!(9),
                            10 => dispatch!(10),
                            11 => dispatch!(11),
                            12 => dispatch!(12),
                            13 => dispatch!(13),
                            _ => core::hint::unreachable_unchecked(),
                        } {
                            Some(nonce) => break nonce,
                            None => if !self.next_search_space() {
                                return None;
                            },
                        }
                    }
                };

                // recompute the hash from the beginning
                // this prevents the compiler from having to compute the final B-H registers alive in tight loops
                let mut final_sha_state = self.prefix_state;
                sha256::digest_block(&mut final_sha_state, &self.message);

                Some((nonce, final_sha_state))
            }
        } else {
            #[inline(never)]
            fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
                let mut buffer : sha2::digest::crypto_common::Block<sha2::Sha256> = Default::default();
                for i in 0..16 {
                    buffer[i*4..i*4+4].copy_from_slice(&self.message[i].to_be_bytes());
                }

                let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

                for key in (100_000_000..1_000_000_000).take(self.limit as usize) {
                    let mut key_copy = key;
                    for j in (0..9).rev() {
                        buffer[self.digit_index + j] = (key_copy % 10) as u8 + b'0';
                        key_copy /= 10;
                    }

                    let mut state = self.prefix_state;
                    sha2::compress256(&mut state, &[buffer]);

                    let state_ab = (state[0] as u64) << 32 | (state[1] as u64);

                    let cmp_fn = if UPWARDS { u64::gt } else { u64::lt };

                    if cmp_fn(&state_ab, &compact_target) {
                        unlikely();

                        return Some((key + self.nonce_addend, state));
                    }
                    self.limit -= 1;
                }

                if !self.next_search_space() {
                    return None;
                }

                self.solve::<UPWARDS>(target)
            }
        }
    }
}

/// Solver for double SHA-256 cases
///
/// It has slightly better than half throughput than the single block solver, but you should use the single block solver if possible
pub struct DoubleBlockSolver {
    pub(crate) message_length: u64,

    pub(crate) nonce_addend: u64,

    attempted_nonces: u64,

    limit: u64,

    // the SHA-256 state A-H for all prefix bytes
    pub(crate) prefix_state: Align16<[u32; 8]>,

    // the message template for the final block
    pub(crate) message: Align64<[u32; 16]>,
}

impl DoubleBlockSolver {
    const DIGIT_IDX: u64 = 54;

    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    pub fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }
}

impl Solver for DoubleBlockSolver {
    type Ctx = ();

    fn new(_ctx: Self::Ctx, mut prefix: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        if !is_supported_lane_position(Self::DIGIT_IDX as usize / 4) {
            return None;
        }

        // construct the message buffer
        let mut prefix_state = Align16(sha256::IV);

        let mut complete_blocks_before = 0;

        // first consume all full blocks, this is shared so use scalar reference implementation
        while prefix.len() >= 64 {
            sha256::digest_block(
                &mut prefix_state,
                &core::array::from_fn(|i| {
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

        let mut message: [u8; 64] = [0; 64];
        let mut ptr = 0;
        message[..prefix.len()].copy_from_slice(prefix);
        ptr += prefix.len();

        // pad with ones until we are on a 64-bit boundary minus 2 byte
        // we have much more leeway here as we are committed to a double block solver, using more bytes is fine, there is nothing useful to be traded off
        // so we will construct and solve exactly this format, for lane 12 and nonce 3456789:
        // [prefix + '1' * k + '12' + '3456' + '789\x80'] | ['\0' * 12 + length]
        let mut nonce_addend = 0;
        while (ptr + 2) % 8 != 0 {
            nonce_addend *= 10;
            nonce_addend += 1;
            *message.get_mut(ptr)? = b'1';
            ptr += 1;
        }
        nonce_addend *= 1_000_000_000;

        // these cases are handled by the single block solver
        if ptr != Self::DIGIT_IDX as usize {
            return None;
        }

        // skip 9 zeroes, this is the part we will interpolate N into
        // the first 2 digits are used as the lane index (10 + (0..16)*(0..4), offset to avoid leading zeroes)
        // the rest are randomly generated then broadcasted to all lanes
        // this gives us about 16e7 * 4 possible attempts, likely enough for any realistic deployment even on the highest difficulty
        // the fail rate would be pgeom(keySpace, 1/difficulty, lower=F) in R
        ptr += 9;

        // we should be at the end of the message buffer minus 1
        debug_assert_eq!(ptr, 63);

        message[ptr] = 0x80;

        let message_length = complete_blocks_before * 64 + ptr as u64;

        Some(Self {
            prefix_state,
            message: Align64(core::array::from_fn(|i| {
                u32::from_be_bytes([
                    message[i * 4],
                    message[i * 4 + 1],
                    message[i * 4 + 2],
                    message[i * 4 + 3],
                ])
            })),
            nonce_addend,
            message_length,
            attempted_nonces: 0,
            limit: u64::MAX,
        })
    }

    fn next_search_space(&mut self) -> bool {
        if self.nonce_addend == 0 {
            return false;
        }

        self.nonce_addend = match self.nonce_addend.checked_add(1_000_000_000) {
            Some(nonce_addend) => nonce_addend,
            None => return false,
        };

        // this case the prefix is guaranteed to be in one block so no need to check
        let mut addend_copy = self.nonce_addend / 1_000_000_000;
        let mut i = Self::DIGIT_IDX as usize - 1;
        let mut last_digit = 0;
        while addend_copy > 0 {
            let idx = SWAP_DWORD_BYTE_ORDER[i];
            last_digit = (addend_copy % 10) as u8;
            let message = decompose_blocks_mut(&mut self.message);
            message[idx] = b'0' + last_digit;
            addend_copy /= 10;
            if i > 0 {
                i -= 1;
            } else {
                return false;
            }
        }

        last_digit == 1
    }

    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))] {
            fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
                if !is_supported_lane_position(Self::DIGIT_IDX as usize / 4) {
                    return None;
                }

                for i in (Self::DIGIT_IDX as usize..).take(9) {
                    let message = decompose_blocks_mut(&mut self.message);
                    message[SWAP_DWORD_BYTE_ORDER[i]] = b'0';
                }

                #[cfg(feature = "compare-64bit")]
                let feedback_ab = (target[0] as u64) << 32 | (target[1] as u64);

                let mut partial_state = self.prefix_state;
                sha256::sha2_arx::<0, 13>(&mut partial_state, self.message[..13].try_into().unwrap());

                let mut terminal_message_schedule = Align16([0; 64]);
                terminal_message_schedule[14] = ((self.message_length as u64 * 8) >> 32) as u32;
                terminal_message_schedule[15] = (self.message_length as u64 * 8) as u32;
                sha256::do_message_schedule_k_w(&mut terminal_message_schedule);

                let mut itoa_buf = Align16(*b"0000\x80000");
                for prefix_set_index in 0..5 {
                    unsafe {
                        let lane_id_0_or_value =
                            _mm512_slli_epi32(load_lane_id_epi32(&LANE_ID_MSB_STR, prefix_set_index), 8);
                        let lane_id_1_or_value = load_lane_id_epi32(&LANE_ID_LSB_STR, prefix_set_index);

                        let lane_index_value_v = _mm512_or_epi32(
                            _mm512_set1_epi32(self.message[13] as _),
                            _mm512_or_epi32(lane_id_0_or_value, lane_id_1_or_value),
                        );

                        for next_inner_key in 1..=10_000_000 {

                            let cum0 = itoa_buf.as_ptr().cast::<u32>().read();
                            let cum1 = itoa_buf.as_ptr().add(4).cast::<u32>().read();

                            let mut state =
                                core::array::from_fn(|i| _mm512_set1_epi32(partial_state[i] as _));

                            {
                                let mut blocks = [
                                    _mm512_set1_epi32(self.message[0] as _),
                                    _mm512_set1_epi32(self.message[1] as _),
                                    _mm512_set1_epi32(self.message[2] as _),
                                    _mm512_set1_epi32(self.message[3] as _),
                                    _mm512_set1_epi32(self.message[4] as _),
                                    _mm512_set1_epi32(self.message[5] as _),
                                    _mm512_set1_epi32(self.message[6] as _),
                                    _mm512_set1_epi32(self.message[7] as _),
                                    _mm512_set1_epi32(self.message[8] as _),
                                    _mm512_set1_epi32(self.message[9] as _),
                                    _mm512_set1_epi32(self.message[10] as _),
                                    _mm512_set1_epi32(self.message[11] as _),
                                    _mm512_set1_epi32(self.message[12] as _),
                                    lane_index_value_v,
                                    _mm512_set1_epi32(cum0 as _),
                                    _mm512_set1_epi32(cum1 as _),
                                ];

                                sha256::avx512::multiway_arx::<13>(&mut state, &mut blocks);

                                // we have to do feedback now
                                state.iter_mut().zip(self.prefix_state.iter()).for_each(
                                    |(state, prefix_state)| {
                                        *state =
                                            _mm512_add_epi32(*state, _mm512_set1_epi32(*prefix_state as _));
                                    },
                                );
                            }

                            // save only A register for comparison
                            let save_a = state[0];

                            #[cfg(feature = "compare-64bit")]
                            let save_b = state[1];

                            sha256::avx512::bcst_multiway_arx::<14>(&mut state, &terminal_message_schedule);

                            #[cfg(not(feature = "compare-64bit"))]
                            let cmp_fn = if UPWARDS {
                                _mm512_cmpgt_epu32_mask
                            } else {
                                _mm512_cmplt_epu32_mask
                            };

                            #[cfg(feature = "compare-64bit")]
                            let cmp64_fn = if UPWARDS {
                                _mm512_cmpgt_epu64_mask
                            } else {
                                _mm512_cmplt_epu64_mask
                            };

                            state[0] = _mm512_add_epi32(state[0], save_a);

                            #[cfg(feature = "compare-64bit")]
                            {
                                state[1] = _mm512_add_epi32(state[1], save_b);
                            }

                            #[cfg(not(feature = "compare-64bit"))]
                            let met_target = (cmp_fn)(state[0], _mm512_set1_epi32(target[0] as _));

                            #[cfg(feature = "compare-64bit")]
                            let result_ab_lo = _mm512_unpacklo_epi32(state[1], state[0]);
                            #[cfg(feature = "compare-64bit")]
                            let result_ab_hi = _mm512_unpackhi_epi32(state[1], state[0]);
                            #[cfg(feature = "compare-64bit")]
                            let met_target = {
                                let ab_met_target_lo =
                                    cmp64_fn(result_ab_lo, _mm512_set1_epi64(feedback_ab as _)) as u16;
                                let ab_met_target_high =
                                    cmp64_fn(result_ab_hi, _mm512_set1_epi64(feedback_ab as _)) as u16;
                                ab_met_target_high << 8 | ab_met_target_lo
                            };

                            if met_target != 0 {
                                unlikely();

                                let success_lane_idx = _tzcnt_u16(met_target) as usize;

                                #[cfg(feature = "compare-64bit")]
                                let success_lane_idx = INDEX_REMAP_PUNPCKLDQ[success_lane_idx];

                                let nonce_prefix = 10 + 16 * prefix_set_index + success_lane_idx;

                                self.message[14] = cum0;
                                self.message[15] = cum1;
                                {
                                    let message_bytes = decompose_blocks_mut(&mut self.message);
                                    *message_bytes.get_unchecked_mut(
                                        *SWAP_DWORD_BYTE_ORDER.get_unchecked(Self::DIGIT_IDX as usize),
                                    ) = (nonce_prefix / 10) as u8 + b'0';
                                    *message_bytes.get_unchecked_mut(
                                        *SWAP_DWORD_BYTE_ORDER.get_unchecked(Self::DIGIT_IDX as usize + 1),
                                    ) = (nonce_prefix % 10) as u8 + b'0';
                                }

                                // recompute the hash from the beginning
                                // this prevents the compiler from having to compute the final B-H registers alive in tight loops
                                let mut final_sha_state = self.prefix_state;
                                sha256::digest_block(&mut final_sha_state, &self.message);
                                let mut terminal_message = [0; 16];
                                terminal_message[14] = ((self.message_length * 8) >> 32) as u32;
                                terminal_message[15] = (self.message_length * 8) as u32;
                                sha256::digest_block(&mut final_sha_state, &terminal_message);

                                let computed_nonce = nonce_prefix as u64 * 10u64.pow(7)
                                    + next_inner_key as u64 - 1
                                    + self.nonce_addend;

                                // the nonce is the 8 digits in the message, plus the first two digits recomputed from the lane index
                                return Some((computed_nonce, *final_sha_state));
                            }

                            self.attempted_nonces += 16;

                            if self.attempted_nonces >= self.limit {
                                return None;
                            }

                            strings::simd_itoa8::<7, true, 0x80>(&mut itoa_buf, next_inner_key);
                        }
                    }
                }

                unlikely();

                // try to advance the search space and tail recurse
                if !self.next_search_space() {
                    return None;
                }

                self.solve::<UPWARDS>(target)
            }
        } else if #[cfg(all(target_arch = "x86_64", target_feature = "sha"))] {
            fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
                if !is_supported_lane_position(Self::DIGIT_IDX as usize / 4) {
                    return None;
                }

                for i in (Self::DIGIT_IDX as usize..).take(9) {
                    let message = decompose_blocks_mut(&mut self.message);
                    message[SWAP_DWORD_BYTE_ORDER[i]] = b'0';
                }

                let iv_state = sha256::sha_ni::prepare_state(&self.prefix_state);
                let mut prefix_state = Align16(self.prefix_state);
                sha256::sha2_arx::<0, 12>(&mut prefix_state, self.message[..12].try_into().unwrap());
                let prepared_state = sha256::sha_ni::prepare_state(&prefix_state);

                let mut terminal_message = Align16([0; 16]);
                terminal_message[14] = ((self.message_length * 8) >> 32) as u32;
                terminal_message[15] = (self.message_length * 8) as u32;

                for nonce_prefix_start in (10u32..=96).step_by(4) {
                    unsafe {
                        const fn to_ascii_u32(input: u32) -> u32 {
                            let high_digit = input / 10;
                            let low_digit = input % 10;
                            u32::from_be_bytes([0, 0, high_digit as u8 + b'0', low_digit as u8 + b'0'])
                        }
                        let lane_index_value_v = [
                            to_ascii_u32(nonce_prefix_start) | self.message[13],
                            to_ascii_u32(nonce_prefix_start + 1) | self.message[13],
                            to_ascii_u32(nonce_prefix_start + 2) | self.message[13],
                            to_ascii_u32(nonce_prefix_start + 3) | self.message[13],
                        ];

                        let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

                        for inner_key in 0..10_000_000 {
                            let mut states0 = prepared_state;
                            let mut states1 = prepared_state;
                            let mut states2 = prepared_state;
                            let mut states3 = prepared_state;

                            let mut key_copy = inner_key;
                            let mut cum0 = 0;
                            for _ in 0..4 {
                                cum0 <<= 8;
                                cum0 |= key_copy % 10;
                                key_copy /= 10;
                            }
                            cum0 |= u32::from_be_bytes(*b"0000");
                            let mut cum1 = 0;
                            for _ in 0..3 {
                                cum1 += key_copy % 10;
                                cum1 <<= 8;
                                key_copy /= 10;
                            }
                            cum1 |= u32::from_be_bytes(*b"000\x80");

                            if key_copy != 0 {
                                debug_assert_eq!(key_copy, 0);
                                core::hint::unreachable_unchecked();
                            }

                            let mut msg0 = Align16([0; 16]);
                            msg0[..13].copy_from_slice(self.message[..13].try_into().unwrap());
                            msg0[14] = cum0;
                            msg0[15] = cum1;

                            struct LaneIdPlucker<'a> {
                                lane_index_value_v: &'a [u32; 4],
                            }
                            impl<'a> sha256::sha_ni::Plucker for LaneIdPlucker<'a> {
                                #[inline(always)]
                                fn pluck_qword3(&mut self, lane: usize, w: &mut __m128i) {
                                    *w = unsafe {
                                        _mm_or_si128(
                                            *w,
                                            _mm_setr_epi32(0, self.lane_index_value_v[lane] as _, 0, 0),
                                        )
                                    };
                                }
                            }

                            sha256::sha_ni::multiway_arx_abef_cdgh::<3, 4, LaneIdPlucker>(
                                [&mut states0, &mut states1, &mut states2, &mut states3],
                                &msg0,
                                LaneIdPlucker {
                                    lane_index_value_v: &lane_index_value_v,
                                },
                            );

                            for s in [&mut states0, &mut states1, &mut states2, &mut states3] {
                                s.iter_mut()
                                    .zip(iv_state.iter())
                                    .for_each(|(state, iv_state)| {
                                        *state = _mm_add_epi32(*state, *iv_state);
                                    });
                            }

                            let save_abs = [
                                states0[0], states1[0], states2[0], states3[0]
                            ];

                            // this isn't really SIMD so we can't really amortize the cost of fetching message schedule
                            // so let's compute it with sha-ni
                            sha256::sha_ni::multiway_arx_abef_cdgh::<0, 4, _>(
                                [&mut states0, &mut states1, &mut states2, &mut states3],
                                &terminal_message,
                                (),
                            );

                            states0[0] = _mm_add_epi32(states0[0], save_abs[0]);
                            states1[0] = _mm_add_epi32(states1[0], save_abs[1]);
                            states2[0] = _mm_add_epi32(states2[0], save_abs[2]);
                            states3[0] = _mm_add_epi32(states3[0], save_abs[3]);

                            let final_abs = [
                                _mm_extract_epi64(states0[0], 1) as u64,
                                _mm_extract_epi64(states1[0], 1) as u64,
                                _mm_extract_epi64(states2[0], 1) as u64,
                                _mm_extract_epi64(states3[0], 1) as u64,
                            ];

                            let success_lane_idx = final_abs.iter().position(|x| {
                                if UPWARDS {
                                    *x > compact_target
                                } else {
                                    *x < compact_target
                                }
                            });

                            if let Some(success_lane_idx) = success_lane_idx {
                                unlikely();

                                let nonce_prefix = nonce_prefix_start + success_lane_idx as u32;
                                self.message[13] = lane_index_value_v[success_lane_idx];
                                self.message[14] = cum0;
                                self.message[15] = cum1;

                                // recompute the hash from the beginning
                                // this prevents the compiler from having to compute the final B-H registers alive in tight loops
                                let mut final_sha_state = self.prefix_state;
                                sha256::digest_block(&mut final_sha_state, &self.message);
                                sha256::digest_block(&mut final_sha_state, &terminal_message);

                                // reverse the byte order
                                let mut nonce_suffix = 0;
                                let mut key_copy = inner_key;
                                for _ in 0..7 {
                                    nonce_suffix *= 10;
                                    nonce_suffix += key_copy % 10;
                                    key_copy /= 10;
                                }

                                let computed_nonce = nonce_prefix as u64 * 10u64.pow(7)
                                    + nonce_suffix as u64
                                    + self.nonce_addend;

                                // the nonce is the 8 digits in the message, plus the first two digits recomputed from the lane index
                                return Some((computed_nonce, *final_sha_state));
                            }

                            self.attempted_nonces += 4;

                            if self.attempted_nonces >= self.limit {
                                return None;
                            }
                        }
                    }
                }

                if !self.next_search_space() {
                    return None;
                }

                self.solve::<UPWARDS>(target)
            }
        } else if #[cfg(target_arch = "wasm32")] {
            fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
                if !is_supported_lane_position(Self::DIGIT_IDX as usize / 4) {
                    return None;
                }

                for i in (Self::DIGIT_IDX as usize..).take(9) {
                    let message = decompose_blocks_mut(&mut self.message);
                    message[SWAP_DWORD_BYTE_ORDER[i]] = b'0';
                }

                let mut partial_state = Align64(self.prefix_state);
                sha256::sha2_arx::<0, 13>(&mut partial_state, self.message[..13].try_into().unwrap());

                let mut terminal_message_schedule = Align16([0; 64]);
                terminal_message_schedule[14] = ((self.message_length as u64 * 8) >> 32) as u32;
                terminal_message_schedule[15] = (self.message_length as u64 * 8) as u32;
                sha256::do_message_schedule_k_w(&mut terminal_message_schedule);

                for prefix_set_index in 0..((100 - 10) / 4) {
                    unsafe {
                        let lane_id_0_or_value =
                            u32x4_shl(load_lane_id_epi32(&LANE_ID_MSB_STR, prefix_set_index), 8);
                        let lane_id_1_or_value = load_lane_id_epi32(&LANE_ID_LSB_STR, prefix_set_index);

                        let lane_index_value_v = v128_or(
                            u32x4_splat(self.message[13] as _),
                            v128_or(lane_id_0_or_value, lane_id_1_or_value),
                        );

                        for inner_key in 0..10_000_000 {
                            let mut key_copy = inner_key;
                            let mut cum0 = 0;
                            for _ in 0..4 {
                                cum0 <<= 8;
                                cum0 |= key_copy % 10;
                                key_copy /= 10;
                            }
                            cum0 |= u32::from_be_bytes(*b"0000");
                            let mut cum1 = 0;
                            for _ in 0..3 {
                                cum1 += key_copy % 10;
                                cum1 <<= 8;
                                key_copy /= 10;
                            }
                            cum1 |= u32::from_be_bytes(*b"000\x80");

                            if key_copy != 0 {
                                debug_assert_eq!(key_copy, 0);
                                core::hint::unreachable_unchecked();
                            }

                            let mut blocks = [
                                u32x4_splat(self.message[0] as _),
                                u32x4_splat(self.message[1] as _),
                                u32x4_splat(self.message[2] as _),
                                u32x4_splat(self.message[3] as _),
                                u32x4_splat(self.message[4] as _),
                                u32x4_splat(self.message[5] as _),
                                u32x4_splat(self.message[6] as _),
                                u32x4_splat(self.message[7] as _),
                                u32x4_splat(self.message[8] as _),
                                u32x4_splat(self.message[9] as _),
                                u32x4_splat(self.message[10] as _),
                                u32x4_splat(self.message[11] as _),
                                u32x4_splat(self.message[12] as _),
                                lane_index_value_v,
                                u32x4_splat(cum0 as _),
                                u32x4_splat(cum1 as _),
                            ];

                            let mut state = core::array::from_fn(|i| u32x4_splat(partial_state[i]));
                            sha256::simd128::multiway_arx::<13>(&mut state, &mut blocks);

                            state.iter_mut().zip(self.prefix_state.iter()).for_each(
                                |(state, prefix_state)| {
                                    *state = u32x4_add(*state, u32x4_splat(*prefix_state as _));
                                },
                            );

                            let save_a = state[0];

                            sha256::simd128::bcst_multiway_arx::<14>(
                                &mut state,
                                &terminal_message_schedule,
                            );

                            let result_a = u32x4_add(state[0], save_a);

                            let cmp_fn = if UPWARDS { u32x4_le } else { u32x4_ge };

                            let a_not_met_target = cmp_fn(result_a, u32x4_splat(target[0]));

                            if !u32x4_all_true(a_not_met_target) {
                                unlikely();

                                let mut extract = [0u32; 4];
                                v128_store(extract.as_mut_ptr().cast(), result_a);
                                let success_lane_idx = extract
                                    .iter()
                                    .position(|x| {
                                        if UPWARDS {
                                            *x > target[0]
                                        } else {
                                            *x < target[0]
                                        }
                                    })
                                    .unwrap();
                                let nonce_prefix = 10 + 4 * prefix_set_index + success_lane_idx;

                                self.message[14] = cum0;
                                self.message[15] = cum1;
                                // stamp the lane ID back onto the message
                                {
                                    let message_bytes = decompose_blocks_mut(&mut self.message);
                                    *message_bytes.get_unchecked_mut(
                                        *SWAP_DWORD_BYTE_ORDER.get_unchecked(Self::DIGIT_IDX as usize),
                                    ) = (nonce_prefix / 10) as u8 + b'0';
                                    *message_bytes.get_unchecked_mut(
                                        *SWAP_DWORD_BYTE_ORDER.get_unchecked(Self::DIGIT_IDX as usize + 1),
                                    ) = (nonce_prefix % 10) as u8 + b'0';
                                }

                                // recompute the hash from the beginning
                                // this prevents the compiler from having to compute the final B-H registers alive in tight loops
                                let mut final_sha_state = self.prefix_state;
                                sha256::digest_block(&mut final_sha_state, &self.message);

                                let mut terminal_message_without_constants = [0; 16];
                                terminal_message_without_constants[14] = ((self.message_length as u64 * 8) >> 32) as u32;
                                terminal_message_without_constants[15] = (self.message_length as u64 * 8) as u32;
                                sha256::digest_block(
                                    &mut final_sha_state,
                                    &terminal_message_without_constants,
                                );

                                // reverse the byte order
                                let mut nonce_suffix = 0;
                                let mut key_copy = inner_key;
                                for _ in 0..7 {
                                    nonce_suffix *= 10;
                                    nonce_suffix += key_copy % 10;
                                    key_copy /= 10;
                                }

                                let computed_nonce = nonce_prefix as u64 * 10u64.pow(7)
                                    + nonce_suffix as u64
                                    + self.nonce_addend;

                                // the nonce is the 8 digits in the message, plus the first two digits recomputed from the lane index
                                return Some((computed_nonce, *final_sha_state));
                            }

                            self.attempted_nonces += 4;

                            if self.attempted_nonces >= self.limit {
                                return None;
                            }
                        }
                    }
                }

                if !self.next_search_space() {
                    return None;
                }

                self.solve::<UPWARDS>(target)
            }
        } else {
            #[inline(never)]
            fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
                let mut buffer : sha2::digest::crypto_common::Block<sha2::Sha256> = Default::default();
                for i in 0..16 {
                    buffer[i*4..i*4+4].copy_from_slice(&self.message[i].to_be_bytes());
                }

                let mut buffer2 : sha2::digest::crypto_common::Block<sha2::Sha256> = Default::default();
                buffer2[56..].copy_from_slice(&((self.message_length as u64 * 8)).to_be_bytes());

                let mut terminal_message_schedule = [0; 64];
                terminal_message_schedule[14] = ((self.message_length as u64 * 8) >> 32) as u32;
                terminal_message_schedule[15] = (self.message_length as u64 * 8) as u32;
                sha256::do_message_schedule_k_w(&mut terminal_message_schedule);

                let feedback_ab = (target[0] as u64) << 32 | (target[1] as u64);
                let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

                for key in (if self.nonce_addend == 0 { 100_000_000 } else { 0 })..1_000_000_000 {
                    let mut key_copy = key;

                    for j in (0..9).rev() {
                        let digit = key_copy % 10;
                        key_copy /= 10;
                        buffer[DoubleBlockSolver::DIGIT_IDX as usize + j] = digit as u8 + b'0';
                    }

                    let mut state = self.prefix_state;
                    sha2::compress256(&mut state, &[buffer]);

                    let save_a = state[0];
                    let save_b = state[1];

                    sha256::sha2_arx_without_constants::<0, 64>(&mut state, terminal_message_schedule);

                    state[0] = state[0].wrapping_add(save_a);
                    state[1] = state[1].wrapping_add(save_b);

                    let ab = (state[0] as u64) << 32 | (state[1] as u64);

                    let cmp_fn = if UPWARDS { u64::gt } else { u64::lt };
                    if cmp_fn(&ab, &compact_target) {
                        unlikely();

                        let mut state = self.prefix_state;
                        sha2::compress256(&mut state, &[buffer, buffer2]);
                        return Some((key as u64 + self.nonce_addend, *state));
                    }
                }

                if !self.next_search_space() {
                    return None;
                }

                self.solve::<UPWARDS>(target)
            }
        }
    }
}

/// Solver for GoAway style SHA-256 challenges
///
/// Goaway challenge has construction:
///
/// challenge := SHA256 (difficulty || secret)
/// criteria := SHA256 (challenge || nonce) where nonce is 8 bytes, which gives us 9 rounds of hot start and a fully explorable nonce space
/// proof := challenge || nonce
pub struct GoAwaySolver {
    challenge: [u32; 8],
    limit: u64,
}

impl GoAwaySolver {
    const MSG_LEN: u32 = 10 * 4 * 8;

    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }
}

impl Solver for GoAwaySolver {
    type Ctx = ();

    fn new(_ctx: Self::Ctx, prefix: &[u8]) -> Option<Self> {
        if !is_supported_lane_position(PREFIX_OFFSET_TO_LANE_POSITION[0]) {
            return None;
        }

        let mut prefix_fixed_up = [0; 32];
        let mut final_prefix = &*prefix;
        if prefix.len() != 32 {
            if prefix.len() == 64 {
                for i in 0..32 {
                    let byte_hex: [u8; 2] = prefix[i * 2..][..2].try_into().unwrap();
                    let high_nibble = if (b'a'..=b'f').contains(&byte_hex[0]) {
                        byte_hex[0] - b'a' + 10
                    } else if (b'0'..=b'9').contains(&byte_hex[0]) {
                        byte_hex[0] - b'0'
                    } else {
                        return None;
                    };
                    let low_nibble = if (b'a'..=b'f').contains(&byte_hex[1]) {
                        byte_hex[1] - b'a' + 10
                    } else if (b'0'..=b'9').contains(&byte_hex[1]) {
                        byte_hex[1] - b'0'
                    } else {
                        return None;
                    };
                    prefix_fixed_up[i] = (high_nibble << 4) | low_nibble;
                }
                final_prefix = &prefix_fixed_up;
            } else {
                return None;
            }
        }

        Some(Self {
            challenge: core::array::from_fn(|i| {
                u32::from_be_bytes([
                    final_prefix[i * 4],
                    final_prefix[i * 4 + 1],
                    final_prefix[i * 4 + 2],
                    final_prefix[i * 4 + 3],
                ])
            }),
            limit: u64::MAX,
        })
    }

    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))] {
            #[inline(never)]
            fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
                unsafe {
                    let lane_id_v = _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

                    if !is_supported_lane_position(PREFIX_OFFSET_TO_LANE_POSITION[0]) {
                        return None;
                    }

                    let mut prefix_state = sha256::IV;
                    sha256::ingest_message_prefix(&mut prefix_state, self.challenge);

                    let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

                    let high_limit = (self.limit >> 32) as u32;
                    let low_limit = self.limit as u32;

                    for high_word in 0..=high_limit {
                        let mut partial_state = Align64(prefix_state);
                        sha256::sha2_arx::<8, _>(&mut partial_state, [high_word]);

                        for low_word in (0..=if high_word == high_limit { low_limit } else { u32::MAX }).step_by(16) {
                            let mut state =
                                core::array::from_fn(|i| _mm512_set1_epi32(partial_state[i] as _));

                            let mut msg = [
                                _mm512_set1_epi32(self.challenge[0] as _),
                                _mm512_set1_epi32(self.challenge[1] as _),
                                _mm512_set1_epi32(self.challenge[2] as _),
                                _mm512_set1_epi32(self.challenge[3] as _),
                                _mm512_set1_epi32(self.challenge[4] as _),
                                _mm512_set1_epi32(self.challenge[5] as _),
                                _mm512_set1_epi32(self.challenge[6] as _),
                                _mm512_set1_epi32(self.challenge[7] as _),
                                _mm512_set1_epi32(high_word as _),
                                _mm512_or_epi32(_mm512_set1_epi32(low_word as _), lane_id_v),
                                _mm512_set1_epi32(u32::from_be_bytes([0x80, 0, 0, 0]) as _),
                                _mm512_setzero_epi32(),
                                _mm512_setzero_epi32(),
                                _mm512_setzero_epi32(),
                                _mm512_setzero_epi32(),
                                _mm512_set1_epi32(Self::MSG_LEN as _),
                            ];
                            sha256::avx512::multiway_arx::<9>(&mut state, &mut msg);

                            state[0] =
                                _mm512_add_epi32(state[0], _mm512_set1_epi32(sha256::IV[0] as _));

                            #[cfg(feature = "compare-64bit")]
                            {
                                state[1] =
                                    _mm512_add_epi32(state[1], _mm512_set1_epi32(sha256::IV[1] as _));
                            }

                            #[cfg(not(feature = "compare-64bit"))]
                            let cmp_fn = if UPWARDS {
                                _mm512_cmpgt_epu32_mask
                            } else {
                                _mm512_cmplt_epu32_mask
                            };

                            #[cfg(feature = "compare-64bit")]
                            let cmp_fn = if UPWARDS {
                                _mm512_cmpgt_epu64_mask
                            } else {
                                _mm512_cmplt_epu64_mask
                            };

                            #[cfg(not(feature = "compare-64bit"))]
                            let met_target = cmp_fn(state[0], _mm512_set1_epi32(target[0] as _));

                            #[cfg(feature = "compare-64bit")]
                            let result_ab_lo = _mm512_unpacklo_epi32(state[1], state[0]);
                            #[cfg(feature = "compare-64bit")]
                            let result_ab_hi = _mm512_unpackhi_epi32(state[1], state[0]);
                            #[cfg(feature = "compare-64bit")]
                            let met_target = {
                                let ab_met_target_lo =
                                    cmp_fn(result_ab_lo, _mm512_set1_epi64(compact_target as _)) as u16;
                                let ab_met_target_high =
                                    cmp_fn(result_ab_hi, _mm512_set1_epi64(compact_target as _)) as u16;
                                ab_met_target_high << 8 | ab_met_target_lo
                            };

                            if met_target != 0 {
                                unlikely();

                                let success_lane_idx = _tzcnt_u16(met_target);

                                #[cfg(feature = "compare-64bit")]
                                let success_lane_idx = INDEX_REMAP_PUNPCKLDQ[success_lane_idx as usize];

                                let mut output_msg: [u32; 16] = [0; 16];

                                let final_low_word = low_word | (success_lane_idx as u32);
                                output_msg[..8].copy_from_slice(&self.challenge);
                                output_msg[8] = high_word;
                                output_msg[9] = final_low_word;
                                output_msg[10] = u32::from_be_bytes([0x80, 0, 0, 0]);
                                output_msg[15] = Self::MSG_LEN as _;

                                let mut final_sha_state = sha256::IV;
                                sha256::digest_block(&mut final_sha_state, &output_msg);

                                return Some((
                                    (high_word as u64) << 32 | final_low_word as u64,
                                    final_sha_state,
                                ));
                            }
                        }
                    }
                }
                None
            }
        } else if #[cfg(all(target_arch = "x86_64", target_feature = "sha"))] {
            #[inline(never)]
            fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
                unsafe {
                    use core::arch::x86_64::*;

                    if !is_supported_lane_position(PREFIX_OFFSET_TO_LANE_POSITION[0]) {
                        return None;
                    }

                    let mut prefix_state = Align16(sha256::IV);
                    sha256::ingest_message_prefix(&mut prefix_state, self.challenge);
                    let prepared_state = sha256::sha_ni::prepare_state(&prefix_state);

                    let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

                    let feedback_ab = {
                        let lows = _mm_cvtsi64x_si128(((sha256::IV[0] as u64) << 32 | sha256::IV[1] as u64) as _);

                        _mm_shuffle_epi32(lows, 0b01001010)
                    };

                    for high_word in 0..=u32::MAX {
                        for low_word in (0..=u32::MAX).step_by(4) {
                            let mut states0 = prepared_state;
                            let mut states1 = prepared_state;
                            let mut states2 = prepared_state;
                            let mut states3 = prepared_state;

                            let mut msg0 = Align16([0; 16]);
                            msg0[0..8].copy_from_slice(&self.challenge);
                            msg0[8] = high_word;
                            msg0[9] = low_word;
                            msg0[10] = u32::from_be_bytes([0x80, 0, 0, 0]);
                            msg0[15] = Self::MSG_LEN as _;

                            struct LaneIdPlucker;
                            impl sha256::sha_ni::Plucker for LaneIdPlucker {
                                #[inline(always)]
                                fn pluck_qword2(&mut self, lane: usize, w: &mut __m128i) {
                                    *w = unsafe { _mm_or_si128(*w, _mm_setr_epi32(0, lane as _, 0, 0)) };
                                }
                            }

                            sha256::sha_ni::multiway_arx_abef_cdgh::<2, 4, _>(
                                [&mut states0, &mut states1, &mut states2, &mut states3],
                                &msg0,
                                LaneIdPlucker,
                            );

                            states0[0] = _mm_add_epi32(states0[0], feedback_ab);
                            states1[0] = _mm_add_epi32(states1[0], feedback_ab);
                            states2[0] = _mm_add_epi32(states2[0], feedback_ab);
                            states3[0] = _mm_add_epi32(states3[0], feedback_ab);

                            let result_abs = [
                                _mm_extract_epi64(states0[0], 1) as u64,
                                _mm_extract_epi64(states1[0], 1) as u64,
                                _mm_extract_epi64(states2[0], 1) as u64,
                                _mm_extract_epi64(states3[0], 1) as u64,
                            ];

                            let success_lane_idx = result_abs.iter().position(|x| {
                                if UPWARDS {
                                    *x > compact_target
                                } else {
                                    *x < compact_target
                                }
                            });

                            if let Some(success_lane_idx) = success_lane_idx {
                                unlikely();

                                let mut output_msg: [u32; 16] = [0; 16];

                                let final_low_word = low_word | (success_lane_idx as u32);
                                output_msg[..8].copy_from_slice(&self.challenge);
                                output_msg[8] = high_word;
                                output_msg[9] = final_low_word;
                                output_msg[10] = u32::from_be_bytes([0x80, 0, 0, 0]);
                                output_msg[15] = Self::MSG_LEN as _;

                                let mut final_sha_state = sha256::IV;
                                sha256::digest_block(&mut final_sha_state, &output_msg);

                                return Some((
                                    (high_word as u64) << 32 | final_low_word as u64,
                                    final_sha_state,
                                ));
                            }
                        }
                    }
                }
                None
            }
        } else if #[cfg(target_arch = "wasm32")] {
            #[inline(never)]
            fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
                unsafe {
                    if !is_supported_lane_position(PREFIX_OFFSET_TO_LANE_POSITION[0]) {
                        return None;
                    }

                    let lane_id_v = u32x4(0, 1, 2, 3);

                    let mut prefix_state = sha256::IV;
                    sha256::ingest_message_prefix(&mut prefix_state, self.challenge);

                    for high_word in 0..=u32::MAX {
                        let mut partial_state = prefix_state;
                        sha256::sha2_arx::<8, _>(&mut partial_state, [high_word]);

                        for low_word in (0..=u32::MAX).step_by(4) {
                            let mut state = core::array::from_fn(|i| u32x4_splat(partial_state[i]));

                            let mut msg = [
                                u32x4_splat(self.challenge[0]),
                                u32x4_splat(self.challenge[1]),
                                u32x4_splat(self.challenge[2]),
                                u32x4_splat(self.challenge[3]),
                                u32x4_splat(self.challenge[4]),
                                u32x4_splat(self.challenge[5]),
                                u32x4_splat(self.challenge[6]),
                                u32x4_splat(self.challenge[7]),
                                u32x4_splat(high_word),
                                v128_or(u32x4_splat(low_word), lane_id_v),
                                u32x4_splat(u32::from_be_bytes([0x80, 0, 0, 0])),
                                u32x4_splat(0),
                                u32x4_splat(0),
                                u32x4_splat(0),
                                u32x4_splat(0),
                                u32x4_splat(Self::MSG_LEN as _),
                            ];

                            sha256::simd128::multiway_arx::<9>(&mut state, &mut msg);
                            let result_a = u32x4_add(state[0], u32x4_splat(sha256::IV[0]));
                            let cmp_fn = if UPWARDS { u32x4_le } else { u32x4_ge };

                            let a_not_met_target = cmp_fn(result_a, u32x4_splat(target[0]));

                            if !u32x4_all_true(a_not_met_target) {
                                unlikely();

                                let mut extract = [0u32; 4];
                                v128_store(extract.as_mut_ptr().cast(), result_a);
                                let success_lane_idx = extract
                                    .iter()
                                    .position(|x| {
                                        if UPWARDS {
                                            *x > target[0]
                                        } else {
                                            *x < target[0]
                                        }
                                    })
                                    .unwrap();
                                let final_low_word = low_word | (success_lane_idx as u32);
                                let mut output_msg: [u32; 16] = [0; 16];
                                output_msg[..8].copy_from_slice(&self.challenge);
                                output_msg[8] = high_word;
                                output_msg[9] = final_low_word;
                                output_msg[10] = u32::from_be_bytes([0x80, 0, 0, 0]);
                                output_msg[15] = Self::MSG_LEN as _;

                                let mut final_sha_state = sha256::IV;
                                sha256::digest_block(&mut final_sha_state, &output_msg);

                                return Some((
                                    (high_word as u64) << 32 | final_low_word as u64,
                                    final_sha_state,
                                ));
                            }
                        }
                    }
                }
                None
            }
        } else {
            #[inline(never)]
            fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
                let mut buffer = Align16([sha2::digest::crypto_common::Block::<sha2::Sha256>::default(); 16]);
                for i in 0..8 {
                    buffer[0][i*4..i*4+4].copy_from_slice(&self.challenge[i].to_be_bytes());
                }
                buffer[0][40] = 0x80;
                buffer[0][60..64].copy_from_slice(&(Self::MSG_LEN as u32).to_be_bytes());

                let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

                for key in 0..=u64::MAX {
                    unsafe {
                        *buffer[0].as_mut_ptr().add(32).cast::<u64>() = u64::from_ne_bytes(key.to_be_bytes());
                    }

                    let mut state = sha256::IV;
                    sha2::compress256(&mut state, &*buffer);

                    state[0] = state[0].wrapping_add(sha256::IV[0]);
                    state[1] = state[1].wrapping_add(sha256::IV[1]);

                    let state_ab = (state[0] as u64) << 32 | (state[1] as u64);

                    let cmp_fn = if UPWARDS { u64::gt } else { u64::lt };
                    if cmp_fn(&state_ab, &compact_target) {
                        unlikely();

                        return Some((key, state));
                    }
                }

                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use sha2::{Digest, Sha256, digest::Output};

    use super::*;

    #[test]
    fn test_prefix_position_to_lane_position() {
        let mut mapping = [0; 64];
        let x = [b'a'; 64];
        for i in 0..64 {
            let single_solver = SingleBlockSolver::new(Default::default(), &x[..i]);
            if let Some(single_solver) = single_solver {
                mapping[i] = single_solver.digit_index / 4;
            } else {
                mapping[i] = DoubleBlockSolver::DIGIT_IDX as usize / 4;
            }
        }
        assert_eq!(mapping, PREFIX_OFFSET_TO_LANE_POSITION);
    }

    pub fn build_prefix_official<W: std::io::Write>(
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

    #[test]
    #[cfg_attr(feature = "wasm-bindgen", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_encode_hex() {
        let mut out = [0u8; 64];
        encode_hex(
            &mut out,
            [
                0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678,
                0x9abcdef0,
            ],
        );
        assert_eq!(
            unsafe { std::str::from_utf8_unchecked(&out) },
            "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
        );
    }

    #[test]
    #[cfg_attr(feature = "wasm-bindgen", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_compute_target_anubis() {
        assert_eq!(
            compute_target_anubis(NonZeroU8::new(1).unwrap()),
            0x10000000000000000000000000000000,
        );
        assert_eq!(
            compute_target_anubis(NonZeroU8::new(2).unwrap()),
            0x01000000000000000000000000000000,
        );
        assert_eq!(
            compute_target_anubis(NonZeroU8::new(3).unwrap()),
            0x00100000000000000000000000000000,
        );
    }

    #[test]
    #[cfg_attr(feature = "wasm-bindgen", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_bincode_string_serialize() {
        let string = "hello";
        let mut homegrown = Vec::new();
        build_prefix(&mut homegrown, string, "z");
        let mut official = Vec::new();
        build_prefix_official(&mut official, string, "z").unwrap();
        assert_eq!(homegrown, official);
    }

    pub(crate) fn test_solve<S: Solver>() -> HashSet<usize>
    where
        <S as Solver>::Ctx: Default,
    {
        const SALT: &str = "z";

        let mut solved = HashSet::new();
        let mut cannot_solve = 0;
        for phrase_len in 0..64 {
            let mut concatenated_prefix = SALT.as_bytes().to_vec();
            let phrase_str = String::from_iter(std::iter::repeat('a').take(phrase_len));
            concatenated_prefix.extend_from_slice(&bincode::serialize(&phrase_str).unwrap());

            let config = pow_sha256::Config { salt: SALT.into() };
            const DIFFICULTY: u32 = 100_000;
            const ANUBIS_DIFFICULTY: NonZeroU8 = NonZeroU8::new(4).unwrap();

            let solver = S::new(Default::default(), &concatenated_prefix);
            let Some(mut solver) = solver else {
                eprintln!(
                    "solver is None for phrase_len: {} (prefix: {})",
                    phrase_len,
                    concatenated_prefix.len()
                );
                cannot_solve += 1;
                continue;
            };
            let mut anubis_solver = S::new(Default::default(), &concatenated_prefix).unwrap();
            'nudge: for try_nudge_count in [0, 1, 9, 10, 11] {
                for _ in 0..try_nudge_count {
                    if !solver.next_search_space() {
                        continue 'nudge;
                    }
                    if !anubis_solver.next_search_space() {
                        continue 'nudge;
                    }
                }

                solved.insert(phrase_len);
                let target_bytes = compute_target(DIFFICULTY).to_be_bytes();
                let target_u32s = core::array::from_fn(|i| {
                    u32::from_be_bytes([
                        target_bytes[i * 4],
                        target_bytes[i * 4 + 1],
                        target_bytes[i * 4 + 2],
                        target_bytes[i * 4 + 3],
                    ])
                });
                let target_anubis = compute_target_anubis(ANUBIS_DIFFICULTY);
                let target_anubis_bytes = target_anubis.to_be_bytes();
                let target_anubis_u32s = core::array::from_fn(|i| {
                    u32::from_be_bytes([
                        target_anubis_bytes[i * 4],
                        target_anubis_bytes[i * 4 + 1],
                        target_anubis_bytes[i * 4 + 2],
                        target_anubis_bytes[i * 4 + 3],
                    ])
                });
                let (nonce, result) = solver.solve::<true>(target_u32s).expect("solver failed");
                let result_128 = extract128_be(result);
                let (anubis_nonce, anubis_result) = anubis_solver
                    .solve::<false>(target_anubis_u32s)
                    .expect("solver failed");
                let anubis_result_128 = extract128_be(anubis_result);
                let anubis_result_bytes = anubis_result_128.to_be_bytes();
                assert!(
                    target_anubis > anubis_result_128,
                    "[{}] target_anubis: {:016x} <= anubis_result: {:016x} (solver: {}, try_nudge_count: {})",
                    core::any::type_name::<S>(),
                    target_anubis,
                    anubis_result_128,
                    core::any::type_name::<S>(),
                    try_nudge_count
                );

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
                    .result(result_128.to_string())
                    .build()
                    .unwrap();
                let anubis_test_response = pow_sha256::PoWBuilder::default()
                    .nonce(anubis_nonce)
                    .result(anubis_result_128.to_string())
                    .build()
                    .unwrap();
                assert_eq!(
                    config.calculate(&test_response, &phrase_str).unwrap(),
                    result_128,
                    "test_response: {:?} (solver: {}, try_nudge_count: {})",
                    test_response,
                    core::any::type_name::<S>(),
                    try_nudge_count
                );
                assert_eq!(
                    config
                        .calculate(&anubis_test_response, &phrase_str)
                        .unwrap(),
                    anubis_result_128
                );

                assert!(
                    config.is_valid_proof(&test_response, &phrase_str),
                    "{} is not valid proof (solver: {})",
                    result_128,
                    core::any::type_name::<S>()
                );

                assert!(
                    config.is_sufficient_difficulty(&test_response, DIFFICULTY),
                    "{:016x} is not sufficient difficulty, expected {:016x} (solver: {})",
                    result_128,
                    compute_target(DIFFICULTY),
                    core::any::type_name::<S>()
                );

                // based on proof-of-work.mjs
                for i in 0..ANUBIS_DIFFICULTY.get() as usize {
                    let byte_index = i / 2;
                    let nibble_index = (1 - i % 2) as u8;

                    let nibble = (anubis_result_bytes[byte_index] >> (nibble_index * 4)) & 0x0f;
                    assert_eq!(
                        nibble,
                        0,
                        "{:08x} is not valid anubis proof (solver: {}, nibble: {})",
                        anubis_result_128,
                        core::any::type_name::<S>(),
                        i
                    );
                }
            }
        }
        println!(
            "cannot_solve: {} out of 64 lengths using {} (success rate: {:.2}%)",
            cannot_solve,
            core::any::type_name::<S>(),
            (64 - cannot_solve) as f64 / 64.0 * 100.0
        );

        solved
    }

    #[test]
    #[cfg_attr(feature = "wasm-bindgen", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_solve_16way() {
        let solved_single_block = test_solve::<SingleBlockSolver>();
        let solved_double_block = test_solve::<DoubleBlockSolver>();
        let mut total_solved = solved_single_block
            .union(&solved_double_block)
            .collect::<Vec<_>>();
        total_solved.sort();
        for expect in 0..64 {
            assert!(
                total_solved.contains(&&expect),
                "{} not in {:?}",
                expect,
                total_solved
            );
        }
    }

    #[test]
    #[cfg_attr(feature = "wasm-bindgen", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_solve_goaway() {
        const DIFFICULTY: NonZeroU8 = NonZeroU8::new(12).unwrap();
        let target = compute_target_goaway(DIFFICULTY).to_be_bytes();
        let target_u32s = core::array::from_fn(|i| {
            u32::from_be_bytes([
                target[i * 4],
                target[i * 4 + 1],
                target[i * 4 + 2],
                target[i * 4 + 3],
            ])
        });
        let mut test_prefix: Output<Sha256> = Default::default();
        test_prefix[..3].copy_from_slice(b"abc");

        let mut solver = GoAwaySolver::new(Default::default(), &test_prefix.as_slice()).unwrap();
        let (nonce, result) = solver.solve::<false>(target_u32s).expect("solver failed");
        assert!(result[0].leading_zeros() >= DIFFICULTY.get() as u32);

        let mut hasher = Sha256::default();
        hasher.update(&test_prefix);
        hasher.update(&nonce.to_be_bytes());
        let hash = hasher.finalize();
        assert!(u128::from_be_bytes(hash[..16].try_into().unwrap()) >= DIFFICULTY.get() as _);
    }
}
