#![allow(clippy::inconsistent_digit_grouping)]
#![allow(clippy::collapsible_if)]
use sha2::digest::{
    consts::{B0, U16},
    generic_array::{ArrayLength, GenericArray},
    typenum::UInt,
};

use crate::{Align16, Align64, AlignerTo, is_supported_lane_position, sha256};

/// Solves an mCaptcha/Anubis/Cap.js SHA256 PoW where the SHA-256 message is a single block (512 bytes minus padding).
///
/// Construct: Proof := (prefix || ASCII_DECIMAL(nonce))
///
/// Currently the mutating part is always 9 digits long.
#[derive(Debug, Clone)]
pub struct SingleBlockMessage {
    /// the message template for the final block, pre-padded except for the mutating part
    pub message: Align64<[u32; 16]>,

    /// the SHA-256 midstate for the previous block
    pub prefix_state: [u32; 8],

    /// the index of the mutating part of the digits in the message
    pub digit_index: usize,

    /// the nonce addend
    pub nonce_addend: u64,

    /// the approximate working set count
    pub approx_working_set_count: core::num::NonZeroU32,

    /// whether there are no trailing zeros
    pub no_trailing_zeros: bool,
}

#[derive(Debug, Clone, Copy)]
/// a prefix for stretching nonces that are accepted as IEEE 754 double precision floats
pub struct IEEE754LosslessFixupPrefix {
    buf: [u8; 9],
    cut: usize,
}

impl IEEE754LosslessFixupPrefix {
    /// fixes up a nonce before sending it to the server
    #[inline(always)]
    pub const fn fixup(&self, nonce: u64) -> f64 {
        let mut decimals = 0.00000_000_000_001 * nonce as f64;
        let tens = self.buf[1] - b'0';
        let ones = self.buf[2] - b'0';
        decimals += (tens * 10 + ones) as f64;
        if self.cut == 0 {
            decimals = -decimals;
        }
        decimals
    }
}

impl AsRef<[u8]> for IEEE754LosslessFixupPrefix {
    fn as_ref(&self) -> &[u8] {
        &self.buf[self.cut..]
    }
}

impl SingleBlockMessage {
    /// creates a new single block message
    pub fn new(mut prefix: &[u8], mut working_set: u32) -> Option<Self> {
        // construct the message buffer
        let mut prefix_state = sha256::IV;
        let mut nonce_addend = 0u64;
        let mut complete_blocks_before = 0;
        let mut approx_working_set_count = 1;

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
                approx_working_set_count *= 10;
                let digit = working_set % 10;
                working_set /= 10;
                digit as u8
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
        if ptr <= 35 {
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

        if working_set != 0 {
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
            approx_working_set_count: approx_working_set_count.try_into().unwrap(),
            no_trailing_zeros: false,
        })
    }

    /// Create a new single block message using only IEEE 754 double precision floats that can stringify losslessly
    ///
    /// The caller is expected to append the bytes from the prefix to the nonce before sending it to the server.
    pub fn new_f64(
        mut prefix: &[u8],
        mut working_set: u32,
    ) -> Option<(Self, Option<IEEE754LosslessFixupPrefix>)> {
        // construct the message buffer
        let mut prefix_state = sha256::IV;
        let mut nonce_addend = 0u64;
        let mut complete_blocks_before = 0;
        let mut approx_working_set_count = 1;

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

        let mut message: [u8; 64] = [0; 64]; // the final message
        let mut ptr = 0;
        let mut fixup_prefix = None;

        if (55..=57).contains(&prefix.len()) {
            // a separate program is ran to make sure these numbers
            // parse and stringifies losslessly
            if working_set >= 32 {
                return None;
            }
            let working_set_msb = working_set / 10;
            let working_set_lsb = working_set % 10;
            let mut tmp_block = [0; 64];
            tmp_block[..prefix.len()].copy_from_slice(prefix);
            let space = 64 - prefix.len();
            let mut padding: IEEE754LosslessFixupPrefix = IEEE754LosslessFixupPrefix {
                buf: *b"-10.00000",
                cut: 0,
            };
            if prefix.len() == 56 {
                padding.cut = 1;
            }
            let mut padding_buf = padding.buf;
            padding_buf[1] = b'1' + working_set_msb as u8;
            padding_buf[2] = b'0' + working_set_lsb as u8;
            let pad = &padding_buf.as_slice()[padding.cut..];
            let (pad_left, pad_right) = pad.split_at(space);
            tmp_block[prefix.len()..].copy_from_slice(pad_left);
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
            prefix = &[];
            complete_blocks_before += 1;
            message[..pad_right.len()].copy_from_slice(pad_right);
            ptr += pad_right.len();
            working_set = 0;
            approx_working_set_count = 32 - working_set;
            fixup_prefix = Some(padding);
        }

        let mut is_fitst_digit = true;
        let mut pop_padding_digit = || {
            if is_fitst_digit {
                is_fitst_digit = false;
                1u8
            } else {
                approx_working_set_count *= 10;
                let digit = working_set % 10;
                working_set /= 10;
                digit as u8
            }
        };

        // greedy padding logic

        // priority 0: if there is not enough room for 9 bytes of padding, pad with '0.(...)'s and then start a new block whenever possible
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

        message[..prefix.len()].copy_from_slice(prefix);
        ptr += prefix.len();

        // we used to not do these more subtle optimizations as it is not typical for mCaptcha
        // but all Anubis deployments start at offset 0, so there is very good incentive to micro-optimize
        if ptr <= 35 && fixup_prefix.is_none() {
            // priority 1: try to pad to an even position to minimize the need to poke 2 words for the lane ID
            if ptr % 2 == 1 {
                if nonce_addend
                    .checked_mul(10_000_000_000 * 2)
                    .filter(|x| *x < 1_000_000_000_000_000)
                    .is_some()
                {
                    nonce_addend *= 10;
                    let pad = pop_padding_digit();
                    nonce_addend += pad as u64;
                    message[ptr] = b'0' + pad;
                    ptr += 1;
                }
            }
            // priority 2: try to pad such that the inner nonce is at a register boundary and PSHUFD shortcut can be used (minus the lane ID)
            while (ptr + 2) % 4 != 0 {
                if nonce_addend
                    .checked_mul(10_000_000_000 * 2)
                    .filter(|x| *x < 1_000_000_000_000_000)
                    .is_some()
                {
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
                .filter(|x| *x < 1_000_000_000_000_000)
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
        nonce_addend = nonce_addend
            .checked_mul(1_000_000_000)
            .filter(|x| *x < 1_000_000_000_000_000)?;

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

        if working_set != 0 {
            return None;
        }

        Some((
            Self {
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
                approx_working_set_count: approx_working_set_count.try_into().unwrap(),
                no_trailing_zeros: fixup_prefix.is_some(),
            },
            fixup_prefix,
        ))
    }
}

/// Solves an mCaptcha/Anubis/Cap.js SHA256 PoW where the SHA-256 message is a double block (1024 bytes minus padding).
///
/// Construct: Proof := (prefix || '1' * k || ASCII_DECIMAL(nonce) || '\x80') | ('\0' * 56 + length)
///
/// Currently the mutating part is always 9 digits long.
pub struct DoubleBlockMessage {
    /// the message template for the final block, pre-padded except for the mutating part
    pub message: Align64<[u32; 16]>,

    /// the SHA-256 midstate for the previous block
    pub prefix_state: Align16<[u32; 8]>,

    /// the length of the message in bytes
    pub message_length: u64,

    /// the nonce addend
    pub nonce_addend: u64,
}

impl DoubleBlockMessage {
    /// the index of the mutating part of the digits in the message
    pub const DIGIT_IDX: u64 = 54;

    /// creates a new double block message
    pub fn new(mut prefix: &[u8], mut working_set: u32) -> Option<Self> {
        if !is_supported_lane_position(Self::DIGIT_IDX as usize / 4) {
            return None;
        }

        // construct the message buffer
        let mut prefix_state = crate::Align16(sha256::IV);

        let mut complete_blocks_before = 0;

        let mut is_fitst_digit = true;
        let mut pop_padding_digit = || {
            if is_fitst_digit {
                is_fitst_digit = false;
                1u8
            } else {
                let digit = working_set % 10;
                working_set /= 10;
                digit as u8
            }
        };

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
        // [prefix + '1' * k + '12' + '3456' + '789\x80'] | ['\0' * 56 + length]
        let mut nonce_addend = 0;
        while (ptr + 2) % 8 != 0 {
            nonce_addend *= 10;
            let pad = pop_padding_digit();
            nonce_addend += pad as u64;
            *message.get_mut(ptr)? = b'0' + pad;
            ptr += 1;
        }
        nonce_addend *= 1_000_000_000;

        // these cases are handled by the single block solver
        if ptr != Self::DIGIT_IDX as usize {
            return None;
        }

        if working_set != 0 {
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
        })
    }
}

/// A wrapper that handles both cases for decimal nonces
pub enum DecimalMessage {
    /// A single block message
    SingleBlock(SingleBlockMessage),

    /// A double block message
    DoubleBlock(DoubleBlockMessage),
}

impl DecimalMessage {
    /// creates a new decimal message
    pub fn new(input: &[u8], working_set: u32) -> Option<Self> {
        SingleBlockMessage::new(input, working_set)
            .map(Self::SingleBlock)
            .or_else(|| DoubleBlockMessage::new(input, working_set).map(Self::DoubleBlock))
    }

    /// creates a new decimal message using only IEEE 754 double precision floats that can stringify losslessly
    pub fn new_f64(
        input: &[u8],
        working_set: u32,
    ) -> Option<(Self, Option<IEEE754LosslessFixupPrefix>)> {
        SingleBlockMessage::new_f64(input, working_set)
            .map(|(message, fixup_prefix)| (Self::SingleBlock(message), fixup_prefix))
            .or_else(|| {
                DoubleBlockMessage::new(input, working_set).map(|x| (Self::DoubleBlock(x), None))
            })
    }
}

/// A message  in the go-away format
///
/// Construct: Proof := (prefix || U64(nonce)) where prefix is 32 bytes
pub struct GoAwayMessage {
    /// the challenge
    pub challenge: [u32; 8],
}

impl GoAwayMessage {
    /// creates a new go-away message
    pub fn new(challenge: [u32; 8]) -> Self {
        Self { challenge }
    }

    /// creates a new go-away message from a 32 byte challenge
    pub fn new_bytes(challenge: &[u8; 32]) -> Self {
        Self {
            challenge: core::array::from_fn(|i| {
                u32::from_be_bytes([
                    challenge[i * 4],
                    challenge[i * 4 + 1],
                    challenge[i * 4 + 2],
                    challenge[i * 4 + 3],
                ])
            }),
        }
    }

    /// creates a new go-away message from a 64 byte challenge
    pub fn new_hex(challenge: &[u8; 64]) -> Option<Self> {
        let mut prefix_fixed_up = [0; 32];
        for i in 0..32 {
            let byte_hex: [u8; 2] = challenge[i * 2..][..2].try_into().unwrap();
            let high_nibble = if byte_hex[0].is_ascii_digit() {
                byte_hex[0] - b'0'
            } else if (b'a'..=b'f').contains(&byte_hex[0]) {
                byte_hex[0] - b'a' + 10
            } else {
                return None;
            };
            let low_nibble = if byte_hex[1].is_ascii_digit() {
                byte_hex[1] - b'0'
            } else if (b'a'..=b'f').contains(&byte_hex[1]) {
                byte_hex[1] - b'a' + 10
            } else {
                return None;
            };
            prefix_fixed_up[i] = (high_nibble << 4) | low_nibble;
        }
        Some(Self::new_bytes(&prefix_fixed_up))
    }
}

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
/// A Look-Up Table for the GoToSocial algorithm
///
///
/// Type Parameters:
/// - T: How many items per SoA element
/// - A: The aligner
pub struct GoToSocialAoSoALUTOwned<
    T: ArrayLength<u32>, // how many nonces per SoA element
    A: AlignerTo<GenericArray<u32, T>, Alignment = Time4<T>>,
> {
    data: alloc::vec::Vec<GoToSocialSoALUTEntry<T, A>>,
}

/// A view of the GoToSocial AoS OA LUT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GotoSocialAoSoALUTView<
    'a,
    T: ArrayLength<u32>,
    A: AlignerTo<GenericArray<u32, T>, Alignment = Time4<T>>,
> {
    data: &'a [GoToSocialSoALUTEntry<T, A>],
}

// supports difficulties up to 1 million
#[cfg(target_feature = "avx512f")]
const BUILT_IN_LUT_16_LEN: usize = 1_000_000 / 16;

#[cfg(target_feature = "avx512f")]
#[allow(long_running_const_eval)]
static BUILT_IN_LUT_16_BUF: [GoToSocialSoALUTEntry<U16, Align64<GenericArray<u32, U16>>>;
    BUILT_IN_LUT_16_LEN] =
    unsafe { core::mem::transmute(*include_bytes!(concat!(env!("OUT_DIR"), "/gts_lut_16.bin"))) };

#[cfg(target_feature = "avx512f")]

/// A built-in view of the GoToSocial AoSOA LUT with 16 items per SoA element that should handle all difficulties up to 500K
pub static BUILT_IN_LUT_16_BUF_VIEW: GotoSocialAoSoALUTView<U16, Align64<GenericArray<u32, U16>>> =
    GotoSocialAoSoALUTView {
        data: &BUILT_IN_LUT_16_BUF,
    };

impl<'a, T: ArrayLength<u32>, A: AlignerTo<GenericArray<u32, T>, Alignment = Time4<T>>>
    GotoSocialAoSoALUTView<'a, T, A>
{
    /// Get the maximum supported nonce
    pub fn max_supported_nonce(&self) -> u64 {
        (self.data.len() as u64 * T::USIZE as u64).saturating_sub(1)
    }

    /// Get the number of bins in the LUT
    pub fn num_bins(&self) -> usize {
        self.data.len()
    }

    /// Iterate over the entries in reverse order
    pub fn iter_rev(
        &'a self,
        max_nonce: u64,
    ) -> Option<
        impl Iterator<
            Item = (
                u64, // which nonce was this based from?
                &'a GoToSocialSoALUTEntry<T, A>,
            ),
        >,
    > {
        let last_index = max_nonce / T::U64;
        if last_index > self.data.len() as u64 {
            return None;
        }
        let base_nonce = last_index * T::USIZE as u64;
        Some(
            self.data[..=last_index as usize]
                .iter()
                .rev()
                .enumerate()
                .map(move |(i, entry)| (base_nonce - i as u64 * T::U64, entry)),
        )
    }
}

/// A Look-Up Table for the GoToSocial algorithm with 16 items per SoA element
#[cfg(feature = "alloc")]
pub type GotoSocialAoSoALUT16 = GoToSocialAoSoALUTOwned<U16, Align64<GenericArray<u32, U16>>>;

/// A view of the GoToSocial AoS OA LUT with 16 items per SoA element
pub type GotoSocialAoSoALUT16View<'a> =
    GotoSocialAoSoALUTView<'a, U16, Align64<GenericArray<u32, U16>>>;

#[cfg(feature = "alloc")]
impl<T: ArrayLength<u32>, A: AlignerTo<GenericArray<u32, T>, Alignment = Time4<T>>>
    GoToSocialAoSoALUTOwned<T, A>
{
    /// Create a new Lookup Table
    pub fn new() -> Self {
        Self {
            data: alloc::vec::Vec::new(),
        }
    }

    /// Get a view of the Lookup Table  
    #[inline(always)]
    pub fn view(&self) -> GotoSocialAoSoALUTView<'_, T, A> {
        GotoSocialAoSoALUTView { data: &self.data }
    }

    /// Build the Lookup Table
    pub fn build(&mut self, max_nonce_by_alignment: u32) {
        if self.data.len() >= max_nonce_by_alignment as usize {
            return;
        }
        let additional_entries = max_nonce_by_alignment as usize - self.data.len();
        self.data.reserve(additional_entries);
        for i in self.data.len()..max_nonce_by_alignment as usize {
            let mut digits = [0; 8];

            let mut word_2s = GenericArray::default();
            let mut word_3s = GenericArray::default();
            let mut msg_lens = GenericArray::default();
            for di in 0..T::USIZE {
                let mut copy = i as u64 * T::USIZE as u64 + di as u64;
                let mut j = 8;
                loop {
                    j -= 1;
                    digits[j] = (copy % 10) as u8 + b'0';
                    copy /= 10;
                    if copy == 0 {
                        break;
                    } else if j == 0 {
                        return;
                    }
                }
                let itoa_buf = &digits[j..];
                let mut output_bytes = [0; 2 * 4];
                output_bytes[..itoa_buf.len()].copy_from_slice(itoa_buf);
                if itoa_buf.len() != 8 {
                    output_bytes[itoa_buf.len()] = 0x80;
                } else {
                    return;
                }
                let msg_len = (itoa_buf.len() as u32 + GoToSocialMessage::SEED_LEN) * 8;
                msg_lens[di] = msg_len;
                word_2s[di] = u32::from_be_bytes([
                    output_bytes[0],
                    output_bytes[1],
                    output_bytes[2],
                    output_bytes[3],
                ]);
                word_3s[di] = u32::from_be_bytes([
                    output_bytes[4],
                    output_bytes[5],
                    output_bytes[6],
                    output_bytes[7],
                ]);
            }
            self.data.push(GoToSocialSoALUTEntry {
                word_2: A::from(word_2s),
                word_3: A::from(word_3s),
                msg_len: A::from(msg_lens),
                _phantom: core::marker::PhantomData,
            });
        }
    }
}

type Time4<T> = UInt<UInt<T, B0>, B0>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A single entry in the GoToSocial SoA LUT
///
///
/// Type Parameters:
/// - T: How many items per SoA element
/// - A: The aligner
pub struct GoToSocialSoALUTEntry<
    T: ArrayLength<u32>,
    A: AlignerTo<GenericArray<u32, T>, Alignment = Time4<T>>,
> {
    pub(crate) word_2: A,
    pub(crate) word_3: A,
    pub(crate) msg_len: A,
    _phantom: core::marker::PhantomData<T>,
}

/// A message in the GoToSocial format
pub struct GoToSocialMessage {
    seed: [u8; 16],
}

impl GoToSocialMessage {
    /// The length of the seed in bytes
    // sync with build.rs
    pub const SEED_LEN: u32 = 16;

    /// creates a new go-to-social message
    pub fn new(seed: [u8; 16]) -> Self {
        Self { seed }
    }

    /// Get the seed as words
    pub fn as_words(&self) -> [u32; 4] {
        [
            u32::from_be_bytes([self.seed[0], self.seed[1], self.seed[2], self.seed[3]]),
            u32::from_be_bytes([self.seed[4], self.seed[5], self.seed[6], self.seed[7]]),
            u32::from_be_bytes([self.seed[8], self.seed[9], self.seed[10], self.seed[11]]),
            u32::from_be_bytes([self.seed[12], self.seed[13], self.seed[14], self.seed[15]]),
        ]
    }
}

/// A shared precomputed state for expanding CapJS batch challenges
pub struct CapJSEmitter {
    seed: u32,
}

#[inline(always)]
const fn fnv1a(state: u32, data: u8) -> u32 {
    let state = state ^ data as u32;
    state
        .wrapping_add(state << 1)
        .wrapping_add(state << 4)
        .wrapping_add(state << 7)
        .wrapping_add(state << 8)
        .wrapping_add(state << 24)
}

#[inline(always)]
const fn capjs_lfsr(state: u32) -> u32 {
    let state = state ^ (state << 13);
    let state = state ^ (state >> 17);
    state ^ (state << 5)
}

impl CapJSEmitter {
    /// Create a new emitter for a given challenge token
    pub const fn new(token: &[u8]) -> Self {
        let mut i = 0;
        let mut hash = 2166136261;
        while i < token.len() {
            hash = fnv1a(hash, token[i]);
            i += 1;
        }
        Self { seed: hash }
    }

    /// Emit a salt and target for the i-th subgoal
    ///
    /// Note: Cap.js nonce index starts from 1
    pub fn emit(&self, salt: &mut [u8], target: &mut [u32], i: u32) {
        let mut digits = [0; 10];
        let mut copy = i;
        let mut j = 10;
        loop {
            j -= 1;
            digits[j] = (copy % 10) as u8;
            copy /= 10;
            if copy == 0 {
                break;
            }
        }
        let itoa_buf = &digits[j..];
        let mut salt_state = self.seed;
        itoa_buf.iter().for_each(|d| {
            salt_state = fnv1a(salt_state, *d + b'0');
        });
        let mut target_state = fnv1a(salt_state, b'd');
        salt.chunks_mut(8).for_each(|d| {
            salt_state = capjs_lfsr(salt_state);
            let state_bytes = salt_state.to_be_bytes();
            let mut buf = [0; 8];
            for i in 0..4 {
                let b = state_bytes[i];
                let high_nibble = b >> 4;
                let low_nibble = b & 0xf;
                buf[i * 2] = if high_nibble < 10 {
                    high_nibble + b'0'
                } else {
                    high_nibble + b'a' - 10
                };
                buf[i * 2 + 1] = if low_nibble < 10 {
                    low_nibble + b'0'
                } else {
                    low_nibble + b'a' - 10
                };
            }
            d.copy_from_slice(&buf[..d.len()]);
        });
        target.iter_mut().for_each(|d| {
            target_state = capjs_lfsr(target_state);
            *d = target_state;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_go_to_social_aosoa_lut() {
        let mut alut = GotoSocialAoSoALUT16::new();
        alut.build(BUILT_IN_LUT_16_LEN as u32);
        assert_eq!(
            alut.data[..BUILT_IN_LUT_16_LEN],
            BUILT_IN_LUT_16_BUF[..BUILT_IN_LUT_16_LEN]
        );
    }

    #[test]
    fn test_double_block_addend_f64_safe() {
        let salt = [b'a'; 64];
        for len in 0..64 {
            if let Some((single_solver, _fixup_prefix)) =
                SingleBlockMessage::new_f64(&salt[..len], 0)
            {
                assert!(single_solver.nonce_addend <= 1_000_000_000_000_000);
            } else if let Some(double_solver) = DoubleBlockMessage::new(&salt[..len], 0) {
                assert!(double_solver.nonce_addend <= 1_000_000_000_000_000);
            } else {
                let single_solver = SingleBlockMessage::new(&salt[..len], 0);
                let double_solver = DoubleBlockMessage::new(&salt[..len], 0);
                panic!(
                    "no messagger for length {}: (u64 single block: {:?}, u64 double block: {:?})",
                    len,
                    single_solver.is_some(),
                    double_solver.is_some()
                );
            }
        }
    }

    #[test]
    fn test_prefix_position_to_lane_position() {
        let mut mapping = [0; 64];
        let x = [b'a'; 64];
        for i in 0..64 {
            let single_solver = SingleBlockMessage::new(&x[..i], 0);
            if let Some(single_solver) = single_solver {
                mapping[i] = single_solver.digit_index / 4;
            } else {
                mapping[i] = DoubleBlockMessage::DIGIT_IDX as usize / 4;
            }
        }
        assert_eq!(mapping, crate::PREFIX_OFFSET_TO_LANE_POSITION);
    }

    #[test]
    fn test_fnv1a() {
        let mut state = 2166136261;
        let data = [240, 159, 166, 132, 240, 159, 140, 136];
        data.iter().for_each(|d| {
            state = fnv1a(state, *d);
        });
        assert_eq!(state, 2868248295);
    }

    #[test]
    fn test_capjs_emitter() {
        const TOKEN: &[u8] = b"challenge token";
        const C: usize = 16;
        const S: usize = 30;
        const D: usize = 8;
        const KNOWN_ANSWER: [([u8; S], [u32; (D + 3) / 8]); C] = [
            (*b"0301c97a7ffc19cd647d324f84a2d9", [0xd4f0af52]),
            (*b"e2462bfec006f422ced5d703f2842e", [0xdf66e3e3]),
            (*b"c9dc0ae6589d3a6605e1344e4e745a", [0x425e36e1]),
            (*b"b47a610af330f9c76d0597a321c293", [0x3f743fab]),
            (*b"9c8bdae31d2ee808c5de8bff808d54", [0x0e401a5c]),
            (*b"488848fd736ecef6fcbb2e6eb7a2f8", [0xcd2ff29f]),
            (*b"6ff608b772f74727d86eafeebffe4d", [0x2f937817]),
            (*b"075dc1a5524efc3134dbc075d67d85", [0x0cbea335]),
            (*b"38f3cb0b73c3f382bbc51e3b184c35", [0xf4e72b04]),
            (*b"a01611f327205c07b8b5e0b790c35e", [0x29fe9e9b]),
            (*b"4097bda25357605354f6a05d9f5544", [0xcecadb61]),
            (*b"f62a5b07141651e21b65a0174385e3", [0x1b5bb71a]),
            (*b"8b10f44f26b28ee39ab47fd4bc905b", [0x4b836fae]),
            (*b"0f919a0ca6d088e44e4633428de8dd", [0x0fa70834]),
            (*b"ea9fd8f221b396723cc2064cfd7cb1", [0xd4038d0a]),
            (*b"5a94c8bcb3e606dd148e7723972538", [0x0a6a8e21]),
        ];

        let emitter = CapJSEmitter::new(TOKEN);
        for (i, (salt, target)) in KNOWN_ANSWER.iter().enumerate() {
            let real_i = i + 1;
            let mut salt_out = [0; S];
            let mut target_out = [0; (D + 3) / 8];
            emitter.emit(&mut salt_out, &mut target_out, real_i as u32);
            assert_eq!(
                salt_out,
                salt.as_slice(),
                "salt is different at index {}",
                i
            );
            assert_eq!(target_out, *target);
        }
    }
}
