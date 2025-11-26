#![allow(clippy::inconsistent_digit_grouping)]
#![allow(clippy::collapsible_if)]
use core::num::NonZeroU8;

use crate::{Align16, Align64, blake3, sha256};

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

    /// whether no trailing zeros are allowed
    pub no_trailing_zeros: bool,
}

#[derive(Debug, Clone, Copy)]
/// a prefix for stretching nonces whose vallidation accepts IEEE 754 double precision floats
///
/// This allows JS numbers to be stretched as long as a regular u64 integer allowing code reuse.
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
        let mut approx_working_set_count = 1u32;

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
                approx_working_set_count = approx_working_set_count.saturating_mul(10);
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
                approx_working_set_count = approx_working_set_count.saturating_mul(10);
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

/// Binary message with a fixed layout
#[derive(Debug, Clone)]
pub struct BinaryMessage {
    /// the SHA-256 midstate for the previous block
    pub prefix_state: Align16<[u32; 8]>,

    /// the residual salt
    pub salt_residual: [u8; 64],

    /// the length of the residual salt
    pub salt_residual_len: usize,

    /// the number of bytes of the nonce
    /// Guaranteed to be less or equal to 8
    pub nonce_byte_count: NonZeroU8,

    /// message length in bytes
    pub message_length: usize,
}

impl BinaryMessage {
    /// creates a new binary message
    pub fn new(salt: &[u8], nonce_byte_count: NonZeroU8) -> Self {
        assert!(
            nonce_byte_count.get() <= 8,
            "nonce_byte_count must be less or equal to 8"
        );
        let mut prefix_state = crate::Align16(sha256::IV);

        let mut chunks = salt.chunks_exact(64);
        for block in &mut chunks {
            sha256::digest_block(
                &mut prefix_state,
                &core::array::from_fn(|i| {
                    u32::from_be_bytes([
                        block[i * 4],
                        block[i * 4 + 1],
                        block[i * 4 + 2],
                        block[i * 4 + 3],
                    ])
                }),
            );
        }
        let remainder = chunks.remainder();
        let mut salt_residual = [0; 64];
        salt_residual[..remainder.len()].copy_from_slice(remainder);
        Self {
            prefix_state,
            salt_residual,
            salt_residual_len: remainder.len(),
            nonce_byte_count,
            message_length: salt.len() + nonce_byte_count.get() as usize,
        }
    }
}

/// A message in the cerberus format
///
/// Note cerberus official solver only supports 32-bit range nonces, but the validator accepts machine sized nonces and should always remain inter-block
pub enum CerberusMessage {
    /// A decimal message
    Decimal(CerberusDecimalMessage),
    /// A binary message (0.4.6+)
    Binary(CerberusBinaryMessage),
}

/// A message in the cerberus binary format (0.4.6+)
///
/// Construct: Proof := (prefix || U64(nonce))
pub struct CerberusBinaryMessage {
    pub(crate) midstate: Align16<[u32; 8]>,
    pub(crate) first_word: u32,
}

impl CerberusBinaryMessage {
    /// Create a new Cerberus message
    pub fn new(salt: &[u8], first_word: u32) -> Self {
        let prehash = ::blake3::hash(salt).to_hex();
        Self::new_prehashed(prehash.as_bytes().try_into().unwrap(), first_word)
    }

    /// Create a new Cerberus message with a prehashed midstate
    pub fn new_prehashed(prehash: &[u8; 64], first_word: u32) -> Self {
        let mut block = [0; 16];
        for i in 0..16 {
            block[i] = u32::from_le_bytes([
                prehash[i * 4],
                prehash[i * 4 + 1],
                prehash[i * 4 + 2],
                prehash[i * 4 + 3],
            ]);
        }
        let midstate = crate::blake3::compress8(
            &crate::blake3::IV,
            &block,
            0,
            64,
            crate::blake3::FLAG_CHUNK_START,
        );

        Self {
            midstate: Align16(midstate),
            first_word,
        }
    }
}

#[derive(Debug, Clone)]
/// A message in the cerberus decimal format (pre 0.4.6)
///
/// Construct: Proof := (prefix || ASCII_GO_INT_DECIMAL(nonce))
pub struct CerberusDecimalMessage {
    pub(crate) prefix_state: Align16<[u32; 8]>,
    pub(crate) salt_residual: Align64<[u8; 64]>,
    pub(crate) salt_residual_len: usize,
    pub(crate) flags: u32,
    pub(crate) nonce_addend: u64,
}

impl CerberusDecimalMessage {
    /// Create a new Cerberus message
    ///
    /// End-to-end salt construction: `${challenge}|${inputNonce}|${ts}|${signature}|`
    pub fn new(salt: &[u8], mut working_set: u32) -> Option<Self> {
        // nonce placement in blake3 is less important than sha256, both early and late salts have strategies to elide computation.
        //
        // so we will keep it in 32-bit range just in case we met a 32-bit server, but in practice this is rarely seen.
        //
        // u32::MAX is 4294967295 (10 digits), we will pop the first digit as outer loop and at most 3 other blocks need to be mutated
        // the last block is byte-order sensitive and needs a left shift to fix

        // actual tree-based hashing is not supported yet, it kicks in at 1024 bytes
        // we can leave 24 bytes of headroom for nonce maneuvering.
        //
        // it is also unlikely any challenge will hash such big chunks
        if salt.len() > 1000 {
            return None;
        }
        let mut chunks = salt.chunks_exact(64);
        let mut prefix_state = crate::Align16(blake3::IV);
        let mut flags = blake3::FLAG_CHUNK_START | blake3::FLAG_CHUNK_END | blake3::FLAG_ROOT;

        for (i, block) in (&mut chunks).enumerate() {
            let block = core::array::from_fn(|i| {
                u32::from_le_bytes([
                    block[i * 4],
                    block[i * 4 + 1],
                    block[i * 4 + 2],
                    block[i * 4 + 3],
                ])
            });
            let this_flag = if i == 0 { blake3::FLAG_CHUNK_START } else { 0 };

            let output = blake3::compress8(&prefix_state, &block, 0, 64, this_flag);
            prefix_state.copy_from_slice(&output);
            flags &= !blake3::FLAG_CHUNK_START;
        }
        let remainder = chunks.remainder();
        let mut salt_residual = crate::Align64([0; 64]);
        salt_residual.0[..remainder.len()].copy_from_slice(remainder);
        let mut ptr = remainder.len();

        let mut nonce_addend = 0;
        // TODO: figure out how to search more than 9G of nonce space for the edge case of 54 bytes modulo 64
        // this is far from the typical case for Cerberus so not very important (even the official solver only searches 4G of nonce space)
        if remainder.len() >= 55 {
            // not enough room for 9 digits, assume 64-bit server and pad generously
            let head_digit = (working_set % 8) as u8 + 1; // i64::MAX starts with 9 so we can only use 1-8 as head digit
            nonce_addend = head_digit as u64;
            salt_residual.0[remainder.len()] = head_digit as u8 + b'0';
            working_set /= 8;
            for x in (remainder.len() + 1)..64 {
                let digit = working_set % 10;
                salt_residual.0[x] = digit as u8 + b'0';
                nonce_addend *= 10;
                nonce_addend += digit as u64;
                working_set /= 10;
            }
            ptr = 0;
            let block = core::array::from_fn(|i| {
                u32::from_le_bytes([
                    salt_residual[i * 4],
                    salt_residual[i * 4 + 1],
                    salt_residual[i * 4 + 2],
                    salt_residual[i * 4 + 3],
                ])
            });

            let output = blake3::compress8(
                &prefix_state,
                &block,
                0,
                64,
                blake3::FLAG_CHUNK_START & flags,
            );
            prefix_state.copy_from_slice(&output);
            flags &= !blake3::FLAG_CHUNK_START;
            salt_residual.fill(0);
        }

        let head_digit = (working_set % 9) as u8 + 1;
        salt_residual[ptr] = head_digit as u8 + b'0';
        nonce_addend *= 10;
        nonce_addend += head_digit as u64;
        working_set /= 9;
        while working_set != 0 {
            ptr += 1;
            let digit = working_set % 10;
            salt_residual[ptr] = digit as u8 + b'0';
            nonce_addend *= 10;
            nonce_addend += digit as u64;
            working_set /= 10;
        }

        if ptr + 9 >= 64 {
            return None;
        }

        ptr += 1;

        for i in 0..9 {
            salt_residual[ptr + i] = b'0';
        }

        Some(Self {
            prefix_state,
            salt_residual_len: ptr,
            salt_residual,
            flags,
            nonce_addend: nonce_addend * 1_000_000_000,
        })
    }
}

/// A message in the go-away format
///
/// Construct: Proof := (prefix || U64(nonce)) where prefix is 32 bytes
#[derive(Clone)]
pub struct GoAwayMessage {
    /// the challenge
    pub(crate) challenge: [u32; 8],
    pub(crate) high_word: u32,
}

impl GoAwayMessage {
    /// creates a new go-away message
    pub fn new(challenge: [u32; 8], high_word: u32) -> Self {
        Self {
            challenge,
            high_word,
        }
    }

    /// sets the high word of the message
    pub fn set_high_word(&mut self, high_word: u32) {
        self.high_word = high_word;
    }

    /// creates a new go-away message from a 32 byte challenge
    pub fn new_bytes(challenge: &[u8; 32], high_word: u32) -> Self {
        Self {
            challenge: core::array::from_fn(|i| {
                u32::from_be_bytes([
                    challenge[i * 4],
                    challenge[i * 4 + 1],
                    challenge[i * 4 + 2],
                    challenge[i * 4 + 3],
                ])
            }),
            high_word,
        }
    }

    /// creates a new go-away message from a 64 byte challenge
    pub fn new_hex(challenge: &[u8; 64], high_word: u32) -> Option<Self> {
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
        Some(Self::new_bytes(&prefix_fixed_up, high_word))
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
