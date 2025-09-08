use crate::{Align16, Align64, is_supported_lane_position, sha256};

// Solves an mCaptcha/Anubis SHA256 PoW where the SHA-256 message is a single block (512 bytes minus padding).
//
// Construct: Proof := (prefix || ASCII_DECIMAL(nonce))
#[derive(Debug, Clone)]
pub struct SingleBlockMessage {
    // the message template for the final block
    pub message: Align64<[u32; 16]>,

    // the SHA-256 state A-H for all prefix bytes
    pub prefix_state: [u32; 8],

    pub digit_index: usize,

    pub nonce_addend: u64,
}

impl SingleBlockMessage {
    pub fn new(mut prefix: &[u8], mut working_set: u32) -> Option<Self> {
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
        })
    }
}

pub struct DoubleBlockMessage {
    // the message template for the final block
    pub message: Align64<[u32; 16]>,

    // the SHA-256 state A-H for all prefix bytes
    pub prefix_state: Align16<[u32; 8]>,

    pub message_length: u64,

    pub nonce_addend: u64,
}

impl DoubleBlockMessage {
    pub const DIGIT_IDX: u64 = 54;

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
        // [prefix + '1' * k + '12' + '3456' + '789\x80'] | ['\0' * 12 + length]
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

pub enum DecimalMessage {
    SingleBlock(SingleBlockMessage),
    DoubleBlock(DoubleBlockMessage),
}

impl DecimalMessage {
    pub fn new(input: &[u8], working_set: u32) -> Option<Self> {
        SingleBlockMessage::new(input, working_set)
            .map(Self::SingleBlock)
            .or_else(|| DoubleBlockMessage::new(input, working_set).map(Self::DoubleBlock))
    }
}

pub struct GoAwayMessage {
    pub challenge: [u32; 8],
}

impl GoAwayMessage {
    pub fn new(challenge: [u32; 8]) -> Self {
        Self { challenge }
    }

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

    pub fn new_hex(challenge: &[u8; 64]) -> Option<Self> {
        let mut prefix_fixed_up = [0; 32];
        for i in 0..32 {
            let byte_hex: [u8; 2] = challenge[i * 2..][..2].try_into().unwrap();
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
        Some(Self::new_bytes(&prefix_fixed_up))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
