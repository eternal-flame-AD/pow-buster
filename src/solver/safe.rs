use sha2::digest::generic_array::GenericArray;

use crate::{
    Align16, Align64, decompose_blocks_mut,
    message::{
        BinaryMessage, CerberusMessage, DecimalMessage, DoubleBlockMessage, GoAwayMessage,
        SingleBlockMessage,
    },
};

/// Safe decimal nonce single block solver.
///
///
/// Current implementation: generic sha2 crate fallback.
pub struct SingleBlockSolver {
    pub(super) message: SingleBlockMessage,

    pub(super) attempted_nonces: u64,

    pub(super) limit: u64,
}

impl From<SingleBlockMessage> for SingleBlockSolver {
    fn from(message: SingleBlockMessage) -> Self {
        Self {
            message,
            attempted_nonces: 0,
            limit: u64::MAX,
        }
    }
}

impl SingleBlockSolver {
    /// Set the limit.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Get the attempted nonces.
    pub fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }
}

impl SingleBlockSolver {
    fn solve_impl<const TYPE: u8, const NO_TRAILING_ZEROS: bool>(
        &mut self,
        target: u64,
        mask: u64,
    ) -> Option<(u64, [u32; 8])> {
        let mut message_be = Align64(sha2::digest::generic_array::GenericArray::default());
        for i in 0..16 {
            message_be.0[i * 4..i * 4 + 4].copy_from_slice(&self.message.message[i].to_be_bytes());
        }
        let target = target & mask;

        for nonzero_digit in 1..=9 {
            for key in 0..100_000_000 {
                let mut key_copy = key;

                if NO_TRAILING_ZEROS {
                    for i in (0..8).rev() {
                        message_be.0[self.message.digit_index + i] = (key_copy % 10) as u8 + b'0';
                        key_copy /= 10;
                    }
                    message_be.0[self.message.digit_index + 8] = b'0' + nonzero_digit as u8;
                } else {
                    for i in (1..9).rev() {
                        message_be.0[self.message.digit_index + i] = (key_copy % 10) as u8 + b'0';
                        key_copy /= 10;
                    }
                    message_be.0[self.message.digit_index] = b'0' + nonzero_digit as u8;
                }

                let mut state = self.message.prefix_state;
                sha2::compress256(&mut state, core::array::from_ref(&*message_be));

                let pass = if TYPE == crate::solver::SOLVE_TYPE_GT {
                    (state[0] as u64) << 32 | (state[1] as u64) > target
                } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                    (state[0] as u64) << 32 | (state[1] as u64) < target
                } else {
                    ((state[0] as u64) << 32 | (state[1] as u64)) & mask == target & mask
                };

                if pass {
                    let mut transformed_key = key;
                    if NO_TRAILING_ZEROS {
                        transformed_key *= 10;
                        transformed_key += nonzero_digit;
                    } else {
                        transformed_key += 100_000_000 * nonzero_digit;
                    }
                    return Some((transformed_key + self.message.nonce_addend, state));
                }
            }
        }

        None
    }
}

impl crate::solver::Solver for SingleBlockSolver {
    fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, [u32; 8])> {
        if self.message.no_trailing_zeros {
            self.solve_impl::<TYPE, true>(target, mask)
        } else {
            self.solve_impl::<TYPE, false>(target, mask)
        }
    }
}

/// Safe decimal nonce double block solver.
///
///
/// Current implementation: generic sha2 crate fallback.
pub struct DoubleBlockSolver {
    pub(super) message: DoubleBlockMessage,
    pub(super) attempted_nonces: u64,

    pub(super) limit: u64,
}

impl From<DoubleBlockMessage> for DoubleBlockSolver {
    fn from(message: DoubleBlockMessage) -> Self {
        Self {
            message,
            attempted_nonces: 0,
            limit: u64::MAX,
        }
    }
}

impl DoubleBlockSolver {
    /// Set the limit.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Get the attempted nonces.
    pub fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }
}

impl crate::solver::Solver for DoubleBlockSolver {
    fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, [u32; 8])> {
        if self.attempted_nonces >= self.limit {
            return None;
        }
        let target = target & mask;

        let mut buffer: sha2::digest::crypto_common::Block<sha2::Sha256> = Default::default();
        for i in 0..16 {
            buffer[i * 4..i * 4 + 4].copy_from_slice(&self.message.message[i].to_be_bytes());
        }

        let mut buffer2: sha2::digest::crypto_common::Block<sha2::Sha256> = Default::default();
        buffer2[56..].copy_from_slice(&(self.message.message_length * 8).to_be_bytes());

        let mut terminal_message_schedule = [0; 64];
        terminal_message_schedule[14] = ((self.message.message_length * 8) >> 32) as u32;
        terminal_message_schedule[15] = (self.message.message_length * 8) as u32;
        crate::sha256::do_message_schedule_k_w(&mut terminal_message_schedule);

        for key in (if self.message.nonce_addend == 0 {
            100_000_000
        } else {
            0
        })..1_000_000_000
        {
            let mut key_copy = key;

            for j in (0..9).rev() {
                let digit = key_copy % 10;
                key_copy /= 10;
                buffer[DoubleBlockMessage::DIGIT_IDX as usize + j] = digit as u8 + b'0'; // TODO: fix this
            }

            let mut state = self.message.prefix_state;
            sha2::compress256(&mut state, &[buffer]);

            let save_a = state[0];
            let save_b = state[1];

            crate::sha256::sha2_arx_without_constants::<0, 64>(
                &mut state,
                terminal_message_schedule,
            );

            state[0] = state[0].wrapping_add(save_a);
            state[1] = state[1].wrapping_add(save_b);

            let ab = (state[0] as u64) << 32 | (state[1] as u64);

            let cmp_fn = |x: &u64, y: &u64| {
                if TYPE == crate::solver::SOLVE_TYPE_GT {
                    x > y
                } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                    x < y
                } else {
                    x & mask == y & mask
                }
            };
            if cmp_fn(&ab, &target) {
                crate::unlikely();

                let mut state = self.message.prefix_state;
                sha2::compress256(&mut state, &[buffer, buffer2]);
                return Some((key as u64 + self.message.nonce_addend, *state));
            }

            self.attempted_nonces += 1;

            if self.attempted_nonces >= self.limit {
                return None;
            }
        }

        crate::unlikely();

        None
    }
}

#[macro_use]
#[path = "impl_decimal_solver.rs"]
mod impl_decimal_solver;

impl_decimal_solver!(
    [SingleBlockSolver, DoubleBlockSolver] => DecimalSolver
);

/// SHA-NI GoAway solver.
///
///
/// Current implementation: generic sha2 crate fallback.
pub struct GoAwaySolver {
    pub(super) challenge: [u32; 8],
    pub(super) attempted_nonces: u64,
    pub(super) limit: u64,
    pub(super) fixed_high_word: Option<u32>,
}

impl From<GoAwayMessage> for GoAwaySolver {
    fn from(challenge: GoAwayMessage) -> Self {
        Self {
            challenge: challenge.challenge,
            attempted_nonces: 0,
            limit: u64::MAX,
            fixed_high_word: None,
        }
    }
}

impl GoAwaySolver {
    const MSG_LEN: u32 = 10 * 4 * 8;

    /// Set the limit.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Get the attempted nonces.
    pub fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }

    /// Set the fixed high word.
    pub fn set_fixed_high_word(&mut self, high_word: u32) {
        self.fixed_high_word = Some(high_word);
    }
}

impl crate::solver::Solver for GoAwaySolver {
    fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, [u32; 8])> {
        let target = target & mask;

        let mut buffer =
            Align16([sha2::digest::crypto_common::Block::<sha2::Sha256>::default(); 16]);
        for i in 0..8 {
            buffer[0][i * 4..i * 4 + 4].copy_from_slice(&self.challenge[i].to_be_bytes());
        }
        buffer[0][40] = 0x80;
        buffer[0][60..64].copy_from_slice(&(Self::MSG_LEN).to_be_bytes());

        let start = (self.fixed_high_word.unwrap_or(0) as u64) << 32;
        let stop = if let Some(high_word) = self.fixed_high_word {
            (high_word as u64 + 1) << 32 - 1
        } else {
            u64::MAX
        };
        for key in start..=stop {
            unsafe {
                *buffer[0].as_mut_ptr().add(32).cast::<u64>() =
                    u64::from_ne_bytes(key.to_be_bytes());
            }

            let mut state = crate::sha256::IV;
            sha2::compress256(&mut state, &*buffer);

            state[0] = state[0].wrapping_add(crate::sha256::IV[0]);
            state[1] = state[1].wrapping_add(crate::sha256::IV[1]);

            let state_ab = (state[0] as u64) << 32 | (state[1] as u64);
            self.attempted_nonces += 1;

            let cmp_fn = |x: &u64, y: &u64| {
                if TYPE == crate::solver::SOLVE_TYPE_GT {
                    x > y
                } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                    x < y
                } else {
                    x & mask == y & mask
                }
            };
            if cmp_fn(&state_ab, &target) {
                crate::unlikely();

                return Some((key, state));
            }

            if self.attempted_nonces >= self.limit {
                return None;
            }
        }
        crate::unlikely();

        None
    }
}

/// Safe binary nonce solver.
///
/// Output: nonce in little endian order
///
/// Current implementation: generic sha2 crate fallback.
pub struct BinarySolver {
    pub(super) message: BinaryMessage,
    pub(super) attempted_nonces: u64,
    pub(super) limit: u64,
}

impl From<BinaryMessage> for BinarySolver {
    fn from(message: BinaryMessage) -> Self {
        Self {
            message,
            attempted_nonces: 0,
            limit: u64::MAX,
        }
    }
}

impl BinarySolver {
    /// Set the limit.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Get the attempted nonces.
    pub fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }
}

impl crate::solver::Solver for BinarySolver {
    fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, [u32; 8])> {
        let salt = &self.message.salt_residual[..self.message.salt_residual_len];
        let mut blocks = [GenericArray::default(); 2];
        blocks[0][..salt.len()].copy_from_slice(salt);
        let mut ptr = salt.len();
        let mut cur_block = 0;

        for _ in 0..self.message.nonce_byte_count.get() {
            blocks[cur_block][ptr] = 0;
            ptr += 1;
            if ptr == 64 {
                cur_block = 1;
                ptr = 0;
            }
        }
        blocks[cur_block][ptr] = 0x80;
        ptr += 1;
        if ptr + 8 > 64 {
            cur_block = 1;
        }
        blocks[cur_block][(64 - 8)..]
            .copy_from_slice(&(self.message.message_length * 8).to_be_bytes());

        let used_blocks = &mut blocks[..=cur_block];

        for x in 0..(self
            .limit
            .min(256u64.saturating_pow(self.message.nonce_byte_count.get() as u32))
            .max(1))
        {
            let mut state = self.message.prefix_state;
            let nonce_bytes = &x.to_le_bytes()[..self.message.nonce_byte_count.get() as usize];
            for i in 0..self.message.nonce_byte_count.get() as usize {
                unsafe {
                    used_blocks
                        .as_mut_ptr()
                        .cast::<u8>()
                        .add(self.message.salt_residual_len + i)
                        .write(nonce_bytes[i]);
                }
            }

            sha2::compress256(&mut state, &used_blocks);

            let cmp_fn = |x: u64, y: u64| {
                if TYPE == crate::solver::SOLVE_TYPE_GT {
                    x > y
                } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                    x < y
                } else {
                    x & mask == y & mask
                }
            };
            if cmp_fn((state[0] as u64) << 32 | (state[1] as u64), target) {
                return Some((x, state.0));
            }

            self.attempted_nonces += 1;

            if self.attempted_nonces >= self.limit {
                return None;
            }
        }

        None
    }
}

/// Safe Cerberus solver.
///
///
/// Current implementation: scalar fallback.
pub struct CerberusSolver {
    message: CerberusMessage,
    attempted_nonces: u64,
    limit: u64,
}

impl From<CerberusMessage> for CerberusSolver {
    fn from(message: CerberusMessage) -> Self {
        Self {
            message,
            attempted_nonces: 0,
            limit: !0,
        }
    }
}

impl CerberusSolver {
    /// Set the limit.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Get the attempted nonces.   
    pub fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }
}

impl crate::solver::Solver for CerberusSolver {
    fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, [u32; 8])> {
        debug_assert_eq!(target, 0);

        let remaining_limit = self.limit.saturating_sub(self.attempted_nonces);

        let mut msg = core::array::from_fn(|i| {
            u32::from_le_bytes([
                self.message.salt_residual[i * 4],
                self.message.salt_residual[i * 4 + 1],
                self.message.salt_residual[i * 4 + 2],
                self.message.salt_residual[i * 4 + 3],
            ])
        });
        assert!(
            self.message.salt_residual_len + 8 < msg.len() * core::mem::size_of::<u32>(),
            "there must be at least 9 bytes of headroom for the nonce"
        );
        for nonce in 0u64..remaining_limit {
            let mut nonce_copy = nonce;
            for i in (0..9).rev() {
                let msg = decompose_blocks_mut(&mut msg);
                #[cfg(target_endian = "little")]
                unsafe {
                    *msg.get_unchecked_mut(self.message.salt_residual_len + i) =
                        (nonce_copy % 10) as u8 + b'0';
                }
                #[cfg(target_endian = "big")]
                {
                    *msg.get_unchecked_mut(self.message.salt_residual_len + i) =
                        (nonce_copy % 10) as u8 + b'0';
                }
                nonce_copy /= 10;
            }
            debug_assert_eq!(nonce_copy, 0);

            let hash = crate::blake3::compress8(
                &mut self.message.prefix_state,
                &msg,
                0,
                self.message.salt_residual_len as u32 + 9,
                self.message.flags,
            );
            self.attempted_nonces += 1;
            if hash[0] & mask as u32 == 0 {
                crate::unlikely();

                return Some(((nonce + self.message.nonce_addend) as u64, hash));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solve_decimal() {
        crate::solver::tests::test_decimal_validator::<DecimalSolver, _>(|prefix, search_space| {
            if let Some(solver) = SingleBlockMessage::new(prefix, search_space).map(Into::into) {
                Some(DecimalSolver::SingleBlock(solver))
            } else {
                DoubleBlockMessage::new(prefix, search_space).map(Into::into)
            }
        });
    }

    #[test]
    fn test_solve_cerberus() {
        crate::solver::tests::test_cerberus_validator::<CerberusSolver, _>(|prefix| {
            CerberusMessage::new(prefix, 0).map(Into::into)
        });
    }

    #[test]
    fn test_solve_decimal_f64() {
        crate::solver::tests::test_decimal_validator_f64_safe::<DecimalSolver, _>(
            |prefix, search_space| {
                if let Some((solver, p)) =
                    SingleBlockMessage::new_f64(prefix, search_space).map(|(x, p)| (x.into(), p))
                {
                    Some((DecimalSolver::SingleBlock(solver), p))
                } else {
                    DoubleBlockMessage::new(prefix, search_space)
                        .map(|x| (DecimalSolver::DoubleBlock(x.into()), None))
                }
            },
        );
    }

    #[test]
    fn test_solve_binary() {
        crate::solver::tests::test_binary_validator::<BinarySolver, _>(
            |prefix, nonce_byte_count| {
                BinarySolver::from(BinaryMessage::new(prefix, nonce_byte_count))
            },
        )
    }

    #[test]
    fn test_solve_goaway() {
        crate::solver::tests::test_goaway_validator::<GoAwaySolver, _>(|prefix| {
            GoAwaySolver::from(GoAwayMessage::new(core::array::from_fn(|i| {
                u32::from_be_bytes([
                    prefix[i * 4],
                    prefix[i * 4 + 1],
                    prefix[i * 4 + 2],
                    prefix[i * 4 + 3],
                ])
            })))
        });
    }
}
