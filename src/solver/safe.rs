use crate::{
    Align16, Align64,
    message::{DecimalMessage, DoubleBlockMessage, GoAwayMessage, SingleBlockMessage},
};

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
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    pub fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }
}

impl crate::solver::Solver for SingleBlockSolver {
    fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
        // start from the blind-spot of the AVX-512 solution first
        let mut message_be = Align64(sha2::digest::generic_array::GenericArray::default());
        for i in 0..16 {
            message_be.0[i * 4..i * 4 + 4].copy_from_slice(&self.message.message[i].to_be_bytes());
        }

        for keyspace in [900_000_000..1_000_000_000, 100_000_000..900_000_000] {
            for key in keyspace {
                let mut key_copy = key;

                for i in (0..9).rev() {
                    message_be.0[self.message.digit_index + i] = (key_copy % 10) as u8 + b'0';
                    key_copy /= 10;
                }

                let mut state = self.message.prefix_state;
                sha2::compress256(&mut state, core::array::from_ref(&*message_be));

                let pass = if UPWARDS {
                    state[0] > target[0]
                } else {
                    state[0] < target[0]
                };

                if pass {
                    return Some((key + self.message.nonce_addend, state));
                }
            }
        }

        None
    }
}

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
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    pub fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }
}

impl crate::solver::Solver for DoubleBlockSolver {
    fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
        if self.attempted_nonces >= self.limit {
            return None;
        }

        let mut buffer: sha2::digest::crypto_common::Block<sha2::Sha256> = Default::default();
        for i in 0..16 {
            buffer[i * 4..i * 4 + 4].copy_from_slice(&self.message.message[i].to_be_bytes());
        }

        let mut buffer2: sha2::digest::crypto_common::Block<sha2::Sha256> = Default::default();
        buffer2[56..].copy_from_slice(&(self.message.message_length as u64 * 8).to_be_bytes());

        let mut terminal_message_schedule = [0; 64];
        terminal_message_schedule[14] = ((self.message.message_length as u64 * 8) >> 32) as u32;
        terminal_message_schedule[15] = (self.message.message_length as u64 * 8) as u32;
        crate::sha256::do_message_schedule_k_w(&mut terminal_message_schedule);

        let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

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

            let cmp_fn = if UPWARDS { u64::gt } else { u64::lt };
            if cmp_fn(&ab, &compact_target) {
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

pub enum DecimalSolver {
    SingleBlock(SingleBlockSolver),
    DoubleBlock(DoubleBlockSolver),
}

impl DecimalSolver {
    pub fn get_attempted_nonces(&self) -> u64 {
        match self {
            Self::SingleBlock(solver) => solver.get_attempted_nonces(),
            Self::DoubleBlock(solver) => solver.get_attempted_nonces(),
        }
    }

    pub fn set_limit(&mut self, limit: u64) {
        match self {
            Self::SingleBlock(solver) => solver.set_limit(limit),
            Self::DoubleBlock(solver) => solver.set_limit(limit),
        }
    }
}

impl From<SingleBlockMessage> for DecimalSolver {
    fn from(message: SingleBlockMessage) -> Self {
        Self::SingleBlock(SingleBlockSolver::from(message))
    }
}

impl From<DoubleBlockMessage> for DecimalSolver {
    fn from(message: DoubleBlockMessage) -> Self {
        Self::DoubleBlock(DoubleBlockSolver::from(message))
    }
}

impl From<DecimalMessage> for DecimalSolver {
    fn from(message: DecimalMessage) -> Self {
        match message {
            DecimalMessage::SingleBlock(message) => {
                Self::SingleBlock(SingleBlockSolver::from(message))
            }
            DecimalMessage::DoubleBlock(message) => {
                Self::DoubleBlock(DoubleBlockSolver::from(message))
            }
        }
    }
}

impl crate::solver::Solver for DecimalSolver {
    fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
        match self {
            Self::SingleBlock(solver) => solver.solve::<UPWARDS>(target),
            Self::DoubleBlock(solver) => solver.solve::<UPWARDS>(target),
        }
    }
}

pub struct GoAwaySolver {
    pub(super) challenge: [u32; 8],
    pub(super) attempted_nonces: u64,
    pub(super) limit: u64,
}

impl From<GoAwayMessage> for GoAwaySolver {
    fn from(challenge: GoAwayMessage) -> Self {
        Self {
            challenge: challenge.challenge,
            attempted_nonces: 0,
            limit: u64::MAX,
        }
    }
}

impl GoAwaySolver {
    const MSG_LEN: u32 = 10 * 4 * 8;

    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    pub fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }
}

impl crate::solver::Solver for GoAwaySolver {
    fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
        let mut buffer =
            Align16([sha2::digest::crypto_common::Block::<sha2::Sha256>::default(); 16]);
        for i in 0..8 {
            buffer[0][i * 4..i * 4 + 4].copy_from_slice(&self.challenge[i].to_be_bytes());
        }
        buffer[0][40] = 0x80;
        buffer[0][60..64].copy_from_slice(&(Self::MSG_LEN as u32).to_be_bytes());

        let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

        for key in 0..=u64::MAX {
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

            let cmp_fn = if UPWARDS { u64::gt } else { u64::lt };
            if cmp_fn(&state_ab, &compact_target) {
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
