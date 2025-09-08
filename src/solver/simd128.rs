use core::arch::wasm32::*;

use crate::{
    Align16, PREFIX_OFFSET_TO_LANE_POSITION, SWAP_DWORD_BYTE_ORDER, decompose_blocks_mut,
    is_supported_lane_position,
    message::{DecimalMessage, DoubleBlockMessage, GoAwayMessage, SingleBlockMessage},
};

static LANE_ID_MSB_STR: Align16<[u8; 5 * 16]> =
    Align16(*b"11111111112222222222333333333344444444445555555555666666666677777777778888888888");

static LANE_ID_LSB_STR: Align16<[u8; 5 * 16]> =
    Align16(*b"01234567890123456789012345678901234567890123456789012345678901234567890123456789");

#[inline(always)]
fn load_lane_id_epi32(src: &Align16<[u8; 5 * 16]>, set_idx: usize) -> v128 {
    #[allow(unused_unsafe)]
    unsafe {
        u32x4(
            src[set_idx * 4] as _,
            src[set_idx * 4 + 1] as _,
            src[set_idx * 4 + 2] as _,
            src[set_idx * 4 + 3] as _,
        )
    }
}

pub struct SingleBlockSolver {
    message: SingleBlockMessage,

    attempted_nonces: u64,

    limit: u64,
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
        let lane_id_0_word_idx = self.message.digit_index / 4;
        if !is_supported_lane_position(lane_id_0_word_idx) {
            return None;
        }
        let lane_id_1_word_idx = (self.message.digit_index + 1) / 4;

        for i in (self.message.digit_index as usize..).take(9) {
            let message = decompose_blocks_mut(&mut self.message.message);
            message[SWAP_DWORD_BYTE_ORDER[i]] = b'0';
        }

        let mut hotstart_state = self.message.prefix_state;
        crate::sha256::sha2_arx::<0>(
            &mut hotstart_state,
            &self.message.message[..lane_id_0_word_idx],
        );

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
                let lane_id_0_byte_idx = this.message.digit_index % 4;
                let lane_id_1_byte_idx = (this.message.digit_index + 1) % 4;

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
                            let message_bytes = decompose_blocks_mut(&mut this.message.message);
                            let mut key_copy = inner_key;
                            for i in (0..7).rev() {
                                let output = key_copy % 10;
                                key_copy /= 10;
                                *message_bytes.get_unchecked_mut(
                                    *SWAP_DWORD_BYTE_ORDER
                                        .get_unchecked(this.message.digit_index + i + 2),
                                ) = output as u8 + b'0';
                            }

                            if key_copy != 0 {
                                debug_assert_eq!(key_copy, 0);
                                core::hint::unreachable_unchecked();
                            }
                        }

                        let mut blocks =
                            core::array::from_fn(|i| u32x4_splat(this.message.message[i]));
                        blocks[LANE_ID_0_WORD_IDX] =
                            v128_or(blocks[LANE_ID_0_WORD_IDX], lane_id_0_or_value);

                        if LANE_ID_1_INCREMENT {
                            blocks[LANE_ID_0_WORD_IDX + LANE_ID_1_INCREMENT as usize] = v128_or(
                                blocks[LANE_ID_0_WORD_IDX + LANE_ID_1_INCREMENT as usize],
                                lane_id_1_or_value,
                            );
                        }

                        let mut state = core::array::from_fn(|i| u32x4_splat(hotstart_state[i]));
                        crate::sha256::simd128::multiway_arx::<LANE_ID_0_WORD_IDX>(
                            &mut state,
                            &mut blocks,
                        );

                        let result_a =
                            u32x4_add(state[0], u32x4_splat(this.message.prefix_state[0]));

                        let cmp_fn = if UPWARDS { u32x4_le } else { u32x4_ge };

                        let a_not_met_target = cmp_fn(result_a, u32x4_splat(target));

                        if !u32x4_all_true(a_not_met_target) {
                            crate::unlikely();

                            let mut extract = [0u32; 4];
                            v128_store(extract.as_mut_ptr().cast(), result_a);
                            let success_lane_idx = extract
                                .iter()
                                .position(|x| if UPWARDS { *x > target } else { *x < target })
                                .unwrap();
                            let nonce_prefix = 10 + 4 * prefix_set_index + success_lane_idx;

                            // stamp the lane ID back onto the message
                            {
                                let message_bytes = decompose_blocks_mut(&mut this.message.message);
                                *message_bytes.get_unchecked_mut(
                                    *SWAP_DWORD_BYTE_ORDER.get_unchecked(this.message.digit_index),
                                ) = (nonce_prefix / 10) as u8 + b'0';
                                *message_bytes.get_unchecked_mut(
                                    *SWAP_DWORD_BYTE_ORDER
                                        .get_unchecked(this.message.digit_index + 1),
                                ) = (nonce_prefix % 10) as u8 + b'0';
                            }

                            // the nonce is the 7 digits in the message, plus the first two digits recomputed from the lane index
                            return Some(
                                nonce_prefix as u64 * 10u64.pow(7)
                                    + inner_key as u64
                                    + this.message.nonce_addend,
                            );
                        }

                        this.attempted_nonces += 4;
                    }

                    if this.attempted_nonces >= this.limit {
                        return None;
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

        let nonce = match lane_id_0_word_idx {
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
            _ => unsafe { core::hint::unreachable_unchecked() },
        }?;

        // recompute the hash from the beginning
        // this prevents the compiler from having to compute the final B-H registers alive in tight loops
        let mut final_sha_state = self.message.prefix_state;
        crate::sha256::digest_block(&mut final_sha_state, &self.message.message);

        Some((nonce, final_sha_state))
    }
}

pub struct DoubleBlockSolver {
    message: DoubleBlockMessage,
    attempted_nonces: u64,

    limit: u64,
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
        if !is_supported_lane_position(DoubleBlockMessage::DIGIT_IDX as usize / 4) {
            return None;
        }

        if self.attempted_nonces >= self.limit {
            return None;
        }

        for i in (DoubleBlockMessage::DIGIT_IDX as usize..).take(9) {
            let message = decompose_blocks_mut(&mut self.message.message);
            message[SWAP_DWORD_BYTE_ORDER[i]] = b'0';
        }

        let mut partial_state = Align16(self.message.prefix_state);
        crate::sha256::sha2_arx::<0>(&mut partial_state, &self.message.message[..13]);

        let mut terminal_message_schedule = Align16([0; 64]);
        terminal_message_schedule[14] = ((self.message.message_length as u64 * 8) >> 32) as u32;
        terminal_message_schedule[15] = (self.message.message_length as u64 * 8) as u32;
        crate::sha256::do_message_schedule_k_w(&mut terminal_message_schedule);

        for prefix_set_index in 0..((100 - 10) / 4) {
            unsafe {
                let lane_id_0_or_value =
                    u32x4_shl(load_lane_id_epi32(&LANE_ID_MSB_STR, prefix_set_index), 8);
                let lane_id_1_or_value = load_lane_id_epi32(&LANE_ID_LSB_STR, prefix_set_index);

                let lane_index_value_v = v128_or(
                    u32x4_splat(self.message.message[13] as _),
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
                        u32x4_splat(self.message.message[0] as _),
                        u32x4_splat(self.message.message[1] as _),
                        u32x4_splat(self.message.message[2] as _),
                        u32x4_splat(self.message.message[3] as _),
                        u32x4_splat(self.message.message[4] as _),
                        u32x4_splat(self.message.message[5] as _),
                        u32x4_splat(self.message.message[6] as _),
                        u32x4_splat(self.message.message[7] as _),
                        u32x4_splat(self.message.message[8] as _),
                        u32x4_splat(self.message.message[9] as _),
                        u32x4_splat(self.message.message[10] as _),
                        u32x4_splat(self.message.message[11] as _),
                        u32x4_splat(self.message.message[12] as _),
                        lane_index_value_v,
                        u32x4_splat(cum0 as _),
                        u32x4_splat(cum1 as _),
                    ];

                    let mut state = core::array::from_fn(|i| u32x4_splat(partial_state[i]));
                    crate::sha256::simd128::multiway_arx::<13>(&mut state, &mut blocks);

                    state
                        .iter_mut()
                        .zip(self.message.prefix_state.iter())
                        .for_each(|(state, prefix_state)| {
                            *state = u32x4_add(*state, u32x4_splat(*prefix_state as _));
                        });

                    let save_a = state[0];

                    crate::sha256::simd128::bcst_multiway_arx::<14>(
                        &mut state,
                        &terminal_message_schedule,
                    );

                    let result_a = u32x4_add(state[0], save_a);

                    let cmp_fn = if UPWARDS { u32x4_le } else { u32x4_ge };

                    let a_not_met_target = cmp_fn(result_a, u32x4_splat(target[0]));

                    if !u32x4_all_true(a_not_met_target) {
                        crate::unlikely();

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

                        self.message.message[14] = cum0;
                        self.message.message[15] = cum1;
                        // stamp the lane ID back onto the message
                        {
                            let message_bytes = decompose_blocks_mut(&mut self.message.message);
                            *message_bytes.get_unchecked_mut(
                                *SWAP_DWORD_BYTE_ORDER
                                    .get_unchecked(DoubleBlockMessage::DIGIT_IDX as usize),
                            ) = (nonce_prefix / 10) as u8 + b'0';
                            *message_bytes.get_unchecked_mut(
                                *SWAP_DWORD_BYTE_ORDER
                                    .get_unchecked(DoubleBlockMessage::DIGIT_IDX as usize + 1),
                            ) = (nonce_prefix % 10) as u8 + b'0';
                        }

                        // recompute the hash from the beginning
                        // this prevents the compiler from having to compute the final B-H registers alive in tight loops
                        let mut final_sha_state = self.message.prefix_state;
                        crate::sha256::digest_block(&mut final_sha_state, &self.message.message);

                        let mut terminal_message_without_constants = [0; 16];
                        terminal_message_without_constants[14] =
                            ((self.message.message_length as u64 * 8) >> 32) as u32;
                        terminal_message_without_constants[15] =
                            (self.message.message_length as u64 * 8) as u32;
                        crate::sha256::digest_block(
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
                            + self.message.nonce_addend;

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

        crate::unlikely();

        None
    }
}

pub enum DecimalSolver {
    SingleBlock(SingleBlockSolver),
    DoubleBlock(DoubleBlockSolver),
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

impl crate::solver::Solver for DecimalSolver {
    fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
        match self {
            Self::SingleBlock(solver) => solver.solve::<UPWARDS>(target),
            Self::DoubleBlock(solver) => solver.solve::<UPWARDS>(target),
        }
    }
}

pub struct GoAwaySolver {
    challenge: [u32; 8],
    attempted_nonces: u64,
    limit: u64,
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
        unsafe {
            if !is_supported_lane_position(PREFIX_OFFSET_TO_LANE_POSITION[0]) {
                return None;
            }

            let lane_id_v = u32x4(0, 1, 2, 3);

            let mut prefix_state = crate::sha256::IV;
            crate::sha256::ingest_message_prefix(&mut prefix_state, self.challenge);

            for high_word in 0..=u32::MAX {
                let mut partial_state = prefix_state;
                crate::sha256::sha2_arx::<8>(&mut partial_state, &[high_word]);

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

                    crate::sha256::simd128::multiway_arx::<9>(&mut state, &mut msg);
                    let result_a = u32x4_add(state[0], u32x4_splat(crate::sha256::IV[0]));
                    let cmp_fn = if UPWARDS { u32x4_le } else { u32x4_ge };

                    let a_not_met_target = cmp_fn(result_a, u32x4_splat(target[0]));

                    if !u32x4_all_true(a_not_met_target) {
                        crate::unlikely();

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

                        let mut final_sha_state = crate::sha256::IV;
                        crate::sha256::digest_block(&mut final_sha_state, &output_msg);

                        return Some((
                            (high_word as u64) << 32 | final_low_word as u64,
                            final_sha_state,
                        ));
                    }

                    self.attempted_nonces += 4;

                    if self.attempted_nonces >= self.limit {
                        return None;
                    }
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
