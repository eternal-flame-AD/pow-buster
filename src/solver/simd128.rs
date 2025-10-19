use core::arch::wasm32::*;

use crate::{
    Align16, PREFIX_OFFSET_TO_LANE_POSITION, SWAP_DWORD_BYTE_ORDER, decompose_blocks_mut,
    is_supported_lane_position,
    message::{
        CerberusMessage, DecimalMessage, DoubleBlockMessage, GoAwayMessage, SingleBlockMessage,
    },
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

static LANE_ID_STR_COMBINED_LE_HI: Align16<[u32; 1000]> = {
    let mut out = [0; 1000];
    let mut i = 0;
    while i < 1000 {
        let mut copy = i;
        let mut ds = [0; 4];
        let mut j = 0;
        while j < 3 {
            ds[j] = (copy % 10) as u8 + b'0';
            copy /= 10;
            j += 1;
        }
        out[i] = u32::from_be_bytes(ds);
        i += 1;
    }
    Align16(out)
};

/// SIMD128 decimal nonce single block solver.
///
///
/// Current implementation: 4 way SIMD with 1-round hotstart granularity.
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
    /// Set the limit.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Get the attempted nonces.
    pub fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
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

impl SingleBlockSolver {
    fn solve_impl<const TYPE: u8, const NO_TRAILING_ZEROS: bool>(
        &mut self,
        target: u64,
        mask: u64,
    ) -> Option<(u64, [u32; 8])> {
        let lane_id_0_word_idx = self.message.digit_index / 4;
        if !is_supported_lane_position(lane_id_0_word_idx) {
            return None;
        }
        let lane_id_1_word_idx = (self.message.digit_index + 1) / 4;
        let target = target & mask;

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
            const TYPE: u8,
            const NO_TRAILING_ZEROS: bool,
        >(
            this: &mut SingleBlockSolver,
            hotstart_state: [u32; 8],
            target: u32,
            mask: u32,
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

                    let mut inner_key = if NO_TRAILING_ZEROS { 1 } else { 0 };
                    let mut bumper = 1;
                    let base_state = core::array::from_fn(|i| u32x4_splat(hotstart_state[i]));
                    while inner_key < 10_000_000 {
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

                        let mut state = base_state;
                        crate::sha256::simd128::multiway_arx::<LANE_ID_0_WORD_IDX>(
                            &mut state,
                            &mut blocks,
                        );

                        let result_a =
                            u32x4_add(state[0], u32x4_splat(this.message.prefix_state[0]));

                        let cmp_fn = |x: v128, y: v128| {
                            if TYPE == crate::solver::SOLVE_TYPE_GT {
                                u32x4_le(x, y)
                            } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                                u32x4_ge(x, y)
                            } else {
                                u32x4_ne(v128_and(x, u32x4_splat(mask)), y)
                            }
                        };

                        let a_not_met_target = cmp_fn(result_a, u32x4_splat(target));

                        if !u32x4_all_true(a_not_met_target) {
                            crate::unlikely();

                            let mut extract = [0u32; 4];
                            v128_store(extract.as_mut_ptr().cast(), result_a);
                            let success_lane_idx = extract
                                .iter()
                                .position(|x| {
                                    if TYPE == crate::solver::SOLVE_TYPE_GT {
                                        *x > target
                                    } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                                        *x < target
                                    } else {
                                        *x & mask == target & mask
                                    }
                                })
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

                        inner_key += 1;

                        if NO_TRAILING_ZEROS {
                            bumper += 1;
                            let should_bump = bumper == 10;
                            inner_key += should_bump as u32;
                            if should_bump {
                                bumper -= 9;
                            }
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

        macro_rules! dispatch {
            ($idx0_words:literal) => {
                if lane_id_0_word_idx == lane_id_1_word_idx {
                    solve_inner::<{ $idx0_words }, false, TYPE, NO_TRAILING_ZEROS>(
                        self,
                        hotstart_state,
                        (target >> 32) as u32,
                        (mask >> 32) as u32,
                    )
                } else {
                    solve_inner::<{ $idx0_words }, true, TYPE, NO_TRAILING_ZEROS>(
                        self,
                        hotstart_state,
                        (target >> 32) as u32,
                        (mask >> 32) as u32,
                    )
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

/// SIMD128 decimal nonce double block solver.
///
///
/// Current implementation: 4 way SIMD with 1-round hotstart granularity.
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
        if !is_supported_lane_position(DoubleBlockMessage::DIGIT_IDX as usize / 4) {
            return None;
        }
        let target = target & mask;

        let target = (target >> 32) as u32;
        let mask = (mask >> 32) as u32;

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

                    let cmp_fn = |x: v128, y: v128| {
                        if TYPE == crate::solver::SOLVE_TYPE_GT {
                            u32x4_le(x, y)
                        } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                            u32x4_ge(x, y)
                        } else {
                            u32x4_ne(v128_and(x, u32x4_splat(mask)), y)
                        }
                    };

                    let a_not_met_target = cmp_fn(result_a, u32x4_splat(target as _));

                    if !u32x4_all_true(a_not_met_target) {
                        crate::unlikely();

                        let mut extract = [0u32; 4];
                        v128_store(extract.as_mut_ptr().cast(), result_a);
                        let success_lane_idx = extract
                            .iter()
                            .position(|x| {
                                if TYPE == crate::solver::SOLVE_TYPE_GT {
                                    *x > target
                                } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                                    *x < target
                                } else {
                                    *x & mask == target & mask
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

#[macro_use]
#[path = "impl_decimal_solver.rs"]
mod impl_decimal_solver;

impl_decimal_solver!(
    [SingleBlockSolver, DoubleBlockSolver] => DecimalSolver
);

/// SIMD128 GoAway solver.
///
///
/// Current implementation: 4 way SIMD with 1-round hotstart granularity.
pub struct GoAwaySolver {
    challenge: [u32; 8],
    attempted_nonces: u64,
    limit: u64,
    fixed_high_word: Option<u32>,
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

        let target = (target >> 32) as u32;
        let mask = (mask >> 32) as u32;

        unsafe {
            if !is_supported_lane_position(PREFIX_OFFSET_TO_LANE_POSITION[0]) {
                return None;
            }

            let lane_id_v = u32x4(0, 1, 2, 3);

            let mut prefix_state = crate::sha256::IV;
            crate::sha256::ingest_message_prefix(&mut prefix_state, self.challenge);

            for high_word in if let Some(high_word) = self.fixed_high_word {
                high_word..=high_word
            } else {
                0..=u32::MAX
            } {
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
                    let cmp_fn = |x: v128, y: v128| {
                        if TYPE == crate::solver::SOLVE_TYPE_GT {
                            u32x4_le(x, y)
                        } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                            u32x4_ge(x, y)
                        } else {
                            u32x4_ne(v128_and(x, u32x4_splat(mask)), y)
                        }
                    };

                    let a_not_met_target = cmp_fn(result_a, u32x4_splat(target));

                    if !u32x4_all_true(a_not_met_target) {
                        crate::unlikely();

                        let mut extract = [0u32; 4];
                        v128_store(extract.as_mut_ptr().cast(), result_a);
                        let success_lane_idx = extract
                            .iter()
                            .position(|x| {
                                if TYPE == crate::solver::SOLVE_TYPE_GT {
                                    *x > target
                                } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                                    *x < target
                                } else {
                                    *x & mask == target & mask
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

/// SIMD128 Ceberus solver.
///
/// Current implementation: 9-digit out-of-order kernel with 4 way SIMD with quarter-round hotstart granularity.
pub struct CerberusSolver {
    message: CerberusMessage,
    attempted_nonces: u64,
    limit: u64,
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
    #[inline(never)]
    fn solve_impl<
        const CENTER_WORD_IDX: usize,
        const LANE_ID_WORD_IDX: usize,
        const CONSTANT_WORD_COUNT: usize,
    >(
        &mut self,
        mut msg: Align16<[u32; 16]>,
        target: u64,
        mask: u64,
    ) -> Option<(u64, u64)> {
        debug_assert_eq!(target, 0);

        let prepared_state = crate::blake3::ingest_message_prefix(
            *self.message.prefix_state,
            &msg[..CONSTANT_WORD_COUNT],
            0,
            self.message.salt_residual_len as u32 + 9,
            self.message.flags,
        );

        for word in 0u32..10000 {
            if self.attempted_nonces >= self.limit {
                return None;
            }
            msg[CENTER_WORD_IDX] = u32::from_be_bytes([
                (word % 10) as u8 + b'0',
                ((word / 10) % 10) as u8 + b'0',
                ((word / 100) % 10) as u8 + b'0',
                ((word / 1000) % 10) as u8 + b'0',
            ]);
            for lane_id_idx in 0..(LANE_ID_STR_COMBINED_LE_HI.len() / 4) {
                unsafe {
                    let mut lane_id_value = v128_load(
                        LANE_ID_STR_COMBINED_LE_HI
                            .as_ptr()
                            .add(lane_id_idx * 4)
                            .cast(),
                    );
                    if CENTER_WORD_IDX < LANE_ID_WORD_IDX {
                        lane_id_value = u32x4_shr(lane_id_value, 8);
                    }
                    if self.attempted_nonces >= self.limit {
                        return None;
                    }

                    let mut state = core::array::from_fn(|i| u32x4_splat(prepared_state[i]));
                    let patch = v128_or(u32x4_splat(msg[LANE_ID_WORD_IDX]), lane_id_value);
                    crate::blake3::simd128::compress_mb4_reduced::<
                        CONSTANT_WORD_COUNT,
                        LANE_ID_WORD_IDX,
                    >(&mut state, &msg, patch);

                    let masked = v128_and(state[0], u32x4_splat(mask as _));

                    self.attempted_nonces += 4;

                    if !u32x4_all_true(masked) {
                        crate::unlikely();

                        let mut extract = [0u32; 4];
                        v128_store(extract.as_mut_ptr().cast(), masked);
                        let success_lane_idx =
                            extract.iter().position(|x| *x & mask as u32 == 0).unwrap() as u64;

                        return Some((word as u64, lane_id_idx as u64 * 4 + success_lane_idx));
                    }
                }
            }
        }
        None
    }
}

impl crate::solver::Solver for CerberusSolver {
    fn solve_nonce_only<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<u64> {
        // two digits as lane ID, N=\x00, ? is prefix
        // position % 4 =0: |1234|5678|NNN9
        // position % 4 =1: |123?|4567|NN89
        // position % 4 =2: |12??|3456|N789
        // position % 4 =3: |1???|2345|6789

        let center_word_idx = self.message.salt_residual_len / 4 + 1;
        let position_mod = self.message.salt_residual_len % 4;

        for resid0 in 0..10u64 {
            for resid1 in 0..10u64 {
                if self.attempted_nonces >= self.limit {
                    return None;
                }
                let mut msg = self.message.salt_residual;

                match position_mod {
                    0 => {
                        msg[self.message.salt_residual_len] = resid0 as u8 + b'0';
                        msg[self.message.salt_residual_len + 8] = resid1 as u8 + b'0';
                    }
                    1 => {
                        msg[self.message.salt_residual_len + 7] = resid0 as u8 + b'0';
                        msg[self.message.salt_residual_len + 8] = resid1 as u8 + b'0';
                    }
                    2 => {
                        msg[self.message.salt_residual_len] = resid0 as u8 + b'0';
                        msg[self.message.salt_residual_len + 1] = resid1 as u8 + b'0';
                    }
                    3 => {
                        msg[self.message.salt_residual_len] = resid0 as u8 + b'0';
                        msg[self.message.salt_residual_len + 8] = resid1 as u8 + b'0';
                    }
                    _ => unreachable!(),
                }

                let msg = Align16(core::array::from_fn(|i| {
                    u32::from_le_bytes([msg[i * 4], msg[i * 4 + 1], msg[i * 4 + 2], msg[i * 4 + 3]])
                }));

                macro_rules! dispatch {
                    ($center_word_idx:literal) => {
                        if position_mod < 2 {
                            self.solve_impl::<$center_word_idx, { $center_word_idx - 1 }, {$center_word_idx - 1}>(
                                msg, target, mask,
                            )
                        } else {
                            self.solve_impl::<$center_word_idx, { $center_word_idx + 1 }, $center_word_idx>(
                                msg, target, mask,
                            )
                        }
                    };
                }

                if let Some((middle_word, success_lane_idx)) = match center_word_idx {
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
                    14 => dispatch!(14),
                    15 => dispatch!(15),
                    _ => unreachable!(),
                } {
                    let output_nonce = self.message.nonce_addend
                        + match position_mod {
                            0 => {
                                10 * middle_word
                                    + 100_000 * success_lane_idx
                                    + 100_000_000 * resid0
                                    + resid1
                            }
                            1 => {
                                100 * middle_word
                                    + 1_000_000 * success_lane_idx
                                    + 10 * resid0
                                    + resid1
                            }
                            2 => {
                                1000 * middle_word
                                    + success_lane_idx
                                    + 100_000_000 * resid0
                                    + 10_000_000 * resid1
                            }
                            3 => {
                                10000 * middle_word
                                    + 10 * success_lane_idx
                                    + 100_000_000 * resid0
                                    + resid1
                            }
                            _ => unreachable!(),
                        };

                    return Some(output_nonce as u64);
                }
            }
        }

        None
    }

    fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, [u32; 8])> {
        if let Some(nonce) = self.solve_nonce_only::<TYPE>(target, mask) {
            let mut output_state = *self.message.prefix_state;
            let mut msg = self.message.salt_residual;

            let mut nonce_copy = nonce;
            for i in (0..9).rev() {
                msg[self.message.salt_residual_len + i] = (nonce_copy % 10) as u8 + b'0';
                nonce_copy /= 10;
            }

            let mut msg = core::array::from_fn(|i| {
                u32::from_le_bytes([msg[i * 4], msg[i * 4 + 1], msg[i * 4 + 2], msg[i * 4 + 3]])
            });

            let hash = crate::blake3::compress8(
                &mut output_state,
                &mut msg,
                0,
                self.message.salt_residual_len as u32 + 9,
                self.message.flags,
            );

            Some((nonce, hash))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solve_cerberus() {
        crate::solver::tests::test_cerberus_validator::<CerberusSolver, _>(|prefix| {
            CerberusMessage::new(prefix, 0).map(Into::into)
        });
    }

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
