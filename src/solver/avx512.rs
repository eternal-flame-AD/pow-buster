use crate::{
    Align16, PREFIX_OFFSET_TO_LANE_POSITION, SWAP_DWORD_BYTE_ORDER, decompose_blocks_mut,
    is_supported_lane_position,
    message::{DecimalMessage, DoubleBlockMessage, GoAwayMessage, SingleBlockMessage},
};
use core::arch::x86_64::*;

static LANE_ID_MSB_STR: Align16<[u8; 5 * 16]> =
    Align16(*b"11111111112222222222333333333344444444445555555555666666666677777777778888888888");

static LANE_ID_LSB_STR: Align16<[u8; 5 * 16]> =
    Align16(*b"01234567890123456789012345678901234567890123456789012345678901234567890123456789");

#[cfg(feature = "compare-64bit")]
const INDEX_REMAP_PUNPCKLDQ: [usize; 16] = [0, 1, 4, 5, 8, 9, 12, 13, 2, 3, 6, 7, 10, 11, 14, 15];

#[inline(always)]
fn load_lane_id_epi32(src: &Align16<[u8; 5 * 16]>, set_idx: usize) -> __m512i {
    debug_assert!(set_idx < 5);
    unsafe { _mm512_cvtepi8_epi32(_mm_load_si128(src.as_ptr().add(set_idx * 16).cast())) }
}

pub struct SingleBlockSolver {
    message: SingleBlockMessage,

    attempted_nonces: u64,

    limit: u64,
}

impl From<super::safe::SingleBlockSolver> for SingleBlockSolver {
    fn from(solver: super::safe::SingleBlockSolver) -> Self {
        Self {
            message: solver.message,
            attempted_nonces: solver.attempted_nonces,
            limit: solver.limit,
        }
    }
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
        if self.attempted_nonces >= self.limit {
            return None;
        }

        // the official default difficulty is 5e6, so we design for 1e8
        // and there should almost always be a valid solution within our supported solution space
        // pgeom(5 * 16e7, 1/5e7, lower=F) = 0.03%
        // pgeom(16e7, 1/5e7, lower=F) = 20%, which is too much so we need the prefix to change as well

        // pre-compute an OR to apply to the message to add the lane ID
        let lane_id_0_word_idx = self.message.digit_index / 4;
        if !is_supported_lane_position(lane_id_0_word_idx) {
            return None;
        }
        let lane_id_1_word_idx = (self.message.digit_index + 1) / 4;

        // zero out the nonce portion to prevent incorrect results if solvers are reused
        for i in (self.message.digit_index..).take(9) {
            let message = decompose_blocks_mut(&mut self.message.message);
            message[SWAP_DWORD_BYTE_ORDER[i]] = b'0';
        }

        // make sure there are no runtime "register indexing" logic
        #[inline(never)]
        fn solve_inner<
            const DIGIT_WORD_IDX0: usize,
            const DIGIT_WORD_IDX1_INCREMENT: bool,
            const UPWARDS: bool,
            const ON_REGISTER_BOUNDARY: bool,
        >(
            this: &mut SingleBlockSolver,
            #[cfg(not(feature = "compare-64bit"))] target: u32,
            #[cfg(feature = "compare-64bit")] target: u64,
        ) -> Option<u64> {
            let mut partial_state = this.message.prefix_state;
            crate::sha256::ingest_message_prefix::<DIGIT_WORD_IDX0>(
                &mut partial_state,
                core::array::from_fn(|i| this.message.message[i]),
            );

            if this.attempted_nonces >= this.limit {
                return None;
            }

            let mut remaining_limit = this.limit.saturating_sub(this.attempted_nonces);
            if remaining_limit == 0 {
                return None;
            }

            let lane_id_0_byte_idx = this.message.digit_index % 4;
            let lane_id_1_byte_idx = (this.message.digit_index + 1) % 4;
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

                    let inner_iteration_end = if remaining_limit < 10_000_000 {
                        remaining_limit as u32
                    } else {
                        10_000_000
                    };
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
                                        _mm512_set1_epi32(this.message.message[$idx] as _),
                                        lane_id_0_or_value_v,
                                    )
                                } else if DIGIT_WORD_IDX1_INCREMENT && $idx == DIGIT_WORD_IDX0 + 1 {
                                    _mm512_or_epi32(
                                        _mm512_set1_epi32(this.message.message[$idx] as _),
                                        lane_id_1_or_value,
                                    )
                                } else if ON_REGISTER_BOUNDARY && $idx == DIGIT_WORD_IDX0 + 1 {
                                    _mm512_set1_epi32(
                                        (inner_key_buf.as_ptr().cast::<u32>().read()) as _,
                                    )
                                } else if ON_REGISTER_BOUNDARY && $idx == DIGIT_WORD_IDX0 + 2 {
                                    _mm512_set1_epi32(
                                        (inner_key_buf.as_ptr().add(4).cast::<u32>().read()) as _,
                                    )
                                } else {
                                    _mm512_set1_epi32(this.message.message[$idx] as _)
                                }
                            };
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
                        crate::sha256::avx512::multiway_arx::<DIGIT_WORD_IDX0>(
                            &mut state,
                            &mut blocks,
                        );

                        state[0] = _mm512_add_epi32(
                            state[0],
                            _mm512_set1_epi32(this.message.prefix_state[0] as _),
                        );

                        #[cfg(feature = "compare-64bit")]
                        {
                            state[1] = _mm512_add_epi32(
                                state[1],
                                _mm512_set1_epi32(this.message.prefix_state[1] as _),
                            );
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
                        let (met_target_high, met_target_lo) = {
                            let ab_met_target_lo =
                                cmp64_fn(result_ab_lo, _mm512_set1_epi64(target as _)) as u16;

                            let ab_met_target_high =
                                cmp64_fn(result_ab_hi, _mm512_set1_epi64(target as _)) as u16;

                            (ab_met_target_high, ab_met_target_lo)
                        };
                        #[cfg(feature = "compare-64bit")]
                        let met_target_test = met_target_high != 0 || met_target_lo != 0;
                        #[cfg(not(feature = "compare-64bit"))]
                        let met_target_test = met_target != 0;

                        if met_target_test {
                            crate::unlikely();

                            #[cfg(not(feature = "compare-64bit"))]
                            let success_lane_idx = _tzcnt_u16(met_target) as usize;

                            // remap the indices according to unpacking order
                            #[cfg(feature = "compare-64bit")]
                            let success_lane_idx = INDEX_REMAP_PUNPCKLDQ
                                [_tzcnt_u16(met_target_high << 8 | met_target_lo) as usize];

                            let nonce_prefix = 10 + 16 * prefix_set_index + success_lane_idx;

                            if ON_REGISTER_BOUNDARY {
                                this.message.message[DIGIT_WORD_IDX0 + 1] =
                                    inner_key_buf.as_ptr().cast::<u32>().read();
                                this.message.message[DIGIT_WORD_IDX0 + 2] =
                                    inner_key_buf.as_ptr().add(4).cast::<u32>().read();
                            }

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
                                nonce_prefix as u64 * 10u64.pow(7) + next_inner_key as u64 - 1,
                            );
                        }

                        this.attempted_nonces += 16;

                        if ON_REGISTER_BOUNDARY {
                            crate::strings::simd_itoa8::<7, true, 0x80>(
                                &mut inner_key_buf,
                                next_inner_key,
                            );
                        } else {
                            let message_bytes = decompose_blocks_mut(&mut this.message.message);
                            let mut key_copy = next_inner_key;

                            for i in (0..7).rev() {
                                let output = key_copy % 10;
                                key_copy /= 10;
                                *message_bytes.get_unchecked_mut(
                                    *SWAP_DWORD_BYTE_ORDER
                                        .get_unchecked(this.message.digit_index + i + 2),
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

            crate::unlikely();
            None
        }

        #[cfg(not(feature = "compare-64bit"))]
        let compact_target = target[0];

        #[cfg(feature = "compare-64bit")]
        let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

        macro_rules! dispatch {
            ($idx0:literal, $idx1_inc:literal) => {
                if self.message.digit_index % 4 == 2 {
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

        Some((nonce + self.message.nonce_addend, final_sha_state))
    }
}

pub struct DoubleBlockSolver {
    message: DoubleBlockMessage,
    attempted_nonces: u64,

    limit: u64,
}

impl From<super::safe::DoubleBlockSolver> for DoubleBlockSolver {
    fn from(solver: super::safe::DoubleBlockSolver) -> Self {
        Self {
            message: solver.message,
            attempted_nonces: solver.attempted_nonces,
            limit: solver.limit,
        }
    }
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

        #[cfg(feature = "compare-64bit")]
        let feedback_ab = (target[0] as u64) << 32 | (target[1] as u64);

        let mut partial_state = self.message.prefix_state;
        crate::sha256::sha2_arx::<0>(&mut partial_state, &self.message.message[..13]);

        let mut terminal_message_schedule = Align16([0; 64]);
        terminal_message_schedule[14] = ((self.message.message_length as u64 * 8) >> 32) as u32;
        terminal_message_schedule[15] = (self.message.message_length as u64 * 8) as u32;
        crate::sha256::do_message_schedule_k_w(&mut terminal_message_schedule);

        let mut itoa_buf = Align16(*b"0000\x80000");
        for prefix_set_index in 0..5 {
            unsafe {
                let lane_id_0_or_value =
                    _mm512_slli_epi32(load_lane_id_epi32(&LANE_ID_MSB_STR, prefix_set_index), 8);
                let lane_id_1_or_value = load_lane_id_epi32(&LANE_ID_LSB_STR, prefix_set_index);

                let lane_index_value_v = _mm512_or_epi32(
                    _mm512_set1_epi32(self.message.message[13] as _),
                    _mm512_or_epi32(lane_id_0_or_value, lane_id_1_or_value),
                );

                for next_inner_key in 1..=10_000_000 {
                    let cum0 = itoa_buf.as_ptr().cast::<u32>().read();
                    let cum1 = itoa_buf.as_ptr().add(4).cast::<u32>().read();

                    let mut state =
                        core::array::from_fn(|i| _mm512_set1_epi32(partial_state[i] as _));

                    {
                        let mut blocks = [
                            _mm512_set1_epi32(self.message.message[0] as _),
                            _mm512_set1_epi32(self.message.message[1] as _),
                            _mm512_set1_epi32(self.message.message[2] as _),
                            _mm512_set1_epi32(self.message.message[3] as _),
                            _mm512_set1_epi32(self.message.message[4] as _),
                            _mm512_set1_epi32(self.message.message[5] as _),
                            _mm512_set1_epi32(self.message.message[6] as _),
                            _mm512_set1_epi32(self.message.message[7] as _),
                            _mm512_set1_epi32(self.message.message[8] as _),
                            _mm512_set1_epi32(self.message.message[9] as _),
                            _mm512_set1_epi32(self.message.message[10] as _),
                            _mm512_set1_epi32(self.message.message[11] as _),
                            _mm512_set1_epi32(self.message.message[12] as _),
                            lane_index_value_v,
                            _mm512_set1_epi32(cum0 as _),
                            _mm512_set1_epi32(cum1 as _),
                        ];

                        crate::sha256::avx512::multiway_arx::<13>(&mut state, &mut blocks);

                        // we have to do feedback now
                        state
                            .iter_mut()
                            .zip(self.message.prefix_state.iter())
                            .for_each(|(state, prefix_state)| {
                                *state =
                                    _mm512_add_epi32(*state, _mm512_set1_epi32(*prefix_state as _));
                            });
                    }

                    // save only A register for comparison
                    let save_a = state[0];

                    #[cfg(feature = "compare-64bit")]
                    let save_b = state[1];

                    crate::sha256::avx512::bcst_multiway_arx::<14>(
                        &mut state,
                        &terminal_message_schedule,
                    );

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
                    let (met_target_high, met_target_lo) = {
                        let ab_met_target_lo =
                            cmp64_fn(result_ab_lo, _mm512_set1_epi64(feedback_ab as _)) as u16;
                        let ab_met_target_high =
                            cmp64_fn(result_ab_hi, _mm512_set1_epi64(feedback_ab as _)) as u16;
                        (ab_met_target_high, ab_met_target_lo)
                    };

                    #[cfg(feature = "compare-64bit")]
                    let met_target_test = met_target_high != 0 || met_target_lo != 0;

                    #[cfg(not(feature = "compare-64bit"))]
                    let met_target_test = met_target != 0;

                    if met_target_test {
                        crate::unlikely();

                        #[cfg(not(feature = "compare-64bit"))]
                        let success_lane_idx = _tzcnt_u16(met_target) as usize;

                        #[cfg(feature = "compare-64bit")]
                        let success_lane_idx = INDEX_REMAP_PUNPCKLDQ
                            [_tzcnt_u16(met_target_high << 8 | met_target_lo) as usize];

                        let nonce_prefix = 10 + 16 * prefix_set_index + success_lane_idx;

                        self.message.message[14] = cum0;
                        self.message.message[15] = cum1;
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
                        let mut terminal_message = [0; 16];
                        terminal_message[14] = ((self.message.message_length * 8) >> 32) as u32;
                        terminal_message[15] = (self.message.message_length * 8) as u32;
                        crate::sha256::digest_block(&mut final_sha_state, &terminal_message);

                        let computed_nonce =
                            nonce_prefix as u64 * 10u64.pow(7) + next_inner_key as u64 - 1
                                + self.message.nonce_addend;

                        // the nonce is the 8 digits in the message, plus the first two digits recomputed from the lane index
                        return Some((computed_nonce, *final_sha_state));
                    }

                    self.attempted_nonces += 16;

                    if self.attempted_nonces >= self.limit {
                        return None;
                    }

                    crate::strings::simd_itoa8::<7, true, 0x80>(&mut itoa_buf, next_inner_key);
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
    challenge: [u32; 8],
    attempted_nonces: u64,
    limit: u64,
}

impl From<super::safe::GoAwaySolver> for GoAwaySolver {
    fn from(solver: super::safe::GoAwaySolver) -> Self {
        Self {
            challenge: solver.challenge,
            attempted_nonces: solver.attempted_nonces,
            limit: solver.limit,
        }
    }
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
            let lane_id_v = _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

            if !is_supported_lane_position(PREFIX_OFFSET_TO_LANE_POSITION[0]) {
                return None;
            }

            let mut prefix_state = crate::sha256::IV;
            crate::sha256::ingest_message_prefix(&mut prefix_state, self.challenge);

            #[cfg(feature = "compare-64bit")]
            let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

            let high_limit = (self.limit >> 32) as u32;
            let low_limit = self.limit as u32;

            for high_word in 0..=high_limit {
                let mut partial_state = prefix_state;
                crate::sha256::sha2_arx::<8>(&mut partial_state, &[high_word]);

                for low_word in (0..=if high_word == high_limit {
                    low_limit
                } else {
                    u32::MAX
                })
                    .step_by(16)
                {
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
                    crate::sha256::avx512::multiway_arx::<9>(&mut state, &mut msg);

                    state[0] =
                        _mm512_add_epi32(state[0], _mm512_set1_epi32(crate::sha256::IV[0] as _));

                    #[cfg(feature = "compare-64bit")]
                    {
                        state[1] = _mm512_add_epi32(
                            state[1],
                            _mm512_set1_epi32(crate::sha256::IV[1] as _),
                        );
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
                    let (met_target_high, met_target_lo) = {
                        let ab_met_target_lo =
                            cmp_fn(result_ab_lo, _mm512_set1_epi64(compact_target as _)) as u16;
                        let ab_met_target_high =
                            cmp_fn(result_ab_hi, _mm512_set1_epi64(compact_target as _)) as u16;
                        (ab_met_target_high, ab_met_target_lo)
                    };

                    #[cfg(feature = "compare-64bit")]
                    let met_target_test = met_target_high != 0 || met_target_lo != 0;
                    #[cfg(not(feature = "compare-64bit"))]
                    let met_target_test = met_target != 0;

                    self.attempted_nonces += 16;

                    if met_target_test {
                        crate::unlikely();

                        #[cfg(not(feature = "compare-64bit"))]
                        let success_lane_idx = _tzcnt_u16(met_target);

                        #[cfg(feature = "compare-64bit")]
                        let success_lane_idx = INDEX_REMAP_PUNPCKLDQ
                            [_tzcnt_u16(met_target_high << 8 | met_target_lo) as usize];

                        let mut output_msg: [u32; 16] = [0; 16];

                        let final_low_word = low_word | (success_lane_idx as u32);
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
