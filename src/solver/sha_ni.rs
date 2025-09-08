#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;

use crate::{
    Align16, PREFIX_OFFSET_TO_LANE_POSITION, SWAP_DWORD_BYTE_ORDER, decompose_blocks_mut,
    is_supported_lane_position,
    message::{DecimalMessage, DoubleBlockMessage, GoAwayMessage, SingleBlockMessage},
};

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
        let lane_id_0_word_idx = self.message.digit_index / 4;
        if !is_supported_lane_position(lane_id_0_word_idx) {
            return None;
        }

        for i in (self.message.digit_index as usize..).take(9) {
            let message = decompose_blocks_mut(&mut self.message.message);
            message[SWAP_DWORD_BYTE_ORDER[i]] = b'0';
        }

        let lane_id_1_word_idx = (self.message.digit_index + 1) / 4;

        #[inline(never)]
        fn solve_inner<
            const DIGIT_WORD_IDX0_DIV_4_TIMES_4: usize,
            const DIGIT_WORD_IDX0_DIV_4: usize,
            const DIGIT_WORD_IDX0_MOD_4: usize,
            const DIGIT_WORD_IDX1_INC: bool,
            const UPWARDS: bool,
            const ON_REGISTER_BOUNDARY: bool,
        >(
            this: &mut SingleBlockSolver,
            target: u64,
        ) -> Option<u64> {
            let mut partial_state = Align16(this.message.prefix_state);
            crate::sha256::ingest_message_prefix::<{ DIGIT_WORD_IDX0_DIV_4_TIMES_4 }>(
                &mut partial_state,
                core::array::from_fn(|i| this.message.message[i]),
            );
            let prepared_state = crate::sha256::sha_ni::prepare_state(&partial_state);
            let lane_id_0_byte_idx = this.message.digit_index % 4;
            let lane_id_1_byte_idx = (this.message.digit_index + 1) % 4;

            // move AB into position for feedback
            let feedback_ab = unsafe {
                let lows = _mm_cvtsi64x_si128(
                    ((this.message.prefix_state[0] as u64) << 32
                        | this.message.prefix_state[1] as u64) as _,
                );

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
                        if !DIGIT_WORD_IDX1_INC {
                            r |= lane_id_1_or_value[i]
                        }
                        r
                    });

                    struct LaneIdPlucker<
                        'a,
                        const DIGIT_WORD_IDX0_DIV_4: usize,
                        const DIGIT_WORD_IDX0_MOD_4: usize,
                        const DIGIT_WORD_IDX1_INC: bool,
                    > {
                        lane_0_or_value: &'a [u32; 4],
                        lane_1_or_value: &'a [u32; 4],
                    }

                    impl<
                        'a,
                        const DIGIT_WORD_IDX0_DIV_4: usize,
                        const DIGIT_WORD_IDX0_MOD_4: usize,
                        const DIGIT_WORD_IDX1_INC: bool,
                    >
                        LaneIdPlucker<
                            'a,
                            DIGIT_WORD_IDX0_DIV_4,
                            DIGIT_WORD_IDX0_MOD_4,
                            DIGIT_WORD_IDX1_INC,
                        >
                    {
                        #[inline(always)]
                        fn fetch_msg_or(&self, idx: usize, lane: usize) -> u32 {
                            if idx == DIGIT_WORD_IDX0_DIV_4 * 4 + DIGIT_WORD_IDX0_MOD_4 {
                                self.lane_0_or_value[lane]
                            } else if DIGIT_WORD_IDX1_INC
                                && idx == DIGIT_WORD_IDX0_DIV_4 * 4 + DIGIT_WORD_IDX0_MOD_4 + 1
                            {
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
                        const DIGIT_WORD_IDX1_INC: bool,
                    > crate::sha256::sha_ni::Plucker
                        for LaneIdPlucker<
                            'a,
                            DIGIT_WORD_IDX0_DIV_4,
                            DIGIT_WORD_IDX0_MOD_4,
                            DIGIT_WORD_IDX1_INC,
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

                    #[cfg(target_feature = "avx2")]
                    let mut itoa_buf = Align16(*b"0000\x80000");

                    for next_inner_key in 1..=10_000_000 {
                        let mut state0 = prepared_state;
                        let mut state1 = prepared_state;
                        let mut state2 = prepared_state;
                        let mut state3 = prepared_state;

                        crate::sha256::sha_ni::multiway_arx_abef_cdgh::<
                            { DIGIT_WORD_IDX0_DIV_4 },
                            4,
                            _,
                        >(
                            [&mut state0, &mut state1, &mut state2, &mut state3],
                            (&this.message.message).into(),
                            LaneIdPlucker::<
                                DIGIT_WORD_IDX0_DIV_4,
                                DIGIT_WORD_IDX0_MOD_4,
                                DIGIT_WORD_IDX1_INC,
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
                            crate::unlikely();

                            let nonce_prefix = nonce_prefix_start + success_lane_idx as u32;

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

                            return Some(nonce_prefix as u64 * 10u64.pow(7) + next_inner_key - 1);
                        }

                        #[cfg(target_feature = "avx2")]
                        {
                            if ON_REGISTER_BOUNDARY {
                                crate::strings::simd_itoa8::<7, true, 0x80>(
                                    this.message
                                        .message
                                        .as_mut_ptr()
                                        .add(DIGIT_WORD_IDX0_DIV_4 * 4 + DIGIT_WORD_IDX0_MOD_4 + 1)
                                        .cast::<Align16<[u8; 8]>>()
                                        .as_mut()
                                        .unwrap(),
                                    next_inner_key as u32,
                                );
                            } else {
                                crate::strings::simd_itoa8::<7, false, 0x80>(
                                    &mut itoa_buf,
                                    next_inner_key as u32,
                                );
                                for i in 0..7 {
                                    let message_bytes =
                                        decompose_blocks_mut(&mut this.message.message);
                                    *message_bytes.get_unchecked_mut(
                                        *SWAP_DWORD_BYTE_ORDER
                                            .get_unchecked(this.message.digit_index + i + 2),
                                    ) = itoa_buf[i];
                                }
                            }
                        }

                        #[cfg(not(target_feature = "avx2"))]
                        {
                            let mut key_copy = next_inner_key;
                            {
                                let message_bytes = decompose_blocks_mut(&mut this.message.message);

                                for i in (0..7).rev() {
                                    let output = key_copy % 10;
                                    key_copy /= 10;
                                    *message_bytes.get_unchecked_mut(
                                        *SWAP_DWORD_BYTE_ORDER
                                            .get_unchecked(this.message.digit_index + i + 2),
                                    ) = output as u8 + b'0';
                                }
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

        let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

        macro_rules! dispatch {
            ($idx0_0:literal, $idx0_1:literal, $idx0_2:literal, $lane_id_1_word_idx_inc:literal) => {
                if self.message.digit_index % 4 == 2 {
                    solve_inner::<
                        { $idx0_0 },
                        { $idx0_1 },
                        { $idx0_2 },
                        { $lane_id_1_word_idx_inc },
                        UPWARDS,
                        true,
                    >(self, compact_target)
                } else {
                    solve_inner::<
                        { $idx0_0 },
                        { $idx0_1 },
                        { $idx0_2 },
                        { $lane_id_1_word_idx_inc },
                        UPWARDS,
                        false,
                    >(self, compact_target)
                }
            };
            ($idx0_0:literal, $idx0_1:literal, $idx0_2:literal) => {
                if lane_id_1_word_idx == lane_id_0_word_idx {
                    dispatch!($idx0_0, $idx0_1, $idx0_2, false)
                } else {
                    dispatch!($idx0_0, $idx0_1, $idx0_2, true)
                }
            };
        }

        let nonce = match lane_id_0_word_idx {
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
            _ => unsafe { core::hint::unreachable_unchecked() },
        }?;

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

        let iv_state = crate::sha256::sha_ni::prepare_state(&self.message.prefix_state);
        let mut prefix_state = Align16(self.message.prefix_state);
        crate::sha256::sha2_arx::<0>(&mut prefix_state, &self.message.message[..12]);
        let prepared_state = crate::sha256::sha_ni::prepare_state(&prefix_state);

        let mut terminal_message = Align16([0; 16]);
        terminal_message[14] = ((self.message.message_length * 8) >> 32) as u32;
        terminal_message[15] = (self.message.message_length * 8) as u32;

        for nonce_prefix_start in (10u32..=96).step_by(4) {
            unsafe {
                const fn to_ascii_u32(input: u32) -> u32 {
                    let high_digit = input / 10;
                    let low_digit = input % 10;
                    u32::from_be_bytes([0, 0, high_digit as u8 + b'0', low_digit as u8 + b'0'])
                }
                let lane_index_value_v = [
                    to_ascii_u32(nonce_prefix_start) | self.message.message[13],
                    to_ascii_u32(nonce_prefix_start + 1) | self.message.message[13],
                    to_ascii_u32(nonce_prefix_start + 2) | self.message.message[13],
                    to_ascii_u32(nonce_prefix_start + 3) | self.message.message[13],
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
                    msg0[..13].copy_from_slice(self.message.message[..13].try_into().unwrap());
                    msg0[14] = cum0;
                    msg0[15] = cum1;

                    struct LaneIdPlucker<'a> {
                        lane_index_value_v: &'a [u32; 4],
                    }
                    impl<'a> crate::sha256::sha_ni::Plucker for LaneIdPlucker<'a> {
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

                    crate::sha256::sha_ni::multiway_arx_abef_cdgh::<3, 4, LaneIdPlucker>(
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

                    let save_abs = [states0[0], states1[0], states2[0], states3[0]];

                    // this isn't really SIMD so we can't really amortize the cost of fetching message schedule
                    // so let's compute it with sha-ni
                    crate::sha256::sha_ni::multiway_arx_abef_cdgh::<0, 4, _>(
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
                        crate::unlikely();

                        let nonce_prefix = nonce_prefix_start + success_lane_idx as u32;
                        self.message.message[13] = lane_index_value_v[success_lane_idx];
                        self.message.message[14] = cum0;
                        self.message.message[15] = cum1;

                        // recompute the hash from the beginning
                        // this prevents the compiler from having to compute the final B-H registers alive in tight loops
                        let mut final_sha_state = self.message.prefix_state;
                        crate::sha256::digest_block(&mut final_sha_state, &self.message.message);
                        crate::sha256::digest_block(&mut final_sha_state, &terminal_message);

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

impl From<super::safe::DecimalSolver> for DecimalSolver {
    fn from(solver: super::safe::DecimalSolver) -> Self {
        match solver {
            super::safe::DecimalSolver::SingleBlock(solver) => {
                Self::SingleBlock(SingleBlockSolver::from(solver))
            }
            super::safe::DecimalSolver::DoubleBlock(solver) => {
                Self::DoubleBlock(DoubleBlockSolver::from(solver))
            }
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
            use core::arch::x86_64::*;

            if !is_supported_lane_position(PREFIX_OFFSET_TO_LANE_POSITION[0]) {
                return None;
            }

            let mut prefix_state = Align16(crate::sha256::IV);
            crate::sha256::ingest_message_prefix(&mut prefix_state, self.challenge);
            let prepared_state = crate::sha256::sha_ni::prepare_state(&prefix_state);

            let compact_target = (target[0] as u64) << 32 | (target[1] as u64);

            let feedback_ab = {
                let lows = _mm_cvtsi64x_si128(
                    ((crate::sha256::IV[0] as u64) << 32 | crate::sha256::IV[1] as u64) as _,
                );

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
                    impl crate::sha256::sha_ni::Plucker for LaneIdPlucker {
                        #[inline(always)]
                        fn pluck_qword2(&mut self, lane: usize, w: &mut __m128i) {
                            *w = unsafe { _mm_or_si128(*w, _mm_setr_epi32(0, lane as _, 0, 0)) };
                        }
                    }

                    crate::sha256::sha_ni::multiway_arx_abef_cdgh::<2, 4, _>(
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

                    self.attempted_nonces += 4;

                    if let Some(success_lane_idx) = success_lane_idx {
                        crate::unlikely();

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
