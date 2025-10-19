use sha2::digest::generic_array::GenericArray;

use crate::{
    Align16, Align64, PREFIX_OFFSET_TO_LANE_POSITION, SWAP_DWORD_BYTE_ORDER, decompose_blocks_mut,
    is_supported_lane_position,
    message::{
        BinaryMessage, CerberusMessage, DecimalMessage, DoubleBlockMessage, GoAwayMessage,
        SingleBlockMessage,
    },
};
use core::arch::x86_64::*;

static LANE_ID_MSB_STR: Align16<[u8; 5 * 16]> =
    Align16(*b"11111111112222222222333333333344444444445555555555666666666677777777778888888888");

static LANE_ID_MSB_STR_0: Align16<[u8; 6 * 16]> =
    Align16(*b"000000000011111111112222222222333333333344444444445555555555666666666677777777778888888888999999");

static LANE_ID_LSB_STR: Align16<[u8; 5 * 16]> =
    Align16(*b"01234567890123456789012345678901234567890123456789012345678901234567890123456789");

static LANE_ID_LSB_STR_0: Align16<[u8; 6 * 16]> =
    Align16(*b"012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345");

static LANE_ID_STR_COMBINED_LE_HI: Align64<[u32; 1000 / 16 * 16]> = {
    let mut out = [0; 1000 / 16 * 16];
    let mut i = 0;
    while i < 1000 / 16 * 16 {
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
    Align64(out)
};

#[expect(dead_code)]
mod static_asserts {
    use super::*;

    const ASSERT_LANE_ID_STR_COMBINED_LE_HI_0: [(); 1] =
        [(); (LANE_ID_STR_COMBINED_LE_HI.0[0] == u32::from_be_bytes(*b"000\x00")) as usize];

    const ASSERT_LANE_ID_STR_COMBINED_LE_HI_1: [(); 1] =
        [(); (LANE_ID_STR_COMBINED_LE_HI.0[1] == u32::from_be_bytes(*b"100\x00")) as usize];

    const ASSERT_LANE_ID_STR_COMBINED_LE_HI_123: [(); 1] =
        [(); (LANE_ID_STR_COMBINED_LE_HI.0[123] == u32::from_be_bytes(*b"321\x00")) as usize];
}

#[cfg(feature = "compare-64bit")]
const INDEX_REMAP_PUNPCKLDQ: [usize; 16] = [0, 1, 4, 5, 8, 9, 12, 13, 2, 3, 6, 7, 10, 11, 14, 15];

#[inline(always)]
fn load_lane_id_epi32<const N: usize>(src: &Align16<[u8; N]>, set_idx: usize) -> __m512i {
    debug_assert!(set_idx * 16 < N);
    unsafe { _mm512_cvtepi8_epi32(_mm_load_si128(src.as_ptr().add(set_idx * 16).cast())) }
}

/// AVX-512 decimal nonce single block solver.
///
///
/// Current implementation: 16 way SIMD with 1-round hotstart granularity.
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
    /// Set the limit.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Get the attempted nonces.
    pub fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }
}

const MUTATION_TYPE_UNALIGNED: u8 = 0;
const MUTATION_TYPE_ALIGNED: u8 = 1;
const MUTATION_TYPE_OCTAL: u8 = 2;
const MUTATION_TYPE_ALIGNED_OCTAL: u8 = MUTATION_TYPE_ALIGNED | MUTATION_TYPE_OCTAL;
const MUTATION_TYPE_UNALIGNED_OCTAL: u8 = MUTATION_TYPE_UNALIGNED | MUTATION_TYPE_OCTAL;

impl crate::solver::Solver for SingleBlockSolver {
    fn solve_nonce_only<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<u64> {
        if self.attempted_nonces >= self.limit {
            return None;
        }
        let target = target & mask;

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

        // make sure there are no runtime "register indexing" logic
        #[inline(never)]
        fn solve_inner<
            const DIGIT_WORD_IDX0: usize,
            const DIGIT_WORD_IDX1_INCREMENT: bool,
            const TYPE: u8,
            const MUTATION_TYPE: u8,
        >(
            this: &mut SingleBlockSolver,
            target: u64,
            mask: u64,
        ) -> Option<u64> {
            let mut partial_state = this.message.prefix_state;
            crate::sha256::ingest_message_prefix::<DIGIT_WORD_IDX0>(
                &mut partial_state,
                core::array::from_fn(|i| this.message.message[i]),
            );

            // zero out the nonce portion to prevent incorrect results if solvers are reused
            for (ix, i) in (this.message.digit_index..).take(9).enumerate() {
                let message = decompose_blocks_mut(&mut this.message.message);
                message[SWAP_DWORD_BYTE_ORDER[i]] =
                    if ix >= 2 && MUTATION_TYPE & MUTATION_TYPE_OCTAL != 0 {
                        b'1'
                    } else {
                        b'0'
                    };
            }

            if this.attempted_nonces >= this.limit {
                return None;
            }

            let mut remaining_limit = this.limit.saturating_sub(this.attempted_nonces);
            if remaining_limit == 0 {
                return None;
            }

            let lane_id_0_byte_idx = this.message.digit_index % 4;
            let lane_id_1_byte_idx = (this.message.digit_index + 1) % 4;

            for prefix_set_index in 0..(if MUTATION_TYPE & MUTATION_TYPE_OCTAL != 0 {
                6
            } else {
                5
            }) {
                let mut inner_key_buf = if MUTATION_TYPE & MUTATION_TYPE_OCTAL != 0 {
                    Align16(*b"1111\x80111")
                } else {
                    Align16(*b"0000\x80000")
                };

                unsafe {
                    let (lane_id_0_or_value, lane_id_1_or_value) =
                        if MUTATION_TYPE & MUTATION_TYPE_OCTAL != 0 {
                            let lane_id_0_or_value = _mm512_sll_epi32(
                                load_lane_id_epi32(&LANE_ID_MSB_STR_0, prefix_set_index),
                                _mm_set1_epi64x(((3 - lane_id_0_byte_idx) * 8) as _),
                            );
                            let lane_id_1_or_value = _mm512_sll_epi32(
                                load_lane_id_epi32(&LANE_ID_LSB_STR_0, prefix_set_index),
                                _mm_set1_epi64x(((3 - lane_id_1_byte_idx) * 8) as _),
                            );

                            (lane_id_0_or_value, lane_id_1_or_value)
                        } else {
                            let lane_id_0_or_value = _mm512_sll_epi32(
                                load_lane_id_epi32(&LANE_ID_MSB_STR, prefix_set_index),
                                _mm_set1_epi64x(((3 - lane_id_0_byte_idx) * 8) as _),
                            );
                            let lane_id_1_or_value = _mm512_sll_epi32(
                                load_lane_id_epi32(&LANE_ID_LSB_STR, prefix_set_index),
                                _mm_set1_epi64x(((3 - lane_id_1_byte_idx) * 8) as _),
                            );

                            (lane_id_0_or_value, lane_id_1_or_value)
                        };

                    let lane_id_0_or_value_v = if !DIGIT_WORD_IDX1_INCREMENT {
                        _mm512_or_epi32(lane_id_0_or_value, lane_id_1_or_value)
                    } else {
                        lane_id_0_or_value
                    };

                    let inner_iteration_end = if MUTATION_TYPE & MUTATION_TYPE_OCTAL != 0 {
                        0o10_000_000
                    } else {
                        10_000_000
                    };
                    let max_iterations = inner_iteration_end;
                    remaining_limit -= max_iterations as u64;

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
                                } else if (MUTATION_TYPE_ALIGNED & MUTATION_TYPE != 0)
                                    && $idx == DIGIT_WORD_IDX0 + 1
                                {
                                    _mm512_set1_epi32(
                                        (inner_key_buf.as_ptr().cast::<u32>().read()) as _,
                                    )
                                } else if (MUTATION_TYPE_ALIGNED & MUTATION_TYPE != 0)
                                    && $idx == DIGIT_WORD_IDX0 + 2
                                {
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
                        let cmp_fn = |x: __m512i, y: __m512i| {
                            if TYPE == crate::solver::SOLVE_TYPE_GT {
                                _mm512_cmpgt_epu32_mask(x, y)
                            } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                                _mm512_cmplt_epu32_mask(x, y)
                            } else {
                                _mm512_cmpeq_epu32_mask(
                                    _mm512_and_si512(x, _mm512_set1_epi32((mask >> 32) as _)),
                                    y,
                                )
                            }
                        };

                        #[cfg(feature = "compare-64bit")]
                        let cmp64_fn = |x: __m512i, y: __m512i| {
                            if TYPE == crate::solver::SOLVE_TYPE_GT {
                                _mm512_cmpgt_epu64_mask(x, y)
                            } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                                _mm512_cmplt_epu64_mask(x, y)
                            } else {
                                _mm512_cmpeq_epu64_mask(
                                    _mm512_and_si512(x, _mm512_set1_epi64(mask as _)),
                                    y,
                                )
                            }
                        };

                        #[cfg(not(feature = "compare-64bit"))]
                        let met_target = cmp_fn(state[0], _mm512_set1_epi32((target >> 32) as _));

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
                            let success_lane_idx = met_target.trailing_zeros() as usize;

                            // remap the indices according to unpacking order
                            #[cfg(feature = "compare-64bit")]
                            let success_lane_idx = INDEX_REMAP_PUNPCKLDQ
                                [(met_target_high << 8 | met_target_lo).trailing_zeros() as usize];

                            let mut nonce_prefix = 16 * prefix_set_index + success_lane_idx;
                            if MUTATION_TYPE & MUTATION_TYPE_OCTAL == 0 {
                                nonce_prefix += 10;
                            }

                            if MUTATION_TYPE & MUTATION_TYPE_ALIGNED != 0 {
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

                            let mut decimal_inner_key = next_inner_key as u64 - 1;
                            if MUTATION_TYPE & MUTATION_TYPE_OCTAL != 0 {
                                decimal_inner_key = 0;
                                let mut key_octal = next_inner_key - 1;
                                for m in (0..7u32).map(|i| 10u64.pow(i)) {
                                    let output = (key_octal % 8) + 1;
                                    key_octal /= 8;
                                    decimal_inner_key += output as u64 * m;
                                }
                                let mut message_be = [0u8; 64];
                                for i in 0..16 {
                                    message_be[i * 4..][..4]
                                        .copy_from_slice(&this.message.message[i].to_be_bytes());
                                }
                            }

                            // the nonce is the 7 digits in the message, plus the first two digits recomputed from the lane index
                            return Some(nonce_prefix as u64 * 10u64.pow(7) + decimal_inner_key);
                        }

                        this.attempted_nonces += 16;

                        if MUTATION_TYPE == MUTATION_TYPE_ALIGNED_OCTAL {
                            crate::strings::to_octal_7::<true, 0x80, 1>(
                                &mut inner_key_buf,
                                next_inner_key,
                            )
                        } else if MUTATION_TYPE == MUTATION_TYPE_ALIGNED {
                            crate::strings::simd_itoa8::<7, true, 0x80>(
                                &mut inner_key_buf,
                                next_inner_key,
                            );
                        } else if MUTATION_TYPE == MUTATION_TYPE_UNALIGNED_OCTAL {
                            let message_bytes = decompose_blocks_mut(&mut this.message.message);
                            let mut key_copy = next_inner_key;

                            for i in (0..7).rev() {
                                let output = key_copy % 8;
                                key_copy /= 8;
                                *message_bytes.get_unchecked_mut(
                                    *SWAP_DWORD_BYTE_ORDER
                                        .get_unchecked(this.message.digit_index + i + 2),
                                ) = output as u8 + b'1';
                            }
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
                        }
                    }
                }
            }

            crate::unlikely();
            None
        }

        macro_rules! dispatch {
            ($idx0:literal, $idx1_inc:literal) => {
                if self.message.digit_index % 4 == 2 {
                    // if we have to much search space it doesn't matter
                    // use the octal kernel
                    if self.message.no_trailing_zeros
                        || self.message.approx_working_set_count.get() >= 100
                    {
                        solve_inner::<$idx0, $idx1_inc, TYPE, MUTATION_TYPE_ALIGNED_OCTAL>(
                            self, target, mask,
                        )
                    } else {
                        solve_inner::<$idx0, $idx1_inc, TYPE, MUTATION_TYPE_ALIGNED>(
                            self, target, mask,
                        )
                    }
                } else if self.message.no_trailing_zeros {
                    solve_inner::<$idx0, $idx1_inc, TYPE, MUTATION_TYPE_UNALIGNED_OCTAL>(
                        self, target, mask,
                    )
                } else {
                    solve_inner::<$idx0, $idx1_inc, TYPE, MUTATION_TYPE_UNALIGNED>(
                        self, target, mask,
                    )
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

        Some(nonce + self.message.nonce_addend)
    }

    fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, [u32; 8])> {
        let nonce = self.solve_nonce_only::<TYPE>(target, mask)?;

        // recompute the hash from the beginning
        // this prevents the compiler from having to compute the final B-H registers alive in tight loops
        let mut final_sha_state = self.message.prefix_state;
        crate::sha256::digest_block(&mut final_sha_state, &self.message.message);

        Some((nonce, final_sha_state))
    }
}

/// AVX-512 decimal nonce double block solver.
///
///
/// Current implementation: 16 way SIMD with 1-round hotstart granularity.
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

        if self.attempted_nonces >= self.limit {
            return None;
        }

        for (ix, i) in (DoubleBlockMessage::DIGIT_IDX as usize..)
            .take(9)
            .enumerate()
        {
            let message = decompose_blocks_mut(&mut self.message.message);
            message[SWAP_DWORD_BYTE_ORDER[i]] = b'0';
            if ix >= 2 {
                message[SWAP_DWORD_BYTE_ORDER[i]] = b'1';
            }
        }

        let mut partial_state = self.message.prefix_state;
        crate::sha256::sha2_arx::<0>(&mut partial_state, &self.message.message[..13]);

        let mut terminal_message_schedule = Align16([0; 64]);
        terminal_message_schedule[14] = ((self.message.message_length * 8) >> 32) as u32;
        terminal_message_schedule[15] = (self.message.message_length * 8) as u32;
        crate::sha256::do_message_schedule_k_w(&mut terminal_message_schedule);

        let mut itoa_buf = Align16(*b"1111\x80111");
        // the addend is definitely not zero for double block solver, so we can start at 0
        // to recoup some lost search space from using octal digits
        for prefix_set_index in 0..(LANE_ID_LSB_STR.len() / 16) {
            unsafe {
                let lane_id_0_or_value =
                    _mm512_slli_epi32(load_lane_id_epi32(&LANE_ID_MSB_STR, prefix_set_index), 8);
                let lane_id_1_or_value = load_lane_id_epi32(&LANE_ID_LSB_STR, prefix_set_index);

                let lane_index_value_v = _mm512_or_epi32(
                    _mm512_set1_epi32(self.message.message[13] as _),
                    _mm512_or_epi32(lane_id_0_or_value, lane_id_1_or_value),
                );

                for next_inner_key in 1..=0o10_000_000 {
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
                    let cmp_fn = |x: __m512i, y: __m512i| {
                        if TYPE == crate::solver::SOLVE_TYPE_GT {
                            _mm512_cmpgt_epu32_mask(x, y)
                        } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                            _mm512_cmplt_epu32_mask(x, y)
                        } else {
                            _mm512_cmpeq_epu32_mask(
                                _mm512_and_si512(x, _mm512_set1_epi32((mask >> 32) as _)),
                                y,
                            )
                        }
                    };

                    #[cfg(feature = "compare-64bit")]
                    let cmp64_fn = |x: __m512i, y: __m512i| {
                        if TYPE == crate::solver::SOLVE_TYPE_GT {
                            _mm512_cmpgt_epu64_mask(x, y)
                        } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                            _mm512_cmplt_epu64_mask(x, y)
                        } else {
                            _mm512_cmpeq_epu64_mask(
                                _mm512_and_si512(x, _mm512_set1_epi64(mask as _)),
                                y,
                            )
                        }
                    };

                    state[0] = _mm512_add_epi32(state[0], save_a);

                    #[cfg(feature = "compare-64bit")]
                    {
                        state[1] = _mm512_add_epi32(state[1], save_b);
                    }

                    #[cfg(not(feature = "compare-64bit"))]
                    let met_target = (cmp_fn)(state[0], _mm512_set1_epi32((target >> 32) as _));

                    #[cfg(feature = "compare-64bit")]
                    let result_ab_lo = _mm512_unpacklo_epi32(state[1], state[0]);
                    #[cfg(feature = "compare-64bit")]
                    let result_ab_hi = _mm512_unpackhi_epi32(state[1], state[0]);
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
                        let success_lane_idx = met_target.trailing_zeros() as usize;

                        #[cfg(feature = "compare-64bit")]
                        let success_lane_idx = INDEX_REMAP_PUNPCKLDQ
                            [(met_target_high << 8 | met_target_lo).trailing_zeros() as usize];

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

                        let mut decimal_inner_key = 0;
                        let mut key_octal = next_inner_key - 1;
                        for m in (0..7u32).map(|i| 10u64.pow(i)) {
                            let output = (key_octal % 8) + 1;
                            key_octal /= 8;
                            decimal_inner_key += output as u64 * m;
                        }

                        let computed_nonce = nonce_prefix as u64 * 10u64.pow(7)
                            + decimal_inner_key
                            + self.message.nonce_addend;

                        // the nonce is the 8 digits in the message, plus the first two digits recomputed from the lane index
                        return Some((computed_nonce, *final_sha_state));
                    }

                    self.attempted_nonces += 16;

                    if self.attempted_nonces >= self.limit {
                        return None;
                    }

                    crate::strings::to_octal_7::<true, 0x80, 1>(&mut itoa_buf, next_inner_key);
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

/// AVX-512 binary nonce solver.
///
/// Output: nonce in little endian order
///
/// Current implementation: 16 way SIMD with 1-round hotstart granularity.
pub struct BinarySolver {
    message: BinaryMessage,
    attempted_nonces: u64,
    limit: u64,
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

impl From<crate::solver::safe::BinarySolver> for BinarySolver {
    fn from(solver: crate::solver::safe::BinarySolver) -> Self {
        Self {
            message: solver.message,
            attempted_nonces: solver.attempted_nonces,
            limit: solver.limit,
        }
    }
}

impl BinarySolver {
    /// Set the limit.
    ///
    /// Limits are approximate and should not be used to constrain search space, use `BinaryMessage` instead.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Get the attempted nonces.
    pub fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }

    #[inline(never)]
    fn solve_impl<
        const TYPE: u8,
        const FIRST_NONCE_WORD_IDX: usize,
        const NEED_SECOND_BLOCK: bool,
    >(
        &mut self,
        prefix_state: [u32; 8],
        first_block: &Align64<[u32; 16]>,
        second_block_schedule: &[u32; 64],
        nonce_byte_offset: usize,
        nonce_byte_count: core::num::NonZeroU8,
        target: u64,
        mask: u64,
    ) -> Option<u64> {
        let target = target & mask;

        // at most 3 words may need to be patched (i.e. 96 bits)
        // from which word to poke the nonce?
        let poke_word_base = FIRST_NONCE_WORD_IDX.min(16 - 4);
        let poke_word_byte_base = poke_word_base * 4;
        let mut poke_word_tbl = Align16([!0u8; 16]);
        let nonce_byte_count_decr = nonce_byte_count.get() as usize - 1;
        for (i, ix) in ((nonce_byte_offset + 1)..)
            .take(nonce_byte_count_decr)
            .enumerate()
        {
            poke_word_tbl.0[unsafe {
                *crate::SWAP_DWORD_BYTE_ORDER.get_unchecked(ix - poke_word_byte_base)
            }] = i as u8;
        }
        let poke_word_tbl = unsafe { _mm_load_si128(poke_word_tbl.as_ptr().cast()) };
        let lane_id_byte_remainder = 3 - nonce_byte_offset % 4;
        let mut lane_id_base = Align64([0u32; 16]);
        for i in 0..16 {
            lane_id_base[i as usize] = i << (lane_id_byte_remainder * 8);
        }
        let lane_id_iterand = 16 << (lane_id_byte_remainder * 8);

        let mut memo_state = prefix_state;
        crate::sha256::ingest_message_prefix::<FIRST_NONCE_WORD_IDX>(
            &mut memo_state,
            first_block[..FIRST_NONCE_WORD_IDX].try_into().unwrap(),
        );

        for x in 0..(self
            .limit
            .min(256u64.saturating_pow(nonce_byte_count_decr as u32))
            .max(1))
        {
            unsafe {
                let mut block_tpl = *first_block;
                let xm = _mm_cvtsi64x_si128(x as _);
                let xmd = _mm_shuffle_epi8(xm, poke_word_tbl);
                let loadd = _mm_loadu_si128(block_tpl.as_ptr().add(poke_word_base).cast());
                _mm_storeu_si128(
                    block_tpl.as_mut_ptr().add(poke_word_base).cast(),
                    _mm_or_si128(loadd, xmd),
                );
                let mut lane_id_v = _mm512_load_si512(lane_id_base.as_ptr().cast());

                for lane_id_set_idx in 0..(256 / 16) {
                    macro_rules! get_msg {
                        ($idx:expr) => {
                            if $idx == FIRST_NONCE_WORD_IDX {
                                _mm512_or_epi32(_mm512_set1_epi32(block_tpl[$idx] as _), lane_id_v)
                            } else {
                                _mm512_set1_epi32(block_tpl[$idx] as _)
                            }
                        };
                    }

                    let mut state = core::array::from_fn(|i| _mm512_set1_epi32(memo_state[i] as _));
                    let mut msg = [
                        get_msg!(0),
                        get_msg!(1),
                        get_msg!(2),
                        get_msg!(3),
                        get_msg!(4),
                        get_msg!(5),
                        get_msg!(6),
                        get_msg!(7),
                        get_msg!(8),
                        get_msg!(9),
                        get_msg!(10),
                        get_msg!(11),
                        get_msg!(12),
                        get_msg!(13),
                        get_msg!(14),
                        get_msg!(15),
                    ];

                    crate::sha256::avx512::multiway_arx::<FIRST_NONCE_WORD_IDX>(
                        &mut state, &mut msg,
                    );

                    if NEED_SECOND_BLOCK {
                        for i in 0..8 {
                            state[i] =
                                _mm512_add_epi32(state[i], _mm512_set1_epi32(prefix_state[i] as _));
                        }
                        let save_a = state[0];
                        #[cfg(feature = "compare-64bit")]
                        let save_b = state[1];

                        crate::sha256::avx512::bcst_multiway_arx::<0>(
                            &mut state,
                            second_block_schedule,
                        );
                        state[0] = _mm512_add_epi32(state[0], save_a);
                        #[cfg(feature = "compare-64bit")]
                        {
                            state[1] = _mm512_add_epi32(state[1], save_b);
                        }
                    } else {
                        state[0] =
                            _mm512_add_epi32(state[0], _mm512_set1_epi32(prefix_state[0] as _));
                        #[cfg(feature = "compare-64bit")]
                        {
                            state[1] =
                                _mm512_add_epi32(state[1], _mm512_set1_epi32(prefix_state[1] as _));
                        }
                    }

                    #[cfg(not(feature = "compare-64bit"))]
                    let cmp_fn = |x: __m512i, y: __m512i| {
                        if TYPE == crate::solver::SOLVE_TYPE_GT {
                            _mm512_cmpgt_epu32_mask(x, y)
                        } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                            _mm512_cmplt_epu32_mask(x, y)
                        } else {
                            _mm512_cmpeq_epu32_mask(
                                _mm512_and_si512(x, _mm512_set1_epi32((mask >> 32) as _)),
                                y,
                            )
                        }
                    };

                    #[cfg(feature = "compare-64bit")]
                    let cmp64_fn = |x: __m512i, y: __m512i| {
                        if TYPE == crate::solver::SOLVE_TYPE_GT {
                            _mm512_cmpgt_epu64_mask(x, y)
                        } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                            _mm512_cmplt_epu64_mask(x, y)
                        } else {
                            _mm512_cmpeq_epu64_mask(
                                _mm512_and_si512(x, _mm512_set1_epi64(mask as _)),
                                y,
                            )
                        }
                    };

                    #[cfg(not(feature = "compare-64bit"))]
                    let met_target = (cmp_fn)(state[0], _mm512_set1_epi32((target >> 32) as _));

                    #[cfg(feature = "compare-64bit")]
                    let result_ab_lo = _mm512_unpacklo_epi32(state[1], state[0]);
                    #[cfg(feature = "compare-64bit")]
                    let result_ab_hi = _mm512_unpackhi_epi32(state[1], state[0]);
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
                        let success_lane_idx = met_target.trailing_zeros() as usize;
                        #[cfg(feature = "compare-64bit")]
                        let success_lane_idx = INDEX_REMAP_PUNPCKLDQ
                            [(met_target_high << 8 | met_target_lo).trailing_zeros() as usize];

                        let nonce_addend = 16 * lane_id_set_idx + success_lane_idx;

                        let nonce = x << 8 | nonce_addend as u64;

                        return Some(nonce);
                    }

                    lane_id_v = _mm512_add_epi32(lane_id_v, _mm512_set1_epi32(lane_id_iterand));
                    self.attempted_nonces += 16;
                }

                if self.attempted_nonces >= self.limit {
                    return None;
                }
            }
        }

        None
    }
}

impl crate::solver::Solver for BinarySolver {
    fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, [u32; 8])> {
        if (self.message.nonce_byte_count.get() == 1) // edge case not worth optimizing, bail out
            || (self.message.salt_residual_len + self.message.nonce_byte_count.get() as usize > 64)
        // TODO: optimize edge case where nonce itself cross block boundary
        {
            crate::unlikely();
            let mut solver = crate::solver::safe::BinarySolver::from(self.message.clone());
            return solver.solve::<TYPE>(target, mask);
        }

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

        let mut block_template_be = Align64([0; 16]);
        for i in 0..16 {
            block_template_be[i] =
                u32::from_be_bytes(used_blocks[0][i * 4..][..4].try_into().unwrap());
        }

        let mut second_block_schedule = [0; 64];
        if cur_block == 1 {
            for i in 0..16 {
                second_block_schedule[i] =
                    u32::from_be_bytes(used_blocks[1][i * 4..][..4].try_into().unwrap());
            }
            crate::sha256::do_message_schedule_k_w(&mut second_block_schedule);
        }

        macro_rules! dispatch {
            ($skipped_rounds:expr) => {
                // bail out for unsupported lane positions
                if !is_supported_lane_position($skipped_rounds) {
                    crate::unlikely();
                    let mut solver = crate::solver::safe::BinarySolver::from(self.message.clone());
                    return solver.solve::<TYPE>(target, mask);
                } else if cur_block == 1 {
                    if let Some(nonce) = self.solve_impl::<TYPE, { $skipped_rounds }, true>(
                        *self.message.prefix_state,
                        &block_template_be,
                        &second_block_schedule,
                        self.message.salt_residual_len,
                        self.message.nonce_byte_count,
                        target,
                        mask,
                    ) {
                        let mut final_sha_state = self.message.prefix_state;
                        for i in 0..self.message.nonce_byte_count.get() as usize {
                            used_blocks[0][self.message.salt_residual_len + i] =
                                nonce.to_le_bytes()[i];
                        }
                        sha2::compress256(&mut final_sha_state, &used_blocks);
                        return Some((nonce, final_sha_state.0));
                    }
                } else {
                    if let Some(nonce) = self.solve_impl::<TYPE, { $skipped_rounds }, false>(
                        *self.message.prefix_state,
                        &block_template_be,
                        &[0; 64],
                        self.message.salt_residual_len,
                        self.message.nonce_byte_count,
                        target,
                        mask,
                    ) {
                        let mut final_sha_state = self.message.prefix_state;
                        for i in 0..self.message.nonce_byte_count.get() as usize {
                            used_blocks[0][self.message.salt_residual_len + i] =
                                nonce.to_le_bytes()[i];
                        }
                        sha2::compress256(&mut final_sha_state, &used_blocks);
                        return Some((nonce, final_sha_state.0));
                    }
                }
            };
        }

        match self.message.salt_residual_len / 4 {
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
            14 => dispatch!(14),
            15 => dispatch!(15),
            _ => unreachable!(),
        }

        crate::unlikely();

        None
    }
}

/// AVX-512 GoAway solver.
///
///
/// Current implementation: 16 way SIMD with 1-round hotstart granularity.
pub struct GoAwaySolver {
    challenge: [u32; 8],
    attempted_nonces: u64,
    limit: u64,
    fixed_high_word: Option<u32>,
}

impl From<super::safe::GoAwaySolver> for GoAwaySolver {
    fn from(solver: super::safe::GoAwaySolver) -> Self {
        Self {
            challenge: solver.challenge,
            attempted_nonces: solver.attempted_nonces,
            limit: solver.limit,
            fixed_high_word: solver.fixed_high_word,
        }
    }
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
    fn solve_nonce_only<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<u64> {
        unsafe {
            let lane_id_v = _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

            if !is_supported_lane_position(PREFIX_OFFSET_TO_LANE_POSITION[0]) {
                return None;
            }

            let target = target & mask;

            let mut prefix_state = crate::sha256::IV;
            crate::sha256::ingest_message_prefix(&mut prefix_state, self.challenge);

            let high_limit = (self.limit >> 32) as u32;
            let low_limit = self.limit as u32;

            for high_word in if let Some(high_word) = self.fixed_high_word {
                high_word..=high_word
            } else {
                0..=u32::MAX
            } {
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
                    let cmp_fn = |x: __m512i, y: __m512i| {
                        if TYPE == crate::solver::SOLVE_TYPE_GT {
                            _mm512_cmpgt_epu32_mask(x, y)
                        } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                            _mm512_cmplt_epu32_mask(x, y)
                        } else {
                            _mm512_cmpeq_epu32_mask(
                                _mm512_and_si512(x, _mm512_set1_epi32((mask >> 32) as _)),
                                y,
                            )
                        }
                    };

                    #[cfg(feature = "compare-64bit")]
                    let cmp64_fn = |x: __m512i, y: __m512i| {
                        if TYPE == crate::solver::SOLVE_TYPE_GT {
                            _mm512_cmpgt_epu64_mask(x, y)
                        } else if TYPE == crate::solver::SOLVE_TYPE_LT {
                            _mm512_cmplt_epu64_mask(x, y)
                        } else {
                            _mm512_cmpeq_epu64_mask(
                                _mm512_and_si512(x, _mm512_set1_epi64(mask as _)),
                                y,
                            )
                        }
                    };

                    #[cfg(not(feature = "compare-64bit"))]
                    let met_target = cmp_fn(state[0], _mm512_set1_epi32((target >> 32) as _));

                    #[cfg(feature = "compare-64bit")]
                    let result_ab_lo = _mm512_unpacklo_epi32(state[1], state[0]);
                    #[cfg(feature = "compare-64bit")]
                    let result_ab_hi = _mm512_unpackhi_epi32(state[1], state[0]);
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

                    self.attempted_nonces += 16;

                    if met_target_test {
                        crate::unlikely();

                        #[cfg(not(feature = "compare-64bit"))]
                        let success_lane_idx = met_target.trailing_zeros();

                        #[cfg(feature = "compare-64bit")]
                        let success_lane_idx = INDEX_REMAP_PUNPCKLDQ
                            [(met_target_high << 8 | met_target_lo).trailing_zeros() as usize];

                        let final_low_word = low_word | (success_lane_idx as u32);

                        return Some((high_word as u64) << 32 | final_low_word as u64);
                    }

                    if self.attempted_nonces >= self.limit {
                        return None;
                    }
                }
            }
        }
        None
    }

    fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, [u32; 8])> {
        let mut output_msg = [0; 16];
        let nonce = self.solve_nonce_only::<TYPE>(target, mask)?;
        output_msg[..8].copy_from_slice(&self.challenge);
        output_msg[8] = (nonce >> 32) as u32;
        output_msg[9] = nonce as u32;
        output_msg[10] = u32::from_be_bytes([0x80, 0, 0, 0]);
        output_msg[15] = Self::MSG_LEN as _;

        let mut final_sha_state = crate::sha256::IV;
        crate::sha256::digest_block(&mut final_sha_state, &output_msg);

        Some((nonce, final_sha_state))
    }
}

/// AVX-512 Ceberus solver.
///
/// Current implementation: 9-digit out-of-order kernel with dual-wavefront 16 way SIMD and quarter-round hotstart granularity.
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

impl CerberusSolver {
    #[inline(never)]
    fn solve_impl<
        const CENTER_WORD_IDX: usize,
        const LANE_ID_WORD_IDX: usize,
        const CONSTANT_WORD_COUNT: usize,
    >(
        &mut self,
        msg_tpl: Align64<[u32; 16]>,
        target: u64,
        mask: u64,
    ) -> Option<(u64, u64)> {
        debug_assert_eq!(target, 0);

        // inform LLVM that padding is guaranteed to be zero
        let mut msg = Align64([0u32; 16]);
        msg.0[..=CENTER_WORD_IDX + 1].copy_from_slice(&msg_tpl.0[..=CENTER_WORD_IDX + 1]);
        let prepared_state = crate::blake3::ingest_message_prefix(
            *self.message.prefix_state,
            &msg[..CONSTANT_WORD_COUNT],
            0,
            self.message.salt_residual_len as u32 + 9,
            self.message.flags,
        );

        for lane_id_idx in 0..(LANE_ID_STR_COMBINED_LE_HI.len() / 16) {
            if self.attempted_nonces >= self.limit {
                return None;
            }
            unsafe {
                let mut lane_id_value = _mm512_load_si512(
                    LANE_ID_STR_COMBINED_LE_HI
                        .as_ptr()
                        .add(lane_id_idx * 16)
                        .cast(),
                );
                if CENTER_WORD_IDX < LANE_ID_WORD_IDX {
                    lane_id_value = _mm512_srli_epi32(lane_id_value, 8);
                }

                let state_base =
                    core::array::from_fn(|i| _mm512_set1_epi32(prepared_state[i] as _));
                let patch =
                    _mm512_or_epi32(_mm512_set1_epi32(msg[LANE_ID_WORD_IDX] as _), lane_id_value);
                let maskv = _mm512_set1_epi32(mask as _);

                for (i, word) in crate::strings::DIGIT_LUT_10000_LE_EVEN.iter().enumerate() {
                    msg[CENTER_WORD_IDX] = *word;

                    let mut state = state_base;

                    crate::blake3::avx512::compress_mb16_reduced::<
                        CONSTANT_WORD_COUNT,
                        LANE_ID_WORD_IDX,
                    >(&mut state, &msg, patch);

                    let s0 = state[0];

                    msg[CENTER_WORD_IDX] |= u32::from_be_bytes([1, 0, 0, 0]);

                    state = state_base;
                    crate::blake3::avx512::compress_mb16_reduced::<
                        CONSTANT_WORD_COUNT,
                        LANE_ID_WORD_IDX,
                    >(&mut state, &msg, patch);
                    let s1 = state[0];

                    let hit0 = _mm512_testn_epi32_mask(s0, maskv);
                    let hit1 = _mm512_testn_epi32_mask(s1, maskv);

                    self.attempted_nonces += 32;

                    if hit0 != 0 || hit1 != 0 {
                        crate::unlikely();

                        let success_lane_idx0 = hit0.trailing_zeros();
                        let success_lane_idx1 = hit1.trailing_zeros();

                        if success_lane_idx0 < success_lane_idx1 {
                            return Some((
                                i as u64 * 2,
                                lane_id_idx as u64 * 16 + success_lane_idx0 as u64,
                            ));
                        } else {
                            return Some((
                                i as u64 * 2 + 1,
                                lane_id_idx as u64 * 16 + success_lane_idx1 as u64,
                            ));
                        }
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

                let msg = Align64(core::array::from_fn(|i| {
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

                    return Some(output_nonce);
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
