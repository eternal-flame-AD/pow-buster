use crate::{Align64, message::CerberusMessage};
use core::arch::x86_64::*;

static LANE_ID_STR_COMBINED_LE_HI: Align64<[u32; 1000 / 8 * 8]> = {
    let mut out = [0; 1000 / 8 * 8];
    let mut i = 0;
    while i < 1000 / 8 * 8 {
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

cpufeatures::new!(avx2, "avx2");

#[derive(Debug, Copy, Clone)]
/// Required features for AVX-2 solver.
pub struct RequiredFeatures;

impl Default for RequiredFeatures {
    fn default() -> Self {
        Self
    }
}

impl crate::solver::CpuIDToken for RequiredFeatures {
    fn get() -> bool {
        avx2::get()
    }
}

/// AVX-2 Cerberus solver.
///
/// Current implementation: 9-digit out-of-order kernel with dual-wavefront 8 way SIMD and quarter-round hotstart granularity.
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
    #[target_feature(enable = "avx2")]
    fn solve_decimal_impl<
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

        let CerberusMessage::Decimal(message) = &self.message else {
            return None;
        };

        // inform LLVM that padding is guaranteed to be zero
        let mut msg = Align64([0u32; 16]);
        msg.0[..=CENTER_WORD_IDX + 1].copy_from_slice(&msg_tpl.0[..=CENTER_WORD_IDX + 1]);
        let prepared_state = crate::blake3::ingest_message_prefix(
            *message.prefix_state,
            &msg[..CONSTANT_WORD_COUNT],
            0,
            message.salt_residual_len as u32 + 9,
            message.flags,
        );

        for lane_id_idx in 0..(LANE_ID_STR_COMBINED_LE_HI.len() / 8) {
            if self.attempted_nonces >= self.limit {
                return None;
            }
            unsafe {
                let mut lane_id_value = _mm256_load_si256(
                    LANE_ID_STR_COMBINED_LE_HI
                        .as_ptr()
                        .add(lane_id_idx * 8)
                        .cast(),
                );
                if CENTER_WORD_IDX < LANE_ID_WORD_IDX {
                    lane_id_value = _mm256_srli_epi32(lane_id_value, 8);
                }

                let state_base =
                    core::array::from_fn(|i| _mm256_set1_epi32(prepared_state[i] as _));
                let patch =
                    _mm256_or_epi32(_mm256_set1_epi32(msg[LANE_ID_WORD_IDX] as _), lane_id_value);
                let maskv = _mm256_set1_epi32((mask >> 32) as _);

                for (i, word) in crate::strings::DIGIT_LUT_10000_LE_EVEN.iter().enumerate() {
                    msg[CENTER_WORD_IDX] = *word;

                    let mut state = state_base;

                    crate::blake3::avx2::compress_mb8::<CONSTANT_WORD_COUNT, LANE_ID_WORD_IDX>(
                        &mut state, &msg, patch,
                    );

                    let s0 = state[0];
                    let sm0 = _mm256_and_si256(s0, maskv);
                    let cmp0 = _mm256_cmpeq_epi32(sm0, _mm256_setzero_si256());
                    let nothit0 = _mm256_testz_si256(cmp0, cmp0);
                    self.attempted_nonces += 8;

                    if nothit0 == 0 {
                        crate::unlikely();
                        let mut dump = Align64([0u32; 8]);
                        let word_idx = i as u64 * 2;

                        _mm256_store_si256(dump.as_mut_ptr().cast(), sm0);

                        let success_lane_idx = dump.0.iter().position(|x| *x == 0).unwrap();

                        return Some((word_idx, lane_id_idx as u64 * 8 + success_lane_idx as u64));
                    }

                    msg[CENTER_WORD_IDX] |= u32::from_be_bytes([1, 0, 0, 0]);

                    state = state_base;
                    crate::blake3::avx2::compress_mb8::<CONSTANT_WORD_COUNT, LANE_ID_WORD_IDX>(
                        &mut state, &msg, patch,
                    );

                    let s1 = state[0];
                    let sm1 = _mm256_and_si256(s1, maskv);
                    let cmp1 = _mm256_cmpeq_epi32(sm1, _mm256_setzero_si256());
                    let nothit1 = _mm256_testz_si256(cmp1, cmp1);
                    self.attempted_nonces += 8;

                    if nothit1 == 0 {
                        crate::unlikely();
                        let mut dump = Align64([0u32; 8]);
                        let word_idx = i as u64 * 2 + 1;

                        _mm256_store_si256(dump.as_mut_ptr().cast(), sm1);

                        let success_lane_idx = dump.0.iter().position(|x| *x == 0).unwrap();

                        return Some((word_idx, lane_id_idx as u64 * 8 + success_lane_idx as u64));
                    }
                }
            }
        }
        None
    }

    #[inline(never)]
    #[target_feature(enable = "avx2")]
    fn solve_binary_impl(&mut self, target: u64, mask: u64) -> Option<u64> {
        debug_assert_eq!(target, 0);

        let CerberusMessage::Binary(message) = &self.message else {
            return None;
        };

        let mut msg = [0; 16];
        msg[0] = message.first_word;
        let prepared_state = crate::blake3::ingest_message_prefix(
            *message.midstate,
            &msg[..1],
            0,
            8,
            crate::blake3::FLAG_CHUNK_END | crate::blake3::FLAG_ROOT,
        );
        unsafe {
            let state_base = core::array::from_fn(|i| _mm256_set1_epi32(prepared_state[i] as _));
            let mut nonce = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
            let increment_nonce = _mm256_set1_epi32(8);
            let masks = (mask >> 32) as u32;
            let maskv = _mm256_set1_epi32(masks as i32);
            for rep in 0..=(u32::MAX / 8) {
                let mut state = state_base;
                crate::blake3::avx2::compress_mb8::<1, 1>(&mut state, &msg, nonce);
                self.attempted_nonces += 8;
                let m = _mm256_and_si256(state[0], maskv);
                let cmp = _mm256_cmpeq_epi32(m, _mm256_setzero_si256());
                let nothit = _mm256_testz_si256(cmp, cmp);
                if nothit == 0 {
                    crate::unlikely();
                    let mut dump = Align64([0u32; 8]);
                    _mm256_store_si256(dump.as_mut_ptr().cast(), state[0]);
                    let success_lane_idx = dump.0.iter().position(|x| *x & masks == 0).unwrap();
                    return Some(
                        (rep * 8 + success_lane_idx as u32) as u64
                            | (message.first_word as u64) << 32,
                    );
                }
                nonce = _mm256_add_epi32(nonce, increment_nonce);
                if self.attempted_nonces >= self.limit {
                    return None;
                }
            }
        }
        None
    }
}

impl crate::solver::Solver for CerberusSolver {
    fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    fn get_attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }

    fn solve_nonce_only<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<u64> {
        match &self.message {
            CerberusMessage::Binary(_) => unsafe { self.solve_binary_impl(target, mask) },
            CerberusMessage::Decimal(message) => {
                // two digits as lane ID, N=\x00, ? is prefix
                // position % 4 =0: |1234|5678|NNN9
                // position % 4 =1: |123?|4567|NN89
                // position % 4 =2: |12??|3456|N789
                // position % 4 =3: |1???|2345|6789

                let center_word_idx = message.salt_residual_len / 4 + 1;
                let nonce_addend = message.nonce_addend;
                let salt_residual = message.salt_residual;
                let salt_residual_len = message.salt_residual_len;
                let position_mod = message.salt_residual_len % 4;

                for resid0 in 0..10u64 {
                    for resid1 in 0..10u64 {
                        if self.attempted_nonces >= self.limit {
                            return None;
                        }
                        let mut msg = salt_residual;

                        match position_mod {
                            0 => {
                                msg[salt_residual_len] = resid0 as u8 + b'0';
                                msg[salt_residual_len + 8] = resid1 as u8 + b'0';
                            }
                            1 => {
                                msg[salt_residual_len + 7] = resid0 as u8 + b'0';
                                msg[salt_residual_len + 8] = resid1 as u8 + b'0';
                            }
                            2 => {
                                msg[salt_residual_len] = resid0 as u8 + b'0';
                                msg[salt_residual_len + 1] = resid1 as u8 + b'0';
                            }
                            3 => {
                                msg[salt_residual_len] = resid0 as u8 + b'0';
                                msg[salt_residual_len + 8] = resid1 as u8 + b'0';
                            }
                            _ => unreachable!(),
                        }

                        let msg = Align64(core::array::from_fn(|i| {
                            u32::from_le_bytes([
                                msg[i * 4],
                                msg[i * 4 + 1],
                                msg[i * 4 + 2],
                                msg[i * 4 + 3],
                            ])
                        }));

                        macro_rules! dispatch {
                            ($center_word_idx:literal) => {
                                if position_mod < 2 {
                                    unsafe {
                                        self.solve_decimal_impl::<$center_word_idx, { $center_word_idx - 1 }, {$center_word_idx - 1}>(
                                        msg, target, mask,
                                        )
                                    }
                                } else {
                                    unsafe {
                                        self.solve_decimal_impl::<$center_word_idx, { $center_word_idx + 1 }, $center_word_idx>(
                                        msg, target, mask,
                                        )
                                    }
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
                            let output_nonce = nonce_addend
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
        }
    }

    fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, [u32; 8])> {
        if let Some(nonce) = self.solve_nonce_only::<TYPE>(target, mask) {
            match &self.message {
                CerberusMessage::Decimal(message) => {
                    let mut msg = message.salt_residual;

                    let mut nonce_copy = nonce;
                    for i in (0..9).rev() {
                        msg[message.salt_residual_len + i] = (nonce_copy % 10) as u8 + b'0';
                        nonce_copy /= 10;
                    }

                    let mut msg = core::array::from_fn(|i| {
                        u32::from_le_bytes([
                            msg[i * 4],
                            msg[i * 4 + 1],
                            msg[i * 4 + 2],
                            msg[i * 4 + 3],
                        ])
                    });

                    let hash = crate::blake3::compress8(
                        &message.prefix_state,
                        &mut msg,
                        0,
                        message.salt_residual_len as u32 + 9,
                        message.flags,
                    );

                    Some((nonce, hash))
                }
                CerberusMessage::Binary(message) => {
                    let mut msg = [0; 16];
                    msg[0] = message.first_word;
                    msg[1] = nonce as u32;
                    let hash = crate::blake3::compress8(
                        &message.midstate,
                        &msg,
                        0,
                        8,
                        crate::blake3::FLAG_CHUNK_END | crate::blake3::FLAG_ROOT,
                    );
                    Some((msg[1] as u64 | (msg[0] as u64) << 32, hash))
                }
            }
        } else {
            None
        }
    }
}

#[cfg(target_feature = "avx2")]
#[cfg(test)]
mod tests {
    use crate::message::{CerberusBinaryMessage, CerberusDecimalMessage};

    use super::*;

    #[test]
    fn test_solve_cerberus_decimal() {
        for i in 0..=1 {
            crate::solver::tests::test_cerberus_decimal_validator::<CerberusSolver, _>(|prefix| {
                Some(CerberusMessage::Decimal(CerberusDecimalMessage::new(prefix, i)?).into())
            });
        }
    }

    #[test]
    fn test_solve_cerberus_binary() {
        for i in 0..=1 {
            crate::solver::tests::test_cerberus_binary_validator::<CerberusSolver, _>(|prefix| {
                Some(CerberusMessage::Binary(CerberusBinaryMessage::new(prefix, i)).into())
            });
        }
    }
}
