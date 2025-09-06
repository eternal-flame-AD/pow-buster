#![cfg_attr(target_feature = "avx512f", allow(dead_code, unused))]

// these are mainly adapted from the sha2 crate as well,
// the core logic is verbatim, but shuffling and batch message loading overhead is removed
use core::arch::x86_64::*;

use crate::Align16;
use crate::sha256::K32;

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/local_macros.rs"));

const K32X4: [[u32; 4]; 16] = [
    [K32[3], K32[2], K32[1], K32[0]],
    [K32[7], K32[6], K32[5], K32[4]],
    [K32[11], K32[10], K32[9], K32[8]],
    [K32[15], K32[14], K32[13], K32[12]],
    [K32[19], K32[18], K32[17], K32[16]],
    [K32[23], K32[22], K32[21], K32[20]],
    [K32[27], K32[26], K32[25], K32[24]],
    [K32[31], K32[30], K32[29], K32[28]],
    [K32[35], K32[34], K32[33], K32[32]],
    [K32[39], K32[38], K32[37], K32[36]],
    [K32[43], K32[42], K32[41], K32[40]],
    [K32[47], K32[46], K32[45], K32[44]],
    [K32[51], K32[50], K32[49], K32[48]],
    [K32[55], K32[54], K32[53], K32[52]],
    [K32[59], K32[58], K32[57], K32[56]],
    [K32[63], K32[62], K32[61], K32[60]],
];

#[inline(always)]
unsafe fn schedule(v0: __m128i, v1: __m128i, v2: __m128i, v3: __m128i) -> __m128i {
    unsafe {
        let t1 = _mm_sha256msg1_epu32(v0, v1);
        let t2 = _mm_alignr_epi8(v3, v2, 4);
        let t3 = _mm_add_epi32(t1, t2);
        _mm_sha256msg2_epu32(t3, v3)
    }
}

#[inline(always)]
pub(crate) fn prepare_state(state: &Align16<[u32; 8]>) -> [__m128i; 2] {
    unsafe {
        let state_ptr = state.as_ptr().cast::<__m128i>();
        let dcba = _mm_load_si128(state_ptr.add(0));
        let efgh = _mm_load_si128(state_ptr.add(1));

        let cdab = _mm_shuffle_epi32(dcba, 0xB1);
        let efgh = _mm_shuffle_epi32(efgh, 0x1B);
        let abef = _mm_alignr_epi8(cdab, efgh, 8);
        let cdgh = _mm_blend_epi16(efgh, cdab, 0xF0);

        [abef, cdgh]
    }
}

#[allow(unused_variables)]
pub trait Plucker {
    fn pluck_qword0(&mut self, lane: usize, w: &mut __m128i) {}
    fn pluck_qword1(&mut self, lane: usize, w: &mut __m128i) {}
    fn pluck_qword2(&mut self, lane: usize, w: &mut __m128i) {}
    fn pluck_qword3(&mut self, lane: usize, w: &mut __m128i) {}
}

impl Plucker for () {}

// ARX network using altered data layout
#[inline(always)]
pub(crate) fn multiway_arx_abef_cdgh<
    const BEGIN_ROUND_BY_4: usize,
    const LANES: usize,
    P: Plucker,
>(
    mut state: [&mut [__m128i; 2]; LANES],
    block_template: &Align16<[u32; 16]>,
    mut plucker: P,
) {
    unsafe {
        macro_rules! rounds4 {
            ($abef:ident, $cdgh:ident, $rest:expr, $i:expr) => {{
                let k = K32X4[$i];
                let kv = _mm_set_epi32(k[0] as i32, k[1] as i32, k[2] as i32, k[3] as i32);
                let t1: [_; LANES] = core::array::from_fn(|i| _mm_add_epi32($rest[i], kv));
                $cdgh = core::array::from_fn(|i| _mm_sha256rnds2_epu32($cdgh[i], $abef[i], t1[i]));
                let t2: [_; LANES] = core::array::from_fn(|i| _mm_shuffle_epi32(t1[i], 0x0E));
                $abef = core::array::from_fn(|i| _mm_sha256rnds2_epu32($abef[i], $cdgh[i], t2[i]));
            }};
        }

        macro_rules! schedule_rounds4 {
            (
            $abef:ident, $cdgh:ident,
            $w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr,
            $i: expr
        ) => {{
                $w4 = core::array::from_fn(|i| schedule($w0[i], $w1[i], $w2[i], $w3[i]));
                rounds4!($abef, $cdgh, $w4, $i);
            }};
        }

        let mut abef: [_; LANES] = core::array::from_fn(|i| state[i][0]);
        let mut cdgh: [_; LANES] = core::array::from_fn(|i| state[i][1]);

        let w0_t = _mm_load_si128(block_template.as_ptr().cast::<u32>().add(0).cast());
        let w1_t = _mm_load_si128(block_template.as_ptr().cast::<u32>().add(4).cast());
        let w2_t = _mm_load_si128(block_template.as_ptr().cast::<u32>().add(8).cast());
        let w3_t = _mm_load_si128(block_template.as_ptr().cast::<u32>().add(12).cast());

        let mut w0: [_; LANES] = core::array::from_fn(|i| {
            let mut w = w0_t;
            plucker.pluck_qword0(i, &mut w);
            w
        });
        let mut w1: [_; LANES] = core::array::from_fn(|i| {
            let mut w = w1_t;
            plucker.pluck_qword1(i, &mut w);
            w
        });
        let mut w2: [_; LANES] = core::array::from_fn(|i| {
            let mut w = w2_t;
            plucker.pluck_qword2(i, &mut w);
            w
        });
        let mut w3: [_; LANES] = core::array::from_fn(|i| {
            let mut w = w3_t;
            plucker.pluck_qword3(i, &mut w);
            w
        });
        let mut w4: [_; LANES] = core::array::from_fn(|i| schedule(w0[i], w1[i], w2[i], w3[i]));

        macro_rules! gate_rnds {
            ($cutoff: literal, $($body:tt)*) => {
                if $cutoff >= BEGIN_ROUND_BY_4 * 4 {
                    $($body)*
                }
            };
        }

        gate_rnds!(0, {
            rounds4!(abef, cdgh, w0, 0);
        });
        gate_rnds!(4, {
            rounds4!(abef, cdgh, w1, 1);
        });
        gate_rnds!(8, {
            rounds4!(abef, cdgh, w2, 2);
        });
        gate_rnds!(12, {
            rounds4!(abef, cdgh, w3, 3);
        });
        gate_rnds!(16, {
            schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 4);
        });
        gate_rnds!(20, {
            schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 5);
        });
        gate_rnds!(24, {
            schedule_rounds4!(abef, cdgh, w2, w3, w4, w0, w1, 6);
        });
        gate_rnds!(28, {
            schedule_rounds4!(abef, cdgh, w3, w4, w0, w1, w2, 7);
        });
        gate_rnds!(32, {
            schedule_rounds4!(abef, cdgh, w4, w0, w1, w2, w3, 8);
        });
        gate_rnds!(36, {
            schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 9);
        });
        gate_rnds!(40, {
            schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 10);
        });
        gate_rnds!(44, {
            schedule_rounds4!(abef, cdgh, w2, w3, w4, w0, w1, 11);
        });
        gate_rnds!(48, {
            schedule_rounds4!(abef, cdgh, w3, w4, w0, w1, w2, 12);
        });
        gate_rnds!(52, {
            schedule_rounds4!(abef, cdgh, w4, w0, w1, w2, w3, 13);
        });
        gate_rnds!(56, {
            schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 14);
        });
        gate_rnds!(60, {
            schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 15);
        });

        state.iter_mut().zip(abef).for_each(|(state, abef)| {
            _mm_store_si128(
                state
                    .as_mut_slice()
                    .as_mut_ptr()
                    .cast::<u32>()
                    .add(0)
                    .cast(),
                abef,
            );
        });

        state.iter_mut().zip(cdgh).for_each(|(state, cdgh)| {
            _mm_store_si128(
                state
                    .as_mut_slice()
                    .as_mut_ptr()
                    .cast::<u32>()
                    .add(4)
                    .cast(),
                cdgh,
            );
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiway_arx() {
        use core::arch::x86_64::*;
        let input_block = [
            0x61626380, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000018,
        ];

        let state = Align16(crate::sha256::IV);

        let mut prepared_state_0 = prepare_state(&state);
        let mut prepared_state_1 = prepare_state(&state);

        multiway_arx_abef_cdgh::<0, 2, ()>(
            [&mut prepared_state_0, &mut prepared_state_1],
            &Align16(input_block),
            (),
        );

        let a = unsafe { _mm_extract_epi32(prepared_state_0[0], 3) as u32 };
        let b = unsafe { _mm_extract_epi32(prepared_state_0[0], 2) as u32 };

        let ab = unsafe { _mm_extract_epi64(prepared_state_0[0], 1) };
        let ab_b = ab as u32;
        let ab_a = (ab >> 32) as u32;

        let mut full_message_schedule = [0u32; 64];
        full_message_schedule[0..16].copy_from_slice(&input_block);
        crate::sha256::do_message_schedule(&mut full_message_schedule);

        let mut reference_state = Align16(crate::sha256::IV);
        crate::sha256::sha2_arx::<0, 64>(&mut reference_state, full_message_schedule);

        assert_eq!(a, reference_state[0]);
        assert_eq!(b, reference_state[1]);
        assert_eq!(ab_a, reference_state[0], "a={} b={}", a, b);
        assert_eq!(ab_b, reference_state[1], "a={} b={}", a, b);
    }
}
