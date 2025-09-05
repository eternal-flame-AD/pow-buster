use core::num::NonZeroU32;

use crate::Align16;
#[cfg(target_feature = "avx512f")]
use crate::Align64;

const MAGIC_NUMBERS: [MagicNumber; 8] = [
    find_magic_number(NonZeroU32::new(1).unwrap()),
    find_magic_number(NonZeroU32::new(10).unwrap()),
    find_magic_number(NonZeroU32::new(100).unwrap()),
    find_magic_number(NonZeroU32::new(1000).unwrap()),
    find_magic_number(NonZeroU32::new(10000).unwrap()),
    find_magic_number(NonZeroU32::new(100000).unwrap()),
    find_magic_number(NonZeroU32::new(1000000).unwrap()),
    find_magic_number(NonZeroU32::new(10000000).unwrap()),
];

#[cfg(target_feature = "avx512f")]
static DIV_BY_10_MULTIPLIERS: Align64<[u64; 8]> = Align64([
    MAGIC_NUMBERS[0].m as u64,
    MAGIC_NUMBERS[1].m as u64,
    MAGIC_NUMBERS[2].m as u64,
    MAGIC_NUMBERS[3].m as u64,
    MAGIC_NUMBERS[4].m as u64,
    MAGIC_NUMBERS[5].m as u64,
    MAGIC_NUMBERS[6].m as u64,
    MAGIC_NUMBERS[7].m as u64,
]);

#[cfg(target_feature = "avx512f")]
static DIV_BY_10_SHIFTS: Align64<[u64; 8]> = Align64([
    (MAGIC_NUMBERS[0].s + 32) as u64,
    (MAGIC_NUMBERS[1].s + 32) as u64,
    (MAGIC_NUMBERS[2].s + 32) as u64,
    (MAGIC_NUMBERS[3].s + 32) as u64,
    (MAGIC_NUMBERS[4].s + 32) as u64,
    (MAGIC_NUMBERS[5].s + 32) as u64,
    (MAGIC_NUMBERS[6].s + 32) as u64,
    (MAGIC_NUMBERS[7].s + 32) as u64,
]);

#[derive(Debug, Clone, Copy)]
struct MagicNumber {
    m: i32,
    s: i32,
}

impl MagicNumber {
    const fn new(m: i32, s: i32) -> Self {
        Self { m, s }
    }

    #[inline(always)]
    const fn divide(self, n: u32) -> u32 {
        let mut t = n;
        t = ((t as u64).wrapping_mul(self.m as u64) >> 32) as u32;
        t = t.wrapping_shr(self.s as u32);
        t += n >> 31;
        t
    }
}

const fn find_magic_number(d: NonZeroU32) -> MagicNumber {
    // https://github.com/milakov/int_fastdiv/blob/master/int_fastdiv.h#L53

    let d = d.get();
    if d == 1 {
        return MagicNumber::new(1, -32);
    }

    const TWO31: u32 = 0x80000000;
    let t = TWO31 + (d >> 31);
    let anc = t - 1 - t % d;
    let mut p = 31;
    let mut q1 = TWO31 / anc;
    let mut r1 = TWO31 - q1 * anc;
    let mut q2 = TWO31 / d;
    let mut r2 = TWO31 - q2 * d;
    let mut delta = u32::MAX;

    while q1 < delta || (q1 == delta && r1 == 0) {
        p += 1;
        q1 = 2 * q1;
        r1 = 2 * r1;
        if r1 >= anc {
            q1 += 1;
            r1 -= anc;
        }
        q2 = 2 * q2;
        r2 = 2 * r2;
        if r2 >= d {
            q2 += 1;
            r2 -= d;
        }
        delta = d - r2;
    }

    MagicNumber::new((q2 + 1) as i32, p - 32)
}

struct ComputeMask<const N: usize, const PLACEHOLDER: u8>;

impl<const N: usize, const PLACEHOLDER: u8> ComputeMask<N, PLACEHOLDER> {
    const MASK: u64 = const {
        let zero_mask = (1u64.unbounded_shl(8 * N as u32)).wrapping_sub(1);
        let placeholder_mask = !zero_mask;

        (u64::from_be_bytes([PLACEHOLDER; 8]) & placeholder_mask)
            ^ (u64::from_be_bytes([b'0'; 8]) & zero_mask)
    };
}

/// Convert up to 8 digits to ASCII
///
/// Parameters:
/// - N: The number of digits to convert, aligned to the left
/// - REGISTER_BSWAP: Swap 32-bit register bytes order
/// - PLACEHOLDER: The placeholder character to use for the rest of the bytes
#[cfg_attr(target_feature = "avx512f", expect(unreachable_code))]
#[inline(always)]
pub(crate) fn simd_itoa8<const N: usize, const REGISTER_BSWAP: bool, const PLACEHOLDER: u8>(
    out: &mut Align16<[u8; 8]>,
    input: u32,
) {
    if N == 0 {
        return;
    }

    let mask = ComputeMask::<N, PLACEHOLDER>::MASK;

    #[cfg(target_feature = "avx512f")]
    {
        use core::arch::x86_64::*;

        struct FindShuffle<const N: usize>;

        impl<const N: usize> FindShuffle<N> {
            const TABLE: Align16<[u8; 16]> = {
                let mut table = [7, 6, 5, 4, 3, 2, 1, 0, 8, 8, 8, 8, 8, 8, 8, 8];
                let mut table2 = [0; 16];
                let mut idx = 0;
                // shift elements by the difference in digit count
                while idx < 8 {
                    table[idx] = table[idx + (8 - N)];
                    idx += 1;
                }
                idx = 0;
                // swap bytes
                while idx < 16 {
                    table2[idx] = table[idx / 4 * 4 + (3 - idx % 4)];
                    idx += 1;
                }
                Align16(table2)
            };
        }

        unsafe {
            let input0 = _mm512_set1_epi64(input as _);
            let v0_mul = _mm512_mul_epi32(
                input0,
                _mm512_load_si512(DIV_BY_10_MULTIPLIERS.as_ptr().cast()),
            );
            let div_results =
                _mm512_srlv_epi64(v0_mul, _mm512_load_si512(DIV_BY_10_SHIFTS.as_ptr().cast()));

            const MAGIC_NUMBER_10_MULTIPLIER: u64 =
                find_magic_number(NonZeroU32::new(10).unwrap()).m as u64;

            let div_div_10_mul = _mm512_mul_epi32(
                div_results,
                _mm512_set1_epi64(MAGIC_NUMBER_10_MULTIPLIER as _),
            );

            const MAGIC_NUMBER_10_SHIFT: u32 =
                find_magic_number(NonZeroU32::new(10).unwrap()).s as u32 + 32;

            let div_div_10_mul_results = _mm512_srli_epi64(div_div_10_mul, MAGIC_NUMBER_10_SHIFT);

            let v0 = _mm512_mul_epi32(div_div_10_mul_results, _mm512_set1_epi64(10));

            let residuals = _mm512_sub_epi64(div_results, v0);

            let mut cvt = _mm512_cvtepi64_epi8(residuals);
            if REGISTER_BSWAP {
                cvt = _mm_or_si128(cvt, _mm_set1_epi8(b'0' as _));
                cvt = _mm_insert_epi8(cvt, PLACEHOLDER as _, 8);
                cvt =
                    _mm_shuffle_epi8(cvt, _mm_load_si128(FindShuffle::<N>::TABLE.as_ptr().cast()));

                let cvtu64 = _mm_cvtsi128_si64(cvt) as u64;
                out.as_mut_ptr().cast::<u64>().write(cvtu64);
            } else {
                let mut cvtu64 = _mm_cvtsi128_si64(cvt) as u64;

                cvtu64 <<= (8 - N) * 8;
                cvtu64 = cvtu64.swap_bytes();

                out.as_mut_ptr().cast::<u64>().write(cvtu64 | mask);
            }
        }

        return;
    }

    let mut input = input;

    out.fill(0);
    for i in (0..N).rev() {
        out[i] = (input % 10) as u8;
        input /= 10;
    }

    let out_ptr = out.as_mut_ptr().cast::<u64>();
    unsafe {
        *out_ptr = *out_ptr | mask;
    }

    if REGISTER_BSWAP {
        let mut out_ptr = out.as_mut_ptr().cast::<u32>();
        unsafe {
            *out_ptr = (*out_ptr).swap_bytes();
            out_ptr = out_ptr.add(1);
            *out_ptr = (*out_ptr).swap_bytes();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_itoa() {
        let mut buf = Align16([0u8; 8]);
        simd_itoa8::<8, false, 0x80>(&mut buf, 12345678);
        assert_eq!(buf, Align16(*b"12345678"));

        simd_itoa8::<8, false, 0x80>(&mut buf, 1_0000_0000);
        assert_eq!(buf, Align16(*b"00000000"));

        simd_itoa8::<7, false, 0x80>(&mut buf, 1234567);
        assert_eq!(buf, Align16(*b"1234567\x80"));

        simd_itoa8::<7, false, 0x80>(&mut buf, 1000_0000);
        assert_eq!(buf, Align16(*b"0000000\x80"));

        simd_itoa8::<8, true, 0x80>(&mut buf, 12345678);
        assert_eq!(buf, Align16(*b"43218765"));

        simd_itoa8::<7, true, 0x80>(&mut buf, 1234567);
        assert_eq!(buf, Align16(*b"4321\x80765"));
    }
}
