#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "wasm-bindgen")]
use wasm_bindgen::prelude::*;

use core::num::NonZeroU8;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "client")]
/// Web client for solving mCaptcha PoW
pub mod client;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "wasm-bindgen")]
mod wasm_ffi;

/// String manipulation functions
#[cfg(any(target_feature = "avx512f", target_feature = "avx2"))]
mod strings;

/// SHA-256 primitives
mod sha256;

pub mod message;

pub mod solver;

#[cfg(feature = "adapter")]
pub mod adapter;

#[cfg(all(
    not(doc),
    not(any(target_arch = "x86_64", target_arch = "x86")),
    not(target_arch = "wasm32")
))]
compile_error!("Only x86_64 and wasm32 are supported");

#[cfg(all(not(doc), target_arch = "wasm32", feature = "compare-64bit"))]
compile_error!("compare-64bit is only supported on x86_64 architectures");

#[cfg(all(
    not(doc),
    target_arch = "wasm32",
    not(feature = "ignore-target-feature-checks"),
    not(target_feature = "simd128")
))]
compile_error!(concat!(
    "SIMD128 extensions required. Compile with -Ctarget-feature=+simd128, ",
    "alternatively pass --features ignore-target-feature-checks to build a slow reference implementation."
));

#[repr(align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Align16<T>(T);

impl<T> core::ops::Deref for Align16<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> core::ops::DerefMut for Align16<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[repr(align(64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Align64<T>(T);

//Ref downcast to Align16
impl<'a, T> Into<&'a Align16<T>> for &'a Align64<T> {
    fn into(self) -> &'a Align16<T> {
        unsafe { core::mem::transmute(self) }
    }
}

//Ref downcast to Align16
impl<'a, T> Into<&'a mut Align16<T>> for &'a mut Align64<T> {
    fn into(self) -> &'a mut Align16<T> {
        unsafe { core::mem::transmute(self) }
    }
}

impl<T> core::ops::Deref for Align64<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> core::ops::DerefMut for Align64<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cold]
fn unlikely() {}

#[cfg(feature = "wasm-bindgen")]
#[wasm_bindgen]
pub fn prefix_offset_to_lane_position(offset: usize) -> usize {
    PREFIX_OFFSET_TO_LANE_POSITION[offset]
}

const PREFIX_OFFSET_TO_LANE_POSITION: [usize; 64] = [
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9, 9,
    8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 13, 13, 13, 13, 13, 13, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1,
];

const SWAP_DWORD_BYTE_ORDER: [usize; 64] = [
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 19, 18, 17, 16, 23, 22, 21, 20, 27, 26,
    25, 24, 31, 30, 29, 28, 35, 34, 33, 32, 39, 38, 37, 36, 43, 42, 41, 40, 47, 46, 45, 44, 51, 50,
    49, 48, 55, 54, 53, 52, 59, 58, 57, 56, 63, 62, 61, 60,
];

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
cfg_if::cfg_if! {
    if #[cfg(target_feature = "avx512f")] {
        pub type SingleBlockSolver = crate::solver::avx512::SingleBlockSolver;
        pub type DoubleBlockSolver = crate::solver::avx512::DoubleBlockSolver;
        pub type DecimalSolver = crate::solver::avx512::DecimalSolver;
        pub type GoAwaySolver = crate::solver::avx512::GoAwaySolver;
    } else if #[cfg(target_feature = "sha")] {
        pub type SingleBlockSolver = crate::solver::sha_ni::SingleBlockSolver;
        pub type DoubleBlockSolver = crate::solver::sha_ni::DoubleBlockSolver;
        pub type DecimalSolver = crate::solver::sha_ni::DecimalSolver;
        pub type GoAwaySolver = crate::solver::sha_ni::GoAwaySolver;
    } else {
        pub type SingleBlockSolver = crate::solver::safe::SingleBlockSolver;
        pub type DoubleBlockSolver = crate::solver::safe::DoubleBlockSolver;
        pub type DecimalSolver = crate::solver::safe::DecimalSolver;
        pub type GoAwaySolver = crate::solver::safe::GoAwaySolver;
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
cfg_if::cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        pub type SingleBlockSolver = crate::solver::simd128::SingleBlockSolver;
        pub type DoubleBlockSolver = crate::solver::simd128::DoubleBlockSolver;
        pub type DecimalSolver = crate::solver::simd128::DecimalSolver;
        pub type GoAwaySolver = crate::solver::simd128::GoAwaySolver;
    } else {
        pub type SingleBlockSolver = crate::solver::safe::SingleBlockSolver;
        pub type DoubleBlockSolver = crate::solver::safe::DoubleBlockSolver;
        pub type DecimalSolver = crate::solver::safe::DecimalSolver;
        pub type GoAwaySolver = crate::solver::safe::GoAwaySolver;
    }
}

pub fn build_prefix<E: Extend<u8>>(out: &mut E, string: &str, salt: &str) {
    out.extend(salt.as_bytes().iter().copied());
    out.extend((string.len() as u64).to_le_bytes());
    out.extend(string.as_bytes().iter().copied());
}

pub const fn decompose_blocks(inp: &[u32; 16]) -> &[u8; 64] {
    unsafe { core::mem::transmute(inp) }
}

pub const fn decompose_blocks_mut(inp: &mut [u32; 16]) -> &mut [u8; 64] {
    unsafe { core::mem::transmute(inp) }
}

/// Compute the target for an mCaptcha PoW
pub const fn compute_target(difficulty_factor: u32) -> u128 {
    u128::MAX - u128::MAX / difficulty_factor as u128
}

/// Compute the target for an mCaptcha PoW
pub const fn compute_target_64(difficulty_factor: u64) -> u128 {
    u128::MAX - u128::MAX / difficulty_factor as u128
}

/// Compute the target for an Anubis PoW
pub const fn compute_target_anubis(difficulty_factor: NonZeroU8) -> u128 {
    // some people misconfigure with difficulty 0
    if difficulty_factor.get() == 0 {
        return u128::MAX;
    }
    1u128 << (128 - difficulty_factor.get() * 4)
}

/// Compute the target for a GoAway PoW
pub const fn compute_target_goaway(difficulty_factor: NonZeroU8) -> u128 {
    1u128 << (128 - difficulty_factor.get())
}

/// Extract top 128 bits from a 64-bit word array
pub const fn extract128_be(inp: [u32; 8]) -> u128 {
    (inp[0] as u128) << 96 | (inp[1] as u128) << 64 | (inp[2] as u128) << 32 | (inp[3] as u128)
}

pub const fn is_supported_lane_position(lane_position: usize) -> bool {
    match lane_position {
        0 => cfg!(feature = "lane-position-0"),
        1 => cfg!(feature = "lane-position-1"),
        2 => cfg!(feature = "lane-position-2"),
        3 => cfg!(feature = "lane-position-3"),
        4 => cfg!(feature = "lane-position-4"),
        5 => cfg!(feature = "lane-position-5"),
        6 => cfg!(feature = "lane-position-6"),
        7 => cfg!(feature = "lane-position-7"),
        8 => cfg!(feature = "lane-position-8"),
        9 => cfg!(feature = "lane-position-9"),
        10 => cfg!(feature = "lane-position-10"),
        11 => cfg!(feature = "lane-position-11"),
        12 => cfg!(feature = "lane-position-12"),
        13 => cfg!(feature = "lane-position-13"),
        14 => cfg!(feature = "lane-position-14"),
        15 => cfg!(feature = "lane-position-15"),
        _ => false,
    }
}

#[cfg(feature = "wasm-bindgen")]
#[wasm_bindgen(js_name = "is_supported_lane_position")]
pub fn is_supported_lane_position_wasm(lane_position: usize) -> bool {
    is_supported_lane_position(lane_position)
}

/// Encode a sha-256 hash into hex
pub fn encode_hex(out: &mut [u8; 64], inp: [u32; 8]) {
    for w in 0..8 {
        let be_bytes = inp[w].to_be_bytes();
        be_bytes.iter().enumerate().for_each(|(i, b)| {
            let high_nibble = b >> 4;
            let low_nibble = b & 0xf;
            out[w * 8 + i * 2] = if high_nibble < 10 {
                high_nibble + b'0'
            } else {
                high_nibble + b'a' - 10
            };
            out[w * 8 + i * 2 + 1] = if low_nibble < 10 {
                low_nibble + b'0'
            } else {
                low_nibble + b'a' - 10
            };
        });
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    pub fn build_prefix_official<W: std::io::Write>(
        out: &mut W,
        string: &str,
        salt: &str,
    ) -> std::io::Result<()> {
        out.write_all(salt.as_bytes())?;
        match bincode::serialize_into(out, string) {
            Ok(_) => (),
            Err(e) => match *e {
                bincode::ErrorKind::Io(e) => return Err(e),
                _ => unreachable!(),
            },
        };
        Ok(())
    }

    #[test]
    #[cfg_attr(feature = "wasm-bindgen", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_encode_hex() {
        let mut out = [0u8; 64];
        encode_hex(
            &mut out,
            [
                0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678,
                0x9abcdef0,
            ],
        );
        assert_eq!(
            unsafe { std::str::from_utf8_unchecked(&out) },
            "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
        );
    }

    #[test]
    #[cfg_attr(feature = "wasm-bindgen", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_compute_target_anubis() {
        assert_eq!(
            compute_target_anubis(NonZeroU8::new(1).unwrap()),
            0x10000000000000000000000000000000,
        );
        assert_eq!(
            compute_target_anubis(NonZeroU8::new(2).unwrap()),
            0x01000000000000000000000000000000,
        );
        assert_eq!(
            compute_target_anubis(NonZeroU8::new(3).unwrap()),
            0x00100000000000000000000000000000,
        );
    }

    #[test]
    #[cfg_attr(feature = "wasm-bindgen", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_bincode_string_serialize() {
        let string = "hello";
        let mut homegrown = Vec::new();
        build_prefix(&mut homegrown, string, "z");
        let mut official = Vec::new();
        build_prefix_official(&mut official, string, "z").unwrap();
        assert_eq!(homegrown, official);
    }
}
