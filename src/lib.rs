#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use sha2::digest::{
    consts::{B1, U0, U16, U64},
    typenum::{IsGreater, PowerOfTwo, Unsigned},
};
#[cfg(feature = "wasm-bindgen")]
use wasm_bindgen::prelude::*;

use core::num::NonZeroU8;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "client")]
/// Web client for end-to-end PoW solving
pub mod client;

#[cfg(feature = "server")]
/// Server for end-to-end PoW solving
pub mod server;

#[cfg(feature = "wasm-bindgen")]
mod wasm_ffi;

#[cfg(any(target_feature = "avx512f", target_feature = "avx2"))]
cfg_if::cfg_if! {
    if #[cfg(feature = "internals")] {
        /// String manipulation functions
        pub mod strings;
    } else {
        mod strings;
    }
}

/// SHA-256 primitives
mod sha256;

/// BLAKE3 primitives
mod blake3;

/// Message builders
pub mod message;

/// Solvers
pub mod solver;

#[cfg(feature = "adapter")]
/// Adapters for end-to-end PoW solving
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

/// A trait for a trivial aligner that has no function except setting the alignment and transparently holding a value of type `T`.
///
/// # Safety
///
/// Implementor must ensure their memory layout is valid.
pub unsafe trait AlignerTo<T>:
    core::ops::Deref<Target = T> + core::ops::DerefMut<Target = T> + From<T>
{
    /// The alignment of the aligner.
    type Alignment: Unsigned + PowerOfTwo + IsGreater<U0, Output = B1>;
    /// The type of the aligner.
    type Output;

    /// Create a `core::alloc::Layout` for the aligner.
    ///
    /// # Panics
    ///
    /// Panics if the request memory size is rejected by the allocator API.
    fn create_layout() -> core::alloc::Layout;
}

#[repr(align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Align to 16 bytes
pub struct Align16<T>(pub T);

unsafe impl<T> AlignerTo<T> for Align16<T> {
    type Alignment = U16;
    type Output = T;
    fn create_layout() -> core::alloc::Layout {
        core::alloc::Layout::new::<Align16<T>>()
    }
}

impl<T> From<T> for Align16<T> {
    fn from(value: T) -> Self {
        Align16(value)
    }
}

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
/// Align to 64 bytes
pub struct Align64<T>(pub T);

unsafe impl<T> AlignerTo<T> for Align64<T> {
    type Alignment = U64;
    type Output = T;
    fn create_layout() -> core::alloc::Layout {
        core::alloc::Layout::new::<Align64<T>>()
    }
}

impl<T> From<T> for Align64<T> {
    fn from(value: T) -> Self {
        Align64(value)
    }
}

// Ref downcast to Align16
impl<'a, T> From<&'a Align64<T>> for &'a Align16<T> {
    fn from(this: &'a Align64<T>) -> &'a Align16<T> {
        unsafe { core::mem::transmute(this) }
    }
}

// Ref downcast to Align16
impl<'a, T> From<&'a mut Align64<T>> for &'a mut Align16<T> {
    fn from(this: &'a mut Align64<T>) -> &'a mut Align16<T> {
        unsafe { core::mem::transmute(this) }
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
/// Convert a prefix offset to a lane position
pub fn prefix_offset_to_lane_position(offset: usize) -> usize {
    PREFIX_OFFSET_TO_LANE_POSITION[offset % 64]
}

const PREFIX_OFFSET_TO_LANE_POSITION: [usize; 64] = [
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9, 9,
    10, 10, 10, 10, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 13, 13, 13, 13, 13, 13, 0, 0, 0, 0, 0,
    0, 0, 1, 1, 1, 1,
];

const SWAP_DWORD_BYTE_ORDER: [usize; 64] = {
    let mut data = [0; 64];
    let mut i = 0;
    while i < 64 {
        data[i] = i / 4 * 4 + 3 - i % 4;
        i += 1;
    }
    data
};

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
cfg_if::cfg_if! {
    if #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))] {
        /// Single block solver
        pub type SingleBlockSolver = crate::solver::avx512::SingleBlockSolver;
        /// Double block solver
        pub type DoubleBlockSolver = crate::solver::avx512::DoubleBlockSolver;
        /// Dynamic dispatching Decimal solver
        pub type DecimalSolver = crate::solver::avx512::DecimalSolver;
        /// Go away solver
        pub type GoAwaySolver = crate::solver::avx512::GoAwaySolver;
        /// Binary solver
        pub type BinarySolver = crate::solver::avx512::BinarySolver;
        /// Cerberus solver
        pub type CerberusSolver = crate::solver::avx512::CerberusSolver;
        /// Solver name
        pub const SOLVER_NAME: &str = "AVX-512";
    } else if #[cfg(target_feature = "sha")] {
        /// Single block solver
        pub type SingleBlockSolver = crate::solver::sha_ni::SingleBlockSolver;
        /// Double block solver
        pub type DoubleBlockSolver = crate::solver::sha_ni::DoubleBlockSolver;
        /// Dynamic dispatching Decimal solver
        pub type DecimalSolver = crate::solver::sha_ni::DecimalSolver;
        /// Go away solver
        pub type GoAwaySolver = crate::solver::sha_ni::GoAwaySolver;
        /// Binary solver
        pub type BinarySolver = crate::solver::safe::BinarySolver;
        /// Cerberus solver
        pub type CerberusSolver = crate::solver::safe::CerberusSolver;
        /// Solver name
        pub const SOLVER_NAME: &str = "SHA-NI";
    } else {
        /// Single block solver
        pub type SingleBlockSolver = crate::solver::safe::SingleBlockSolver;
        /// Double block solver
        pub type DoubleBlockSolver = crate::solver::safe::DoubleBlockSolver;
        /// Dynamic dispatching Decimal solver
        pub type DecimalSolver = crate::solver::safe::DecimalSolver;
        /// Go away solver
        pub type GoAwaySolver = crate::solver::safe::GoAwaySolver;
        /// Binary solver
        pub type BinarySolver = crate::solver::safe::BinarySolver;
        /// Cerberus solver
        pub type CerberusSolver = crate::solver::safe::CerberusSolver;
        /// Solver name
        pub const SOLVER_NAME: &str = "Fallback";
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
cfg_if::cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        /// Single block solver
        pub type SingleBlockSolver = crate::solver::simd128::SingleBlockSolver;
        /// Double block solver
        pub type DoubleBlockSolver = crate::solver::simd128::DoubleBlockSolver;
        /// Dynamic dispatching Decimal solver
        pub type DecimalSolver = crate::solver::simd128::DecimalSolver;
        /// Go away solver
        pub type GoAwaySolver = crate::solver::simd128::GoAwaySolver;
        /// Binary solver
        pub type BinarySolver = crate::solver::safe::BinarySolver;
        /// Cerberus solver
        pub type CerberusSolver = crate::solver::simd128::CerberusSolver;
        /// Solver name
        pub const SOLVER_NAME: &str = "SIMD128";
    } else {
        /// Single block solver
        pub type SingleBlockSolver = crate::solver::safe::SingleBlockSolver;
        /// Double block solver
        pub type DoubleBlockSolver = crate::solver::safe::DoubleBlockSolver;
        /// Dynamic dispatching Decimal solver
        pub type DecimalSolver = crate::solver::safe::DecimalSolver;
        /// Go away solver
        pub type GoAwaySolver = crate::solver::safe::GoAwaySolver;
        /// Binary solver
        pub type BinarySolver = crate::solver::safe::BinarySolver;
        /// Cerberus solver
        pub type CerberusSolver = crate::solver::safe::CerberusSolver;
        /// Solver name
        pub const SOLVER_NAME: &str = "Fallback";
    }
}

/// Build a prefix for mCaptcha PoW
pub fn build_mcaptcha_prefix<E: Extend<u8>>(out: &mut E, string: &str, salt: &str) {
    out.extend(salt.as_bytes().iter().copied());
    out.extend((string.len() as u64).to_le_bytes());
    out.extend(string.as_bytes().iter().copied());
}

pub(crate) const fn decompose_blocks_mut(inp: &mut [u32; 16]) -> &mut [u8; 64] {
    unsafe { core::mem::transmute(inp) }
}

/// Compute the target for an mCaptcha PoW
pub const fn compute_target_mcaptcha(difficulty_factor: u64) -> u64 {
    u64::MAX - u64::MAX / difficulty_factor
}

/// Compute the target for an Anubis PoW
pub const fn compute_target_anubis(difficulty_factor: NonZeroU8) -> u64 {
    // some people misconfigure with difficulty 0
    if difficulty_factor.get() == 0 {
        return u64::MAX;
    }
    1u64 << (64 - difficulty_factor.get() * 4)
}

/// Compute the target for a GoAway PoW
pub const fn compute_target_goaway(difficulty_factor: NonZeroU8) -> u64 {
    1u64 << (64 - difficulty_factor.get())
}

/// Compute a mask for a Cerberus PoW
pub const fn compute_mask_cerberus(difficulty_factor: NonZeroU8) -> u32 {
    !(!0u32 >> (difficulty_factor.get() * 2)).swap_bytes()
}

/// Extract top 128 bits from a 64-bit word array
pub const fn extract128_be(inp: [u32; 8]) -> u128 {
    (inp[0] as u128) << 96 | (inp[1] as u128) << 64 | (inp[2] as u128) << 32 | (inp[3] as u128)
}

/// Extract top 64 bits from a 64-bit word array
pub const fn extract64_be(inp: [u32; 8]) -> u64 {
    (inp[0] as u64) << 32 | (inp[1] as u64)
}

/// Check if a lane position is supported in the current build
#[allow(clippy::match_like_matches_macro)]
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
/// Check if a lane position is supported in the current build
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

/// Encode a blake3 hash into hex
pub fn encode_hex_le(out: &mut [u8; 64], inp: [u32; 8]) {
    for w in 0..8 {
        let be_bytes = inp[w].to_le_bytes();
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
    fn test_compute_target_anubis() {
        assert_eq!(
            compute_target_anubis(NonZeroU8::new(1).unwrap()),
            0x1000000000000000,
        );
        assert_eq!(
            compute_target_anubis(NonZeroU8::new(2).unwrap()),
            0x0100000000000000,
        );
        assert_eq!(
            compute_target_anubis(NonZeroU8::new(3).unwrap()),
            0x0010000000000000,
        );
    }

    #[test]
    fn test_bincode_string_serialize() {
        let string = "hello";
        let mut homegrown = Vec::new();
        build_mcaptcha_prefix(&mut homegrown, string, "z");
        let mut official = Vec::new();
        build_prefix_official(&mut official, string, "z").unwrap();
        assert_eq!(homegrown, official);
    }

    #[test]
    fn test_cerberus_mask() {
        fn check_small(hash: &[u8; 32], n: usize) -> bool {
            // https://github.com/sjtug/cerberus/blob/ee8f903f1311da7022aec68c8686739b40f4a168/pow/src/check_dubit.rs
            let first_word: u32 = (hash[0] as u32) << 24
                | (hash[1] as u32) << 16
                | (hash[2] as u32) << 8
                | (hash[3] as u32);
            first_word.leading_zeros() >= (n as u32 * 2)
        }

        for i in 1..8 {
            let mask = compute_mask_cerberus(NonZeroU8::new(i).unwrap());
            eprintln!("mask: {:08x}", mask);
        }

        // hash[0] is the LSB of the H0 register

        let mask = compute_mask_cerberus(NonZeroU8::new(7).unwrap());
        let hash_partial = (!mask).to_le_bytes();
        eprintln!("hash_partial: {:02x?}", hash_partial);
        let mut test = [0; 32];
        test[..4].copy_from_slice(&hash_partial);
        assert!(check_small(&test, 7));
    }
}
