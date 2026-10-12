/// JIT with AVX512DQ
#[cfg(feature = "jit-infra")]
pub mod hashx_avx512dq;

/// Vendor-specific code
pub mod hashx_vendor;

#[derive(Clone, Copy, PartialEq, Eq)]
/// What kind of test to use
pub enum TestMode {
    /// result < threshold
    LessThan,
    /// mask & result == 0
    Mask,
}
