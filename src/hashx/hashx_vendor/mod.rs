#[cfg(feature = "jit-infra")]
pub mod compiler;
pub mod constraints;
pub mod err;
pub mod generator;
pub mod program;
pub mod rand;
pub mod register;
pub mod scheduler;
pub mod siphash;

use program::Program;
use rand_core::RngCore;

pub use err::Error;
pub use rand::SipRand;
pub use siphash::SipState;

/// Pre-built hash program that can be rapidly computed with different inputs
///
/// The program and initial state representation are not specified in this
/// public interface, but [`std::fmt::Debug`] can describe program internals.
#[derive(Debug)]
pub struct HashX {
    /// Keys used to generate an initial register state from the hash input
    ///
    /// Half of the key material generated from seed bytes go into the random
    /// program generator, and the other half are saved here for use in each
    /// hash invocation.
    pub register_key: SipState,

    /// A prepared randomly generated hash program
    ///
    /// In compiled runtimes this will be executable code, and in the
    /// interpreter it's a list of instructions. There is no stable API for
    /// program information, but the Debug trait will list programs in either
    /// format.
    pub program: Program,
}

impl HashX {
    /// The maximum available output size for [`Self::hash_to_bytes()`]
    pub const FULL_SIZE: usize = 32;

    /// Generate a new hash function with the supplied seed.
    pub fn new(seed: &[u8]) -> Result<Self, Error> {
        HashXBuilder::new().build(seed)
    }

    /// Calculate the first 64-bit word of the hash, without converting to bytes.
    pub fn hash_to_u64(&self, input: u64) -> u64 {
        self.hash_to_regs(input).digest(self.register_key)[0]
    }

    /// Calculate the hash function at its full output width, returning a fixed
    /// size byte array.
    pub fn hash_to_bytes(&self, input: u64) -> [u8; Self::FULL_SIZE] {
        let words = self.hash_to_regs(input).digest(self.register_key);
        let mut bytes = [0_u8; Self::FULL_SIZE];
        for word in 0..words.len() {
            bytes[word * 8..(word + 1) * 8].copy_from_slice(&words[word].to_le_bytes());
        }
        bytes
    }

    /// Common setup for hashes with any output format
    #[inline(always)]
    fn hash_to_regs(&self, input: u64) -> register::RegisterFile {
        let mut regs = register::RegisterFile::new(self.register_key, input);
        self.program.interpret(&mut regs);
        regs
    }
}

/// Builder for creating [`HashX`] instances with custom settings
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct HashXBuilder {
    _private: (),
}

impl HashXBuilder {
    /// Create a new [`HashXBuilder`] with default settings.
    ///
    /// Immediately calling [`Self::build()`] would be equivalent to using
    /// [`HashX::new()`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Build a [`HashX`] instance with a seed and the selected options.
    pub fn build(&self, seed: &[u8]) -> Result<HashX, Error> {
        let (key0, key1) = SipState::pair_from_seed(seed);
        let mut rng = SipRand::new(key0);
        self.build_from_rng(&mut rng, key1)
    }

    /// Build a [`HashX`] instance from an arbitrary [`RngCore`] and
    /// a [`SipState`] key used for initializing the register file.
    pub fn build_from_rng<R: RngCore>(
        &self,
        rng: &mut R,
        register_key: SipState,
    ) -> Result<HashX, Error> {
        let program = Program::generate(rng)?;
        self.build_from_program(program, register_key)
    }

    /// Build a [`HashX`] instance from an already-generated [`Program`] and
    /// [`SipState`] key.
    ///
    /// The program is either stored as-is or compiled, depending on the current
    /// [`RuntimeOption`]. Requires a program as well as a [`SipState`] to be
    /// used for initializing the register file.
    fn build_from_program(&self, program: Program, register_key: SipState) -> Result<HashX, Error> {
        Ok(HashX {
            register_key,
            program,
        })
    }
}
