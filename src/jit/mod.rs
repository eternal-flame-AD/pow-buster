use iced_x86::code_asm::*;

use crate::Align64;

/// Module for executable memory mapping
pub mod exec_map;

// custom AVX512 vector register preserving calling convention:
// RDI point to the data buffer
// k6 and k7 are caller saved for predicate logics
// the rest are all callee saved except those explicitly passed as parameters

const RESOURCE_ALU: u32 = 1 << 0;
const RESOURCE_MUL: u32 = 1 << 1;

/// Register class trait
pub trait RegisterClass: Copy + Send + Sync + 'static {
    /// The machine register type
    type MachineRegister: Copy + Send + Sync + 'static;
    /// The interpreter register type
    type InterpreterRegister: Copy + Send + Sync + 'static;
}

#[derive(Copy, Clone, Debug)]
/// Register class for 64-bit registers
pub struct RegisterClass64;

impl RegisterClass for RegisterClass64 {
    type MachineRegister = AsmRegister64;
    type InterpreterRegister = u64;
}

#[derive(Copy, Clone, Debug)]
/// Register class for ZMM registers
pub struct RegisterClassZmm64;

impl RegisterClass for RegisterClassZmm64 {
    type MachineRegister = AsmRegisterZmm;
    type InterpreterRegister = Align64<[u64; 8]>;
}

/// A macro-unit of Task when spans multiple bundles of instructions
pub trait Task<Rc: RegisterClass> {
    /// A bitmask of which resources the next bundle of instructions will need
    ///
    /// Codegen should allocate a port for the corresponding resources and mark them as busy
    fn resources(&self) -> u32;

    /// How many cycles will the next bundle of instructions be stalled for?
    fn latency(&self) -> u32;

    /// Emit the next bundle of instructions
    ///
    /// Returns true if the task is complete
    fn emit_next(
        &mut self,
        out: &mut CodeAssembler,
        dst: Rc::MachineRegister,
        src: Rc::MachineRegister,
    ) -> bool;

    /// Describe what this task is supposed to do in regular code
    ///
    /// For testing and interpreter use
    fn interpret(
        &self,
        data: &[u8],
        dst: &mut Rc::InterpreterRegister,
        src: &Rc::InterpreterRegister,
    );

    /// Interpret the task for self-modifying registers
    fn interpret_self(&self, data: &[u8], dst: &mut Rc::InterpreterRegister);

    /// Convenience function to emit all the instructions for this task
    fn emit_all(
        &mut self,
        out: &mut CodeAssembler,
        dst: Rc::MachineRegister,
        src: Rc::MachineRegister,
    ) {
        while !self.emit_next(out, dst, src) {}
    }
}

/// XOR two ZMM registers
#[derive(Clone, Copy, Debug)]
pub struct Zmm64Xor;

impl Zmm64Xor {
    /// Create a new Zmm64Xor
    pub fn new() -> Self {
        Self
    }
}

impl Task<RegisterClassZmm64> for Zmm64Xor {
    fn resources(&self) -> u32 {
        RESOURCE_ALU
    }

    fn latency(&self) -> u32 {
        1
    }

    fn interpret(
        &self,
        _data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
        src: &<RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        dst.0
            .iter_mut()
            .zip(src.0.iter())
            .for_each(|(d, s)| *d ^= *s);
    }

    fn interpret_self(
        &self,
        _data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        dst.0.iter_mut().for_each(|d| *d ^= *d);
    }

    fn emit_next(
        &mut self,
        ass: &mut CodeAssembler,
        dst: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
        src: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
    ) -> bool {
        ass.vpxorq(dst, dst, src).unwrap();
        true
    }
}

/// Add or subtract two ZMM registers
#[derive(Clone, Copy, Debug)]
pub struct Zmm64AddSub {
    sub: bool,
}

impl Zmm64AddSub {
    /// Create a new Zmm64AddSub
    pub fn new(sub: bool) -> Self {
        Self { sub }
    }
}

impl Task<RegisterClassZmm64> for Zmm64AddSub {
    fn resources(&self) -> u32 {
        RESOURCE_ALU
    }

    fn latency(&self) -> u32 {
        1
    }

    fn interpret(
        &self,
        _data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
        src: &<RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        dst.0.iter_mut().zip(src.0.iter()).for_each(|(d, s)| {
            if self.sub {
                *d = d.wrapping_sub(*s)
            } else {
                *d = d.wrapping_add(*s)
            }
        });
    }

    fn interpret_self(
        &self,
        _data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        dst.0.iter_mut().for_each(|d| {
            if self.sub {
                *d = 0
            } else {
                *d = d.wrapping_add(*d)
            }
        });
    }

    fn emit_next(
        &mut self,
        ass: &mut CodeAssembler,
        dst: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
        src: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
    ) -> bool {
        if self.sub {
            ass.vpsubq(dst, dst, src).unwrap();
        } else {
            ass.vpaddq(dst, dst, src).unwrap();
        }
        true
    }

    fn emit_all(
        &mut self,
        ass: &mut CodeAssembler,
        dst: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
        src: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
    ) {
        while !self.emit_next(ass, dst, src) {}
    }
}

/// Add a broadcasted constant to a ZMM register at a given offset w.r.t. the `rdi` register
#[derive(Clone, Copy, Debug)]
pub struct Zmm64AddConstBcst {
    data_offset: u32,
}

impl Zmm64AddConstBcst {
    /// Create a new Zmm64AddConstBcst
    pub fn new(data_offset: u32) -> Self {
        Self { data_offset }
    }
}

impl Task<RegisterClassZmm64> for Zmm64AddConstBcst {
    fn resources(&self) -> u32 {
        RESOURCE_ALU
    }

    fn latency(&self) -> u32 {
        1
    }

    fn interpret(
        &self,
        data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
        _src: &<RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        let imm_ptr = unsafe { data.as_ptr().byte_add(self.data_offset as usize) };
        assert_eq!(imm_ptr.align_offset(8), 0);
        let imm = unsafe { imm_ptr.cast::<u64>().read() };
        dst.0.iter_mut().for_each(|d| *d = d.wrapping_add(imm));
    }

    fn interpret_self(
        &self,
        _data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        let imm_ptr = unsafe { _data.as_ptr().byte_add(self.data_offset as usize) };
        assert_eq!(imm_ptr.align_offset(8), 0);
        let imm = unsafe { imm_ptr.cast::<u64>().read() };
        dst.0.iter_mut().for_each(|d| *d = d.wrapping_add(imm));
    }

    fn emit_next(
        &mut self,
        ass: &mut CodeAssembler,
        dst: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
        _src: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
    ) -> bool {
        ass.vpaddq(dst, dst, qword_bcst(rdi + self.data_offset))
            .unwrap();
        true
    }
}

/// Add a broadcasted constant to a ZMM register at a given offset w.r.t. the `rdi` register
#[derive(Clone, Copy, Debug)]
pub struct Zmm64XorConstBcst {
    data_offset: u32,
}

impl Zmm64XorConstBcst {
    /// Create a new Zmm64XorConstBcst
    pub fn new(data_offset: u32) -> Self {
        Self { data_offset }
    }
}

impl Task<RegisterClassZmm64> for Zmm64XorConstBcst {
    fn resources(&self) -> u32 {
        RESOURCE_ALU
    }

    fn latency(&self) -> u32 {
        1
    }

    fn interpret(
        &self,
        data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
        _src: &<RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        let imm_ptr = unsafe { data.as_ptr().byte_add(self.data_offset as usize) };
        assert_eq!(imm_ptr.align_offset(8), 0);
        let imm = unsafe { imm_ptr.cast::<u64>().read() };
        dst.0.iter_mut().for_each(|d| *d = *d ^ imm);
    }

    fn interpret_self(
        &self,
        _data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        let imm_ptr = unsafe { _data.as_ptr().byte_add(self.data_offset as usize) };
        assert_eq!(imm_ptr.align_offset(8), 0);
        let imm = unsafe { imm_ptr.cast::<u64>().read() };
        dst.0.iter_mut().for_each(|d| *d = *d ^ imm);
    }

    fn emit_next(
        &mut self,
        ass: &mut CodeAssembler,
        dst: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
        _src: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
    ) -> bool {
        ass.vpxorq(dst, dst, qword_bcst(rdi + self.data_offset))
            .unwrap();
        true
    }
}

#[derive(Clone, Copy, Debug)]
/// Rotate left a ZMM register by a given amount
pub struct Zmm64Rol {
    amount: u32,
}

impl Zmm64Rol {
    /// Create a new Zmm64Rol
    pub fn new(amount: u32) -> Self {
        Self { amount }
    }
}

impl Task<RegisterClassZmm64> for Zmm64Rol {
    fn resources(&self) -> u32 {
        RESOURCE_ALU
    }

    fn latency(&self) -> u32 {
        1
    }

    fn interpret(
        &self,
        _data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
        src: &<RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        dst.0
            .iter_mut()
            .zip(src.0.iter())
            .for_each(|(d, s)| *d = s.rotate_left(self.amount));
    }

    fn interpret_self(
        &self,
        _data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        dst.0
            .iter_mut()
            .for_each(|d| *d = d.rotate_left(self.amount));
    }

    fn emit_next(
        &mut self,
        ass: &mut CodeAssembler,
        dst: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
        src: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
    ) -> bool {
        ass.vprolq(dst, src, self.amount).unwrap();
        true
    }
}

/// Multiply unsigned 64-bit integers, report low 64 bits
#[derive(Clone, Copy, Debug)]
pub struct Zmm64MulLow64;

impl Zmm64MulLow64 {
    /// Create a new Zmm64MulLow64
    pub fn new() -> Self {
        Self
    }
}

impl Task<RegisterClassZmm64> for Zmm64MulLow64 {
    fn resources(&self) -> u32 {
        RESOURCE_MUL
    }

    fn latency(&self) -> u32 {
        4
    }

    fn interpret(
        &self,
        _data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
        src: &<RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        dst.0
            .iter_mut()
            .zip(src.0.iter())
            .for_each(|(d, s)| *d = d.wrapping_mul(*s));
    }

    fn interpret_self(
        &self,
        _data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        dst.0.iter_mut().for_each(|d| *d = d.wrapping_mul(*d));
    }

    fn emit_next(
        &mut self,
        ass: &mut CodeAssembler,
        dst: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
        src: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
    ) -> bool {
        ass.vpmullq(dst, dst, src).unwrap();
        true
    }
}

#[derive(Clone, Copy, Debug)]
/// Data for a mask test
pub struct MaskTestData {
    /// The offset of the test mask
    pub test_mask_offset: u32,
    /// The register to test
    pub test_reg: AsmRegisterK,
}

#[derive(Clone, Copy, Debug)]
/// Multiply two ZMM registers and store the high 64 bits
pub struct Zmm64MulHi64 {
    magic_ffff_fffe_offset: u32,
    magic_ffff_ffff_offset: u32,
    magic_1_ffff_fffe_offset: u32,
    test: Option<MaskTestData>,
    scratch_regs: [AsmRegisterZmm; 5],
    signed: bool,
    step: u32,
}

impl Zmm64MulHi64 {
    /// Create a new Zmm64MulHi64
    pub fn new(
        signed: bool,
        magic_ffff_fffe_offset: u32,
        magic_ffff_ffff_offset: u32,
        magic_1_ffff_ffe_offset: u32,
        scratch_regs: [AsmRegisterZmm; 5],
    ) -> Self {
        Self {
            magic_ffff_fffe_offset,
            magic_ffff_ffff_offset,
            magic_1_ffff_fffe_offset: magic_1_ffff_ffe_offset,
            test: None,
            scratch_regs,
            signed,
            step: 0,
        }
    }

    /// Set the test mask
    pub fn set_test(&mut self, test: MaskTestData) {
        self.test = Some(test);
    }
}

impl Task<RegisterClassZmm64> for Zmm64MulHi64 {
    fn resources(&self) -> u32 {
        if self.step == 0 {
            RESOURCE_MUL
        } else {
            RESOURCE_ALU
        }
    }

    fn latency(&self) -> u32 {
        6
    }

    fn interpret(
        &self,
        _data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
        src: &<RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        if self.signed {
            dst.0.iter_mut().zip(src.0.iter()).for_each(|(d, s)| {
                let r_wide = i128::from(*d as i64) * i128::from(*s as i64);
                *d = (r_wide >> 64) as u64;
            });
        } else {
            dst.0.iter_mut().zip(src.0.iter()).for_each(|(d, s)| {
                let r_wide = u128::from(*d) * u128::from(*s);
                *d = (r_wide >> 64) as u64;
            });
        }
    }

    fn interpret_self(
        &self,
        _data: &[u8],
        dst: &mut <RegisterClassZmm64 as RegisterClass>::InterpreterRegister,
    ) {
        if self.signed {
            dst.0.iter_mut().for_each(|d| {
                let r_wide = i128::from(*d as i64) * i128::from(*d as i64);
                *d = (r_wide >> 64) as u64;
            });
        } else {
            dst.0.iter_mut().for_each(|d| {
                let r_wide = u128::from(*d) * u128::from(*d);
                *d = (r_wide >> 64) as u64;
            });
        }
    }

    fn emit_next(
        &mut self,
        ass: &mut CodeAssembler,
        dst: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
        src: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
    ) -> bool {
        let [scratch1, scratch2, scratch3, scratch4, scratch5] = self.scratch_regs;
        if src != dst {
            if !self.signed {
                if self.step == 0 {
                    ass.vpsrlq(scratch1, dst, 32).unwrap();
                    ass.vpsrlq(scratch2, src, 32).unwrap();
                    ass.vpmuludq(scratch3, src, dst).unwrap();
                    ass.vpmuludq(dst, scratch2, dst).unwrap();
                    ass.vpmuludq(scratch5, src, scratch1).unwrap();
                    ass.vpmuludq(scratch1, scratch2, scratch1).unwrap();
                    ass.vpsrlq(scratch3, scratch3, 32).unwrap();
                } else if self.step == 1 {
                    ass.vpandq(scratch2, dst, qword_bcst(rdi + self.magic_ffff_ffff_offset))
                        .unwrap();
                    ass.vpandq(
                        scratch4,
                        scratch5,
                        qword_bcst(rdi + self.magic_ffff_ffff_offset),
                    )
                    .unwrap();
                    ass.vpsrlq(dst, dst, 32).unwrap();
                    ass.vpaddq(scratch4, scratch4, scratch2).unwrap();
                    ass.vpaddq(dst, dst, scratch1).unwrap();
                    ass.vpsrlq(scratch1, scratch5, 32).unwrap();
                    ass.vpaddq(scratch3, scratch4, scratch3).unwrap();
                    ass.vpaddq(dst, dst, scratch1).unwrap();
                    ass.vpsrlq(scratch3, scratch3, 32).unwrap();
                    ass.vpaddq(dst, dst, scratch3).unwrap();
                }
            } else {
                let v_zmm0 = dst;
                let v_zmm1 = src;
                let v_zmm2 = scratch1;
                let v_zmm3 = scratch2;
                let v_zmm4 = scratch3;
                let v_zmm5 = scratch4;
                let v_zmm6 = scratch5;

                if self.step == 0 {
                    ass.vpxorq(v_zmm2, v_zmm1, v_zmm0).unwrap();
                    ass.vpmovq2m(k7, v_zmm2).unwrap();
                    ass.vpabsq(v_zmm2, v_zmm1).unwrap();
                    ass.vptestmq(k6.k7(), v_zmm1, v_zmm0).unwrap();
                    ass.vpabsq(v_zmm0, v_zmm0).unwrap();
                    ass.vpsrlq(v_zmm4, v_zmm2, 32).unwrap();
                    ass.vpsrlq(v_zmm3, v_zmm0, 32).unwrap();
                    ass.vpmuludq(v_zmm5, v_zmm2, v_zmm0).unwrap();
                    ass.vpmuludq(v_zmm0, v_zmm4, v_zmm0).unwrap();
                    ass.vpmuludq(v_zmm2, v_zmm2, v_zmm3).unwrap();
                    ass.vpmuludq(v_zmm3, v_zmm4, v_zmm3).unwrap();
                    ass.vpandq(
                        v_zmm4,
                        v_zmm0,
                        qword_bcst(rdi + self.magic_ffff_ffff_offset),
                    )
                    .unwrap();
                    ass.vpsrlq(v_zmm0, v_zmm0, 32).unwrap();
                    ass.vpsrlq(v_zmm5, v_zmm5, 32).unwrap();
                    ass.vpandq(
                        v_zmm6,
                        v_zmm2,
                        qword_bcst(rdi + self.magic_ffff_ffff_offset),
                    )
                    .unwrap();
                    ass.vpaddq(v_zmm0, v_zmm0, v_zmm3).unwrap();
                    ass.vpsrlq(v_zmm2, v_zmm2, 32).unwrap();
                    ass.vpaddq(v_zmm6, v_zmm6, v_zmm4).unwrap();
                    ass.vpaddq(v_zmm0, v_zmm0, v_zmm2).unwrap();
                    ass.vpmovm2q(v_zmm2, k6).unwrap();
                    ass.vpaddq(v_zmm5, v_zmm6, v_zmm5).unwrap();
                    ass.vpsrlq(v_zmm5, v_zmm5, 32).unwrap();
                    ass.vpaddq(v_zmm0, v_zmm0, v_zmm5).unwrap();
                    ass.vpxorq(v_zmm0, v_zmm0, v_zmm2).unwrap();
                }
            }
        } else {
            if !self.signed {
                let v_zmm0 = dst;
                let v_zmm1 = scratch1;
                let v_zmm2 = scratch2;
                let v_zmm3 = scratch3;

                if self.step == 0 {
                    ass.vpsrlq(v_zmm1, v_zmm0, 32).unwrap();
                    ass.vpmuludq(v_zmm2, v_zmm0, v_zmm0).unwrap();
                    ass.vpmuludq(v_zmm0, v_zmm1, v_zmm0).unwrap();
                    ass.vpmuludq(v_zmm1, v_zmm1, v_zmm1).unwrap();
                } else if self.step == 1 {
                    ass.vpsrlq(v_zmm2, v_zmm2, 32).unwrap();
                    ass.vpaddq(v_zmm3, v_zmm0, v_zmm0).unwrap();
                    ass.vpsrlq(v_zmm0, v_zmm0, 31).unwrap();
                    ass.vpandq(
                        v_zmm3,
                        v_zmm3,
                        qword_bcst(rdi + self.magic_1_ffff_fffe_offset),
                    )
                    .unwrap();
                    ass.vpandq(
                        v_zmm0,
                        v_zmm0,
                        qword_bcst(rdi + self.magic_1_ffff_fffe_offset),
                    )
                    .unwrap();
                    ass.vpaddq(v_zmm2, v_zmm3, v_zmm2).unwrap();
                    ass.vpaddq(v_zmm0, v_zmm0, v_zmm1).unwrap();
                    ass.vpsrlq(v_zmm2, v_zmm2, 32).unwrap();
                    ass.vpaddq(v_zmm0, v_zmm0, v_zmm2).unwrap();
                }
            } else {
                let v_zmm0 = dst;
                let v_zmm1 = scratch1;
                let v_zmm2 = scratch2;
                let v_zmm3 = scratch3;

                if self.step == 0 {
                    ass.vpabsq(v_zmm0, v_zmm0).unwrap();
                    ass.vpsrlq(v_zmm1, v_zmm0, 32).unwrap();
                    ass.vpmuludq(v_zmm2, v_zmm0, v_zmm0).unwrap();
                    ass.vpmuludq(v_zmm0, v_zmm1, v_zmm0).unwrap();
                    ass.vpmuludq(v_zmm1, v_zmm1, v_zmm1).unwrap();
                } else if self.step == 1 {
                    ass.vpsrlq(v_zmm2, v_zmm2, 32).unwrap();
                    ass.vpaddq(v_zmm3, v_zmm0, v_zmm0).unwrap();
                    ass.vpsrlq(v_zmm0, v_zmm0, 31).unwrap();
                    ass.vpandq(
                        v_zmm3,
                        v_zmm3,
                        qword_bcst(rdi + self.magic_1_ffff_fffe_offset),
                    )
                    .unwrap();
                    ass.vpandq(
                        v_zmm0,
                        v_zmm0,
                        qword_bcst(rdi + self.magic_ffff_fffe_offset),
                    )
                    .unwrap();
                    ass.vpaddq(v_zmm2, v_zmm3, v_zmm2).unwrap();
                    ass.vpaddq(v_zmm0, v_zmm0, v_zmm1).unwrap();
                    ass.vpsrlq(v_zmm2, v_zmm2, 32).unwrap();
                    ass.vpaddq(v_zmm0, v_zmm0, v_zmm2).unwrap();
                }
            }
        }

        if self.step == 1
            && let Some(test) = self.test
        {
            ass.vptestnmq(test.test_reg, dst, qword_bcst(rdi + test.test_mask_offset))
                .unwrap();
        }

        self.step += 1;

        self.step > 1
    }

    fn emit_all(
        &mut self,
        ass: &mut CodeAssembler,
        dst: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
        src: <RegisterClassZmm64 as RegisterClass>::MachineRegister,
    ) {
        while !self.emit_next(ass, dst, src) {}
    }
}

pub(crate) fn sipround_avx512_jit<const WAVES: usize>(
    a: &mut CodeAssembler,
    v0: [AsmRegisterZmm; WAVES],
    v1: [AsmRegisterZmm; WAVES],
    v2: [AsmRegisterZmm; WAVES],
    v3: [AsmRegisterZmm; WAVES],
) {
    macro_rules! foreach_wave {
        ($w: ident; { $($stmt: stmt;)* }) => {
            $(
                for $w in 0..WAVES {
                    $stmt
                }
            )*
        };
    }
    foreach_wave!(w; {
        a.vpaddq(v0[w], v0[w], v1[w]).unwrap();
        a.vpaddq(v2[w], v2[w], v3[w]).unwrap();
        a.vprolq(v1[w], v1[w], 13).unwrap();
        a.vprolq(v3[w], v3[w], 16).unwrap();
        a.vpxorq(v1[w], v1[w], v0[w]).unwrap();
        a.vpxorq(v3[w], v3[w], v2[w]).unwrap();
        a.vprolq(v0[w], v0[w], 32).unwrap();
        a.vpaddq(v2[w], v2[w], v1[w]).unwrap();
        a.vpaddq(v0[w], v0[w], v3[w]).unwrap();
        a.vprolq(v1[w], v1[w], 17).unwrap();
        a.vprolq(v3[w], v3[w], 21).unwrap();
        a.vpxorq(v1[w], v1[w], v2[w]).unwrap();
        a.vpxorq(v3[w], v3[w], v0[w]).unwrap();
        a.vprolq(v2[w], v2[w], 32).unwrap();
    });
}

/// Compute SipRound, outputs v0 only, clobbers v2, v3
pub(crate) fn sipround_avx512_jit_v0_only<const WAVES: usize>(
    a: &mut CodeAssembler,
    v0: [AsmRegisterZmm; WAVES],
    v1: [AsmRegisterZmm; WAVES],
    v2: [AsmRegisterZmm; WAVES],
    v3: [AsmRegisterZmm; WAVES],
) {
    macro_rules! foreach_wave {
        ($w: ident; { $($stmt: stmt;)* }) => {
            $(
                for $w in 0..WAVES {
                    $stmt
                }
            )*
        };
    }
    foreach_wave!(w; {
        a.vpaddq(v0[w], v0[w], v1[w]).unwrap();
        a.vpaddq(v2[w], v2[w], v3[w]).unwrap();
        a.vprolq(v3[w], v3[w], 16).unwrap();
        a.vpxorq(v3[w], v3[w], v2[w]).unwrap();
        a.vprolq(v0[w], v0[w], 32).unwrap();
        a.vpaddq(v0[w], v0[w], v3[w]).unwrap();
    });
}

#[cfg(target_feature = "avx512f")]
#[cfg_attr(not(test), expect(dead_code))]
pub(crate) mod sample {
    pub(crate) fn simd_umulh(
        a: core::arch::x86_64::__m512i,
        b: core::arch::x86_64::__m512i,
    ) -> core::arch::x86_64::__m512i {
        use core::arch::x86_64::*;
        unsafe {
            let src_i = a;
            let dst_i = b;
            let src_hi = _mm512_srli_epi64(src_i, 32);
            let dst_hi = _mm512_srli_epi64(dst_i, 32);
            let ll = _mm512_mul_epu32(dst_i, src_i); // this is 64:0

            let ll_hi = _mm512_srli_epi64(ll, 32); // this is 64:32
            let lh = _mm512_mul_epu32(dst_hi, src_i); // this is 96:32
            let hl = _mm512_mul_epu32(src_hi, dst_i); // this is 96:32

            let lh_low = _mm512_and_si512(lh, _mm512_set1_epi64(0xFFFF_FFFFu64 as i64));
            let hl_low = _mm512_and_si512(hl, _mm512_set1_epi64(0xFFFF_FFFFu64 as i64));
            let mut ll_carry = _mm512_add_epi64(lh_low, hl_low);
            ll_carry = _mm512_add_epi64(ll_carry, ll_hi);
            ll_carry = _mm512_srli_epi64(ll_carry, 32);

            let mut res = _mm512_mul_epu32(src_hi, dst_hi);

            res = _mm512_add_epi64(res, ll_carry);
            res = _mm512_add_epi64(res, _mm512_srli_epi64(lh, 32));
            res = _mm512_add_epi64(res, _mm512_srli_epi64(hl, 32));

            res
        }
    }

    pub(crate) fn simd_smulh(
        mut a: core::arch::x86_64::__m512i,
        mut b: core::arch::x86_64::__m512i,
    ) -> core::arch::x86_64::__m512i {
        use core::arch::x86_64::*;
        unsafe {
            let mut output_sign = _mm512_movepi64_mask(a) ^ _mm512_movepi64_mask(b);
            output_sign &= _mm512_test_epi64_mask(a, b);

            a = _mm512_abs_epi64(a);
            b = _mm512_abs_epi64(b);

            let mut res = simd_umulh(a, b);
            res = _mm512_mask_xor_epi64(res, output_sign, res, _mm512_set1_epi64(-1));
            res
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_simd_smulh() {
        use core::arch::x86_64::*;

        use rand::RngExt;
        use rand::SeedableRng;

        let mut rng = rand::rngs::SmallRng::seed_from_u64(1);

        let mut a = Align64([0i64; 8]);
        let mut b: Align64<[i64; 8]> = Align64(core::array::from_fn(|_| rng.random()));

        for _ in 0..1000 {
            let expected_result: [u64; 8] = core::array::from_fn(|i| {
                let a = a.0[i];
                let b = b.0[i];
                (i128::from(a) * i128::from(b) >> 64) as u64
            });
            let mut result = Align64([0u64; 8]);
            unsafe {
                let av = _mm512_loadu_si512(a.as_ptr().cast::<__m512i>());
                let bv = _mm512_loadu_si512(b.as_ptr().cast::<__m512i>());
                let res = sample::simd_smulh(av, bv);
                _mm512_storeu_si512(result.as_mut_ptr().cast(), res);
            }
            assert_eq!(result.0, expected_result);

            for i in 0..8 {
                a[i] = rng.random();
                b[i] = rng.random();
            }
        }
    }

    #[cfg(target_feature = "avx512f")]
    fn test_zmm64_instr_1op<T: Task<RegisterClassZmm64> + Clone>(instr: T, data: &[u8]) {
        use rand::SeedableRng;

        let mut rng = rand::rngs::SmallRng::seed_from_u64(1);

        for _rep in 0..1000 {
            use rand::RngExt;

            use crate::jit::exec_map::ExecMap;

            let mut dst = Align64(core::array::from_fn(|_| rng.random()));
            let input = dst;

            let mut map = ExecMap::new((16384).try_into().unwrap()).unwrap();

            let mut ass = CodeAssembler::new(64).unwrap();

            let dst_reg = zmm0;

            instr.clone().emit_all(&mut ass, dst_reg, dst_reg);

            ass.ret().unwrap();

            let code = ass.assemble(map.as_ptr() as u64).unwrap();
            map.commit_code(&code).unwrap();
            let mut dst_jit = dst;

            unsafe {
                core::arch::asm!(
                    "vmovdqa64 zmm0, zmmword ptr [{dst}]",
                    "call {map}",
                    "vmovdqa64 zmmword ptr [{dst}], zmm0",
                    in("rdi") data.as_ptr() as u64,
                    dst = in(reg) &raw mut dst_jit,
                    map = in(reg) map.as_ptr() as u64,
                    out("zmm0") _,
                    out("k0") _,
                    out("k1") _,
                    out("k6") _,
                    out("k7") _,
                    out("r8") _,
                    out("zmm2") _,
                    out("zmm3") _,
                    out("zmm4") _,
                    out("zmm5") _,
                    out("zmm6") _,
                    out("zmm7") _,
                    out("zmm8") _,
                    options(nostack),
                );
            }

            instr.interpret_self(data, &mut dst);

            assert_eq!(dst, dst_jit, "dst register mismatch! (input: {:?})", input);
        }
    }

    #[cfg(target_feature = "avx512f")]
    fn test_zmm64_instr_2op<T: Task<RegisterClassZmm64> + Clone>(instr: T, data: &[u8]) {
        use rand::SeedableRng;

        let mut rng = rand::rngs::SmallRng::seed_from_u64(1);

        for rep in 0..1000 {
            use crate::jit::exec_map::ExecMap;
            use rand::RngExt;

            let src = Align64(core::array::from_fn(|_| rng.random()));
            let mut dst = Align64(core::array::from_fn(|_| rng.random()));

            let mut map = ExecMap::new((16384).try_into().unwrap()).unwrap();

            let mut ass = CodeAssembler::new(64).unwrap();

            let dst_reg = zmm0;
            let src_reg = zmm1;

            instr.clone().emit_all(&mut ass, dst_reg, src_reg);

            ass.ret().unwrap();

            let code = ass.assemble(map.as_ptr() as u64).unwrap();
            map.commit_code(&code).unwrap();

            let mut src_jit = src;
            let mut dst_jit = dst;

            unsafe {
                core::arch::asm!(
                    "vmovdqa64 zmm0, zmmword ptr [{dst}]",
                    "vmovdqa64 zmm1, zmmword ptr [{src}]",
                    "call {map}",
                    "vmovdqa64 zmmword ptr [{dst}], zmm0",
                    "vmovdqa64 zmmword ptr [{src}], zmm1",
                    in("rdi") data.as_ptr() as u64,
                    src = in(reg) &raw mut src_jit,
                    dst = in(reg) &raw mut dst_jit,
                    map = in(reg) map.as_ptr() as u64,
                    out("zmm0") _,
                    out("zmm1") _,
                    out("r8") _,
                    out("k0") _,
                    out("k1") _,
                    out("k6") _,
                    out("k7") _,
                    out("zmm2") _,
                    out("zmm3") _,
                    out("zmm4") _,
                    out("zmm5") _,
                    out("zmm6") _,
                    out("zmm7") _,
                    out("zmm8") _,
                    out("zmm28") _,
                    out("zmm29") _,
                    out("zmm30") _,
                    out("zmm31") _,
                    options(nostack),
                );
            }

            instr.interpret(data, &mut dst, &src);

            assert_eq!(dst, dst_jit, "dst register mismatch! (rep: {})", rep);
            assert_eq!(src, src_jit, "src register overwritten! (rep: {})", rep);
        }
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_xor() {
        test_zmm64_instr_1op(Zmm64Xor, &[]);
        test_zmm64_instr_2op(Zmm64Xor, &[]);
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_add() {
        test_zmm64_instr_1op(Zmm64AddSub::new(false), &[]);
        test_zmm64_instr_2op(Zmm64AddSub::new(false), &[]);
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_sub() {
        test_zmm64_instr_1op(Zmm64AddSub::new(true), &[]);
        test_zmm64_instr_2op(Zmm64AddSub::new(true), &[]);
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_add_const_bcst() {
        let data = Align64([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        test_zmm64_instr_1op(Zmm64AddConstBcst { data_offset: 0 }, &*data);
        test_zmm64_instr_1op(Zmm64AddConstBcst { data_offset: 8 }, &*data);
        test_zmm64_instr_2op(Zmm64AddConstBcst { data_offset: 0 }, &*data);
        test_zmm64_instr_2op(Zmm64AddConstBcst { data_offset: 8 }, &*data);
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_xor_const_bcst() {
        let data = Align64([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        test_zmm64_instr_1op(Zmm64XorConstBcst { data_offset: 0 }, &*data);
        test_zmm64_instr_1op(Zmm64XorConstBcst { data_offset: 8 }, &*data);
        test_zmm64_instr_2op(Zmm64XorConstBcst { data_offset: 0 }, &*data);
        test_zmm64_instr_2op(Zmm64XorConstBcst { data_offset: 8 }, &*data);
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_rol() {
        test_zmm64_instr_1op(Zmm64Rol { amount: 1 }, &[]);
        test_zmm64_instr_2op(Zmm64Rol { amount: 1 }, &[]);
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_mul_low() {
        test_zmm64_instr_1op(Zmm64MulLow64, &[]);
        test_zmm64_instr_2op(Zmm64MulLow64, &[]);
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_mul_hi_2op() {
        let mut data = Align64([0u8; 24]);
        unsafe {
            data.as_mut_ptr().cast::<u64>().write(0xFFFF_FFFFu64);
            data.as_mut_ptr()
                .add(8)
                .cast::<u64>()
                .write(0x1_FFFF_FFFEu64);
            data.as_mut_ptr()
                .add(16)
                .cast::<u64>()
                .write(0xFFFF_FFFEu64);
        }

        test_zmm64_instr_2op(
            Zmm64MulHi64 {
                scratch_regs: [zmm2, zmm3, zmm4, zmm5, zmm6],
                signed: false,
                magic_ffff_ffff_offset: 0,
                magic_1_ffff_fffe_offset: 8,
                magic_ffff_fffe_offset: 16,
                step: 0,
                test: None,
            },
            &*data,
        );
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_mul_hi_1op() {
        let mut data = Align64([0u8; 16]);
        unsafe {
            data.as_mut_ptr().cast::<u64>().write(0xFFFF_FFFFu64);
            data.as_mut_ptr()
                .add(8)
                .cast::<u64>()
                .write(0x1_FFFF_FFFEu64);
        }

        test_zmm64_instr_1op(
            Zmm64MulHi64 {
                scratch_regs: [zmm2, zmm3, zmm4, zmm5, zmm6],
                signed: false,
                magic_ffff_ffff_offset: 0,
                magic_1_ffff_fffe_offset: 8,
                magic_ffff_fffe_offset: 16,
                step: 0,
                test: None,
            },
            &*data,
        );
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_mul_hi_2op_signed() {
        let mut data = Align64([0u8; 24]);
        unsafe {
            data.as_mut_ptr().cast::<u64>().write(0xFFFF_FFFFu64);
            data.as_mut_ptr()
                .add(8)
                .cast::<u64>()
                .write(0x1_FFFF_FFFEu64);
            data.as_mut_ptr()
                .add(16)
                .cast::<u64>()
                .write(0xFFFF_FFFEu64);
        }
        test_zmm64_instr_2op(
            Zmm64MulHi64 {
                scratch_regs: [zmm2, zmm3, zmm4, zmm5, zmm6],
                signed: true,
                magic_ffff_ffff_offset: 0,
                magic_1_ffff_fffe_offset: 8,
                magic_ffff_fffe_offset: 16,
                step: 0,
                test: None,
            },
            &*data,
        );
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_mul_hi_1op_signed() {
        let mut data = Align64([0u8; 24]);
        unsafe {
            data.as_mut_ptr().cast::<u64>().write(0xFFFF_FFFFu64);
            data.as_mut_ptr()
                .add(8)
                .cast::<u64>()
                .write(0x1_FFFF_FFFEu64);
            data.as_mut_ptr()
                .add(16)
                .cast::<u64>()
                .write(0xFFFF_FFFEu64);
        }

        test_zmm64_instr_1op(
            Zmm64MulHi64 {
                scratch_regs: [zmm2, zmm3, zmm4, zmm5, zmm6],
                signed: true,
                magic_ffff_ffff_offset: 0,
                magic_1_ffff_fffe_offset: 8,
                magic_ffff_fffe_offset: 16,
                step: 0,
                test: None,
            },
            &*data,
        );
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_mul_hi_2op_signed_with_test() {
        use rand::SeedableRng;

        let mut rng = rand::rngs::SmallRng::seed_from_u64(1);

        for _rep in 0..1000 {
            use rand::RngExt;

            let mut mask = 0b0u64;
            let bit_0 = rng.random_range(0..32);
            let bit_1 = rng.random_range(0..32);
            mask |= 1 << bit_0;
            mask |= 1 << bit_1;
            let mask = mask;

            let mut data = Align64([0u8; 32]);
            unsafe {
                data.as_mut_ptr().cast::<u64>().write(0xFFFF_FFFFu64);
                data.as_mut_ptr()
                    .add(8)
                    .cast::<u64>()
                    .write(0x1_FFFF_FFFEu64);
                data.as_mut_ptr()
                    .add(16)
                    .cast::<u64>()
                    .write(0xFFFF_FFFEu64);
                data.as_mut_ptr().add(24).cast::<u64>().write(mask);
            }

            let mut instr = Zmm64MulHi64 {
                scratch_regs: [zmm2, zmm3, zmm4, zmm5, zmm6],
                signed: true,
                magic_ffff_ffff_offset: 0,
                magic_1_ffff_fffe_offset: 8,
                magic_ffff_fffe_offset: 16,
                step: 0,
                test: None,
            };
            instr.set_test(MaskTestData {
                test_mask_offset: 24,
                test_reg: k1,
            });

            for rep in 0..100 {
                use rand::RngExt;

                use crate::jit::exec_map::ExecMap;

                let src: Align64<[u64; 8]> = Align64(core::array::from_fn(|_| rng.random()));
                let mut dst: Align64<[u64; 8]> = Align64(core::array::from_fn(|_| rng.random()));

                let mut map = ExecMap::new((16384).try_into().unwrap()).unwrap();

                let mut ass = CodeAssembler::new(64).unwrap();

                let dst_reg = zmm0;
                let src_reg = zmm1;

                instr.clone().emit_all(&mut ass, dst_reg, src_reg);

                ass.ret().unwrap();

                let code = ass.assemble(map.as_ptr() as u64).unwrap();
                map.commit_code(&code).unwrap();

                let mut src_jit = src;
                let mut dst_jit = dst;

                let src_intrinsics = src;
                let mut dst_intrinsics = dst;
                unsafe {
                    use core::arch::x86_64::*;

                    let av = _mm512_loadu_si512(src_intrinsics.as_ptr().cast::<__m512i>());
                    let bv = _mm512_loadu_si512(dst_intrinsics.as_ptr().cast::<__m512i>());
                    let res = sample::simd_smulh(av, bv);
                    _mm512_storeu_si512(dst_intrinsics.as_mut_ptr().cast(), res);
                }

                let mut k: u32;

                unsafe {
                    core::arch::asm!(
                        "vmovdqa64 zmm0, zmmword ptr [{dst}]",
                        "vmovdqa64 zmm1, zmmword ptr [{src}]",
                        "call {map}",
                        "vmovdqa64 zmmword ptr [{dst}], zmm0",
                        "vmovdqa64 zmmword ptr [{src}], zmm1",
                        "kmovw {k:e}, k1",
                        in("rdi") data.as_ptr() as u64,
                        src = in(reg) &raw mut src_jit,
                        dst = in(reg) &raw mut dst_jit,
                        map = in(reg) map.as_ptr() as u64,
                        k = out(reg) k,
                        out("k1") _,
                        out("k6") _,
                        out("k7") _,
                        out("zmm0") _,
                        out("zmm1") _,
                        out("r8") _,
                        out("zmm2") _,
                        out("zmm3") _,
                        out("zmm4") _,
                        out("zmm5") _,
                        out("zmm6") _,
                        out("zmm7") _,
                        out("zmm8") _,
                        options(nostack),
                    );
                }

                let k = k as u8;

                let mut expected_k = 0u8;

                instr.interpret(data.as_slice(), &mut dst, &src);
                for i in 0..8 {
                    if dst.0[i] & mask == 0 {
                        expected_k |= 1 << i;
                    }
                }

                assert_eq!(
                    dst, dst_intrinsics,
                    "dst register mismatch on intrinsics! (rep: {})",
                    rep
                );
                assert_eq!(dst, dst_jit, "dst register mismatch! (rep: {})", rep);
                assert_eq!(src, src_jit, "src register overwritten! (rep: {})", rep);
                assert_eq!(
                    k, expected_k,
                    "k register mismatch (got: {:08b}, expected: {:08b})",
                    k, expected_k
                );
            }
        }
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_mul_hi_1op_signed_with_test() {
        use rand::SeedableRng;

        let mut rng = rand::rngs::SmallRng::seed_from_u64(1);

        for _rep in 0..1000 {
            use rand::RngExt;

            let mut mask = 0b0u64;
            let bit_0 = rng.random_range(0..32);
            let bit_1 = rng.random_range(0..32);
            mask |= 1 << bit_0;
            mask |= 1 << bit_1;
            let mask = mask;

            let mut data = Align64([0u8; 32]);
            unsafe {
                data.as_mut_ptr().cast::<u64>().write(0xFFFF_FFFFu64);
                data.as_mut_ptr()
                    .add(8)
                    .cast::<u64>()
                    .write(0x1_FFFF_FFFEu64);
                data.as_mut_ptr()
                    .add(16)
                    .cast::<u64>()
                    .write(0xFFFF_FFFEu64);
                data.as_mut_ptr().add(24).cast::<u64>().write(mask);
            }

            let mut instr = Zmm64MulHi64 {
                scratch_regs: [zmm2, zmm3, zmm4, zmm5, zmm6],
                signed: true,
                magic_ffff_ffff_offset: 0,
                magic_1_ffff_fffe_offset: 8,
                magic_ffff_fffe_offset: 16,
                step: 0,
                test: None,
            };
            instr.set_test(MaskTestData {
                test_mask_offset: 24,
                test_reg: k1,
            });

            for rep in 0..100 {
                use rand::RngExt;

                use crate::jit::exec_map::ExecMap;

                let mut dst = Align64(core::array::from_fn(|_| rng.random()));
                let dst_copy = dst;

                let mut map = ExecMap::new((16384).try_into().unwrap()).unwrap();

                let mut ass = CodeAssembler::new(64).unwrap();

                let dst_reg = zmm0;

                instr.clone().emit_all(&mut ass, dst_reg, dst_reg);

                ass.ret().unwrap();

                let code = ass.assemble(map.as_ptr() as u64).unwrap();
                map.commit_code(&code).unwrap();

                let mut dst_jit = dst;

                let mut k: u32;

                unsafe {
                    core::arch::asm!(
                        "vmovdqa64 zmm0, zmmword ptr [{dst}]",
                        "call {map}",
                        "vmovdqa64 zmmword ptr [{dst}], zmm0",
                        "kmovw {k:e}, k1",
                        in("rdi") data.as_ptr() as u64,
                        dst = in(reg) &raw mut dst_jit,
                        map = in(reg) map.as_ptr() as u64,
                        k = out(reg) k,
                        out("k6") _,
                        out("k7") _,
                        out("zmm0") _,
                        out("zmm1") _,
                        out("r8") _,
                        out("zmm2") _,
                        out("zmm3") _,
                        out("zmm4") _,
                        out("zmm5") _,
                        out("zmm6") _,
                        out("zmm7") _,
                        out("zmm8") _,
                        options(nostack),
                    );
                }

                let k = k as u8;

                let mut expected_k = 0u8;

                instr.interpret(data.as_slice(), &mut dst, &dst_copy);
                for i in 0..8 {
                    if dst.0[i] & mask == 0 {
                        expected_k |= 1 << i;
                    }
                }

                assert_eq!(dst, dst_jit, "dst register mismatch! (rep: {})", rep);
                assert_eq!(
                    k, expected_k,
                    "k register mismatch (got: {:08b}, expected: {:08b})",
                    k, expected_k
                );
            }
        }
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_mul_hi_2op_unsigned_with_test() {
        use rand::SeedableRng;

        let mut rng = rand::rngs::SmallRng::seed_from_u64(1);

        for _rep in 0..1000 {
            use rand::RngExt;

            let mut mask = 0b0u64;
            let bit_0 = rng.random_range(0..32);
            let bit_1 = rng.random_range(0..32);
            mask |= 1 << bit_0;
            mask |= 1 << bit_1;
            let mask = mask;

            let mut data = Align64([0u8; 32]);
            unsafe {
                data.as_mut_ptr().cast::<u64>().write(0xFFFF_FFFFu64);
                data.as_mut_ptr()
                    .add(8)
                    .cast::<u64>()
                    .write(0x1_FFFF_FFFEu64);
                data.as_mut_ptr()
                    .add(16)
                    .cast::<u64>()
                    .write(0xFFFF_FFFEu64);
                data.as_mut_ptr().add(24).cast::<u64>().write(mask);
            }

            let mut instr = Zmm64MulHi64 {
                scratch_regs: [zmm2, zmm3, zmm4, zmm5, zmm6],
                signed: false,
                magic_ffff_ffff_offset: 0,
                magic_1_ffff_fffe_offset: 8,
                magic_ffff_fffe_offset: 16,
                step: 0,
                test: None,
            };
            instr.set_test(MaskTestData {
                test_mask_offset: 24,
                test_reg: k1,
            });

            for rep in 0..100 {
                use rand::RngExt;

                use crate::jit::exec_map::ExecMap;

                let src = Align64(core::array::from_fn(|_| rng.random()));
                let mut dst = Align64(core::array::from_fn(|_| rng.random()));

                let mut map = ExecMap::new((16384).try_into().unwrap()).unwrap();

                let mut ass = CodeAssembler::new(64).unwrap();

                let dst_reg = zmm0;
                let src_reg = zmm1;

                instr.clone().emit_all(&mut ass, dst_reg, src_reg);

                ass.ret().unwrap();

                let code = ass.assemble(map.as_ptr() as u64).unwrap();
                map.commit_code(&code).unwrap();

                let mut src_jit = src;
                let mut dst_jit = dst;

                let mut k: u32;

                unsafe {
                    core::arch::asm!(
                        "vmovdqa64 zmm0, zmmword ptr [{dst}]",
                        "vmovdqa64 zmm1, zmmword ptr [{src}]",
                        "call {map}",
                        "vmovdqa64 zmmword ptr [{dst}], zmm0",
                        "vmovdqa64 zmmword ptr [{src}], zmm1",
                        "kmovw {k:e}, k1",
                        in("rdi") data.as_ptr() as u64,
                        src = in(reg) &raw mut src_jit,
                        dst = in(reg) &raw mut dst_jit,
                        map = in(reg) map.as_ptr() as u64,
                        k = out(reg) k,
                        out("k7") _,
                        out("r8") _,
                        out("zmm0") _,
                        out("zmm1") _,
                        out("zmm2") _,
                        out("zmm3") _,
                        out("zmm4") _,
                        out("zmm5") _,
                        out("zmm6") _,
                        out("zmm7") _,
                        out("zmm8") _,
                        options(nostack),
                    );
                }

                let k = k as u8;

                let mut expected_k = 0u8;

                instr.interpret(data.as_slice(), &mut dst, &src);
                for i in 0..8 {
                    if dst.0[i] & mask == 0 {
                        expected_k |= 1 << i;
                    }
                }

                assert_eq!(dst, dst_jit, "dst register mismatch! (rep: {})", rep);
                assert_eq!(src, src_jit, "src register overwritten! (rep: {})", rep);
                assert_eq!(
                    k, expected_k,
                    "k register mismatch (got: {:08b}, expected: {:08b})",
                    k, expected_k
                );
            }
        }
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_zmm64_mul_hi_1op_unsigned_with_test() {
        use rand::SeedableRng;

        let mut rng = rand::rngs::SmallRng::seed_from_u64(1);

        for _rep in 0..1000 {
            use rand::RngExt;

            let mut mask = 0b0u64;
            let bit_0 = rng.random_range(0..32);
            let bit_1 = rng.random_range(0..32);
            mask |= 1 << bit_0;
            mask |= 1 << bit_1;
            let mask = mask;

            let mut data = Align64([0u8; 32]);
            unsafe {
                data.as_mut_ptr().cast::<u64>().write(0xFFFF_FFFFu64);
                data.as_mut_ptr()
                    .add(8)
                    .cast::<u64>()
                    .write(0x1_FFFF_FFFEu64);
                data.as_mut_ptr()
                    .add(16)
                    .cast::<u64>()
                    .write(0xFFFF_FFFEu64);
                data.as_mut_ptr().add(24).cast::<u64>().write(mask);
            }

            let mut instr = Zmm64MulHi64 {
                scratch_regs: [zmm2, zmm3, zmm4, zmm5, zmm6],
                signed: false,
                magic_ffff_ffff_offset: 0,
                magic_1_ffff_fffe_offset: 8,
                magic_ffff_fffe_offset: 16,
                step: 0,
                test: None,
            };
            instr.set_test(MaskTestData {
                test_mask_offset: 24,
                test_reg: k1,
            });

            for rep in 0..100 {
                use rand::RngExt;

                use crate::jit::exec_map::ExecMap;

                let mut dst = Align64(core::array::from_fn(|_| rng.random()));
                let dst_copy = dst;

                let mut map = ExecMap::new((16384).try_into().unwrap()).unwrap();

                let mut ass = CodeAssembler::new(64).unwrap();

                let dst_reg = zmm0;

                instr.clone().emit_all(&mut ass, dst_reg, dst_reg);

                ass.ret().unwrap();

                let code = ass.assemble(map.as_ptr() as u64).unwrap();
                map.commit_code(&code).unwrap();

                let mut dst_jit = dst;

                let mut k: u32;

                unsafe {
                    core::arch::asm!(
                        "vmovdqa64 zmm0, zmmword ptr [{dst}]",
                        "call {map}",
                        "vmovdqa64 zmmword ptr [{dst}], zmm0",
                        "kmovw {k:e}, k1",
                        in("rdi") data.as_ptr() as u64,
                        dst = in(reg) &raw mut dst_jit,
                        map = in(reg) map.as_ptr() as u64,
                        k = out(reg) k,
                        out("k1") _,
                        out("zmm0") _,
                        out("zmm1") _,
                        out("r8") _,
                        out("zmm2") _,
                        out("zmm3") _,
                        out("zmm4") _,
                        out("zmm5") _,
                        out("zmm6") _,
                        out("zmm7") _,
                        out("zmm8") _,
                        options(nostack),
                    );
                }

                let k = k as u8;

                let mut expected_k = 0u8;

                instr.interpret(data.as_slice(), &mut dst, &dst_copy);
                for i in 0..8 {
                    if dst.0[i] & mask == 0 {
                        expected_k |= 1 << i;
                    }
                }

                assert_eq!(dst, dst_jit, "dst register mismatch! (rep: {})", rep);
                assert_eq!(
                    k, expected_k,
                    "k register mismatch (got: {:08b}, expected: {:08b})",
                    k, expected_k
                );
            }
        }
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_mulh_special_vectors() {
        use core::arch::x86_64::*;

        use crate::jit::exec_map::ExecMap;

        let a = 18446744073709551578u64;
        let b = 18446744073709551611u64;
        let expected_result = (u128::from(a) * u128::from(b) >> 64) as u64;

        unsafe {
            let av = _mm512_set1_epi64(a as i64);
            let bv = _mm512_set1_epi64(b as i64);
            let result = sample::simd_umulh(av, bv);
            let result = _mm256_extract_epi64(_mm512_castsi512_si256(result), 0) as u64;
            assert_eq!(result, expected_result);
        }

        let mut map = ExecMap::new((16384).try_into().unwrap()).unwrap();

        let mut data = Align64([0u8; 24]);
        unsafe {
            data.as_mut_ptr().cast::<u64>().write(0xFFFF_FFFFu64);
            data.as_mut_ptr()
                .add(8)
                .cast::<u64>()
                .write(0x1_FFFF_FFFEu64);
            data.as_mut_ptr()
                .add(16)
                .cast::<u64>()
                .write(0xFFFF_FFFEu64);
        }

        let instr = Zmm64MulHi64 {
            scratch_regs: [zmm2, zmm3, zmm4, zmm5, zmm6],
            signed: false,
            magic_ffff_ffff_offset: 0,
            magic_1_ffff_fffe_offset: 8,
            magic_ffff_fffe_offset: 16,
            step: 0,
            test: None,
        };

        let mut dst = Align64(core::array::from_fn(|_| a as u64));
        let src = Align64(core::array::from_fn(|_| b as u64));

        let mut ass = CodeAssembler::new(64).unwrap();
        instr.clone().emit_all(&mut ass, zmm0, zmm1);
        ass.ret().unwrap();

        let code = ass.assemble(map.as_ptr() as u64).unwrap();
        map.commit_code(&code).unwrap();

        let mut dst_jit = dst;
        let mut src_jit = src;

        let expected_dst = Align64(core::array::from_fn(|_| expected_result as u64));
        instr.interpret(data.as_slice(), &mut dst, &src);
        assert_eq!(dst, expected_dst);

        unsafe {
            core::arch::asm!(
                "vmovdqa64 zmm0, zmmword ptr [{dst}]",
                "vmovdqa64 zmm1, zmmword ptr [{src}]",
                "call {map}",
                "vmovdqa64 zmmword ptr [{dst}], zmm0",
                "vmovdqa64 zmmword ptr [{src}], zmm1",
                in("rdi") data.as_ptr() as u64,
                dst = in(reg) &raw mut dst_jit,
                src = in(reg) &raw mut src_jit,
                map = in(reg) map.as_ptr() as u64,
                out("zmm0") _,
                out("zmm1") _,
                out("r8") _,
                out("zmm2") _,
                out("zmm3") _,
                out("zmm4") _,
                out("zmm5") _,
                out("zmm6") _,
                out("zmm7") _,
                out("zmm8") _,
                options(nostack),
            );
        }

        assert_eq!(
            expected_dst, dst_jit,
            "expected dst: {:016x?}, got: {:016x?}",
            expected_dst, dst_jit
        );
        assert_eq!(src, src_jit);
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_mulh_special_vectors_1op() {
        use core::arch::x86_64::*;

        use crate::jit::exec_map::ExecMap;
        let a = 3478801740564115556i64;
        let expected_result = (i128::from(a) * i128::from(a) >> 64) as u64;

        unsafe {
            let av = _mm512_set1_epi64(a);
            let result = sample::simd_smulh(av, av);
            let result = _mm256_extract_epi64(_mm512_castsi512_si256(result), 0) as u64;
            assert_eq!(result, expected_result);
        }

        let mut map = ExecMap::new((16384).try_into().unwrap()).unwrap();

        let mut data = Align64([0u8; 24]);
        unsafe {
            data.as_mut_ptr().cast::<u64>().write(0xFFFF_FFFFu64);
            data.as_mut_ptr()
                .add(8)
                .cast::<u64>()
                .write(0x1_FFFF_FFFEu64);
            data.as_mut_ptr()
                .add(16)
                .cast::<u64>()
                .write(0xFFFF_FFFEu64);
        }

        let instr = Zmm64MulHi64 {
            scratch_regs: [zmm2, zmm3, zmm4, zmm5, zmm6],
            signed: true,
            magic_ffff_ffff_offset: 0,
            magic_1_ffff_fffe_offset: 8,
            magic_ffff_fffe_offset: 16,
            step: 0,
            test: None,
        };

        let mut dst = Align64(core::array::from_fn(|_| a as u64));
        let src = dst;

        let mut ass = CodeAssembler::new(64).unwrap();
        instr.clone().emit_all(&mut ass, zmm0, zmm0);
        ass.ret().unwrap();

        let code = ass.assemble(map.as_ptr() as u64).unwrap();
        map.commit_code(&code).unwrap();

        let mut dst_jit = dst;

        let expected_dst = Align64(core::array::from_fn(|_| expected_result as u64));
        instr.interpret(data.as_slice(), &mut dst, &src);
        assert_eq!(dst, expected_dst);

        unsafe {
            core::arch::asm!(
                "vmovdqa64 zmm0, zmmword ptr [{dst}]",
                "call {map}",
                "vmovdqa64 zmmword ptr [{dst}], zmm0",
                in("rdi") data.as_ptr() as u64,
                dst = in(reg) &raw mut dst_jit,
                map = in(reg) map.as_ptr() as u64,
                out("zmm0") _,
                out("r8") _,
                out("zmm2") _,
                out("zmm3") _,
                out("zmm4") _,
                out("zmm5") _,
                out("zmm6") _,
                out("zmm7") _,
                out("zmm8") _,
                options(nostack),
            );
        }

        assert_eq!(
            expected_dst, dst_jit,
            "expected dst: {:016x?}, got: {:016x?}",
            expected_dst, dst_jit
        );
    }
}
