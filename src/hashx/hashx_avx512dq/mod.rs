use core::num::NonZeroUsize;

use iced_x86::{DecoderOptions, Formatter, FormatterOutput, IntelFormatter, code_asm::*};

use crate::{
    Align64, Align128,
    hashx::{
        TestMode,
        hashx_vendor::{
            HashX,
            program::{
                BRANCH_EN, Instruction, OPCODE_ADD_CONST_EN, OPCODE_ADDSHIFT_EN, OPCODE_MUL_EN,
                OPCODE_MULH_EN, OPCODE_ROTATE_EN, OPCODE_SUB_EN, OPCODE_XOR_CONST_EN,
                OPCODE_XOR_EN,
            },
        },
    },
    jit::exec_map::ExecMapView,
};

#[allow(unreachable_code)]
pub(crate) fn cpuid_check() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        cpufeatures::new!(avx512dq, "avx512dq");

        return avx512dq::get();
    }

    false
}

trait RegisterZMMExt {
    fn attach_mask_gated(self, gate: bool, mask: AsmRegisterK) -> AsmRegisterZmm;
    fn attach_mask(self, mask: AsmRegisterK) -> AsmRegisterZmm;
}

impl RegisterZMMExt for AsmRegisterZmm {
    /// Attach a mask if gate is true, otherwise return the register itself
    fn attach_mask_gated(self, gate: bool, mask: AsmRegisterK) -> AsmRegisterZmm {
        if gate { self.attach_mask(mask) } else { self }
    }
    /// Attach a mask to the register
    fn attach_mask(self, mask: AsmRegisterK) -> AsmRegisterZmm {
        if mask == k0 {
            self
        } else if mask == k1 {
            self.k1()
        } else if mask == k2 {
            self.k2()
        } else if mask == k3 {
            self.k3()
        } else if mask == k4 {
            self.k4()
        } else if mask == k5 {
            self.k5()
        } else if mask == k6 {
            self.k6()
        } else if mask == k7 {
            self.k7()
        } else {
            unreachable!("invalid mask");
        }
    }
}

/// A compiled multi-buffer sifter
pub struct CompiledSifter<'a> {
    code_len: usize,
    data: &'a mut DataBuffer,
    map: &'a mut ExecMapView,
}

/// Data buffer
pub type DataBuffer = Align128<[u64; 512]>;

#[repr(transparent)]
/// Register dump
struct RegisterDump {
    data: [[Align64<[u64; 8]>; 8]; 2],
}

impl RegisterDump {
    fn get_lane(&self, lane: usize) -> [u64; 8] {
        core::array::from_fn(|i| self.data[lane / 8][i][lane % 8])
    }
}

#[cfg(any(test, feature = "std"))]
impl std::fmt::Debug for RegisterDump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "RegisterDump {{")?;
        for i in 0..2 {
            for j in 0..8 {
                writeln!(f, "  {}: {:016x?}", i * 8 + j, self.get_lane(i * 8 + j))?;
            }
        }
        write!(f, "}}")
    }
}

impl Default for RegisterDump {
    fn default() -> Self {
        Self {
            data: [[Align64([0; 8]); 8]; 2],
        }
    }
}

impl<'a> CompiledSifter<'a> {
    /// Hashes attempted per call
    pub const HASHES_PER_CALL: u32 = 1024;
    const ITERATION_COUNT: u32 = Self::HASHES_PER_CALL / 16;

    /// The wanted size for the mapping
    pub const WANTED_SIZE: NonZeroUsize = NonZeroUsize::new(32 << 10).unwrap();

    /// Create a new compiled sifter with an existing memory map
    pub fn new_ex(
        map: &'a mut ExecMapView,
        data: &'a mut DataBuffer,
        hashx: &HashX,
        test: TestMode,
        enable_debug: bool,
    ) -> Self {
        use crate::jit::*;
        let HashX {
            register_key,
            program,
        } = hashx;

        let [v0, v1, v2, v3] = register_key.clone().into();
        let v1_ee = v1 ^ 0xee; // this is always the same step, do this before compiling

        // MulHi clobbers k6 and k7!

        // lane enable mask
        let lane_en = [k1, k2];

        // branch inhibit mask
        let branch_inh = [k3, k4];

        let registers = [
            [zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7],
            [zmm8, zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15],
        ];

        let scratches = [
            [zmm20, zmm21, zmm22, zmm23, zmm24, zmm25],
            [zmm26, zmm27, zmm28, zmm29, zmm30, zmm31],
        ];
        let input_offset_v = [zmm18, zmm19];

        let data_ptr = rdi;
        let input_offset = rsi;
        let dbg_ptr = rcx;
        let compare_num = r8;
        let ret = eax;
        let loop_var = r10d;

        let mut data_count = 0;

        macro_rules! place_data {
            ($val:expr) => {{
                data[data_count] = $val;
                let ptr = data_ptr + 8 * data_count;
                data_count += 1;
                ptr
            }};
        }

        macro_rules! place_data_offset {
            ($val:expr) => {{
                data[data_count] = $val;
                let ptr = 8 * data_count;
                data_count += 1;
                ptr as u32
            }};
        }

        // initialy the input is guaranteed to be aligned
        let seq_0_8 = place_data!(0);
        for i in 1..8 {
            place_data!(i);
        }

        let const_ee = place_data!(0xee);
        let const_v0 = place_data!(v0);
        let const_v1 = place_data!(v1_ee);
        let const_v2 = place_data!(v2);
        let const_v3 = place_data!(v3);
        let const_8 = place_data!(8);

        let mut a = CodeAssembler::new(64).unwrap();
        a.set_prefer_vex(false);
        a.xor(ret, ret).unwrap();
        a.mov(loop_var, Self::ITERATION_COUNT).unwrap();

        // setup input offset vector to be [input_offset, input_offset + 8] and [input_offset + 8, input_offset + 16]
        a.vmovdqa64(input_offset_v[0], qword_ptr(seq_0_8)).unwrap();
        a.vpaddq(
            input_offset_v[0],
            input_offset_v[0],
            qword_bcst(input_offset),
        )
        .unwrap();

        let mut loop_begin = a.create_label();
        a.set_label(&mut loop_begin).unwrap();
        a.vpaddq(input_offset_v[1], input_offset_v[0], qword_bcst(const_8))
            .unwrap();

        a.vpbroadcastq(registers[0][0], qword_ptr(const_v0))
            .unwrap();
        a.vmovdqa64(registers[1][0], registers[0][0]).unwrap();
        a.vpbroadcastq(registers[0][1], qword_ptr(const_v1))
            .unwrap();
        a.vmovdqa64(registers[1][1], registers[0][1]).unwrap();
        a.vpbroadcastq(registers[0][2], qword_ptr(const_v2))
            .unwrap();
        a.vmovdqa64(registers[1][2], registers[0][2]).unwrap();
        a.vpxorq(registers[0][3], input_offset_v[0], qword_bcst(const_v3))
            .unwrap();
        a.vpxorq(registers[1][3], input_offset_v[1], qword_bcst(const_v3))
            .unwrap();

        for _round in 0..2 {
            sipround_avx512_jit(
                &mut a,
                [registers[0][0], registers[1][0]],
                [registers[0][1], registers[1][1]],
                [registers[0][2], registers[1][2]],
                [registers[0][3], registers[1][3]],
            );
        }

        for i in 0..2 {
            a.vpxorq(registers[i][0], registers[i][0], input_offset_v[i])
                .unwrap();
            a.vpxorq(registers[i][2], registers[i][2], qword_bcst(const_ee))
                .unwrap();
        }

        for _round in 0..4 {
            sipround_avx512_jit(
                &mut a,
                [registers[0][0], registers[1][0]],
                [registers[0][1], registers[1][1]],
                [registers[0][2], registers[1][2]],
                [registers[0][3], registers[1][3]],
            );
        }

        for i in 0..2 {
            a.kxorw(branch_inh[i], branch_inh[i], branch_inh[i])
                .unwrap();
            for j in 0..4 {
                if j == 1 {
                    a.vpxorq(
                        registers[i][j + 4],
                        registers[i][j],
                        qword_bcst(place_data!(0xdd)),
                    )
                    .unwrap();
                } else {
                    a.vmovdqa64(registers[i][j + 4], registers[i][j]).unwrap();
                }
            }
            a.kxorw(lane_en[i], lane_en[i], lane_en[i]).unwrap();
        }

        for _round in 0..4 {
            sipround_avx512_jit(
                &mut a,
                [registers[0][4], registers[1][4]],
                [registers[0][5], registers[1][5]],
                [registers[0][6], registers[1][6]],
                [registers[0][7], registers[1][7]],
            );
        }

        let magic_ffff_fffe = place_data_offset!(0xFFFF_FFFEu64);
        let magic_ffff_ffff = place_data_offset!(0xFFFF_FFFFu64);
        let magic_1_ffff_fffe = place_data_offset!(0x1_FFFF_FFFEu64);

        let mut branch_target = None;

        let mut backwards_edge = false;

        let mut fallthrough_branch = None;

        let mut pc = 0;
        let mut cnt_branch = 0;
        // unroll branches and generate straight line code
        while pc < program.len() {
            let inst = &program[pc];
            let mut next_pc = pc + 1;
            let mut placed_data = None;

            if let Instruction::Target = inst {
                branch_target = Some(next_pc);
            }

            for i in 0..2 {
                match inst {
                    Instruction::AddConst { dst, src } if OPCODE_ADD_CONST_EN => {
                        if placed_data.is_none() {
                            let imm = i64::from(*src) as u64;
                            placed_data = Some(place_data_offset!(imm));
                        }
                        Zmm64AddConstBcst::new(placed_data.unwrap()).emit_all(
                            &mut a,
                            registers[i][dst.as_usize()]
                                .attach_mask_gated(backwards_edge, lane_en[i]),
                            registers[i][dst.as_usize()],
                        );
                    }
                    Instruction::XorConst { dst, src } if OPCODE_XOR_CONST_EN => {
                        if placed_data.is_none() {
                            let imm = i64::from(*src) as u64;
                            placed_data = Some(place_data_offset!(imm));
                        }
                        Zmm64XorConstBcst::new(placed_data.unwrap()).emit_all(
                            &mut a,
                            registers[i][dst.as_usize()]
                                .attach_mask_gated(backwards_edge, lane_en[i]),
                            registers[i][dst.as_usize()],
                        );
                    }
                    Instruction::Xor { dst, src } if OPCODE_XOR_EN => {
                        Zmm64Xor::new().emit_all(
                            &mut a,
                            registers[i][dst.as_usize()]
                                .attach_mask_gated(backwards_edge, lane_en[i]),
                            registers[i][src.as_usize()],
                        );
                    }
                    Instruction::Sub { dst, src } if OPCODE_SUB_EN => {
                        Zmm64AddSub::new(true).emit_all(
                            &mut a,
                            registers[i][dst.as_usize()]
                                .attach_mask_gated(backwards_edge, lane_en[i]),
                            registers[i][src.as_usize()],
                        );
                    }
                    Instruction::Rotate { dst, right_rotate } if OPCODE_ROTATE_EN => {
                        Zmm64Rol::new((64 - *right_rotate) as u32).emit_all(
                            &mut a,
                            registers[i][dst.as_usize()]
                                .attach_mask_gated(backwards_edge, lane_en[i]),
                            registers[i][dst.as_usize()],
                        );
                    }
                    Instruction::Mul { dst, src } if OPCODE_MUL_EN => {
                        Zmm64MulLow64::new().emit_all(
                            &mut a,
                            registers[i][dst.as_usize()]
                                .attach_mask_gated(backwards_edge, lane_en[i]),
                            registers[i][src.as_usize()],
                        );
                    }
                    Instruction::UMulH { dst, src } | Instruction::SMulH { dst, src } => {
                        if OPCODE_MULH_EN {
                            let mut test_mask = None;
                            let mut search_pc = pc + 1;
                            // find if this UMulH is used for a branch
                            while !backwards_edge && search_pc < hashx.program.len() {
                                let inst = &hashx.program[search_pc];
                                if let Instruction::UMulH { .. } | Instruction::SMulH { .. } = inst
                                {
                                    break;
                                }
                                if let Instruction::Branch { mask } = inst {
                                    test_mask = Some(*mask);
                                    break;
                                }
                                search_pc += 1;
                            }
                            let signed = matches!(inst, Instruction::SMulH { .. });
                            let mut codegen = Zmm64MulHi64::new(
                                signed,
                                magic_ffff_fffe,
                                magic_ffff_ffff,
                                magic_1_ffff_fffe,
                                scratches[i][..5].try_into().unwrap(),
                            );
                            // if so, set the test mask
                            if let Some(test_mask) = test_mask {
                                codegen.set_test(MaskTestData {
                                    test_mask_offset: placed_data
                                        .unwrap_or_else(|| place_data_offset!(test_mask as u64)),
                                    test_reg: lane_en[i],
                                });
                            }

                            if src == dst && backwards_edge && !signed {
                                a.vmovdqa64(scratches[i][5], registers[i][dst.as_usize()])
                                    .unwrap();
                                codegen.emit_all(&mut a, scratches[i][5], scratches[i][5]);
                                a.vmovdqa64(
                                    registers[i][dst.as_usize()]
                                        .attach_mask_gated(backwards_edge, lane_en[i]),
                                    scratches[i][5],
                                )
                                .unwrap();
                            } else {
                                codegen.emit_all(
                                    &mut a,
                                    registers[i][dst.as_usize()]
                                        .attach_mask_gated(backwards_edge, lane_en[i]),
                                    registers[i][src.as_usize()],
                                );
                            }

                            if test_mask.is_some() {
                                a.kandnw(lane_en[i], branch_inh[i], lane_en[i]).unwrap();
                                a.korw(branch_inh[i], branch_inh[i], lane_en[i]).unwrap();
                            }
                        }
                    }
                    Instruction::AddShift {
                        dst,
                        src,
                        left_shift,
                    } if OPCODE_ADDSHIFT_EN => {
                        if *left_shift == 0 {
                            a.vpaddq(
                                registers[i][dst.as_usize()]
                                    .attach_mask_gated(backwards_edge, lane_en[i]),
                                registers[i][dst.as_usize()],
                                registers[i][src.as_usize()],
                            )
                            .unwrap();
                        } else {
                            a.vpsllq(
                                scratches[i][5],
                                registers[i][src.as_usize()],
                                *left_shift as u32,
                            )
                            .unwrap();
                            a.vpaddq(
                                registers[i][dst.as_usize()]
                                    .attach_mask_gated(backwards_edge, lane_en[i]),
                                registers[i][dst.as_usize()],
                                scratches[i][5],
                            )
                            .unwrap();
                        }
                    }
                    Instruction::Target => {}
                    Instruction::Branch { .. } => {
                        if let Some(branch_target_pc) = branch_target {
                            next_pc = branch_target_pc;

                            // HashX tends to zeroize itself (!) at later stages, causing more predictable branches
                            // so we insert jumps in case some parts can be relicably skipped
                            // 6 is empirically a good number
                            //
                            // some random samples: (1 -> should skip, 0 -> should take)
                            // branching info: [0.27, 0.40, 0.38, 0.53, 0.47, 0.41, 0.53, 0.51, 0.54, 0.56, 0.57, 0.63, 0.64, 0.67, 0.63, 0.62]
                            // branching info: [0.49, 0.48, 0.45, 0.48, 0.46, 0.46, 0.46, 0.48, 0.52, 0.63, 0.66, 0.55, 0.69, 0.70, 0.75, 0.60]
                            // branching info: [0.37, 0.33, 0.43, 0.44, 0.38, 0.48, 0.53, 0.50, 0.52, 0.58, 0.58, 0.62, 0.62, 0.62, 0.75, 0.71]
                            // branching info: [0.32, 0.45, 0.57, 0.35, 0.45, 0.57, 0.38, 0.51, 0.57, 0.65, 0.52, 0.55, 0.74, 0.58, 0.65, 0.81]
                            // branching info: [0.41, 0.48, 0.39, 0.47, 0.49, 0.40, 0.59, 0.49, 0.56, 0.56, 0.65, 0.59, 0.56, 0.60, 0.63, 0.77]
                            // branching info: [0.39, 0.41, 0.40, 0.37, 0.46, 0.57, 0.47, 0.56, 0.59, 0.54, 0.60, 0.58, 0.64, 0.63, 0.68, 0.67]
                            // branching info: [0.35, 0.42, 0.42, 0.47, 0.35, 0.47, 0.51, 0.60, 0.60, 0.55, 0.63, 0.63, 0.63, 0.54, 0.70, 0.70]
                            // branching info: [0.43, 0.36, 0.44, 0.38, 0.45, 0.48, 0.53, 0.53, 0.54, 0.46, 0.59, 0.63, 0.59, 0.65, 0.66, 0.66]
                            // branching info: [0.40, 0.37, 0.36, 0.42, 0.43, 0.45, 0.49, 0.54, 0.57, 0.59, 0.60, 0.64, 0.65, 0.65, 0.67, 0.68]
                            // branching info: [0.39, 0.35, 0.43, 0.39, 0.47, 0.49, 0.52, 0.51, 0.50, 0.53, 0.58, 0.61, 0.59, 0.66, 0.67, 0.73]
                            // branching info: [0.29, 0.41, 0.37, 0.43, 0.40, 0.46, 0.53, 0.61, 0.55, 0.57, 0.60, 0.61, 0.66, 0.64, 0.65, 0.70]
                            // branching info: [0.34, 0.38, 0.37, 0.41, 0.49, 0.48, 0.48, 0.52, 0.54, 0.52, 0.58, 0.61, 0.62, 0.69, 0.66, 0.68]
                            // branching info: [0.35, 0.44, 0.42, 0.47, 0.41, 0.45, 0.55, 0.51, 0.61, 0.58, 0.58, 0.54, 0.58, 0.68, 0.68, 0.70]
                            if !enable_debug && i == 1 && cnt_branch >= 6 {
                                let lbl_fallthrough = a.create_label();
                                a.kortestw(lane_en[0], lane_en[1]).unwrap();
                                a.jz(lbl_fallthrough).unwrap();
                                fallthrough_branch = Some(lbl_fallthrough);
                            }
                            backwards_edge = true;

                            // when branch is disabled, fuse lane_en off on backwards path
                            if !BRANCH_EN {
                                a.kxorw(lane_en[i], lane_en[i], lane_en[i]).unwrap();
                            }
                        } else {
                            if let Some(mut lbl_fallthrough) = fallthrough_branch.take() {
                                a.set_label(&mut lbl_fallthrough).unwrap();
                            }
                            backwards_edge = false;
                        }
                    }
                    _ => {
                        eprintln!("ignoring disabled instruction {:?}", inst);
                    }
                }
            }

            if backwards_edge && let Instruction::Branch { .. } = inst {
                branch_target = None;
                cnt_branch += 1;
            }

            pc = next_pc;
        }

        if enable_debug {
            let mut lbl_dump_regs_fallthrough = a.create_label();
            a.test(dbg_ptr, dbg_ptr).unwrap();
            a.jz(lbl_dump_regs_fallthrough).unwrap();

            for i in 0..2 {
                for j in 0..8 {
                    a.vmovdqa64(dbg_ptr + (i * 8 + j) * 64, registers[i][j])
                        .unwrap();
                }
            }

            a.set_label(&mut lbl_dump_regs_fallthrough).unwrap();
        }

        let const_v1_orig = place_data!(v1);

        a.vpaddq(registers[0][0], registers[0][0], qword_bcst(const_v0))
            .unwrap();
        a.vpaddq(registers[0][1], registers[0][1], qword_bcst(const_v1_orig))
            .unwrap();
        a.vpaddq(registers[0][6], registers[0][6], qword_bcst(const_v2))
            .unwrap();
        a.vpaddq(registers[0][7], registers[0][7], qword_bcst(const_v3))
            .unwrap();
        a.vpaddq(registers[1][0], registers[1][0], qword_bcst(const_v0))
            .unwrap();
        a.vpaddq(registers[1][1], registers[1][1], qword_bcst(const_v1_orig))
            .unwrap();
        a.vpaddq(registers[1][6], registers[1][6], qword_bcst(const_v2))
            .unwrap();
        a.vpaddq(registers[1][7], registers[1][7], qword_bcst(const_v3))
            .unwrap();
        a.vpbroadcastq(scratches[0][0], compare_num).unwrap();

        sipround_avx512_jit_v0_only(
            &mut a,
            [
                registers[0][0],
                registers[0][4],
                registers[1][0],
                registers[1][4],
            ],
            [
                registers[0][1],
                registers[0][5],
                registers[1][1],
                registers[1][5],
            ],
            [
                registers[0][2],
                registers[0][6],
                registers[1][2],
                registers[1][6],
            ],
            [
                registers[0][3],
                registers[0][7],
                registers[1][3],
                registers[1][7],
            ],
        );
        // the 64-bit hash output is the v0 register self-xored
        for i in 0..2 {
            a.vpxorq(registers[i][0], registers[i][0], registers[i][4])
                .unwrap();
        }
        match test {
            TestMode::LessThan => {
                a.vpcmpltuq(lane_en[0], registers[0][0], scratches[0][0])
                    .unwrap();
                a.vpcmpltuq(lane_en[1], registers[1][0], scratches[0][0])
                    .unwrap();
            }
            TestMode::Mask => {
                a.vptestnmq(lane_en[0], registers[0][0], scratches[0][0])
                    .unwrap();
                a.vptestnmq(lane_en[1], registers[1][0], scratches[0][0])
                    .unwrap();
            }
        }
        a.kortestw(lane_en[0], lane_en[1]).unwrap();
        let mut found = a.create_label();
        a.jne(found).unwrap();

        let mut loop_end = a.create_label();

        a.vpaddq(input_offset_v[0], input_offset_v[1], qword_bcst(const_8))
            .unwrap();
        a.add(qword_ptr(input_offset), 16).unwrap();
        a.sub(loop_var, 1).unwrap();
        a.jnz(loop_begin).unwrap();

        a.set_label(&mut loop_end).unwrap();
        a.ret().unwrap();

        a.set_label(&mut found).unwrap();
        a.kshiftlw(lane_en[1], lane_en[1], 8).unwrap();
        a.korw(lane_en[0], lane_en[0], lane_en[1]).unwrap();
        a.kmovw(ret, lane_en[0]).unwrap();

        a.ret().unwrap();
        _ = data_count;

        let code = a.assemble(map.as_ptr() as u64).unwrap();
        map.commit_code(&code).unwrap();

        Self {
            data,
            map,
            code_len: code.len(),
        }
    }

    /// Disassemble the kernel
    pub fn disas<W: std::io::Write>(&self, w: &mut W) {
        use iced_x86::Decoder;

        let bytes = unsafe { core::slice::from_raw_parts(self.map.as_ptr(), self.code_len) };
        let mut decoder = Decoder::with_ip(64, &bytes, 0, DecoderOptions::NONE);

        // Formatters: Masm*, Nasm*, Gas* (AT&T) and Intel* (XED).
        // For fastest code, see `SpecializedFormatter` which is ~3.3x faster. Use it if formatting
        // speed is more important than being able to re-assemble formatted instructions.
        let mut formatter = IntelFormatter::new();

        struct CustomOutput {
            output: String,
        }

        impl FormatterOutput for CustomOutput {
            fn write(&mut self, text: &str, kind: iced_x86::FormatterTextKind) {
                let mapped_text = if kind == iced_x86::FormatterTextKind::Register {
                    let mut text = text.to_string();
                    text = text.replace("k1", "lane_en[0]");
                    text = text.replace("k2", "lane_en[1]");
                    text = text.replace("k3", "branch_inh[0]");
                    text = text.replace("k4", "branch_inh[1]");

                    for s in 20..32 {
                        let reg_name = format!("zmm{}", s);
                        let s = s - 20;
                        text = text.replace(&reg_name, &format!("S{}[{}]", s % 6, s / 6));
                    }
                    text = text.replace("zmm18", "input_offset_v[0]");
                    text = text.replace("zmm19", "input_offset_v[1]");

                    for r in (0..16).rev() {
                        let reg_name = format!("zmm{}", r);
                        text = text.replace(&reg_name, &format!("R{}[{}]", r % 8, r / 8));
                    }
                    std::borrow::Cow::Owned(text)
                } else {
                    text.into()
                };
                self.output.write(&mapped_text, kind);
            }
        }

        // String implements FormatterOutput
        let mut output = CustomOutput {
            output: String::new(),
        };

        // Initialize this outside the loop because decode_out() writes to every field
        let mut instruction = iced_x86::Instruction::default();

        // The decoder also implements Iterator/IntoIterator so you could use a for loop:
        //      for instruction in &mut decoder { /* ... */ }
        // or collect():
        //      let instructions: Vec<_> = decoder.into_iter().collect();
        // but can_decode()/decode_out() is a little faster:
        while decoder.can_decode() {
            // There's also a decode() method that returns an instruction but that also
            // means it copies an instruction (40 bytes):
            //     instruction = decoder.decode();
            decoder.decode_out(&mut instruction);

            // Format the instruction ("disassemble" it)
            output.output.clear();
            formatter.format(&instruction, &mut output);

            // Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
            write!(w, "{:016X} ", instruction.ip()).unwrap();

            writeln!(w, " {}", output.output).unwrap();
        }
    }

    #[inline(always)]
    /// Run the kernel with debugging information input
    fn sift_ex(
        &self,
        input_offset: &mut u64,
        compare_num: u64,
        dbg_ptr: Option<&mut RegisterDump>,
    ) -> u32 {
        let mut ret;
        unsafe {
            core::arch::asm!(
                "call {exec}",
                in("rdi") self.data.as_ptr() as u64,
                in("rsi") input_offset,
                in("rcx") dbg_ptr.map(|x| x as *mut _).unwrap_or(core::ptr::null_mut()),
                out("eax") ret,
                in("r8") compare_num,
                out("r10") _, // loop counter
                exec = in(reg) self.map.as_ptr() as u64,
                out("k0") _,
                out("k1") _,
                out("k2") _,
                out("k3") _,
                out("k4") _,
                out("k5") _,
                out("k6") _,
                out("k7") _,
                out("zmm0") _,
                out("zmm1") _,
                out("zmm2") _,
                out("zmm3") _,
                out("zmm4") _,
                out("zmm5") _,
                out("zmm6") _,
                out("zmm7") _,
                out("zmm8") _,
                out("zmm9") _,
                out("zmm10") _,
                out("zmm11") _,
                out("zmm12") _,
                out("zmm13") _,
                out("zmm14") _,
                out("zmm15") _,
                out("zmm16") _,
                out("zmm17") _,
                out("zmm18") _,
                out("zmm19") _,
                out("zmm20") _,
                out("zmm21") _,
                out("zmm22") _,
                out("zmm23") _,
                out("zmm24") _,
                out("zmm25") _,
                out("zmm26") _,
                out("zmm27") _,
                out("zmm28") _,
                out("zmm29") _,
                out("zmm30") _,
                out("zmm31") _,
            );
        }
        ret
    }

    #[inline(always)]
    /// Run the kernel without debugging information without debugging information input
    pub fn sift(&self, compare_num: u64, input_offset: &mut u64) -> u32 {
        self.sift_ex(input_offset, compare_num, None)
    }
}

#[cfg(test)]
mod tests {
    use crate::{hashx::hashx_vendor::register::RegisterFile, jit::exec_map::ExecMap};

    use super::*;

    #[test]
    fn test_sift() {
        let threshold = 1 << (64 - 10);
        let expected_hashes = u64::MAX / threshold;
        let mut total_checked = 0;
        let mut count_seeds = 0;
        let mut map = ExecMap::new(CompiledSifter::WANTED_SIZE).unwrap();
        let mut data = Box::<DataBuffer>::new_uninit();
        unsafe {
            data.assume_init_mut().fill(0);
        }
        let mut data = unsafe { data.assume_init() };
        for seed in 0..2048u32 {
            let Ok(hashx) = HashX::new(&seed.to_le_bytes()) else {
                continue;
            };
            let branch_cnt = hashx
                .program
                .iter()
                .filter(|x| matches!(x, Instruction::Branch { .. }))
                .count();
            assert_eq!(branch_cnt, 16, "branch count mismatch");
            count_seeds += 1;

            let sip_state = hashx.register_key;
            let sifter =
                CompiledSifter::new_ex(&mut map, &mut data, &hashx, TestMode::LessThan, true);

            let mut input_offset = 0;

            loop {
                let hit_mask = sifter.sift_ex(&mut input_offset, threshold, None);

                if hit_mask != 0 {
                    let offset = input_offset + hit_mask.trailing_zeros() as u64;
                    let mut reg_file = RegisterFile::new(hashx.register_key, offset);
                    hashx.program.interpret(&mut reg_file);
                    let got_digest = reg_file.digest(sip_state);
                    assert!(
                        got_digest[0] < threshold,
                        "reported offset {} is less than threshold, got digest: {:016x?} (threshold: {:016x})",
                        offset,
                        got_digest,
                        threshold
                    );
                    total_checked += offset;

                    break;
                }
            }
        }

        assert_ne!(count_seeds, 0, "no seeds checked");
        let expected_checked = expected_hashes * total_checked;
        // make a statistical test to make sure the approximate hash number is sane (no more than 150% of the expected value)
        assert!(
            count_seeds < expected_checked + expected_checked / 2,
            "count_seeds: {}, expected_checked: {}",
            count_seeds,
            expected_checked
        );
    }

    #[test]
    fn test_sift_mask() {
        let mask = 0b110101010111u64;
        let num_bits = mask.count_ones();
        let mut count_seeds = 0;
        let mut total_checked = 0;
        let mut map = ExecMap::new(CompiledSifter::WANTED_SIZE).unwrap();
        let mut data = Box::<DataBuffer>::new_uninit();
        unsafe {
            data.assume_init_mut().fill(0);
        }
        let mut data = unsafe { data.assume_init() };
        for seed in 0..2048u32 {
            let Ok(hashx) = HashX::new(&seed.to_le_bytes()) else {
                continue;
            };
            count_seeds += 1;

            let sip_state = hashx.register_key;
            let sifter = CompiledSifter::new_ex(&mut map, &mut data, &hashx, TestMode::Mask, true);

            let mut input_offset = 0;

            loop {
                let old_input_offset = input_offset;
                let hit_mask = sifter.sift_ex(&mut input_offset, mask, None);

                if hit_mask != 0 {
                    let offset = input_offset + hit_mask.trailing_zeros() as u64;
                    let mut reg_file = RegisterFile::new(hashx.register_key, offset);
                    hashx.program.interpret(&mut reg_file);
                    let got_digest = reg_file.digest(sip_state);
                    assert!(
                        got_digest[0] & mask == 0,
                        "reported offset {} is not masked, got digest: {:016x?} (mask: {:016x})",
                        offset,
                        got_digest,
                        mask
                    );

                    // if switchboard is all on, also validate the official crate returns the same digest
                    if BRANCH_EN
                        && OPCODE_ADDSHIFT_EN
                        && OPCODE_ROTATE_EN
                        && OPCODE_MUL_EN
                        && OPCODE_MULH_EN
                        && OPCODE_ADD_CONST_EN
                        && OPCODE_SUB_EN
                        && OPCODE_XOR_EN
                        && OPCODE_XOR_CONST_EN
                    {
                        let real_prog = ::hashx::HashX::new(&seed.to_le_bytes()).unwrap();
                        let real_prog_digest = real_prog.hash_to_u64(offset);
                        assert_eq!(real_prog_digest, got_digest[0], "digest mismatch");
                    }

                    total_checked += offset;

                    break;
                } else {
                    assert_eq!(
                        input_offset,
                        old_input_offset + CompiledSifter::HASHES_PER_CALL as u64
                    );
                }
            }
        }
        assert_ne!(count_seeds, 0, "no seeds checked");
        let expected_checked = (1 << num_bits) * total_checked;
        // make a statistical test to make sure the approximate hash number is sane (no more than 150% of the expected value)
        assert!(
            count_seeds < expected_checked + expected_checked / 2,
            "count_seeds: {}, expected_checked: {}",
            count_seeds,
            expected_checked
        );
    }
}
