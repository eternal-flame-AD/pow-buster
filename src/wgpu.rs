use typenum::{B1, IsGreater, U0, U256, Unsigned};
use wgpu::util::{BufferInitDescriptor, DeviceExt};

use crate::{SWAP_DWORD_BYTE_ORDER, SingleBlockSolver16Way, decompose_blocks_mut};

const GEOM_QUANTILE_50: f32 = 0.6931471805599453;

#[cfg(debug_assertions)]
macro_rules! some_dbg {
    ($v:expr) => {
        Some($v)
    };
}

#[cfg(not(debug_assertions))]
macro_rules! some_dbg {
    ($v:expr) => {
        None
    };
}

pub struct VulkanDeviceContext {
    device: wgpu::Device,
    queue: wgpu::Queue,

    solution_clear_buffer: wgpu::Buffer,
    solution_buffer: wgpu::Buffer,
    solution_download_buffer: wgpu::Buffer,
    message_template_buffer: wgpu::Buffer,
    saved_state_buffer: wgpu::Buffer,
    bind_group: wgpu::BindGroup,
    pipeline: wgpu::ComputePipeline,
}

impl VulkanDeviceContext {
    pub fn new(device: wgpu::Device, queue: wgpu::Queue) -> Self {
        #[cfg(debug_assertions)]
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("SHA-256 Compressor"),
            source: wgpu::ShaderSource::Wgsl(include_str!("sha256.wgsl").into()),
        });

        #[cfg(not(debug_assertions))]
        let shader = unsafe {
            device.create_shader_module_trusted(
                wgpu::ShaderModuleDescriptor {
                    label: some_dbg!("SHA-256 Compressor"),
                    source: wgpu::ShaderSource::Wgsl(include_str!("sha256.wgsl").into()),
                },
                wgpu::ShaderRuntimeChecks {
                    bounds_checks: false,
                    force_loop_bounding: false,
                },
            )
        };

        let solution_clear_buffer = device.create_buffer_init(&BufferInitDescriptor {
            label: some_dbg!("Solution Clear Buffer"),
            contents: &[!0; 4],
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        });

        let solution_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: some_dbg!("Solution Buffer"),
            size: 4,
            usage: wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let solution_download_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: some_dbg!("Solution Download Buffer"),
            size: 4,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });

        let message_template_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: some_dbg!("Message Template Buffer"),
            size: 64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::MAP_WRITE,
            mapped_at_creation: false,
        });

        let saved_state_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: some_dbg!("Saved State Buffer"),
            size: 4 * 12,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::MAP_WRITE,
            mapped_at_creation: false,
        });

        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: None,
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Bind Group"),
            layout: &layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: solution_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: message_template_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: saved_state_buffer.as_entire_binding(),
                },
            ],
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: some_dbg!("SHA-256 Compressor Pipeline"),
            layout: Some(
                &device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
                    label: None,
                    bind_group_layouts: &[&layout],
                    push_constant_ranges: &[],
                }),
            ),
            module: &shader,
            entry_point: Some("findNonce"),
            cache: None,
            compilation_options: wgpu::PipelineCompilationOptions {
                constants: &[],
                zero_initialize_workgroup_memory: false,
            },
        });

        Self {
            device,
            queue,
            solution_clear_buffer,
            solution_buffer,
            solution_download_buffer,
            message_template_buffer,
            saved_state_buffer,
            bind_group,
            pipeline,
        }
    }
}

pub struct VulkanSingleBlockSolver<'a, WorkGroupSize: Unsigned + IsGreater<U0, Output = B1> = U256>
{
    ctx: &'a mut VulkanDeviceContext,
    message: [u32; 16],
    saved_state: [u32; 12],

    digit_index: usize,
    nonce_addend: u64,

    _marker: std::marker::PhantomData<WorkGroupSize>,
}

impl<'a, WorkGroupSize: Unsigned + IsGreater<U0, Output = B1>>
    VulkanSingleBlockSolver<'a, WorkGroupSize>
{
    const SAVED_STATE_NONCE_OFFSET_IDX: usize = 8;
    const SAVED_STATE_TARGET_MSB_IDX: usize = 9;
    const SAVED_STATE_TARGET_NUMBER_BYTE_IDX: usize = 10;
    const SAVED_STATE_TESTS_PER_THREAD_IDX: usize = 11;
}

impl<'a, WorkGroupSize: Unsigned + IsGreater<U0, Output = B1>> crate::Solver
    for VulkanSingleBlockSolver<'a, WorkGroupSize>
{
    type Ctx = &'a mut VulkanDeviceContext;

    fn new(ctx: Self::Ctx, prefix: &[u8]) -> Option<Self> {
        let tmp_solver = SingleBlockSolver16Way::new((), prefix)?;

        let mut saved_state = [0; 12];
        saved_state[Self::SAVED_STATE_TARGET_NUMBER_BYTE_IDX] = tmp_solver.digit_index as u32;
        saved_state[0..8].copy_from_slice(&tmp_solver.prefix_state);

        ctx.message_template_buffer
            .map_async(wgpu::MapMode::Write, 0..64, |_| {});

        ctx.device
            .poll(wgpu::PollType::Poll)
            .expect("failed to wait for device");
        unsafe {
            ctx.message_template_buffer
                .get_mapped_range_mut(0..64)
                .copy_from_slice(core::slice::from_raw_parts(
                    crate::decompose_blocks(&tmp_solver.message).as_ptr(),
                    64,
                ));
        }
        ctx.message_template_buffer.unmap();

        Some(Self {
            ctx,
            message: tmp_solver.message,
            digit_index: tmp_solver.digit_index,
            nonce_addend: tmp_solver.nonce_addend,
            saved_state,
            _marker: std::marker::PhantomData,
        })
    }

    fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
        assert!(
            UPWARDS,
            "wgpu solver currently only supports upwards comparisons"
        );

        self.saved_state[Self::SAVED_STATE_TARGET_MSB_IDX] = target[0];

        let effective_difficulty = u32::MAX.div_ceil(u32::MAX - target[0]);
        let tests_per_thread_float =
            ((effective_difficulty / 256 / WorkGroupSize::U32) as f32 * GEOM_QUANTILE_50).ceil();
        let tests_per_thread = (tests_per_thread_float.ceil() as u32).max(2).min(8192);

        self.saved_state[Self::SAVED_STATE_TESTS_PER_THREAD_IDX] = tests_per_thread;

        let per_iter_solution_space = (256 * WorkGroupSize::U32 * tests_per_thread) as u32;

        let mut search_begin = 100_000_000u32;
        let mut search_end = search_begin + per_iter_solution_space;
        loop {
            self.saved_state[Self::SAVED_STATE_NONCE_OFFSET_IDX] = search_begin;

            self.ctx.saved_state_buffer.map_async(
                wgpu::MapMode::Write,
                0..core::mem::size_of_val(&self.saved_state) as u64,
                |_| {},
            );

            self.ctx
                .device
                .poll(wgpu::PollType::Poll)
                .expect("failed to wait for device");

            unsafe {
                self.ctx
                    .saved_state_buffer
                    .get_mapped_range_mut(0..(core::mem::size_of_val(&self.saved_state) as u64))
                    .copy_from_slice(core::slice::from_raw_parts(
                        self.saved_state.as_ptr().cast(),
                        core::mem::size_of_val(&self.saved_state),
                    ));
            }

            self.ctx.saved_state_buffer.unmap();

            let mut encoder =
                self.ctx
                    .device
                    .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                        label: Some("SHA-256 Compressor Encoder"),
                    });

            encoder.copy_buffer_to_buffer(
                &self.ctx.solution_clear_buffer,
                0,
                &self.ctx.solution_buffer,
                0,
                4,
            );

            {
                let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                    label: None,
                    timestamp_writes: None,
                });

                pass.set_pipeline(&self.ctx.pipeline);
                pass.set_bind_group(0, &self.ctx.bind_group, &[]);
                pass.dispatch_workgroups(WorkGroupSize::U32, 1, 1);
            }
            encoder.copy_buffer_to_buffer(
                &self.ctx.solution_buffer,
                0,
                &self.ctx.solution_download_buffer,
                0,
                4,
            );

            let cmd = encoder.finish();
            let wait = self.ctx.queue.submit([cmd]);

            self.ctx
                .solution_download_buffer
                .map_async(wgpu::MapMode::Read, 0..4, |_| {});

            self.ctx
                .device
                .poll(wgpu::PollType::WaitForSubmissionIndex(wait))
                .expect("failed to poll device");

            let solution_nonce = {
                let data = self.ctx.solution_download_buffer.get_mapped_range(0..4);
                u32::from_le_bytes([data[0], data[1], data[2], data[3]])
            };

            self.ctx.solution_download_buffer.unmap();

            if solution_nonce != !0 {
                // reconstruct the final message
                let mut tmp = solution_nonce;
                for i in (0..9).rev() {
                    let digit = tmp % 10;
                    tmp /= 10;
                    decompose_blocks_mut(&mut self.message)
                        [SWAP_DWORD_BYTE_ORDER[self.digit_index + i]] = digit as u8 + b'0';
                }

                // get the result in CPU
                crate::sha256::digest_block(
                    (&mut self.saved_state[0..8]).try_into().unwrap(),
                    &self.message,
                );

                return Some((
                    (solution_nonce as u64) + self.nonce_addend,
                    self.saved_state[0..8].try_into().unwrap(),
                ));
            }

            search_begin = search_end;
            search_end = search_begin.checked_add(per_iter_solution_space)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Solver, compute_target};

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn test_solve_wgpu() {
        use typenum::U1024;
        const SALT: &str = "x";

        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: wgpu::Backends::VULKAN,
            ..Default::default()
        });
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await
            .unwrap();
        let mut features = wgpu::Features::empty();
        features.insert(wgpu::Features::MAPPABLE_PRIMARY_BUFFERS);
        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: None,
                required_features: features,
                required_limits: wgpu::Limits::default(),
                memory_hints: wgpu::MemoryHints::Performance,
                trace: wgpu::Trace::Off,
            })
            .await
            .unwrap();

        let mut ctx = VulkanDeviceContext::new(device, queue);

        let mut cannot_solve = 0;
        for phrase_len in 0..64 {
            eprintln!("phrase_len: {}", phrase_len);
            let mut concatenated_prefix = SALT.as_bytes().to_vec();
            let phrase_str = String::from_iter(std::iter::repeat('a').take(phrase_len));
            concatenated_prefix.extend_from_slice(&bincode::serialize(&phrase_str).unwrap());

            let config = pow_sha256::ConfigBuilder::default()
                .salt(SALT.to_string())
                .build()
                .unwrap();

            let Some(mut solver) =
                VulkanSingleBlockSolver::<U1024>::new(&mut ctx, &concatenated_prefix)
            else {
                cannot_solve += 1;
                continue;
            };
            let target = compute_target(5_000_000);
            let target_bytes = target.to_be_bytes();
            let target_u32s = core::array::from_fn(|i| {
                u32::from_be_bytes([
                    target_bytes[i * 4],
                    target_bytes[i * 4 + 1],
                    target_bytes[i * 4 + 2],
                    target_bytes[i * 4 + 3],
                ])
            });
            eprintln!("target: {:08x?}", target_u32s);
            let result = solver.solve::<true>(target_u32s).unwrap();
            eprintln!("result: {:?}", result);

            let test_response = pow_sha256::PoWBuilder::default()
                .nonce(result.0)
                .result(crate::extract128_be(result.1).to_string())
                .build()
                .unwrap();

            let expected_result = config.calculate(&test_response, &phrase_str).unwrap();
            assert_eq!(expected_result, crate::extract128_be(result.1));
            assert!(config.is_valid_proof(&test_response, &phrase_str));
        }

        println!(
            "cannot_solve: {} out of 64 lengths (success rate: {:.2}%)",
            cannot_solve,
            (64 - cannot_solve) as f64 / 64.0 * 100.0
        );
    }
}
