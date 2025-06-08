use std::time::Duration;

use criterion::{BenchmarkId, Throughput};
use criterion::{Criterion, criterion_group, criterion_main};

use simd_mcaptcha_solver::{SingleBlockSolver, Solver, compute_target};

struct ProofKey {
    difficulty: u32,
    solver_type: &'static str,
}

impl std::fmt::Display for ProofKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.solver_type, self.difficulty)
    }
}

pub fn bench_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_proof");
    group.sample_size(250);
    group.warm_up_time(Duration::from_secs(8));
    group.measurement_time(Duration::from_secs(15));
    group.throughput(Throughput::Elements(1));
    for difficulty in [
        50_000, 100_000, 1_000_000, 4_000_000, 10_000_000, 50_000_000,
    ] {
        let target = compute_target(difficulty);
        let target_bytes = target.to_be_bytes();
        let target_u32s = core::array::from_fn(|i| {
            u32::from_be_bytes([
                target_bytes[i * 4],
                target_bytes[i * 4 + 1],
                target_bytes[i * 4 + 2],
                target_bytes[i * 4 + 3],
            ])
        });
        let mut counter = 0u64;
        group.bench_with_input(
            BenchmarkId::new(
                "proof",
                ProofKey {
                    difficulty,
                    solver_type: "native",
                },
            ),
            &difficulty,
            |b, &_difficulty| {
                counter += 1;
                let mut solver =
                    SingleBlockSolver::new((), &counter.to_ne_bytes()).expect("solver is None");

                b.iter(|| solver.solve(target_u32s).expect("solver failed"))
            },
        );
        counter = 0;
        group.bench_with_input(
            BenchmarkId::new(
                "proof",
                ProofKey {
                    difficulty,
                    solver_type: "official",
                },
            ),
            &difficulty,
            |b, &_difficulty| {
                counter += 1;
                let solver = pow_sha256::ConfigBuilder::default()
                    .salt(counter.to_string())
                    .build()
                    .unwrap();

                b.iter(|| {
                    let pow = solver.prove_work(&"x", difficulty).unwrap();
                    (pow.nonce, pow.result)
                })
            },
        );
        #[cfg(feature = "wgpu")]
        {
            use simd_mcaptcha_solver::wgpu::VulkanDeviceContext;
            counter = 0;

            let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
                backends: wgpu::Backends::VULKAN,
                ..Default::default()
            });
            let adapter =
                pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
                    power_preference: wgpu::PowerPreference::HighPerformance,
                    compatible_surface: None,
                    force_fallback_adapter: false,
                }))
                .unwrap();
            let mut features = wgpu::Features::empty();
            features.insert(wgpu::Features::MAPPABLE_PRIMARY_BUFFERS);
            let (device, queue) =
                pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
                    label: None,
                    required_features: features,
                    required_limits: wgpu::Limits::default(),
                    memory_hints: wgpu::MemoryHints::Performance,
                    trace: wgpu::Trace::Off,
                }))
                .unwrap();

            group.bench_with_input(
                BenchmarkId::new(
                    "proof",
                    ProofKey {
                        difficulty,
                        solver_type: "wgpu",
                    },
                ),
                &difficulty,
                |b, &_difficulty| {
                    use generic_array::typenum::U256;
                    use simd_mcaptcha_solver::wgpu::VulkanSingleBlockSolver;
                    b.iter_custom(|iters| {
                        let mut ctx = VulkanDeviceContext::new(device.clone(), queue.clone());

                        let start = std::time::Instant::now();
                        for _ in 0..iters {
                            counter += 1;
                            let mut solver = VulkanSingleBlockSolver::<U256>::new(
                                &mut ctx,
                                &counter.to_ne_bytes(),
                            )
                            .unwrap();
                            core::hint::black_box(
                                solver.solve(target_u32s).expect("solver failed"),
                            );
                        }
                        start.elapsed()
                    })
                },
            );
        }
    }
}

criterion_group!(benches, bench_proof);
criterion_main!(benches);
