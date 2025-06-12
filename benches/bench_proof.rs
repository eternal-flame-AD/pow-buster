#![feature(random)]

use std::time::Duration;

use criterion::{BenchmarkId, Throughput};
use criterion::{Criterion, criterion_group, criterion_main};

use sha2::Digest;
use sha2::digest::generic_array::sequence::GenericSequence;
use simd_mcaptcha::{Sha2CrateSolver, SingleBlockSolver, Solver, compute_target};

struct ProofKey {
    difficulty: u32,
    solver_type: &'static str,
}

impl std::fmt::Display for ProofKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.solver_type, self.difficulty)
    }
}

pub fn bench_sha2_crate_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_sha2_crate_single");
    group.sample_size(250);
    group.warm_up_time(Duration::from_secs(8));
    group.measurement_time(Duration::from_secs(15));
    group.throughput(Throughput::Bytes(64));

    let prefix = b"0123456789abcdef";

    group.bench_function("sha2_crate_sequential", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            let mut hasher = sha2::Sha256::new();
            hasher.update(prefix);
            for i in 0..iters {
                let mut tmp = [0u8; 64];
                tmp[..8].copy_from_slice(&i.to_ne_bytes());
                hasher.update(&tmp);
            }
            core::hint::black_box(hasher.finalize());
            start.elapsed()
        })
    });

    group.bench_function("sha2_crate_reset_after_each", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            let mut hasher = sha2::Sha256::new();
            for i in 0..iters {
                let mut tmp = [0u8; 64 - 9]; // subtract off the padding
                tmp[..8].copy_from_slice(&i.to_ne_bytes());
                core::hint::black_box(hasher.finalize_reset());
            }
            core::hint::black_box(hasher.finalize());
            start.elapsed()
        })
    });

    group.bench_function("sha2_crate_reset_after_each_with_prefix", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            let mut hasher_base = sha2::Sha256::new();
            hasher_base.update(u64::to_ne_bytes(std::random::random()));
            for i in 0..iters {
                let mut hasher = hasher_base.clone();
                hasher.update(&i.to_ne_bytes());
                core::hint::black_box(hasher.finalize());
            }
            start.elapsed()
        })
    });

    group.bench_function("sha2_crate_reset_after_each_with_prefix_manual", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            let mut state_base = [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ];
            sha2::compress256(
                &mut state_base,
                &[sha2::digest::generic_array::GenericArray::generate(|i| {
                    i as u8
                })],
            );
            let mut tmp = sha2::digest::generic_array::GenericArray::default();
            for i in 0..iters {
                let mut state = state_base.clone();
                tmp[..8].copy_from_slice(&i.to_ne_bytes());
                sha2::compress256(&mut state, &[tmp]);
                core::hint::black_box(state);
            }
            start.elapsed()
        })
    });
}

pub fn bench_sha2_crate_bulk(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_sha2_crate_bulk");
    group.sample_size(100);
    group.warm_up_time(Duration::from_secs(5));
    group.measurement_time(Duration::from_secs(10));

    const BUFFER_SIZE: usize = 1_048_576;
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    // Create a large buffer of data to hash
    let mut data = vec![0u8; BUFFER_SIZE];

    data.iter_mut().enumerate().for_each(|(i, b)| {
        *b = i as u8;
    });

    group.bench_function("sha2_crate_bulk_1MB", |b| {
        b.iter(|| {
            // The entire hash operation is timed
            let mut hasher = sha2::Sha256::new();
            hasher.update(&data);
            core::hint::black_box(hasher.finalize());
        })
    });
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
                    solver_type: "native (sha2)",
                },
            ),
            &difficulty,
            |b, &_difficulty| {
                counter += 1;
                let mut solver =
                    Sha2CrateSolver::new((), &counter.to_ne_bytes()).expect("solver is None");

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
            use simd_mcaptcha::wgpu::VulkanDeviceContext;
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
                    use simd_mcaptcha::wgpu::VulkanSingleBlockSolver;
                    use typenum::U256;
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

#[cfg(feature = "rayon")]
pub fn bench_proof_rayon(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_rayon_hashrate");
    group.sample_size(100);
    group.warm_up_time(Duration::from_secs(8));
    group.measurement_time(Duration::from_secs(15));
    group.throughput(Throughput::Elements(1024 * 5_000_000));

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

    group.bench_function("proof_rayon", |b| {
        let mut counter = 0u64;
        b.iter_batched(
            || {
                counter += 1;
                counter * 1024
            },
            |start| {
                use rayon::iter::{IntoParallelIterator, ParallelIterator};

                (0..1024)
                    .into_par_iter()
                    .map(|addend| {
                        let mut solver =
                            SingleBlockSolver::new((), &(addend + start).to_ne_bytes())
                                .expect("solver is None");

                        let start = std::time::Instant::now();
                        solver.solve(target_u32s).expect("solver failed");
                        start.elapsed()
                    })
                    .sum::<Duration>()
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_proof,
    bench_sha2_crate_single,
    bench_sha2_crate_bulk,
);
#[cfg(feature = "rayon")]
criterion_group!(benches_rayon, bench_proof_rayon);

#[cfg(not(feature = "rayon"))]
criterion_main!(benches);

#[cfg(feature = "rayon")]
criterion_main!(benches, benches_rayon);
