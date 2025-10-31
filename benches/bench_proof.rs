use std::time::Duration;

use criterion::{BenchmarkId, Throughput};
use criterion::{Criterion, criterion_group, criterion_main};

use pow_buster::BinarySolver;
use pow_buster::message::BinaryMessage;
use pow_buster::{
    DoubleBlockSolver, SingleBlockSolver, compute_target_mcaptcha,
    message::{DoubleBlockMessage, SingleBlockMessage},
    solver::Solver,
};
use sha2::Digest;
use sha2::digest::generic_array::sequence::GenericSequence;

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
            let hasher_base = sha2::Sha256::new();
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
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(8));
    group.measurement_time(Duration::from_secs(30));
    for difficulty in [50_000, 100_000, 1_000_000, 4_000_000, 10_000_000] {
        group.throughput(Throughput::Elements(difficulty as u64));
        let target = compute_target_mcaptcha(difficulty as u64);
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
                static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

                b.iter_custom(|iters| {
                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        for _ in 0..10 {
                            let counter =
                                COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let mut prefix = [0; 64];
                            prefix[..8].copy_from_slice(&counter.to_ne_bytes());
                            let mut solver: SingleBlockSolver = SingleBlockSolver::from(
                                SingleBlockMessage::new(&prefix, 0).expect("solver is None"),
                            );
                            core::hint::black_box(
                                solver
                                    .solve::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                                    .expect("solver failed"),
                            );
                        }
                    }
                    start.elapsed() / 10
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new(
                "proof (capjs)",
                ProofKey {
                    difficulty,
                    solver_type: "native",
                },
            ),
            &difficulty,
            |b, &_difficulty| {
                static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

                b.iter_custom(|iters| {
                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        for _ in 0..10 {
                            let counter =
                                COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let mut prefix = [0; 32]; // CapJS has a 32-byte prefix
                            prefix[..8].copy_from_slice(&counter.to_ne_bytes());
                            let mut solver: SingleBlockSolver = SingleBlockSolver::from(
                                SingleBlockMessage::new(&prefix, 0).expect("solver is None"),
                            );
                            core::hint::black_box(
                                solver
                                    .solve::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                                    .expect("solver failed"),
                            );
                        }
                    }
                    start.elapsed() / 10
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new(
                "proof (double block)",
                ProofKey {
                    difficulty,
                    solver_type: "native",
                },
            ),
            &difficulty,
            |b, &_difficulty| {
                b.iter_custom(|iters| {
                    let start = std::time::Instant::now();
                    let mut prefix: [u8; 48] = [0; 48];
                    static COUNTER: std::sync::atomic::AtomicU64 =
                        std::sync::atomic::AtomicU64::new(0);
                    for _ in 0..iters {
                        for _ in 0..10 {
                            prefix[..8].copy_from_slice(
                                &COUNTER
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                                    .to_ne_bytes(),
                            );
                            let mut solver = DoubleBlockSolver::from(
                                DoubleBlockMessage::new(&prefix, 0).expect("solver is None"),
                            );
                            core::hint::black_box(
                                solver
                                    .solve::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                                    .expect("solver failed"),
                            );
                        }
                    }
                    start.elapsed() / 10
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new(
                "proof (binary u32)",
                ProofKey {
                    difficulty,
                    solver_type: "native",
                },
            ),
            &difficulty,
            |b, &_difficulty| {
                b.iter_custom(|iters| {
                    let start = std::time::Instant::now();
                    let mut prefix: [u8; 64] = [0; 64];
                    static COUNTER: std::sync::atomic::AtomicU64 =
                        std::sync::atomic::AtomicU64::new(0);
                    for _ in 0..iters {
                        for _ in 0..10 {
                            prefix[..8].copy_from_slice(
                                &COUNTER
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                                    .to_ne_bytes(),
                            );
                            let mut solver = BinarySolver::from(BinaryMessage::new(
                                &prefix,
                                4.try_into().unwrap(),
                            ));
                            core::hint::black_box(
                                solver
                                    .solve::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                                    .expect("solver failed"),
                            );
                        }
                    }
                    start.elapsed() / 10
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new(
                "proof",
                ProofKey {
                    difficulty,
                    solver_type: "safe (sha2)",
                },
            ),
            &difficulty,
            |b, &_difficulty| {
                static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

                b.iter_custom(|iters| {
                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        for _ in 0..10 {
                            let mut solver = pow_buster::solver::safe::SingleBlockSolver::from(
                                SingleBlockMessage::new(
                                    &COUNTER
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                                        .to_ne_bytes(),
                                    0,
                                )
                                .expect("solver is None"),
                            );
                            core::hint::black_box(
                                solver
                                    .solve::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                                    .expect("solver failed"),
                            );
                        }
                    }
                    start.elapsed() / 10
                })
            },
        );
    }
}

pub fn bench_proof_multi_threaded(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_multi_threaded_hashrate");
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(8));
    group.measurement_time(Duration::from_secs(15));

    let target = compute_target_mcaptcha(2_000_000);
    let num_threads = num_cpus::get();
    let work_count = num_threads * 32;
    group.throughput(Throughput::Elements(work_count as u64 * 2_000_000));

    eprintln!("spawning {} threads", num_threads);

    group.bench_function("proof_multi_threaded", |b| {
        b.iter_custom(|iters| {
            let work_ctr = std::sync::atomic::AtomicUsize::new(0);
            let barrier = std::sync::Barrier::new(num_threads + 1);
            std::thread::scope(|s| {
                let work_ctr = &work_ctr;
                let barrier = &barrier;

                for _ in 0..num_threads {
                    s.spawn(move || {
                        barrier.wait();

                        loop {
                            let this_work =
                                work_ctr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if this_work >= work_count * iters as usize {
                                break;
                            }
                            let mut prefix = [0; 64];
                            prefix[..8].copy_from_slice(&this_work.to_le_bytes());
                            let mut solver = SingleBlockSolver::from(
                                SingleBlockMessage::new(&prefix, 0).expect("solver is None"),
                            );
                            core::hint::black_box(
                                solver
                                    .solve::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                                    .expect("solver failed"),
                            );
                        }

                        barrier.wait();
                    });
                }

                barrier.wait();
                let begin = std::time::Instant::now();
                barrier.wait();
                begin.elapsed()
            })
        });
    });

    group.bench_function("proof_multi_threaded (double block)", |b| {
        b.iter_custom(|iters| {
            let work_ctr = std::sync::atomic::AtomicUsize::new(0);
            let barrier = std::sync::Barrier::new(num_threads + 1);
            std::thread::scope(|s| {
                let work_ctr = &work_ctr;
                let barrier = &barrier;

                for _ in 0..num_threads {
                    s.spawn(move || {
                        barrier.wait();

                        loop {
                            let this_work =
                                work_ctr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if this_work >= work_count * iters as usize {
                                break;
                            }
                            let mut prefix: [u8; 48] = [0; 48];
                            prefix[..8].copy_from_slice(&this_work.to_le_bytes());
                            let mut solver = DoubleBlockSolver::from(
                                DoubleBlockMessage::new(&prefix, 0).expect("solver is None"),
                            );
                            core::hint::black_box(
                                solver
                                    .solve::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                                    .expect("solver failed"),
                            );
                        }

                        barrier.wait();
                    });
                }

                barrier.wait();
                let begin = std::time::Instant::now();
                barrier.wait();
                begin.elapsed()
            })
        });
    });

    group.bench_function("proof_multi_threaded (go away)", |b| {
        b.iter_custom(|iters| {
            let work_ctr = std::sync::atomic::AtomicUsize::new(0);
            let barrier = std::sync::Barrier::new(num_threads + 1);
            std::thread::scope(|s| {
                let work_ctr = &work_ctr;
                let barrier = &barrier;

                for _ in 0..num_threads {
                    s.spawn(move || {
                        use pow_buster::{GoAwaySolver, message::GoAwayMessage};

                        barrier.wait();

                        loop {
                            let this_work =
                                work_ctr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if this_work >= work_count * iters as usize {
                                break;
                            }
                            let mut prefix = [0; 32];
                            prefix[..8].copy_from_slice(&this_work.to_le_bytes());
                            let mut solver = GoAwaySolver::from(GoAwayMessage::new_bytes(&prefix));
                            core::hint::black_box(
                                solver
                                    .solve::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                                    .expect("solver failed"),
                            );
                        }

                        barrier.wait();
                    });
                }

                barrier.wait();
                let begin = std::time::Instant::now();
                barrier.wait();
                begin.elapsed()
            })
        });
    });
}

mod capjs_verbatim {
    // license: Apache-2.0
    // author: Tiago
    // source: https://github.com/tiagozip/cap/blob/main/wasm/src/rust/src/lib.rs
    use sha2::{Digest, Sha256};

    pub fn solve_pow(salt: String, target: String) -> u64 {
        let salt_bytes = salt.as_bytes();

        let target_bytes = parse_hex_target(&target);
        let target_bits = target.len() * 4; // each hex char = 4 bits

        let mut nonce_buffer = [0u8; 20]; // u64::MAX has at most 20 digits

        for nonce in 0..u64::MAX {
            let nonce_len = write_u64_to_buffer(nonce, &mut nonce_buffer);
            let nonce_bytes = &nonce_buffer[..nonce_len];

            let mut hasher = Sha256::new();
            hasher.update(salt_bytes);
            hasher.update(nonce_bytes);
            let hash_result = hasher.finalize();

            if hash_matches_target(&hash_result, &target_bytes, target_bits) {
                return nonce;
            }
        }

        unreachable!("Solution should be found before exhausting u64::MAX");
    }

    fn parse_hex_target(target: &str) -> Vec<u8> {
        let mut padded_target = target.to_string();

        if padded_target.len() % 2 != 0 {
            padded_target.push('0');
        }

        (0..padded_target.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&padded_target[i..i + 2], 16).unwrap())
            .collect()
    }

    fn write_u64_to_buffer(mut value: u64, buffer: &mut [u8]) -> usize {
        if value == 0 {
            buffer[0] = b'0';
            return 1;
        }

        let mut len = 0;
        let mut temp = value;

        while temp > 0 {
            len += 1;
            temp /= 10;
        }

        for i in (0..len).rev() {
            buffer[i] = (value % 10) as u8 + b'0';
            value /= 10;
        }

        len
    }

    fn hash_matches_target(hash: &[u8], target_bytes: &[u8], target_bits: usize) -> bool {
        let full_bytes = target_bits / 8;
        let remaining_bits = target_bits % 8;

        if hash[..full_bytes] != target_bytes[..full_bytes] {
            return false;
        }

        if remaining_bits > 0 && full_bytes < target_bytes.len() {
            let mask = 0xFF << (8 - remaining_bits);
            let hash_masked = hash[full_bytes] & mask;
            let target_masked = target_bytes[full_bytes] & mask;
            return hash_masked == target_masked;
        }

        true
    }
}

pub fn bench_capjs_verbatim(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_capjs_verbatim");
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(8));
    group.measurement_time(Duration::from_secs(15));
    group.throughput(Throughput::Elements(16u64.pow(5)));

    let mut salt = 0u32;

    group.bench_function("capjs_verbatim", |b| {
        b.iter(|| {
            capjs_verbatim::solve_pow(salt.to_string(), String::from("01234"));
            salt += 1;
        })
    });
}

criterion_group!(
    benches,
    bench_proof,
    bench_sha2_crate_single,
    bench_sha2_crate_bulk,
    bench_capjs_verbatim,
    bench_proof_multi_threaded,
);

criterion_main!(benches);
