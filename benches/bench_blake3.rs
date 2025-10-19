use std::num::NonZeroU8;
use std::time::Duration;

use criterion::Throughput;
use criterion::{Criterion, criterion_group, criterion_main};
use pow_buster::message::CerberusMessage;
use pow_buster::solver::Solver;
use pow_buster::{CerberusSolver, compute_mask_cerberus};

#[allow(unused)]
mod cerberus_verbatim {
    pub fn check_leading_zero_dubits(n: usize) -> fn(&[u8; 32], usize) -> bool {
        match n {
            0..=16 => check_small,
            _ => check_general,
        }
    }

    fn check_small(hash: &[u8; 32], n: usize) -> bool {
        let first_word: u32 = (hash[0] as u32) << 24
            | (hash[1] as u32) << 16
            | (hash[2] as u32) << 8
            | (hash[3] as u32);
        first_word.leading_zeros() >= (n as u32 * 2)
    }

    fn check_general(hash: &[u8; 32], n: usize) -> bool {
        panic!("I'm lazy")
    }

    pub fn process_task(data: &[u8], difficulty: u32, thread_id: u32, threads: u32) -> u32 {
        use std::io::Write;
        let dubit_checker: fn(&[u8; 32], usize) -> bool =
            check_leading_zero_dubits(difficulty as usize);
        let mut hasher = blake3::Hasher::new();

        for i in (thread_id..).step_by(threads as usize) {
            hasher.reset();

            let mut attempt = data.to_vec();
            write!(&mut attempt, "{}", i).unwrap();

            hasher.update(attempt.as_slice());
            let hash = hasher.finalize();

            if dubit_checker(hash.as_bytes(), difficulty as usize) {
                return i;
            }
        }

        unreachable!()
    }
}

pub fn bench_blake3_cerberus(c: &mut Criterion) {
    const SAMPLE_SALT: [u8; 216] = *b"849c253990ebc3dc23e265f52692d5a53b89e72b76527a3e35a41c6bedad5867|3959614364|1759954402|803eb7fa618142da5c8ab89cc1109775f6c37d25520deae1e3bd2b1803aa9a8e15b2aae8a9ad2cc4f58f4c9ff2cf4999f2bef0ff5e389b15895d0cc2200d4a03|";

    let mut group = c.benchmark_group("blake3_cerberus");
    group.sample_size(200);
    group.warm_up_time(Duration::from_secs(8));
    group.measurement_time(Duration::from_secs(15));

    let difficulty = compute_mask_cerberus(NonZeroU8::new(10).unwrap());
    group.throughput(Throughput::Elements(1 << (10 * 2)));

    let mut ctr = 0u64;
    group.bench_function("blake3_cerberus", |b| {
        let mut salt = SAMPLE_SALT;
        b.iter(|| {
            salt[..8].copy_from_slice(&ctr.to_le_bytes());
            let mut solver = CerberusSolver::from(CerberusMessage::new(&salt, 0).unwrap());
            ctr += 1;
            solver.solve::<{ pow_buster::solver::SOLVE_TYPE_MASK }>(0, difficulty as u64)
        });
    });

    group.sample_size(100);

    group.bench_function("cerberus_verbatim", |b| {
        let mut salt = SAMPLE_SALT;
        b.iter(|| {
            salt[..8].copy_from_slice(&ctr.to_le_bytes());
            ctr += 1;
            cerberus_verbatim::process_task(salt.as_slice(), 10, 0, 1)
        });
    });
}

pub fn bench_blake3_cerberus_multi_threaded(c: &mut Criterion) {
    const SAMPLE_SALT: [u8; 216] = *b"849c253990ebc3dc23e265f52692d5a53b89e72b76527a3e35a41c6bedad5867|3959614364|1759954402|803eb7fa618142da5c8ab89cc1109775f6c37d25520deae1e3bd2b1803aa9a8e15b2aae8a9ad2cc4f58f4c9ff2cf4999f2bef0ff5e389b15895d0cc2200d4a03|";

    let mut group = c.benchmark_group("blake3_cerberus_multi_threaded");
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(8));
    group.measurement_time(Duration::from_secs(60));

    let mask = compute_mask_cerberus(NonZeroU8::new(10).unwrap());

    let num_threads = num_cpus::get();

    let work_count = num_threads * 16;
    group.throughput(Throughput::Elements(work_count as u64 * (1 << (10 * 2))));

    eprintln!("spawning {} threads", num_threads);

    group.bench_function("blake3_cerberus_multi_threaded", |b| {
        b.iter_custom(|iters| {
            let work_ctr = std::sync::atomic::AtomicUsize::new(0);
            let barrier = std::sync::Barrier::new(num_threads + 1);
            std::thread::scope(|s| {
                let work_ctr = &work_ctr;
                let barrier = &barrier;

                for _ in 0..num_threads {
                    s.spawn(move || {
                        let mut salt = SAMPLE_SALT;

                        barrier.wait();

                        loop {
                            let this_work =
                                work_ctr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if this_work >= work_count * iters as usize {
                                break;
                            }
                            salt[..8].copy_from_slice(&(this_work as u64).to_le_bytes());
                            let mut solver =
                                CerberusSolver::from(CerberusMessage::new(&salt, 0).unwrap());
                            core::hint::black_box(
                                solver.solve::<{ pow_buster::solver::SOLVE_TYPE_MASK }>(
                                    0,
                                    mask as u64,
                                ),
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

criterion_group!(
    benches,
    bench_blake3_cerberus,
    bench_blake3_cerberus_multi_threaded
);
criterion_main!(benches);
