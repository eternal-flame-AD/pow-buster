use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

#[cold]
// break any code movement
fn brk() {}

fn bench_hashx(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_hashx");
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(8));
    group.measurement_time(Duration::from_secs(15));

    const N_BITS: u32 = 19;
    const THRESHOLD: u64 = (1 << N_BITS) - 1;

    group.throughput(Throughput::Elements(1 << N_BITS));

    let mut seed = 0u64;

    #[cfg(feature = "jit-infra")]
    group.bench_function("hashx_avx512dq_jit", |b| {
        use pow_buster::{
            hashx::{
                TestMode,
                hashx_avx512dq::{CompiledSifter, DataBuffer},
                hashx_vendor::HashX,
            },
            jit::exec_map::ExecMap,
        };

        let mut map = ExecMap::new(CompiledSifter::WANTED_SIZE).unwrap();
        let mut data = Box::<DataBuffer>::new_uninit();
        unsafe {
            data.assume_init_mut().fill(0);
        }
        let mut data = unsafe { data.assume_init() };
        b.iter(|| {
            loop {
                seed += 1;
                let Ok(prog) = HashX::new(&seed.to_le_bytes()) else {
                    continue;
                };
                let compiled =
                    CompiledSifter::new_ex(&mut map, &mut data, &prog, TestMode::Mask, false);

                let mut input_offset = 0;

                loop {
                    let hit_mask = compiled.sift(THRESHOLD, &mut input_offset);

                    if hit_mask == 0 {
                        continue;
                    }

                    let offset = input_offset + hit_mask.trailing_zeros() as u64;

                    return core::hint::black_box(offset);
                }
            }
        })
    });

    let can_compile = hashx::HashXBuilder::new()
        .runtime(hashx::RuntimeOption::CompileOnly)
        .build(&[0; 8])
        .is_ok();

    if can_compile {
        group.bench_function("hashx_official", |b| {
            b.iter(|| {
                loop {
                    seed += 1;
                    let Ok(prog) = hashx::HashXBuilder::new()
                        .runtime(hashx::RuntimeOption::CompileOnly)
                        .build(&seed.to_le_bytes())
                    else {
                        continue;
                    };

                    for input in 0.. {
                        let hash = prog.hash_to_u64(input);

                        if hash & THRESHOLD == 0 {
                            return core::hint::black_box(input);
                        }
                    }
                }
            })
        });
    }

    group.bench_function("hashx_official_interpreter", |b| {
        b.iter(|| {
            loop {
                seed += 1;
                let Ok(prog) = hashx::HashXBuilder::new()
                    .runtime(hashx::RuntimeOption::InterpretOnly)
                    .build(&seed.to_le_bytes())
                else {
                    continue;
                };

                for input in 0.. {
                    let hash = prog.hash_to_u64(input);

                    if hash & THRESHOLD == 0 {
                        return core::hint::black_box(input);
                    }
                }
            }
        })
    });

    group.throughput(Throughput::Elements(16));

    #[cfg(feature = "jit-infra")]
    group.bench_function("hashx_avx512dq_run", |b| {
        use pow_buster::{
            hashx::{
                TestMode,
                hashx_avx512dq::{CompiledSifter, DataBuffer},
                hashx_vendor::HashX,
            },
            jit::exec_map::ExecMap,
        };

        let mut map = ExecMap::new(CompiledSifter::WANTED_SIZE).unwrap();
        let mut data = Box::<DataBuffer>::new_uninit();
        unsafe {
            data.assume_init_mut().fill(0);
        }
        let mut data = unsafe { data.assume_init() };

        let prog = HashX::new(&1234u32.to_le_bytes()).unwrap();
        let compiled = CompiledSifter::new_ex(&mut map, &mut data, &prog, TestMode::Mask, false);
        let mut input_offset = 0;
        b.iter(|| {
            compiled.sift(THRESHOLD, &mut input_offset);
        })
    });
}

#[cfg(feature = "jit-infra")]
fn bench_hashx_jit(c: &mut Criterion) {
    use pow_buster::{
        hashx::{
            TestMode,
            hashx_avx512dq::{CompiledSifter, DataBuffer},
            hashx_vendor::HashX,
        },
        jit::exec_map::ExecMap,
    };

    let mut map = ExecMap::new(CompiledSifter::WANTED_SIZE).unwrap();

    let mut group = c.benchmark_group("bench_hashx");
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(8));
    group.measurement_time(Duration::from_secs(15));

    group.throughput(Throughput::Elements(1));

    let mut data = Box::<DataBuffer>::new_uninit();
    unsafe {
        data.assume_init_mut().fill(0);
    }
    let mut data = unsafe { data.assume_init() };

    let mut seed = 0u64;
    group.bench_function("hashx_jit_only", |b| {
        b.iter(|| {
            loop {
                seed += 1;
                let Ok(prog) = HashX::new(&seed.to_le_bytes()) else {
                    continue;
                };
                let _compiled =
                    CompiledSifter::new_ex(&mut map, &mut data, &prog, TestMode::LessThan, false);

                break;
            }
        })
    });
}

fn benchmark_hashx_multi_thread(c: &mut Criterion) {
    if let Err(e) = std::thread::Builder::new().spawn(|| {}) {
        eprintln!("cannot spawn threads, skipping benchmark: {}", e);
        return;
    }

    let mut group = c.benchmark_group("bench_hashx_multi_thread");
    group.sample_size(25);
    group.warm_up_time(Duration::from_secs(8));
    group.measurement_time(Duration::from_secs(40));

    let num_threads: u32 = std::env::var("NUM_THREADS")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| v.parse().expect("NUM_THREADS must be a number"))
        .unwrap_or_else(|| num_cpus::get())
        .try_into()
        .unwrap();

    const WORK_BATCH: usize = 32;

    let num_works = num_threads as usize * WORK_BATCH;
    group.throughput(Throughput::Elements((1 << N_BITS) * num_works as u64));

    const N_BITS: u32 = 18;
    const THRESHOLD: u64 = (1 << N_BITS) - 1;
    eprintln!(
        "using {} threads at difficulty {} (mean {} hashes per attempt)",
        num_threads,
        N_BITS,
        (1 << N_BITS) as u64
    );

    let mut seed = 0u64;

    #[cfg(feature = "jit-infra")]
    thread_local! {
        static MAP: std::cell::UnsafeCell<(pow_buster::jit::exec_map::ExecMap, pow_buster::hashx::hashx_avx512dq::DataBuffer)> = std::cell::UnsafeCell::new((pow_buster::jit::exec_map::ExecMap::new(
            pow_buster::hashx::hashx_avx512dq::CompiledSifter::WANTED_SIZE,
        )
        .unwrap(), unsafe { core::mem::zeroed() }));
    }

    let can_compile = ::hashx::HashXBuilder::new()
        .runtime(hashx::RuntimeOption::CompileOnly)
        .build(&[0; 8])
        .is_ok();

    let mut safe_seeds = Vec::with_capacity(num_works);

    while safe_seeds.len() < num_works {
        seed += 1;
        let Ok(_) = ::hashx::HashXBuilder::new()
            .runtime(::hashx::RuntimeOption::InterpretOnly)
            .build(&seed.to_le_bytes())
        else {
            continue;
        };

        safe_seeds.push(seed);
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_mfence();
    }

    brk();

    let clk = quanta::Clock::new();

    #[cfg(feature = "jit-infra")]
    group.bench_function("avx512dq_jit", |b| {
        b.iter_custom(|r| {
            let work_ctr = core::sync::atomic::AtomicUsize::new(0);
            let sum = core::sync::atomic::AtomicU64::new(0);
            let total_time = core::sync::atomic::AtomicU64::new(0);
            let r = usize::try_from(r).unwrap();

            std::thread::scope(|s| {
                for thread_idx in 0..num_threads {
                    let _ = thread_idx;
                    let work_ctr = &work_ctr;
                    let safe_seeds = &safe_seeds;
                    let clk = &clk;
                    let sum = &sum;
                    let total_time = &total_time;
                    s.spawn(move || {
                        MAP.with(|map_data| {
                            loop {
                                use pow_buster::hashx::{
                                    TestMode, hashx_avx512dq::CompiledSifter, hashx_vendor::HashX,
                                };

                                let this_work =
                                    work_ctr.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                                if this_work >= num_works * r {
                                    break;
                                }

                                let (map, data) =
                                    unsafe { map_data.get().as_mut().unwrap_unchecked() };

                                let prog =
                                    HashX::new(&safe_seeds[this_work % num_works].to_le_bytes())
                                        .unwrap();
                                let prog =
                                    CompiledSifter::new_ex(map, data, &prog, TestMode::Mask, false);

                                let start = clk.raw();
                                let mut input_offset = 0;
                                loop {
                                    let hit_mask = prog.sift(THRESHOLD, &mut input_offset);

                                    if hit_mask != 0 {
                                        sum.fetch_add(
                                            input_offset + hit_mask.trailing_zeros() as u64,
                                            core::sync::atomic::Ordering::Relaxed,
                                        );
                                        let end = clk.raw();
                                        let dur = clk.delta_as_nanos(start, end);
                                        total_time
                                            .fetch_add(dur, core::sync::atomic::Ordering::Relaxed);
                                        break;
                                    }
                                }
                            }
                        })
                    });
                }
            });
            core::hint::black_box(sum.load(core::sync::atomic::Ordering::Relaxed));
            std::time::Duration::from_nanos(total_time.load(core::sync::atomic::Ordering::Relaxed))
                / num_threads
        });
    });

    if can_compile {
        group.bench_function("official_jit", |b| {
            b.iter_custom(|r| {
                let work_ctr = core::sync::atomic::AtomicUsize::new(0);
                let sum = core::sync::atomic::AtomicU64::new(0);
                let total_time = core::sync::atomic::AtomicU64::new(0);
                let r = usize::try_from(r).unwrap();
                std::thread::scope(|s| {
                    for thread_idx in 0..num_threads {
                        let _ = thread_idx;
                        let work_ctr = &work_ctr;
                        let safe_seeds = &safe_seeds;
                        let sum = &sum;
                        let total_time = &total_time;
                        let clk = &clk;
                        s.spawn(move || {
                            loop {
                                let this_work =
                                    work_ctr.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                                if this_work >= num_works * r {
                                    break;
                                }

                                let prog = ::hashx::HashXBuilder::new()
                                    .runtime(hashx::RuntimeOption::CompileOnly)
                                    .build(&safe_seeds[this_work % num_works].to_le_bytes())
                                    .unwrap();

                                let start = clk.raw();
                                for input in 0.. {
                                    let hash = prog.hash_to_u64(input);

                                    if hash & THRESHOLD == 0 {
                                        sum.fetch_add(input, core::sync::atomic::Ordering::Relaxed);
                                        let end = clk.raw();
                                        let dur = clk.delta_as_nanos(start, end);
                                        total_time
                                            .fetch_add(dur, core::sync::atomic::Ordering::Relaxed);
                                        break;
                                    }
                                }
                            }
                        });
                    }
                });
                core::hint::black_box(sum.load(core::sync::atomic::Ordering::Relaxed));
                std::time::Duration::from_nanos(
                    total_time.load(core::sync::atomic::Ordering::Relaxed),
                ) / num_threads
            });
        });
    }

    group.bench_function("official_interpreter", |b| {
        b.iter_custom(|r| {
            let work_ctr = core::sync::atomic::AtomicUsize::new(0);
            let sum = core::sync::atomic::AtomicU64::new(0);
            let total_time = core::sync::atomic::AtomicU64::new(0);
            let clk = &clk;
            let r = usize::try_from(r).unwrap();
            std::thread::scope(|s| {
                for thread_idx in 0..num_threads {
                    let _ = thread_idx;
                    let work_ctr = &work_ctr;
                    let safe_seeds = &safe_seeds;
                    let sum = &sum;
                    let total_time = &total_time;
                    s.spawn(move || {
                        loop {
                            let this_work =
                                work_ctr.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                            if this_work >= num_works * r {
                                break;
                            }

                            let prog = ::hashx::HashXBuilder::new()
                                .runtime(hashx::RuntimeOption::InterpretOnly)
                                .build(&safe_seeds[this_work % num_works].to_le_bytes())
                                .unwrap();

                            let start = clk.raw();
                            for input in 0.. {
                                let hash = prog.hash_to_u64(input);

                                if hash & THRESHOLD == 0 {
                                    sum.fetch_add(input, core::sync::atomic::Ordering::Relaxed);
                                    let end = clk.raw();
                                    let dur = clk.delta_as_nanos(start, end);
                                    total_time
                                        .fetch_add(dur, core::sync::atomic::Ordering::Relaxed);
                                    break;
                                }
                            }
                        }
                    });
                }
            });
            core::hint::black_box(sum.load(core::sync::atomic::Ordering::Relaxed));
            std::time::Duration::from_nanos(total_time.load(core::sync::atomic::Ordering::Relaxed))
                / num_threads
        });
    });
}

criterion_group!(benches, bench_hashx, benchmark_hashx_multi_thread);

#[cfg(feature = "jit-infra")]
criterion_group!(benches_jit, bench_hashx_jit);

#[cfg(feature = "jit-infra")]
criterion_main!(benches, benches_jit);

#[cfg(not(feature = "jit-infra"))]
criterion_main!(benches);
