use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};

use simd_mcaptcha::{DoubleBlockSolver16Way, SingleBlockSolver16Way, Solver, compute_target};

#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Subcommand)]
enum SubCommand {
    #[cfg(feature = "client")]
    Live {
        #[clap(long, default_value = "http://localhost:7000")]
        host: String,

        #[clap(long)]
        site_key: String,

        #[clap(short, long, default_value = "32")]
        n_workers: Option<u32>,

        #[clap(long)]
        do_control: bool,

        #[cfg(feature = "wgpu")]
        #[clap(long)]
        use_gpu: bool,
    },
    Profile {
        #[clap(short, long, default_value = "10000000")]
        difficulty: u32,
    },
    ProfileMt {
        #[clap(short, long, default_value = "10000000")]
        difficulty: u32,

        #[clap(long)]
        speed: bool,

        #[clap(short, long, default_value = "1")]
        n_threads: Option<u32>,
    },
    Time {
        #[clap(short, long, default_value = "10000000")]
        difficulty: u32,

        #[cfg(feature = "official")]
        #[clap(long)]
        test_official: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.subcommand {
        SubCommand::Profile { difficulty } => {
            println!(
                "entering busy loop, attach profiler to this process now (difficulty: {})",
                difficulty
            );
            for prefix in 0..u64::MAX {
                let prefix = prefix.to_ne_bytes();
                let mut solver = SingleBlockSolver16Way::new((), &prefix).expect("solver is None");
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
                let result = solver.solve(target_u32s).expect("solver failed");
                core::hint::black_box(result);
            }
        }
        SubCommand::ProfileMt {
            difficulty,
            speed,
            n_threads,
        } => {
            let n_threads = n_threads.unwrap_or_else(|| num_cpus::get() as u32);
            println!(
                "entering busy loop, attach profiler to this process now (difficulty: {}, n_threads: {})",
                difficulty, n_threads
            );
            let counter = Arc::new(AtomicU64::new(0));
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(n_threads as usize)
                .build()
                .unwrap();
            if speed {
                let counter = counter.clone();
                let start = Instant::now();
                loop {
                    let counter = counter.load(Ordering::Relaxed);
                    eprintln!("{} rps", counter as f32 / start.elapsed().as_secs_f32());
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            pool.broadcast(move |_| {
                for prefix in 0..u64::MAX {
                    let prefix = prefix.to_ne_bytes();
                    let mut solver =
                        SingleBlockSolver16Way::new((), &prefix).expect("solver is None");
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
                    let result = solver.solve(target_u32s).expect("solver failed");
                    counter.fetch_add(1, Ordering::Relaxed);
                    core::hint::black_box(result);
                }
            });
        }
        SubCommand::Time {
            difficulty,
            #[cfg(feature = "official")]
            test_official,
        } => {
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
            let begin = Instant::now();
            for i in 0..20u64 {
                let mut solver =
                    SingleBlockSolver16Way::new((), &i.to_ne_bytes()).expect("solver is None");
                let inner_begin = Instant::now();
                let (nonce, result) = solver.solve(target_u32s).expect("solver failed");
                eprintln!(
                    "native: in {:.3} seconds {:?}",
                    inner_begin.elapsed().as_secs_f32(),
                    (nonce, result)
                );
            }
            let elapsed = begin.elapsed();
            println!(
                "Single block solver: {} seconds at difficulty {}",
                elapsed.as_secs_f32() / 20.0,
                difficulty
            );
            let begin = Instant::now();
            let mut prefix = [0u8; 48];
            for i in 0..20u64 {
                prefix[0] = i.to_ne_bytes()[0];
                let mut solver = DoubleBlockSolver16Way::new((), &prefix).expect("solver is None");
                let inner_begin = Instant::now();
                let (nonce, result) = solver.solve(target_u32s).expect("solver failed");
                eprintln!(
                    "double block solver: in {:.3} seconds {:?}",
                    inner_begin.elapsed().as_secs_f32(),
                    (nonce, result)
                );
            }
            let elapsed = begin.elapsed();
            println!(
                "Double block solver: {} seconds at difficulty {}",
                elapsed.as_secs_f32() / 20.0,
                difficulty
            );
            #[cfg(feature = "official")]
            if test_official {
                let solver = pow_sha256::ConfigBuilder::default()
                    .salt("x".to_string())
                    .build()
                    .unwrap();
                let begin = Instant::now();
                for i in 0..10u64 {
                    let inner_begin = Instant::now();
                    let result = solver.prove_work(&i.to_string(), difficulty).unwrap();
                    eprintln!(
                        "official: in {:.3} seconds {:?}",
                        inner_begin.elapsed().as_secs_f32(),
                        result
                    );
                }
                let elapsed = begin.elapsed();
                println!(
                    "{} seconds at difficulty {}",
                    elapsed.as_secs_f32() / 10.0,
                    difficulty
                );
            }
        }
        #[cfg(feature = "client")]
        SubCommand::Live {
            host,
            site_key,
            n_workers,
            do_control,
            #[cfg(feature = "wgpu")]
            use_gpu,
        } => {
            use std::io::Write;

            let n_workers = n_workers.unwrap_or_else(|| num_cpus::get() as u32);
            eprintln!("You are hitting host {}, n_workers: {}", host, n_workers);
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(n_workers as usize)
                .build()
                .unwrap();
            let pool = Arc::new(pool);

            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async move {
                if do_control {
                    let host = host.clone();
                    let site_key = site_key.clone();
                    let pool = pool.clone();
                    tokio::spawn(async move {
                        eprintln!("running 10 seconds of control sending random proofs");
                        let client = reqwest::ClientBuilder::new().build().unwrap();
                        let begin = Instant::now();
                        let count = Arc::new(AtomicU64::new(0));
                        let mut js = tokio::task::JoinSet::new();
                        for _ in 0..n_workers {
                            let count_clone = count.clone();
                            let client = client.clone();
                            let host = host.clone();
                            let site_key = site_key.clone();
                            let pool = pool.clone();
                            js.spawn(async move {
                                while begin.elapsed() < Duration::from_secs(10) {
                                    simd_mcaptcha::client::solve_mcaptcha(
                                        &pool, &client, &host, &site_key, false,
                                    )
                                    .await
                                    .expect_err("random proof should fail but somehow succeeded");
                                    count_clone.fetch_add(1, Ordering::SeqCst);
                                }
                            });
                        }
                        while let Some(Ok(_)) = js.join_next().await {}
                        eprintln!(
                            "Fake Proof Control: {} requests in {:.1} seconds, {:.1} rps",
                            count.load(Ordering::SeqCst),
                            begin.elapsed().as_secs_f32(),
                            count.load(Ordering::SeqCst) as f32 / begin.elapsed().as_secs_f32()
                        );
                    });
                }

                let mut last_succeeded = 0;
                let mut last_failed = 0;
                let succeeded = Arc::new(AtomicU64::new(0));
                let failed = Arc::new(AtomicU64::new(0));

                for _ in 0..n_workers {
                    let host_clone = host.clone();

                    let succeeded_clone = succeeded.clone();
                    let failed_clone = failed.clone();
                    let site_key_clone = site_key.clone();
                    let pool = pool.clone();

                    #[cfg(feature = "wgpu")]
                    if use_gpu {
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
                        let mut ctx = simd_mcaptcha::wgpu::VulkanDeviceContext::new(device, queue);

                        tokio::spawn(async move {
                            let client = reqwest::ClientBuilder::new().build().unwrap();
                            loop {
                                match simd_mcaptcha::client::solve_mcaptcha_wgpu(
                                    &mut ctx,
                                    &client,
                                    &host_clone,
                                    &site_key_clone,
                                    true,
                                )
                                .await
                                {
                                    Ok(_) => {
                                        succeeded_clone.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Err(e) => {
                                        eprintln!("wgpu error: {:?}", e);
                                        failed_clone.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        });

                        continue;
                    }

                    tokio::spawn(async move {
                        let client = reqwest::ClientBuilder::new().build().unwrap();

                        loop {
                            match simd_mcaptcha::client::solve_mcaptcha(
                                &pool,
                                &client,
                                &host_clone,
                                &site_key_clone,
                                true,
                            )
                            .await
                            {
                                Ok(token) => {
                                    let mut stdout = std::io::stdout().lock();
                                    stdout
                                        .write_all(token.as_bytes())
                                        .expect("stdout write failed");
                                    stdout.write_all(b"\n").expect("stdout write failed");
                                    stdout.flush().expect("stdout flush failed");

                                    succeeded_clone.fetch_add(1, Ordering::Relaxed)
                                }
                                Err(_) => failed_clone.fetch_add(1, Ordering::Relaxed),
                            };
                        }
                    });
                }

                let begin = Instant::now();
                let mut ticker = tokio::time::interval(Duration::from_secs(5));
                loop {
                    ticker.tick().await;
                    let elapsed = begin.elapsed();
                    let succeeded = succeeded.load(Ordering::Relaxed);
                    let failed = failed.load(Ordering::Relaxed);
                    let diff_succeeded = succeeded - last_succeeded;
                    let diff_failed = failed - last_failed;
                    let rate_5sec_succeeded: f32 = diff_succeeded as f32 / 5.0;
                    let rate_5sec_failed = diff_failed as f32 / 5.0;

                    eprintln!(
                        "[{:.1}s] succeeded: {}, failed: {}, 5s: {:.1}rps, 5s_failed: {:.1}rps",
                        elapsed.as_secs_f32(),
                        succeeded,
                        failed,
                        rate_5sec_succeeded,
                        rate_5sec_failed,
                    );
                    last_succeeded = succeeded;
                    last_failed = failed;
                }
            });
        }
    }
}
