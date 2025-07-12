use std::{
    num::NonZeroU8,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};

use simd_mcaptcha::{
    DoubleBlockSolver16Way, GoAwaySolver16Way, SingleBlockSolver16Way, Solver, compute_target,
    compute_target_anubis,
};

#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiType {
    Mcaptcha,
    Anubis,
}

impl FromStr for ApiType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mcaptcha" => Ok(ApiType::Mcaptcha),
            "anubis" => Ok(ApiType::Anubis),
            _ => Err(format!("invalid api type: {}", s)),
        }
    }
}

#[derive(Subcommand)]
enum SubCommand {
    #[cfg(feature = "client")]
    Live {
        #[clap(long, default_value = "mcaptcha")]
        api_type: String,

        #[clap(long, default_value = "http://localhost:7000")]
        host: String,

        #[clap(long, default_value = "x")]
        site_key: String,

        #[clap(short, long, default_value = "32")]
        n_workers: Option<u32>,

        #[clap(long)]
        do_control: bool,
    },
    #[cfg(feature = "client")]
    Anubis {
        #[clap(long, default_value = "http://localhost:8923/")]
        url: String,
    },
    #[cfg(feature = "client")]
    GoAway {
        #[clap(long, default_value = "http://localhost:8080/")]
        url: String,
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

        #[clap(long)]
        double_block: bool,
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
                // mimick an anubis-like situation
                let mut prefix_bytes = [0; 64];
                prefix_bytes[..8].copy_from_slice(&prefix.to_ne_bytes());
                let mut solver =
                    SingleBlockSolver16Way::new((), &prefix_bytes).expect("solver is None");
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
                let result = solver.solve::<true>(target_u32s).expect("solver failed");
                core::hint::black_box(result);
            }
        }
        SubCommand::ProfileMt {
            difficulty,
            speed,
            n_threads,
            double_block,
        } => {
            let n_threads = n_threads.unwrap_or_else(|| num_cpus::get() as u32);
            println!(
                "entering busy loop, attach profiler to this process now (difficulty: {}, n_threads: {})",
                difficulty, n_threads
            );
            let counter = Arc::new(AtomicU64::new(0));

            let (upwards, target, expected_iters) = if difficulty > 32 {
                (true, compute_target(difficulty), difficulty)
            } else {
                (
                    false,
                    compute_target_anubis(NonZeroU8::new(difficulty as u8).unwrap()),
                    1 << (4 * (difficulty as u8)),
                )
            };

            for _ in 0..n_threads {
                let counter = counter.clone();
                std::thread::spawn(move || {
                    if double_block {
                        for prefix in 0..u64::MAX {
                            let mut prefix_bytes = [0u8; 48];
                            prefix_bytes[..8].copy_from_slice(&prefix.to_ne_bytes());
                            let mut solver = DoubleBlockSolver16Way::new((), &prefix_bytes)
                                .expect("solver is None");
                            let target_bytes = target.to_be_bytes();
                            let target_u32s = core::array::from_fn(|i| {
                                u32::from_be_bytes([
                                    target_bytes[i * 4],
                                    target_bytes[i * 4 + 1],
                                    target_bytes[i * 4 + 2],
                                    target_bytes[i * 4 + 3],
                                ])
                            });
                            let result = solver
                                .solve_dyn(target_u32s, upwards)
                                .expect("solver failed");
                            counter.fetch_add(1, Ordering::Relaxed);
                            core::hint::black_box(result);
                        }
                    } else {
                        for prefix in 0..u64::MAX {
                            // mimick an anubis-like situation
                            let mut prefix_bytes = [0; 64];
                            prefix_bytes[..8].copy_from_slice(&prefix.to_ne_bytes());
                            let mut solver = SingleBlockSolver16Way::new((), &prefix_bytes)
                                .expect("solver is None");

                            let target_bytes = target.to_be_bytes();
                            let target_u32s = core::array::from_fn(|i| {
                                u32::from_be_bytes([
                                    target_bytes[i * 4],
                                    target_bytes[i * 4 + 1],
                                    target_bytes[i * 4 + 2],
                                    target_bytes[i * 4 + 3],
                                ])
                            });
                            let result = solver
                                .solve_dyn(target_u32s, upwards)
                                .expect("solver failed");
                            counter.fetch_add(1, Ordering::Relaxed);
                            core::hint::black_box(result);
                        }
                    }
                });
            }
            if speed {
                let counter = counter.clone();
                let start = Instant::now();
                loop {
                    let counter = counter.load(Ordering::Relaxed);
                    eprintln!(
                        "{} rps ({:.2} GH/s)",
                        counter as f32 / start.elapsed().as_secs_f32(),
                        counter as f32 * expected_iters as f32
                            / 1024.0
                            / 1024.0
                            / 1024.0
                            / start.elapsed().as_secs_f32()
                    );
                    std::thread::sleep(Duration::from_secs(1));
                }
            } else {
                loop {
                    std::thread::park();
                }
            }
        }
        SubCommand::Time {
            difficulty,
            #[cfg(feature = "official")]
            test_official,
        } => {
            let (upwards, target, expected_iters) = if difficulty > 32 {
                (true, compute_target(difficulty), difficulty)
            } else {
                (
                    false,
                    compute_target_anubis(NonZeroU8::new(difficulty as u8).unwrap()),
                    1 << (4 * (difficulty as u8)),
                )
            };
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
            for i in 0..20u8 {
                // mimick an anubis-like situation
                let mut prefix_bytes = [0; 32];
                prefix_bytes[0] = i;
                let mut solver =
                    SingleBlockSolver16Way::new((), &prefix_bytes).expect("solver is None");
                let inner_begin = Instant::now();
                let (nonce, result) = solver
                    .solve_dyn(target_u32s, upwards)
                    .expect("solver failed");
                let mut hex_output = [0u8; 64];
                simd_mcaptcha::encode_hex(&mut hex_output, result);
                eprintln!(
                    "[{}]: in {:.3} seconds ({}, {})",
                    core::any::type_name::<SingleBlockSolver16Way>(),
                    inner_begin.elapsed().as_secs_f32(),
                    nonce,
                    unsafe { std::str::from_utf8_unchecked(&hex_output) }
                );
            }
            let elapsed = begin.elapsed();
            println!(
                "[{}]: {} seconds at difficulty {} ({:.2} MH/s)",
                core::any::type_name::<SingleBlockSolver16Way>(),
                elapsed.as_secs_f32() / 20.0,
                expected_iters,
                expected_iters as f32 / elapsed.as_secs_f32() * 20.0 / 1024.0 / 1024.0
            );
            let begin = Instant::now();
            let mut prefix = [0u8; 48];
            for i in 0..20u8 {
                prefix[0] = i;
                let mut solver = DoubleBlockSolver16Way::new((), &prefix).expect("solver is None");
                let inner_begin = Instant::now();
                let (nonce, result) = solver
                    .solve_dyn(target_u32s, upwards)
                    .expect("solver failed");
                let mut hex_output = [0u8; 64];
                simd_mcaptcha::encode_hex(&mut hex_output, result);
                eprintln!(
                    "[{}]: in {:.3} seconds ({}, {})",
                    core::any::type_name::<DoubleBlockSolver16Way>(),
                    inner_begin.elapsed().as_secs_f32(),
                    nonce,
                    unsafe { std::str::from_utf8_unchecked(&hex_output) }
                );
            }
            let elapsed = begin.elapsed();
            println!(
                "[{}]: {} seconds at difficulty {} ({:.2} MH/s)",
                core::any::type_name::<DoubleBlockSolver16Way>(),
                elapsed.as_secs_f32() / 20.0,
                expected_iters,
                expected_iters as f32 / elapsed.as_secs_f32() * 20.0 / 1024.0 / 1024.0
            );
            let begin = Instant::now();
            let mut total_iters = 0;
            for i in 0..20u8 {
                let mut prefix = [0u8; 32];
                prefix[0] = i;
                let mut solver = GoAwaySolver16Way::new((), &prefix).expect("solver is None");
                let inner_begin = Instant::now();
                let (nonce, result) = solver
                    .solve_dyn(target_u32s, upwards)
                    .expect("solver failed");
                let mut hex_output = [0u8; 64];
                simd_mcaptcha::encode_hex(&mut hex_output, result);
                eprintln!(
                    "[{}]: in {:.3} seconds ({}, {})",
                    core::any::type_name::<GoAwaySolver16Way>(),
                    inner_begin.elapsed().as_secs_f32(),
                    nonce,
                    unsafe { std::str::from_utf8_unchecked(&hex_output) }
                );
                total_iters += nonce;
            }
            let elapsed = begin.elapsed();
            println!(
                "[{}]: {} seconds at difficulty {} ({:.2} MH/s)",
                core::any::type_name::<GoAwaySolver16Way>(),
                elapsed.as_secs_f32() / 20.0,
                expected_iters,
                total_iters as f32 / elapsed.as_secs_f32() / 1024.0 / 1024.0
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
                    "official: {} seconds at difficulty {} ({:.2} MH/s)",
                    elapsed.as_secs_f32() / 10.0,
                    difficulty,
                    difficulty as f32 / elapsed.as_secs_f32() * 10.0 / 1024.0 / 1024.0
                );
            }
        }
        #[cfg(feature = "client")]
        SubCommand::Anubis { url } => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async move {
                let client = reqwest::ClientBuilder::new()
                    .gzip(true)
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap();
                let response = simd_mcaptcha::client::solve_anubis(&client, &url, true)
                    .await
                    .unwrap();
                println!("set-cookie: {}", response);
            });
        }
        #[cfg(feature = "client")]
        SubCommand::GoAway { url } => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async move {
                let client = reqwest::ClientBuilder::new()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap();
                let response =
                    simd_mcaptcha::client::solve_goaway_js_pow_sha256(&client, &url, true)
                        .await
                        .unwrap();
                println!("set-cookie: {}", response);
            });
        }
        #[cfg(feature = "client")]
        SubCommand::Live {
            api_type,
            host,
            site_key,
            n_workers,
            do_control,
        } => {
            use std::io::Write;

            let api_type = ApiType::from_str(&api_type).unwrap();
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
                        let client = reqwest::ClientBuilder::new()
                            .gzip(api_type == ApiType::Anubis) // for some reason anubis requires gzip
                            .redirect(reqwest::redirect::Policy::none())
                            .build()
                            .unwrap();
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
                                match api_type {
                                    ApiType::Mcaptcha => {
                                        while begin.elapsed() < Duration::from_secs(10) {
                                            simd_mcaptcha::client::solve_mcaptcha(
                                                &pool, &client, &host, &site_key, false,
                                            )
                                            .await
                                            .expect_err(
                                                "random proof should fail but somehow succeeded",
                                            );
                                            count_clone.fetch_add(1, Ordering::SeqCst);
                                        }
                                    }
                                    ApiType::Anubis => {
                                        while begin.elapsed() < Duration::from_secs(10) {
                                            simd_mcaptcha::client::solve_anubis(
                                                &client, &host, false,
                                            )
                                            .await
                                            .expect_err(
                                                "random proof should fail but somehow succeeded",
                                            );
                                            count_clone.fetch_add(1, Ordering::SeqCst);
                                        }
                                    }
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

                    let api_type = api_type.clone();
                    tokio::spawn(async move {
                        let client = reqwest::ClientBuilder::new()
                            .gzip(api_type == ApiType::Anubis) // for some reason anubis requires gzip
                            .redirect(reqwest::redirect::Policy::none())
                            .build()
                            .unwrap();

                        match api_type {
                            ApiType::Mcaptcha => loop {
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
                            },
                            ApiType::Anubis => loop {
                                match simd_mcaptcha::client::solve_anubis(
                                    &client,
                                    &host_clone,
                                    true,
                                )
                                .await
                                {
                                    Ok(response) => {
                                        let mut stdout = std::io::stdout().lock();
                                        stdout
                                            .write_all(response.as_bytes())
                                            .expect("stdout write failed");
                                        stdout.write_all(b"\n").expect("stdout write failed");
                                        stdout.flush().expect("stdout flush failed");

                                        succeeded_clone.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Err(e) => {
                                        eprintln!("anubis error: {:?}", e);
                                        failed_clone.fetch_add(1, Ordering::Relaxed);
                                    }
                                };
                            },
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
