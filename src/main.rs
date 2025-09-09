use std::{
    num::NonZeroU8,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};

use simd_mcaptcha::{
    DecimalSolver, DoubleBlockSolver, GoAwaySolver, SingleBlockSolver, compute_target_64,
    compute_target_anubis,
    message::{DecimalMessage, GoAwayMessage},
    solver::Solver,
};

#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "live-throughput-test")]
enum ApiType {
    Mcaptcha,
    Anubis,
}

#[cfg(feature = "live-throughput-test")]
impl std::str::FromStr for ApiType {
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
    #[cfg(feature = "live-throughput-test")]
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
    #[cfg(feature = "server")]
    Server {
        #[clap(long, default_value = "127.0.0.1:8080")]
        addr: String,

        #[clap(short, long, default_value = "200000000")]
        limit: u64,

        #[clap(short, long, default_value = "2")]
        n_workers: usize,

        #[clap(
            short,
            long,
            default_value = "5000",
            help = "request timeout in milliseconds"
        )]
        timeout: u64,

        #[clap(long)]
        check_origin: Option<String>,
    },
    Profile {
        #[clap(short, long, default_value = "10000000")]
        difficulty: u64,

        #[clap(short, long, default_value = "64")]
        prefix_length: usize,
    },
    ProfileMt {
        #[clap(short, long, default_value = "10000000")]
        difficulty: u64,

        #[clap(long)]
        speed: bool,

        #[clap(short, long, default_value = "1")]
        n_threads: Option<u32>,

        #[clap(short, long, default_value = "64")]
        prefix_length: usize,
    },
    Time {
        #[clap(short, long, default_value = "10000000")]
        difficulty: u64,

        #[cfg(feature = "official")]
        #[clap(long)]
        test_official: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.subcommand {
        SubCommand::Profile {
            difficulty,
            prefix_length,
        } => {
            println!(
                "entering busy loop, attach profiler to this process now (difficulty: {})",
                difficulty
            );
            for prefix in 0..u64::MAX {
                // mimick an anubis-like situation
                let mut prefix_bytes = [0; 64];
                prefix_bytes[..8].copy_from_slice(&prefix.to_ne_bytes());
                let mut solver = DecimalSolver::from(
                    DecimalMessage::new(&prefix_bytes[..(prefix_length % 64)], 0)
                        .expect("solver is None"),
                );
                let target = compute_target_64(difficulty);
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
            prefix_length,
        } => {
            let n_threads = n_threads.unwrap_or_else(|| num_cpus::get() as u32);
            println!(
                "entering busy loop, attach profiler to this process now (difficulty: {}, n_threads: {})",
                difficulty, n_threads
            );
            let counter = Arc::new(AtomicU64::new(0));

            let (target, expected_iters) = if difficulty > 32 {
                (compute_target_64(difficulty), difficulty)
            } else {
                (
                    compute_target_anubis(NonZeroU8::new(difficulty as u8).unwrap()),
                    1 << (4 * (difficulty as u8)),
                )
            };

            for _ in 0..n_threads {
                let counter = counter.clone();
                std::thread::spawn(move || {
                    for prefix in 0..u64::MAX {
                        // mimick an anubis-like situation
                        let mut prefix_bytes = [0; 64];
                        prefix_bytes[..8].copy_from_slice(&prefix.to_ne_bytes());
                        let mut solver = DecimalSolver::from(
                            DecimalMessage::new(&prefix_bytes[..(prefix_length % 64)], 0)
                                .expect("solver is None"),
                        );

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
                        counter.fetch_add(1, Ordering::Relaxed);
                        core::hint::black_box(result);
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
            let target = compute_target_64(difficulty);
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
            let mut total_nonces = 0;
            for i in 0..40u8 {
                // mimick an anubis-like situation
                let mut prefix_bytes = [0; 64];
                prefix_bytes[0] = i;
                let mut solver = DecimalSolver::from(
                    DecimalMessage::new(&prefix_bytes, 0).expect("solver is None"),
                );
                let inner_begin = Instant::now();
                let (nonce, _) = solver.solve::<true>(target_u32s).expect("solver failed");
                eprintln!(
                    "[{}]: in {:.3} seconds ({})",
                    core::any::type_name::<SingleBlockSolver>(),
                    inner_begin.elapsed().as_secs_f32(),
                    nonce,
                );
                total_nonces += solver.get_attempted_nonces();
            }
            let elapsed = begin.elapsed();
            println!(
                "[{}]: {} seconds at difficulty {} ({:.2} MH/s)",
                core::any::type_name::<SingleBlockSolver>(),
                elapsed.as_secs_f32() / 40.0,
                difficulty,
                total_nonces as f32 / elapsed.as_secs_f32() / 1024.0 / 1024.0
            );
            let begin = Instant::now();
            let mut total_nonces = 0;
            let mut prefix = [0u8; 48];
            for i in 0..40u8 {
                prefix[0] = i;
                let mut solver =
                    DecimalSolver::from(DecimalMessage::new(&prefix, 0).expect("solver is None"));
                let inner_begin = Instant::now();
                let (nonce, _) = solver.solve::<true>(target_u32s).expect("solver failed");
                eprintln!(
                    "[{}]: in {:.3} seconds ({})",
                    core::any::type_name::<DoubleBlockSolver>(),
                    inner_begin.elapsed().as_secs_f32(),
                    nonce,
                );
                total_nonces += solver.get_attempted_nonces();
            }
            let elapsed = begin.elapsed();
            println!(
                "[{}]: {} seconds at difficulty {} ({:.2} MH/s)",
                core::any::type_name::<DoubleBlockSolver>(),
                elapsed.as_secs_f32() / 40.0,
                difficulty,
                total_nonces as f32 / elapsed.as_secs_f32() / 1024.0 / 1024.0
            );
            let begin = Instant::now();
            let mut total_nonces = 0;
            for i in 0..40u8 {
                let mut prefix = [0u8; 32];
                prefix[0] = i;
                let mut solver = GoAwaySolver::from(GoAwayMessage::new_bytes(&prefix));
                let inner_begin = Instant::now();
                let (nonce, _) = solver.solve::<true>(target_u32s).expect("solver failed");
                eprintln!(
                    "[{}]: in {:.3} seconds ({})",
                    core::any::type_name::<GoAwaySolver>(),
                    inner_begin.elapsed().as_secs_f32(),
                    nonce
                );
                total_nonces += nonce;
            }
            let elapsed = begin.elapsed();
            println!(
                "[{}]: {} seconds at difficulty {} ({:.2} MH/s)",
                core::any::type_name::<GoAwaySolver>(),
                elapsed.as_secs_f32() / 40.0,
                difficulty,
                total_nonces as f32 / elapsed.as_secs_f32() / 1024.0 / 1024.0
            );
            #[cfg(feature = "official")]
            if test_official && let Ok(difficulty) = difficulty.try_into() {
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
        #[cfg(feature = "live-throughput-test")]
        SubCommand::Live {
            api_type,
            host,
            site_key,
            n_workers,
            do_control,
        } => {
            let api_type: ApiType = api_type.parse().unwrap();
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
                let packed_time = Arc::new(AtomicU64::new(0));

                for _ in 0..n_workers {
                    let host_clone = host.clone();

                    let succeeded_clone = succeeded.clone();
                    let failed_clone = failed.clone();
                    let site_key_clone = site_key.clone();
                    let packed_time_clone = packed_time.clone();
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
                                let mut iotime = 0;
                                let start = Instant::now();
                                match simd_mcaptcha::client::solve_mcaptcha_ex(
                                    &pool,
                                    &client,
                                    &host_clone,
                                    &site_key_clone,
                                    true,
                                    &mut iotime,
                                )
                                .await
                                {
                                    Ok(_) => {
                                        succeeded_clone.fetch_add(1, Ordering::Relaxed)
                                    }
                                    Err(_) => failed_clone.fetch_add(1, Ordering::Relaxed),
                                };
                                let mut packed_time = start.elapsed().as_micros() as u64;
                                packed_time <<=32;
                                packed_time += iotime as u64;
                                packed_time_clone.fetch_add(packed_time, Ordering::Relaxed);
                            },
                            ApiType::Anubis => loop {
                                let mut iotime = 0;
                                let start = Instant::now();
                                match simd_mcaptcha::client::solve_anubis_ex(
                                    &client,
                                    &host_clone,
                                    true,
                                    &mut iotime,
                                )
                                .await
                                {
                                    Ok(_) => {
                                        succeeded_clone.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Err(e) => {
                                        eprintln!("anubis error: {:?}", e);
                                        failed_clone.fetch_add(1, Ordering::Relaxed);
                                    }
                                };
                                let mut packed_time = start.elapsed().as_micros() as u64 / 10;
                                packed_time <<=32;
                                packed_time += iotime as u64 / 10;
                                packed_time_clone.fetch_add(packed_time, Ordering::Relaxed);
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

                    let packed_time = packed_time.load(Ordering::Relaxed);
                    let iowait = packed_time as u32;
                    let total = (packed_time >> 32) as u32;

                    eprintln!(
                        "[{:.1}s] proofs accepted: {}, failed: {}, 5s: {:.1}pps, 5s_failed: {:.1}rps, {:.2}% http_wait",
                        elapsed.as_secs_f32(),
                        succeeded,
                        failed,
                        rate_5sec_succeeded,
                        rate_5sec_failed,
                        if total > 0 { iowait as f64 / total as f64 * 100.0 } else { 0.0 },
                    );
                    last_succeeded = succeeded;
                    last_failed = failed;
                }
            });
        }
        #[cfg(feature = "server")]
        SubCommand::Server {
            addr,
            mut limit,
            n_workers,
            check_origin,
            timeout,
        } => {
            use tracing::level_filters::LevelFilter;
            use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().pretty())
                .with(
                    tracing_subscriber::EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                )
                .init();

            if limit == 0 {
                limit = u64::MAX;
            }

            let mut app = match check_origin {
                Some(check_origin) => {
                    let expected_origin = url::Url::parse(&check_origin).unwrap();
                    simd_mcaptcha::server::AppState::new(n_workers, limit)
                        .router_with_origin_check(expected_origin)
                }
                None => simd_mcaptcha::server::AppState::new(n_workers, limit).router(),
            };

            if timeout > 0 {
                app = app.layer(tower_http::timeout::TimeoutLayer::new(
                    std::time::Duration::from_millis(timeout),
                ));
            }

            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
                )
                .await
                .unwrap();
            });
        }
    }
}
