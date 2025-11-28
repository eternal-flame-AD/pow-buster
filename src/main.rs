use std::{
    num::{NonZeroU32, NonZeroU64},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand, ValueEnum};

use pow_buster::{
    Align16, BinarySolver, CerberusSolver, DecimalSolver, DoubleBlockSolver, GoAwaySolver,
    SingleBlockSolver, compute_mask_anubis, compute_mask_cerberus, compute_mask_goaway,
    compute_target_mcaptcha,
    message::{
        BinaryMessage, CerberusBinaryMessage, CerberusDecimalMessage, CerberusMessage,
        DecimalMessage, GoAwayMessage,
    },
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
    Cerberus,
    CapJs,
}

#[cfg(feature = "live-throughput-test")]
impl std::str::FromStr for ApiType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mcaptcha" => Ok(ApiType::Mcaptcha),
            "anubis" => Ok(ApiType::Anubis),
            "capjs" | "cap-js" => Ok(ApiType::CapJs),
            "cerberus" => Ok(ApiType::Cerberus),
            _ => Err(format!("invalid api type: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Anubis,
    CerberusBinary,
    CerberusDecimal,
    GoAway,
    Mcaptcha,
}

impl ValueEnum for Scheme {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Scheme::Anubis,
            Scheme::CerberusBinary,
            Scheme::CerberusDecimal,
            Scheme::GoAway,
            Scheme::Mcaptcha,
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            Scheme::Anubis => Some(clap::builder::PossibleValue::new("anubis")),
            Scheme::CerberusBinary => Some(clap::builder::PossibleValue::new("cerberus-binary")),
            Scheme::CerberusDecimal => {
                Some(clap::builder::PossibleValue::new("cerberus-decimal").alias("cerberus"))
            }
            Scheme::GoAway => Some(clap::builder::PossibleValue::new("goaway")),
            Scheme::Mcaptcha => Some(clap::builder::PossibleValue::new("mcaptcha")),
        }
    }
}

#[derive(Subcommand)]
enum SubCommand {
    /// Spin-loop a solver for profiling
    Profile {
        #[clap(short, long, default_value = "10000000")]
        difficulty: u64,

        #[clap(short, long, default_value = "64")]
        prefix_length: usize,
    },
    /// Spin-loop a solver on multiple threads for profiling
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
    /// Print solver timing data
    Time {
        #[clap(short, long, default_value = "10000000")]
        difficulty: u64,
    },
    /// Solve a generic PoW
    Solve {
        #[clap(short, long, help = "use the explicitly provided salt")]
        salt: String,

        #[clap(short = 't', long)]
        scheme: Scheme,

        #[clap(short, long, help = "use the explicitly provided difficulty")]
        difficulty: NonZeroU64,

        #[clap(short = 'j', long, help = "thread count", default_value = "1")]
        num_threads: NonZeroU32,

        #[clap(long, help = "show progress")]
        progress: bool,
    },
    /// Start a server for a solver service
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
    /// Solve an Anubis PoW with a real URL
    #[cfg(feature = "client")]
    Anubis {
        #[clap(long, default_value = "http://localhost:8923/")]
        url: String,
    },
    /// Solve a Cerberus PoW with a real URL
    #[cfg(feature = "client")]
    Cerberus {
        #[clap(long, default_value = "http://127.0.0.1:9000/")]
        url: String,
    },
    /// Solve Cap.js with a real URL
    #[cfg(feature = "client")]
    CapJs {
        #[clap(long, default_value = "http://localhost:3000/")]
        url: String,

        #[clap(long)]
        site_key: String,

        #[clap(long)]
        num_threads: Option<u32>,
    },
    /// Solve a GoAway PoW with a real URL
    #[cfg(feature = "client")]
    GoAway {
        #[clap(long, default_value = "http://localhost:8080/")]
        url: String,
    },
    /// Live throughput test using multiple workers
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

        #[clap(short, long)]
        n_threads: Option<u32>,
    },
}

fn main() {
    #[cfg(feature = "tracing-subscriber")]
    {
        use tracing::level_filters::LevelFilter;
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .pretty(),
            )
            .with(
                tracing_subscriber::EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .init();
    }
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
                let target = compute_target_mcaptcha(difficulty);
                let result = solver
                    .solve_nonce_only::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                    .expect("solver failed");
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

            let (target, expected_iters) = (compute_target_mcaptcha(difficulty), difficulty);

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

                        let result = solver
                            .solve_nonce_only::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                            .expect("solver failed");
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
        #[cfg(feature = "client")]
        SubCommand::CapJs {
            url,
            site_key,
            num_threads,
        } => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let mut pb = rayon::ThreadPoolBuilder::new();
            if let Some(num_threads) = num_threads {
                pb = pb.num_threads(num_threads as usize);
            }

            let pool = pb.build().unwrap();
            let pool = Arc::new(pool);

            runtime.block_on(async move {
                use pow_buster::adapter::capjs::{CapJsResponse, SolveCapJsResponseMeta};

                let client = pow_buster::client::build_client().build().unwrap();
                let (response, meta) =
                    pow_buster::client::solve_capjs(&pool, &client, &url, &site_key)
                        .await
                        .unwrap();

                #[derive(serde::Serialize)]
                struct MixedResponse {
                    #[serde(flatten)]
                    response: CapJsResponse,
                    #[serde(rename = "_meta")]
                    meta: SolveCapJsResponseMeta,
                }

                serde_json::to_writer_pretty(std::io::stdout(), &MixedResponse { response, meta })
                    .unwrap();
                println!();
            });
        }
        SubCommand::Time { difficulty } => {
            let target = compute_target_mcaptcha(difficulty);
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
                let nonce = solver
                    .solve_nonce_only::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                    .expect("solver failed");
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
                let nonce = solver
                    .solve_nonce_only::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                    .expect("solver failed");
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
            let mut prefix = [0u8; 64];
            for i in 0..40u8 {
                prefix[0] = i;
                let mut solver =
                    BinarySolver::from(BinaryMessage::new(&prefix, 4.try_into().unwrap()));
                let inner_begin = Instant::now();
                let nonce = solver
                    .solve_nonce_only::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                    .expect("solver failed");
                eprintln!(
                    "[{}]: in {:.3} seconds ({})",
                    core::any::type_name::<BinarySolver>(),
                    inner_begin.elapsed().as_secs_f32(),
                    nonce,
                );
                total_nonces += solver.get_attempted_nonces();
            }
            let elapsed = begin.elapsed();
            println!(
                "[{}]: {} seconds at difficulty {} ({:.2} MH/s)",
                core::any::type_name::<BinarySolver>(),
                elapsed.as_secs_f32() / 40.0,
                difficulty,
                total_nonces as f32 / elapsed.as_secs_f32() / 1024.0 / 1024.0
            );
            let begin = Instant::now();
            let mut total_nonces = 0;
            for i in 0..40u8 {
                let mut prefix = [0u8; 32];
                prefix[0] = i;
                let mut solver = GoAwaySolver::from(GoAwayMessage::new_bytes(&prefix, 0));
                let inner_begin = Instant::now();
                let nonce = solver
                    .solve_nonce_only::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, !0)
                    .expect("solver failed");
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
            let cerberus_difficulty = (0u8..=15)
                .rev()
                .find(|&i| 4u64.saturating_pow(i as u32) <= difficulty * 8)
                .unwrap_or(15);
            let mask = compute_mask_cerberus(
                cerberus_difficulty
                    .try_into()
                    .expect("difficulty out of range"),
            );
            let mut salt = *b"849c253990ebc3dc23e265f52692d5a53b89e72b76527a3e35a41c6bedad5867|3959614364|1759954402|803eb7fa618142da5c8ab89cc1109775f6c37d25520deae1e3bd2b1803aa9a8e15b2aae8a9ad2cc4f58f4c9ff2cf4999f2bef0ff5e389b15895d0cc2200d4a03|";

            let begin = Instant::now();
            let mut total_nonces = 0;
            for i in 0..40u8 {
                salt[0] = i;
                let mut solver = CerberusSolver::from(CerberusMessage::Binary(
                    CerberusBinaryMessage::new(&salt, i as u32),
                ));
                let inner_begin = Instant::now();
                let nonce = solver
                    .solve_nonce_only::<{ pow_buster::solver::SOLVE_TYPE_MASK }>(0, mask as u64)
                    .expect("solver failed");
                eprintln!(
                    "[{}]: in {:.3} seconds ({})",
                    core::any::type_name::<CerberusSolver>(),
                    inner_begin.elapsed().as_secs_f32(),
                    nonce,
                );
                total_nonces += solver.get_attempted_nonces();
            }
            let elapsed = begin.elapsed();
            println!(
                "[{}]: {} seconds at difficulty {} ({:.2} MH/s)",
                core::any::type_name::<CerberusSolver>(),
                elapsed.as_secs_f32() / 40.0,
                cerberus_difficulty,
                total_nonces as f32 / elapsed.as_secs_f32() / 1024.0 / 1024.0
            );
        }
        SubCommand::Solve {
            salt,
            scheme,
            difficulty,
            num_threads,
            progress,
        } => {
            let (target, mask, estimated_work) = match scheme {
                Scheme::Anubis => (
                    0,
                    compute_mask_anubis(difficulty.try_into().expect("difficulty out of range")),
                    16u64.saturating_pow(difficulty.get().try_into().unwrap()),
                ),
                Scheme::Mcaptcha => (
                    compute_target_mcaptcha(difficulty.get()),
                    !0,
                    difficulty.get(),
                ),
                Scheme::CerberusBinary | Scheme::CerberusDecimal => (
                    0,
                    compute_mask_cerberus(
                        u8::try_from(difficulty.get())
                            .expect("difficulty out of range")
                            .try_into()
                            .expect("difficulty cannot be zero"),
                    ) as u64,
                    4u64.saturating_pow(difficulty.get().try_into().unwrap()),
                ),
                Scheme::GoAway => (
                    0,
                    compute_mask_goaway(difficulty.try_into().expect("difficulty out of range")),
                    2u64.saturating_pow(difficulty.get().try_into().unwrap()),
                ),
            };

            let (tx, rx) = std::sync::mpsc::channel();
            let salt_bytes = salt.as_bytes();
            let nonce_attempted = core::sync::atomic::AtomicU64::new(0);
            let ws_churn = core::sync::atomic::AtomicU64::new(0);

            std::thread::scope(|s| {
                let nonce_attempted = &nonce_attempted;
                let ws_churn = &ws_churn;
                (0..num_threads.get()).for_each(|ix| {
                    let tx = tx.clone();
                    s.spawn(move || match scheme {
                        Scheme::GoAway => {
                            #[cfg(not(feature = "compare-64bit"))]
                            {
                                assert_eq!(mask as u32, 0, "64-bit comparison is required for this difficulty, rebuild with `compare-64bit` feature");
                            }
                            let mut message = GoAwayMessage::new_hex(
                                salt_bytes.try_into().expect("invalid salt length"),
                                0,
                            )
                            .expect("invalid salt: must be hex");
                        for high_word in (ix..).step_by(num_threads.get() as usize) {
                                message.set_high_word(high_word);
                                let mut solver = GoAwaySolver::from(message.clone());
                                let result = solver
                                    .solve::<{ pow_buster::solver::SOLVE_TYPE_MASK }>(target, mask);
                                nonce_attempted
                                    .fetch_add(solver.get_attempted_nonces(), Ordering::Relaxed);
                                ws_churn.fetch_add(1, Ordering::Relaxed);
                                let Some(result) = result else {
                                    continue;
                                };
                                tx.send(result).unwrap();
                            }
                        }
                        Scheme::CerberusDecimal => {
                            for working_set in (ix..).step_by(num_threads.get() as usize) {
                                let Some(message) = CerberusDecimalMessage::new(salt_bytes, working_set) else {
                                    return;
                                };
                                let mut solver = CerberusSolver::from(CerberusMessage::Decimal(message));
                                let result = solver.solve::<{ pow_buster::solver::SOLVE_TYPE_MASK }>(0, mask);
                                nonce_attempted.fetch_add(solver.get_attempted_nonces(), Ordering::Relaxed);
                                ws_churn.fetch_add(1, Ordering::Relaxed);
                                let Some(result) = result else {
                                    continue;
                                };
                                tx.send(result).unwrap();
                            }
                        }
                        Scheme::CerberusBinary => {
                            let prehash = ::blake3::hash(salt_bytes).to_hex();
                            for working_set in (ix..).step_by(num_threads.get() as usize) {
                                let message = CerberusBinaryMessage::new_prehashed(prehash.as_bytes().try_into().unwrap(), working_set);
                                let mut solver = CerberusSolver::from(CerberusMessage::Binary(message));
                                let result = solver.solve::<{ pow_buster::solver::SOLVE_TYPE_MASK }>(0, mask);
                                nonce_attempted.fetch_add(solver.get_attempted_nonces(), Ordering::Relaxed);
                                ws_churn.fetch_add(1, Ordering::Relaxed);
                                let Some(result) = result else {
                                    continue;
                                };
                                tx.send(result).unwrap();
                            }
                        }
                        Scheme::Mcaptcha => {
                            #[cfg(not(feature = "compare-64bit"))]
                            {
                                assert_ne!(target >> 32, u32::MAX as u64, "64-bit comparison is required for this difficulty, rebuild with `compare-64bit` feature");
                            }
                            for working_set in (ix..).step_by(num_threads.get() as usize) {
                                let Some(message) = DecimalMessage::new(salt_bytes, working_set)
                                else {
                                    return;
                                };
                                let mut solver = DecimalSolver::from(message);
                                let result = solver
                                    .solve::<{ pow_buster::solver::SOLVE_TYPE_GT }>(target, mask);
                                nonce_attempted
                                    .fetch_add(solver.get_attempted_nonces(), Ordering::Relaxed);
                                ws_churn.fetch_add(1, Ordering::Relaxed);
                                let Some(result) = result else {
                                    continue;
                                };
                                tx.send(result).unwrap();
                            }
                        }
                        Scheme::Anubis => {
                            #[cfg(not(feature = "compare-64bit"))]
                            {
                                assert_eq!(mask as u32, 0, "64-bit comparison is required for this difficulty, rebuild with `compare-64bit` feature");
                            }
                            for working_set in (ix..).step_by(num_threads.get() as usize) {
                                let Some(message) = DecimalMessage::new(salt_bytes, working_set)
                                else {
                                    return;
                                };
                                let mut solver = DecimalSolver::from(message);
                                let result = solver
                                    .solve::<{ pow_buster::solver::SOLVE_TYPE_MASK }>(0, mask);
                                nonce_attempted
                                    .fetch_add(solver.get_attempted_nonces(), Ordering::Relaxed);
                                ws_churn.fetch_add(1, Ordering::Relaxed);
                                let Some(result) = result else {
                                    continue;
                                };
                                tx.send(result).unwrap();
                            }
                        }
                    });
                });

                if progress {
                    s.spawn(|| {
                        let begin = Instant::now();
                        loop {
                            std::thread::sleep(Duration::from_secs(5));
                            let nonce_attempted = nonce_attempted.load(Ordering::Relaxed);
                            eprintln!(
                                "attempted/estimated: {}/{} ({:.2} MH/s, outer loop churn: {:.2} rps)",
                                nonce_attempted,
                                estimated_work,
                                nonce_attempted as f64
                                    / 1024.0
                                    / 1024.0
                                    / begin.elapsed().as_secs_f64(),
                                ws_churn.load(Ordering::Relaxed) as f64
                                    / begin.elapsed().as_secs_f64()
                            );
                        }
                    });
                }

                let Ok((nonce, result)) = rx.recv() else {
                    eprintln!("no solution found");
                    std::process::exit(1);
                };
                match scheme {
                    Scheme::GoAway => {
                        let mut goaway_token = Align16([b'0'; 64 + 8 * 2]);
                        goaway_token[..64].copy_from_slice(salt_bytes);
                        let nonce_bytes = nonce.to_be_bytes();
                        for i in 0..8 {
                            let high_nibble = nonce_bytes[i] >> 4;
                            let low_nibble = nonce_bytes[i] & 0x0f;
                            goaway_token[64 + i * 2] = if high_nibble < 10 {
                                b'0' + high_nibble
                            } else {
                                b'a' + high_nibble - 10
                            };
                            goaway_token[64 + i * 2 + 1] = if low_nibble < 10 {
                                b'0' + low_nibble
                            } else {
                                b'a' + low_nibble - 10
                            };
                        }

                        let mut goaway_id = Align16([0; 32]);
                        // this doesn't do anything, just make something up for the id
                        for i in 0..4 {
                            let result_bytes: [u8; 4] = result[i].to_ne_bytes();
                            for j in 0..4 {
                                let high_nibble = result_bytes[j] >> 4;
                                let low_nibble = result_bytes[j] & 0x0f;
                                goaway_id[(4 * i + j) * 2] = if high_nibble < 10 {
                                    b'0' + high_nibble
                                } else {
                                    b'a' + high_nibble - 10
                                };
                                goaway_id[(4 * i + j) * 2 + 1] = if low_nibble < 10 {
                                    b'0' + low_nibble
                                } else {
                                    b'a' + low_nibble - 10
                                };
                            }
                        }

                        println!(
                            "__goaway_token={}&__goaway_id={}",
                            core::str::from_utf8(&goaway_token[..]).unwrap(),
                            core::str::from_utf8(&goaway_id[..]).unwrap()
                        );
                    }
                    Scheme::CerberusBinary | Scheme::CerberusDecimal => {
                        let mut hex = [0u8; 64];
                        pow_buster::encode_hex_le(&mut hex, result);
                        println!(
                            "solution={nonce}&response={}",
                            core::str::from_utf8(&hex).unwrap()
                        );
                    }
                    Scheme::Anubis | Scheme::Mcaptcha => {
                        let mut hex = [0u8; 64];
                        pow_buster::encode_hex(&mut hex, result);
                        println!(
                            "nonce={nonce}&response={}",
                            core::str::from_utf8(&hex).unwrap()
                        );
                    }
                }
                std::process::exit(0);
            });
        }
        #[cfg(feature = "client")]
        SubCommand::Anubis { url } => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async move {
                let client = pow_buster::client::build_client().build().unwrap();
                let response = pow_buster::client::solve_anubis(&client, &url)
                    .await
                    .unwrap();
                println!("cookie: {}", response);
            });
        }
        #[cfg(feature = "client")]
        SubCommand::Cerberus { url } => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let client = pow_buster::client::build_client().build().unwrap();
                let response = pow_buster::client::solve_cerberus(&client, &url)
                    .await
                    .unwrap();
                println!("cookie: {}", response);
            });
        }
        #[cfg(feature = "client")]
        SubCommand::GoAway { url } => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async move {
                let client = pow_buster::client::build_client().build().unwrap();
                let response = pow_buster::client::solve_goaway_js_pow_sha256(&client, &url)
                    .await
                    .unwrap();
                println!("cookie: {}", response);
            });
        }
        #[cfg(feature = "live-throughput-test")]
        SubCommand::Live {
            api_type,
            host,
            site_key,
            n_workers,
            n_threads,
        } => {
            let api_type: ApiType = api_type.parse().unwrap();
            let n_workers = n_workers.unwrap_or_else(|| num_cpus::get() as u32);
            eprintln!("You are hitting host {}, n_workers: {}", host, n_workers);

            let mut pb = rayon::ThreadPoolBuilder::new();
            if let Some(n_threads) = n_threads {
                pb = pb.num_threads(n_threads as usize);
            }

            let pool = pb.build().unwrap();
            let semaphore = Arc::new(tokio::sync::Semaphore::new(pool.current_num_threads()));
            let pool = Arc::new(pool);

            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async move {
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
                    let semaphore = semaphore.clone();
                    tokio::spawn(async move {
                        let client = pow_buster::client::build_client()
                            .build()
                            .unwrap();

                        match api_type {
                            ApiType::Mcaptcha => loop {
                                let mut iotime = 0;
                                let start = Instant::now();
                                match pow_buster::client::solve_mcaptcha_ex(
                                    &pool,
                                    &client,
                                    &host_clone,
                                    &site_key_clone,
                                    &mut iotime,
                                )
                                .await
                                {
                                    Ok(_) => {
                                        succeeded_clone.fetch_add(1, Ordering::Relaxed)
                                    }
                                    Err(_) => failed_clone.fetch_add(1, Ordering::Relaxed),
                                };
                                let mut packed_time = start.elapsed().as_micros() as u64 / 16;
                                packed_time <<=32;
                                packed_time += iotime as u64 / 16;
                                packed_time_clone.fetch_add(packed_time, Ordering::Relaxed);
                            },
                            ApiType::Anubis => loop {
                                let mut iotime = 0;
                                let start = Instant::now();
                                match pow_buster::client::solve_anubis_ex(
                                    &client,
                                    &host_clone,
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
                                let mut packed_time = start.elapsed().as_micros() as u64 / 16;
                                packed_time <<= 32;
                                packed_time += iotime as u64 / 16;
                                packed_time_clone.fetch_add(packed_time, Ordering::Relaxed);
                            },
                            ApiType::Cerberus => loop {
                                let mut iotime = 0;
                                let start = Instant::now();
                                match pow_buster::client::solve_cerberus_ex(&client, &host_clone, &mut iotime)
                                    .await {
                                        Ok(_) => {
                                            succeeded_clone.fetch_add(1, Ordering::Relaxed);
                                        }
                                        Err(e) => {
                                            eprintln!("cerberus error: {:?}", e);
                                            failed_clone.fetch_add(1, Ordering::Relaxed);
                                        }
                                    };
                                let mut packed_time = start.elapsed().as_micros() as u64 / 16;
                                packed_time <<= 32;
                                packed_time += iotime as u64 / 16;
                                packed_time_clone.fetch_add(packed_time, Ordering::Relaxed);
                            },
                            ApiType::CapJs => loop {
                                let mut iotime = 0;
                                let start = Instant::now();
                                match pow_buster::client::solve_capjs_worker(&pool, &client, &host_clone, &site_key_clone, &mut iotime, &semaphore)
                                    .await {
                                        Ok(_) => {
                                            succeeded_clone.fetch_add(1, Ordering::Relaxed);
                                        }
                                        Err(e) => {
                                            eprintln!("capjs error: {:?}", e);
                                            failed_clone.fetch_add(1, Ordering::Relaxed);
                                        }
                                    };
                                let mut packed_time = start.elapsed().as_micros() as u64 / 16;
                                packed_time <<= 32;
                                packed_time += iotime as u64 / 16;
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
            if limit == 0 {
                limit = u64::MAX;
            }

            let mut app = match check_origin {
                Some(check_origin) => {
                    let expected_origin = url::Url::parse(&check_origin).unwrap();
                    pow_buster::server::AppState::new(n_workers, limit)
                        .router_with_origin_check(expected_origin)
                }
                None => pow_buster::server::AppState::new(n_workers, limit).router(),
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
