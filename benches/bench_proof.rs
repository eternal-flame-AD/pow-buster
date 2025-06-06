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
    for difficulty in [50_000, 100_000, 1_000_000, 4_000_000, 10_000_000] {
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
                    SingleBlockSolver::new(&counter.to_ne_bytes()).expect("solver is None");

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
    }
}

criterion_group!(benches, bench_proof);
criterion_main!(benches);
