use criterion::{Criterion, criterion_group, criterion_main};

pub fn bench_proof_go_to_social(c: &mut Criterion) {
    use std::time::Duration;

    use criterion::Throughput;
    use pow_buster::message::GotoSocialAoSoALUT16;

    let mut lut = GotoSocialAoSoALUT16::new();
    let lut_start = std::time::Instant::now();
    lut.build(400000);
    let max_nonce = lut.view().max_supported_nonce();
    let lut_duration = lut_start.elapsed();
    eprintln!(
        "Time to build LUT: {:?} ({:.2} nonces/sec)",
        lut_duration,
        max_nonce as f64 / lut_duration.as_secs_f64()
    );

    #[cfg(target_feature = "avx512f")]
    {
        let mut group = c.benchmark_group("bench_proof_go_to_social");
        group.sample_size(50);
        group.warm_up_time(Duration::from_secs(8));
        group.measurement_time(Duration::from_secs(15));

        let center = 1048576;
        group.throughput(Throughput::Elements(max_nonce - center));

        let mut jitter = 0u16;
        let mut sign = false;
        let mut seed1 = 0u64;
        let mut seed2 = 0u64;
        group.bench_function("proof_go_to_social", |b| {
            b.iter_batched(
                || {
                    use sha2::{Digest, Sha256};

                    seed1 += 1;
                    seed2 += 1;
                    let answer = core::hint::black_box(
                        (center as i64 + (jitter as i64) * (if sign { 1 } else { -1 })) as u64,
                    );
                    let seed1_bytes = seed1.to_be_bytes();
                    let seed2_bytes = seed2.to_be_bytes();
                    let mut hasher = Sha256::new();
                    hasher.update(&seed1_bytes);
                    hasher.update(&seed2_bytes);
                    let nonce_string = answer.to_string();
                    hasher.update(&nonce_string.as_bytes());
                    let image = hasher.finalize();
                    jitter = jitter.wrapping_add(1);
                    sign = !sign;
                    (seed1_bytes, seed2_bytes, image, answer)
                },
                |(seed1_bytes, seed2_bytes, image, answer)| {
                    use pow_buster::{
                        message::GoToSocialMessage,
                        solver::{Solver, avx512::GoToSocialSolver},
                    };

                    let target = GoToSocialSolver::extract_target(&image).unwrap();

                    let mut seed_bytes = [0; 16];
                    seed_bytes[..8].copy_from_slice(&seed1_bytes);
                    seed_bytes[8..].copy_from_slice(&seed2_bytes);

                    let message = GoToSocialMessage::new(seed_bytes);
                    let mut solver = GoToSocialSolver::new(lut.view(), message);

                    let solution = solver
                        .solve_nonce_only::<{ pow_buster::solver::SOLVE_TYPE_DH_PREIMAGE }>(
                            target,
                            u64::MAX,
                        )
                        .unwrap();
                    assert_eq!(solution, answer);
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
}

#[cfg(target_feature = "avx512f")]
criterion_group!(benches, bench_proof_go_to_social);

#[cfg(target_feature = "avx512f")]
criterion_main!(benches);
