use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use pow_buster::Align16;

#[rustfmt::skip]
macro_rules! repeat3 {
    ($i:ident, $c:block) => {
        { let $i = 0; $c; }
        { let $i = 1; $c; }
        { let $i = 2; $c; }
    };
}

pub fn bench_itoa7(c: &mut Criterion) {
    let mut group: criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> =
        c.benchmark_group("bench_itoa7");
    group.sample_size(100);

    group.throughput(Throughput::Elements(1));

    let mut x = 10_000_000u32;
    const METHODS: [&str; 3] = ["div_mod", "simd", "octal"];
    repeat3!(method, {
        group.bench_with_input(
            BenchmarkId::new("itoa7", METHODS[method]),
            &METHODS[method],
            |b, &_| {
                b.iter(|| {
                    x -= 1;
                    if x == 0 {
                        x = 10_000_000u32;
                    }
                    let mut buf = Align16([0u8; 8]);
                    match method {
                        0 => {
                            const BSWAP: [usize; 8] = [3, 2, 1, 0, 7, 6, 5, 4];
                            let mut copy = x;
                            for i in (0..7).rev() {
                                buf[BSWAP[i]] = (copy % 10) as u8 + b'0';
                                copy /= 10;
                            }
                            buf[4] = 0x80;
                        }
                        1 => pow_buster::strings::simd_itoa8::<7, true, 0x80>(&mut buf, x),
                        2 => pow_buster::strings::to_octal_7::<true, 0x80, 1>(&mut buf, x),
                        _ => unreachable!(),
                    }
                    buf
                })
            },
        );
    });
}

criterion_group!(benches, bench_itoa7);
criterion_main!(benches);
