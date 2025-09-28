use std::io::Cursor;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use pow_buster::Align16;

#[rustfmt::skip]
macro_rules! repeat4 {
    ($i:ident, $c:block) => {
        #[allow(non_upper_case_globals)]
        {
            { const $i: usize = 0; $c; }
            { const $i: usize = 1; $c; }
            { const $i: usize = 2; $c; }
            { const $i: usize = 3; $c; }
        }
    };
}

pub fn bench_itoa7(c: &mut Criterion) {
    let mut group: criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> =
        c.benchmark_group("bench_itoa7");
    group.sample_size(200);

    group.throughput(Throughput::Elements(1));
    const METHODS: [&str; 4] = [
        "format_bswap",
        "div_mod",
        #[cfg(target_feature = "avx512f")]
        {
            "simd_avx512"
        },
        #[cfg(not(target_feature = "avx512f"))]
        {
            "simd_avx2"
        },
        #[cfg(target_feature = "avx512f")]
        "octal_avx512",
        #[cfg(not(target_feature = "avx512f"))]
        "octal",
    ];
    repeat4!(method, {
        if cfg!(target_feature = "avx2") || method != 2 {
            let base = if method == 3 { 8u32 } else { 10u32 };
            let mut x = base.pow(7);
            group.bench_with_input(
                BenchmarkId::new("itoa7", METHODS[method]),
                &METHODS[method],
                |b, &_| {
                    b.iter(|| {
                        x += 1;
                        if x == base.pow(8) {
                            x = base.pow(7);
                        }
                        let mut buf = Align16([0u8; 8]);
                        match method {
                            0 => {
                                // 40 miter/s
                                unsafe {
                                    use std::io::Write;
                                    let mut buf = Cursor::new(buf.as_mut_slice());
                                    write!(buf, "{}", x).unwrap_unchecked();
                                    buf.write_all(b"\x80").unwrap_unchecked();
                                }
                                let mut out_ptr = buf.as_mut_slice().as_mut_ptr().cast::<u32>();
                                unsafe {
                                    *out_ptr = (*out_ptr).swap_bytes();
                                    out_ptr = out_ptr.add(1);
                                    *out_ptr = (*out_ptr).swap_bytes();
                                }
                            }
                            1 => {
                                // 225 miter/s
                                const BSWAP: [usize; 8] = [3, 2, 1, 0, 7, 6, 5, 4];
                                let mut copy = x;
                                for i in (0..7).rev() {
                                    buf[BSWAP[i]] = (copy % 10) as u8 + b'0';
                                    copy /= 10;
                                }
                                buf[4] = 0x80;
                            }
                            // 925 miter/s on AVX512; 600 miter/s on AVX2
                            2 => pow_buster::strings::simd_itoa8::<7, true, 0x80>(&mut buf, x),
                            // 1.7 giter/s on AVX512; 650 miter/s on AVX2
                            3 => pow_buster::strings::to_octal_7::<true, 0x80, 1>(&mut buf, x),
                            _ => unreachable!(),
                        }
                        buf
                    })
                },
            );
        }
    });
}

criterion_group!(benches, bench_itoa7);
criterion_main!(benches);
