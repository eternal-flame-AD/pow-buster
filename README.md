# simd-mCaptcha

A fast, adversarially implemented mCaptcha PoW solver.

Note: you don't need to clone the submodule, it is only used as a pointer for what I used to for benchmarking.

## Limitations

We took some shortcuts and it is not a completely general solution.

- Currently only supports about 90.62% of the sites, depending on how long their salt is. 

  If you want an "always works" solution implement yourself, it's not that complicated, just that it is much harder to provide a single generic solution to cover every subcase of the remaining 9.38%. 

- Requires AVX512 CPU
- Only builds on nightly Rust because avx512 intrinsics are not stable yet
- A $1 - P_{geom}(64e7, 1/\text{difficulty})$ chance of failure for any particular hash, which for 1e8 (takes about 20 seconds on a browser) is about 0.1%

## Ethical Disclaimer (i.e. How Dare you Publish this?)

If you _really_ want to attack a real website with mCaptcha, you should:

1. Get a GPU (or fancy FPGAs).
2. Download an off the shelf SHA-2 implementation (C++/DPC++/HDL/SPIR-V/...).
3. Compile/HLS/Synthesize it to your GPU/FPGA.
4. Profit.

This is an academic demo of optimization space for CPU only solutions.

## Benchmark

### Formal Benchmark

Speedup against official solution, reported by Criterion.rs, single-threaded (DNF = cannot produce enough samples in 120s for statistical significance):


| Difficulty factor | SIMD (ms) | Official Autovectorized (ms) | Official Generic X86 (ms) |
| ----------------- | --------- | ---------------------------- | ------------------------- |
| 50_000            | 0.642     | 2.620                        | 5.065                     |
| 100_000           | 1.313     | 5.241                        | 10.396                    |
| 1_000_000         | 13.619    | 50.579                       | 98.235                    |
| 4_000_000         | 58.464    | 177.98                       | 345.48                    |
| 10_000_000        | 140.95    | 510.64                       | DNF                       |

WASM benchmark reported by [official benchmark page](https://mcaptcha.github.io/benches/), this is _only_ to illustrate what difficulty numbers are realistic for a website, they are _not_ directly comparable to the Criterion.rs benchmark as they do not have a proper warm-up and statistical testing like Criterion.rs does:

```
User Agent: Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0
Hardware concurrency: 32
```

| Difficulty factor | Duration(ms) |
| ----------------- | ------------ |
| 500_000           | 238          |
| 1_000_000         | 224          |
| 1_500_000         | 223          |
| 2_000_000         | 223          |
| 2_500_000         | 845          |
| 3_000_000         | 844          |
| 3_500_000         | 2161         |
| 4_000_000         | 2147         |
| 4_500_000         | 2145         |

### End to End Benchmark

A default official docker-compose instance is used for the benchmark target  (the default 33-byte salt was unchanged).

The following were configured for difficulty 5_000_000 (default max tier).

```sh
> RUSTFLAGS="-Ctarget-cpu=native" \
    cargo run --features cli --release -- live \
    --site-key emPgsyJP5SWeNEot2IBbg0ezOE1GNhof \
    --do-control >/dev/null

You are hitting host http://localhost:7000
running 10 seconds of control sending random proofs
[0.0s] succeeded: 0, failed: 0, 5s: 0.0rps, 5s_failed: 0.0rps
[5.0s] succeeded: 693, failed: 0, 5s: 138.6rps, 5s_failed: 0.0rps
[10.0s] succeeded: 1387, failed: 0, 5s: 138.8rps, 5s_failed: 0.0rps
Fake Proof Control: 3859 requests in 10.1 seconds, 382.9 rps
[15.0s] succeeded: 2552, failed: 0, 5s: 233.0rps, 5s_failed: 0.0rps
[20.0s] succeeded: 3772, failed: 0, 5s: 244.0rps, 5s_failed: 0.0rps
[25.0s] succeeded: 4973, failed: 0, 5s: 240.2rps, 5s_failed: 0.0rps
[30.0s] succeeded: 6099, failed: 0, 5s: 225.2rps, 5s_failed: 0.0rps
[35.0s] succeeded: 7260, failed: 0, 5s: 232.2rps, 5s_failed: 0.0rps
[40.0s] succeeded: 8435, failed: 0, 5s: 235.0rps, 5s_failed: 0.0rps
[45.0s] succeeded: 9619, failed: 0, 5s: 236.8rps, 5s_failed: 0.0rps
[50.0s] succeeded: 10819, failed: 0, 5s: 240.0rps, 5s_failed: 0.0rps
[55.0s] succeeded: 12018, failed: 0, 5s: 239.8rps, 5s_failed: 0.0rps
[60.0s] succeeded: 13249, failed: 0, 5s: 246.2rps, 5s_failed: 0.0rps
```

All 32 cores of a AMD Ryzen 9 7950X are used for the end-to-end benchmark.

## Contributing

Contributions are welcome, roughly in priority order we want:

1. We need 6 special cases where messages cross block boundaries, it needs some SIMD (particularly register pressure management) expertise but should not be too hard. A macro or typenum generic solution would be best.
2. General profiling and further optimization.
3. An AVX-2 solution and corresponding benchmark.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

This project contains some copy pasted or minimally modified code from the [sha2](https://crates.io/crates/sha2) crate, in the core SHA-2 routine in [sha256.rs](src/sha256.rs).

## AI Disclaimer

YES, this crate includes AI generated code, does it matter?

- Can _anyone_ use AI to write this particular solution? Absolutely not, you have to give it enough context or direction, which requires human intelligence.
- Is the core logic generated or conceived by an AI? Absolutely not, it can't.
- Did AI "plagiarize" this solution? Absolutely, it plagiarized the FIPS 180-4 SHA-2 IV, round constants, and test vector, and "subtly" embedded it into my code, go figure if it is important to you.

  Little challenge to "human touch"/"tool usage" enjoyers: ssshhhhh... actually the AES key of my password manager is the SHA-256 of all the bytes in the source code that is typed by my keyboard concatenated together (sort files in alphabetical order), give it a crack! $1M reward!

That is why I argue gatekeeping or who is "good at programming" based on "AI usage" is a bad idea.

