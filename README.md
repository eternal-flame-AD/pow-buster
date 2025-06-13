# simd-mCaptcha

## Table of Contents

- [simd-mCaptcha](#simd-mcaptcha)
  - [Table of Contents](#table-of-contents)
  - [Limitations](#limitations)
  - [Ethical Disclaimer (i.e. the "How Dare you Publish this?" question)](#ethical-disclaimer-ie-the-how-dare-you-publish-this-question)
    - [Why not private disclosure?](#why-not-private-disclosure)
    - [Can't this be used to attack a real website?](#cant-this-be-used-to-attack-a-real-website)
  - [Benchmark](#benchmark)
    - [Formal Benchmark](#formal-benchmark)
    - [Official Widget Benchmark](#official-widget-benchmark)
    - [End to End Benchmark](#end-to-end-benchmark)
      - [CPU only](#cpu-only)
      - [wgpu Solution](#wgpu-solution)
    - [Throughput Sanity Check](#throughput-sanity-check)
  - [Security Implications](#security-implications)
  - [Server-Side Performance Observations](#server-side-performance-observations)
  - [Future Work (i.e. Okay, so what would be a good PoW then?)](#future-work-ie-okay-so-what-would-be-a-good-pow-then)
  - [Contributing](#contributing)
  - [License](#license)
  - [AI Disclaimer](#ai-disclaimer)

A fast, adversarially implemented mCaptcha PoW solver, targeting AVX-512 and SPIR-V compute (shader in WGSL).

Tracking issue for upstream: [mCaptcha/mCaptcha#186](https://github.com/mCaptcha/mCaptcha/issues/186)

The benchmarks demonstrate a significant performance gap between browser-based JavaScript execution and native implementations (both optimized CPU and unoptimized GPU), suggesting fundamental challenges for PoW-based browser CAPTCHA systems.

## Limitations

We assume you have a relatively modern and powerful platform, specifically:

- Requires AVX-512 CPU or a [wgpu](https://wgpu.rs) compatible GPU
- Only builds on nightly Rust because avx512 intrinsics are not stable yet, it also currently doesn't build on non-x86_64 targets.
- This is designed for "low", practical-for-a-website difficulty settings, A $1 - P_{geom}(80e7, 1/\text{difficulty})$ chance of failure for any particular challenge, which for 1e8 (takes about 10 seconds on a browser) is about 0.03%, the GPU solver has much lower failure rate.
- The WGSL implementation is not optimized for performance, it has some major problems:
  1. Didn't use vectorized arithmetic.
  2. Didn't use workgroup shared memory.
  3. Didn't properly batch challenges.
  4. Didn't generate specialized optimal kernel code.
  5. How to efficiently fetch challenges and feed to the GPU is completely implemented synchronously.

  However I want to keep this a limitation, I do not intend on writing "attack ready" code.

## Ethical Disclaimer (i.e. the "How Dare you Publish this?" question)

### Why not private disclosure? 

This isn't a vulnerability nor anything previously unknown. I didn't "skip" or somehow "simplify" any number of SHA-2 rounds, it is a materialized analysis of performance characteristics of the system. Everybody knows PoW system loses protection margin using hardware or software optimizations.
 
Website operators deploying mCaptcha bear the responsibility to understand the performance characteristics and security implications of their chosen PoW parameters, and whether that protects against their identified threat. __The purpose of this research is to provide the statistical analysis and empirical validation data necessary for informed deployment decisions, including optimized CPU only solutions.__ 

### Can't this be used to attack a real website?

Yes and no, yes, if you can reproduce the benchmark you by definition _has_ to have the capacity to hit an mCaptcha endpoint much faster than clicking the Captcha widget, but also no, I don't think it's too complicated to do much better than this PoC, for a particular website. This is an academic demo of optimization space for non-batched "universal" CPU and GPU solutions, it is not economical for wielding a true targeted attack.

If you _really_ want to attack a real website with mCaptcha, you should:

1. Get a GPU (or fancy FPGAs).
2. Download an off the shelf SHA-2 implementation (C++/DPC++/HDL/SPIR-V/...), whatever is fastest for your platform and most specialized for your target configuration.
3. Tune the batching to minimize device transfer overhead for normal difficulty settings.
4. Compile/HLS/Synthesize it to your GPU/FPGA.
5. Profit.

## Benchmark

TLDR; My extrapolated throughput for each approach, corroborated by empirical and formal benchmarks:

![Extrapolated throughput](plots/time.png)


Note: To reproduce, you don't need to clone the submodule, it is only used as a pointer for what I used to for benchmarking.

### Formal Benchmark

Speedup against official solution, reported by Criterion.rs, single-threaded:

Results on AMD Ryzen 9 7950X, 32 cores (wgpu uses NVIDIA RTX 4070), when supported, single-hash number comes first (there is 90% chance your deployment is single-hash, this vagueness is IMO design oversight by the mCaptcha team), double-hash number comes second, all numbers are in milliseconds, compiled with `-Ctarget-cpu=native` unless otherwise specified.


| DFactor    | AVX-512  [^1] | Safe Optimized [^2] | Official (*)  | Official Generic x64 (*) | wgpu (Vulkan) |
| ---------- | ------------- | ------------------- | ------------- | ------------------------ | ------------- |
| 50_000     | 0.623/1.066   | 1.606/?             | 2.940/4.654   | 5.3261/9.683             | 0.097         |
| 100_000    | 1.268/2.232   | 3.314/?             | 5.089/10.471  | 9.8579/24.664            | 0.126         |
| 1_000_000  | 11.574/20.610 | 42.727/?            | 65.015/42.353 | 137.78/97.271            | 0.489         |
| 4_000_000  | 44.254/52.155 | 92.932/?            | 227.14/162.24 | 489.67/382.04            | 1.844         |
| 10_000_000 | 113.47/145.46 | 410.26/?            | 505.85/707.39 | DNS                      | 4.201         |

(*) = Since official solution allocated a variable length string per iteration, it is pretty difficult to get it to perform it stably both in terms of how many blocks to hash and how long the allocation takes, serious non-linear performance degradation seems to be observed and it is likely attributed to re-allocation overhead.
(?) = not implemented, but I expect close to a clean double

[^1]: Results on a Netcup (R) RS 4000 G11 (26 EUR/month at the time of writing, backed by AMD EPYC 9634), shows comparable performance with a ~15-20% slowdown across the board, with relatively similar speedup ratio.
[^2]: Represents a custom implementation using safe, externally-validated cryptographic abstractions only and no platform-specific optimizations.

### Official Widget Benchmark

WASM benchmark reported by [official benchmark page](https://mcaptcha.github.io/benches/), this is _only_ to illustrate what difficulty numbers are realistic for a website, they are _not_ directly comparable to the Criterion.rs benchmark as they do not have a proper warm-up and statistical testing like Criterion.rs does:

```text
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

#### CPU only

The following were configured for difficulty 5_000_000 (default max tier).

10 consecutive solutions using the official Captcha widget:  [0.105s, 1.69s, 1.06s, 1.89s, 1.91s, 1.09s, 1.80s, 0.97s, 0.71s, 1.15s, 3.59s, 1.09s, 0.14s, 3.98s, 1.26s, 1.05s, 1.26s]

```sh
> RUSTFLAGS="-Ctarget-cpu=native" \
    cargo run --features cli --release -- live \
    --site-key emPgsyJP5SWeNEot2IBbg0ezOE1GNhof \
    --n-workers 38 \
    --do-control >/dev/null

You are hitting host http://localhost:7000
running 10 seconds of control sending random proofs
[0.0s] succeeded: 0, failed: 0, 5s: 0.0rps, 5s_failed: 0.0rps
[5.0s] succeeded: 725, failed: 0, 5s: 145.0rps, 5s_failed: 0.0rps
[10.0s] succeeded: 1453, failed: 0, 5s: 145.6rps, 5s_failed: 0.0rps
Fake Proof Control: 3732 requests in 10.1 seconds, 369.2 rps
[15.0s] succeeded: 2690, failed: 0, 5s: 247.4rps, 5s_failed: 0.0rps
[20.0s] succeeded: 3902, failed: 0, 5s: 242.4rps, 5s_failed: 0.0rps
[25.0s] succeeded: 5110, failed: 0, 5s: 241.6rps, 5s_failed: 0.0rps
[30.0s] succeeded: 6368, failed: 0, 5s: 251.6rps, 5s_failed: 0.0rps
[35.0s] succeeded: 7587, failed: 0, 5s: 243.8rps, 5s_failed: 0.0rps
[40.0s] succeeded: 8840, failed: 0, 5s: 250.6rps, 5s_failed: 0.0rps
[45.0s] succeeded: 10081, failed: 0, 5s: 248.2rps, 5s_failed: 0.0rps
[50.0s] succeeded: 11302, failed: 0, 5s: 244.2rps, 5s_failed: 0.0rps
[55.0s] succeeded: 12505, failed: 0, 5s: 240.6rps, 5s_failed: 0.0rps
[60.0s] succeeded: 13761, failed: 0, 5s: 251.2rps, 5s_failed: 0.0rps
```

All 32 cores of a AMD Ryzen 9 7950X are used for the end-to-end benchmark. It seems we are at the bottleneck of the server being able to record successful attempts, as further performance tuning only show improvement in offline benchmarks.

#### wgpu Solution

This is a `wgpu` powered non-batched solution (each dispatch only solves one nonce), running at the highest difficulty (50_000_000) where the official Captcha widget do not break due to timeout (30 seconds):

Note: this is ran at the highest difficulty to minimize the overhead of non-batched kernel launch. This is an academic demo not designed to be "efficient" to attack the most realistic settings.

10 consecutive solutions using the official Captcha widget: [3.26s, 1.86s, 2.20s, 5.76s, 10.20s, 2.13s, 8.29s, 23.09s, 3.21s, 2.40s, 15.00s, 1.20s, 23.40s, 9.00s, 29.40s, 2.40s, 12.60s, 1.80s, 4.80s]


```sh
target/release/mcaptcha_pow_solver  live \
    --site-key 0wSp29HfHz2HPbro0vLtoLubQcMtocv7 \
    --do-control \
    --use-gpu \
    --n-workers 4 \
    >/dev/null

You are hitting host http://localhost:7000
running 10 seconds of control sending random proofs
[0.0s] succeeded: 1, failed: 0, 5s: 0.2rps, 5s_failed: 0.0rps
[5.0s] succeeded: 277, failed: 0, 5s: 55.2rps, 5s_failed: 0.0rps
Fake Proof Control: 5462 requests in 10.0 seconds, 545.7 rps
[10.0s] succeeded: 563, failed: 0, 5s: 57.2rps, 5s_failed: 0.0rps
[15.0s] succeeded: 853, failed: 0, 5s: 58.0rps, 5s_failed: 0.0rps
[20.0s] succeeded: 1158, failed: 0, 5s: 61.0rps, 5s_failed: 0.0rps
[25.0s] succeeded: 1407, failed: 0, 5s: 49.8rps, 5s_failed: 0.0rps
[30.0s] succeeded: 1691, failed: 0, 5s: 56.8rps, 5s_failed: 0.0rps
[35.0s] succeeded: 1934, failed: 0, 5s: 48.6rps, 5s_failed: 0.0rps
[40.0s] succeeded: 2187, failed: 0, 5s: 50.6rps, 5s_failed: 0.0rps
[45.0s] succeeded: 2453, failed: 0, 5s: 53.2rps, 5s_failed: 0.0rps
[50.0s] succeeded: 2676, failed: 0, 5s: 44.6rps, 5s_failed: 0.0rps
[55.0s] succeeded: 2924, failed: 0, 5s: 49.6rps, 5s_failed: 0.0rps
[60.0s] succeeded: 3195, failed: 0, 5s: 54.2rps, 5s_failed: 0.0rps
```

### Throughput Sanity Check

Just as a sanity check to make sure we are actually performing checks with effective data parallelism and the difference is not just because implementation overhead, here are the numbers from OpenSSL with SHA-NI support:

```sh
> openssl speed sha256
type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
sha256          207107.04k   645724.06k  1507281.95k  2220402.22k  2655970.10k  2687872.17k
```

The single-threaded throughput for OpenSSL with SHA-NI support is about 12.94 MH/s (828.2MB/s) single block, 42.00 MH/s (2.86 GB/s) continuous, for us it is about 61.82 MH/s (3.96 GB/s) single-hash, 52.907 MH/s (6.77 GB/s) double-hash at difficulty closest to default highest (4e6).

The peak throughput reported by `openssl speed -multi 32 sha256` is 239.76 MH/s (15.34 GB/s) single block, 1.14 GH/s (73.24 GB/s) continuous. The multi-threaded rash rate derived from formal benchmark is 1.186 GH/s (95% conf: 1.1830, 1.1881, 75.88GB/s derived) at default highest difficulty (5e6) for single-hash, 725.68 MH/s (95% conf: 722.05, 729.19, 92.89 GB/s derived) for double-hash case.

## Security Implications

The performance benchmarks demonstrate a fundamental challenge for browser-based PoW CAPTCHA systems:

1. The performance gap between optimized native code and browser JavaScript (>100x) makes it impractical to set difficulty levels that are both:
   - High enough to prevent automated solving on native hardware
   - Low enough to be solvable in browsers within reasonable timeouts

2. The GPU implementation, even unoptimized, shows that commodity hardware can solve high-difficulty challenges orders of magnitude faster than browsers.

These findings suggest that both designing and adopting a PoW-based CAPTCHA systems may need additional verification mechanisms beyond empirical testing.

## Server-Side Performance Observations

> Wait, why is the "fake proof" RPS so low? (only ~650RPS)?

An important observation from our end-to-end testing: even when sending **completely invalid proofs** that should be rejected immediately, the mCaptcha server could only handle ~650 RPS on a 32-core AMD Ryzen 9 7950X with very low effective CPU utilization.

A brief analysis of the server-side code reveals significant architectural overhead of the mCaptcha system itself, it includes overheads like:

- String construction/cloning (expensive memory allocation)
- Async context switch (to query Redis)
- Sync context switch (back to thread pool)
- Improperly implemented spin loop without yielding (try_recv() in a tight loop - no PAUSE, no parking, no yielding)
- HashMap/VecDeque based per-IP queuing with no eviction (memory leak with IPv6 /64 prefixes?)
- Cross-thread message passing for every single verification

All for a single SHA-256 verification. The "correct" solution is simply act as a timestamp server, send the signed timestamp to the client statelessly, and on challenge response verify the timestamp is within acceptable range, all would be completed in likely fewer CPU cycles than it took to parse and respond to a JSON-HTTP request.

This finding is corroborated by the original developer's [own performance testing](https://github.com/mCaptcha/mCaptcha/issues/37), where their "DDoS protection" demonstration showed that on their i7-7950H:
- **"Protected" server**: 60-80 RPS sustained with 5+ second response times  
- **"Unprotected" server**: 150 RPS maximum before collapse, with no significantly higher response time.

The fact that our optimized CPU solver can generate **250 RPS** of valid solutions (i.e. ~1.2 Ghashes/s) while our own hosted server can only handle **650 RPS** of any requests (effectively one single hash per request) demonstrates that the protection margin is minimal - less than 3x between "protected" then the "captcha" itself is completely overwhelmed, for a single commodity CPU.

## Future Work (i.e. Okay, so what would be a good PoW then?)

My own early thoughts, all speculative:

The intuitive solution is to use a memory bound (script, Argon2, etc.) function, but I argue that is also a bad idea. For the scale of services that require a PoW Captcha, they likely _cannot_ take 100 RPS of even just validating a memory hard function. They need a semaphore, which is using a DDoS attack vector to substitute another (the endpoint being protected).

The issue with using PoW in a "one-on-one" configuration (unlike cryptocurrency like BTC where it is "one-on-all") is, in fact, even if the function is perfect (an ideal VDF), most services scales sub-linearly (buying twice as much hardware don't serve twice as much users) but you need to adapt to the lowest common denominator for legitimate users, and the attacker would use the fastest and most economic solution possible (which is often superlinear for most intents and purposes when stacking up better hardware and more optimizations), which often is at least one order of magnitude if not more different. So trying to do any kind of pure PoW, for a website, is a losing game.

I think a better avenue to minimize "I got x times faster by doing ..." would be to add fixed constant factor, IO-serialized "mini-PoW" challenges that are easily solved but the challenger needs to submit the results for the first sub-goal to get the input for the next sub-goal (which can be implemented using cheap cryptographic primitives statelessly). 

The benefit of this approach is that it makes it incredibly difficult to get an advantage using more compute-oriented hardware, for example, GPU would never be able to amortize the transfer and dispatch overhead, and with a fixed large constant factor (IO latency), any data parallelism solution would be unlikely to get multiple folds of speedup. Additionally, the server can randomize and withhold the exact number of steps required, which makes building purpose-built solvers (like ASICs) almost impossible. 

On the server end, trying to respond to a particular WebSocket message or HTTP request is incredibly fast (often on the order of 1e5+ RPS), and up to 10 round trips are unlikely to make a significant difference than the capacity of 1 round trip for a traditional pure PoW system.

And obviously, IO-bound task are much "greener" and discriminate much less against less powerful hardware, both are good properties for "the good guys".

## Contributing

Contributions are welcome, roughly in priority order we want:

1. We need 6 special cases where messages cross block boundaries, it needs some SIMD (particularly register pressure management) expertise but should not be too hard. A macro or typenum generic solution would be best.
2. General profiling and further optimization.
3. Would be nice to have a real WebGPU solution that runs side-by-side with the current real Captcha widget.
4. An AVX-2 solution and corresponding benchmark. (low priority as this isn't really a "product")

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

