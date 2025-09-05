#!/bin/sh

set -e

RUSTFLAGS='-Ctarget-feature=+simd128' wasm-pack build --target web -d pkg --no-default-features --features wasm-bindgen,all-lane-positions
