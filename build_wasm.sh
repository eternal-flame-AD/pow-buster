#!/bin/sh

set -e

RUSTFLAGS='-Ctarget-feature=+simd128' wasm-pack build --target web -d pkg --no-default-features --features adapter,all-lane-positions

for file in pkg/*.wasm; do
  gzip -9knf "$file"
done