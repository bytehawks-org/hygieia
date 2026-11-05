#!/usr/bin/env bash
# Build the WASM engine into ./pkg. Requires: rustup target wasm32-unknown-unknown,
# wasm-bindgen-cli matching the wasm-bindgen crate version (see Cargo.lock).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -p hygeia-blocker --target wasm32-unknown-unknown --release
wasm-bindgen --target web --no-typescript --out-dir extension/pkg \
  target/wasm32-unknown-unknown/release/hygeia_blocker.wasm
echo "built extension/pkg ($(du -h extension/pkg/*.wasm | cut -f1) wasm)"
