#!/usr/bin/env bash
set -e

echo "======================================="
echo "AIX8 COMPLETE CRYPTO TEST SUITE"
echo "======================================="

echo
echo "Checking Rust installation..."
if ! command -v cargo >/dev/null 2>&1; then
    echo "Rust not installed. Installing Rust..."
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    source $HOME/.cargo/env
fi

echo
echo "Updating Rust toolchain..."
rustup update

echo
echo "Checking cargo-fuzz..."
if ! command -v cargo-fuzz >/dev/null 2>&1; then
    echo "Installing cargo-fuzz..."
    cargo install cargo-fuzz
fi

echo
echo "Checking AFL..."
if ! command -v cargo-afl >/dev/null 2>&1; then
    echo "Installing AFL..."
    cargo install afl || true
fi

echo
echo "======================================="
echo "Building project"
echo "======================================="
cargo build --release

echo
echo "======================================="
echo "Running standard tests"
echo "======================================="
cargo test --release -- --test-threads=1

echo
echo "======================================="
echo "Running ignored tests (10GB torture)"
echo "======================================="
cargo test --release -- --ignored --test-threads=1

echo
echo "======================================="
echo "Running libFuzzer cryptographic fuzzing"
echo "======================================="
if [ -d fuzz ]; then
    cargo fuzz run decrypt -- -runs=100000
else
    echo "Fuzz directory not found. Initializing fuzzing..."
    cargo fuzz init
    cargo fuzz run decrypt -- -runs=100000
fi

echo
echo "======================================="
echo "Optional AFL fuzzing (60 seconds)"
echo "======================================="
if command -v cargo-afl >/dev/null 2>&1; then
    mkdir -p afl_in
    mkdir -p afl_out
    echo "seed" > afl_in/seed
    timeout 60 cargo afl fuzz -i afl_in -o afl_out target/debug/fuzz_target || true
else
    echo "AFL not available, skipping."
fi

echo
echo "======================================="
echo "ALL TESTS COMPLETED SUCCESSFULLY"
echo "======================================="