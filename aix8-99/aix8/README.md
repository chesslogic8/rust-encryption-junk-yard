# AIX8



AIX8 is a simple command‑line file encryption tool written in Rust.

It encrypts or decrypts files automatically depending on the file
extension.

Cryptography used:

-   XChaCha20‑Poly1305 authenticated encryption
-   Argon2 password‑based key derivation
-   Random salt and nonce per file

The project also includes automated tests and fuzz testing to help
detect bugs.

------------------------------------------------------------------------

## How It Works

Encryption and decryption are automatic.

-   If you pass a normal file → it encrypts it.
-   If you pass an `.aix` file → it decrypts it.

Examples:

Encrypt a file:

    aix8 myfile.txt

Output:

    myfile.txt.aix

Decrypt a file:

    aix8 myfile.txt.aix

Output:

    myfile.txt

The program will prompt for a password.

------------------------------------------------------------------------

## Building

Install Rust if needed:

https://www.rust-lang.org/tools/install

Build the project:

    cargo build --release

Binary location:

    target/release/aix8

------------------------------------------------------------------------

## Running Tests

Run unit tests:

    cargo test

Show test output:

    cargo test -- --nocapture

------------------------------------------------------------------------

## Fuzz Testing

This project uses `cargo-fuzz` for security testing.

Install once:

    cargo install cargo-fuzz

Run the fuzzer:

    cargo +nightly fuzz run fuzz_target_1 \
    -max_len=1048576 \
    -workers=16 \
    -use_value_profile=1

The fuzzer will run indefinitely and test millions of random inputs.

If a crash occurs it will appear in:

    fuzz/artifacts/fuzz_target_1/

------------------------------------------------------------------------

## Running All Tests

If you created the helper script:

    ./run_all_tests.sh

This can run:

-   cargo test
-   quick fuzz check
-   other verification steps

------------------------------------------------------------------------

## Project Structure

    src/
        lib.rs          core encryption logic
        bin/aix8.rs     command‑line application

    tests/
        integration tests

    fuzz/
        fuzz_targets/
            fuzz_target_1.rs

------------------------------------------------------------------------

## Continuous Integration

GitHub Actions automatically runs:

    cargo build
    cargo test

whenever code is pushed to the repository.

------------------------------------------------------------------------

## Security Notice

This project is experimental.

Do not rely on it to protect critical data without independent security
review.

If you discover a vulnerability, please report it responsibly.

------------------------------------------------------------------------

## License

MIT
