# MIST/1

MIST is a sans-I/O transport for authenticated, encrypted UDP connections with reliable streams and unordered messages.

- [core/](core/README.md) contains the C11 library, tests, and benchmarks. Run `make -C core test`.
- [rust/](rust/README.md) contains the Rust binding. Run `cargo test --manifest-path rust/Cargo.toml`.
