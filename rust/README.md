# MIST for Rust

A thin Rust binding around the [C11 core](../core/README.md). Cargo builds the bundled C library with Make and a C11 toolchain. Use the crate as a local dependency with `mist = { path = "rust" }`.

Use `mist::core` for the sans-I/O API. Create a `Connection::client` or `Connection::server` with a local private key and a pinned peer public key. The application supplies entropy, datagrams, and monotonic timestamps in microseconds. Drain `next_event()` after receiving a datagram or polling. Call `poll()` again at the time returned by `next_deadline()`.

Datagram and receive payloads borrow the connection. Hand datagrams to the UDP layer promptly. Call `stream_consume()` or `message_consume()` after processing received data to release credit. Copy a payload if it needs to outlive the event.

Responder slots can share a `ReplayCache` through `Config`. The Rust binding synchronizes access to a shared replay cache.

## Cross-language LTO

Cargo's `-C linker-plugin-lto` rustflag makes the build script compile the C
archive as LLVM bitcode. It uses ThinLTO unless the rustflags also request
`-C lto=fat`. Regular Cargo profile LTO leaves the C archive as native objects.

Use compatible Clang and LLD releases for the LLVM version shown by
`rustc -vV`. The build script defaults to `clang` in this mode and honors
`CC` and `AR`.

```sh
CC=clang RUSTFLAGS="-C linker-plugin-lto -C linker=clang -C link-arg=-fuse-ld=lld" \
    cargo test --manifest-path rust/Cargo.toml --release
```

For fat LTO, add `-C embed-bitcode=yes -C lto=fat` to the same rustflags.
Cargo can otherwise pass `-C embed-bitcode=no` to dependency builds.
[Rust linker-plugin LTO documentation](https://doc.rust-lang.org/rustc/linker-plugin-lto.html)

## Tokio

Enable the `tokio` feature with `mist = { path = "rust", features = ["tokio"] }`. Use `mist::tokio::Socket::connect` on the client and `mist::tokio::Listener::bind` followed by `accept` on the server. The client supplies its local private key and the responder's pinned public key. The listener takes its local private key and an optional boxed `Fn(&[u8; 32]) -> bool + Send` policy. Pass `Some(policy)` to check an allowlist against the authenticated initiator key, or `None` to authorize any authenticated initiator. The listener accepts one authorized peer and dedicates its bound UDP socket to that connection.

The resulting byte socket implements Tokio's `AsyncRead` and `AsyncWrite` and drives MIST in a background task. Call `shutdown().await` to finish the writing half and wait for its acknowledgment. The reading half remains usable until the peer finishes its writing half.

From the repository root, run `cargo test --manifest-path rust/Cargo.toml` for the core binding or add `--features tokio` for the UDP tests.

### Run the UDP echo examples

From the repository root, start the server in one terminal.

```sh
cargo run --manifest-path rust/Cargo.toml --features tokio --example tokio_server
```

Run the client in a second terminal.

```sh
cargo run --manifest-path rust/Cargo.toml --features tokio --example tokio_client -- "hello MIST"
```

The client prints `echo: hello MIST` and exits. The server exits after echoing the stream. The examples use fixed demo keys and loopback UDP. The server binds port 43000 and the client uses an ephemeral port.

## Toki

On Linux, enable the `toki` feature to use `mist::toki::Listener` and `mist::toki::Socket` under a Toki executor. They have the same socket and key-policy interface as the Tokio adapter. The byte sockets use Tokio's I/O traits and run UDP readiness, timers, and driver tasks on Toki.

Start the server first and run the client in a second terminal.

```sh
cargo run --manifest-path rust/Cargo.toml --features toki --example toki_server
cargo run --manifest-path rust/Cargo.toml --features toki --example toki_client -- "hello MIST"
```
