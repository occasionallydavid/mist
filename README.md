# MIST/1

MIST/1 is a C11 sans-I/O transport library for authenticated connections, reliable bidirectional byte streams, and reliable unordered messages over UDP datagrams. The application owns the socket, network path, clock, and source of secure entropy. The library uses the C standard library and builds with its cryptographic primitives included.

## Build and verify

```sh
make
make test
make sanitize
make fuzz
./build/fuzz_packet -max_total_time=60 -max_len=4096
```

Link `build/libmist.a` and add `include/` to the include path. The public interface is in [include/mist.h](include/mist.h). The fuzz target requires Clang with libFuzzer. The ordinary library and test builds accept GCC or Clang.

## Drive a connection

1. Create an initiator with `mist_client_create` using the responder's pinned X25519 public key. Create a responder with `mist_server_create` for an exact peer key or `mist_server_create_with_policy` for a caller-owned allowlist or authorization policy.
2. Drain `mist_next_event` after creating the connection, after feeding a datagram with `mist_input`, and after polling with `mist_poll`. Supply the exact requested number of secure random bytes on `MIST_NEED_RANDOM`.
3. Hand each `MIST_SEND_DATAGRAM` to the UDP layer promptly. The library treats it as sent. Copy the datagram before making another mutating call on that connection if the network layer needs to hold it.
4. Schedule `mist_poll` at the time returned by `mist_next_deadline`. Use the same monotonic microsecond clock for input and timers. Poll once more whenever the deadline is already due. `MIST_NO_DEADLINE` means no timer is pending.
5. On `MIST_CONNECTED`, the event exposes the authenticated peer key. Use `mist_open_stream`, `mist_stream_write`, and `mist_stream_finish` for ordered streams. Keep any bytes a short write could not accept and retry after `MIST_WRITABLE`. Use `mist_send_message` for a complete message of up to 1,024 bytes, subject to the peer's stream receive window.
6. Read each `MIST_STREAM_READABLE` slice and consume all or part of it with `mist_stream_consume`. A positive consume makes the next readable slice eligible for an event. `MIST_STREAM_FIN` reports that all preceding bytes are available. Release each `MIST_MESSAGE` with `mist_message_consume` to restore receive credit.
7. Start a fresh connection when `MIST_RECONNECT_REQUIRED` arrives. Use `mist_close` to initiate local closure and continue driving timers until `MIST_CLOSED`. Use `mist_destroy` to release the connection object.

A responder object represents one connection slot. A UDP listener should bound the number of allocated slots and route packets for an active CID to its existing slot. For replay protection across slots, pass a shared `mist_replay_cache` through the responder configuration. The cache retains authenticated INIT identities and ephemeral public keys for up to 120 seconds, subject to its capacity. Use one monotonic time domain for all connections sharing it. Callers synchronize access to a connection or shared cache when using multiple threads.

## Resource and protocol choices

- Initial receive windows are supported up to 64 MiB and initial stream allowances up to 1,024 per class. The connection receive window must fit within `max_recv_buffer`. The byte budgets cover payload credit and queued payload bytes. Stream state, sparse page overhead, and bounded history use additional memory.
- Each outgoing class has 1,024 stream slots. Incoming slots are sized by the advertised stream allowance. Stream-count credit advances as completed stream ordinals become contiguous. Messages can be delivered and consumed out of order while waiting for earlier ordinals to retire.
- The receiver checks overlapping bytes that it still retains and recent retired message digests and final offsets. Older retransmissions below the consumption or completion watermark cannot modify receive state or produce events. Exact byte comparison for arbitrarily old released stream data would require unbounded history.
- Session replacement is signaled one minute before the 24-hour limit or 1,024 packets before the packet-number limit. The idle timeout is 60 seconds.

## Cryptography and tests

The X25519 field arithmetic and ChaCha20 and Poly1305 cores come from Monocypher 4.0.3 under its BSD-2-Clause or CC0-1.0 terms. The extracted source retains its notices. MIST uses the IETF AEAD layout, BLAKE2s, and the exact Noise IK prologue and payloads specified for MIST/1. [Monocypher 4.0.3](https://github.com/LoupVaillant/Monocypher/tree/4.0.3), [Noise revision 34](https://noiseprotocol.org/noise.html), [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748), [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439), [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693)

The tests include cryptographic vectors, a MIST handshake vector derived independently and cross-checked against Cacophony, and a two-endpoint virtual network with loss, delay, duplication, reordering, truncation, and corruption. The fuzz harness exercises both raw datagrams and authenticated frame processing. The protocol and this implementation have not undergone independent security review. [Cacophony test vectors](https://github.com/rweather/noise-c/blob/master/tests/vector/cacophony.txt)
