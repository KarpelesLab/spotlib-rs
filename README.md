# spotlib-rs

[![CI](https://github.com/KarpelesLab/spotlib-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/spotlib-rs/actions/workflows/ci.yml)
[![Release-plz](https://github.com/KarpelesLab/spotlib-rs/actions/workflows/release-plz.yml/badge.svg)](https://github.com/KarpelesLab/spotlib-rs/actions/workflows/release-plz.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Rust implementation of the **Spot** secure messaging protocol — a pure-Rust
port of the Go [`spotlib`](https://github.com/KarpelesLab/spotlib) and
[`spotproto`](https://github.com/KarpelesLab/spotproto) packages, wire
compatible with them.

Spot lets clients exchange end-to-end encrypted messages through a network of
relay servers. Each client has a cryptographic identity; messages addressed to
a key-based address (`k.<hash>`) are automatically encrypted for and signed
between the endpoints, so relays only ever see ciphertext.

The workspace has two crates:

| Crate | Version | Docs | Description |
|-------|---------|------|-------------|
| [`spotproto`](spotproto) | [![Crates.io](https://img.shields.io/crates/v/spotproto.svg)](https://crates.io/crates/spotproto) | [![Docs.rs](https://docs.rs/spotproto/badge.svg)](https://docs.rs/spotproto) | The wire protocol: packet framing, the handshake (CBOR), and the instant-message format. |
| [`spotlib`](spotlib) | [![Crates.io](https://img.shields.io/crates/v/spotlib.svg)](https://crates.io/crates/spotlib) | [![Docs.rs](https://docs.rs/spotlib/badge.svg)](https://docs.rs/spotlib) | The client: identity, connection management, message routing, and the high-level messaging API. |

## Pure Rust, no async runtime

Everything is pure Rust with no C dependencies and no async runtime —
connections run on background threads. The cryptography and transport come
from sibling Karpelès Lab crates:

- [`bottlers`](https://crates.io/crates/bottlers) — the Bottle secure-container
  format (multi-recipient encryption, signatures, ID cards).
- [`purecrypto`](https://crates.io/crates/purecrypto) — the underlying
  cryptographic primitives and TLS.
- [`rsurl`](https://crates.io/crates/rsurl) — the platform REST call (host
  discovery) and the persistent split WebSocket transport.

## Usage

Add the client crate:

```toml
[dependencies]
spotlib = "0.1"
```

Connect with an ephemeral identity, wait until online, and round-trip an
end-to-end encrypted message:

```rust
use std::time::Duration;

fn main() -> Result<(), spotlib::Error> {
    let t = Duration::from_secs(30);

    // Persist the identity key across runs with spotlib::DiskStore instead of
    // the ephemeral key used here.
    let client = spotlib::Client::builder()
        .handler("myendpoint", |msg| Ok(Some(msg.body.clone())))
        .build()?;
    client.wait_online(t)?;

    // The address other peers reach us at: k.<base64url sha256 of our key>.
    println!("{}", client.target_id());

    // Encrypt + sign a query, verify + decrypt the response.
    let response = client.query("k.<target>/endpoint", b"payload", t)?;
    println!("{} bytes", response.len());
    Ok(())
}
```

See [`spotlib/examples/spot_test.rs`](spotlib/examples/spot_test.rs) for a
runnable example (`cargo run --example spot_test`, with `SPOTLIB_DEBUG=1` for
connection logs), and the [crate docs](https://docs.rs/spotlib) for the full
API: `send_to`, `listen_packet`, blob storage, group membership, ID-card
lookup, events, and the disk-backed key store.

## How it works

- **Identity.** Each client holds a keychain and a signed Bottle *ID card*. Its
  address is `k.` + the base64url SHA-256 of its primary public key.
- **Transport.** The client opens WebSocket (`wss://`) connections to spot
  servers discovered via the REST API, dialing through a custom connector that
  resolves `g-dns.net` hostnames (base32-encoded IPs) locally. TLS and RFC 6455
  framing are handled by rsurl's split WebSocket — a reader thread and a writer
  thread share one connection.
- **Messaging.** Messages to `k.` addresses are wrapped in a Bottle: encrypted
  for the recipient's decryption keys and signed by the sender. Queries block
  for a response; `send_to` is fire-and-forget. Incoming messages are routed to
  per-message reply queues or to registered endpoint handlers.

## Status

Functional and verified against the live Spot network (handshake, server time,
and end-to-end encrypted message round-trips). APIs may still change.

## License

MIT — see [LICENSE](LICENSE).
