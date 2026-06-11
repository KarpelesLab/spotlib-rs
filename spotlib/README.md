# spotlib

Client for the Spot secure messaging network: end-to-end encrypted
communication with connection management, cryptographic identity, message
routing, and request-response as well as fire-and-forget messaging.

This is a Rust port of the Go package
[`github.com/KarpelesLab/spotlib`](https://github.com/KarpelesLab/spotlib).
Pure Rust all the way down — built on
[`bottlers`](https://crates.io/crates/bottlers) (Bottle containers),
[`purecrypto`](https://crates.io/crates/purecrypto) (TLS & primitives) and
[`rsurl`](https://crates.io/crates/rsurl) (REST API). No async runtime;
connections are handled by background threads.

## Usage

```rust
use std::time::Duration;

let t = Duration::from_secs(30);

// create a client (use spotlib::DiskStore to persist the identity key)
let client = spotlib::Client::builder()
    .handler("myendpoint", |msg| Ok(Some(msg.body.clone())))
    .build()?;
client.wait_online(t)?;

// the local address other peers can reach us at
println!("{}", client.target_id()); // k.<base64url sha256 of public key>

// E2E encrypted query (encrypt + sign, verify + decrypt the response)
let res = client.query("k.<target>/endpoint", b"payload", t)?;
```

See the crate docs and `examples/spot_test.rs` for more.
