# spotproto

Wire protocol for the Spot real-time messaging network: packet framing,
handshake request/response (CBOR), and the instant message format.

This is a Rust port of the Go package
[`github.com/KarpelesLab/spotproto`](https://github.com/KarpelesLab/spotproto),
wire compatible with it, built on [`bottlers`](https://crates.io/crates/bottlers)
for the cryptography.

See [`spotlib`](https://crates.io/crates/spotlib) for the client implementation.
