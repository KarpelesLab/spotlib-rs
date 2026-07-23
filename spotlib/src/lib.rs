//! Client for the Spot secure messaging network.
//!
//! Spotlib enables secure, end-to-end encrypted communication between clients
//! through the Spot network. It handles connection management, cryptographic
//! identity, message routing, and provides both request-response and
//! fire-and-forget messaging patterns.
//!
//! This crate is a Rust port of the Go package
//! [`github.com/KarpelesLab/spotlib`](https://github.com/KarpelesLab/spotlib).
//! It is built on [`bottlers`] for cryptography, [`purecrypto`] for TLS, and
//! [`rsurl`](https://crates.io/crates/rsurl) for the platform REST API —
//! pure Rust all the way down, no async runtime required (connections are
//! handled by background threads).
//!
//! # Basic usage
//!
//! Create a new client (with an ephemeral identity) and wait for it to come
//! online:
//!
//! ```no_run
//! use std::time::Duration;
//!
//! let client = spotlib::Client::new()?;
//! client.wait_online(Duration::from_secs(30))?;
//! # Ok::<(), spotlib::Error>(())
//! ```
//!
//! # Sending messages
//!
//! Send an encrypted query and wait for the response:
//!
//! ```no_run
//! # use std::time::Duration;
//! # let client = spotlib::Client::new()?;
//! let response = client.query("k.targetID/endpoint", b"payload", Duration::from_secs(30))?;
//! # Ok::<(), spotlib::Error>(())
//! ```
//!
//! Send a one-way encrypted message:
//!
//! ```no_run
//! # use std::time::Duration;
//! # let client = spotlib::Client::new()?;
//! client.send_to("k.targetID/endpoint", b"payload", Duration::from_secs(30))?;
//! # Ok::<(), spotlib::Error>(())
//! ```
//!
//! # Receiving messages
//!
//! Register a handler for incoming messages on an endpoint (decrypted
//! automatically; the returned bytes are sent back as the response):
//!
//! ```no_run
//! let client = spotlib::Client::builder()
//!     .handler("myendpoint", |msg| Ok(Some(msg.body.clone())))
//!     .build()?;
//! # Ok::<(), spotlib::Error>(())
//! ```
//!
//! # Identity and addressing
//!
//! Each client has a cryptographic identity represented by an ID card. The
//! client's address ([`Client::target_id`]) is derived from the SHA-256 hash
//! of its public key and has the format `k.<base64url hash>`. Messages to
//! key-based addresses are automatically encrypted and signed; the
//! recipient's public key is retrieved and cached automatically. Use
//! [`DiskStore`] to persist the identity key across runs.
//!
//! # wasm32 (browser)
//!
//! spotlib also runs in the browser on `wasm32-unknown-unknown`. Because the
//! browser event loop cannot block and has no threads, the network-facing API
//! there is **async** and driven on the browser event loop: `Client::query`,
//! `Client::wait_online`, `Client::send_to`, the `get_*`/`store_blob`/
//! `fetch_blob`/`get_time` methods, and `PacketConn::recv` become `async fn`.
//! `Client::new`/`build`, `close`, `target_id`, `subscribe_events`,
//! `set_handler` and the other non-networking methods keep their synchronous
//! signatures. Connections use rsurl's `aio` WebSocket/Fetch backend over the
//! browser's native APIs.
//!
//! Building for wasm requires disabling the default `native` feature:
//!
//! ```sh
//! cargo build --no-default-features --target wasm32-unknown-unknown
//! ```
//!
//! Two integration requirements are the embedder's responsibility:
//! - **Randomness** — purecrypto's `OsRng` draws entropy through an imported
//!   host function `purecrypto.random_get(ptr, len)`. Wire it to
//!   `crypto.getRandomValues` (browser) or `crypto.randomFillSync` (Node).
//! - **Key persistence** — [`DiskStore`] is native-only. On wasm, supply keys
//!   via [`ClientBuilder::key`]/[`ClientBuilder::keychain`] and persist them
//!   yourself (e.g. in `localStorage`).

// The `native` feature selects the blocking, thread-backed implementation and
// is on by default. It may only be disabled on wasm32, where the async browser
// implementation is compiled instead.
#[cfg(all(feature = "native", target_arch = "wasm32"))]
compile_error!(
    "spotlib: build for wasm32 with `--no-default-features` \
     (the `native` feature cannot be used on wasm32)"
);
#[cfg(all(not(feature = "native"), not(target_arch = "wasm32")))]
compile_error!("spotlib: the `native` feature can only be disabled on wasm32 targets");

mod api;
mod client;
mod error;
mod events;
mod identity;
mod im;
mod packetconn;
mod utils;

// Native (blocking, thread-backed) transport, connection management and disk
// key storage.
#[cfg(feature = "native")]
mod conn;
#[cfg(feature = "native")]
mod resolver;
#[cfg(feature = "native")]
mod store;
#[cfg(feature = "native")]
mod transport;

// Browser (wasm32) async transport and connection management.
#[cfg(not(feature = "native"))]
mod conn_wasm;
#[cfg(not(feature = "native"))]
mod transport_wasm;

pub use client::{Client, ClientBuilder, MessageHandler};
pub use error::{Error, Result};
pub use events::{ClientEvent, Hub};
pub use identity::clone_private_key;
pub use im::InstantMessage;
pub use packetconn::PacketConn;

/// Disk-backed key storage (native only; not available on wasm32, where key
/// persistence is the embedder's responsibility).
#[cfg(feature = "native")]
pub use store::DiskStore;

// re-export the protocol crate and message type handlers receive
pub use spotproto;
pub use spotproto::Message;
