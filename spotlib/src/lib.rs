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

mod api;
mod client;
mod conn;
mod error;
mod events;
mod identity;
mod im;
mod packetconn;
mod resolver;
mod store;
mod tlsconn;
mod utils;
mod ws;

pub use client::{Client, ClientBuilder, MessageHandler};
pub use error::{Error, Result};
pub use events::{ClientEvent, Hub};
pub use identity::clone_private_key;
pub use im::InstantMessage;
pub use packetconn::PacketConn;
pub use store::DiskStore;

// re-export the protocol crate and message type handlers receive
pub use spotproto;
pub use spotproto::Message;
