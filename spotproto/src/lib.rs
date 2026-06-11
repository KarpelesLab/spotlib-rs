//! Wire protocol for the Spot real-time messaging network.
//!
//! Each client establishes one or more websocket connections to spot servers.
//! Packets are already encapsulated (known length), so every packet starts
//! with a single byte carrying the protocol version (high 4 bits, currently 0)
//! and the packet type (low 4 bits), followed by type-specific data:
//!
//! * `0x0` ping (C→S) / pong (S→C)
//! * `0x1` handshake request (S→C) or response (C→S), CBOR encoded
//! * `0x2` instant message, binary encoded
//!
//! This crate is a Rust port of the Go package
//! [`github.com/KarpelesLab/spotproto`](https://github.com/KarpelesLab/spotproto)
//! and is wire compatible with it.

mod clientid;
mod encoding;
mod error;
mod handshake;
mod message;
mod packet;

pub use clientid::ClientId;
pub use encoding::{base64url_decode, base64url_encode};
pub use error::Error;
pub use handshake::{HandshakeRequest, HandshakeResponse};
pub use message::{Message, MSG_FLAG_ERROR, MSG_FLAG_NOT_BOTTLE, MSG_FLAG_RESPONSE};
pub use packet::{parse, version_and_packet, Packet, HANDSHAKE, INSTANT_MSG, PING_PONG};
