//! Browser (wasm32) WebSocket transport, built on rsurl's async `aio`
//! WebSocket (`WsSink` + `WsStream`) over the browser's native `WebSocket`.
//!
//! The browser owns DNS, TLS and RFC 6455 framing (including ping/pong and the
//! close handshake), so this is a thin async adapter: it dials `wss://host{path}`
//! and reads binary spot packets off the stream. There is no custom connector
//! or local `g-dns.net` decoding — the browser resolves the hostname.

use rsurl::aio::{WebSocket, WsMessage, WsSink, WsStream};

use crate::error::{Error, Result};

/// The outcome of a single websocket read.
pub enum Incoming {
    /// A binary spot packet.
    Packet(Vec<u8>),
    /// The peer closed the connection.
    Closed,
}

/// Dials `wss://host{path}` and returns the split send/receive halves.
pub async fn connect(host: &str, path: &str) -> Result<(WsSink, WsStream)> {
    let url = format!("wss://{host}{path}");
    let ws = WebSocket::connect(&url)
        .await
        .map_err(|e| Error::Ws(e.to_string()))?;
    Ok(ws.split())
}

/// Reads the next binary spot packet, skipping text messages and reporting a
/// clean close. Control frames are handled inside the browser.
pub async fn recv_packet(stream: &mut WsStream) -> Result<Incoming> {
    loop {
        match stream.recv().await {
            Some(Ok(WsMessage::Binary(data))) => return Ok(Incoming::Packet(data)),
            Some(Ok(WsMessage::Text(_))) => continue, // ignored by the spot protocol
            Some(Err(e)) => return Err(Error::Ws(e.to_string())),
            None => return Ok(Incoming::Closed),
        }
    }
}
