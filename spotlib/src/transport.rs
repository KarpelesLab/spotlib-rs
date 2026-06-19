//! WebSocket transport for spot connections, built on rsurl's persistent
//! split WebSocket (`WsReader` + `WsWriter`) over a custom connector that
//! resolves `g-dns.net` hostnames locally.
//!
//! rsurl drives TLS (full-duplex: the socket read blocks outside the TLS
//! engine lock while writes serialize under it) and RFC 6455 framing,
//! including auto-pong and close echo on the read side. We only add the
//! g-dns.net dialing and a thin spot-packet read adapter.

use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rsurl::net::{Client, Connector, NetStream};
use rsurl::{WsMessage, WsReader, WsWriter};

use crate::error::{Error, Result};
use crate::resolver::lookup_host;

/// A connector that resolves `g-dns.net` hostnames to their embedded base32
/// IP addresses and dials directly, falling back to the system resolver for
/// everything else. TLS SNI remains the original hostname (set by rsurl from
/// the URL), matching the spot servers' certificates.
#[derive(Debug)]
struct GdnsConnector;

impl Connector for GdnsConnector {
    fn connect(
        &self,
        host: &str,
        port: u16,
        timeout: Option<Duration>,
    ) -> rsurl::Result<Box<dyn NetStream>> {
        let addrs = lookup_host(host, port).map_err(|e| match e {
            Error::Io(io) => rsurl::Error::Io(io),
            other => rsurl::Error::Io(io::Error::other(other.to_string())),
        })?;
        let mut last: Option<io::Error> = None;
        for addr in addrs {
            let res = match timeout {
                Some(t) => TcpStream::connect_timeout(&addr, t),
                None => TcpStream::connect(addr),
            };
            match res {
                Ok(s) => return Ok(Box::new(s)),
                Err(e) => last = Some(e),
            }
        }
        Err(rsurl::Error::Io(last.unwrap_or_else(|| {
            io::Error::other(format!("no addresses found for {host}"))
        })))
    }

    fn is_direct(&self) -> bool {
        true
    }
}

/// The outcome of a single websocket read.
pub enum Incoming {
    /// A binary spot packet.
    Packet(Vec<u8>),
    /// The peer closed the connection.
    Closed,
    /// The read timed out (no data within the read deadline). The stream is
    /// resumable: a later read continues mid-frame thanks to rsurl's inbound
    /// buffering.
    Timeout,
}

/// Dials `wss://host{path}` and returns the split read/write halves. The
/// `connect_timeout` bounds the dial; per-phase read deadlines are set on the
/// returned reader via [`set_read_timeout`](WsReader::set_read_timeout).
pub fn connect(host: &str, path: &str, connect_timeout: Duration) -> Result<(WsReader, WsWriter)> {
    let client = Client::new()
        .connector(Arc::new(GdnsConnector))
        .verify_tls(true)
        .connect_timeout(Some(connect_timeout))
        // We manage read deadlines per phase on the reader; block by default.
        .read_timeout(None);
    let url = format!("wss://{host}{path}");
    let ws = client
        .websocket(&url)
        .map_err(|e| Error::Ws(e.to_string()))?;
    Ok(ws.split())
}

/// Reads the next binary spot packet, skipping text messages and classifying
/// read timeouts and clean closes. Control frames (ping/pong/close) are
/// handled inside rsurl's reader.
pub fn recv_packet(reader: &mut WsReader) -> Result<Incoming> {
    loop {
        match reader.recv() {
            Ok(Some(WsMessage::Binary(data))) => return Ok(Incoming::Packet(data)),
            Ok(Some(WsMessage::Text(_))) => continue, // ignored by the spot protocol
            Ok(None) => return Ok(Incoming::Closed),
            Err(rsurl::Error::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(Incoming::Timeout)
            }
            Err(e) => return Err(Error::Ws(e.to_string())),
        }
    }
}

/// Sends a raw binary frame on the (mutex-guarded) writer.
pub fn send(writer: &std::sync::Mutex<WsWriter>, bytes: &[u8]) -> Result<()> {
    writer
        .lock()
        .unwrap()
        .send_binary(bytes)
        .map_err(|e| Error::Ws(e.to_string()))
}

/// Sends a close frame on the writer (best effort, idempotent).
pub fn close(writer: &std::sync::Mutex<WsWriter>) {
    let _ = writer.lock().unwrap().close();
}
