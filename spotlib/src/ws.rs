//! Minimal RFC 6455 WebSocket client over [`TlsConn`].
//!
//! Supports what the spot protocol needs: the upgrade handshake, masked
//! binary sends, message reassembly (continuation frames), and inline
//! control-frame handling (ping→pong, close echo). No extensions are
//! offered, so RSV bits are rejected.

use std::time::Duration;

use purecrypto::der::base64_encode;
use purecrypto::hash::{Digest, Sha1};
use purecrypto::rng::{OsRng, RngCore};

use crate::error::{Error, Result};
use crate::resolver;
use crate::tlsconn::{TlsConn, TlsWriter};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const OPCODE_CONT: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

/// Maximum reassembled message size (matches the 1MB read limit used by the
/// Go client).
const MAX_MESSAGE: usize = 1024 * 1024;

/// A received WebSocket message.
pub enum WsMessage {
    /// A binary data message.
    Binary(Vec<u8>),
    /// A text data message (ignored by the spot protocol).
    #[allow(dead_code)]
    Text(Vec<u8>),
}

/// The read side of an established WebSocket connection.
pub struct WsConn {
    tls: TlsConn,
    writer: WsWriter,
}

/// A cloneable, thread-safe handle for sending WebSocket messages.
#[derive(Clone)]
pub struct WsWriter {
    w: TlsWriter,
}

impl WsConn {
    /// Dials `host:443`, performs the TLS and WebSocket handshakes and
    /// returns an established connection to `wss://host/path`.
    pub fn connect(host: &str, path: &str, timeout: Duration) -> Result<WsConn> {
        let sock = resolver::dial(host, 443, timeout)?;
        sock.set_read_timeout(Some(timeout))?;
        let mut tls = TlsConn::connect(sock, host)?;

        // websocket upgrade handshake
        let mut key_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut key_bytes);
        let key = base64_encode(&key_bytes);
        let req = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        );
        let writer = tls.writer();
        writer.write_all(req.as_bytes())?;

        let head = tls.read_until(b"\r\n\r\n", 64 * 1024)?;
        let head = String::from_utf8_lossy(&head);
        let mut lines = head.split("\r\n");
        let status = lines.next().unwrap_or("");
        if !status.starts_with("HTTP/1.1 101") {
            return Err(Error::Ws(format!("unexpected upgrade response: {status}")));
        }
        let mut accept_ok = false;
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("sec-websocket-accept") {
                    let mut h = Sha1::new();
                    h.update(key.as_bytes());
                    h.update(WS_GUID.as_bytes());
                    let expect = base64_encode(h.finalize().as_ref());
                    accept_ok = value.trim() == expect;
                }
            }
        }
        if !accept_ok {
            return Err(Error::Ws("invalid Sec-WebSocket-Accept".into()));
        }

        Ok(WsConn {
            tls,
            writer: WsWriter { w: writer },
        })
    }

    /// Returns a cloneable handle for sending messages on this connection.
    pub fn writer(&self) -> WsWriter {
        self.writer.clone()
    }

    /// Sets the read timeout for subsequent reads (None = block forever).
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        self.tls.set_read_timeout(dur)
    }

    /// Reads the next data message, transparently answering control frames.
    /// Returns `None` when the peer closed the connection.
    pub fn read_message(&mut self) -> Result<Option<WsMessage>> {
        let mut msg: Vec<u8> = Vec::new();
        let mut msg_opcode: Option<u8> = None;

        loop {
            let (fin, opcode, payload) = self.read_frame()?;
            match opcode {
                OPCODE_PING => {
                    self.writer.send_frame(OPCODE_PONG, &payload)?;
                }
                OPCODE_PONG => {}
                OPCODE_CLOSE => {
                    // echo the status code (if any) and report the close
                    let echo = if payload.len() >= 2 { &payload[..2] } else { &[] };
                    let _ = self.writer.send_frame(OPCODE_CLOSE, echo);
                    return Ok(None);
                }
                OPCODE_TEXT | OPCODE_BINARY => {
                    if msg_opcode.is_some() {
                        return Err(Error::Ws("unexpected data frame during fragmented message".into()));
                    }
                    msg_opcode = Some(opcode);
                    msg = payload;
                    if fin {
                        return Ok(Some(self.finish(msg_opcode.unwrap(), msg)));
                    }
                }
                OPCODE_CONT => {
                    if msg_opcode.is_none() {
                        return Err(Error::Ws("continuation frame without initial frame".into()));
                    }
                    if msg.len() + payload.len() > MAX_MESSAGE {
                        return Err(Error::Ws("message too large".into()));
                    }
                    msg.extend_from_slice(&payload);
                    if fin {
                        return Ok(Some(self.finish(msg_opcode.unwrap(), msg)));
                    }
                }
                _ => return Err(Error::Ws(format!("unsupported opcode {opcode:#x}"))),
            }
        }
    }

    fn finish(&self, opcode: u8, msg: Vec<u8>) -> WsMessage {
        if opcode == OPCODE_TEXT {
            WsMessage::Text(msg)
        } else {
            WsMessage::Binary(msg)
        }
    }

    /// Reads a single frame, returning (fin, opcode, unmasked payload).
    fn read_frame(&mut self) -> Result<(bool, u8, Vec<u8>)> {
        let hdr = self.tls.read_exact(2)?;
        let fin = hdr[0] & 0x80 != 0;
        if hdr[0] & 0x70 != 0 {
            return Err(Error::Ws("unexpected RSV bits (no extension negotiated)".into()));
        }
        let opcode = hdr[0] & 0x0f;
        let masked = hdr[1] & 0x80 != 0;
        let mut len = (hdr[1] & 0x7f) as u64;
        if opcode >= OPCODE_CLOSE {
            // control frames must not be fragmented and carry at most 125 bytes
            if !fin || len > 125 {
                return Err(Error::Ws("invalid control frame".into()));
            }
        }
        if len == 126 {
            let b = self.tls.read_exact(2)?;
            len = u16::from_be_bytes([b[0], b[1]]) as u64;
        } else if len == 127 {
            let b = self.tls.read_exact(8)?;
            len = u64::from_be_bytes(b.try_into().unwrap());
        }
        if len > MAX_MESSAGE as u64 {
            return Err(Error::Ws("frame too large".into()));
        }
        let mask = if masked {
            Some(self.tls.read_exact(4)?)
        } else {
            None
        };
        let mut payload = self.tls.read_exact(len as usize)?;
        if let Some(mask) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        Ok((fin, opcode, payload))
    }
}

impl WsWriter {
    /// Sends a binary data message.
    pub fn send_binary(&self, payload: &[u8]) -> Result<()> {
        self.send_frame(OPCODE_BINARY, payload)
    }

    /// Closes the connection (sends a close frame and shuts down the socket).
    pub fn close(&self) {
        let _ = self.send_frame(OPCODE_CLOSE, &1000u16.to_be_bytes());
        self.w.shutdown();
    }

    /// Builds and sends a single masked client frame. The frame is written
    /// atomically with respect to other writers.
    fn send_frame(&self, opcode: u8, payload: &[u8]) -> Result<()> {
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | opcode); // FIN, no fragmentation on send
        let len = payload.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len < 65536 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mut mask = [0u8; 4];
        OsRng.fill_bytes(&mut mask);
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, &b)| b ^ mask[i % 4]));
        self.w.write_all(&frame)
    }
}
