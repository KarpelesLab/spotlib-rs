//! Full-duplex blocking TLS client on top of purecrypto's sans-IO
//! [`Connection`].
//!
//! The TLS state machine and the socket write half live behind one mutex;
//! reads block on the socket *without* holding it, so concurrent threads can
//! keep sending while a reader waits for data. All outbound wire bytes
//! (`send` + `pop`) are produced and written under the same lock, keeping TLS
//! records contiguous on the wire.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use purecrypto::tls::{Config, Connection, HandshakeStatus};

use crate::error::{Error, Result};

struct Shared {
    conn: Connection,
    sock: TcpStream, // write half (cloned from the read half)
}

/// The read side of an established TLS connection. Use [`TlsConn::writer`]
/// to obtain a cloneable write handle.
pub struct TlsConn {
    rd: TcpStream,
    shared: Arc<Mutex<Shared>>,
    /// Decrypted plaintext not yet consumed by the caller.
    buf: Vec<u8>,
}

/// A cloneable, thread-safe write handle to a [`TlsConn`].
#[derive(Clone)]
pub struct TlsWriter {
    shared: Arc<Mutex<Shared>>,
}

fn tls_err<E: std::fmt::Debug>(e: E) -> Error {
    Error::Tls(format!("{e:?}"))
}

impl TlsConn {
    /// Performs a TLS client handshake over `sock` for server name `sni`,
    /// verifying the certificate chain against the system root store.
    pub fn connect(sock: TcpStream, sni: &str) -> Result<TlsConn> {
        let roots = rsurl::tls::load_system_roots().map_err(|e| Error::Tls(e.to_string()))?;
        let cfg = Config::builder()
            .tls_only()
            .roots(roots)
            .server_name(sni)
            .verify_certificates(true)
            .build();
        let mut conn = Connection::client(&cfg).map_err(tls_err)?;

        let mut wr = sock.try_clone()?;
        let mut rd = sock;
        let mut rbuf = [0u8; 16384];
        loop {
            let out = conn.pop().map_err(tls_err)?;
            if !out.is_empty() {
                wr.write_all(&out)?;
            }
            match conn.handshake().map_err(tls_err)? {
                HandshakeStatus::Complete => break,
                HandshakeStatus::WantWrite => continue,
                HandshakeStatus::WantRead => {
                    let n = rd.read(&mut rbuf)?;
                    if n == 0 {
                        return Err(Error::Tls("connection closed during handshake".into()));
                    }
                    conn.feed(&rbuf[..n]).map_err(tls_err)?;
                }
            }
        }
        // flush whatever the handshake completion produced (e.g. Finished)
        let out = conn.pop().map_err(tls_err)?;
        if !out.is_empty() {
            wr.write_all(&out)?;
        }

        Ok(TlsConn {
            rd,
            shared: Arc::new(Mutex::new(Shared { conn, sock: wr })),
            buf: Vec::new(),
        })
    }

    /// Returns a cloneable write handle for this connection.
    pub fn writer(&self) -> TlsWriter {
        TlsWriter {
            shared: self.shared.clone(),
        }
    }

    /// Blocks until at least one more plaintext byte is available, feeding
    /// wire data into the TLS engine.
    fn fill(&mut self) -> Result<()> {
        let mut rbuf = [0u8; 16384];
        loop {
            let n = self.rd.read(&mut rbuf)?;
            if n == 0 {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed",
                )));
            }
            let mut sh = self.shared.lock().unwrap();
            sh.conn.feed(&rbuf[..n]).map_err(tls_err)?;
            loop {
                let data = sh.conn.recv().map_err(tls_err)?;
                if data.is_empty() {
                    break;
                }
                self.buf.extend_from_slice(&data);
            }
            // the engine may emit handshake responses (key updates, etc.)
            let out = sh.conn.pop().map_err(tls_err)?;
            if !out.is_empty() {
                sh.sock.write_all(&out)?;
            }
            if sh.conn.received_close_notify() && self.buf.is_empty() {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "tls close notify",
                )));
            }
            drop(sh);
            if !self.buf.is_empty() {
                return Ok(());
            }
        }
    }

    /// Reads exactly `n` plaintext bytes.
    pub fn read_exact(&mut self, n: usize) -> Result<Vec<u8>> {
        while self.buf.len() < n {
            self.fill()?;
        }
        let rest = self.buf.split_off(n);
        let out = std::mem::replace(&mut self.buf, rest);
        Ok(out)
    }

    /// Reads plaintext until the buffer contains the byte sequence `delim`,
    /// returning everything up to and including it. `max` bounds the total
    /// size to protect against unbounded buffering.
    pub fn read_until(&mut self, delim: &[u8], max: usize) -> Result<Vec<u8>> {
        loop {
            if let Some(pos) = find(&self.buf, delim) {
                let end = pos + delim.len();
                let rest = self.buf.split_off(end);
                let out = std::mem::replace(&mut self.buf, rest);
                return Ok(out);
            }
            if self.buf.len() > max {
                return Err(Error::Ws("response header too large".into()));
            }
            self.fill()?;
        }
    }

    /// Sets the read timeout on the underlying socket (None = block forever).
    pub fn set_read_timeout(&self, dur: Option<std::time::Duration>) -> Result<()> {
        self.rd.set_read_timeout(dur)?;
        Ok(())
    }
}

impl TlsWriter {
    /// Encrypts and writes `data` as application data. The whole buffer is
    /// written atomically with respect to other writers.
    pub fn write_all(&self, data: &[u8]) -> Result<()> {
        let mut sh = self.shared.lock().unwrap();
        sh.conn.send(data).map_err(tls_err)?;
        let out = sh.conn.pop().map_err(tls_err)?;
        sh.sock.write_all(&out)?;
        Ok(())
    }

    /// Shuts down the underlying socket, unblocking any reader.
    pub fn shutdown(&self) {
        if let Ok(sh) = self.shared.lock() {
            let _ = sh.sock.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}
