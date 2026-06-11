//! A datagram-style interface over spot messaging, similar to a UDP socket:
//! received packets are queued on a channel, sends are encrypted
//! fire-and-forget messages.

use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use crate::client::{Client, Inner};
use crate::error::{Error, Result};

/// A packet-oriented connection bound to an endpoint name. Messages sent to
/// `<target_id>/<name>` are received here; outgoing packets are encrypted
/// and signed automatically. Created via [`Client::listen_packet`].
pub struct PacketConn {
    inner: Arc<Inner>,
    name: String,
    rx: Mutex<mpsc::Receiver<(Vec<u8>, String)>>,
}

impl Client {
    /// Returns a [`PacketConn`] receiving messages on the given endpoint
    /// name. Only encrypted messages are accepted; signatures are verified.
    pub fn listen_packet(&self, name: &str) -> PacketConn {
        let (tx, rx) = mpsc::channel::<(Vec<u8>, String)>();
        let handler = move |msg: &spotproto::Message| {
            if !msg.is_encrypted() {
                return Err("invalid message: must be encrypted".to_string());
            }
            let _ = tx.send((msg.body.clone(), msg.sender.clone()));
            Ok(None)
        };
        self.inner()
            .handlers
            .write()
            .unwrap()
            .insert(name.to_string(), Arc::new(handler));
        PacketConn {
            inner: self.inner().clone(),
            name: name.to_string(),
            rx: Mutex::new(rx),
        }
    }
}

impl PacketConn {
    /// Receives the next packet, returning its payload and the sender's spot
    /// address. Pass `None` to block until a packet arrives.
    pub fn recv(&self, timeout: Option<Duration>) -> Result<(Vec<u8>, String)> {
        let rx = self.rx.lock().unwrap();
        match timeout {
            Some(dur) => rx.recv_timeout(dur).map_err(|e| match e {
                mpsc::RecvTimeoutError::Timeout => Error::Timeout,
                mpsc::RecvTimeoutError::Disconnected => Error::Closed,
            }),
            None => rx.recv().map_err(|_| Error::Closed),
        }
    }

    /// Encrypts and sends a packet to a spot address (typically `k.<hash>/<endpoint>`).
    pub fn send_to(&self, addr: &str, payload: &[u8], timeout: Duration) -> Result<()> {
        self.inner.send_to_with_from(
            addr,
            payload,
            &format!("/{}", self.name),
            Instant::now() + timeout,
        )
    }

    /// The local spot address of this endpoint (`<target_id>/<name>`).
    pub fn local_addr(&self) -> String {
        format!("{}/{}", self.inner.target_id(), self.name)
    }
}

impl Drop for PacketConn {
    fn drop(&mut self) {
        // unregister the handler; the channel sender drops with it
        self.inner.handlers.write().unwrap().remove(&self.name);
    }
}
