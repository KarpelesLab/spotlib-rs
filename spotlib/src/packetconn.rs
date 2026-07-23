//! A datagram-style interface over spot messaging, similar to a UDP socket:
//! received packets are queued on a channel, sends are encrypted
//! fire-and-forget messages.
//!
//! Native uses a blocking `std::sync::mpsc` channel and blocking `recv`; on
//! wasm32 the channel is an async `futures_channel::mpsc` and `recv` is an
//! `async fn`.

use std::sync::Arc;
use std::time::Duration;

use crate::client::{Client, Inner};
use crate::error::{Error, Result};

#[cfg(feature = "native")]
use std::sync::{mpsc, Mutex};

#[cfg(not(feature = "native"))]
use futures_channel::mpsc;
#[cfg(not(feature = "native"))]
use futures_util::lock::Mutex;
#[cfg(not(feature = "native"))]
use futures_util::StreamExt;

/// A packet-oriented connection bound to an endpoint name. Messages sent to
/// `<target_id>/<name>` are received here; outgoing packets are encrypted
/// and signed automatically. Created via [`Client::listen_packet`].
pub struct PacketConn {
    inner: Arc<Inner>,
    name: String,
    #[cfg(feature = "native")]
    rx: Mutex<mpsc::Receiver<(Vec<u8>, String)>>,
    #[cfg(not(feature = "native"))]
    rx: Mutex<mpsc::UnboundedReceiver<(Vec<u8>, String)>>,
}

impl Client {
    /// Returns a [`PacketConn`] receiving messages on the given endpoint
    /// name. Only encrypted messages are accepted; signatures are verified.
    pub fn listen_packet(&self, name: &str) -> PacketConn {
        #[cfg(feature = "native")]
        let (tx, rx) = mpsc::channel::<(Vec<u8>, String)>();
        #[cfg(not(feature = "native"))]
        let (tx, rx) = mpsc::unbounded::<(Vec<u8>, String)>();

        let handler = move |msg: &spotproto::Message| {
            if !msg.is_encrypted() {
                return Err("invalid message: must be encrypted".to_string());
            }
            #[cfg(feature = "native")]
            let _ = tx.send((msg.body.clone(), msg.sender.clone()));
            #[cfg(not(feature = "native"))]
            let _ = tx.unbounded_send((msg.body.clone(), msg.sender.clone()));
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

#[cfg(feature = "native")]
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
            std::time::Instant::now() + timeout,
        )
    }

    /// The local spot address of this endpoint (`<target_id>/<name>`).
    pub fn local_addr(&self) -> String {
        format!("{}/{}", self.inner.target_id(), self.name)
    }
}

#[cfg(not(feature = "native"))]
impl PacketConn {
    /// Receives the next packet, returning its payload and the sender's spot
    /// address. Pass `None` to wait indefinitely until a packet arrives.
    pub async fn recv(&self, timeout: Option<Duration>) -> Result<(Vec<u8>, String)> {
        let mut rx = self.rx.lock().await;
        match timeout {
            Some(dur) => match crate::conn_wasm::with_timeout(rx.next(), dur).await {
                Some(Some(item)) => Ok(item),
                Some(None) => Err(Error::Closed),
                None => Err(Error::Timeout),
            },
            None => rx.next().await.ok_or(Error::Closed),
        }
    }

    /// Encrypts and sends a packet to a spot address (typically `k.<hash>/<endpoint>`).
    pub async fn send_to(&self, addr: &str, payload: &[u8], timeout: Duration) -> Result<()> {
        self.inner
            .send_to_with_from(addr, payload, &format!("/{}", self.name), timeout)
            .await
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
