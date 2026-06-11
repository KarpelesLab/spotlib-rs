//! A small event hub for client status notifications.

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;

/// Events emitted by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// The client transitioned from 0 to ≥1 online connections.
    Online,
    /// The client lost its last online connection.
    Offline,
    /// Connection status changed: (online connections, total connections).
    Status(u32, u32),
}

/// A simple broadcast hub: every subscriber receives every event emitted
/// after it subscribed. Disconnected subscribers are dropped automatically.
#[derive(Default)]
pub struct Hub {
    subs: Mutex<Vec<Sender<ClientEvent>>>,
}

impl Hub {
    /// Creates a new event hub.
    pub fn new() -> Hub {
        Hub::default()
    }

    /// Subscribes to all future events.
    pub fn subscribe(&self) -> Receiver<ClientEvent> {
        let (tx, rx) = channel();
        self.subs.lock().unwrap().push(tx);
        rx
    }

    /// Emits an event to all current subscribers.
    pub fn emit(&self, ev: ClientEvent) {
        self.subs
            .lock()
            .unwrap()
            .retain(|tx| tx.send(ev.clone()).is_ok());
    }
}
