//! The spot client: identity, connections, message routing and the
//! high-level messaging API.
//!
//! The network-facing methods exist in two flavours selected by the `native`
//! feature. With `native` (the default) they are the blocking, thread-backed
//! API. On wasm32 (with `native` disabled) they are `async` and driven on the
//! browser event loop; the pure crypto, identity and state code below is shared
//! between both.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

#[cfg(feature = "native")]
use std::sync::Condvar;
#[cfg(feature = "native")]
use std::time::Instant;

use bottlers::{Bottle, IDCard, Keychain, Opener, PrivateKey};
use spotproto::{Message, MSG_FLAG_ERROR, MSG_FLAG_NOT_BOTTLE, MSG_FLAG_RESPONSE};

use crate::error::{Error, Result};
use crate::events::{ClientEvent, Hub};
use crate::identity;
use crate::utils::{uuid_string, uuid_v4};

#[cfg(feature = "native")]
use crate::conn;

#[cfg(not(feature = "native"))]
use crate::conn_wasm;
#[cfg(not(feature = "native"))]
use futures_channel::oneshot;

/// A message handler registered for an endpoint. Receives the (decrypted)
/// message; returning `Ok(Some(body))` sends a response, `Ok(None)` stays
/// silent, and `Err(text)` sends an error response.
pub type MessageHandler =
    Arc<dyn Fn(&Message) -> std::result::Result<Option<Vec<u8>>, String> + Send + Sync>;

/// Default timeout applied by convenience methods that fetch remote ID cards
/// internally.
const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct IdState {
    pub card: IDCard,
    pub signed: Vec<u8>,
}

/// Multi-consumer outgoing message queue: any online connection's writer
/// thread picks up queued messages, mirroring the Go client's shared channel.
#[cfg(feature = "native")]
#[derive(Default)]
pub(crate) struct WriteQueue {
    q: Mutex<VecDeque<Message>>,
    cv: Condvar,
}

#[cfg(feature = "native")]
impl WriteQueue {
    pub fn push(&self, msg: Message) {
        self.q.lock().unwrap().push_back(msg);
        self.cv.notify_one();
    }

    pub fn push_front(&self, msg: Message) {
        self.q.lock().unwrap().push_front(msg);
        self.cv.notify_one();
    }

    pub fn pop_timeout(&self, dur: Duration) -> Option<Message> {
        let mut q = self.q.lock().unwrap();
        let deadline = Instant::now() + dur;
        loop {
            if let Some(msg) = q.pop_front() {
                return Some(msg);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, _) = self.cv.wait_timeout(q, deadline - now).unwrap();
            q = guard;
        }
    }

    pub fn wake_all(&self) {
        self.cv.notify_all();
    }
}

pub(crate) struct Inner {
    pub kc: Keychain,
    pub signer_pkix: Vec<u8>,
    pub opener: Opener,
    pub id: Mutex<IdState>,
    pub events: Hub,
    pub hosts: Mutex<HashSet<String>>,
    pub min_conn: AtomicU32,
    pub conn_cnt: AtomicU32,
    pub online_cnt: Mutex<u32>,
    pub handlers: RwLock<HashMap<String, MessageHandler>>,
    pub id_cache: Mutex<HashMap<Vec<u8>, Arc<IDCard>>>,
    pub closed: AtomicBool,

    // --- native (blocking) synchronization -------------------------------
    #[cfg(feature = "native")]
    pub wrq: WriteQueue,
    #[cfg(feature = "native")]
    pub online_cv: Condvar,
    #[cfg(feature = "native")]
    pub in_q: Mutex<HashMap<String, mpsc::Sender<Message>>>,

    // --- wasm (single-threaded async) state -------------------------------
    /// The send half of the current online connection, if any. Outgoing
    /// messages are written here directly; when offline they wait in `outq`.
    #[cfg(not(feature = "native"))]
    pub sink: Mutex<Option<rsurl::aio::WsSink>>,
    /// Outgoing messages queued while offline, flushed once a connection comes
    /// online.
    #[cfg(not(feature = "native"))]
    pub outq: Mutex<VecDeque<Message>>,
    /// One-shot wakers for `wait_online` callers, fired on any online change.
    #[cfg(not(feature = "native"))]
    pub online_waiters: Mutex<Vec<oneshot::Sender<()>>>,
    #[cfg(not(feature = "native"))]
    pub in_q: Mutex<HashMap<String, oneshot::Sender<Message>>>,
}

// ===========================================================================
// Shared: pure crypto, identity and state helpers (target-independent).
// ===========================================================================

impl Inner {
    /// The main signing key.
    pub fn signer(&self) -> &PrivateKey {
        self.kc
            .get_key(&self.signer_pkix)
            .expect("signer key is always in the keychain")
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub fn logf(&self, args: std::fmt::Arguments<'_>) {
        if std::env::var_os("SPOTLIB_DEBUG").is_some() {
            eprintln!("spot client: {args}");
        }
    }

    /// The signed binary ID card sent during handshakes.
    pub fn id_bin(&self) -> Vec<u8> {
        self.id.lock().unwrap().signed.clone()
    }

    /// Updates group memberships from server-provided records and re-signs
    /// the ID card.
    pub fn handle_groups(&self, groups: &[Vec<u8>]) -> Result<()> {
        let mut st = self.id.lock().unwrap();
        identity::update_groups(&mut st.card, groups)?;
        st.signed = st.card.sign(self.signer())?;
        Ok(())
    }

    pub fn get_handler(&self, endpoint: &str) -> Option<MessageHandler> {
        self.handlers.read().unwrap().get(endpoint).cloned()
    }

    // --- crypto ------------------------------------------------------------

    /// Prepares a message body for sending: encrypted for `rid` when given,
    /// always signed, CBOR encoded.
    pub fn prepare_message(&self, rid: Option<&IDCard>, payload: &[u8]) -> Result<Vec<u8>> {
        let mut bottle = Bottle::new(payload.to_vec());
        if let Some(rid) = rid {
            let keys = rid.keys_for("decrypt", identity::now_unix());
            bottle.encrypt(&keys)?;
            bottle.bottle_up()?;
        }
        bottle.sign(self.signer())?;
        Ok(bottle.to_cbor()?)
    }

    /// Decrypts and verifies a received message body. When `rid` is given the
    /// message must be encrypted and signed by that identity.
    pub fn decode_message(&self, rid: Option<&IDCard>, payload: &[u8]) -> Result<Vec<u8>> {
        let (buf, info) = self.opener.open_cbor(payload)?;
        if let Some(rid) = rid {
            if info.decryption == 0 {
                return Err(Error::Other("incoming message is not encrypted".into()));
            }
            if !identity::signed_by(&info, rid) {
                self.need_key_refresh();
                return Err(Error::Other(
                    "incoming message is not signed by sender".into(),
                ));
            }
        }
        Ok(buf)
    }

    // --- id cache ------------------------------------------------------------

    fn get_idcard_from_cache(&self, h: &[u8]) -> Option<Arc<IDCard>> {
        self.id_cache.lock().unwrap().get(h).cloned()
    }

    pub fn set_idcard_cache(&self, h: Vec<u8>, card: IDCard) {
        let mut cache = self.id_cache.lock().unwrap();
        if cache.len() > 1024 {
            // cache overfill protection
            cache.clear();
        }
        cache.insert(h, Arc::new(card));
    }

    /// Clears the ID cache when signature verification fails, so fresh ID
    /// cards get fetched when needed.
    fn need_key_refresh(&self) {
        self.id_cache.lock().unwrap().clear();
    }

    /// The local client ID (`k.<base64 hash>`).
    pub fn target_id(&self) -> String {
        let st = self.id.lock().unwrap();
        let h = bottlers::hash::sha256(&st.card.self_key);
        format!("k.{}", spotproto::base64url_encode(&h))
    }

    /// Parses the key hash out of a recipient like
    /// `k.<base64url hash>[/<endpoint>]`.
    fn recipient_hash(rcv: &str) -> Result<Vec<u8>> {
        let rcv = rcv.split('/').next().unwrap_or(rcv);
        let parts: Vec<&str> = rcv.split('.').collect();
        if parts.len() < 2 || parts[0] != "k" {
            return Err(Error::InvalidTarget(rcv.to_string()));
        }
        spotproto::base64url_decode(parts[parts.len() - 1])
            .ok_or_else(|| Error::InvalidTarget(rcv.to_string()))
    }
}

// ===========================================================================
// Native (blocking, thread-backed) implementation.
// ===========================================================================

#[cfg(feature = "native")]
impl Inner {
    // --- online state -----------------------------------------------------

    pub fn online_incr(&self) {
        let mut cnt = self.online_cnt.lock().unwrap();
        *cnt += 1;
        if *cnt == 1 {
            self.events.emit(ClientEvent::Status(
                *cnt,
                self.conn_cnt.load(Ordering::Relaxed),
            ));
            self.events.emit(ClientEvent::Online);
        }
        self.online_cv.notify_all();
    }

    pub fn online_decr(&self) {
        let mut cnt = self.online_cnt.lock().unwrap();
        *cnt -= 1;
        if *cnt == 0 {
            self.events.emit(ClientEvent::Status(
                *cnt,
                self.conn_cnt.load(Ordering::Relaxed),
            ));
            self.events.emit(ClientEvent::Offline);
        }
    }

    // --- inbound routing ----------------------------------------------------

    pub fn make_in_q(&self, key: String) -> mpsc::Receiver<Message> {
        let (tx, rx) = mpsc::channel();
        self.in_q.lock().unwrap().insert(key, tx);
        rx
    }

    pub fn take_in_q(&self, key: &str) -> Option<mpsc::Sender<Message>> {
        self.in_q.lock().unwrap().remove(key)
    }

    /// Routes an incoming instant message to a waiting query or a handler.
    pub fn route_message(self: &Arc<Self>, msg: Message) {
        let rcv = &msg.recipient;
        let Some(pos) = rcv.find('/') else { return };
        let mut name = &rcv[pos + 1..];
        if let Some(pos2) = name.find('/') {
            name = &name[..pos2];
        }

        if let Some(q) = self.take_in_q(name) {
            let _ = q.send(msg);
        } else if let Some(h) = self.get_handler(name) {
            let inner = self.clone();
            std::thread::spawn(move || inner.run_handler(msg, h));
        } else {
            self.logf(format_args!(
                "unable to route packet targetted to {}",
                msg.recipient
            ));
        }
    }

    /// Processes an incoming message through a handler: decrypts it if
    /// needed, runs the handler (catching panics), and sends back a response
    /// unless the message was itself a response.
    fn run_handler(self: Arc<Self>, mut msg: Message, h: MessageHandler) {
        let mut rid: Option<Arc<IDCard>> = None;

        if msg.flags & MSG_FLAG_NOT_BOTTLE == 0 {
            let deadline = Instant::now() + DEFAULT_QUERY_TIMEOUT;
            match self.get_idcard_for_recipient(&msg.sender, deadline) {
                Ok(card) => rid = Some(card),
                Err(e) => {
                    self.logf(format_args!("cannot send encrypted response: {e}"));
                    return;
                }
            }
            match self.decode_message(rid.as_deref(), &msg.body) {
                Ok(body) => msg.body = body,
                Err(e) => {
                    self.logf(format_args!("failed to decode incoming message: {e}"));
                    return;
                }
            }
        }

        // catch panics so a misbehaving handler doesn't kill the process
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h(&msg)))
            .unwrap_or_else(|e| {
                let text = e
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| e.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".into());
                Err(format!("panic in handler: {text}"))
            });

        if msg.flags & MSG_FLAG_RESPONSE == MSG_FLAG_RESPONSE {
            // do not generate a response to a response
            return;
        }

        let mut res_flags = MSG_FLAG_RESPONSE;
        let body = match res {
            Ok(None) => return, // no response
            Ok(Some(body)) => body,
            Err(e) => {
                res_flags |= MSG_FLAG_ERROR;
                e.into_bytes()
            }
        };

        let body = if msg.flags & MSG_FLAG_NOT_BOTTLE == 0 {
            // we got a bottle, need to respond with a bottle
            match self.prepare_message(rid.as_deref(), &body) {
                Ok(b) => b,
                Err(e) => {
                    self.logf(format_args!("failed to prepare response: {e}"));
                    return;
                }
            }
        } else {
            res_flags |= MSG_FLAG_NOT_BOTTLE;
            body
        };

        self.wrq.push(Message {
            message_id: msg.message_id,
            flags: res_flags,
            recipient: msg.sender.clone(),
            sender: "/noreply".into(),
            body,
        });
    }

    // --- queries -------------------------------------------------------------

    /// Sends a request and waits for the response until `deadline`. When the
    /// target is key-based (starts with `k.`), the message is encrypted and
    /// signed so only the recipient can open it.
    pub fn query(
        self: &Arc<Self>,
        target: &str,
        body: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        if target.is_empty() {
            return Err(Error::InvalidTarget(String::new()));
        }

        let mut rid: Option<Arc<IDCard>> = None;
        if target.starts_with('k') {
            rid = Some(self.get_idcard_for_recipient(target, deadline)?);
        }
        let body = self.prepare_message(rid.as_deref(), body)?;

        let id = uuid_v4();
        let id_str = uuid_string(&id);
        let rx = self.make_in_q(id_str.clone());
        // make sure the queue entry is removed however we exit
        let _guard = InQGuard {
            inner: self,
            key: &id_str,
        };

        self.wrq.push(Message {
            message_id: id,
            flags: 0,
            recipient: target.to_string(),
            sender: format!("/{id_str}"),
            body,
        });

        let now = Instant::now();
        if now >= deadline {
            return Err(Error::Timeout);
        }
        let mut obj = match rx.recv_timeout(deadline - now) {
            Ok(msg) => msg,
            Err(_) => {
                return if self.is_closed() {
                    Err(Error::Closed)
                } else {
                    Err(Error::Timeout)
                }
            }
        };

        if obj.flags & MSG_FLAG_NOT_BOTTLE == 0 {
            obj.body = self
                .decode_message(rid.as_deref(), &obj.body)
                .map_err(|e| Error::Other(format!("failed to decode response: {e}")))?;
        } else if rid.is_some() {
            // we sent an encrypted query, the response must be encrypted too
            return Err(Error::Other(
                "remote failed to respond with an encrypted response".into(),
            ));
        }
        if obj.flags & MSG_FLAG_ERROR != 0 {
            return Err(Error::Remote(
                String::from_utf8_lossy(&obj.body).into_owned(),
            ));
        }
        Ok(obj.body)
    }

    /// Returns the ID card for the given key hash, from cache or the server.
    pub fn get_idcard(self: &Arc<Self>, h: &[u8], deadline: Instant) -> Result<Arc<IDCard>> {
        if let Some(card) = self.get_idcard_from_cache(h) {
            return Ok(card);
        }
        let buf = self.query("@/idcard_find", h, deadline)?;
        let card = IDCard::from_signed(&buf)?;
        let card = Arc::new(card);
        self.id_cache
            .lock()
            .unwrap()
            .insert(h.to_vec(), card.clone());
        Ok(card)
    }

    /// Encrypts and sends a payload with an explicit sender endpoint.
    pub fn send_to_with_from(
        self: &Arc<Self>,
        target: &str,
        payload: &[u8],
        from: &str,
        deadline: Instant,
    ) -> Result<()> {
        let rid = self.get_idcard_for_recipient(target, deadline)?;
        let body = self.prepare_message(Some(&rid), payload)?;

        let id = uuid_v4();
        let from = if from.is_empty() {
            format!("/{}", uuid_string(&id))
        } else {
            if !from.starts_with('/') {
                return Err(Error::InvalidTarget(from.to_string()));
            }
            from.to_string()
        };

        self.wrq.push(Message {
            message_id: id,
            flags: 0,
            recipient: target.to_string(),
            sender: from,
            body,
        });
        Ok(())
    }

    /// Returns the ID card of a recipient like `k.<base64url hash>/<endpoint>`.
    pub fn get_idcard_for_recipient(
        self: &Arc<Self>,
        rcv: &str,
        deadline: Instant,
    ) -> Result<Arc<IDCard>> {
        let h = Self::recipient_hash(rcv)?;
        self.get_idcard(&h, deadline)
    }
}

#[cfg(feature = "native")]
struct InQGuard<'a> {
    inner: &'a Inner,
    key: &'a str,
}

#[cfg(feature = "native")]
impl Drop for InQGuard<'_> {
    fn drop(&mut self) {
        self.inner.take_in_q(self.key);
    }
}

// ===========================================================================
// Wasm (single-threaded async) implementation.
// ===========================================================================

#[cfg(not(feature = "native"))]
impl Inner {
    // --- online state -----------------------------------------------------

    pub fn online_incr(&self) {
        let mut cnt = self.online_cnt.lock().unwrap();
        *cnt += 1;
        if *cnt == 1 {
            self.events.emit(ClientEvent::Status(
                *cnt,
                self.conn_cnt.load(Ordering::Relaxed),
            ));
            self.events.emit(ClientEvent::Online);
        }
        drop(cnt);
        self.wake_online_waiters();
    }

    pub fn online_decr(&self) {
        let mut cnt = self.online_cnt.lock().unwrap();
        *cnt -= 1;
        if *cnt == 0 {
            self.events.emit(ClientEvent::Status(
                *cnt,
                self.conn_cnt.load(Ordering::Relaxed),
            ));
            self.events.emit(ClientEvent::Offline);
        }
        drop(cnt);
        self.wake_online_waiters();
    }

    /// Fires every parked `wait_online` waker so callers re-evaluate.
    pub fn wake_online_waiters(&self) {
        let waiters = std::mem::take(&mut *self.online_waiters.lock().unwrap());
        for tx in waiters {
            let _ = tx.send(());
        }
    }

    // --- outgoing -----------------------------------------------------------

    /// Installs the send half of a freshly online connection and flushes any
    /// messages queued while offline.
    pub fn set_sink(&self, sink: rsurl::aio::WsSink) {
        *self.sink.lock().unwrap() = Some(sink);
        self.flush_out();
    }

    /// Drops the current sink (the connection died); queued messages remain in
    /// `outq` for the next connection.
    pub fn drop_sink(&self) {
        *self.sink.lock().unwrap() = None;
    }

    /// Sends a pre-encoded packet on the current online sink (used for
    /// mid-stream handshake responses). Errors if there is no live connection.
    pub fn send_raw(&self, buf: &[u8]) -> Result<()> {
        match self.sink.lock().unwrap().as_ref() {
            Some(s) => s.send_binary(buf).map_err(|e| Error::Ws(e.to_string())),
            None => Err(Error::Ws("no active connection".into())),
        }
    }

    /// Queues a message and attempts an immediate flush.
    pub fn push_out(&self, msg: Message) {
        self.outq.lock().unwrap().push_back(msg);
        self.flush_out();
    }

    /// Writes as many queued messages as the current sink accepts. On a send
    /// error the sink is dropped and the message re-queued for the next
    /// connection.
    fn flush_out(&self) {
        let mut sink = self.sink.lock().unwrap();
        if sink.is_none() {
            return;
        }
        loop {
            let Some(msg) = self.outq.lock().unwrap().pop_front() else {
                break;
            };
            let buf = match spotproto::Packet::Message(msg.clone()).encode() {
                Ok(buf) => buf,
                Err(e) => {
                    self.logf(format_args!("failed to encode message: {e}"));
                    continue;
                }
            };
            // Borrow the sink only to send, so the mutable reassignment below
            // does not overlap the immutable borrow.
            let sent = sink
                .as_ref()
                .map(|s| s.send_binary(&buf).is_ok())
                .unwrap_or(false);
            if !sent {
                // connection is dying: requeue and drop the sink
                self.outq.lock().unwrap().push_front(msg);
                *sink = None;
                break;
            }
        }
    }

    // --- inbound routing ----------------------------------------------------

    pub fn make_in_q(&self, key: String) -> oneshot::Receiver<Message> {
        let (tx, rx) = oneshot::channel();
        self.in_q.lock().unwrap().insert(key, tx);
        rx
    }

    pub fn take_in_q(&self, key: &str) -> Option<oneshot::Sender<Message>> {
        self.in_q.lock().unwrap().remove(key)
    }

    /// Routes an incoming instant message to a waiting query or a handler.
    pub fn route_message(self: &Arc<Self>, msg: Message) {
        let rcv = &msg.recipient;
        let Some(pos) = rcv.find('/') else { return };
        let mut name = &rcv[pos + 1..];
        if let Some(pos2) = name.find('/') {
            name = &name[..pos2];
        }

        if let Some(q) = self.take_in_q(name) {
            let _ = q.send(msg);
        } else if let Some(h) = self.get_handler(name) {
            let inner = self.clone();
            wasm_bindgen_futures::spawn_local(async move { inner.run_handler(msg, h).await });
        } else {
            self.logf(format_args!(
                "unable to route packet targetted to {}",
                msg.recipient
            ));
        }
    }

    /// Processes an incoming message through a handler: decrypts it if needed,
    /// runs the handler, and sends back a response unless the message was
    /// itself a response.
    async fn run_handler(self: Arc<Self>, mut msg: Message, h: MessageHandler) {
        let mut rid: Option<Arc<IDCard>> = None;

        if msg.flags & MSG_FLAG_NOT_BOTTLE == 0 {
            match self
                .get_idcard_for_recipient(&msg.sender, DEFAULT_QUERY_TIMEOUT)
                .await
            {
                Ok(card) => rid = Some(card),
                Err(e) => {
                    self.logf(format_args!("cannot send encrypted response: {e}"));
                    return;
                }
            }
            match self.decode_message(rid.as_deref(), &msg.body) {
                Ok(body) => msg.body = body,
                Err(e) => {
                    self.logf(format_args!("failed to decode incoming message: {e}"));
                    return;
                }
            }
        }

        let res = h(&msg);

        if msg.flags & MSG_FLAG_RESPONSE == MSG_FLAG_RESPONSE {
            // do not generate a response to a response
            return;
        }

        let mut res_flags = MSG_FLAG_RESPONSE;
        let body = match res {
            Ok(None) => return, // no response
            Ok(Some(body)) => body,
            Err(e) => {
                res_flags |= MSG_FLAG_ERROR;
                e.into_bytes()
            }
        };

        let body = if msg.flags & MSG_FLAG_NOT_BOTTLE == 0 {
            // we got a bottle, need to respond with a bottle
            match self.prepare_message(rid.as_deref(), &body) {
                Ok(b) => b,
                Err(e) => {
                    self.logf(format_args!("failed to prepare response: {e}"));
                    return;
                }
            }
        } else {
            res_flags |= MSG_FLAG_NOT_BOTTLE;
            body
        };

        self.push_out(Message {
            message_id: msg.message_id,
            flags: res_flags,
            recipient: msg.sender.clone(),
            sender: "/noreply".into(),
            body,
        });
    }

    // --- queries -------------------------------------------------------------

    /// Sends a request and waits for the response for up to `timeout`. When the
    /// target is key-based (starts with `k.`), the message is encrypted and
    /// signed so only the recipient can open it.
    pub async fn query(
        self: &Arc<Self>,
        target: &str,
        body: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        if target.is_empty() {
            return Err(Error::InvalidTarget(String::new()));
        }

        let mut rid: Option<Arc<IDCard>> = None;
        if target.starts_with('k') {
            rid = Some(self.get_idcard_for_recipient(target, timeout).await?);
        }
        let body = self.prepare_message(rid.as_deref(), body)?;

        let id = uuid_v4();
        let id_str = uuid_string(&id);
        let rx = self.make_in_q(id_str.clone());
        let _guard = InQGuard {
            inner: self,
            key: &id_str,
        };

        self.push_out(Message {
            message_id: id,
            flags: 0,
            recipient: target.to_string(),
            sender: format!("/{id_str}"),
            body,
        });

        let mut obj = match conn_wasm::with_timeout(rx, timeout).await {
            Some(Ok(msg)) => msg,
            Some(Err(_)) => return Err(Error::Closed),
            None => {
                return if self.is_closed() {
                    Err(Error::Closed)
                } else {
                    Err(Error::Timeout)
                }
            }
        };

        if obj.flags & MSG_FLAG_NOT_BOTTLE == 0 {
            obj.body = self
                .decode_message(rid.as_deref(), &obj.body)
                .map_err(|e| Error::Other(format!("failed to decode response: {e}")))?;
        } else if rid.is_some() {
            return Err(Error::Other(
                "remote failed to respond with an encrypted response".into(),
            ));
        }
        if obj.flags & MSG_FLAG_ERROR != 0 {
            return Err(Error::Remote(
                String::from_utf8_lossy(&obj.body).into_owned(),
            ));
        }
        Ok(obj.body)
    }

    /// Returns the ID card for the given key hash, from cache or the server.
    pub async fn get_idcard(self: &Arc<Self>, h: &[u8], timeout: Duration) -> Result<Arc<IDCard>> {
        if let Some(card) = self.get_idcard_from_cache(h) {
            return Ok(card);
        }
        // `query` → `get_idcard_for_recipient` → `get_idcard` → `query` is a
        // mutually recursive async cycle; box this edge so the future type is
        // finite. (The `@/idcard_find` target is not key-based, so no infinite
        // recursion happens at runtime — this is purely a type-size break.)
        let buf = Box::pin(self.query("@/idcard_find", h, timeout)).await?;
        let card = IDCard::from_signed(&buf)?;
        let card = Arc::new(card);
        self.id_cache
            .lock()
            .unwrap()
            .insert(h.to_vec(), card.clone());
        Ok(card)
    }

    /// Encrypts and sends a payload with an explicit sender endpoint.
    pub async fn send_to_with_from(
        self: &Arc<Self>,
        target: &str,
        payload: &[u8],
        from: &str,
        timeout: Duration,
    ) -> Result<()> {
        let rid = self.get_idcard_for_recipient(target, timeout).await?;
        let body = self.prepare_message(Some(&rid), payload)?;

        let id = uuid_v4();
        let from = if from.is_empty() {
            format!("/{}", uuid_string(&id))
        } else {
            if !from.starts_with('/') {
                return Err(Error::InvalidTarget(from.to_string()));
            }
            from.to_string()
        };

        self.push_out(Message {
            message_id: id,
            flags: 0,
            recipient: target.to_string(),
            sender: from,
            body,
        });
        Ok(())
    }

    /// Returns the ID card of a recipient like `k.<base64url hash>/<endpoint>`.
    pub async fn get_idcard_for_recipient(
        self: &Arc<Self>,
        rcv: &str,
        timeout: Duration,
    ) -> Result<Arc<IDCard>> {
        let h = Self::recipient_hash(rcv)?;
        self.get_idcard(&h, timeout).await
    }
}

#[cfg(not(feature = "native"))]
struct InQGuard<'a> {
    inner: &'a Inner,
    key: &'a str,
}

#[cfg(not(feature = "native"))]
impl Drop for InQGuard<'_> {
    fn drop(&mut self) {
        self.inner.take_in_q(self.key);
    }
}

// ===========================================================================
// Builder (shared, with target-specific construction and startup).
// ===========================================================================

/// Builder for [`Client`], allowing keys, metadata and handlers to be set
/// before the client connects.
#[derive(Default)]
pub struct ClientBuilder {
    keys: Vec<PrivateKey>,
    meta: BTreeMap<String, String>,
    handlers: HashMap<String, MessageHandler>,
}

impl ClientBuilder {
    /// Adds a private key; the first signing-capable key becomes the client's
    /// main identity key. Supported types: ECDSA P-256, Ed25519, RSA.
    pub fn key(mut self, key: PrivateKey) -> Self {
        self.keys.push(key);
        self
    }

    /// Adds all the keys of a keychain.
    pub fn keychain(mut self, kc: Keychain) -> Self {
        // Keychain has no draining iterator; duplicate the keys instead.
        for key in kc.keys() {
            if let Ok(copy) = identity::clone_private_key(key) {
                self.keys.push(copy);
            }
        }
        self
    }

    /// Adds a metadata entry to the client's ID card.
    pub fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.meta.insert(key.into(), value.into());
        self
    }

    /// Registers a message handler for an endpoint.
    pub fn handler<F>(mut self, endpoint: impl Into<String>, h: F) -> Self
    where
        F: Fn(&Message) -> std::result::Result<Option<Vec<u8>>, String> + Send + Sync + 'static,
    {
        self.handlers.insert(endpoint.into(), Arc::new(h));
        self
    }

    /// Builds the client and starts connecting to the spot network.
    pub fn build(self) -> Result<Client> {
        let mut kc = Keychain::new();
        let mut opener_kc = Keychain::new();

        let ephemeral = self.keys.is_empty();
        let mut keys = self.keys;
        if ephemeral {
            // generate a new ecdsa private key
            let sk = purecrypto::ec::ecdsa::EcdsaPrivateKey::generate(&mut purecrypto::rng::OsRng);
            keys.push(PrivateKey::Ecdsa(sk));
        }
        for key in keys {
            opener_kc
                .add_key(identity::clone_private_key(&key)?)
                .map_err(Error::Bottle)?;
            kc.add_key(key).map_err(Error::Bottle)?;
        }

        let signer_pkix = kc
            .first_signer()
            .ok_or_else(|| Error::Other("no signing key available".into()))?
            .public_pkix()?;

        // generate a client ID card
        let signer = kc.get_key(&signer_pkix).unwrap();
        let mut card = IDCard::new(signer, identity::now_unix())?;
        card.meta = Some(self.meta);
        identity::add_keychain(&mut card, &kc)?;
        if ephemeral {
            identity::add_key_purposes(
                &mut card,
                signer_pkix.clone(),
                &["ephemeral"],
                identity::now_unix(),
            );
        }
        // sign the ID
        let signed = card.sign(signer)?;

        let mut handlers = self.handlers;
        default_handlers(&mut handlers);

        let inner = Arc::new(Inner {
            kc,
            signer_pkix,
            opener: Opener::new(opener_kc),
            id: Mutex::new(IdState { card, signed }),
            events: Hub::new(),
            hosts: Mutex::new(HashSet::new()),
            min_conn: AtomicU32::new(1),
            conn_cnt: AtomicU32::new(0),
            online_cnt: Mutex::new(0),
            handlers: RwLock::new(handlers),
            id_cache: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),

            #[cfg(feature = "native")]
            wrq: WriteQueue::default(),
            #[cfg(feature = "native")]
            online_cv: Condvar::new(),
            #[cfg(feature = "native")]
            in_q: Mutex::new(HashMap::new()),

            #[cfg(not(feature = "native"))]
            sink: Mutex::new(None),
            #[cfg(not(feature = "native"))]
            outq: Mutex::new(VecDeque::new()),
            #[cfg(not(feature = "native"))]
            online_waiters: Mutex::new(Vec::new()),
            #[cfg(not(feature = "native"))]
            in_q: Mutex::new(HashMap::new()),
        });

        // register the default handlers needing access to the client state
        register_inner_handlers(&inner);

        // start the connection management driver
        #[cfg(feature = "native")]
        {
            let main_inner = inner.clone();
            std::thread::spawn(move || conn::main_thread(main_inner));
        }
        #[cfg(not(feature = "native"))]
        {
            let main_inner = inner.clone();
            wasm_bindgen_futures::spawn_local(
                async move { conn_wasm::main_loop(main_inner).await },
            );
        }

        Ok(Client { inner })
    }
}

/// Installs the default handlers that don't need client state.
fn default_handlers(handlers: &mut HashMap<String, MessageHandler>) {
    handlers.entry("ping".to_string()).or_insert_with(|| {
        Arc::new(|msg: &Message| {
            let body = if msg.body.len() > 128 {
                msg.body[..128].to_vec()
            } else {
                msg.body.clone()
            };
            Ok(Some(body))
        })
    });
    handlers.entry("version".to_string()).or_insert_with(|| {
        Arc::new(|_: &Message| {
            Ok(Some(
                format!("spotlib-rs/{}", env!("CARGO_PKG_VERSION")).into_bytes(),
            ))
        })
    });
}

/// Installs the default handlers that need access to the client state.
fn register_inner_handlers(inner: &Arc<Inner>) {
    let mut handlers = inner.handlers.write().unwrap();

    let finger_inner = Arc::downgrade(inner);
    handlers.entry("finger".to_string()).or_insert_with(|| {
        Arc::new(move |_: &Message| match finger_inner.upgrade() {
            Some(inner) => Ok(Some(inner.id_bin())),
            None => Err("client is closed".into()),
        })
    });

    let idcard_inner = Arc::downgrade(inner);
    handlers
        .entry("idcard_update".to_string())
        .or_insert_with(|| {
            Arc::new(move |msg: &Message| {
                // process ID card update notifications
                if msg.body.is_empty() {
                    return Err("empty ID card data received".into());
                }
                let idc = IDCard::from_signed(&msg.body)
                    .map_err(|e| format!("invalid ID card format: {e}"))?;
                if let Some(inner) = idcard_inner.upgrade() {
                    let h = bottlers::hash::sha256(&idc.self_key);
                    inner.set_idcard_cache(h.to_vec(), idc);
                }
                // no response needed for this notification
                Ok(None)
            })
        });
}

// ===========================================================================
// Client: public API. Shared methods below; network-facing methods are
// blocking (native) or async (wasm), defined in the target-specific blocks.
// ===========================================================================

/// A client connected to the Spot messaging network.
///
/// The client maintains websocket connections to spot servers, handles its
/// cryptographic identity, and provides query/response and fire-and-forget
/// messaging with automatic end-to-end encryption for key-based targets
/// (`k.<hash>` addresses).
pub struct Client {
    inner: Arc<Inner>,
}

impl Client {
    pub(crate) fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }

    /// Creates a new client with a fresh ephemeral identity and starts
    /// connecting to the spot network.
    pub fn new() -> Result<Client> {
        ClientBuilder::default().build()
    }

    /// Returns a builder to configure keys, metadata and handlers.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Gracefully shuts down the client. Also triggered by dropping it.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Relaxed);
        #[cfg(feature = "native")]
        {
            self.inner.wrq.wake_all();
            // wake up wait_online callers
            self.inner.online_cv.notify_all();
        }
        #[cfg(not(feature = "native"))]
        {
            self.inner.wake_online_waiters();
        }
    }

    /// Returns a copy of the client's own identity card.
    pub fn id_card(&self) -> IDCard {
        self.inner.id.lock().unwrap().card.clone()
    }

    /// Returns the signed binary identity card.
    pub fn id_card_bin(&self) -> Vec<u8> {
        self.inner.id_bin()
    }

    /// Returns the local client ID (`k.<base64 hash>`) that other clients can
    /// use to send messages to this client.
    pub fn target_id(&self) -> String {
        self.inner.target_id()
    }

    /// Returns the number of spot server connections, and how many of them
    /// are online (past the handshake step).
    pub fn connection_count(&self) -> (u32, u32) {
        (
            self.inner.conn_cnt.load(Ordering::Relaxed),
            *self.inner.online_cnt.lock().unwrap(),
        )
    }

    /// Subscribes to client events (online/offline/status changes).
    pub fn subscribe_events(&self) -> mpsc::Receiver<ClientEvent> {
        self.inner.events.subscribe()
    }

    /// Registers (or removes, when `None`) a message handler for an endpoint.
    pub fn set_handler<F>(&self, endpoint: impl Into<String>, handler: Option<F>)
    where
        F: Fn(&Message) -> std::result::Result<Option<Vec<u8>>, String> + Send + Sync + 'static,
    {
        let mut handlers = self.inner.handlers.write().unwrap();
        match handler {
            Some(h) => {
                handlers.insert(endpoint.into(), Arc::new(h));
            }
            None => {
                handlers.remove(&endpoint.into());
            }
        }
    }
}

// --- Native (blocking) public API ------------------------------------------

#[cfg(feature = "native")]
impl Client {
    /// Waits until at least `min_conn` connections are online — the minimum
    /// the client maintains (the server-reported value, capped at the number
    /// of available hosts, and always at least one). Returns
    /// [`Error::Timeout`] if that many connections are not established within
    /// `timeout`, or [`Error::Closed`] if the client is closed meanwhile.
    pub fn wait_online(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut cnt = self.inner.online_cnt.lock().unwrap();
        loop {
            let want = self.inner.min_conn.load(Ordering::Relaxed).max(1);
            if *cnt >= want {
                return Ok(());
            }
            if self.inner.is_closed() {
                return Err(Error::Closed);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::Timeout);
            }
            let (guard, _) = self
                .inner
                .online_cv
                .wait_timeout(cnt, deadline - now)
                .unwrap();
            cnt = guard;
        }
    }

    /// Sends a request and waits for the response. If the target is key-based
    /// (starts with `k.`), the message is encrypted and signed so only the
    /// recipient can open it.
    pub fn query(&self, target: &str, body: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        self.inner.query(target, body, Instant::now() + timeout)
    }

    /// Encrypts and sends a one-way payload to the given key-based target.
    pub fn send_to(&self, target: &str, payload: &[u8], timeout: Duration) -> Result<()> {
        self.send_to_with_from(target, payload, "", timeout)
    }

    /// Encrypts and sends a payload, with an explicit sender endpoint
    /// (must start with `/`; defaults to a random one when empty).
    pub fn send_to_with_from(
        &self,
        target: &str,
        payload: &[u8],
        from: &str,
        timeout: Duration,
    ) -> Result<()> {
        self.inner
            .send_to_with_from(target, payload, from, Instant::now() + timeout)
    }

    /// Retrieves the member IDs of the given group.
    pub fn get_group_members(&self, group_key: &[u8], timeout: Duration) -> Result<Vec<String>> {
        let buf = self.query("@/group_list", group_key, timeout)?;
        Ok(buf
            .chunks(32)
            .map(|h| format!("k.{}", spotproto::base64url_encode(h)))
            .collect())
    }

    /// Stores a value under a key, encrypted so only this client (with the
    /// same private key) can retrieve it. Best-effort storage: data may be
    /// purged after some time without access; values are limited to slightly
    /// less than 49kB. An empty value deletes the key.
    pub fn store_blob(&self, key: &str, value: &[u8], timeout: Duration) -> Result<()> {
        if value.is_empty() {
            // handle this as a delete
            self.query("@/store_blob", format!("{key}\0").as_bytes(), timeout)?;
            return Ok(());
        }
        let body = self.inner.build_store_blob(key, value)?;
        self.query("@/store_blob", &body, timeout)?;
        Ok(())
    }

    /// Fetches a blob previously stored with [`Client::store_blob`],
    /// decrypting and verifying it.
    pub fn fetch_blob(&self, key: &str, timeout: Duration) -> Result<Vec<u8>> {
        let buf = self.query("@/fetch_blob", key.as_bytes(), timeout)?;
        self.inner.open_fetched_blob(&buf)
    }

    /// Returns the binary (signed) ID card for the given key hash. This also
    /// subscribes the client to updates for this ID card.
    pub fn get_idcard_bin(&self, h: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        self.query("@/idcard_find", h, timeout)
    }

    /// Returns the ID card for the given key hash, using the local cache when
    /// possible. Also subscribes to updates for this ID card.
    pub fn get_idcard(&self, h: &[u8], timeout: Duration) -> Result<Arc<IDCard>> {
        self.inner.get_idcard(h, Instant::now() + timeout)
    }

    /// Returns the ID card of a recipient given as `k.<hash>[/<endpoint>]`.
    pub fn get_idcard_for_recipient(&self, rcv: &str, timeout: Duration) -> Result<Arc<IDCard>> {
        self.inner
            .get_idcard_for_recipient(rcv, Instant::now() + timeout)
    }

    /// Queries the spot server for its current time, useful for clock
    /// synchronization or connectivity checks.
    pub fn get_time(&self, timeout: Duration) -> Result<SystemTime> {
        let res = self.query("@/time", &[], timeout)?;
        parse_server_time(&res)
    }
}

// --- Wasm (async) public API ------------------------------------------------

#[cfg(not(feature = "native"))]
impl Client {
    /// Waits until at least `min_conn` connections are online. Returns
    /// [`Error::Timeout`] if not reached within `timeout`, or [`Error::Closed`]
    /// if the client is closed meanwhile.
    pub async fn wait_online(&self, timeout: Duration) -> Result<()> {
        let deadline_ms = conn_wasm::now_ms() + timeout.as_millis() as f64;
        loop {
            {
                let cnt = self.inner.online_cnt.lock().unwrap();
                let want = self.inner.min_conn.load(Ordering::Relaxed).max(1);
                if *cnt >= want {
                    return Ok(());
                }
            }
            if self.inner.is_closed() {
                return Err(Error::Closed);
            }
            let remaining = deadline_ms - conn_wasm::now_ms();
            if remaining <= 0.0 {
                return Err(Error::Timeout);
            }
            // Park a waker, then wait for it (fired on any online change) or the
            // remaining time. Any wake re-evaluates the count; the deadline
            // bounds the total wait across repeated wakes.
            let (tx, rx) = oneshot::channel();
            self.inner.online_waiters.lock().unwrap().push(tx);
            let _ = conn_wasm::with_timeout(rx, Duration::from_millis(remaining as u64)).await;
        }
    }

    /// Sends a request and waits for the response. If the target is key-based
    /// (starts with `k.`), the message is encrypted and signed so only the
    /// recipient can open it.
    pub async fn query(&self, target: &str, body: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        self.inner.query(target, body, timeout).await
    }

    /// Encrypts and sends a one-way payload to the given key-based target.
    pub async fn send_to(&self, target: &str, payload: &[u8], timeout: Duration) -> Result<()> {
        self.send_to_with_from(target, payload, "", timeout).await
    }

    /// Encrypts and sends a payload, with an explicit sender endpoint
    /// (must start with `/`; defaults to a random one when empty).
    pub async fn send_to_with_from(
        &self,
        target: &str,
        payload: &[u8],
        from: &str,
        timeout: Duration,
    ) -> Result<()> {
        self.inner
            .send_to_with_from(target, payload, from, timeout)
            .await
    }

    /// Retrieves the member IDs of the given group.
    pub async fn get_group_members(
        &self,
        group_key: &[u8],
        timeout: Duration,
    ) -> Result<Vec<String>> {
        let buf = self.query("@/group_list", group_key, timeout).await?;
        Ok(buf
            .chunks(32)
            .map(|h| format!("k.{}", spotproto::base64url_encode(h)))
            .collect())
    }

    /// Stores a value under a key, encrypted so only this client can retrieve
    /// it. An empty value deletes the key.
    pub async fn store_blob(&self, key: &str, value: &[u8], timeout: Duration) -> Result<()> {
        if value.is_empty() {
            self.query("@/store_blob", format!("{key}\0").as_bytes(), timeout)
                .await?;
            return Ok(());
        }
        let body = self.inner.build_store_blob(key, value)?;
        self.query("@/store_blob", &body, timeout).await?;
        Ok(())
    }

    /// Fetches a blob previously stored with [`Client::store_blob`],
    /// decrypting and verifying it.
    pub async fn fetch_blob(&self, key: &str, timeout: Duration) -> Result<Vec<u8>> {
        let buf = self.query("@/fetch_blob", key.as_bytes(), timeout).await?;
        self.inner.open_fetched_blob(&buf)
    }

    /// Returns the binary (signed) ID card for the given key hash.
    pub async fn get_idcard_bin(&self, h: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        self.query("@/idcard_find", h, timeout).await
    }

    /// Returns the ID card for the given key hash, using the local cache when
    /// possible.
    pub async fn get_idcard(&self, h: &[u8], timeout: Duration) -> Result<Arc<IDCard>> {
        self.inner.get_idcard(h, timeout).await
    }

    /// Returns the ID card of a recipient given as `k.<hash>[/<endpoint>]`.
    pub async fn get_idcard_for_recipient(
        &self,
        rcv: &str,
        timeout: Duration,
    ) -> Result<Arc<IDCard>> {
        self.inner.get_idcard_for_recipient(rcv, timeout).await
    }

    /// Queries the spot server for its current time.
    pub async fn get_time(&self, timeout: Duration) -> Result<SystemTime> {
        let res = self.query("@/time", &[], timeout).await?;
        parse_server_time(&res)
    }
}

// --- Shared helpers used by both API flavours -------------------------------

impl Inner {
    /// Builds the encrypted, signed `store_blob` request body for `key`/`value`.
    fn build_store_blob(&self, key: &str, value: &[u8]) -> Result<Vec<u8>> {
        let mut bottle = Bottle::new(value.to_vec());
        {
            let st = self.id.lock().unwrap();
            let keys = st.card.keys_for("decrypt", identity::now_unix());
            bottle.encrypt(&keys)?;
        }
        bottle.bottle_up()?;
        let mut sig_cnt = 0;
        let mut sig_err: Option<bottlers::BottleError> = None;
        for key in self.kc.keys() {
            match bottle.sign(key) {
                Ok(()) => sig_cnt += 1,
                Err(e) => sig_err = Some(e),
            }
        }
        if sig_cnt == 0 {
            return Err(match sig_err {
                Some(e) => Error::Bottle(e),
                None => Error::Other("no signature key was available".into()),
            });
        }
        let buf = bottle.to_cbor()?;
        let mut body = format!("{key}\0").into_bytes();
        body.extend_from_slice(&buf);
        Ok(body)
    }

    /// Decrypts and verifies a blob fetched from the server.
    fn open_fetched_blob(&self, buf: &[u8]) -> Result<Vec<u8>> {
        let (data, info) = self.opener.open_cbor(buf)?;
        let signed_ok = {
            let st = self.id.lock().unwrap();
            identity::signed_by(&info, &st.card)
        };
        if !signed_ok {
            return Err(Error::Other("data was not signed by us".into()));
        }
        if info.decryption == 0 {
            return Err(Error::Other("data was not encrypted".into()));
        }
        Ok(data)
    }
}

/// Parses the 12-byte server time reply into a [`SystemTime`].
fn parse_server_time(res: &[u8]) -> Result<SystemTime> {
    if res.len() < 12 {
        return Err(Error::Other("unable to parse time from server".into()));
    }
    let secs = u64::from_be_bytes(res[..8].try_into().unwrap());
    let nanos = u32::from_be_bytes(res[8..12].try_into().unwrap());
    Ok(SystemTime::UNIX_EPOCH + Duration::new(secs, nanos))
}

impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}
