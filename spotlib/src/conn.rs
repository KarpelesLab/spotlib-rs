//! Connection management: server discovery, per-connection threads, the spot
//! handshake, and packet dispatch.
//!
//! Each connection's websocket is split into a [`WsReader`] driven by this
//! thread's read loop and a [`WsWriter`] (behind a mutex) shared between the
//! read loop — which answers mid-stream re-handshakes — and a dedicated
//! writer thread that drains the client's shared outgoing message queue.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rsurl::{WsReader, WsWriter};
use spotproto::Packet;

use crate::api;
use crate::client::Inner;
use crate::error::{Error, Result};
use crate::transport::{self, Incoming};

/// How long the websocket dial (TCP + TLS + upgrade) may take.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// Read deadline while waiting for the spot handshake to complete.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(300);
/// Fallback steady-state read deadline, used only when the transport cannot
/// provide a [`rsurl::WsShutdown`] handle (e.g. an unsplittable socket): it
/// bounds how long a quiet connection blocks before re-checking the shutdown
/// flag. When a shutdown handle is available the reader blocks with no
/// deadline and is woken directly. rsurl buffers partial frames, so a deadline
/// that lands mid-frame is resumed safely.
const STEADY_READ_TIMEOUT: Duration = Duration::from_secs(120);
/// Polling granularity for the writer thread checking for shutdown.
const WRITE_POLL: Duration = Duration::from_millis(500);
/// Pause between connection attempts for a single host, preventing a busy loop
/// against an unreachable or misbehaving host.
const CONN_RETRY_DELAY: Duration = Duration::from_secs(2);
/// How long a connection must stay online (past the handshake) before the host
/// is considered known-good and its failure counter resets. A session that
/// drops faster is treated as a failed attempt instead, so a host that changed
/// and now misbehaves eventually gives up rather than looping forever.
const CONN_HEALTHY_AFTER: Duration = Duration::from_secs(30);
/// Consecutive failed attempts (a failed dial, or a session that never became
/// usable) after which we give up on a host. Giving up drops `conn_cnt`; once
/// it falls below `min_conn` the main thread pulls a fresh host list.
const CONN_MAX_FAIL: u32 = 10;

/// Manages the client lifecycle: performs the initial connection, then
/// periodically ensures enough connections are established.
pub(crate) fn main_thread(inner: Arc<Inner>) {
    inner.logf(format_args!("client entering main thread"));

    if let Err(e) = run_connect(&inner) {
        inner.logf(format_args!("failed to perform initial connection: {e}"));
    }

    let mut tick = 0u32;
    while !inner.is_closed() {
        std::thread::sleep(Duration::from_secs(1));
        tick += 1;
        if tick < 30 {
            continue;
        }
        tick = 0;
        let cnt = inner.conn_cnt.load(Ordering::Relaxed);
        if cnt < inner.min_conn.load(Ordering::Relaxed) {
            if let Err(e) = run_connect(&inner) {
                inner.logf(format_args!("failed to perform connection: {e}"));
            }
        }
    }
}

/// Fetches the server list and spawns connection threads as needed.
fn run_connect(inner: &Arc<Inner>) -> Result<()> {
    let (mut hosts, mut min_conn) = api::get_hosts()?;
    hosts.truncate(10);
    // Default to "all of them", and never require more connections than there
    // are hosts to dial — otherwise `wait_online` could never be satisfied.
    if min_conn == 0 || min_conn > hosts.len() as u32 {
        min_conn = hosts.len() as u32;
    }
    {
        // Update the threshold under the online-count lock and wake any waiter
        // so a `wait_online` parked on the condvar re-evaluates against it
        // instead of missing the change.
        let _guard = inner.online_cnt.lock().unwrap();
        inner.min_conn.store(min_conn, Ordering::Relaxed);
    }
    inner.online_cv.notify_all();

    for host in hosts {
        if inner.is_closed() {
            break;
        }
        let registered = inner.hosts.lock().unwrap().insert(host.clone());
        if !registered {
            continue;
        }
        inner.logf(format_args!("connecting to host: {host}"));
        let inner = inner.clone();
        std::thread::spawn(move || conn_thread(inner, host));
        // delay things a bit so we don't perform too many handshakes at once
        std::thread::sleep(Duration::from_secs(2));
    }
    Ok(())
}

/// Per-connection thread: dials and handles the connection, reconnecting
/// until the client closes or too many consecutive failures occur.
fn conn_thread(inner: Arc<Inner>, host: String) {
    inner.conn_cnt.fetch_add(1, Ordering::Relaxed);

    // Consecutive failed attempts. A host that merely flaps keeps retrying
    // (keeping conn_cnt up) until it exhausts CONN_MAX_FAIL; only a genuinely
    // healthy session resets the counter. This way a host that now accepts TCP
    // but rejects the handshake eventually gives up instead of pinning conn_cnt
    // forever — letting the main thread pull a fresh host list.
    let mut fails: u32 = 0;
    while !inner.is_closed() {
        match transport::connect(&host, "/_websocket", DIAL_TIMEOUT) {
            Err(e) => {
                inner.logf(format_args!("failed to connect to server: {e}"));
                fails += 1;
                if fails > CONN_MAX_FAIL {
                    // can't reach this host anymore: give up so a fresh host can take its place
                    break;
                }
                std::thread::sleep(CONN_RETRY_DELAY);
            }
            Ok((reader, writer)) => {
                let start = Instant::now();
                let (online, res) = handle(&inner, reader, writer);
                if let Err(e) = res {
                    inner.logf(format_args!("error during communications with server: {e}"));
                }
                if online && start.elapsed() >= CONN_HEALTHY_AFTER {
                    // genuinely usable for a while: a later drop is a fresh
                    // start, so a known-good host keeps reconnecting
                    fails = 0;
                    std::thread::sleep(CONN_RETRY_DELAY);
                    continue;
                }
                // the handshake failed, or the session dropped almost
                // immediately: count it so conn_cnt can eventually drop and
                // trigger a host refresh
                fails += 1;
                if fails > CONN_MAX_FAIL {
                    break;
                }
                std::thread::sleep(CONN_RETRY_DELAY);
            }
        }
    }

    inner.hosts.lock().unwrap().remove(&host);
    inner.conn_cnt.fetch_sub(1, Ordering::Relaxed);
}

/// Handles an established websocket connection: performs the spot handshake,
/// then routes packets until the connection dies.
///
/// The returned bool reports whether the connection became online (completed
/// the handshake) before the result occurred, letting the caller tell a host
/// that is reachable and working from one that connects but never establishes
/// a usable session.
fn handle(inner: &Arc<Inner>, mut reader: WsReader, writer: WsWriter) -> (bool, Result<()>) {
    let writer = Arc::new(Mutex::new(writer));
    // A handle that force-closes the socket to wake the parked read loop on
    // shutdown. When present the reader blocks with no deadline; otherwise we
    // fall back to polling with a finite read timeout.
    let shutdown = reader.shutdown_handle();

    if let Err(e) = reader.set_read_timeout(Some(HANDSHAKE_TIMEOUT)) {
        return (false, Err(Error::Ws(e.to_string())));
    }
    if let Err(e) = handshake(inner, &mut reader, &writer) {
        return (false, Err(e));
    }
    let steady = shutdown
        .as_ref()
        .map_or(Some(STEADY_READ_TIMEOUT), |_| None);
    if let Err(e) = reader.set_read_timeout(steady) {
        return (false, Err(Error::Ws(e.to_string())));
    }

    inner.online_incr();
    let _online_guard = OnlineGuard { inner };

    // writer thread: forwards queued outgoing messages onto this connection
    let dead = Arc::new(AtomicBool::new(false));
    let writer_dead = dead.clone();
    let writer_inner = inner.clone();
    let writer_w = writer.clone();
    let writer_shutdown = shutdown.clone();
    let writer_thread = std::thread::spawn(move || {
        loop {
            if writer_dead.load(Ordering::Relaxed) {
                return;
            }
            if writer_inner.is_closed() {
                // send a graceful close, then force the socket down so the
                // parked read loop returns at once
                transport::close(&writer_w);
                if let Some(s) = &writer_shutdown {
                    let _ = s.shutdown();
                }
                return;
            }
            let Some(msg) = writer_inner.wrq.pop_timeout(WRITE_POLL) else {
                continue;
            };
            let buf = match Packet::Message(msg.clone()).encode() {
                Ok(buf) => buf,
                Err(e) => {
                    writer_inner.logf(format_args!("failed to encode message: {e}"));
                    continue;
                }
            };
            if transport::send(&writer_w, &buf).is_err() {
                // connection is dying: requeue so another connection sends it
                writer_inner.wrq.push_front(msg);
                return;
            }
        }
    });

    let res = read_loop(inner, &mut reader, &writer);
    dead.store(true, Ordering::Relaxed);
    let _ = writer_thread.join();
    (true, res)
}

/// Performs the authentication handshake: answers challenges (updating group
/// membership when requested) until the server reports ready.
fn handshake(inner: &Arc<Inner>, reader: &mut WsReader, writer: &Mutex<WsWriter>) -> Result<()> {
    loop {
        let data = match transport::recv_packet(reader)? {
            Incoming::Packet(data) => data,
            Incoming::Closed => return Err(Error::Ws("connection closed during handshake".into())),
            Incoming::Timeout => return Err(Error::Ws("handshake timed out".into())),
        };
        match spotproto::parse(&data, true)? {
            Packet::HandshakeRequest(req) => {
                if req.ready {
                    inner.logf(format_args!(
                        "authentication done, connected as c.{}",
                        req.client_id
                    ));
                    return Ok(());
                }
                respond_handshake(inner, &req, writer)?;
            }
            other => {
                inner.logf(format_args!("unsupported handshake packet type {other:?}"));
            }
        }
    }
}

/// Builds and sends a response to a handshake request, updating group
/// membership first when the server provided new records.
fn respond_handshake(
    inner: &Arc<Inner>,
    req: &spotproto::HandshakeRequest,
    writer: &Mutex<WsWriter>,
) -> Result<()> {
    if let Some(groups) = &req.groups {
        // need to re-compute our identity with the new memberships
        if let Err(e) = inner.handle_groups(groups) {
            inner.logf(format_args!("failed to update groups: {e}"));
        }
    }
    let mut res = req.respond(inner.signer())?;
    res.id = inner.id_bin();
    transport::send(writer, &Packet::HandshakeResponse(res).encode()?)
}

/// Reads and dispatches packets until the connection closes.
fn read_loop(inner: &Arc<Inner>, reader: &mut WsReader, writer: &Mutex<WsWriter>) -> Result<()> {
    loop {
        let data = match transport::recv_packet(reader)? {
            Incoming::Packet(data) => data,
            Incoming::Closed => return Ok(()), // clean close
            Incoming::Timeout => {
                if inner.is_closed() {
                    return Ok(());
                }
                continue;
            }
        };
        match spotproto::parse(&data, true)? {
            Packet::HandshakeRequest(req) => {
                if req.ready {
                    continue;
                }
                respond_handshake(inner, &req, writer)?;
            }
            Packet::Message(msg) => inner.route_message(msg),
            other => {
                inner.logf(format_args!("unsupported packet type {other:?}"));
            }
        }
    }
}

struct OnlineGuard<'a> {
    inner: &'a Arc<Inner>,
}

impl Drop for OnlineGuard<'_> {
    fn drop(&mut self) {
        self.inner.online_decr();
    }
}
