//! Browser (wasm32) connection management: server discovery and per-connection
//! async tasks, the spot handshake, and packet dispatch — the single-threaded,
//! `async` counterpart of [`crate::conn`].
//!
//! Everything runs on the browser event loop via
//! [`wasm_bindgen_futures::spawn_local`]. There are no threads: a connection is
//! an async task that owns its [`WsStream`](rsurl::aio::WsStream) read loop,
//! while outgoing user messages are written straight to the shared
//! [`WsSink`](rsurl::aio::WsSink) installed on [`Inner`] once the connection is
//! online.

use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::{select, Either};
use gloo_timers::future::TimeoutFuture;
use spotproto::Packet;

use crate::api;
use crate::client::Inner;
use crate::error::{Error, Result};
use crate::identity;
use crate::transport_wasm::{self, Incoming};

/// Read deadline while waiting for the spot handshake to complete.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(300);
/// Steady-state read deadline: bounds how long a quiet connection waits before
/// re-checking the shutdown flag (the browser WebSocket has no read timeout).
const STEADY_READ_TIMEOUT: Duration = Duration::from_secs(120);
/// Pause between connection attempts for a single host.
const CONN_RETRY_DELAY: Duration = Duration::from_secs(2);
/// Delay between dialing successive hosts, to avoid a burst of handshakes.
const CONN_STAGGER: Duration = Duration::from_secs(2);
/// How long a connection must stay online before the host is considered
/// known-good and its failure counter resets.
const CONN_HEALTHY_AFTER: i64 = 30;
/// Consecutive failed attempts after which we give up on a host.
const CONN_MAX_FAIL: u32 = 10;
/// Maintenance tick: how often to re-check the connection count.
const MAINTENANCE_TICK: Duration = Duration::from_secs(30);

/// Sleeps for `dur` on the browser event loop.
pub async fn sleep(dur: Duration) {
    TimeoutFuture::new(millis(dur)).await;
}

/// Current wall-clock time in milliseconds (browser `Date.now()`), used to
/// track deadlines across repeated waits.
pub fn now_ms() -> f64 {
    js_sys::Date::now()
}

/// Awaits `fut`, returning `Some(output)` if it completes within `dur`, or
/// `None` on timeout.
pub async fn with_timeout<F: Future>(fut: F, dur: Duration) -> Option<F::Output> {
    let timeout = TimeoutFuture::new(millis(dur));
    futures_util::pin_mut!(fut);
    futures_util::pin_mut!(timeout);
    match select(fut, timeout).await {
        Either::Left((out, _)) => Some(out),
        Either::Right(((), _)) => None,
    }
}

/// Clamps a `Duration` to the `u32` millisecond range `TimeoutFuture` accepts.
fn millis(dur: Duration) -> u32 {
    dur.as_millis().min(u32::MAX as u128) as u32
}

/// Manages the client lifecycle: performs the initial connection, then
/// periodically ensures enough connections are established.
pub async fn main_loop(inner: Arc<Inner>) {
    inner.logf(format_args!("client entering main loop"));
    run_connect(&inner).await;

    while !inner.is_closed() {
        sleep(MAINTENANCE_TICK).await;
        if inner.is_closed() {
            break;
        }
        let cnt = inner.conn_cnt.load(Ordering::Relaxed);
        if cnt < inner.min_conn.load(Ordering::Relaxed) {
            run_connect(&inner).await;
        }
    }
}

/// Fetches the server list and spawns connection tasks as needed.
async fn run_connect(inner: &Arc<Inner>) {
    let (mut hosts, mut min_conn) = match api::get_hosts().await {
        Ok(v) => v,
        Err(e) => {
            inner.logf(format_args!("failed to fetch host list: {e}"));
            return;
        }
    };
    hosts.truncate(10);
    // Default to "all of them", and never require more connections than there
    // are hosts to dial — otherwise `wait_online` could never be satisfied.
    if min_conn == 0 || min_conn > hosts.len() as u32 {
        min_conn = hosts.len() as u32;
    }
    inner.min_conn.store(min_conn, Ordering::Relaxed);
    // Wake any `wait_online` waiter so it re-evaluates against the new threshold.
    inner.wake_online_waiters();

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
        wasm_bindgen_futures::spawn_local(async move { conn_task(inner, host).await });
        // stagger dials so we don't perform too many handshakes at once
        sleep(CONN_STAGGER).await;
    }
}

/// Per-connection task: dials and handles the connection, reconnecting until
/// the client closes or too many consecutive failures occur.
async fn conn_task(inner: Arc<Inner>, host: String) {
    inner.conn_cnt.fetch_add(1, Ordering::Relaxed);

    let mut fails: u32 = 0;
    while !inner.is_closed() {
        match transport_wasm::connect(&host, "/_websocket").await {
            Err(e) => {
                inner.logf(format_args!("failed to connect to server: {e}"));
                fails += 1;
                if fails > CONN_MAX_FAIL {
                    break;
                }
                sleep(CONN_RETRY_DELAY).await;
            }
            Ok((sink, stream)) => {
                let start = identity::now_unix();
                let (online, res) = handle(&inner, sink, stream).await;
                if let Err(e) = res {
                    inner.logf(format_args!("error during communications with server: {e}"));
                }
                if online && identity::now_unix() - start >= CONN_HEALTHY_AFTER {
                    fails = 0;
                    sleep(CONN_RETRY_DELAY).await;
                    continue;
                }
                fails += 1;
                if fails > CONN_MAX_FAIL {
                    break;
                }
                sleep(CONN_RETRY_DELAY).await;
            }
        }
    }

    inner.hosts.lock().unwrap().remove(&host);
    inner.conn_cnt.fetch_sub(1, Ordering::Relaxed);
}

/// Handles an established websocket connection: performs the spot handshake,
/// installs the sink for outgoing traffic, then routes packets until the
/// connection dies. The bool reports whether the connection became online.
async fn handle(
    inner: &Arc<Inner>,
    mut sink: rsurl::aio::WsSink,
    mut stream: rsurl::aio::WsStream,
) -> (bool, Result<()>) {
    if let Err(e) = handshake(inner, &mut stream, &mut sink).await {
        return (false, Err(e));
    }

    inner.online_incr();
    // Hand the sink to `Inner` for outgoing user messages and flush anything
    // that was queued while offline.
    inner.set_sink(sink);

    let res = read_loop(inner, &mut stream).await;

    inner.drop_sink();
    inner.online_decr();
    (true, res)
}

/// Performs the authentication handshake, answering challenges (updating group
/// membership when requested) until the server reports ready. Responses go
/// directly onto `sink`, which is not yet shared with `Inner`.
async fn handshake(
    inner: &Arc<Inner>,
    stream: &mut rsurl::aio::WsStream,
    sink: &mut rsurl::aio::WsSink,
) -> Result<()> {
    loop {
        let data = match with_timeout(transport_wasm::recv_packet(stream), HANDSHAKE_TIMEOUT).await
        {
            Some(Ok(Incoming::Packet(data))) => data,
            Some(Ok(Incoming::Closed)) => {
                return Err(Error::Ws("connection closed during handshake".into()))
            }
            Some(Err(e)) => return Err(e),
            None => return Err(Error::Ws("handshake timed out".into())),
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
                let buf = build_handshake_response(inner, &req)?;
                sink.send_binary(&buf)
                    .map_err(|e| Error::Ws(e.to_string()))?;
            }
            other => {
                inner.logf(format_args!("unsupported handshake packet type {other:?}"));
            }
        }
    }
}

/// Builds a `HandshakeResponse` for `req`, updating group membership first when
/// the server provided new records.
fn build_handshake_response(
    inner: &Arc<Inner>,
    req: &spotproto::HandshakeRequest,
) -> Result<Vec<u8>> {
    if let Some(groups) = &req.groups {
        if let Err(e) = inner.handle_groups(groups) {
            inner.logf(format_args!("failed to update groups: {e}"));
        }
    }
    let mut res = req.respond(inner.signer())?;
    res.id = inner.id_bin();
    Ok(Packet::HandshakeResponse(res).encode()?)
}

/// Reads and dispatches packets until the connection closes.
async fn read_loop(inner: &Arc<Inner>, stream: &mut rsurl::aio::WsStream) -> Result<()> {
    loop {
        let data =
            match with_timeout(transport_wasm::recv_packet(stream), STEADY_READ_TIMEOUT).await {
                Some(Ok(Incoming::Packet(data))) => data,
                Some(Ok(Incoming::Closed)) => return Ok(()), // clean close
                Some(Err(e)) => return Err(e),
                None => {
                    // no data within the deadline: re-check shutdown and keep going
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
                let buf = build_handshake_response(inner, &req)?;
                inner.send_raw(&buf)?;
            }
            Packet::Message(msg) => inner.route_message(msg),
            other => {
                inner.logf(format_args!("unsupported packet type {other:?}"));
            }
        }
        if inner.is_closed() {
            return Ok(());
        }
    }
}
