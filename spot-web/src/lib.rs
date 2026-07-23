//! wasm-bindgen bindings that expose the spotlib browser client to JavaScript.
//!
//! spotlib's wasm build is `async` (see the crate's `wasm32 (browser)` docs), so
//! the network methods here return JS `Promise`s built with
//! [`future_to_promise`](wasm_bindgen_futures::future_to_promise). The client is
//! held behind an [`Rc`] so each promise can own a cheap handle for its `'static`
//! future.
//!
//! # Randomness
//!
//! purecrypto's `OsRng` imports a host function `purecrypto.random_get(ptr, len)`
//! which is **not** provided by wasm-bindgen. The generated glue is patched at
//! build time (`web/scripts/patch-rng.mjs`) to supply it from
//! `crypto.getRandomValues`. Without that patch the module fails to instantiate.

use std::rc::Rc;
use std::time::{Duration, UNIX_EPOCH};

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

/// Installs a panic hook that forwards Rust panics to the browser console.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// A spot client usable from JavaScript.
#[wasm_bindgen]
pub struct SpotClient {
    client: Rc<spotlib::Client>,
}

#[wasm_bindgen]
impl SpotClient {
    /// Creates a client with a fresh ephemeral identity and starts connecting
    /// to the spot network.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<SpotClient, JsError> {
        let client = spotlib::Client::new().map_err(|e| JsError::new(&e.to_string()))?;
        Ok(SpotClient {
            client: Rc::new(client),
        })
    }

    /// The client's own spot address (`k.<base64url hash>`).
    #[wasm_bindgen(getter, js_name = targetId)]
    pub fn target_id(&self) -> String {
        self.client.target_id()
    }

    /// Total number of server connections.
    #[wasm_bindgen(js_name = connTotal)]
    pub fn conn_total(&self) -> u32 {
        self.client.connection_count().0
    }

    /// Number of connections that are online (past the handshake).
    #[wasm_bindgen(js_name = connOnline)]
    pub fn conn_online(&self) -> u32 {
        self.client.connection_count().1
    }

    /// Resolves once the client has the minimum number of online connections,
    /// or rejects on timeout / close. `timeout_ms` bounds the wait.
    #[wasm_bindgen(js_name = waitOnline)]
    pub fn wait_online(&self, timeout_ms: u32) -> js_sys::Promise {
        let client = self.client.clone();
        future_to_promise(async move {
            client
                .wait_online(Duration::from_millis(timeout_ms as u64))
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(|e| JsValue::from_str(&e.to_string()))
        })
    }

    /// Sends a query and resolves with the response bytes (a `Uint8Array`).
    /// Key-based targets (`k.…`) are end-to-end encrypted automatically.
    pub fn query(&self, target: String, body: Vec<u8>, timeout_ms: u32) -> js_sys::Promise {
        let client = self.client.clone();
        future_to_promise(async move {
            client
                .query(&target, &body, Duration::from_millis(timeout_ms as u64))
                .await
                .map(|v| js_sys::Uint8Array::from(v.as_slice()).into())
                .map_err(|e| JsValue::from_str(&e.to_string()))
        })
    }

    /// Like [`query`](Self::query) but takes/returns UTF-8 text (lossy on
    /// decode). Handy for text endpoints such as `ping`.
    #[wasm_bindgen(js_name = queryText)]
    pub fn query_text(&self, target: String, body: String, timeout_ms: u32) -> js_sys::Promise {
        let client = self.client.clone();
        future_to_promise(async move {
            client
                .query(&target, body.as_bytes(), Duration::from_millis(timeout_ms as u64))
                .await
                .map(|v| JsValue::from_str(&String::from_utf8_lossy(&v)))
                .map_err(|e| JsValue::from_str(&e.to_string()))
        })
    }

    /// Queries the spot server for its current time, resolving with the Unix
    /// time in milliseconds (suitable for `new Date(ms)`).
    #[wasm_bindgen(js_name = getTime)]
    pub fn get_time(&self, timeout_ms: u32) -> js_sys::Promise {
        let client = self.client.clone();
        future_to_promise(async move {
            client
                .get_time(Duration::from_millis(timeout_ms as u64))
                .await
                .map(|t| {
                    let ms = t
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs_f64() * 1000.0)
                        .unwrap_or(0.0);
                    JsValue::from_f64(ms)
                })
                .map_err(|e| JsValue::from_str(&e.to_string()))
        })
    }

    /// Gracefully shuts the client down.
    pub fn close(&self) {
        self.client.close();
    }
}
