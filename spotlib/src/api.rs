//! Spot platform REST API access (host discovery).
//!
//! Native fetches over rsurl's blocking HTTP client; on wasm32 it uses rsurl's
//! async `aio` client (the browser Fetch API). The response parsing is shared.

use crate::error::{Error, Result};

/// Default API host queried for the spot server list.
pub const API_HOST: &str = "www.atonline.com";

/// The URL of the `Spot:connect` host-discovery endpoint.
fn connect_url() -> String {
    format!("https://{API_HOST}/_special/rest/Spot:connect")
}

/// Parses the `Spot:connect` JSON response into the host list and the minimum
/// recommended connection count.
fn parse_hosts(status: u16, body: &[u8]) -> Result<(Vec<String>, u32)> {
    if status != 200 {
        return Err(Error::Api(format!("Spot:connect returned status {status}")));
    }
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| Error::Api(e.to_string()))?;
    if v["result"].as_str() != Some("success") {
        let msg = v["error"].as_str().unwrap_or("unknown api error");
        return Err(Error::Api(msg.to_string()));
    }
    let data = &v["data"];
    let hosts = data["hosts"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|h| h.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let min_conn = data["min_conn"].as_u64().unwrap_or(0) as u32;
    Ok((hosts, min_conn))
}

/// Retrieves the list of available spot servers from the platform API,
/// returning the host list and the minimum recommended connection count.
#[cfg(feature = "native")]
pub fn get_hosts() -> Result<(Vec<String>, u32)> {
    let res = rsurl::get(connect_url()).map_err(|e| Error::Api(e.to_string()))?;
    parse_hosts(res.status, &res.body)
}

/// Retrieves the list of available spot servers from the platform API
/// (wasm: via the browser Fetch API).
#[cfg(not(feature = "native"))]
pub async fn get_hosts() -> Result<(Vec<String>, u32)> {
    let res = rsurl::aio::get(&connect_url())
        .await
        .map_err(|e| Error::Api(e.to_string()))?;
    parse_hosts(res.status, &res.body)
}
