//! Spot platform REST API access (host discovery).

use crate::error::{Error, Result};

/// Default API host queried for the spot server list.
pub const API_HOST: &str = "www.atonline.com";

/// Retrieves the list of available spot servers from the platform API,
/// returning the host list and the minimum recommended connection count.
pub fn get_hosts() -> Result<(Vec<String>, u32)> {
    let url = format!("https://{API_HOST}/_special/rest/Spot:connect");
    let res = rsurl::get(&url).map_err(|e| Error::Api(e.to_string()))?;
    if res.status != 200 {
        return Err(Error::Api(format!("Spot:connect returned status {}", res.status)));
    }
    let v: serde_json::Value =
        serde_json::from_slice(&res.body).map_err(|e| Error::Api(e.to_string()))?;
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
