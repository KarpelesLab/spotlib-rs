//! Custom DNS handling for `g-dns.net` hostnames.
//!
//! Spot server hostnames under `g-dns.net` encode their IP addresses directly
//! in the name as base32 (RFC 4648, no padding), e.g.
//! `<base32-ipv4>.g-dns.net` or `<base32-ipv4>-<base32-ipv6>.g-dns.net`.
//! Decoding them locally avoids DNS lookups that can fail on misconfigured
//! resolvers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use crate::error::{Error, Result};

/// Resolves a hostname to IP addresses, decoding `g-dns.net` names locally
/// and falling back to the system resolver otherwise. Used by the websocket
/// transport's connector.
pub fn lookup_host(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let lower = host.to_ascii_lowercase();
    if let Some(encoded) = lower.strip_suffix(".g-dns.net") {
        let mut out = Vec::new();
        for part in encoded.split('-') {
            if part.is_empty() {
                continue;
            }
            if let Some(ip) = decode_base32_ip(part) {
                out.push(SocketAddr::new(ip, port));
            }
        }
        if !out.is_empty() {
            return Ok(out);
        }
        // fall back to regular DNS if no valid IPs were decoded
    }
    Ok((host, port)
        .to_socket_addrs()
        .map_err(Error::Io)?
        .collect())
}

/// Decodes a base32-encoded IP address (4 bytes = IPv4, 16 bytes = IPv6).
fn decode_base32_ip(encoded: &str) -> Option<IpAddr> {
    let data = base32_decode(encoded)?;
    match data.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
        16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&data);
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// RFC 4648 base32 decoding (standard alphabet, case-insensitive, no padding).
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        bits = (bits << 5) | v as u32;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    // leftover bits must be zero padding
    if bits & ((1 << nbits) - 1) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_ipv4() {
        // 127.0.0.1 = 7f 00 00 01 -> base32 "P4AAAAI"
        assert_eq!(
            decode_base32_ip("P4AAAAI"),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
        // case-insensitive
        assert_eq!(
            decode_base32_ip("p4aaaai"),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
    }

    #[test]
    fn base32_ipv6() {
        // ::1
        let mut b = [0u8; 16];
        b[15] = 1;
        let enc = encode_base32(&b);
        assert_eq!(decode_base32_ip(&enc), Some(IpAddr::V6(Ipv6Addr::from(b))));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(decode_base32_ip("191"), None); // invalid chars
        assert_eq!(decode_base32_ip("AAAA"), None); // wrong byte count
    }

    // test-only encoder matching Go's base32.StdEncoding (no padding)
    fn encode_base32(data: &[u8]) -> String {
        const ALPHA: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut bits: u64 = 0;
        let mut nbits: u32 = 0;
        let mut out = String::new();
        for &b in data {
            bits = (bits << 8) | b as u64;
            nbits += 8;
            while nbits >= 5 {
                nbits -= 5;
                out.push(ALPHA[(bits >> nbits) as usize & 31] as char);
            }
        }
        if nbits > 0 {
            out.push(ALPHA[(bits << (5 - nbits)) as usize & 31] as char);
        }
        out
    }

    #[test]
    fn lookup_gdns() {
        let addrs = lookup_host("P4AAAAI.g-dns.net", 443).unwrap();
        assert_eq!(addrs, vec![SocketAddr::from(([127, 0, 0, 1], 443))]);
    }
}
