use bottlers::PrivateKey;
use ciborium::value::Value;

use crate::error::Error;

/// Handshake request, sent from server to client to initiate (or complete)
/// the handshake (packet type `0x1`, S→C). CBOR map with fields `rdy`, `srv`,
/// `cid`, `rnd` and `grp`.
#[derive(Debug, Clone, Default)]
pub struct HandshakeRequest {
    /// Indicates handshake completion when true.
    pub ready: bool,
    /// Short name of the server.
    pub server_code: String,
    /// Connection identifier assigned by the server.
    pub client_id: String,
    /// Random blob to be signed by the client for authentication.
    pub nonce: Vec<u8>,
    /// Groups the client belongs to (signed membership records).
    pub groups: Option<Vec<Vec<u8>>>,
    /// Raw CBOR buffer this request was parsed from, kept around because the
    /// response signature must cover the exact bytes sent by the server.
    raw: Option<Vec<u8>>,
}

impl HandshakeRequest {
    /// Serializes the handshake request to CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut map: Vec<(Value, Value)> = Vec::new();
        if self.ready {
            map.push((Value::Text("rdy".into()), Value::Bool(true)));
        }
        map.push((
            Value::Text("srv".into()),
            Value::Text(self.server_code.clone()),
        ));
        map.push((
            Value::Text("cid".into()),
            Value::Text(self.client_id.clone()),
        ));
        map.push((Value::Text("rnd".into()), Value::Bytes(self.nonce.clone())));
        map.push((
            Value::Text("grp".into()),
            match &self.groups {
                None => Value::Null,
                Some(g) => Value::Array(g.iter().map(|b| Value::Bytes(b.clone())).collect()),
            },
        ));
        to_cbor(&Value::Map(map))
    }

    /// Parses a handshake request from CBOR, remembering the raw buffer so
    /// [`HandshakeRequest::respond`] can sign the exact bytes received.
    pub fn from_cbor(buf: &[u8]) -> Result<Self, Error> {
        let v: Value = ciborium::from_reader(buf).map_err(|e| Error::Cbor(e.to_string()))?;
        let Value::Map(map) = v else {
            return Err(Error::Cbor("handshake request must be a map".into()));
        };
        let mut req = HandshakeRequest {
            raw: Some(buf.to_vec()),
            ..Default::default()
        };
        for (k, v) in map {
            let Value::Text(key) = k else { continue };
            match (key.as_str(), v) {
                ("rdy", Value::Bool(b)) => req.ready = b,
                ("srv", Value::Text(s)) => req.server_code = s,
                ("cid", Value::Text(s)) => req.client_id = s,
                ("rnd", Value::Bytes(b)) => req.nonce = b,
                ("grp", Value::Array(items)) => {
                    let mut groups = Vec::with_capacity(items.len());
                    for item in items {
                        if let Value::Bytes(b) = item {
                            groups.push(b);
                        }
                    }
                    req.groups = Some(groups);
                }
                _ => {}
            }
        }
        Ok(req)
    }

    /// Generates a response to this handshake request, signing the raw request
    /// buffer with the given key. The response carries the PKIX-encoded public
    /// key; the optional signed ID card (`id` field) can be set afterwards.
    pub fn respond(&self, key: &PrivateKey) -> Result<HandshakeResponse, Error> {
        let raw = match &self.raw {
            Some(r) => r.clone(),
            // guess what the raw buffer was; we really should have the original
            None => self.to_cbor()?,
        };
        let sig = bottlers::sign::sign(key, &raw)?;
        Ok(HandshakeResponse {
            id: Vec::new(),
            key: key.public_pkix()?,
            sig,
        })
    }
}

/// Handshake response, sent from client to server (packet type `0x1`, C→S).
/// CBOR map with fields `id`, `key` and `sig`.
#[derive(Debug, Clone, Default)]
pub struct HandshakeResponse {
    /// Optional client identifier (a signed ID card).
    pub id: Vec<u8>,
    /// The client's PKIX-encoded public key.
    pub key: Vec<u8>,
    /// Signature over the raw handshake request.
    pub sig: Vec<u8>,
}

impl HandshakeResponse {
    /// Serializes the handshake response to CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let map: Vec<(Value, Value)> = vec![
            (
                Value::Text("id".into()),
                if self.id.is_empty() {
                    Value::Null
                } else {
                    Value::Bytes(self.id.clone())
                },
            ),
            (Value::Text("key".into()), Value::Bytes(self.key.clone())),
            (Value::Text("sig".into()), Value::Bytes(self.sig.clone())),
        ];
        to_cbor(&Value::Map(map))
    }

    /// Parses a handshake response from CBOR.
    pub fn from_cbor(buf: &[u8]) -> Result<Self, Error> {
        let v: Value = ciborium::from_reader(buf).map_err(|e| Error::Cbor(e.to_string()))?;
        let Value::Map(map) = v else {
            return Err(Error::Cbor("handshake response must be a map".into()));
        };
        let mut res = HandshakeResponse::default();
        for (k, v) in map {
            let Value::Text(key) = k else { continue };
            match (key.as_str(), v) {
                ("id", Value::Bytes(b)) => res.id = b,
                ("key", Value::Bytes(b)) => res.key = b,
                ("sig", Value::Bytes(b)) => res.sig = b,
                _ => {}
            }
        }
        Ok(res)
    }
}

fn to_cbor(v: &Value) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).map_err(|e| Error::Cbor(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let req = HandshakeRequest {
            ready: false,
            server_code: "srv1".into(),
            client_id: "srv1.conn-abc".into(),
            nonce: vec![1, 2, 3, 4],
            groups: None,
            raw: None,
        };
        let buf = req.to_cbor().unwrap();
        let back = HandshakeRequest::from_cbor(&buf).unwrap();
        assert_eq!(back.server_code, "srv1");
        assert_eq!(back.client_id, "srv1.conn-abc");
        assert_eq!(back.nonce, vec![1, 2, 3, 4]);
        assert!(!back.ready);
        assert!(back.groups.is_none());
    }

    #[test]
    fn respond_signs_raw_buffer() {
        use purecrypto::rng::OsRng;
        let sk = purecrypto::ec::ecdsa::EcdsaPrivateKey::generate(&mut OsRng);
        let key = PrivateKey::Ecdsa(sk);

        let req = HandshakeRequest {
            server_code: "s".into(),
            client_id: "s.c".into(),
            nonce: vec![9; 32],
            ..Default::default()
        };
        let buf = req.to_cbor().unwrap();
        let parsed = HandshakeRequest::from_cbor(&buf).unwrap();
        let res = parsed.respond(&key).unwrap();
        assert!(!res.key.is_empty());
        // the signature must verify against the raw request bytes
        bottlers::sign::verify_pkix(&res.key, &buf, &res.sig).unwrap();

        let enc = res.to_cbor().unwrap();
        let back = HandshakeResponse::from_cbor(&enc).unwrap();
        assert_eq!(back.key, res.key);
        assert_eq!(back.sig, res.sig);
        assert!(back.id.is_empty());
    }
}
