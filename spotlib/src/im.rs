//! Bottle-based instant message helper: a message with metadata carried in
//! bottle headers (`mid`, `flg`, `dst`, `rto`), as used by spot servers.

use bottlers::cbor::{append_uvarint, read_uvarint};
use bottlers::{Bottle, HeaderValue, OpenResult};

use crate::error::{Error, Result};

/// A message with metadata, content and cryptographic information.
#[derive(Debug, Clone, Default)]
pub struct InstantMessage {
    /// Unique message identifier.
    pub id: [u8; 16],
    /// Message flags for special handling.
    pub flags: u64,
    /// Target recipient identifier.
    pub recipient: String,
    /// Source sender identifier ("reply to").
    pub sender: String,
    /// Actual message content.
    pub body: Vec<u8>,
    /// Whether the message was encrypted (set when decoding).
    pub encrypted: bool,
    /// Public keys that signed the message (set when decoding).
    pub signed_by: Vec<Vec<u8>>,
}

impl InstantMessage {
    /// Extracts an instant message from an opened bottle: `buf` and `res` are
    /// the payload and result of [`bottlers::Opener::open_cbor`]. Metadata is
    /// read from the innermost bottle's headers.
    pub fn decode(buf: Vec<u8>, res: &OpenResult) -> Result<InstantMessage> {
        let b = res.last();

        let mut im = InstantMessage {
            body: buf,
            ..Default::default()
        };

        match b.header.get("mid") {
            Some(HeaderValue::Bytes(v)) => {
                let n = v.len().min(16);
                im.id[..n].copy_from_slice(&v[..n]);
            }
            _ => {
                return Err(Error::Other(
                    "invalid message, message ID is missing".into(),
                ))
            }
        }
        if let Some(HeaderValue::Integer(v)) = b.header.get("flg") {
            im.flags = i128::from(*v) as u64;
        }
        if let Some(HeaderValue::Text(v)) = b.header.get("dst") {
            im.recipient = v.clone();
        }
        if let Some(HeaderValue::Text(v)) = b.header.get("rto") {
            im.sender = v.clone();
        }

        im.encrypted = res.decryption > 0;
        im.signed_by = res.signatures.iter().map(|s| s.signer.clone()).collect();

        Ok(im)
    }

    /// Converts the message into a bottle carrying its metadata as headers,
    /// ready for encryption/signing.
    pub fn bottle(&self) -> Bottle {
        let mut b = Bottle::new(self.body.clone());
        b.header
            .insert("mid".into(), HeaderValue::Bytes(self.id.to_vec()));
        if self.flags != 0 {
            b.header.insert(
                "flg".into(),
                HeaderValue::Integer((self.flags as i64).into()),
            );
        }
        if !self.recipient.is_empty() {
            b.header
                .insert("dst".into(), HeaderValue::Text(self.recipient.clone()));
        }
        if !self.sender.is_empty() {
            b.header
                .insert("rto".into(), HeaderValue::Text(self.sender.clone()));
        }
        b
    }

    /// Serializes the message into the binary instant message wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.id);
        append_uvarint(&mut buf, self.flags);
        append_uvarint(&mut buf, self.recipient.len() as u64);
        buf.extend_from_slice(self.recipient.as_bytes());
        append_uvarint(&mut buf, self.sender.len() as u64);
        buf.extend_from_slice(self.sender.as_bytes());
        buf.extend_from_slice(&self.body);
        buf
    }

    /// Reads the fixed header (message ID and flags) from a binary buffer.
    pub fn read_header(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.len() < 16 {
            return Err(Error::Other("truncated instant message".into()));
        }
        self.id.copy_from_slice(&buf[..16]);
        let (flags, n) =
            read_uvarint(&buf[16..]).map_err(|e| Error::Other(format!("bad flags varint: {e}")))?;
        self.flags = flags;
        Ok(16 + n)
    }
}
