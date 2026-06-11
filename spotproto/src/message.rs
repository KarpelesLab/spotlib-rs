use bottlers::cbor::{append_uvarint, read_uvarint};

use crate::error::Error;

/// This is a response message that must not trigger further responses.
pub const MSG_FLAG_RESPONSE: u64 = 1 << 0;
/// The message body contains an error string.
pub const MSG_FLAG_ERROR: u64 = 1 << 1;
/// Body is not an encrypted bottle. Normally messages must be encrypted for
/// the recipient and signed by the sender using a [`bottlers::Bottle`], but
/// some protocols skip this for efficiency or when payloads are already
/// encrypted by another mechanism.
pub const MSG_FLAG_NOT_BOTTLE: u64 = 1 << 2;

/// An instant message exchanged between hosts (packet type `0x2`).
///
/// Wire format: 16-byte message id, flags (unsigned varint), length-prefixed
/// recipient address, length-prefixed sender address, then the body until the
/// end of the packet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    /// Unique identifier for the message (typically a UUID).
    pub message_id: [u8; 16],
    /// Flags controlling message handling (see the `MSG_FLAG_*` constants).
    pub flags: u64,
    /// Target client ID, e.g. `k.<hash>/endpoint`.
    pub recipient: String,
    /// Originating client ID.
    pub sender: String,
    /// Message payload (up to 65535 bytes).
    pub body: Vec<u8>,
}

impl Message {
    /// Serializes the message to its binary wire format (without the leading
    /// packet type byte).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + self.recipient.len() + self.sender.len() + self.body.len());
        buf.extend_from_slice(&self.message_id);
        append_uvarint(&mut buf, self.flags);
        append_uvarint(&mut buf, self.recipient.len() as u64);
        buf.extend_from_slice(self.recipient.as_bytes());
        append_uvarint(&mut buf, self.sender.len() as u64);
        buf.extend_from_slice(self.sender.as_bytes());
        buf.extend_from_slice(&self.body);
        buf
    }

    /// Decodes a message from its binary wire format.
    pub fn parse(buf: &[u8]) -> Result<Self, Error> {
        let mut msg = Message::default();
        if buf.len() < 16 {
            return Err(Error::Truncated);
        }
        msg.message_id.copy_from_slice(&buf[..16]);
        let mut pos = 16;
        msg.flags = read_varint(buf, &mut pos)?;
        msg.recipient = read_name(buf, &mut pos)?;
        msg.sender = read_name(buf, &mut pos)?;
        msg.body = buf[pos..].to_vec();
        Ok(msg)
    }

    /// Returns true if the message must be encrypted (its body is a bottle).
    /// Handlers can use this to ensure they only act on encrypted messages.
    pub fn is_encrypted(&self) -> bool {
        self.flags & MSG_FLAG_NOT_BOTTLE == 0
    }
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, Error> {
    let (v, n) = read_uvarint(&buf[*pos..]).map_err(|_| Error::Truncated)?;
    *pos += n;
    Ok(v)
}

fn read_name(buf: &[u8], pos: &mut usize) -> Result<String, Error> {
    let ln = read_varint(buf, pos)? as usize;
    if ln > 256 {
        return Err(Error::NameTooLong);
    }
    if buf.len() - *pos < ln {
        return Err(Error::Truncated);
    }
    let s = String::from_utf8_lossy(&buf[*pos..*pos + ln]).into_owned();
    *pos += ln;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let msg = Message {
            message_id: *b"0123456789abcdef",
            flags: MSG_FLAG_RESPONSE | MSG_FLAG_NOT_BOTTLE,
            recipient: "k.abcdef/endpoint".to_string(),
            sender: "/some-uuid".to_string(),
            body: b"hello".to_vec(),
        };
        let buf = msg.to_bytes();
        let back = Message::parse(&buf).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn rejects_short() {
        assert!(Message::parse(&[0u8; 10]).is_err());
    }

    #[test]
    fn rejects_long_name() {
        let mut buf = vec![0u8; 16]; // message id
        buf.push(0); // flags
        bottlers::cbor::append_uvarint(&mut buf, 300); // recipient length
        buf.extend_from_slice(&[b'a'; 300]);
        assert!(matches!(Message::parse(&buf), Err(Error::NameTooLong)));
    }
}
