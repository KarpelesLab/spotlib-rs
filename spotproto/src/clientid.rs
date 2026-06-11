use std::fmt;

use bottlers::IDCard;

use crate::encoding::base64url_encode;

/// A client identifier in the protocol, in the form `type.target` or
/// `type.server_id.target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientId {
    /// Identifier type (`b'k'` for key-based, `b'c'` for connection,
    /// `b'g'` for group).
    pub typ: u8,
    /// Server identifier (empty for global IDs).
    pub server_id: String,
    /// The specific identifier value (key hash, connection name, etc.).
    pub target: String,
}

impl ClientId {
    /// Creates a key-based client ID from an ID card. The target is the
    /// base64url-encoded SHA-256 hash of the card's primary public key.
    pub fn from_idcard(id: &IDCard) -> ClientId {
        let h = bottlers::hash::sha256(&id.self_key);
        ClientId {
            typ: b'k',
            server_id: String::new(),
            target: base64url_encode(&h),
        }
    }
}

impl fmt::Display for ClientId {
    /// Formats the client ID in its canonical string form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.server_id.is_empty() {
            write!(f, "{}.{}", self.typ as char, self.target)
        } else {
            write!(f, "{}.{}.{}", self.typ as char, self.server_id, self.target)
        }
    }
}
