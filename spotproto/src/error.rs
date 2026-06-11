use std::fmt;

/// Errors returned by the protocol parser and serializers.
#[derive(Debug)]
pub enum Error {
    /// Attempted to parse an empty buffer.
    EmptyBuffer,
    /// The packet carries an unsupported protocol version (version, packet id).
    InvalidVersion(u8, u8),
    /// The packet type id is not known.
    UnknownPacket(u8),
    /// The buffer ended before the packet was fully decoded.
    Truncated,
    /// A name (sender/recipient) length exceeds the 256 byte limit.
    NameTooLong,
    /// CBOR encoding or decoding failed.
    Cbor(String),
    /// A cryptographic operation failed.
    Bottle(bottlers::BottleError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::EmptyBuffer => write!(f, "empty buffer"),
            Error::InvalidVersion(v, p) => {
                write!(f, "invalid packet version {v} (packet {p})")
            }
            Error::UnknownPacket(p) => {
                write!(f, "failed to parse message: unknown packet id {p:x}")
            }
            Error::Truncated => write!(f, "truncated packet"),
            Error::NameTooLong => write!(f, "cannot read name from packet: too long"),
            Error::Cbor(e) => write!(f, "cbor error: {e}"),
            Error::Bottle(e) => write!(f, "bottle error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<bottlers::BottleError> for Error {
    fn from(e: bottlers::BottleError) -> Self {
        Error::Bottle(e)
    }
}
