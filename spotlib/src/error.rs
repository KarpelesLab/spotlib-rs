use std::fmt;
use std::io;

/// Errors returned by the spot client.
#[derive(Debug)]
pub enum Error {
    /// Network I/O failure.
    Io(io::Error),
    /// TLS failure.
    Tls(String),
    /// WebSocket protocol failure.
    Ws(String),
    /// Spot protocol failure.
    Proto(spotproto::Error),
    /// Cryptographic (bottle) failure.
    Bottle(bottlers::BottleError),
    /// Spot API (REST) failure.
    Api(String),
    /// The operation timed out.
    Timeout,
    /// The client has been closed.
    Closed,
    /// The target address is invalid.
    InvalidTarget(String),
    /// The remote responded with an error message.
    Remote(String),
    /// Anything else.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Tls(e) => write!(f, "tls error: {e}"),
            Error::Ws(e) => write!(f, "websocket error: {e}"),
            Error::Proto(e) => write!(f, "protocol error: {e}"),
            Error::Bottle(e) => write!(f, "crypto error: {e}"),
            Error::Api(e) => write!(f, "api error: {e}"),
            Error::Timeout => write!(f, "operation timed out"),
            Error::Closed => write!(f, "client is closed"),
            Error::InvalidTarget(t) => write!(f, "invalid target {t}"),
            Error::Remote(e) => write!(f, "{e}"),
            Error::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Proto(e) => Some(e),
            Error::Bottle(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<spotproto::Error> for Error {
    fn from(e: spotproto::Error) -> Self {
        Error::Proto(e)
    }
}

impl From<bottlers::BottleError> for Error {
    fn from(e: bottlers::BottleError) -> Self {
        Error::Bottle(e)
    }
}

/// Convenience result alias for spotlib operations.
pub type Result<T> = std::result::Result<T, Error>;
