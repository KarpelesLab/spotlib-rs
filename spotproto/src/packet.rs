use crate::error::Error;
use crate::handshake::{HandshakeRequest, HandshakeResponse};
use crate::message::Message;

/// Ping/pong keep-alive packet type id.
pub const PING_PONG: u8 = 0x0;
/// Handshake request or response packet type id.
pub const HANDSHAKE: u8 = 0x1;
/// Instant message packet type id.
pub const INSTANT_MSG: u8 = 0x2;

/// A parsed protocol packet.
#[derive(Debug, Clone)]
pub enum Packet {
    /// Ping (C→S) / pong (S→C); the payload is echoed back unchanged.
    Ping(Vec<u8>),
    /// Handshake request (parsed on the client side).
    HandshakeRequest(HandshakeRequest),
    /// Handshake response (parsed on the server side).
    HandshakeResponse(HandshakeResponse),
    /// Instant message.
    Message(Message),
}

impl Packet {
    /// Serializes the packet to its full wire format, including the leading
    /// version/type byte.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let (typ, payload) = match self {
            Packet::Ping(data) => (PING_PONG, data.clone()),
            Packet::HandshakeRequest(req) => (HANDSHAKE, req.to_cbor()?),
            Packet::HandshakeResponse(res) => (HANDSHAKE, res.to_cbor()?),
            Packet::Message(msg) => (INSTANT_MSG, msg.to_bytes()),
        };
        let mut buf = Vec::with_capacity(payload.len() + 1);
        buf.push(typ);
        buf.extend_from_slice(&payload);
        Ok(buf)
    }
}

/// Returns the version and packet id encoded in a packet's first byte.
pub fn version_and_packet(v: u8) -> (u8, u8) {
    (v >> 4 & 0xf, v & 0xf)
}

/// Decodes a raw buffer into the appropriate [`Packet`]. `is_client`
/// indicates whether this is parsed on the client side, which decides how
/// handshake packets are interpreted.
pub fn parse(buf: &[u8], is_client: bool) -> Result<Packet, Error> {
    if buf.is_empty() {
        return Err(Error::EmptyBuffer);
    }
    let (vers, pkt) = version_and_packet(buf[0]);
    if vers != 0 {
        return Err(Error::InvalidVersion(vers, pkt));
    }
    let buf = &buf[1..];
    match pkt {
        PING_PONG => Ok(Packet::Ping(buf.to_vec())),
        HANDSHAKE => {
            if is_client {
                Ok(Packet::HandshakeRequest(HandshakeRequest::from_cbor(buf)?))
            } else {
                Ok(Packet::HandshakeResponse(HandshakeResponse::from_cbor(buf)?))
            }
        }
        INSTANT_MSG => Ok(Packet::Message(Message::parse(buf)?)),
        _ => Err(Error::UnknownPacket(pkt)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ping() {
        let pkt = parse(&[0x00, 1, 2, 3], true).unwrap();
        match pkt {
            Packet::Ping(data) => assert_eq!(data, vec![1, 2, 3]),
            _ => panic!("expected ping"),
        }
    }

    #[test]
    fn rejects_bad_version() {
        assert!(matches!(
            parse(&[0x10], true),
            Err(Error::InvalidVersion(1, 0))
        ));
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(parse(&[], true), Err(Error::EmptyBuffer)));
    }

    #[test]
    fn message_packet_round_trip() {
        let msg = Message {
            message_id: [7; 16],
            flags: 0,
            recipient: "k.x/ep".into(),
            sender: "/id".into(),
            body: b"data".to_vec(),
        };
        let buf = Packet::Message(msg.clone()).encode().unwrap();
        assert_eq!(buf[0], INSTANT_MSG);
        match parse(&buf, true).unwrap() {
            Packet::Message(m) => assert_eq!(m, msg),
            _ => panic!("expected message"),
        }
    }
}
