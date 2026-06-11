//! Small helpers: UUID v4 generation and formatting.

use purecrypto::rng::{OsRng, RngCore};

/// Generates a random (version 4) UUID.
pub fn uuid_v4() -> [u8; 16] {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    b
}

/// Formats a UUID in its canonical hyphenated lowercase form.
pub fn uuid_string(b: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_format() {
        let u = uuid_v4();
        let s = uuid_string(&u);
        assert_eq!(s.len(), 36);
        assert_eq!(s.as_bytes()[8], b'-');
        assert_eq!(s.as_bytes()[13], b'-');
        assert_eq!(&s[14..15], "4"); // version nibble
    }
}
