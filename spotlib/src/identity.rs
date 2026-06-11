//! Identity helpers on top of bottlers: key duplication, IDCard subkey
//! population and group membership updates.
//!
//! These mirror gobottle APIs that bottlers 0.1.0 does not expose yet
//! (`Keychain` is consumed by `Opener::new`, `PrivateKey` is not `Clone`,
//! and `IDCard.AddKeychain` / `UpdateGroups` / `OpenResult.SignedBy(IDCard)`
//! have no direct equivalent).

use bottlers::{IDCard, Membership, OpenResult, PrivateKey, SubKey};
use ciborium::value::Value;

use crate::error::{Error, Result};

/// Duplicates a private key by round-tripping its secret material.
/// Supported variants: ECDSA P-256, Ed25519, RSA. Other key types cannot be
/// duplicated with the current purecrypto API.
pub fn clone_private_key(key: &PrivateKey) -> Result<PrivateKey> {
    match key {
        PrivateKey::Ecdsa(sk) => {
            let copy = purecrypto::ec::ecdsa::EcdsaPrivateKey::from_bytes(&sk.to_bytes())
                .map_err(|e| Error::Other(format!("bad ecdsa key: {e:?}")))?;
            Ok(PrivateKey::Ecdsa(copy))
        }
        PrivateKey::Ed25519(sk) => Ok(PrivateKey::Ed25519(
            purecrypto::ec::Ed25519PrivateKey::from_bytes(sk.to_bytes()),
        )),
        PrivateKey::Rsa(sk) => {
            let copy = purecrypto::rsa::BoxedRsaPrivateKey::from_pkcs8_der(&sk.to_pkcs8_der())
                .map_err(|e| Error::Other(format!("bad rsa key: {e:?}")))?;
            Ok(PrivateKey::Rsa(copy))
        }
        _ => Err(Error::Other(
            "unsupported key type for spot client identity".into(),
        )),
    }
}

/// Returns the purposes a key should be listed with on an ID card, mirroring
/// gobottle's `IDCard.AddKeychain` detection.
fn key_purposes(key: &PrivateKey) -> &'static [&'static str] {
    match key {
        PrivateKey::Ecdsa(_) => &["decrypt", "sign"],
        PrivateKey::Rsa(_) => &["decrypt", "sign"],
        PrivateKey::Ed25519(_) => &["sign"],
        PrivateKey::X25519(_) => &["decrypt"],
        PrivateKey::MlKem(_) => &["decrypt"],
        PrivateKey::MlDsa44(_) | PrivateKey::MlDsa65(_) | PrivateKey::MlDsa87(_) => &["sign"],
        PrivateKey::SlhDsa(_) => &["sign"],
    }
}

/// Adds the keys of a keychain to the ID card with their detected purposes
/// (the port of gobottle's `IDCard.AddKeychain`).
pub fn add_keychain(id: &mut IDCard, kc: &bottlers::Keychain) -> Result<()> {
    let now = now_unix();
    for key in kc.keys() {
        let purposes = key_purposes(key);
        if purposes.is_empty() {
            continue;
        }
        let pkix = key.public_pkix()?;
        add_key_purposes(id, pkix, purposes, now);
    }
    Ok(())
}

/// Adds purposes to the subkey matching `pkix`, creating the entry if needed.
pub fn add_key_purposes(id: &mut IDCard, pkix: Vec<u8>, purposes: &[&str], now: i64) {
    if let Some(sub) = id.subkeys.iter_mut().find(|s| s.key == pkix) {
        sub.add_purpose(purposes);
    } else {
        let mut sub = SubKey {
            key: pkix,
            issued: now,
            expires: None,
            purposes: Vec::new(),
        };
        sub.add_purpose(purposes);
        id.subkeys.push(sub);
    }
}

/// Updates the ID card's group memberships from signed membership records
/// (the port of gobottle's `IDCard.UpdateGroups`).
pub fn update_groups(id: &mut IDCard, data: &[Vec<u8>]) -> Result<()> {
    for buf in data {
        let m = parse_membership(buf)?;
        // check if it's an update for us
        if m.subject.as_deref() != Some(id.self_key.as_slice()) {
            continue;
        }
        // check signature
        m.verify(None)
            .map_err(|e| Error::Other(format!("failed to verify membership: {e}")))?;
        let groups = id.groups.get_or_insert_with(Vec::new);
        if m.status != "valid" {
            // no longer a member: remove the membership if we have it
            groups.retain(|sub| sub.key != m.key);
            continue;
        }
        let mut m = m;
        // the subject is implicit once stored on the card
        m.subject = None;
        if let Some(existing) = groups.iter_mut().find(|sub| sub.key == m.key) {
            *existing = m;
        } else {
            groups.push(m);
        }
    }
    Ok(())
}

/// Parses a standalone CBOR-encoded membership record (integer-keyed map,
/// fields 1..7 — bottlers only decodes these as part of an IDCard).
pub fn parse_membership(buf: &[u8]) -> Result<Membership> {
    let v: Value = ciborium::from_reader(buf)
        .map_err(|e| Error::Other(format!("failed to unmarshal membership: {e}")))?;
    let Value::Map(entries) = v else {
        return Err(Error::Other("membership must be a map".into()));
    };
    let get = |key: i64| -> Option<&Value> {
        entries.iter().find_map(|(k, val)| match k {
            Value::Integer(i) if i128::from(*i) == key as i128 => Some(val),
            _ => None,
        })
    };
    let opt_bytes = |key: i64| -> Option<Vec<u8>> {
        match get(key) {
            Some(Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        }
    };
    let info = match get(5) {
        Some(Value::Map(m)) => {
            let mut out = std::collections::BTreeMap::new();
            for (k, val) in m {
                if let (Value::Text(k), Value::Text(v)) = (k, val) {
                    out.insert(k.clone(), v.clone());
                }
            }
            Some(out)
        }
        _ => None,
    };
    Ok(Membership {
        subject: opt_bytes(1),
        key: opt_bytes(2).ok_or_else(|| Error::Other("membership key missing".into()))?,
        status: match get(3) {
            Some(Value::Text(t)) => t.clone(),
            _ => return Err(Error::Other("membership status missing".into())),
        },
        issued: match get(4) {
            Some(Value::Integer(i)) => i128::from(*i) as i64,
            _ => 0,
        },
        info,
        sign_key: opt_bytes(6),
        signature: opt_bytes(7),
    })
}

/// Returns true if the open result carries a verified signature by any
/// non-expired "sign" subkey of the given ID card (the port of gobottle's
/// `OpenResult.SignedBy`).
pub fn signed_by(info: &OpenResult, id: &IDCard) -> bool {
    let now = now_unix();
    id.subkeys.iter().any(|sub| {
        sub.has_purpose("sign")
            && sub.expires.map(|exp| exp > now).unwrap_or(true)
            && info.signed_by_pkix(&sub.key)
    })
}

/// Current time as Unix seconds.
pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
