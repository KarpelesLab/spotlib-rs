//! Disk-backed key storage: persists client identity keys as PEM-encoded
//! PKCS#8 files (`id_<type>.key`) in a configuration directory, generating an
//! ECDSA P-256 key on first use.

use std::path::{Path, PathBuf};

use bottlers::{Keychain, PrivateKey};
use purecrypto::der::{pem_decode, pem_encode, Reader};
use purecrypto::ec::boxed::BoxedEcdsaPrivateKey;
use purecrypto::ec::ecdsa::EcdsaPrivateKey;
use purecrypto::ec::CurveId;

use crate::error::{Error, Result};
use crate::identity::clone_private_key;

/// Stores client identity keys on disk.
pub struct DiskStore {
    path: PathBuf,
    keys: Vec<PrivateKey>,
}

impl DiskStore {
    /// Opens (or initializes) the default store at
    /// `$XDG_CONFIG_HOME/spot` (falling back to `~/.config/spot`).
    /// If no key exists yet, a new ECDSA P-256 key is generated.
    pub fn new() -> Result<DiskStore> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".config")))
            .ok_or_else(|| Error::Other("cannot determine config directory".into()))?;
        Self::with_path(base.join("spot"))
    }

    /// Opens (or initializes) a store at the given path. If no key exists, a
    /// new ECDSA P-256 key is generated.
    pub fn with_path(path: impl Into<PathBuf>) -> Result<DiskStore> {
        let path = path.into();
        std::fs::create_dir_all(&path)?;
        restrict_dir(&path);

        let mut store = DiskStore {
            path,
            keys: Vec::new(),
        };
        store.load_keys()?;
        if store.keys.is_empty() {
            store.generate_key()?;
        }
        Ok(store)
    }

    /// The directory where keys are stored.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Builds a keychain holding (copies of) the stored keys, suitable for
    /// [`crate::ClientBuilder::keychain`].
    pub fn keychain(&self) -> Result<Keychain> {
        let mut kc = Keychain::new();
        for key in &self.keys {
            kc.add_key(clone_private_key(key)?)?;
        }
        Ok(kc)
    }

    /// Adds a key to the store, persisting it to disk. `key_type` names the
    /// file (e.g. "ecdsa", "rsa").
    pub fn add_key(&mut self, key: PrivateKey, key_type: &str) -> Result<()> {
        let der = private_key_pkcs8(&key)?;
        let pem = pem_encode("PRIVATE KEY", &der);

        let mut path = self.path.join(format!("id_{key_type}.key"));
        let mut n = 0;
        while path.exists() {
            n += 1;
            path = self.path.join(format!("id_{key_type}_{n}.key"));
        }
        write_restricted(&path, pem.as_bytes())?;
        self.keys.push(key);
        Ok(())
    }

    fn load_keys(&mut self) -> Result<()> {
        let entries = match std::fs::read_dir(&self.path) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(Error::Io(e)),
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("id_") || !name.ends_with(".key") {
                continue;
            }
            // load what we can, skip unreadable/unsupported files
            if let Ok(data) = std::fs::read_to_string(entry.path()) {
                if let Ok(key) = parse_key_pem(&data) {
                    self.keys.push(key);
                }
            }
        }
        Ok(())
    }

    fn generate_key(&mut self) -> Result<()> {
        let sk = EcdsaPrivateKey::generate(&mut purecrypto::rng::OsRng);
        self.add_key(PrivateKey::Ecdsa(sk), "ecdsa")
    }
}

/// Parses a PEM-encoded PKCS#8 private key into a bottlers key.
fn parse_key_pem(pem: &str) -> Result<PrivateKey> {
    let der = pem_decode(pem, "PRIVATE KEY")
        .map_err(|e| Error::Other(format!("failed to decode PEM block: {e:?}")))?;
    if let Ok(boxed) = BoxedEcdsaPrivateKey::from_pkcs8_der(&der) {
        if boxed.curve() != CurveId::P256 {
            return Err(Error::Other("only P-256 ECDSA keys are supported".into()));
        }
        return Ok(PrivateKey::Ecdsa(ecdsa_from_boxed(&boxed)?));
    }
    if let Ok(rsa) = purecrypto::rsa::BoxedRsaPrivateKey::from_pkcs8_der(&der) {
        return Ok(PrivateKey::Rsa(rsa));
    }
    Err(Error::Other("unsupported private key type".into()))
}

/// Serializes a bottlers private key to PKCS#8 DER.
fn private_key_pkcs8(key: &PrivateKey) -> Result<Vec<u8>> {
    match key {
        PrivateKey::Ecdsa(sk) => {
            let boxed = BoxedEcdsaPrivateKey::from_bytes(CurveId::P256, &sk.to_bytes())
                .map_err(|e| Error::Other(format!("bad ecdsa key: {e:?}")))?;
            Ok(boxed.to_pkcs8_der())
        }
        PrivateKey::Rsa(sk) => Ok(sk.to_pkcs8_der()),
        _ => Err(Error::Other(
            "unsupported key type for disk storage".into(),
        )),
    }
}

/// Extracts the P-256 scalar from a boxed key (purecrypto exposes no direct
/// scalar accessor, so we go through the SEC1 encoding).
fn ecdsa_from_boxed(boxed: &BoxedEcdsaPrivateKey) -> Result<EcdsaPrivateKey> {
    let sec1 = boxed.to_sec1_der();
    let parse = || -> std::result::Result<EcdsaPrivateKey, String> {
        let mut r = Reader::new(&sec1);
        let mut seq = r.read_sequence().map_err(|e| format!("{e:?}"))?;
        let _version = seq.read_integer_bytes().map_err(|e| format!("{e:?}"))?;
        let d = seq.read_octet_string().map_err(|e| format!("{e:?}"))?;
        let d: [u8; 32] = d.try_into().map_err(|_| "bad scalar length".to_string())?;
        EcdsaPrivateKey::from_bytes(&d).map_err(|e| format!("{e:?}"))
    };
    parse().map_err(|e| Error::Other(format!("failed to extract ecdsa scalar: {e}")))
}

#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) {}

fn write_restricted(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_reload() {
        let dir = std::env::temp_dir().join(format!("spotlib-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let store = DiskStore::with_path(&dir).unwrap();
        let kc = store.keychain().unwrap();
        let pkix1 = kc.first_signer().unwrap().public_pkix().unwrap();

        // reloading must yield the same key
        let store2 = DiskStore::with_path(&dir).unwrap();
        let kc2 = store2.keychain().unwrap();
        let pkix2 = kc2.first_signer().unwrap().public_pkix().unwrap();
        assert_eq!(pkix1, pkix2);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
