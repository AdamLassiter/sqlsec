use std::path::PathBuf;

use argon2::Argon2;
use parking_lot::Mutex;

use super::KmsProvider;
use crate::crypto::keys::KekId;

/// Device-local KEK provider. Reads a 32-byte key from a file, or
/// derives one from a passphrase via Argon2id.
pub struct DeviceKeyProvider {
    id: KekId,
    /// Cached KEK bytes — computed once, then reused.
    cached: Mutex<Option<Vec<u8>>>,
    source: KeySource,
}

enum KeySource {
    File(PathBuf),
    Passphrase(String),
}

/// Fixed salt for passphrase derivation. In production, store a
/// random salt alongside the database and pass it in.
const DEFAULT_SALT: &[u8; 16] = b"evfs-default-slt";

impl DeviceKeyProvider {
    pub fn from_keyfile(path: PathBuf) -> Self {
        let id = KekId(format!("device:file:{}", path.display()));
        Self {
            id,
            cached: Mutex::new(None),
            source: KeySource::File(path),
        }
    }

    pub fn from_passphrase(passphrase: &str) -> Self {
        let id = KekId("device:passphrase".into());
        Self {
            id,
            cached: Mutex::new(None),
            source: KeySource::Passphrase(passphrase.to_owned()),
        }
    }

    fn load_kek(&self) -> anyhow::Result<Vec<u8>> {
        match &self.source {
            KeySource::File(path) => {
                let bytes = std::fs::read(path)?;
                anyhow::ensure!(
                    bytes.len() == 32,
                    "keyfile must be exactly 32 bytes, got {}",
                    bytes.len()
                );
                Ok(bytes)
            }
            KeySource::Passphrase(pw) => {
                let mut kek = [0u8; 32];
                Argon2::default()
                    .hash_password_into(pw.as_bytes(), DEFAULT_SALT, &mut kek)
                    .map_err(|e| anyhow::anyhow!("argon2 failed: {e}"))?;
                Ok(kek.to_vec())
            }
        }
    }

    fn get_cached_or_load(&self) -> anyhow::Result<Vec<u8>> {
        let mut guard = self.cached.lock();
        if let Some(ref cached) = *guard {
            return Ok(cached.clone());
        }
        let kek = self.load_kek()?;
        *guard = Some(kek.clone());
        Ok(kek)
    }
}

impl KmsProvider for DeviceKeyProvider {
    fn get_kek(&self) -> anyhow::Result<(KekId, Vec<u8>)> {
        let bytes = self.get_cached_or_load()?;
        Ok((self.id.clone(), bytes))
    }

    fn get_kek_by_id(&self, id: &KekId) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            id == &self.id,
            "unknown KEK id: {id:?} (expected {:?})",
            self.id
        );
        self.get_cached_or_load()
    }
}
