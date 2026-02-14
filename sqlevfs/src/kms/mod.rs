pub mod cloud;
pub mod local;

use crate::crypto::keys::KekId;

/// Synchronous interface for obtaining key-encryption keys.
pub trait KmsProvider: Send + Sync + 'static {
    /// Return the current active KEK (id + raw bytes).
    fn get_kek(&self) -> anyhow::Result<(KekId, Vec<u8>)>;

    /// Retrieve a specific KEK by id (needed during rotation to
    /// unwrap DEKs wrapped under older KEKs).
    fn get_kek_by_id(&self, id: &KekId) -> anyhow::Result<Vec<u8>>;

    /// Optional: ask the KMS to wrap a blob directly (for providers
    /// where the KEK never leaves the HSM). Default falls back to
    /// local envelope encryption.
    fn wrap_blob(&self, _plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("direct wrap not supported; use local envelope")
    }

    /// Optional: ask the KMS to unwrap a blob directly.
    fn unwrap_blob(&self, _ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("direct unwrap not supported; use local envelope")
    }
}
