use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::Aead,
};

use super::keys::Dek;

const TAG_LEN: usize = 16;

/// Encrypt a database page in place.
///
/// Layout after encryption:
/// ```text
/// [ encrypted payload          | TAG (16) | unused reserved ]
/// |<-- page_len - reserve -->|  |<-------- reserve -------->|
/// ```
///
/// The nonce is derived deterministically from the page number.
/// This is safe because each (DEK, page_no) pair is unique and
/// DEKs are random. On key rotation the DEK changes.
pub fn encrypt_page(
    page: &mut [u8],
    page_no: u32,
    dek: &Dek,
    reserve: usize,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        reserve >= TAG_LEN,
        "reserve ({reserve}) must be >= {TAG_LEN}"
    );
    let page_len = page.len();
    let payload_len = page_len - reserve;

    let nonce_bytes = page_nonce(page_no);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(dek.as_bytes())?;

    // Encrypt the payload portion only.
    let ciphertext = cipher
        .encrypt(nonce, &page[..payload_len])
        .map_err(|e| anyhow::anyhow!("page encrypt failed: {e}"))?;

    // ciphertext = encrypted_payload || tag
    let ct_len = ciphertext.len() - TAG_LEN;
    debug_assert_eq!(ct_len, payload_len);

    page[..ct_len].copy_from_slice(&ciphertext[..ct_len]);
    page[payload_len..payload_len + TAG_LEN]
        .copy_from_slice(&ciphertext[ct_len..]);

    Ok(())
}

/// Decrypt a database page in place.
pub fn decrypt_page(
    page: &mut [u8],
    page_no: u32,
    dek: &Dek,
    reserve: usize,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        reserve >= TAG_LEN,
        "reserve ({reserve}) must be >= {TAG_LEN}"
    );
    let page_len = page.len();
    let payload_len = page_len - reserve;

    let nonce_bytes = page_nonce(page_no);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(dek.as_bytes())?;

    // Reassemble the ciphertext+tag buffer aes-gcm expects.
    let mut buf = Vec::with_capacity(payload_len + TAG_LEN);
    buf.extend_from_slice(&page[..payload_len]);
    buf.extend_from_slice(&page[payload_len..payload_len + TAG_LEN]);

    let plaintext = cipher
        .decrypt(nonce, buf.as_ref())
        .map_err(|e| anyhow::anyhow!("page decrypt failed: {e}"))?;

    page[..plaintext.len()].copy_from_slice(&plaintext);
    // Zero out the tag area in the reserved region.
    page[payload_len..payload_len + TAG_LEN].fill(0);

    Ok(())
}

/// Deterministic nonce from page number.
fn page_nonce(page_no: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&page_no.to_le_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Dek;

    #[test]
    fn round_trip() {
        let dek = Dek::generate();
        let reserve = 32;
        let page_size = 4096;
        let mut page = vec![0xABu8; page_size];
        let original = page.clone();

        encrypt_page(&mut page, 1, &dek, reserve).unwrap();
        assert_ne!(&page[..page_size - reserve], &original[..page_size - reserve]);

        decrypt_page(&mut page, 1, &dek, reserve).unwrap();
        assert_eq!(&page[..page_size - reserve], &original[..page_size - reserve]);
    }

    #[test]
    fn wrong_key_fails() {
        let dek1 = Dek::generate();
        let dek2 = Dek::generate();
        let reserve = 32;
        let mut page = vec![0xCDu8; 4096];

        encrypt_page(&mut page, 1, &dek1, reserve).unwrap();
        assert!(decrypt_page(&mut page, 1, &dek2, reserve).is_err());
    }

    #[test]
    fn wrong_page_no_fails() {
        let dek = Dek::generate();
        let reserve = 32;
        let mut page = vec![0xEFu8; 4096];

        encrypt_page(&mut page, 1, &dek, reserve).unwrap();
        assert!(decrypt_page(&mut page, 2, &dek, reserve).is_err());
    }
}