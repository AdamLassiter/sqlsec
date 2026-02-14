//! Helpers used by the VFS I/O layer.

use std::{collections::HashMap, sync::Arc};

use crate::{crypto::keys::KeyScope, keyring::Keyring};

/// Shared context carried by every open file handle.
pub struct FileContext {
    pub keyring: Arc<Keyring>,
    pub page_size: u32,
    pub reserve_size: usize,
    /// Lazily-built map from btree root page → KeyScope.
    /// `None` means "use Database scope for everything".
    pub page_scope_map: Option<HashMap<u32, KeyScope>>,
}

impl FileContext {
    pub fn encrypt_page(&self, page: &mut [u8], page_no: u32) -> anyhow::Result<()> {
        let dek = self
            .keyring
            .dek_for_page(page_no, self.page_scope_map.as_ref())?;
        crate::crypto::page::encrypt_page(page, page_no, &dek, self.reserve_size)
    }

    pub fn decrypt_page(&self, page: &mut [u8], page_no: u32) -> anyhow::Result<()> {
        let dek = self
            .keyring
            .dek_for_page(page_no, self.page_scope_map.as_ref())?;
        crate::crypto::page::decrypt_page(page, page_no, &dek, self.reserve_size)
    }

    /// Build the page→scope map by querying sqlite_master.
    ///
    /// Called lazily on first read/write if per-table encryption is
    /// enabled. Requires a separate read of page 1 (the schema
    /// table) which is always encrypted under `KeyScope::Database`.
    pub fn build_page_scope_map(&mut self, root_pages: &[(String, u32)]) {
        let mut map = HashMap::new();
        for (table_name, root_page) in root_pages {
            map.insert(*root_page, KeyScope::Table(table_name.clone()));
        }
        self.page_scope_map = Some(map);
    }
}
