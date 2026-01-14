mod authorizer;
pub mod context;
pub mod ffi;
pub mod label;
pub mod views;

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rusqlite::{Connection, Result};
use std::collections::HashMap;
use std::ffi::{c_char, c_int};

use context::SecurityContext;

/// Global map: db handle address -> SecurityContext
pub static CONTEXTS: Lazy<Mutex<HashMap<usize, SecurityContext>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Get or create context for a connection
pub fn get_context(db_ptr: usize) -> SecurityContext {
    CONTEXTS.lock().entry(db_ptr).or_default().clone()
}

pub fn set_context(db_ptr: usize, ctx: SecurityContext) {
    CONTEXTS.lock().insert(db_ptr, ctx);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_secext_init(
    db: *mut rusqlite::ffi::sqlite3,
    _pz_err_msg: *mut *mut c_char,
    p_api: *mut rusqlite::ffi::sqlite3_api_routines,
) -> c_int {
    unsafe {
        // Initialize the API for loadable extensions
        if let Err(_) = rusqlite::ffi::rusqlite_extension_init2(p_api) {
            return rusqlite::ffi::SQLITE_ERROR;
        }

        if init_extension_ffi(db).is_err() {
            return rusqlite::ffi::SQLITE_ERROR;
        }

        // Install authorizer
        authorizer::install(db);

        rusqlite::ffi::SQLITE_OK
    }
}

/// Initialize using raw FFI (for loadable extension)
fn init_extension_ffi(db: *mut rusqlite::ffi::sqlite3) -> Result<()> {
    unsafe {
        let conn = Connection::from_handle(db)?;

        // Create metadata tables
        conn.execute_batch(
            r#"
        CREATE TABLE IF NOT EXISTS sec_labels (
            id   INTEGER PRIMARY KEY,
            expr TEXT NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS sec_tables (
            logical_name   TEXT PRIMARY KEY,
            physical_name  TEXT NOT NULL,
            row_label_col  TEXT NOT NULL,
            table_label_id INTEGER REFERENCES sec_labels(id)
        );

        CREATE TABLE IF NOT EXISTS sec_columns (
            logical_table TEXT NOT NULL,
            column_name   TEXT NOT NULL,
            label_id      INTEGER REFERENCES sec_labels(id),
            PRIMARY KEY (logical_table, column_name)
        );
        "#,
        )?;

        std::mem::forget(conn); // Don't close the connection we don't own

        // Register functions via FFI
        ffi::register_functions_ffi(db);

        Ok(())
    }
}