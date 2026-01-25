use std::mem::forget;

use rusqlite::{Connection, Result};

use crate::label::{LABEL_CACHE, parse::parse};



/// Define a label using a Connection reference (for tests and direct use)
pub fn define_label(conn: &Connection, expr: &str) -> Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO sec_labels (expr) VALUES (?1)",
        [expr],
    )?;

    let id: i64 = conn.query_row("SELECT id FROM sec_labels WHERE expr = ?1", [expr], |r| {
        r.get(0)
    })?;

    if let Ok(label) = parse(expr) {
        LABEL_CACHE.lock().insert(id, label);
    }

    Ok(id)
}

/// Define a label from raw db pointer (for FFI)
pub fn define_label_raw(db_ptr: usize, expr: &str) -> Result<i64> {
    let conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };
    let result = define_label(&conn, expr);
    forget(conn);
    result
}
