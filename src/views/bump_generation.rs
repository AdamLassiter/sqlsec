use std::mem::forget;

use rusqlite::{Connection, Result};

pub fn bump_generation(conn: &mut Connection) -> Result<()> {
    conn.execute(
        r#"
        UPDATE sec_meta
        SET value = value + 1
        WHERE key = 'generation';
        "#,
        [],
    )?;
    Ok(())
}

pub fn bump_generation_raw(db_ptr: usize) -> Result<()> {
    let mut conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };

    let result = bump_generation(&mut conn);

    forget(conn);
    result
}
