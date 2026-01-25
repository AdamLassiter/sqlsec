pub mod bump_generation;
pub mod refresh_views;
pub mod register_table;
pub mod write_triggers;

use std::io::ErrorKind;

use rusqlite::{Connection, Error, Result};

#[derive(Debug)]
pub struct SecTable {
    logical_name: String,
    physical_name: String,
    row_label_col: String,
    table_label_id: Option<i64>,
    insert_label_id: Option<i64>,
}

#[derive(Debug)]
pub struct SecColumn {
    column_name: String,
    label_id: Option<i64>,
}

fn get_physical_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{}\")", table))?;
    let cols = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>>>()?;
    Ok(cols)
}

fn get_primary_key_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{}\")", table))?;

    let mut pk_cols: Vec<(i64, String)> = Vec::new();

    let rows = stmt.query_map([], |row| {
        let name: String = row.get(1)?;
        let pk: i64 = row.get(5)?;
        Ok((pk, name))
    })?;

    for row in rows {
        let (pk, name) = row?;
        if pk > 0 {
            pk_cols.push((pk, name));
        }
    }

    // Sort by PK position (important for composite keys)
    pk_cols.sort_by_key(|(pk, _)| *pk);

    Ok(pk_cols.into_iter().map(|(_, name)| name).collect())
}

fn invalid<T: ToString>(msg: T) -> Error {
    Error::UserFunctionError(Box::new(std::io::Error::new(
        ErrorKind::InvalidInput,
        msg.to_string(),
    )))
}
