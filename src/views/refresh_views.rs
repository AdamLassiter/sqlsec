use std::mem::forget;

use rusqlite::{Connection, Error, Result};

use crate::{
    context::{effective_context, sec_ctx::SecurityContext},
    label::evaluate::is_visible_conn,
    views::{SecColumn, SecTable, write_triggers::create_write_triggers},
};

fn refresh_err(err: Error, table: &str) -> Error {
    Error::UserFunctionError(Box::new(std::io::Error::other(format!(
        "sqlsec refresh failed for table '{}': {}",
        table, err
    ))))
}

/// Refresh views using Connection reference
pub fn refresh_views(conn: &mut Connection, ctx: &SecurityContext) -> Result<()> {
    let tx = conn.transaction()?; // BEGIN

    let tables = load_sec_tables(&tx)?;

    for table in tables {
        refresh_single_view(&tx, &table, ctx).map_err(|e| refresh_err(e, &table.logical_name))?;
    }

    tx.execute_batch(
        r#"
        INSERT OR REPLACE INTO sec_meta (key, value)
        VALUES ('last_refresh_generation',
            (SELECT value FROM sec_meta WHERE key = 'generation'));

        INSERT OR REPLACE INTO sec_meta (key, value)
        VALUES ('views_initialized', 1);
        "#,
    )?;

    tx.commit()?; // COMMIT
    Ok(())
}

/// Refresh views from raw pointer (for FFI)
pub fn refresh_views_raw(db_ptr: usize) -> Result<()> {
    let mut conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };

    let ctx = effective_context(db_ptr);

    let result = refresh_views(&mut conn, &ctx);

    forget(conn);
    result
}

fn refresh_single_view(conn: &Connection, table: &SecTable, ctx: &SecurityContext) -> Result<()> {
    // Check table-level visibility
    if !is_visible_conn(conn, table.table_label_id, ctx) {
        conn.execute(
            &format!("DROP VIEW IF EXISTS \"{}\"", table.logical_name),
            [],
        )?;
        return Ok(());
    }

    // Get columns and filter by visibility
    let all_columns = load_sec_columns(conn, &table.logical_name)?;
    let visible_columns: Vec<&str> = all_columns
        .iter()
        .filter(|c| is_visible_conn(conn, c.label_id, ctx))
        .map(|c| c.column_name.as_str())
        .collect();

    if visible_columns.is_empty() {
        conn.execute(
            &format!("DROP VIEW IF EXISTS \"{}\"", table.logical_name),
            [],
        )?;
        return Ok(());
    }

    // Build SELECT list
    let select_cols = visible_columns
        .iter()
        .map(|c| format!("\"{}\"", c))
        .collect::<Vec<_>>()
        .join(", ");

    // Build the view DDL
    let view_sql = format!(
        r#"
        DROP VIEW IF EXISTS "{}";
        CREATE TEMP VIEW "{}" AS
        SELECT {}
        FROM "{}"
        WHERE sec_assert_fresh()
          AND sec_row_visible("{}");
        "#,
        table.logical_name,
        table.logical_name,
        select_cols,
        table.physical_name,
        table.row_label_col
    );

    conn.execute_batch(&view_sql)?;

    // Create INSTEAD OF triggers for writes
    create_write_triggers(conn, table, &visible_columns)?;

    Ok(())
}

fn load_sec_tables(conn: &Connection) -> Result<Vec<SecTable>> {
    let mut stmt = conn.prepare(
        "SELECT logical_name, physical_name, row_label_col, table_label_id, insert_label_id FROM sec_tables",
    )?;

    let tables = stmt
        .query_map([], |row| {
            Ok(SecTable {
                logical_name: row.get(0)?,
                physical_name: row.get(1)?,
                row_label_col: row.get(2)?,
                table_label_id: row.get(3)?,
                insert_label_id: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>>>()?;

    Ok(tables)
}

fn load_sec_columns(conn: &Connection, logical_table: &str) -> Result<Vec<SecColumn>> {
    let mut stmt =
        conn.prepare("SELECT column_name, label_id FROM sec_columns WHERE logical_table = ?1")?;

    let cols = stmt
        .query_map([logical_table], |row| {
            Ok(SecColumn {
                column_name: row.get(0)?,
                label_id: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>>>()?;

    Ok(cols)
}
