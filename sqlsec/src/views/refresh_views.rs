use std::mem::forget;

use rusqlite::{Connection, Error, Result};

use crate::{
    context::{effective_context, sec_ctx::SecurityContext},
    label::evaluate::{is_visible_conn, load_levels},
    views::{SecTable, get_sec_columns, get_sec_tables, write_triggers::create_write_triggers},
};

fn refresh_err(err: Error, table: &str) -> Error {
    Error::UserFunctionError(Box::new(std::io::Error::other(format!(
        "sqlsec refresh failed for table '{}': {}",
        table, err
    ))))
}

/// Refresh views using Connection reference
pub fn refresh_views(conn: &mut Connection, ctx: &SecurityContext) -> Result<()> {
    load_levels(conn)?;

    let tx = conn.transaction()?; // BEGIN

    let tables = get_sec_tables(&tx)?;

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
    let all_columns = get_sec_columns(conn, &table.logical_name)?;
    let visible_columns: Vec<&str> = all_columns
        .iter()
        .filter(|c| is_visible_conn(conn, c.read_label_id, ctx))
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
          AND sec_label_visible("{}");
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
