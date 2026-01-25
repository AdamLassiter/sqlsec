use rusqlite::{Connection, Result};

use crate::views::{SecTable, get_primary_key_columns, invalid};

pub fn create_write_triggers(
    conn: &Connection,
    table: &SecTable,
    visible_cols: &[&str],
) -> Result<()> {
    let logical = &table.logical_name;
    let physical = &table.physical_name;
    let row_label_col = &table.row_label_col;

    let insert_cols = visible_cols
        .iter()
        .map(|c| format!("\"{}\"", c))
        .collect::<Vec<_>>()
        .join(", ");

    let insert_vals = visible_cols
        .iter()
        .map(|c| format!("NEW.\"{}\"", c))
        .collect::<Vec<_>>()
        .join(", ");

    let refesh_guard = r#"
        SELECT CASE
            WHEN (SELECT value FROM sec_meta WHERE key = 'generation')
               != (SELECT value FROM sec_meta WHERE key = 'last_refresh_generation')
            THEN RAISE(ABORT, 'security views are stale: call sec_refresh_views()')
        END;
        "#;

    let row_label_assignment = if table.insert_label_id.is_some() {
        format!(
            r#"COALESCE(
                (
                    SELECT insert_label_id
                    FROM sec_tables
                    WHERE logical_name = '{logical}'
                      AND insert_label_id IS NOT NULL
                      AND sec_row_visible(insert_label_id)
                ),
                (
                    SELECT table_label_id
                    FROM sec_tables
                    WHERE logical_name = '{logical}'
                ),
                1
            )"#
        )
    } else if let Some(table_label_id) = table.table_label_id {
        table_label_id.to_string()
    } else {
        "1".to_string()
    };

    let insert_guard = format!(
        r#"
        SELECT CASE
            WHEN NEW."{row_label_col}" IS NOT NULL
             AND (SELECT allow_explicit_label
                  FROM sec_tables
                  WHERE logical_name = '{logical}') = 0
            THEN RAISE(ABORT, 'explicit row_label_id not allowed')
        END;
        "#
    );

    let visibility_guard = format!(
        r#"
        SELECT CASE
            WHEN NEW."{row_label_col}" IS NOT NULL
             AND NOT sec_row_visible(NEW."{row_label_col}")
            THEN RAISE(ABORT, 'row_label_id not visible')
        END;
        "#
    );

    let insert_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_ins";
        CREATE TEMP TRIGGER "{logical}_sec_ins"
        INSTEAD OF INSERT ON "{logical}"
        BEGIN
            {refesh_guard}
            {insert_guard}
            {visibility_guard}

            INSERT INTO "{physical}" ("{row_label_col}", {insert_cols})
            VALUES (
                {row_label_assignment},
                {insert_vals}
            );
        END;
        "#
    );

    let update_sets = visible_cols
        .iter()
        .map(|c| format!("\"{}\" = NEW.\"{}\"", c, c))
        .collect::<Vec<_>>()
        .join(", ");

    let pk_cols = get_primary_key_columns(conn, physical)?;

    if pk_cols.is_empty() {
        return Err(invalid(format!(
            "secured table '{physical}' must have a PRIMARY KEY"
        )));
    }

    let pk_where_old = {
        let prefix: &str = "OLD";
        let pk_cols: &[String] = &pk_cols;
        pk_cols
            .iter()
            .map(|c| format!("\"{}\" = {}.\"{}\"", c, prefix, c))
            .collect::<Vec<_>>()
            .join(" AND ")
    };

    let pk_guard = pk_cols
        .iter()
        .map(|c| format!("OLD.\"{}\" != NEW.\"{}\"", c, c))
        .collect::<Vec<_>>()
        .join(" OR ");
    let pk_guard = format!(
        r#"
            SELECT CASE WHEN {pk_guard}
                THEN RAISE(ABORT, 'cannot update primary key')
            END;
        "#
    );

    let label_guard = format!(
        r#"
        SELECT CASE
            WHEN NEW."{col}" != OLD."{col}"
            THEN RAISE(ABORT, 'cannot update row_label_id')
        END;
        "#,
        col = row_label_col
    );

    let update_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_upd";
        CREATE TEMP TRIGGER "{logical}_sec_upd"
        INSTEAD OF UPDATE ON "{logical}"
        BEGIN
            {refesh_guard}
            {pk_guard}
            {label_guard}

            UPDATE "{physical}"
            SET {update_sets}
            WHERE {pk_where_old}
              AND sec_row_visible("{row_label_col}");
        END;
        "#
    );

    let delete_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_del";
        CREATE TEMP TRIGGER "{logical}_sec_del"
        INSTEAD OF DELETE ON "{logical}"
        BEGIN
            {refesh_guard}

            DELETE FROM "{physical}"
            WHERE {pk_where_old}
              AND sec_row_visible("{row_label_col}");
        END;
        "#
    );

    conn.execute_batch(&insert_trigger)
        .map_err(|e| trigger_err(e, logical, "INSERT"))?;

    conn.execute_batch(&update_trigger)
        .map_err(|e| trigger_err(e, logical, "UPDATE"))?;

    conn.execute_batch(&delete_trigger)
        .map_err(|e| trigger_err(e, logical, "DELETE"))?;

    Ok(())
}

fn trigger_err(err: rusqlite::Error, table: &str, kind: &str) -> rusqlite::Error {
    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::other(format!(
        "failed to create {} trigger for table '{}': {}",
        kind, table, err
    ))))
}
