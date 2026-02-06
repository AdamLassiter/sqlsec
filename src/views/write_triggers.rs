use rusqlite::{Connection, Result};

use crate::{
    context::effective_context,
    label::evaluate::is_visible_conn,
    views::{SecTable, get_primary_key_columns, get_sec_columns, invalid},
};

pub fn create_write_triggers(
    conn: &Connection,
    table: &SecTable,
    visible_cols: &[&str],
) -> Result<()> {
    create_insert_trigger(conn, table, visible_cols)?;
    create_update_trigger(conn, table, visible_cols)?;
    create_delete_trigger(conn, table)?;

    Ok(())
}

fn create_delete_trigger(conn: &Connection, table: &SecTable) -> Result<(), rusqlite::Error> {
    let logical = &table.logical_name;
    let physical = &table.physical_name;
    let row_label_col = &table.row_label_col;

    let pk_cols = pk_cols(conn, physical)?;
    let pk_where_old = pk_where_old(&pk_cols);

    let refesh_guard = refresh_guard();

    let delete_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_del";
        CREATE TEMP TRIGGER "{logical}_sec_del"
        INSTEAD OF DELETE ON "{logical}"
        BEGIN
            {refesh_guard}

            DELETE FROM "{physical}"
            WHERE {pk_where_old}
              AND sec_label_visible("{row_label_col}");
        END;
        "#
    );

    conn.execute_batch(&delete_trigger)
        .map_err(|e| trigger_err(e, logical, "DELETE"))?;
    Ok(())
}

fn create_update_trigger(
    conn: &Connection,
    table: &SecTable,
    visible_cols: &[&str],
) -> Result<(), rusqlite::Error> {
    let logical = &table.logical_name;
    let physical = &table.physical_name;
    let row_label_col = &table.row_label_col;

    let update_sets = visible_cols
        .iter()
        .map(|c| format!("\"{}\" = NEW.\"{}\"", c, c))
        .collect::<Vec<_>>()
        .join(", ");

    let pk_cols = pk_cols(conn, physical)?;
    let pk_where_old = pk_where_old(&pk_cols);

    let refresh_guard = refresh_guard();
    let update_pk_guard = update_pk_guard(pk_cols);
    let update_label_guard = update_label_guard(row_label_col);
    let column_policy_guards = column_update_policy_guards(conn, logical)?;

    let update_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_upd";
        CREATE TEMP TRIGGER "{logical}_sec_upd"
        INSTEAD OF UPDATE ON "{logical}"
        BEGIN
            {refresh_guard}
            {update_pk_guard}
            {update_label_guard}
            {column_policy_guards}

            UPDATE "{physical}"
            SET {update_sets}
            WHERE {pk_where_old}
              AND sec_label_visible("{row_label_col}");
        END;
        "#
    );

    conn.execute_batch(&update_trigger)
        .map_err(|e| trigger_err(e, logical, "UPDATE"))?;
    Ok(())
}

fn create_insert_trigger(
    conn: &Connection,
    table: &SecTable,
    visible_cols: &[&str],
) -> Result<(), rusqlite::Error> {
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
    let row_label_assignment = if table.insert_label_id.is_some() {
        format!(
            r#"COALESCE(
                (
                    SELECT insert_label_id
                    FROM sec_tables
                    WHERE logical_name = '{logical}'
                      AND insert_label_id IS NOT NULL
                      AND sec_label_visible(insert_label_id)
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

    let refesh_guard = refresh_guard();
    let implicit_label_guard = implicit_label_guard(logical, row_label_col);
    let label_visible_guard = label_visible_guard(row_label_col);

    let insert_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_ins";
        CREATE TEMP TRIGGER "{logical}_sec_ins"
        INSTEAD OF INSERT ON "{logical}"
        BEGIN
            {refesh_guard}
            {implicit_label_guard}
            {label_visible_guard}

            INSERT INTO "{physical}" ("{row_label_col}", {insert_cols})
            VALUES (
                {row_label_assignment},
                {insert_vals}
            );
        END;
        "#
    );

    conn.execute_batch(&insert_trigger)
        .map_err(|e| trigger_err(e, logical, "INSERT"))?;
    Ok(())
}

fn update_pk_guard(pk_cols: Vec<String>) -> String {
    let pk_updated = pk_cols
        .iter()
        .map(|col| format!("OLD.\"{col}\" != NEW.\"{col}\""))
        .collect::<Vec<_>>()
        .join(" OR ");
    format!(
        r#"
            SELECT CASE WHEN {pk_updated}
                THEN RAISE(ABORT, 'cannot update primary key')
            END;
        "#
    )
}

fn label_visible_guard(row_label_col: &String) -> String {
    format!(
        r#"
        SELECT CASE
            WHEN NEW."{row_label_col}" IS NOT NULL
             AND NOT sec_label_visible(NEW."{row_label_col}")
            THEN RAISE(ABORT, 'row_label_col {row_label_col} not visible')
        END;
        "#
    )
}

fn update_label_guard(row_label_col: &String) -> String {
    format!(
        r#"
        SELECT CASE
            WHEN NEW."{row_label_col}" != OLD."{row_label_col}"
            THEN RAISE(ABORT, 'cannot update raw_label_col {row_label_col}')
        END;
        "#,
    )
}

fn implicit_label_guard(logical: &String, row_label_col: &String) -> String {
    format!(
        r#"
        SELECT CASE
            WHEN NEW."{row_label_col}" IS NULL
             AND (SELECT allow_implicit_label
                  FROM sec_tables
                  WHERE logical_name = '{logical}') = 0
            THEN RAISE(ABORT, 'implicit row_label_col {row_label_col} not allowed')
        END;
        "#
    )
}

fn refresh_guard() -> &'static str {
    (r#"
    SELECT CASE
        WHEN (SELECT value FROM sec_meta WHERE key = 'generation')
          != (SELECT value FROM sec_meta WHERE key = 'last_refresh_generation')
        THEN RAISE(ABORT, 'security views are stale: call sec_refresh_views()')
    END;
    "#) as _
}

fn pk_cols(conn: &Connection, physical: &String) -> Result<Vec<String>, rusqlite::Error> {
    let pk_cols = get_primary_key_columns(conn, physical)?;
    if pk_cols.is_empty() {
        return Err(invalid(format!(
            "secured table '{physical}' must have a PRIMARY KEY"
        )));
    }
    Ok(pk_cols)
}

fn pk_where_old(pk_cols: &[String]) -> String {
    let pk_cols: &[String] = pk_cols;
    pk_cols
        .iter()
        .map(|col| format!("\"{col}\" = OLD.\"{col}\""))
        .collect::<Vec<_>>()
        .join(" AND ")
}

fn trigger_err(err: rusqlite::Error, table: &str, kind: &str) -> rusqlite::Error {
    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::other(format!(
        "failed to create {} trigger for table '{}': {}",
        kind, table, err
    ))))
}

fn column_update_policy_guards(
    conn: &Connection,
    logical: &str,
) -> Result<String, rusqlite::Error> {
    let mut guards = Vec::new();

    let ctx = effective_context(unsafe { conn.handle() as usize });
    let all_columns = get_sec_columns(conn, logical)?;

    // Generate guards for columns that have a policy AND the user doesn't satisfy it
    let protected_columns = all_columns
        .iter()
        .filter(|c| {
            c.update_label_id.is_some() 
                && !is_visible_conn(conn, c.update_label_id, &ctx)
        });

    for col in protected_columns {
        let col_name = &col.column_name;
        guards.push(format!(
            r#"
            SELECT CASE
                WHEN OLD."{col_name}" IS NOT NEW."{col_name}"
                THEN RAISE(ABORT, 'update denied on column {col_name}')
            END;
            "#
        ));
    }

    Ok(guards.join("\n"))
}