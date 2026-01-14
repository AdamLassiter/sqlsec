use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, Result};
use sqlsec::context::SecurityContext;
use sqlsec::{get_context, label, set_context, views};
use std::collections::HashSet;

/// Initialize extension on a connection (test version - uses rusqlite safe API)
fn init_test_db() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    let db_ptr = conn.as_raw() as usize;

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

    // Register functions using closure captures for db_ptr
    register_test_functions(&conn, db_ptr)?;

    Ok(conn)
}

fn register_test_functions(conn: &Connection, db_ptr: usize) -> Result<()> {
    conn.create_scalar_function("sec_set_attr", 2, FunctionFlags::SQLITE_UTF8, move |ctx| {
        let key: String = ctx.get(0)?;
        let val: String = ctx.get(1)?;

        let mut sec_ctx = get_context(db_ptr);
        sec_ctx.set_attr(&key, &val);
        set_context(db_ptr, sec_ctx);

        Ok(1i64)
    })?;

    conn.create_scalar_function(
        "sec_clear_context",
        0,
        FunctionFlags::SQLITE_UTF8,
        move |_ctx| {
            set_context(db_ptr, SecurityContext::default());
            Ok(1i64)
        },
    )?;

    conn.create_scalar_function(
        "sec_define_label",
        1,
        FunctionFlags::SQLITE_UTF8,
        move |ctx| {
            let expr: String = ctx.get(0)?;

            if label::parse(&expr).is_err() {
                return Err(rusqlite::Error::InvalidFunctionParameterType(
                    0,
                    rusqlite::types::Type::Text,
                ));
            }

            let label_id = label::define_label_raw(db_ptr, &expr)?;
            Ok(label_id)
        },
    )?;

    conn.create_scalar_function(
        "sec_row_visible",
        1,
        FunctionFlags::SQLITE_UTF8,
        move |ctx| {
            let label_id: Option<i64> = ctx.get(0)?;

            let visible = match label_id {
                None => true,
                Some(id) => {
                    let sec_ctx = get_context(db_ptr);
                    label::evaluate_by_id(db_ptr, id, &sec_ctx).unwrap_or(false)
                }
            };

            Ok(if visible { 1i64 } else { 0i64 })
        },
    )?;

    conn.create_scalar_function(
        "sec_refresh_views",
        0,
        FunctionFlags::SQLITE_UTF8,
        move |_ctx| {
            views::refresh_views_raw(db_ptr)?;
            Ok(1i64)
        },
    )?;

    conn.create_scalar_function(
        "sec_register_table",
        4,
        FunctionFlags::SQLITE_UTF8,
        move |ctx| {
            let logical: String = ctx.get(0)?;
            let physical: String = ctx.get(1)?;
            let row_col: String = ctx.get(2)?;
            let table_label: Option<i64> = ctx.get(3)?;

            views::register_table_raw(db_ptr, &logical, &physical, &row_col, table_label)?;
            Ok(1i64)
        },
    )?;

    Ok(())
}

fn setup_test_data(conn: &Connection) -> Result<()> {
    // Create private base table
    conn.execute_batch(
        r#"
        CREATE TABLE __sec_customers (
            id            INTEGER PRIMARY KEY,
            row_label_id  INTEGER NOT NULL,
            name          TEXT,
            email         TEXT,
            ssn           TEXT
        );
        "#,
    )?;

    // Define labels
    let label_everyone: i64 =
        conn.query_row("SELECT sec_define_label('true')", [], |r| r.get(0))?;

    let label_admin: i64 =
        conn.query_row("SELECT sec_define_label('role=admin')", [], |r| r.get(0))?;

    let label_admin_or_auditor: i64 = conn.query_row(
        "SELECT sec_define_label('(role=admin|role=auditor)')",
        [],
        |r| r.get(0),
    )?;

    // Insert test data with different row labels
    conn.execute(
        "INSERT INTO __sec_customers VALUES (1, ?1, 'Alice', 'alice@example.com', '111-11-1111')",
        [label_everyone],
    )?;
    conn.execute(
        "INSERT INTO __sec_customers VALUES (2, ?1, 'Bob', 'bob@example.com', '222-22-2222')",
        [label_admin],
    )?;
    conn.execute(
        "INSERT INTO __sec_customers VALUES (3, ?1, 'Charlie', 'charlie@example.com', '333-33-3333')",
        [label_admin_or_auditor],
    )?;

    // Register secure table
    conn.execute(
        "SELECT sec_register_table('customers', '__sec_customers', 'row_label_id', NULL)",
        [],
    )?;

    // Set column labels
    conn.execute(
        "UPDATE sec_columns SET label_id = ?1 WHERE column_name = 'ssn'",
        [label_admin],
    )?;
    conn.execute(
        "UPDATE sec_columns SET label_id = ?1 WHERE column_name = 'email'",
        [label_admin_or_auditor],
    )?;

    Ok(())
}

fn get_visible_rows(conn: &Connection) -> Result<Vec<(i64, String)>> {
    let mut stmt = conn.prepare("SELECT id, name FROM customers")?;
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>>>()?;
    Ok(rows)
}

fn get_visible_columns(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("PRAGMA table_info(customers)")?;
    let cols = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>>>()?;
    Ok(cols)
}

#[test]
fn test_regular_user_sees_limited_data() -> Result<()> {
    let conn = init_test_db()?;
    setup_test_data(&conn)?;

    // Set context as regular user
    conn.execute("SELECT sec_set_attr('role', 'user')", [])?;
    conn.execute("SELECT sec_refresh_views()", [])?;

    // Check visible rows
    let rows = get_visible_rows(&conn)?;
    assert_eq!(rows.len(), 1, "regular user should see only 1 row");
    assert_eq!(rows[0], (1, "Alice".to_string()));

    // Check visible columns
    let cols = get_visible_columns(&conn)?;
    let col_set: HashSet<_> = cols.iter().map(|s| s.as_str()).collect();

    assert!(col_set.contains("id"), "should see id");
    assert!(col_set.contains("name"), "should see name");
    assert!(!col_set.contains("email"), "should NOT see email");
    assert!(!col_set.contains("ssn"), "should NOT see ssn");

    Ok(())
}

#[test]
fn test_auditor_sees_more_data() -> Result<()> {
    let conn = init_test_db()?;
    setup_test_data(&conn)?;

    // Set context as auditor
    conn.execute("SELECT sec_set_attr('role', 'auditor')", [])?;
    conn.execute("SELECT sec_refresh_views()", [])?;

    // Check visible rows
    let rows = get_visible_rows(&conn)?;
    assert_eq!(rows.len(), 2, "auditor should see 2 rows");

    let names: HashSet<_> = rows.iter().map(|(_, n)| n.as_str()).collect();
    assert!(names.contains("Alice"));
    assert!(names.contains("Charlie"));
    assert!(!names.contains("Bob"), "Bob requires admin");

    // Check visible columns
    let cols = get_visible_columns(&conn)?;
    let col_set: HashSet<_> = cols.iter().map(|s| s.as_str()).collect();

    assert!(col_set.contains("id"));
    assert!(col_set.contains("name"));
    assert!(col_set.contains("email"), "auditor should see email");
    assert!(!col_set.contains("ssn"), "auditor should NOT see ssn");

    Ok(())
}

#[test]
fn test_admin_sees_everything() -> Result<()> {
    let conn = init_test_db()?;
    setup_test_data(&conn)?;

    // Set context as admin
    conn.execute("SELECT sec_set_attr('role', 'admin')", [])?;
    conn.execute("SELECT sec_refresh_views()", [])?;

    // Check visible rows
    let rows = get_visible_rows(&conn)?;
    assert_eq!(rows.len(), 3, "admin should see all 3 rows");

    // Check visible columns
    let cols = get_visible_columns(&conn)?;
    let col_set: HashSet<_> = cols.iter().map(|s| s.as_str()).collect();

    assert!(col_set.contains("id"));
    assert!(col_set.contains("name"));
    assert!(col_set.contains("email"));
    assert!(col_set.contains("ssn"), "admin should see ssn");

    Ok(())
}

#[test]
fn test_context_switching() -> Result<()> {
    let conn = init_test_db()?;
    setup_test_data(&conn)?;

    // Start as user
    conn.execute("SELECT sec_set_attr('role', 'user')", [])?;
    conn.execute("SELECT sec_refresh_views()", [])?;

    let rows = get_visible_rows(&conn)?;
    assert_eq!(rows.len(), 1);

    // Switch to admin
    conn.execute("SELECT sec_clear_context()", [])?;
    conn.execute("SELECT sec_set_attr('role', 'admin')", [])?;
    conn.execute("SELECT sec_refresh_views()", [])?;

    let rows = get_visible_rows(&conn)?;
    assert_eq!(rows.len(), 3, "after switching to admin");

    // Switch back to user
    conn.execute("SELECT sec_clear_context()", [])?;
    conn.execute("SELECT sec_set_attr('role', 'user')", [])?;
    conn.execute("SELECT sec_refresh_views()", [])?;

    let rows = get_visible_rows(&conn)?;
    assert_eq!(rows.len(), 1, "after switching back to user");

    Ok(())
}

#[test]
fn test_multiple_attributes() -> Result<()> {
    let conn = init_test_db()?;

    // Create test table with AND label
    conn.execute_batch(
        r#"
        CREATE TABLE __sec_secrets (
            id           INTEGER PRIMARY KEY,
            row_label_id INTEGER NOT NULL,
            data         TEXT
        );
        "#,
    )?;

    // Label requiring both role=admin AND team=finance
    let label_and: i64 = conn.query_row(
        "SELECT sec_define_label('role=admin&team=finance')",
        [],
        |r| r.get(0),
    )?;

    conn.execute(
        "INSERT INTO __sec_secrets VALUES (1, ?1, 'secret data')",
        [label_and],
    )?;

    conn.execute(
        "SELECT sec_register_table('secrets', '__sec_secrets', 'row_label_id', NULL)",
        [],
    )?;

    // Only admin role - should not see
    conn.execute("SELECT sec_clear_context()", [])?;
    conn.execute("SELECT sec_set_attr('role', 'admin')", [])?;
    conn.execute("SELECT sec_refresh_views()", [])?;

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0))?;
    assert_eq!(count, 0, "admin alone should not see AND-protected row");

    // Add team=finance - now should see
    conn.execute("SELECT sec_set_attr('team', 'finance')", [])?;
    conn.execute("SELECT sec_refresh_views()", [])?;

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0))?;
    assert_eq!(count, 1, "admin+finance should see the row");

    Ok(())
}

#[test]
fn test_insert_through_view() -> Result<()> {
    let conn = init_test_db()?;
    setup_test_data(&conn)?;

    // As admin
    conn.execute("SELECT sec_set_attr('role', 'admin')", [])?;
    conn.execute("SELECT sec_refresh_views()", [])?;

    // Insert through view
    conn.execute(
        "INSERT INTO customers (id, name, email, ssn) VALUES (99, 'Test', 'test@test.com', '999-99-9999')",
        [],
    )?;

    // Verify it landed in base table
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM __sec_customers WHERE id = 99",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 1);

    Ok(())
}

#[test]
fn test_hidden_columns_not_queryable() -> Result<()> {
    let conn = init_test_db()?;
    setup_test_data(&conn)?;

    // As regular user
    conn.execute("SELECT sec_set_attr('role', 'user')", [])?;
    conn.execute("SELECT sec_refresh_views()", [])?;

    // Trying to select hidden column should fail
    let result = conn.execute("SELECT ssn FROM customers", []);
    assert!(result.is_err(), "selecting hidden column should error");

    Ok(())
}
