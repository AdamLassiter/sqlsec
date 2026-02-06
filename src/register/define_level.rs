use std::{
    ffi::{CStr, c_char, c_int},
    mem::forget,
};

use rusqlite::{
    Connection,
    Result,
    ffi::{
        SQLITE_NULL,
        SQLITE_UTF8,
        sqlite3,
        sqlite3_context,
        sqlite3_context_db_handle,
        sqlite3_create_function_v2,
        sqlite3_result_int64,
        sqlite3_value,
        sqlite3_value_int64,
        sqlite3_value_text,
        sqlite3_value_type,
    },
};

use crate::{
    label::LEVELS_CACHE,
    register::{Sqlite3FunctionV2, sqlite_error},
};

pub struct DefineLevel;

impl Sqlite3FunctionV2 for DefineLevel {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_define_level".as_ptr(),
                3,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_define_level),
                None,
                None,
                None,
            );
        }
    }
}

pub(crate) extern "C" fn ffi_sec_define_level(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 3 {
            sqlite_error(ctx, "define_level", "expected 3 arguments");
            return;
        }

        let attr_ptr = sqlite3_value_text(*argv);
        let name_ptr = sqlite3_value_text(*argv.add(1));

        if attr_ptr.is_null() {
            sqlite_error(ctx, "define_level", "NULL argument 1 'attr_name'");
            return;
        }
        if name_ptr.is_null() {
            sqlite_error(ctx, "define_level", "NULL argument 2 'level_name'");
            return;
        }
        if sqlite3_value_type(*argv.add(2)) == SQLITE_NULL {
            sqlite_error(ctx, "define_level", "NULL argument 3 'level_value'");
            return;
        }

        let attr = CStr::from_ptr(attr_ptr as *const c_char).to_string_lossy();
        let name = CStr::from_ptr(name_ptr as *const c_char).to_string_lossy();
        let value = sqlite3_value_int64(*argv.add(2));

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;

        match define_level_raw(db_ptr, &attr, &name, value) {
            Ok(v) => sqlite3_result_int64(ctx, v),
            Err(e) => sqlite_error(ctx, "define_level", e),
        }
    }
}

pub fn define_level(conn: &Connection, attr: &str, name: &str, value: i64) -> Result<i64> {
    conn.execute(
        r#"
        INSERT OR REPLACE INTO sec_levels (attr_name, level_name, level_value)
        VALUES (?1, ?2, ?3)
        "#,
        rusqlite::params![attr, name, value],
    )?;

    // Update cache
    LEVELS_CACHE
        .lock()
        .entry(attr.to_string())
        .or_default()
        .insert(name.to_string(), value);

    Ok(value)
}

pub fn define_level_raw(db_ptr: usize, attr: &str, name: &str, value: i64) -> Result<i64> {
    let conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };
    let result = define_level(&conn, attr, name, value);
    forget(conn);
    result
}
