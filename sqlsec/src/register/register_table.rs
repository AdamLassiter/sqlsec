use std::ffi::{CStr, c_char, c_int};

use rusqlite::ffi::{
    SQLITE_NULL,
    SQLITE_UTF8,
    sqlite3,
    sqlite3_context,
    sqlite3_context_db_handle,
    sqlite3_create_function_v2,
    sqlite3_result_int,
    sqlite3_value,
    sqlite3_value_int64,
    sqlite3_value_text,
    sqlite3_value_type,
};

use crate::{
    register::{Sqlite3FunctionV2, sqlite_error},
    views::register_table::register_table_raw,
};

pub struct RegisterTable;

impl Sqlite3FunctionV2 for RegisterTable {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_register_table".as_ptr(),
                5,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_register_table),
                None,
                None,
                None,
            );
        }
    }
}

pub(crate) extern "C" fn ffi_sec_register_table(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 5 {
            sqlite_error(ctx, "register_table", "expected 5 arguments");
            return;
        }

        let logical_ptr = sqlite3_value_text(*argv);
        let physical_ptr = sqlite3_value_text(*argv.add(1));
        let row_col_ptr = sqlite3_value_text(*argv.add(2));

        let table_label_id = if sqlite3_value_type(*argv.add(3)) == SQLITE_NULL {
            None
        } else {
            Some(sqlite3_value_int64(*argv.add(3)))
        };
        let insert_label_id = if sqlite3_value_type(*argv.add(4)) == SQLITE_NULL {
            None
        } else {
            Some(sqlite3_value_int64(*argv.add(4)))
        };

        if logical_ptr.is_null() {
            sqlite_error(ctx, "register_table", "NULL argument 1 'logical'");
            return;
        }
        if physical_ptr.is_null() {
            sqlite_error(ctx, "register_table", "NULL argument 2 ''physical'");
            return;
        }
        if row_col_ptr.is_null() {
            sqlite_error(ctx, "register_table", "NULL argument 3 'row_label_col'");
            return;
        }

        let logical = CStr::from_ptr(logical_ptr as *const c_char).to_string_lossy();
        let physical = CStr::from_ptr(physical_ptr as *const c_char).to_string_lossy();
        let row_col = CStr::from_ptr(row_col_ptr as *const c_char).to_string_lossy();

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        match register_table_raw(
            db_ptr,
            &logical,
            &physical,
            &row_col,
            table_label_id,
            insert_label_id,
        ) {
            Ok(_) => sqlite3_result_int(ctx, 1),
            Err(e) => {
                sqlite_error(ctx, "register_table", e);
            }
        }
    }
}
