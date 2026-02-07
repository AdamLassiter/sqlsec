use std::ffi::{CStr, c_char, c_int};

use rusqlite::ffi::{
    SQLITE_UTF8,
    sqlite3,
    sqlite3_context,
    sqlite3_context_db_handle,
    sqlite3_create_function_v2,
    sqlite3_result_int64,
    sqlite3_value,
    sqlite3_value_text,
};

use crate::{
    label::{define::define_label_raw, parse::parse},
    register::{Sqlite3FunctionV2, sqlite_error},
};

pub struct DefineLabel;

impl Sqlite3FunctionV2 for DefineLabel {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_define_label".as_ptr(),
                1,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_define_label),
                None,
                None,
                None,
            );
        }
    }
}

pub(crate) extern "C" fn ffi_sec_define_label(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 1 {
            sqlite_error(ctx, "define_label", "expected 1 argument");
            return;
        }

        let expr_ptr = sqlite3_value_text(*argv);
        if expr_ptr.is_null() {
            sqlite_error(ctx, "define_label", "NULL argument 1 'expr'");
            return;
        }

        let expr = CStr::from_ptr(expr_ptr as *const c_char).to_string_lossy();

        // Validate parse
        if parse(&expr).is_err() {
            sqlite_error(ctx, "define_label", "invalid label expression");
            return;
        }

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        match define_label_raw(db_ptr, &expr) {
            Ok(id) => sqlite3_result_int64(ctx, id),
            Err(e) => {
                sqlite_error(ctx, "define_label", e);
            }
        }
    }
}
