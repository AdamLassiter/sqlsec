use std::ffi::c_int;

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
    sqlite3_value_type,
};

use crate::{
    context::effective_context,
    label::evaluate::evaluate_by_id,
    register::{Sqlite3FunctionV2, sqlite_error},
};

pub struct RowVisible;

impl Sqlite3FunctionV2 for RowVisible {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_row_visible".as_ptr(),
                1,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_row_visible),
                None,
                None,
                None,
            );
        }
    }
}

pub(crate) extern "C" fn ffi_sec_row_visible(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 1 {
            sqlite_error(ctx, "row_visible", "expected 1 argument");
            return;
        }

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;

        let label_id = if sqlite3_value_type(*argv) == SQLITE_NULL {
            None
        } else {
            Some(sqlite3_value_int64(*argv))
        };

        let visible = match label_id {
            None => true,
            Some(id) => {
                let sec_ctx = effective_context(db_ptr);
                match evaluate_by_id(db_ptr, id, &sec_ctx) {
                    Ok(res) => res,
                    Err(e) => {
                        sqlite_error(ctx, "row_visible", e);
                        return;
                    }
                }
            }
        };

        sqlite3_result_int(ctx, if visible { 1 } else { 0 });
    }
}
