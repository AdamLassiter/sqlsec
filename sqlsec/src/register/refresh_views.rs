use std::ffi::c_int;

use rusqlite::ffi::{
    SQLITE_UTF8,
    sqlite3,
    sqlite3_context,
    sqlite3_context_db_handle,
    sqlite3_create_function_v2,
    sqlite3_result_int,
    sqlite3_value,
};

use crate::{
    register::{Sqlite3FunctionV2, sqlite_error},
    views::refresh_views::refresh_views_raw,
};

pub struct RefreshViews;

impl Sqlite3FunctionV2 for RefreshViews {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_refresh_views".as_ptr(),
                0,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_refresh_views),
                None,
                None,
                None,
            );
        }
    }
}

pub(crate) extern "C" fn ffi_sec_refresh_views(
    ctx: *mut sqlite3_context,
    _argc: c_int,
    _argv: *mut *mut sqlite3_value,
) {
    unsafe {
        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        match refresh_views_raw(db_ptr) {
            Ok(_) => sqlite3_result_int(ctx, 1),
            Err(e) => {
                sqlite_error(ctx, "refresh_views", e);
            }
        }
    }
}
