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

use crate::register::{Sqlite3FunctionV2, sqlite_error};

pub struct AssertFresh;

impl Sqlite3FunctionV2 for AssertFresh {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_assert_fresh".as_ptr(),
                0,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_assert_fresh),
                None,
                None,
                None,
            );
        }
    }
}

pub(crate) extern "C" fn ffi_sec_assert_fresh(
    ctx: *mut sqlite3_context,
    argc: c_int,
    _argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 0 {
            sqlite_error(ctx, "assert_fresh", "expected 0 arguments");
            return;
        }

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        let conn = match rusqlite::Connection::from_handle(db_ptr as *mut _) {
            Ok(c) => c,
            Err(e) => {
                sqlite_error(ctx, "assert_fresh", e);
                return;
            }
        };

        let generation: i64 = conn
            .query_row(
                "SELECT value FROM sec_meta WHERE key = 'generation'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let last_refresh: i64 = conn
            .query_row(
                "SELECT value FROM sec_meta WHERE key = 'last_refresh_generation'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(-1);

        std::mem::forget(conn);

        if generation != last_refresh {
            sqlite_error(
                ctx,
                "assert_fresh",
                "security views are stale: call sec_refresh_views()",
            );
        } else {
            sqlite3_result_int(ctx, 1);
        }
    }
}
