use std::ffi::c_int;

use rusqlite::ffi::{
    SQLITE_UTF8,
    sqlite3,
    sqlite3_context,
    sqlite3_context_db_handle,
    sqlite3_create_function_v2,
    sqlite3_result_int64,
    sqlite3_value,
};

use crate::{
    context::{get_context_stack, set_context_stack},
    register::{Sqlite3FunctionV2, sqlite_error},
    views::bump_generation::bump_generation_raw,
};

pub struct PopContext;

impl Sqlite3FunctionV2 for PopContext {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_pop_context".as_ptr(),
                0,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_pop_context),
                None,
                None,
                None,
            );
        }
    }
}

pub(crate) extern "C" fn ffi_sec_pop_context(
    ctx: *mut sqlite3_context,
    _argc: c_int,
    _argv: *mut *mut sqlite3_value,
) {
    unsafe {
        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        let mut stack = get_context_stack(db_ptr);

        if stack.pop().is_none() {
            sqlite_error(ctx, "pop_context", "cannot pop base context");
            return;
        }
        set_context_stack(db_ptr, stack);

        match bump_generation_raw(db_ptr) {
            Ok(_) => sqlite3_result_int64(ctx, 1),
            Err(e) => {
                sqlite_error(ctx, "pop_context", e);
            }
        }
    }
}
