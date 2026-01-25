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
    context::{get_context_stack, set_context_stack},
    register::{Sqlite3FunctionV2, sqlite_error},
    views::bump_generation::bump_generation_raw,
};

pub struct PushContext;

impl Sqlite3FunctionV2 for PushContext {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_push_context".as_ptr(),
                -1,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_push_context),
                None,
                None,
                None,
            );
        }
    }
}

pub(crate) extern "C" fn ffi_sec_push_context(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        let mut stack = get_context_stack(db_ptr);

        let name = if argc == 1 {
            let name_ptr = sqlite3_value_text(*argv);
            if !name_ptr.is_null() {
                Some(
                    CStr::from_ptr(name_ptr as *const c_char)
                        .to_string_lossy()
                        .to_string(),
                )
            } else {
                None
            }
        } else {
            None
        };

        stack.push(name);
        set_context_stack(db_ptr, stack);

        match bump_generation_raw(db_ptr) {
            Ok(_) => sqlite3_result_int64(ctx, 1),
            Err(e) => {
                sqlite_error(ctx, "push_context", e);
            }
        }
    }
}
