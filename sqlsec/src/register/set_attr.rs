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

pub struct SetAttr;

impl Sqlite3FunctionV2 for SetAttr {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_set_attr".as_ptr(),
                2,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_set_attr),
                None,
                None,
                None,
            );
        }
    }
}

pub(crate) extern "C" fn ffi_sec_set_attr(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 2 {
            sqlite_error(ctx, "set_attr", "expected 2 arguments");
            return;
        }

        let key = sqlite3_value_text(*argv);
        let val = sqlite3_value_text(*argv.add(1));

        if key.is_null() || val.is_null() {
            sqlite_error(ctx, "set_attr", "NULL argument 1 'key'");
            return;
        }
        if key.is_null() || val.is_null() {
            sqlite_error(ctx, "set_attr", "NULL argument 2 'value'");
            return;
        }

        let key = CStr::from_ptr(key as *const c_char).to_string_lossy();
        let val = CStr::from_ptr(val as *const c_char).to_string_lossy();

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        let mut stack = get_context_stack(db_ptr);
        stack.current_mut().set_attr(&key, &val);
        set_context_stack(db_ptr, stack);

        match bump_generation_raw(db_ptr) {
            Ok(_) => sqlite3_result_int64(ctx, 1),
            Err(e) => {
                sqlite_error(ctx, "set_attr", e);
            }
        }
    }
}
