use rusqlite::ffi;
use std::ffi::{c_char, c_int, CStr};

const PRIVATE_PREFIX: &str = "__sec_";
const METADATA_TABLES: &[&str] = &["sec_labels", "sec_tables", "sec_columns"];

pub fn install(db: *mut ffi::sqlite3) {
    unsafe {
        ffi::sqlite3_set_authorizer(db, Some(authorizer_callback), std::ptr::null_mut());
    }
}

extern "C" fn authorizer_callback(
    _user_data: *mut std::ffi::c_void,
    action: c_int,
    arg1: *const c_char,
    _arg2: *const c_char,
    _arg3: *const c_char,
    _arg4: *const c_char,
) -> c_int {
    // Only care about table access
    let table_name = match action {
        ffi::SQLITE_READ | ffi::SQLITE_UPDATE | ffi::SQLITE_INSERT | ffi::SQLITE_DELETE => {
            if arg1.is_null() {
                return ffi::SQLITE_OK;
            }
            match unsafe { CStr::from_ptr(arg1).to_str() } {
                Ok(s) => s,
                Err(_) => return ffi::SQLITE_OK,
            }
        }
        _ => return ffi::SQLITE_OK,
    };

    // Block direct access to private tables
    if table_name.starts_with(PRIVATE_PREFIX) {
        return ffi::SQLITE_DENY;
    }

    // Block direct modification of metadata tables (allow reads for internal use)
    if action != ffi::SQLITE_READ && METADATA_TABLES.contains(&table_name) {
        return ffi::SQLITE_DENY;
    }

    ffi::SQLITE_OK
}