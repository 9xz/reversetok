use std::ffi::{c_char, CStr, CString};

use crate::{dynamic::dynamic_json, http::sign_json, ttencrypt::ttencrypt_json};

fn call_json(input: *const c_char, handler: fn(&str) -> String) -> *mut c_char {
    let text = if input.is_null() {
        return std::ptr::null_mut();
    } else {
        // SAFETY: the caller supplies a valid NUL-terminated UTF-8 string.
        unsafe { CStr::from_ptr(input) }
    };
    let json = match text.to_str() {
        Ok(value) => handler(value),
        Err(error) => format!(
            "{{\"ok\":false,\"error\":{}}}",
            serde_json::to_string(&error.to_string()).unwrap()
        ),
    };
    match CString::new(json) {
        Ok(value) => value.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn reversetok_sign_json(input: *const c_char) -> *mut c_char {
    call_json(input, sign_json)
}

#[no_mangle]
pub extern "C" fn reversetok_ttencrypt_json(input: *const c_char) -> *mut c_char {
    call_json(input, ttencrypt_json)
}

#[no_mangle]
pub extern "C" fn reversetok_dynamic_json(input: *const c_char) -> *mut c_char {
    call_json(input, dynamic_json)
}

/// # Safety
/// `value` must come from a reversetok JSON function and must not have been freed already.
#[no_mangle]
pub unsafe extern "C" fn reversetok_free_string(value: *mut c_char) {
    if !value.is_null() {
        // SAFETY: value was returned by a reversetok JSON function and is freed exactly once.
        unsafe { drop(CString::from_raw(value)) };
    }
}

#[no_mangle]
pub extern "C" fn reversetok_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr().cast()
}
