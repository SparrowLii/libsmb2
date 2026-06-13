mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::ffi::CStr;

pub fn nt_error_to_str(status: u32) -> &'static str {
    let ptr = unsafe { ffi::nterror_to_str(status) };
    if ptr.is_null() {
        return "";
    }

    unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("")
}

pub fn nt_error_to_errno(status: u32) -> i32 {
    unsafe { ffi::nterror_to_errno(status) }
}
