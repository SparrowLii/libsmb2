use std::{ffi::CStr, ffi::CString, ptr::NonNull};

mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatResult {
    pub rc: i32,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureResult {
    pub rc: i32,
    pub wrote_new_buffer: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatFailureResult {
    pub rc: i32,
    pub released_allocated_storage: bool,
}

fn c_format(format: &str) -> CString {
    CString::new(format).expect("format must not contain interior NUL bytes")
}

unsafe fn take_result(result: ffi::asprintf_ffi_result) -> Option<FormatResult> {
    let data = NonNull::new(result.data)?;
    let text = CStr::from_ptr(data.as_ptr()).to_string_lossy().into_owned();
    ffi::asprintf_ffi_free(data.as_ptr());
    Some(FormatResult {
        rc: result.rc,
        text,
    })
}

pub fn vscprintf_two_ints(format: &str, first: i32, second: i32) -> i32 {
    let format = c_format(format);
    unsafe { ffi::asprintf_ffi_vscprintf_two_ints(format.as_ptr(), first, second) }
}

pub fn vscprintf_reuse_after_length(format: &str, first: i32, second: i32) -> i32 {
    let format = c_format(format);
    unsafe { ffi::asprintf_ffi_vscprintf_reuse_after_length(format.as_ptr(), first, second) }
}

pub fn vasprintf_two_ints(format: &str, first: i32, second: i32) -> Option<FormatResult> {
    let format = c_format(format);
    unsafe {
        take_result(ffi::asprintf_ffi_vasprintf_two_ints(
            format.as_ptr(),
            first,
            second,
        ))
    }
}

pub fn asprintf_two_ints(format: &str, first: i32, second: i32) -> Option<FormatResult> {
    let format = c_format(format);
    unsafe {
        take_result(ffi::asprintf_ffi_asprintf_two_ints(
            format.as_ptr(),
            first,
            second,
        ))
    }
}

pub fn vasprintf_null_format_failure() -> i32 {
    unsafe { ffi::asprintf_ffi_vasprintf_null_format() }
}

pub fn vasprintf_length_failure_preserves_output() -> FailureResult {
    let mut output = std::ptr::null_mut();
    let rc = unsafe { ffi::asprintf_ffi_vasprintf_length_failure(&mut output) };
    FailureResult {
        rc,
        wrote_new_buffer: !output.is_null(),
    }
}

pub fn vasprintf_alloc_failure_preserves_output() -> FailureResult {
    let mut output = std::ptr::null_mut();
    let rc = unsafe { ffi::asprintf_ffi_vasprintf_forced_alloc_failure(&mut output) };
    let wrote_new_buffer = output.is_null();
    unsafe { ffi::asprintf_ffi_free(output) };
    FailureResult {
        rc,
        wrote_new_buffer,
    }
}

pub fn vasprintf_format_failure_releases_storage() -> FormatFailureResult {
    let result = unsafe { ffi::asprintf_ffi_vasprintf_forced_format_failure() };
    FormatFailureResult {
        rc: result.rc,
        released_allocated_storage: result.free_count == 1,
    }
}

pub fn xbox_inline_maps_to_inline() -> bool {
    unsafe { ffi::asprintf_ffi_xbox_inline_maps_to___inline() == 1 }
}
