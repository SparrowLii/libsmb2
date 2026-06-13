mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::ffi::{CStr, CString};

pub fn utf8_to_utf16_units(input: &str) -> Option<Vec<u16>> {
    let input = CString::new(input).ok()?;
    let ptr = unsafe { ffi::smb2_utf8_to_utf16(input.as_ptr()) };
    if ptr.is_null() {
        return None;
    }

    let result = unsafe {
        let len = usize::try_from((*ptr).len).ok()?;
        let units = std::slice::from_raw_parts((*ptr).val.as_ptr(), len).to_vec();
        ffi::unicode_ffi_free(ptr.cast());
        units
    };

    Some(result)
}

pub fn utf16_units_to_utf8(units: &[u16]) -> Option<String> {
    let ptr = unsafe { ffi::smb2_utf16_to_utf8(units.as_ptr(), units.len()) };
    if ptr.is_null() {
        return None;
    }

    let result = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
    unsafe { ffi::unicode_ffi_free(ptr.cast_mut().cast()) };

    Some(result)
}
