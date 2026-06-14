use std::{ffi::c_void, ptr::NonNull};

mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub struct AllocContext {
    ptr: NonNull<c_void>,
    size: usize,
}

pub struct ChildAllocationFailure {
    pub returned_null: bool,
    pub set_error_called: bool,
    pub message: String,
}

impl AllocContext {
    pub fn new(size: usize) -> Option<Self> {
        let ptr = unsafe { ffi::smb2_alloc_init(std::ptr::null_mut(), size) };
        NonNull::new(ptr).map(|ptr| Self { ptr, size })
    }

    pub fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().cast::<u8>(), self.size) }
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr().cast::<u8>(), self.size) }
    }

    pub fn alloc_child(&mut self, size: usize) -> Option<&mut [u8]> {
        let ptr = unsafe { ffi::smb2_alloc_data(std::ptr::null_mut(), self.ptr.as_ptr(), size) };
        NonNull::new(ptr)
            .map(|ptr| unsafe { std::slice::from_raw_parts_mut(ptr.as_ptr().cast::<u8>(), size) })
    }
}

impl Drop for AllocContext {
    fn drop(&mut self) {
        unsafe { ffi::smb2_free_data(std::ptr::null_mut(), self.ptr.as_ptr()) };
    }
}

pub fn free_null_is_noop() {
    unsafe { ffi::smb2_free_data(std::ptr::null_mut(), std::ptr::null_mut()) };
}

pub fn forced_init_failure_returns_null(size: usize) -> bool {
    unsafe { ffi::alloc_ffi_forced_init_failure_returns_null(size) != 0 }
}

pub fn forced_child_failure(child_size: usize) -> ChildAllocationFailure {
    let result = unsafe { ffi::alloc_ffi_forced_child_failure(child_size) };
    let nul = result
        .message
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(result.message.len());
    let bytes = result.message[..nul]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();

    ChildAllocationFailure {
        returned_null: result.returned_null != 0,
        set_error_called: result.set_error_called != 0,
        message: String::from_utf8_lossy(&bytes).into_owned(),
    }
}
