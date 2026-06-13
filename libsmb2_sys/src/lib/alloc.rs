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
