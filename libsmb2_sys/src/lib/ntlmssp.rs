use std::ptr::NonNull;

mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub const NEGOTIATE_MESSAGE: u32 = 0x0000_0001;
pub const CHALLENGE_MESSAGE: u32 = 0x0000_0002;
pub const AUTHENTICATION_MESSAGE: u32 = 0x0000_0003;
pub const SMB2_KEY_SIZE: usize = 16;

pub struct AuthContext {
    ptr: NonNull<ffi::auth_data>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSnapshot {
    pub created: bool,
    pub authenticated: i32,
    pub spnego_initial: i32,
    pub spnego_after_set: i32,
    pub key_rc: i32,
    pub invalid_key_rc: i32,
    pub key_size: u8,
    pub key: [u8; SMB2_KEY_SIZE],
    pub free_count_after_destroy: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeyCopy {
    pub rc: i32,
    pub key_size: u8,
    pub key: [u8; SMB2_KEY_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageTypeResult {
    pub rc: i32,
    pub message_type: u32,
    pub ptr_offset: Option<usize>,
    pub len: i32,
    pub is_wrapped: i32,
    pub set_error_called: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobResult {
    pub rc: i32,
    pub output_len: u16,
    pub message_type: u32,
    pub is_wrapped: i32,
    pub set_error_called: bool,
    pub bytes: Vec<u8>,
    pub error: String,
}

impl AuthContext {
    pub fn new_default() -> Option<Self> {
        NonNull::new(unsafe { ffi::ntlmssp_ffi_context_new_default() }).map(|ptr| Self { ptr })
    }

    pub fn set_spnego_wrapping(&mut self, wrap: i32) {
        unsafe { ffi::ntlmssp_ffi_context_set_spnego_wrapping(self.ptr.as_ptr(), wrap) };
    }

    pub fn spnego_wrapping(&self) -> i32 {
        unsafe { ffi::ntlmssp_ffi_context_get_spnego_wrapping(self.ptr.as_ptr()) }
    }

    pub fn authenticated(&self) -> i32 {
        unsafe { ffi::ntlmssp_ffi_context_get_authenticated(self.ptr.as_ptr()) }
    }

    pub fn session_key(&self) -> SessionKeyCopy {
        convert_key(unsafe { ffi::ntlmssp_ffi_context_get_session_key(self.ptr.as_ptr()) })
    }
}

impl Drop for AuthContext {
    fn drop(&mut self) {
        unsafe { ffi::ntlmssp_ffi_context_destroy(self.ptr.as_ptr()) };
    }
}

pub fn context_success() -> ContextSnapshot {
    let raw = unsafe { ffi::ntlmssp_ffi_context_success() };
    let mut key = [0; SMB2_KEY_SIZE];
    key.copy_from_slice(&raw.key[..SMB2_KEY_SIZE]);
    ContextSnapshot {
        created: raw.created != 0,
        authenticated: raw.authenticated,
        spnego_initial: raw.spnego_initial,
        spnego_after_set: raw.spnego_after_set,
        key_rc: raw.key_rc,
        invalid_key_rc: raw.invalid_key_rc,
        key_size: raw.key_size,
        key,
        free_count_after_destroy: raw.free_count_after_destroy,
    }
}

pub fn context_allocation_failure() -> bool {
    unsafe { ffi::ntlmssp_ffi_context_allocation_failure() != 0 }
}

pub fn destroy_populated_context_free_count() -> i32 {
    unsafe { ffi::ntlmssp_ffi_destroy_populated_context_free_count() }
}

pub fn wrapping_roundtrip(wrap: i32) -> i32 {
    unsafe { ffi::ntlmssp_ffi_wrapping_roundtrip(wrap) }
}

pub fn authenticated_null() -> i32 {
    unsafe { ffi::ntlmssp_ffi_authenticated_null() }
}

pub fn session_key_copy() -> SessionKeyCopy {
    convert_key(unsafe { ffi::ntlmssp_ffi_session_key_copy() })
}

pub fn session_key_invalid_arguments() -> SessionKeyCopy {
    convert_key(unsafe { ffi::ntlmssp_ffi_session_key_invalid_arguments() })
}

pub fn message_type_raw(message_type: u32) -> MessageTypeResult {
    convert_message(unsafe { ffi::ntlmssp_ffi_message_type_raw(message_type) })
}

pub fn message_type_invalid_short() -> MessageTypeResult {
    convert_message(unsafe { ffi::ntlmssp_ffi_message_type_invalid_short() })
}

pub fn generate_initial_client_negotiate() -> BlobResult {
    convert_blob(unsafe { ffi::ntlmssp_ffi_generate_initial_client_negotiate() })
}

pub fn generate_invalid_client_blob() -> BlobResult {
    convert_blob(unsafe { ffi::ntlmssp_ffi_generate_invalid_client_blob() })
}

pub fn authenticate_invalid_input() -> i32 {
    unsafe { ffi::ntlmssp_ffi_authenticate_invalid_input() }
}

fn convert_key(raw: ffi::ntlmssp_ffi_key_result) -> SessionKeyCopy {
    let mut key = [0; SMB2_KEY_SIZE];
    key.copy_from_slice(&raw.key[..SMB2_KEY_SIZE]);
    SessionKeyCopy {
        rc: raw.rc,
        key_size: raw.key_size,
        key,
    }
}

fn convert_message(raw: ffi::ntlmssp_ffi_message_result) -> MessageTypeResult {
    MessageTypeResult {
        rc: raw.rc,
        message_type: raw.message_type,
        ptr_offset: (raw.ptr_offset != usize::MAX).then_some(raw.ptr_offset),
        len: raw.len,
        is_wrapped: raw.is_wrapped,
        set_error_called: raw.set_error_called != 0,
    }
}

fn convert_blob(raw: ffi::ntlmssp_ffi_blob_result) -> BlobResult {
    let len = raw.len.min(raw.bytes.len());
    BlobResult {
        rc: raw.rc,
        output_len: raw.output_len,
        message_type: raw.message_type,
        is_wrapped: raw.is_wrapped,
        set_error_called: raw.set_error_called != 0,
        bytes: raw.bytes[..len].to_vec(),
        error: c_buffer_to_string(&raw.error),
    }
}

fn c_buffer_to_string(buf: &[i8]) -> String {
    let end = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    let bytes = buf[..end]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).into_owned()
}
