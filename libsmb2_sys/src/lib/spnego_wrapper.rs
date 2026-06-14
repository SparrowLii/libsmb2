//! Safe SPNEGO wrapper harnesses from `lib/spnego-wrapper.c` and constants from
//! `lib/spnego-wrapper.h`.

mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

/// Kerberos mechanism bit reported by SPNEGO mechanism parsing.
pub const SPNEGO_MECHANISM_KRB5: u32 = 0x0001;

/// NTLMSSP mechanism bit reported by SPNEGO mechanism parsing.
pub const SPNEGO_MECHANISM_NTLMSSP: u32 = 0x0002;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpnegoBlobResult {
    pub rc: i32,
    pub has_blob: bool,
    pub set_error_called: bool,
    pub mechanisms: u32,
    pub token_offset: Option<usize>,
    pub token_len: usize,
    pub bytes: Vec<u8>,
    pub error: String,
}

pub fn create_negotiate_reply(allow_ntlmssp: bool) -> SpnegoBlobResult {
    convert(unsafe { ffi::spnego_ffi_create_negotiate_reply(allow_ntlmssp as i32, 0) })
}

pub fn create_negotiate_reply_alloc_failure() -> SpnegoBlobResult {
    convert(unsafe { ffi::spnego_ffi_create_negotiate_reply(1, 1) })
}

pub fn wrap_gssapi(token: Option<&[u8]>) -> SpnegoBlobResult {
    let (ptr, len) = optional_token(token);
    convert(unsafe { ffi::spnego_ffi_wrap_gssapi(ptr, len, 0) })
}

pub fn wrap_ntlmssp_challenge(token: &[u8]) -> SpnegoBlobResult {
    convert(unsafe {
        ffi::spnego_ffi_wrap_ntlmssp_challenge(token.as_ptr(), token.len() as i32, 0)
    })
}

pub fn wrap_ntlmssp_auth(token: &[u8]) -> SpnegoBlobResult {
    convert(unsafe { ffi::spnego_ffi_wrap_ntlmssp_auth(token.as_ptr(), token.len() as i32, 0) })
}

pub fn wrap_authenticate_result(authorized_ok: bool) -> SpnegoBlobResult {
    convert(unsafe { ffi::spnego_ffi_wrap_authenticate_result(authorized_ok as i32, 0) })
}

pub fn wrap_authenticate_result_alloc_failure() -> SpnegoBlobResult {
    convert(unsafe { ffi::spnego_ffi_wrap_authenticate_result(1, 1) })
}

pub fn unwrap_gssapi(blob: &[u8], suppress_errors: bool) -> SpnegoBlobResult {
    convert(unsafe {
        ffi::spnego_ffi_unwrap_gssapi(blob.as_ptr(), blob.len() as i32, suppress_errors as i32)
    })
}

pub fn unwrap_blob(blob: &[u8], suppress_errors: bool) -> SpnegoBlobResult {
    convert(unsafe {
        ffi::spnego_ffi_unwrap_blob(blob.as_ptr(), blob.len() as i32, suppress_errors as i32, 0)
    })
}

pub fn unwrap_blob_with_null_token(blob: &[u8]) -> SpnegoBlobResult {
    convert(unsafe { ffi::spnego_ffi_unwrap_blob(blob.as_ptr(), blob.len() as i32, 0, 1) })
}

pub fn unwrap_targ(blob: &[u8]) -> SpnegoBlobResult {
    convert(unsafe { ffi::spnego_ffi_unwrap_targ(blob.as_ptr(), blob.len() as i32) })
}

fn optional_token(token: Option<&[u8]>) -> (*const u8, i32) {
    token.map_or((std::ptr::null(), 0), |bytes| {
        (bytes.as_ptr(), bytes.len() as i32)
    })
}

fn convert(raw: ffi::spnego_ffi_blob_result) -> SpnegoBlobResult {
    let len = raw.len.min(raw.bytes.len());
    SpnegoBlobResult {
        rc: raw.rc,
        has_blob: raw.has_blob != 0,
        set_error_called: raw.set_error_called != 0,
        mechanisms: raw.mechanisms,
        token_offset: (raw.token_offset != 0 && raw.token_offset != usize::MAX)
            .then_some(raw.token_offset),
        token_len: raw.token_len,
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
