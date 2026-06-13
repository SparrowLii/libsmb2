//! C ABI adapter for the Rust libsmb2 implementation.

use libsmb2_rs::lib::sync;
use libsmb2_rs::{Smb2Client, Smb2Url};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

fn empty_c_string() -> CString {
    CString::new("").expect("empty string cannot contain an interior NUL")
}

fn ffi_error_string(message: &str) -> CString {
    let sanitized = message.replace('\0', " ");
    CString::new(sanitized).unwrap_or_else(|_| empty_c_string())
}

fn invalid_argument_code() -> i32 {
    -22
}

/// Opaque Rust-backed SMB2 context handle used by the C ABI layer.
pub struct Smb2RustContext {
    inner: Smb2Client,
    error_string: CString,
}

impl Smb2RustContext {
    fn new() -> Self {
        Self {
            inner: Smb2Client::new(),
            error_string: empty_c_string(),
        }
    }

    fn set_error(&mut self, message: &str) {
        self.inner.set_error(message);
        self.error_string = ffi_error_string(message);
    }

    fn clear_error(&mut self) {
        self.inner.set_error("");
        self.error_string = empty_c_string();
    }

    fn sync_error_from_client(&mut self) {
        let error = self.inner.error().unwrap_or_default().to_owned();
        self.error_string = ffi_error_string(&error);
    }

    fn finish_status(&mut self, result: libsmb2_rs::Result<impl Sized>) -> i32 {
        match result {
            Ok(_) => {
                self.clear_error();
                0
            }
            Err(error) => {
                self.sync_error_from_client();
                if self.error_string.as_bytes().is_empty() {
                    self.set_error("SMB2 operation failed");
                }
                error.code()
            }
        }
    }
}

/// C-compatible parsed URL returned by `smb2_parse_url`.
#[repr(C)]
pub struct Smb2RustUrl {
    pub domain: *const c_char,
    pub user: *const c_char,
    pub server: *const c_char,
    pub share: *const c_char,
    pub path: *const c_char,
    domain_storage: Option<CString>,
    user_storage: Option<CString>,
    server_storage: CString,
    share_storage: CString,
    path_storage: Option<CString>,
}

impl Smb2RustUrl {
    fn new(url: Smb2Url) -> Result<Self, ()> {
        let domain_storage = optional_c_string(url.domain)?;
        let user_storage = optional_c_string(url.user)?;
        let server_storage = CString::new(url.server).map_err(|_| ())?;
        let share_storage = CString::new(url.share).map_err(|_| ())?;
        let path_storage = optional_c_string(url.path)?;

        Ok(Self {
            domain: optional_ptr(&domain_storage),
            user: optional_ptr(&user_storage),
            server: server_storage.as_ptr(),
            share: share_storage.as_ptr(),
            path: optional_ptr(&path_storage),
            domain_storage,
            user_storage,
            server_storage,
            share_storage,
            path_storage,
        })
    }
}

fn optional_c_string(value: Option<String>) -> Result<Option<CString>, ()> {
    value.map(CString::new).transpose().map_err(|_| ())
}

fn optional_ptr(value: &Option<CString>) -> *const c_char {
    value.as_ref().map_or(ptr::null(), |value| value.as_ptr())
}

unsafe fn c_string_arg<'a>(value: *const c_char) -> Option<&'a str> {
    if value.is_null() {
        return None;
    }

    // SAFETY: The caller provides a pointer to a NUL-terminated C string.
    unsafe { CStr::from_ptr(value) }.to_str().ok()
}

unsafe fn required_c_string_arg<'a>(
    context: &mut Smb2RustContext,
    name: &str,
    value: *const c_char,
) -> Result<&'a str, i32> {
    let Some(value) = (unsafe { c_string_arg(value) }) else {
        context.set_error(&format!("{name} is not valid UTF-8 or is NULL"));
        return Err(invalid_argument_code());
    };
    Ok(value)
}

unsafe fn optional_c_string_arg<'a>(value: *const c_char) -> Option<&'a str> {
    unsafe { c_string_arg(value) }
}

/// Creates a new Rust-backed SMB2 context.
///
/// Returns a null pointer if Rust context construction panics. The returned
/// pointer must be released with [`smb2_destroy_context`].
#[no_mangle]
pub extern "C" fn smb2_init_context() -> *mut Smb2RustContext {
    match catch_unwind(Smb2RustContext::new) {
        Ok(context) => Box::into_raw(Box::new(context)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Destroys a context previously returned by [`smb2_init_context`].
///
/// Passing a null pointer is allowed and has no effect.
///
/// # Safety
///
/// `context` must be either null or a pointer returned by [`smb2_init_context`]
/// that has not already been passed to [`smb2_destroy_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_destroy_context(context: *mut Smb2RustContext) {
    if context.is_null() {
        return;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract requires a unique pointer returned by
        // smb2_init_context that has not already been destroyed.
        unsafe { drop(Box::from_raw(context)) };
    }));

    if result.is_err() {
        std::process::abort();
    }
}

/// Releases a URL previously returned by [`smb2_parse_url`].
///
/// Passing a null pointer is allowed and has no effect.
///
/// # Safety
///
/// `url` must be either null or a pointer returned by [`smb2_parse_url`] that
/// has not already been passed to [`smb2_destroy_url`].
#[no_mangle]
pub unsafe extern "C" fn smb2_destroy_url(url: *mut Smb2RustUrl) {
    if url.is_null() {
        return;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract requires a unique URL pointer returned by
        // smb2_parse_url that has not already been destroyed.
        unsafe { drop(Box::from_raw(url)) };
    }));

    if result.is_err() {
        std::process::abort();
    }
}

/// Parses an SMB URL into a C-compatible `smb2_url` structure.
///
/// Returns null and records an error on invalid input.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`]. `url` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_parse_url(
    context: *mut Smb2RustContext,
    url: *const c_char,
) -> *mut Smb2RustUrl {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return ptr::null_mut();
        }

        // SAFETY: The caller contract requires a valid live context pointer.
        let context = unsafe { &mut *context };
        let Some(url) = (unsafe { c_string_arg(url) }) else {
            context.set_error("URL is not valid UTF-8 or is NULL");
            return ptr::null_mut();
        };

        match context.inner.parse_url(url).and_then(|parsed| {
            Smb2RustUrl::new(parsed).map_err(|()| libsmb2_rs::ErrorCode::from_errno(22))
        }) {
            Ok(parsed) => {
                context.clear_error();
                Box::into_raw(Box::new(parsed))
            }
            Err(_) => {
                context.sync_error_from_client();
                if context.error_string.as_bytes().is_empty() {
                    context.set_error("Failed to parse SMB URL");
                }
                ptr::null_mut()
            }
        }
    }));

    result.unwrap_or(ptr::null_mut())
}

/// Returns the last error string recorded on the context.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_get_error(context: *const Smb2RustContext) -> *const c_char {
    if context.is_null() {
        return c"".as_ptr();
    }

    // SAFETY: The caller contract requires a valid live context pointer.
    unsafe { (*context).error_string.as_ptr() }
}

/// Sets the SMB2 security mode on the Rust-backed context.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_set_security_mode(context: *mut Smb2RustContext, security_mode: u16) {
    if context.is_null() {
        return;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract requires a valid live context pointer.
        let context = unsafe { &mut *context };
        context.inner.set_security_mode(security_mode);
    }));

    if result.is_err() {
        std::process::abort();
    }
}

/// Connects the Rust-backed context to a share through the local sync skeleton.
///
/// Returns `0` on success or a negative errno-compatible code on failure.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`]. String pointers must be null or valid
/// NUL-terminated C strings as required by the legacy API.
#[no_mangle]
pub unsafe extern "C" fn smb2_connect_share(
    context: *mut Smb2RustContext,
    server: *const c_char,
    share: *const c_char,
    user: *const c_char,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }

        // SAFETY: The caller contract requires a valid live context pointer.
        let context = unsafe { &mut *context };
        let server = match unsafe { required_c_string_arg(context, "server", server) } {
            Ok(server) => server,
            Err(code) => return code,
        };
        let share = match unsafe { required_c_string_arg(context, "share", share) } {
            Ok(share) => share,
            Err(code) => return code,
        };
        let user = unsafe { optional_c_string_arg(user) };
        let result = sync::smb2_connect_share(&mut context.inner, server, share, user);
        context.finish_status(result)
    }));

    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Disconnects the Rust-backed context from the current share.
///
/// Returns `0` on success or a negative errno-compatible code on failure.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`].
#[no_mangle]
pub unsafe extern "C" fn smb2_disconnect_share(context: *mut Smb2RustContext) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }

        // SAFETY: The caller contract requires a valid live context pointer.
        let context = unsafe { &mut *context };
        let result = sync::smb2_disconnect_share(&mut context.inner);
        context.finish_status(result)
    }));

    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Creates a directory through the Rust-backed local sync skeleton.
///
/// Returns `0` on success or a negative errno-compatible code on failure.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`]. `path` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_mkdir(context: *mut Smb2RustContext, path: *const c_char) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }

        // SAFETY: The caller contract requires a valid live context pointer.
        let context = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        let result = sync::smb2_mkdir(&mut context.inner, path);
        context.finish_status(result)
    }));

    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Removes a directory through the Rust-backed local sync skeleton.
///
/// Returns `0` on success or a negative errno-compatible code on failure.
///
/// # Safety
///
/// `context` must be null or a valid live pointer returned by
/// [`smb2_init_context`]. `path` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn smb2_rmdir(context: *mut Smb2RustContext, path: *const c_char) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return invalid_argument_code();
        }

        // SAFETY: The caller contract requires a valid live context pointer.
        let context = unsafe { &mut *context };
        let path = match unsafe { required_c_string_arg(context, "path", path) } {
            Ok(path) => path,
            Err(code) => return code,
        };
        let result = sync::smb2_rmdir(&mut context.inner, path);
        context.finish_status(result)
    }));

    result.unwrap_or_else(|_| invalid_argument_code())
}

/// Returns the current SMB2 message id stored in the Rust-backed context.
///
/// Returns `0` for a null context. This small accessor gives C smoke tests a
/// stable way to verify that an opaque Rust context is usable.
///
/// # Safety
///
/// `context` must be null or a valid pointer returned by [`smb2_init_context`]
/// that has not been destroyed.
#[no_mangle]
pub unsafe extern "C" fn smb2_context_message_id(context: *const Smb2RustContext) -> u64 {
    if context.is_null() {
        return 0;
    }

    // SAFETY: The caller contract requires a valid live context pointer.
    unsafe { (*context).inner.last_request_message_id() }
}
