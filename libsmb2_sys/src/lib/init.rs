use std::{ffi::CStr, os::raw::c_char, ptr::NonNull};

type InitFfiContext = std::ffi::c_void;

extern "C" {
    fn init_ffi_context_new() -> *mut InitFfiContext;
    fn init_ffi_context_free(smb2: *mut InitFfiContext);
    fn init_ffi_get_error(smb2: *const InitFfiContext) -> *const c_char;
    fn init_ffi_get_nterror(smb2: *const InitFfiContext) -> i32;
    fn init_ffi_set_nterror(smb2: *mut InitFfiContext, nterror: i32);
    fn init_ffi_set_client_guid(smb2: *mut InitFfiContext, guid: *const u8);
    fn init_ffi_get_client_guid(smb2: *const InitFfiContext) -> *const u8;
    fn init_ffi_get_dialect(smb2: *const InitFfiContext) -> u16;
    fn init_ffi_set_dialect(smb2: *mut InitFfiContext, dialect: u16);
    fn init_ffi_set_security_mode(smb2: *mut InitFfiContext, security_mode: u16);
    fn init_ffi_get_security_mode(smb2: *const InitFfiContext) -> u16;
    fn init_ffi_set_password_from_file(smb2: *mut InitFfiContext);
    fn init_ffi_get_password(smb2: *const InitFfiContext) -> *const c_char;
    fn init_ffi_set_user(smb2: *mut InitFfiContext, user: *const c_char);
    fn init_ffi_get_user(smb2: *const InitFfiContext) -> *const c_char;
    fn init_ffi_set_password(smb2: *mut InitFfiContext, password: *const c_char);
    fn init_ffi_set_domain(smb2: *mut InitFfiContext, domain: *const c_char);
    fn init_ffi_get_domain(smb2: *const InitFfiContext) -> *const c_char;
    fn init_ffi_set_workstation(smb2: *mut InitFfiContext, workstation: *const c_char);
    fn init_ffi_get_workstation(smb2: *const InitFfiContext) -> *const c_char;
    fn init_ffi_set_server(smb2: *mut InitFfiContext, server: *const c_char);
    fn init_ffi_set_opaque(smb2: *mut InitFfiContext, opaque: *mut std::ffi::c_void);
    fn init_ffi_get_opaque(smb2: *const InitFfiContext) -> *mut std::ffi::c_void;
    fn init_ffi_set_seal(smb2: *mut InitFfiContext, val: i32);
    fn init_ffi_get_seal(smb2: *const InitFfiContext) -> i32;
    fn init_ffi_set_sign(smb2: *mut InitFfiContext, val: i32);
    fn init_ffi_get_sign(smb2: *const InitFfiContext) -> i32;
    fn init_ffi_context_active(smb2: *const InitFfiContext) -> i32;
    fn init_ffi_iovector_free_probe() -> i32;
    fn init_ffi_iovector_add_probe(total_size: *mut usize) -> i32;
    fn init_ffi_iovector_overflow_probe() -> i32;
    fn init_ffi_set_error_literal(smb2: *mut InitFfiContext, error_string: *const c_char);
    fn init_ffi_error_callback_probe(smb2: *mut InitFfiContext) -> i32;
    fn init_ffi_set_nterror_with_error(
        smb2: *mut InitFfiContext,
        nterror: i32,
        error_string: *const c_char,
    );
    fn init_ffi_set_authentication(smb2: *mut InitFfiContext, val: i32);
    fn init_ffi_get_authentication(smb2: *const InitFfiContext) -> i32;
    fn init_ffi_set_timeout(smb2: *mut InitFfiContext, seconds: i32);
    fn init_ffi_get_timeout(smb2: *const InitFfiContext) -> i32;
    fn init_ffi_set_version(smb2: *mut InitFfiContext, version: i32);
    fn init_ffi_get_version(smb2: *const InitFfiContext) -> i32;
    fn init_ffi_get_libversion(major: *mut u8, minor: *mut u8, patch: *mut u8);
    fn init_ffi_set_passthrough(smb2: *mut InitFfiContext, passthrough: i32);
    fn init_ffi_get_passthrough(smb2: *mut InitFfiContext) -> i32;
    fn init_ffi_oplock_callback_probe(smb2: *mut InitFfiContext) -> i32;
    fn init_ffi_delegate_credentials_unavailable(
        input: *mut InitFfiContext,
        output: *mut InitFfiContext,
    ) -> i32;
    fn init_ffi_set_max_read_size(smb2: *mut InitFfiContext, max_read_size: u32);
    fn init_ffi_get_max_read_size(smb2: *const InitFfiContext) -> u32;
    fn init_ffi_set_max_write_size(smb2: *mut InitFfiContext, max_write_size: u32);
    fn init_ffi_get_max_write_size(smb2: *const InitFfiContext) -> u32;
    fn init_ffi_file_handle_from_id(file_id: *const u8) -> *mut InitFfiFileHandle;
    fn init_ffi_file_handle_free(fh: *mut InitFfiFileHandle);
    fn init_ffi_file_handle_get_id(fh: *const InitFfiFileHandle) -> *const u8;
    fn init_ffi_parse_url_snapshot(url: *const c_char, snapshot: *mut InitFfiUrlSnapshot) -> i32;
    fn init_ffi_parse_url_error(url: *const c_char) -> *const c_char;
    fn init_ffi_parse_url_query_snapshot(
        seal: *mut i32,
        version: *mut i32,
        sec: *mut i32,
        timeout: *mut i32,
    ) -> i32;
    fn init_ffi_parse_url_bad_query_error() -> *const c_char;
    fn init_ffi_destroy_parsed_url_probe() -> i32;
    fn init_ffi_destroy_null_url_probe() -> i32;
    fn init_ffi_real_context_defaults() -> InitFfiContextDefaults;
    fn init_ffi_init_context_allocation_failure_probe() -> i32;
    fn init_ffi_destroy_active_context_probe() -> i32;
    fn init_ffi_destroy_null_context_probe() -> i32;
    fn init_ffi_active_contexts_probe() -> i32;
    fn init_ffi_real_context_active_probe() -> i32;
}

pub struct InitContext {
    ptr: NonNull<InitFfiContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LibVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

type InitFfiFileHandle = std::ffi::c_void;

pub struct InitFileHandle {
    ptr: NonNull<InitFfiFileHandle>,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InitFfiUrlSnapshot {
    domain: [c_char; 64],
    user: [c_char; 64],
    server: [c_char; 64],
    share: [c_char; 64],
    path: [c_char; 128],
}

impl Default for InitFfiUrlSnapshot {
    fn default() -> Self {
        Self {
            domain: [0; 64],
            user: [0; 64],
            server: [0; 64],
            share: [0; 64],
            path: [0; 128],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlSnapshot {
    pub domain: Option<String>,
    pub user: Option<String>,
    pub server: String,
    pub share: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrlQuerySnapshot {
    pub seal: i32,
    pub version: i32,
    pub authentication: i32,
    pub timeout: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitContextDefaults {
    pub allocated: i32,
    pub fd: i32,
    pub security: i32,
    pub version: i32,
    pub ndr: i32,
    pub active: i32,
}

type InitFfiContextDefaults = InitContextDefaults;

pub const SMB2_INVALID_SOCKET_DEFAULT: i32 = -1;
pub const SMB2_SEC_UNDEFINED_DEFAULT: i32 = 0;
pub const SMB2_SEC_NTLMSSP_VALUE: i32 = 1;
pub const SMB2_VERSION_ANY_DEFAULT: i32 = 0;
pub const SMB2_VERSION_ANY3_VALUE: i32 = 3;

impl InitContext {
    pub fn new() -> Option<Self> {
        NonNull::new(unsafe { init_ffi_context_new() }).map(|ptr| Self { ptr })
    }

    pub fn error(&self) -> &str {
        string_from_ptr(unsafe { init_ffi_get_error(self.ptr.as_ptr()) }).unwrap_or("")
    }

    pub fn null_error() -> &'static str {
        string_from_ptr(unsafe { init_ffi_get_error(std::ptr::null()) }).unwrap_or("")
    }

    pub fn nterror(&self) -> i32 {
        unsafe { init_ffi_get_nterror(self.ptr.as_ptr()) }
    }

    pub fn null_nterror() -> i32 {
        unsafe { init_ffi_get_nterror(std::ptr::null()) }
    }

    pub fn set_nterror_for_test(&mut self, nterror: i32) {
        unsafe { init_ffi_set_nterror(self.ptr.as_ptr(), nterror) };
    }

    pub fn set_client_guid(&mut self, guid: [u8; 16]) {
        unsafe { init_ffi_set_client_guid(self.ptr.as_ptr(), guid.as_ptr()) };
    }

    pub fn client_guid(&self) -> [u8; 16] {
        let ptr = unsafe { init_ffi_get_client_guid(self.ptr.as_ptr()) };
        if ptr.is_null() {
            return [0; 16];
        }
        let mut guid = [0; 16];
        unsafe { std::ptr::copy_nonoverlapping(ptr, guid.as_mut_ptr(), guid.len()) };
        guid
    }

    pub fn dialect(&self) -> u16 {
        unsafe { init_ffi_get_dialect(self.ptr.as_ptr()) }
    }

    pub fn set_dialect_for_test(&mut self, dialect: u16) {
        unsafe { init_ffi_set_dialect(self.ptr.as_ptr(), dialect) };
    }

    pub fn set_security_mode(&mut self, security_mode: u16) {
        unsafe { init_ffi_set_security_mode(self.ptr.as_ptr(), security_mode) };
    }

    pub fn security_mode(&self) -> u16 {
        unsafe { init_ffi_get_security_mode(self.ptr.as_ptr()) }
    }

    pub fn set_password_from_file(&mut self) {
        unsafe { init_ffi_set_password_from_file(self.ptr.as_ptr()) };
    }

    pub fn password(&self) -> Option<&str> {
        string_from_ptr(unsafe { init_ffi_get_password(self.ptr.as_ptr()) })
    }

    pub fn set_user(&mut self, user: &str) {
        with_c_string(user, |ptr| unsafe {
            init_ffi_set_user(self.ptr.as_ptr(), ptr)
        });
    }

    pub fn user(&self) -> Option<&str> {
        string_from_ptr(unsafe { init_ffi_get_user(self.ptr.as_ptr()) })
    }

    pub fn set_password(&mut self, password: &str) {
        with_c_string(password, |ptr| unsafe {
            init_ffi_set_password(self.ptr.as_ptr(), ptr)
        });
    }

    pub fn set_domain(&mut self, domain: &str) {
        with_c_string(domain, |ptr| unsafe {
            init_ffi_set_domain(self.ptr.as_ptr(), ptr)
        });
    }

    pub fn domain(&self) -> Option<&str> {
        string_from_ptr(unsafe { init_ffi_get_domain(self.ptr.as_ptr()) })
    }

    pub fn set_workstation(&mut self, workstation: &str) {
        with_c_string(workstation, |ptr| unsafe {
            init_ffi_set_workstation(self.ptr.as_ptr(), ptr);
        });
    }

    pub fn workstation(&self) -> Option<&str> {
        string_from_ptr(unsafe { init_ffi_get_workstation(self.ptr.as_ptr()) })
    }

    pub fn set_server_for_test(&mut self, server: &str) {
        with_c_string(server, |ptr| unsafe {
            init_ffi_set_server(self.ptr.as_ptr(), ptr)
        });
    }

    pub fn set_opaque(&mut self, opaque: usize) {
        unsafe { init_ffi_set_opaque(self.ptr.as_ptr(), opaque as *mut std::ffi::c_void) };
    }

    pub fn opaque(&self) -> usize {
        unsafe { init_ffi_get_opaque(self.ptr.as_ptr()) as usize }
    }

    pub fn set_seal(&mut self, val: i32) {
        unsafe { init_ffi_set_seal(self.ptr.as_ptr(), val) };
    }

    pub fn seal(&self) -> i32 {
        unsafe { init_ffi_get_seal(self.ptr.as_ptr()) }
    }

    pub fn set_sign(&mut self, val: i32) {
        unsafe { init_ffi_set_sign(self.ptr.as_ptr(), val) };
    }

    pub fn sign(&self) -> i32 {
        unsafe { init_ffi_get_sign(self.ptr.as_ptr()) }
    }

    pub fn is_active_for_test(&self) -> bool {
        unsafe { init_ffi_context_active(self.ptr.as_ptr()) != 0 }
    }

    pub fn set_error_for_test(&mut self, error: &str) {
        with_c_string(error, |ptr| unsafe {
            init_ffi_set_error_literal(self.ptr.as_ptr(), ptr)
        });
    }

    pub fn clear_error_for_test(&mut self) {
        unsafe { init_ffi_set_error_literal(self.ptr.as_ptr(), std::ptr::null()) };
    }

    pub fn error_callback_probe(&mut self) -> i32 {
        unsafe { init_ffi_error_callback_probe(self.ptr.as_ptr()) }
    }

    pub fn set_nterror_with_error_for_test(&mut self, nterror: i32, error: &str) {
        with_c_string(error, |ptr| unsafe {
            init_ffi_set_nterror_with_error(self.ptr.as_ptr(), nterror, ptr)
        });
    }

    pub fn set_authentication(&mut self, val: i32) {
        unsafe { init_ffi_set_authentication(self.ptr.as_ptr(), val) };
    }

    pub fn authentication(&self) -> i32 {
        unsafe { init_ffi_get_authentication(self.ptr.as_ptr()) }
    }

    pub fn set_timeout(&mut self, seconds: i32) {
        unsafe { init_ffi_set_timeout(self.ptr.as_ptr(), seconds) };
    }

    pub fn timeout(&self) -> i32 {
        unsafe { init_ffi_get_timeout(self.ptr.as_ptr()) }
    }

    pub fn set_version(&mut self, version: i32) {
        unsafe { init_ffi_set_version(self.ptr.as_ptr(), version) };
    }

    pub fn version(&self) -> i32 {
        unsafe { init_ffi_get_version(self.ptr.as_ptr()) }
    }

    pub fn libversion() -> LibVersion {
        let mut version = LibVersion {
            major: 0,
            minor: 0,
            patch: 0,
        };
        unsafe {
            init_ffi_get_libversion(&mut version.major, &mut version.minor, &mut version.patch)
        };
        version
    }

    pub fn set_passthrough(&mut self, passthrough: i32) {
        unsafe { init_ffi_set_passthrough(self.ptr.as_ptr(), passthrough) };
    }

    pub fn passthrough(&mut self) -> i32 {
        unsafe { init_ffi_get_passthrough(self.ptr.as_ptr()) }
    }

    pub fn oplock_callback_probe(&mut self) -> bool {
        unsafe { init_ffi_oplock_callback_probe(self.ptr.as_ptr()) != 0 }
    }

    pub fn delegate_credentials_unavailable(&mut self, output: &mut InitContext) -> i32 {
        unsafe { init_ffi_delegate_credentials_unavailable(self.ptr.as_ptr(), output.ptr.as_ptr()) }
    }

    pub fn set_max_read_size_for_test(&mut self, max_read_size: u32) {
        unsafe { init_ffi_set_max_read_size(self.ptr.as_ptr(), max_read_size) };
    }

    pub fn max_read_size(&self) -> u32 {
        unsafe { init_ffi_get_max_read_size(self.ptr.as_ptr()) }
    }

    pub fn set_max_write_size_for_test(&mut self, max_write_size: u32) {
        unsafe { init_ffi_set_max_write_size(self.ptr.as_ptr(), max_write_size) };
    }

    pub fn max_write_size(&self) -> u32 {
        unsafe { init_ffi_get_max_write_size(self.ptr.as_ptr()) }
    }
}

pub fn iovector_free_probe() -> bool {
    unsafe { init_ffi_iovector_free_probe() == 1 }
}

pub fn iovector_add_probe() -> Option<usize> {
    let mut total_size = 0;
    let ok = unsafe { init_ffi_iovector_add_probe(&mut total_size) };
    (ok == 1).then_some(total_size)
}

pub fn iovector_overflow_probe() -> bool {
    unsafe { init_ffi_iovector_overflow_probe() == 1 }
}

pub fn parse_url_snapshot(url: &str) -> Option<UrlSnapshot> {
    let mut snapshot = InitFfiUrlSnapshot::default();
    let ok = with_c_string(url, |ptr| unsafe {
        init_ffi_parse_url_snapshot(ptr, &mut snapshot)
    });
    (ok == 1).then(|| UrlSnapshot {
        domain: optional_string_from_array(&snapshot.domain),
        user: optional_string_from_array(&snapshot.user),
        server: string_from_array(&snapshot.server),
        share: string_from_array(&snapshot.share),
        path: optional_string_from_array(&snapshot.path),
    })
}

pub fn parse_url_error(url: &str) -> String {
    with_c_string(url, |ptr| unsafe {
        owned_string_from_ptr(init_ffi_parse_url_error(ptr))
    })
}

pub fn parse_url_query_snapshot() -> Option<UrlQuerySnapshot> {
    let mut seal = 0;
    let mut version = 0;
    let mut authentication = 0;
    let mut timeout = 0;
    let ok = unsafe {
        init_ffi_parse_url_query_snapshot(
            &mut seal,
            &mut version,
            &mut authentication,
            &mut timeout,
        )
    };
    (ok == 1).then_some(UrlQuerySnapshot {
        seal,
        version,
        authentication,
        timeout,
    })
}

pub fn parse_url_bad_query_error() -> String {
    unsafe { owned_string_from_ptr(init_ffi_parse_url_bad_query_error()) }
}

pub fn destroy_parsed_url_probe() -> bool {
    unsafe { init_ffi_destroy_parsed_url_probe() == 1 }
}

pub fn destroy_null_url_probe() -> bool {
    unsafe { init_ffi_destroy_null_url_probe() == 1 }
}

pub fn real_context_defaults() -> InitContextDefaults {
    unsafe { init_ffi_real_context_defaults() }
}

pub fn init_context_allocation_failure_probe() -> bool {
    unsafe { init_ffi_init_context_allocation_failure_probe() == 1 }
}

pub fn destroy_active_context_probe() -> bool {
    unsafe { init_ffi_destroy_active_context_probe() == 1 }
}

pub fn destroy_null_context_probe() -> bool {
    unsafe { init_ffi_destroy_null_context_probe() == 1 }
}

pub fn active_contexts_probe() -> bool {
    unsafe { init_ffi_active_contexts_probe() == 1 }
}

pub fn real_context_active_probe() -> bool {
    unsafe { init_ffi_real_context_active_probe() == 1 }
}

impl Drop for InitContext {
    fn drop(&mut self) {
        unsafe { init_ffi_context_free(self.ptr.as_ptr()) };
    }
}

fn string_from_ptr<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

fn owned_string_from_ptr(ptr: *const c_char) -> String {
    string_from_ptr(ptr).unwrap_or("").to_owned()
}

fn string_from_array(bytes: &[c_char]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let bytes = &bytes[..end];
    let bytes = unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), bytes.len()) };
    String::from_utf8_lossy(bytes).into_owned()
}

fn optional_string_from_array(bytes: &[c_char]) -> Option<String> {
    let value = string_from_array(bytes);
    (!value.is_empty()).then_some(value)
}

fn with_c_string<T>(input: &str, f: impl FnOnce(*const c_char) -> T) -> T {
    let mut bytes = Vec::with_capacity(input.len() + 1);
    bytes.extend(input.as_bytes().iter().copied().filter(|byte| *byte != 0));
    bytes.push(0);
    f(bytes.as_ptr().cast())
}

impl InitFileHandle {
    pub fn from_file_id(file_id: [u8; 16]) -> Option<Self> {
        NonNull::new(unsafe { init_ffi_file_handle_from_id(file_id.as_ptr()) })
            .map(|ptr| Self { ptr })
    }

    pub fn file_id(&self) -> [u8; 16] {
        let ptr = unsafe { init_ffi_file_handle_get_id(self.ptr.as_ptr()) };
        if ptr.is_null() {
            return [0; 16];
        }
        let mut file_id = [0; 16];
        unsafe { std::ptr::copy_nonoverlapping(ptr, file_id.as_mut_ptr(), file_id.len()) };
        file_id
    }
}

impl Drop for InitFileHandle {
    fn drop(&mut self) {
        unsafe { init_ffi_file_handle_free(self.ptr.as_ptr()) };
    }
}
