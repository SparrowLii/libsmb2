use smb2_rust::{
    smb2_connect_share, smb2_context_message_id, smb2_destroy_context, smb2_destroy_url,
    smb2_disconnect_share, smb2_get_error, smb2_init_context, smb2_mkdir, smb2_parse_url,
    smb2_rmdir, smb2_set_security_mode,
};
use std::ffi::{CStr, CString};

#[test]
fn ffi_context_lifecycle_allocates_and_releases_context() {
    let context = smb2_init_context();

    assert!(!context.is_null());
    assert_eq!(unsafe { smb2_context_message_id(context) }, 0);

    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_context_helpers_accept_null_context() {
    assert_eq!(unsafe { smb2_context_message_id(std::ptr::null()) }, 0);

    unsafe { smb2_destroy_context(std::ptr::null_mut()) };
}

#[test]
fn ffi_parse_url_returns_c_compatible_fields() {
    let context = smb2_init_context();
    assert!(!context.is_null());

    let input = CString::new("smb://DOMAIN;user@example/share/path/to/file").unwrap();
    let url = unsafe { smb2_parse_url(context, input.as_ptr()) };
    assert!(!url.is_null());

    unsafe {
        assert_eq!(CStr::from_ptr((*url).domain).to_str().unwrap(), "DOMAIN");
        assert_eq!(CStr::from_ptr((*url).user).to_str().unwrap(), "user");
        assert_eq!(CStr::from_ptr((*url).server).to_str().unwrap(), "example");
        assert_eq!(CStr::from_ptr((*url).share).to_str().unwrap(), "share");
        assert_eq!(
            CStr::from_ptr((*url).path).to_str().unwrap(),
            "path/to/file"
        );
    }

    unsafe { smb2_destroy_url(url) };
    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_parse_url_sets_error_for_invalid_input() {
    let context = smb2_init_context();
    assert!(!context.is_null());

    let input = CString::new("http://example/share").unwrap();
    let url = unsafe { smb2_parse_url(context, input.as_ptr()) };
    assert!(url.is_null());

    let error = unsafe { CStr::from_ptr(smb2_get_error(context)).to_str().unwrap() };
    assert_eq!(error, "URL does not start with 'smb://'");

    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_config_helpers_accept_valid_context() {
    let context = smb2_init_context();
    assert!(!context.is_null());

    unsafe { smb2_set_security_mode(context, 1) };

    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_sync_directory_operations_use_local_state_machine() {
    let context = smb2_init_context();
    assert!(!context.is_null());

    let server = CString::new("example").unwrap();
    let share = CString::new("share").unwrap();
    let user = CString::new("user").unwrap();
    let path = CString::new("dir").unwrap();

    assert_eq!(
        unsafe { smb2_connect_share(context, server.as_ptr(), share.as_ptr(), user.as_ptr()) },
        0
    );
    assert_eq!(unsafe { smb2_mkdir(context, path.as_ptr()) }, 0);
    assert_eq!(unsafe { smb2_rmdir(context, path.as_ptr()) }, 0);
    assert_eq!(unsafe { smb2_disconnect_share(context) }, 0);

    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_sync_directory_operation_reports_error_for_null_path() {
    let context = smb2_init_context();
    assert!(!context.is_null());

    assert_eq!(unsafe { smb2_mkdir(context, std::ptr::null()) }, -22);

    let error = unsafe { CStr::from_ptr(smb2_get_error(context)).to_str().unwrap() };
    assert_eq!(error, "path is not valid UTF-8 or is NULL");

    unsafe { smb2_destroy_context(context) };
}
