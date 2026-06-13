use smb2_rust::{
    dcerpc_allocate_pdu, dcerpc_create_context, dcerpc_free_pdu, dcerpc_ptr_coder,
    dcerpc_set_endian, dcerpc_set_tctx, dcerpc_utf16z_coder,
    free_smb2_file_notify_change_information, nterror_to_errno, nterror_to_str,
    smb2_active_contexts, smb2_add_compound_pdu, smb2_close, smb2_close_context,
    smb2_cmd_echo_async, smb2_connect_share, smb2_context_active, smb2_context_message_id,
    smb2_decode_fileidfulldirectoryinformation, smb2_decode_filenotifychangeinformation,
    smb2_destroy_context, smb2_destroy_url, smb2_disconnect_share, smb2_fh_from_file_id,
    smb2_free_data, smb2_free_pdu, smb2_get_client_guid, smb2_get_compound_pdu, smb2_get_dialect,
    smb2_get_domain, smb2_get_error, smb2_get_fd, smb2_get_fds, smb2_get_file_id,
    smb2_get_libsmb2Version, smb2_get_nterror, smb2_get_opaque, smb2_get_passthrough,
    smb2_get_pdu_message_id, smb2_get_user, smb2_get_workstation, smb2_init_context, smb2_mkdir,
    smb2_parse_url, smb2_rmdir, smb2_service, smb2_service_fd, smb2_set_client_guid,
    smb2_set_domain, smb2_set_error, smb2_set_opaque, smb2_set_passthrough,
    smb2_set_pdu_message_id, smb2_set_security_mode, smb2_set_user, smb2_set_version,
    smb2_set_workstation, smb2_which_events, srvsvc_SHARE_INFO_1_CONTAINER_coder,
    srvsvc_SHARE_INFO_1_coder, DceRpcUtf16C, Smb2FileIdFullDirectoryInformationC,
    Smb2FileNotifyChangeInformationC, Smb2Iovec, Smb2LibVersion, SrvsvcShareInfo1C,
    SrvsvcShareInfo1ContainerC,
};
use std::ffi::{CStr, CString};
use std::os::raw::c_void;

const SMB2_POLLIN: i32 = 0x0001;

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
    assert_eq!(smb2_active_contexts(), std::ptr::null_mut());

    unsafe { smb2_close_context(std::ptr::null_mut()) };
    unsafe { smb2_destroy_context(std::ptr::null_mut()) };
    unsafe { smb2_destroy_url(std::ptr::null_mut()) };
    unsafe { smb2_free_data(std::ptr::null_mut(), std::ptr::null_mut()) };
    free_smb2_file_notify_change_information(std::ptr::null_mut(), std::ptr::null_mut());
    unsafe { smb2_get_libsmb2Version(std::ptr::null_mut()) };
}

#[test]
fn ffi_context_active_and_event_helpers_observe_idle_context() {
    let context = smb2_init_context();
    assert!(!context.is_null());

    assert_eq!(unsafe { smb2_context_active(context) }, 1);
    assert!(unsafe { smb2_get_fd(context) } >= 0);
    assert_eq!(unsafe { smb2_which_events(context) }, 0);
    assert_eq!(unsafe { smb2_service(context, 0) }, 0);
    assert_eq!(unsafe { smb2_service_fd(context, -1, 0) }, 0);

    let mut fd_count = usize::MAX;
    let mut timeout = 0;
    let fds = unsafe { smb2_get_fds(context, &mut fd_count, &mut timeout) };
    assert!(!fds.is_null());
    assert_eq!(fd_count, 1);
    assert_eq!(timeout, -1);

    unsafe { smb2_close_context(context) };
    assert_eq!(unsafe { smb2_get_fd(context) }, -1);

    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_async_cat_surface_completes_through_service_loop() {
    let context = smb2_init_context();
    assert!(!context.is_null());

    let server = CString::new("example").unwrap();
    let share = CString::new("share").unwrap();
    let user = CString::new("user").unwrap();
    let path = CString::new("file.txt").unwrap();
    let mut state = AsyncState::default();

    assert_eq!(
        unsafe {
            smb2_rust::smb2_connect_share_async(
                context,
                server.as_ptr(),
                share.as_ptr(),
                user.as_ptr(),
                Some(connect_cb),
                (&mut state as *mut AsyncState).cast::<c_void>(),
            )
        },
        0
    );
    service_until(context, || state.connected);

    assert_eq!(
        unsafe {
            smb2_rust::smb2_open_async(
                context,
                path.as_ptr(),
                0,
                Some(open_cb),
                (&mut state as *mut AsyncState).cast::<c_void>(),
            )
        },
        0
    );
    service_until(context, || !state.fh.is_null());

    assert_eq!(
        unsafe {
            smb2_rust::smb2_pread_async(
                context,
                state.fh,
                state.buf.as_mut_ptr(),
                state.buf.len() as u32,
                0,
                Some(read_cb),
                (&mut state as *mut AsyncState).cast::<c_void>(),
            )
        },
        0
    );
    service_until(context, || state.read_done);

    assert_eq!(
        unsafe {
            smb2_rust::smb2_close_async(
                context,
                state.fh,
                Some(close_cb),
                (&mut state as *mut AsyncState).cast::<c_void>(),
            )
        },
        0
    );
    service_until(context, || state.closed);

    assert_eq!(
        unsafe {
            smb2_rust::smb2_disconnect_share_async(
                context,
                Some(disconnect_cb),
                (&mut state as *mut AsyncState).cast::<c_void>(),
            )
        },
        0
    );
    service_until(context, || state.disconnected);

    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_cancelled_open_pdu_does_not_fire_callback() {
    let context = smb2_init_context();
    assert!(!context.is_null());

    let server = CString::new("example").unwrap();
    let share = CString::new("share").unwrap();
    let path = CString::new("file.txt").unwrap();
    let mut state = AsyncState::default();

    assert_eq!(
        unsafe { smb2_connect_share(context, server.as_ptr(), share.as_ptr(), std::ptr::null()) },
        0
    );
    let pdu = unsafe {
        smb2_rust::smb2_open_async_pdu(
            context,
            path.as_ptr(),
            0,
            Some(cancelled_cb),
            (&mut state as *mut AsyncState).cast::<c_void>(),
            None,
        )
    };
    assert!(!pdu.is_null());
    unsafe { smb2_free_pdu(context, pdu) };
    assert_eq!(unsafe { smb2_service(context, SMB2_POLLIN) }, 0);
    assert!(!state.cancelled_fired);

    unsafe { smb2_destroy_context(context) };
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
    unsafe { smb2_set_passthrough(context, 1) };
    let mut passthrough = 0;
    unsafe { smb2_get_passthrough(context, &mut passthrough) };
    assert_eq!(passthrough, 1);

    let user = CString::new("alice").unwrap();
    let domain = CString::new("DOMAIN").unwrap();
    let workstation = CString::new("WORKSTATION").unwrap();
    unsafe { smb2_set_user(context, user.as_ptr()) };
    unsafe { smb2_set_domain(context, domain.as_ptr()) };
    unsafe { smb2_set_workstation(context, workstation.as_ptr()) };
    unsafe {
        assert_eq!(
            CStr::from_ptr(smb2_get_user(context)).to_str().unwrap(),
            "alice"
        );
        assert_eq!(
            CStr::from_ptr(smb2_get_domain(context)).to_str().unwrap(),
            "DOMAIN"
        );
        assert_eq!(
            CStr::from_ptr(smb2_get_workstation(context))
                .to_str()
                .unwrap(),
            "WORKSTATION"
        );
    }

    let mut opaque_marker = 7_u32;
    unsafe { smb2_set_opaque(context, (&mut opaque_marker as *mut u32).cast::<c_void>()) };
    assert_eq!(
        unsafe { smb2_get_opaque(context) },
        (&mut opaque_marker as *mut u32).cast::<c_void>()
    );

    let guid = [0xabu8; 16];
    unsafe { smb2_set_client_guid(context, guid.as_ptr()) };
    let guid_ptr = unsafe { smb2_get_client_guid(context) }.cast::<u8>();
    assert!(!guid_ptr.is_null());
    let observed = unsafe { std::slice::from_raw_parts(guid_ptr, guid.len()) };
    assert_eq!(observed, guid);

    unsafe { smb2_set_version(context, 0x0311) };
    assert_eq!(unsafe { smb2_get_dialect(context) }, 0);

    let mut version = Smb2LibVersion::default();
    unsafe { smb2_get_libsmb2Version(&mut version) };
    assert_eq!(version.major_version, 4);
    assert_eq!(version.minor_version, 0);
    assert_eq!(version.patch_version, 0);

    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_error_and_status_helpers_are_observable_without_network() {
    let context = smb2_init_context();
    assert!(!context.is_null());

    let message = CString::new("offline error").unwrap();
    unsafe { smb2_set_error(context, message.as_ptr()) };
    let error = unsafe { CStr::from_ptr(smb2_get_error(context)).to_str().unwrap() };
    assert_eq!(error, "offline error");

    let bad_url = CString::new("http://example/share").unwrap();
    assert!(unsafe { smb2_parse_url(context, bad_url.as_ptr()) }.is_null());
    assert_eq!(unsafe { smb2_get_nterror(context) }, -22);

    assert_eq!(nterror_to_errno(0), 0);
    assert_eq!(nterror_to_errno(0xC000_000D), 22);
    let status = nterror_to_str(0);
    assert_eq!(
        unsafe { CStr::from_ptr(status).to_str().unwrap() },
        "STATUS_SUCCESS"
    );

    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_compound_pdu_helpers_link_public_pdu_state() {
    let context = smb2_init_context();
    assert!(!context.is_null());

    let first = smb2_cmd_echo_async(context, None, std::ptr::null_mut());
    let second = smb2_cmd_echo_async(context, None, std::ptr::null_mut());
    assert!(!first.is_null());
    assert!(!second.is_null());

    unsafe { smb2_set_pdu_message_id(context, first, 7) };
    assert_eq!(unsafe { smb2_get_pdu_message_id(context, first) }, 7);

    unsafe { smb2_add_compound_pdu(context, first, second) };
    assert_eq!(unsafe { smb2_get_compound_pdu(context, first) }, second);

    unsafe { smb2_free_pdu(context, second) };
    unsafe { smb2_free_pdu(context, first) };
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

#[test]
fn ffi_file_handle_from_file_id_exposes_internal_file_id() {
    let context = smb2_init_context();
    assert!(!context.is_null());
    let mut file_id = [0x11_u8; 16];
    file_id[15] = 0xee;

    let handle = unsafe { smb2_fh_from_file_id(context, &mut file_id) };
    assert!(!handle.is_null());
    file_id.fill(0);

    let borrowed = unsafe { smb2_get_file_id(handle) };
    assert!(!borrowed.is_null());
    assert_eq!(
        unsafe { *borrowed },
        [
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0xee,
        ]
    );

    assert_eq!(unsafe { smb2_close(context, handle) }, 0);
    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_fileid_full_directory_decoder_fills_output_and_error() {
    let context = smb2_init_context();
    assert!(!context.is_null());
    let mut buffer = fileid_full_directory_entry("ab");
    let mut vec = Smb2Iovec {
        buf: buffer.as_mut_ptr(),
        len: buffer.len(),
        free: None,
    };
    let mut out = Smb2FileIdFullDirectoryInformationC::default();

    assert_eq!(
        unsafe { smb2_decode_fileidfulldirectoryinformation(context, &mut out, &mut vec) },
        0
    );
    assert_eq!(out.file_index, 7);
    assert_eq!(out.end_of_file, 0x0102_0304_0506_0708);
    assert_eq!(out.allocation_size, 0x1112_1314_1516_1718);
    assert_eq!(out.file_attributes, 0x20);
    assert_eq!(out.ea_size, 3);
    assert_eq!(out.file_id, 0xa1a2_a3a4_a5a6_a7a8);
    assert_eq!(unsafe { CStr::from_ptr(out.name).to_str().unwrap() }, "ab");

    let name_len = 100_u32.to_le_bytes();
    buffer[60..64].copy_from_slice(&name_len);
    assert_eq!(
        unsafe { smb2_decode_fileidfulldirectoryinformation(context, &mut out, &mut vec) },
        -1
    );
    let error = unsafe { CStr::from_ptr(smb2_get_error(context)).to_str().unwrap() };
    assert_eq!(error, "Malformed name in query.\n");

    vec.len = 8;
    assert_eq!(
        unsafe { smb2_decode_fileidfulldirectoryinformation(context, &mut out, &mut vec) },
        -1
    );

    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_filenotify_decoder_handles_chain_and_short_buffer() {
    let context = smb2_init_context();
    assert!(!context.is_null());
    let mut buffer = notify_chain();
    let mut vec = Smb2Iovec {
        buf: buffer.as_mut_ptr(),
        len: buffer.len(),
        free: None,
    };
    let mut out = Smb2FileNotifyChangeInformationC::default();

    assert_eq!(
        unsafe { smb2_decode_filenotifychangeinformation(context, &mut out, &mut vec, 0) },
        0
    );
    assert_eq!(out.action, 1);
    assert_eq!(unsafe { CStr::from_ptr(out.name).to_str().unwrap() }, "a");
    assert!(!out.next.is_null());
    assert_eq!(unsafe { (*out.next).action }, 3);
    assert_eq!(
        unsafe { CStr::from_ptr((*out.next).name).to_str().unwrap() },
        "b"
    );

    free_smb2_file_notify_change_information(context, out.next);
    out.next = std::ptr::null_mut();

    let mut short = [0_u8; 4];
    vec = Smb2Iovec {
        buf: short.as_mut_ptr(),
        len: short.len(),
        free: None,
    };
    assert_eq!(
        unsafe { smb2_decode_filenotifychangeinformation(context, &mut out, &mut vec, 0) },
        0
    );
    assert_eq!(out.action, 0);
    assert!(out.name.is_null());
    assert!(out.next.is_null());

    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_dcerpc_utf16_coder_matches_coder_test_vector() {
    let context = smb2_init_context();
    assert!(!context.is_null());
    let dce = dcerpc_create_context(context);
    assert!(!dce.is_null());
    let pdu = dcerpc_allocate_pdu(dce, 1, std::mem::size_of::<DceRpcUtf16C>() as i32);
    assert!(!pdu.is_null());
    dcerpc_set_tctx(dce, 0);
    dcerpc_set_endian(pdu, 1);

    let text = CString::new("\\\\win16-1").unwrap();
    let mut value = DceRpcUtf16C {
        max_count: 0,
        offset: 0,
        actual_count: 0,
        utf16: std::ptr::null_mut(),
        utf8: text.as_ptr(),
    };
    let mut buffer = [0_u8; 64];
    let mut iov = Smb2Iovec {
        buf: buffer.as_mut_ptr(),
        len: buffer.len(),
        free: None,
    };
    let mut offset = 0;

    assert_eq!(
        unsafe {
            dcerpc_ptr_coder(
                dce,
                pdu,
                &mut iov,
                &mut offset,
                (&mut value as *mut DceRpcUtf16C).cast::<c_void>(),
                0,
                Some(dcerpc_utf16z_coder),
            )
        },
        0
    );
    assert_eq!(offset, 32);
    assert_eq!(
        &buffer[..offset as usize],
        &[
            0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x5c, 0x00,
            0x5c, 0x00, 0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x2d, 0x00,
            0x31, 0x00, 0x00, 0x00,
        ]
    );

    unsafe { dcerpc_free_pdu(dce, pdu) };
    unsafe { smb2_rust::dcerpc_destroy_context(dce) };
    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_srvsvc_share_info_1_coder_matches_coder_test_vector() {
    let context = smb2_init_context();
    assert!(!context.is_null());
    let dce = dcerpc_create_context(context);
    assert!(!dce.is_null());
    let pdu = dcerpc_allocate_pdu(dce, 1, std::mem::size_of::<SrvsvcShareInfo1C>() as i32);
    assert!(!pdu.is_null());
    dcerpc_set_tctx(dce, 0);
    dcerpc_set_endian(pdu, 1);

    let netname = CString::new("IPC$").unwrap();
    let remark = CString::new("Remote IPC").unwrap();
    let mut value = SrvsvcShareInfo1C {
        netname: dcerpc_utf16(netname.as_ptr()),
        type_: 0x8000_0003,
        remark: dcerpc_utf16(remark.as_ptr()),
    };
    let mut buffer = [0_u8; 128];
    let mut iov = Smb2Iovec {
        buf: buffer.as_mut_ptr(),
        len: buffer.len(),
        free: None,
    };
    let mut offset = 0;

    assert_eq!(
        srvsvc_SHARE_INFO_1_coder(
            dce,
            pdu,
            &mut iov,
            &mut offset,
            (&mut value as *mut SrvsvcShareInfo1C).cast::<c_void>(),
        ),
        0
    );
    assert_eq!(offset, 70);
    assert_eq!(
        &buffer[..offset as usize],
        &[
            0x55, 0x70, 0x74, 0x72, 0x03, 0x00, 0x00, 0x80, 0x55, 0x70, 0x74, 0x72, 0x05, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x49, 0x00, 0x50, 0x00,
            0x43, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x52, 0x00, 0x65, 0x00, 0x6d, 0x00, 0x6f, 0x00,
            0x74, 0x00, 0x65, 0x00, 0x20, 0x00, 0x49, 0x00, 0x50, 0x00, 0x43, 0x00, 0x00, 0x00,
        ]
    );

    unsafe { dcerpc_free_pdu(dce, pdu) };
    unsafe { smb2_rust::dcerpc_destroy_context(dce) };
    unsafe { smb2_destroy_context(context) };
}

#[test]
fn ffi_srvsvc_share_info_1_container_coder_writes_entries() {
    let context = smb2_init_context();
    assert!(!context.is_null());
    let dce = dcerpc_create_context(context);
    assert!(!dce.is_null());
    let pdu = dcerpc_allocate_pdu(
        dce,
        1,
        std::mem::size_of::<SrvsvcShareInfo1ContainerC>() as i32,
    );
    assert!(!pdu.is_null());
    dcerpc_set_tctx(dce, 0);
    dcerpc_set_endian(pdu, 1);

    let netname = CString::new("IPC$").unwrap();
    let remark = CString::new("Remote IPC").unwrap();
    let mut entries = [SrvsvcShareInfo1C {
        netname: dcerpc_utf16(netname.as_ptr()),
        type_: 0x8000_0003,
        remark: dcerpc_utf16(remark.as_ptr()),
    }];
    let mut container = SrvsvcShareInfo1ContainerC {
        entries_read: entries.len() as u32,
        share_info_1: entries.as_mut_ptr(),
    };
    let mut buffer = [0_u8; 160];
    let mut iov = Smb2Iovec {
        buf: buffer.as_mut_ptr(),
        len: buffer.len(),
        free: None,
    };
    let mut offset = 0;

    assert_eq!(
        srvsvc_SHARE_INFO_1_CONTAINER_coder(
            dce,
            pdu,
            &mut iov,
            &mut offset,
            (&mut container as *mut SrvsvcShareInfo1ContainerC).cast::<c_void>(),
        ),
        0
    );
    assert_eq!(offset, 82);
    assert_eq!(
        &buffer[..12],
        &[0x01, 0, 0, 0, 0x55, 0x70, 0x74, 0x72, 0x01, 0, 0, 0]
    );

    unsafe { dcerpc_free_pdu(dce, pdu) };
    unsafe { smb2_rust::dcerpc_destroy_context(dce) };
    unsafe { smb2_destroy_context(context) };
}

fn fileid_full_directory_entry(name: &str) -> Vec<u8> {
    let name_bytes = utf16le(name);
    let mut buffer = vec![0_u8; 80 + name_bytes.len()];
    write_u32(&mut buffer, 4, 7);
    write_u64(&mut buffer, 40, 0x0102_0304_0506_0708);
    write_u64(&mut buffer, 48, 0x1112_1314_1516_1718);
    write_u32(&mut buffer, 56, 0x20);
    write_u32(&mut buffer, 60, name_bytes.len() as u32);
    write_u32(&mut buffer, 64, 3);
    write_u64(&mut buffer, 72, 0xa1a2_a3a4_a5a6_a7a8);
    buffer[80..].copy_from_slice(&name_bytes);
    buffer
}

fn dcerpc_utf16(utf8: *const i8) -> DceRpcUtf16C {
    DceRpcUtf16C {
        max_count: 0,
        offset: 0,
        actual_count: 0,
        utf16: std::ptr::null_mut(),
        utf8,
    }
}

#[derive(Default)]
struct AsyncState {
    connected: bool,
    fh: *mut smb2_rust::Smb2RustFileHandle,
    buf: [u8; 16],
    read_done: bool,
    closed: bool,
    disconnected: bool,
    cancelled_fired: bool,
}

fn service_until(context: *mut smb2_rust::Smb2RustContext, done: impl Fn() -> bool) {
    for _ in 0..16 {
        if done() {
            return;
        }
        assert_eq!(unsafe { smb2_service(context, SMB2_POLLIN) }, 0);
    }
    assert!(done());
}

unsafe extern "C" fn connect_cb(
    _smb2: *mut smb2_rust::Smb2RustContext,
    status: i32,
    _command_data: *mut c_void,
    private_data: *mut c_void,
) {
    assert_eq!(status, 0);
    unsafe { (*private_data.cast::<AsyncState>()).connected = true };
}

unsafe extern "C" fn open_cb(
    _smb2: *mut smb2_rust::Smb2RustContext,
    status: i32,
    command_data: *mut c_void,
    private_data: *mut c_void,
) {
    assert_eq!(status, 0);
    assert!(!command_data.is_null());
    unsafe { (*private_data.cast::<AsyncState>()).fh = command_data.cast() };
}

unsafe extern "C" fn read_cb(
    _smb2: *mut smb2_rust::Smb2RustContext,
    status: i32,
    _command_data: *mut c_void,
    private_data: *mut c_void,
) {
    assert_eq!(status, 0);
    unsafe { (*private_data.cast::<AsyncState>()).read_done = true };
}

unsafe extern "C" fn close_cb(
    _smb2: *mut smb2_rust::Smb2RustContext,
    status: i32,
    _command_data: *mut c_void,
    private_data: *mut c_void,
) {
    assert_eq!(status, 0);
    unsafe { (*private_data.cast::<AsyncState>()).closed = true };
}

unsafe extern "C" fn disconnect_cb(
    _smb2: *mut smb2_rust::Smb2RustContext,
    status: i32,
    _command_data: *mut c_void,
    private_data: *mut c_void,
) {
    assert_eq!(status, 0);
    unsafe { (*private_data.cast::<AsyncState>()).disconnected = true };
}

unsafe extern "C" fn cancelled_cb(
    _smb2: *mut smb2_rust::Smb2RustContext,
    _status: i32,
    _command_data: *mut c_void,
    private_data: *mut c_void,
) {
    unsafe { (*private_data.cast::<AsyncState>()).cancelled_fired = true };
}

fn notify_chain() -> Vec<u8> {
    let first_name = utf16le("a");
    let second_name = utf16le("b");
    let first_len = 12 + first_name.len();
    let first_padded = (first_len + 3) & !3;
    let mut buffer = vec![0_u8; first_padded + 12 + second_name.len()];
    write_u32(&mut buffer, 0, first_padded as u32);
    write_u32(&mut buffer, 4, 1);
    write_u32(&mut buffer, 8, first_name.len() as u32);
    buffer[12..12 + first_name.len()].copy_from_slice(&first_name);
    write_u32(&mut buffer, first_padded + 4, 3);
    write_u32(&mut buffer, first_padded + 8, second_name.len() as u32);
    buffer[first_padded + 12..].copy_from_slice(&second_name);
    buffer
}

fn utf16le(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

fn write_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
