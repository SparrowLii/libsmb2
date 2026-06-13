use libsmb2_sys::include::asprintf;
use libsmb2_sys::include::config::{AMIGA_OS_CONFIG, APPLE_CONFIG};
use libsmb2_sys::include::libsmb2_private::{
    context_layout, directory_layout, discard_const_addr, header_layout, io_vectors_layout,
    is_server_for_owning_server, min_i32, pad_to_32bit, pad_to_64bit, pdu_layout,
    private_constants, sizeof_smb2_context, sizeof_smb2_header, sizeof_smb2_io_vectors,
    sizeof_smb2_pdu, sizeof_smb2dir, sync_cb_data_layout, tree_id_for_current_index,
};
use libsmb2_sys::include::{portable_endian, slist};
use libsmb2_sys::legacy::{
    aes, aes128ccm, compat, errors, hmac_md5, md4, md5, sha, timestamps, unicode,
};
use libsmb2_sys::smb2::{
    libsmb2_dcerpc, libsmb2_dcerpc_lsa, libsmb2_dcerpc_srvsvc, smb2_errors, smb2_ioctl,
};
use libsmb2_sys::RecvState;

#[test]
fn test_smoke_libsmb2_private_constants_and_layouts() {
    // Smoke source: include/libsmb2-private.h; target: libsmb2_private; path: constants/layouts.
    let constants = private_constants();

    assert_eq!(constants.max_error_size, 256);
    assert_eq!(constants.spl_size, 4);
    assert_eq!(constants.header_size, 64);
    assert_eq!(constants.signature_size, 16);
    assert_eq!(constants.key_size, 16);
    assert_eq!(constants.max_vectors, 256);
    assert_eq!(constants.max_tree_nesting, 32);
    assert_eq!(constants.max_credits, 1024);
    assert_eq!(constants.salt_size, 32);
    assert_eq!(constants.max_pdu_size, 16 * 1024 * 1024);
    assert_eq!(constants.preauth_hash_size, 64);
    assert_eq!(pad_to_32bit(5), 8);
    assert_eq!(pad_to_64bit(9), 16);
    assert_eq!(RecvState::Spl.value(), Some(0));
    assert_eq!(RecvState::Unknown.value(), Some(6));
    assert_eq!(sizeof_smb2_header(), 64);
    assert!(sizeof_smb2_io_vectors() > sizeof_smb2_header());
    assert!(sizeof_smb2_context() > 0);
    assert!(sizeof_smb2_pdu() > 0);
    assert!(sizeof_smb2dir() > 0);

    assert_eq!(min_i32(3, 7), 3);
    let marker = 42_u32;
    assert_eq!(
        discard_const_addr(&marker),
        (&marker as *const u32) as usize
    );

    let context = context_layout();
    assert_eq!(context.error_string_len, constants.max_error_size as usize);
    assert_eq!(context.header_len, constants.header_size as usize);
    assert_eq!(context.tree_id_len, constants.max_tree_nesting as usize);
    assert_eq!(context.signing_key_len, constants.key_size as usize);
    assert_eq!(context.serverin_key_len, constants.key_size as usize);
    assert_eq!(context.serverout_key_len, constants.key_size as usize);
    assert_eq!(context.salt_len, constants.salt_size as usize);
    assert!(context.has_connect_cb_data);
    assert!(context.has_io_vectors);
    assert!(context.has_owning_server);

    let vectors = io_vectors_layout();
    assert_eq!(vectors.iov_len, constants.max_vectors as usize);
    assert!(vectors.has_num_done);
    assert!(vectors.has_total_size);
    assert!(vectors.has_niov);

    let header = header_layout();
    assert_eq!(header.protocol_id_len, 4);
    assert_eq!(header.signature_len, constants.signature_size as usize);
    assert!(header.has_async_id);
    assert!(header.has_process_id);
    assert!(header.has_tree_id);

    let pdu = pdu_layout();
    assert_eq!(pdu.hdr_len, constants.header_size as usize);
    assert!(pdu.has_header);
    assert!(pdu.has_out_vectors);
    assert!(pdu.has_in_vectors);
    assert!(pdu.has_payload);
    assert!(pdu.has_free_payload);

    let callback = sync_cb_data_layout();
    assert!(callback.has_is_finished);
    assert!(callback.has_status);
    assert!(callback.has_ptr);

    let dir = directory_layout();
    assert!(dir.has_internal_next);
    assert!(dir.has_internal_dirent);
    assert!(dir.has_entries);
    assert!(dir.has_current_entry);
    assert!(dir.has_index);

    assert_eq!(tree_id_for_current_index(-1, 0x1122_3344), 0xdead_beef);
    assert_eq!(tree_id_for_current_index(0, 0x1122_3344), 0x1122_3344);
    assert!(!is_server_for_owning_server(false));
    assert!(is_server_for_owning_server(true));
}

#[test]
fn test_smoke_smb2_ioctl_constants() {
    // Smoke source: include/smb2/smb2-ioctl.h; target: smb2_ioctl; path: constants.
    assert_eq!(smb2_ioctl::FSCTL_GET_REPARSE_POINT, 0x0009_00A8);
    assert_eq!(smb2_ioctl::FSCTL_PIPE_TRANSCEIVE, 0x0011_C017);
    assert_eq!(
        smb2_ioctl::FSCTL_GET_SHADOW_COPY_DATA,
        smb2_ioctl::FSCTL_SRV_ENUMERATE_SNAPSHOTS
    );
}

#[test]
fn test_smoke_portable_endian_conversions() {
    // Smoke source: include/portable-endian.h; target: portable_endian; path: conversions.
    assert_eq!(portable_endian::host_to_be16(0x1234), 0x1234_u16.to_be());
    assert_eq!(portable_endian::be16_to_host(0x1234_u16.to_be()), 0x1234);
    assert_eq!(portable_endian::host_to_le16(0x1234), 0x1234_u16.to_le());
    assert_eq!(portable_endian::le16_to_host(0x1234_u16.to_le()), 0x1234);
    assert_eq!(
        portable_endian::host_to_be32(0x1234_5678),
        0x1234_5678_u32.to_be()
    );
    assert_eq!(
        portable_endian::be32_to_host(0x1234_5678_u32.to_be()),
        0x1234_5678
    );
    assert_eq!(
        portable_endian::host_to_le32(0x1234_5678),
        0x1234_5678_u32.to_le()
    );
    assert_eq!(
        portable_endian::le32_to_host(0x1234_5678_u32.to_le()),
        0x1234_5678
    );
    assert_eq!(
        portable_endian::host_to_be64(0x1234_5678_9ABC_DEF0),
        0x1234_5678_9ABC_DEF0_u64.to_be()
    );
    assert_eq!(
        portable_endian::be64_to_host(0x1234_5678_9ABC_DEF0_u64.to_be()),
        0x1234_5678_9ABC_DEF0
    );
    assert_eq!(
        portable_endian::host_to_le64(0x1234_5678_9ABC_DEF0),
        0x1234_5678_9ABC_DEF0_u64.to_le()
    );
    assert_eq!(
        portable_endian::le64_to_host(0x1234_5678_9ABC_DEF0_u64.to_le()),
        0x1234_5678_9ABC_DEF0
    );
}

#[test]
fn test_smoke_slist_macro_wrappers() {
    // Smoke source: include/slist.h; target: SMB2_LIST_* macro wrappers.
    let mut first = slist::SListNode::new();
    let mut second = slist::SListNode::new();
    let mut third = slist::SListNode::new();
    let mut missing = slist::SListNode::new();
    let mut list = slist::SListHead::empty();

    list.add(&mut first);
    assert!(list.head_is(Some(&first)));
    assert!(first.next_is(None));

    list.add_end(&mut second);
    assert!(list.head_is(Some(&first)));
    assert!(first.next_is(Some(&second)));
    assert!(second.next_is(None));

    list.add(&mut third);
    assert!(list.head_is(Some(&third)));
    assert!(third.next_is(Some(&first)));
    assert_eq!(list.len(), 3);
    assert!(list.head_is(Some(&third)));

    list.remove(&mut first);
    assert!(list.head_is(Some(&third)));
    assert!(third.next_is(Some(&second)));
    assert_eq!(list.len(), 2);

    list.remove(&mut missing);
    assert!(list.head_is(Some(&third)));
    assert_eq!(list.len(), 2);

    list.remove(&mut third);
    assert!(list.head_is(Some(&second)));
}

#[test]
fn test_smoke_asprintf_header_wrappers() {
    // Smoke source: include/asprintf.h; target: header-only format helpers.
    assert_eq!(asprintf::vscprintf_two_ints("%d:%02d", 7, 5), 4);
    assert_eq!(asprintf::vscprintf_reuse_after_length("%d:%02d", 7, 5), 4);

    let vasprintf_result = asprintf::vasprintf_two_ints("%d:%02d", 7, 5).unwrap();
    assert_eq!(vasprintf_result.rc, 4);
    assert_eq!(vasprintf_result.text, "7:05");

    let asprintf_result = asprintf::asprintf_two_ints("%d:%02d", 7, 5).unwrap();
    assert_eq!(asprintf_result.rc, 4);
    assert_eq!(asprintf_result.text, "7:05");

    assert_eq!(asprintf::vasprintf_null_format_failure(), -1);

    let length_failure = asprintf::vasprintf_length_failure_preserves_output();
    assert_eq!(length_failure.rc, -1);
    assert!(!length_failure.wrote_new_buffer);

    let allocation_failure = asprintf::vasprintf_alloc_failure_preserves_output();
    assert_eq!(allocation_failure.rc, -1);
    assert!(!allocation_failure.wrote_new_buffer);

    let formatting_failure = asprintf::vasprintf_format_failure_releases_storage();
    assert_eq!(formatting_failure.rc, -1);
    assert!(formatting_failure.released_allocated_storage);
    assert!(asprintf::xbox_inline_maps_to_inline());
}

#[test]
fn test_smoke_platform_config_macros() {
    // Smoke source: include/amiga_os/config.h and include/apple/config.h; target: config macros.
    assert_eq!(AMIGA_OS_CONFIG.configure_option_tcp_linger, Some(1));
    assert_eq!(AMIGA_OS_CONFIG.have_arpa_inet_h, Some(1));
    assert_eq!(AMIGA_OS_CONFIG.have_gssapi_gssapi_h, None);
    assert_eq!(AMIGA_OS_CONFIG.have_linger, None);
    assert_eq!(AMIGA_OS_CONFIG.have_poll_h, None);
    assert_eq!(AMIGA_OS_CONFIG.have_sockaddr_storage, None);
    assert_eq!(AMIGA_OS_CONFIG.lt_objdir, ".libs/");
    assert_eq!(AMIGA_OS_CONFIG.package, "libsmb2");
    assert_eq!(AMIGA_OS_CONFIG.version, "4.0.0");

    assert_eq!(APPLE_CONFIG.configure_option_tcp_linger, Some(1));
    assert_eq!(APPLE_CONFIG.have_arpa_inet_h, Some(1));
    assert_eq!(APPLE_CONFIG.have_gssapi_gssapi_h, Some(1));
    assert_eq!(APPLE_CONFIG.have_linger, Some(1));
    assert_eq!(APPLE_CONFIG.have_poll_h, Some(1));
    assert_eq!(APPLE_CONFIG.have_sockaddr_storage, Some(1));
    assert_eq!(APPLE_CONFIG.have_sys_iovec_h, None);
    assert_eq!(APPLE_CONFIG.package_string, "libsmb2 4.0.0");
}

#[test]
fn test_smoke_smb2_errors_constants() {
    // Smoke source: include/smb2/smb2-errors.h; target: smb2_errors; path: constants.
    assert_eq!(smb2_errors::SMB2_STATUS_SUCCESS, 0x0000_0000);
    assert_eq!(smb2_errors::SMB2_STATUS_SEVERITY_ERROR, 0xC000_0000);
    assert_eq!(smb2_errors::SMB2_STATUS_INVALID_PARAMETER, 0xC000_000D);
    assert_eq!(smb2_errors::SMB2_STATUS_ACCESS_DENIED, 0xC000_0022);
    assert_eq!(smb2_errors::SMB2_STATUS_CODE_MASK, 0x0000_FFFF);
}

#[test]
fn test_smoke_aes_encrypt_block() {
    // Smoke source: lib/aes.c; target: aes; path: AES-128 ECB block encryption.
    let input = aes::AesBlock([
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f,
    ]);
    let key = aes::AesBlock([
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ]);

    assert_eq!(
        aes::encrypt_block(input, key).0,
        [
            0x8c, 0xaa, 0x7f, 0x58, 0x9a, 0xa0, 0xce, 0xb6, 0x35, 0x0a, 0x45, 0xe7, 0x0a, 0x6e,
            0x43, 0x5b,
        ]
    );
}

#[test]
fn test_smoke_aes128ccm_encrypt_decrypt_known_vector() {
    // Smoke source: lib/aes128ccm.c; target: aes128ccm; path: known vector.
    let mut key = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];
    let mut nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
    let mut aad = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let plaintext = [0x20, 0x21, 0x22, 0x23];
    let mut payload = plaintext;

    let mut mac = aes128ccm::encrypt(&mut key, &mut nonce, &mut aad, &mut payload, 4).unwrap();
    assert_eq!(payload, [0x71, 0x62, 0x01, 0x5b]);
    assert_eq!(mac, [0x4d, 0xac, 0x25, 0x5d]);

    aes128ccm::decrypt(&mut key, &mut nonce, &mut aad, &mut payload, &mut mac).unwrap();
    assert_eq!(payload, plaintext);
}

#[test]
fn test_smoke_libsmb2_dcerpc_lsa_constants_and_data_model() {
    // Smoke source: include/smb2/libsmb2-dcerpc-lsa.h; target: LSA constants/models.
    assert_eq!(libsmb2_dcerpc_lsa::LSA_CLOSE, 0x00);
    assert_eq!(libsmb2_dcerpc_lsa::LSA_OPENPOLICY2, 0x2c);
    assert_eq!(libsmb2_dcerpc_lsa::LSA_LOOKUPSIDS2, 0x39);
    assert_eq!(libsmb2_dcerpc_lsa::POLICY_LOOKUP_NAMES, 0x0000_0800);
    assert_eq!(libsmb2_dcerpc_lsa::NT_SID_AUTHORITY, [0, 0, 0, 0, 0, 5]);
    assert_eq!(libsmb2_dcerpc_lsa::LsapLookupLevel::Wksta as u32, 1);
    assert_eq!(
        libsmb2_dcerpc_lsa::LsapLookupLevel::RodcReferralToFullDc as u32,
        7
    );

    let sid = libsmb2_dcerpc_lsa::RpcSid::new(libsmb2_dcerpc_lsa::NT_SID_AUTHORITY, &[32, 544]);
    assert_eq!(sid.revision, 1);
    assert_eq!(sid.sub_authority_count(), 2);
    assert_eq!(sid.sub_authorities, [32, 544]);

    let attrs = libsmb2_dcerpc_lsa::ObjectAttributes::empty_for_openpolicy2();
    assert!(attrs.root_directory_is_null);
    assert_eq!(attrs.length, 0);
    assert_eq!(attrs.attributes, 0);
}

#[test]
fn test_smoke_libsmb2_dcerpc_context_pdu_and_error_boundary() {
    // Smoke source: include/smb2/libsmb2-dcerpc.h/lib/dcerpc.c; target: DCERPC core lifecycle.
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    assert!(libsmb2_dcerpc::dcerpc_get_smb2_context(&dce));
    assert_eq!(libsmb2_dcerpc::dcerpc_get_error(&dce), None);

    let mut pdu =
        libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, libsmb2_dcerpc::DCERPC_ENCODE, 4).unwrap();
    assert_eq!(pdu.direction, libsmb2_dcerpc::DCERPC_ENCODE);
    assert_eq!(libsmb2_dcerpc::dcerpc_get_pdu_payload(&pdu).len(), 4);

    libsmb2_dcerpc::dcerpc_set_size_is(&mut pdu, 7);
    assert_eq!(libsmb2_dcerpc::dcerpc_get_size_is(&pdu), 7);
    libsmb2_dcerpc::dcerpc_free_pdu(&mut dce, pdu);

    let result = libsmb2_dcerpc::dcerpc_open_async(&mut dce, Box::new(|_, _, _| {}));
    assert_eq!(result.unwrap_err().code(), -38);
    assert_eq!(
        libsmb2_dcerpc::dcerpc_get_error(&dce),
        Some("DCERPC open requires real SMB2 named-pipe transport")
    );
}

#[test]
fn test_smoke_libsmb2_dcerpc_scalar_uuid_handle_utf16_and_carray_coders() {
    // Smoke source: lib/dcerpc.c; target: offline NDR coder harness.
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu =
        libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, libsmb2_dcerpc::DCERPC_ENCODE, 0).unwrap();
    let mut iov = libsmb2_dcerpc::Smb2Iovec::default();
    let mut offset = 0;
    let mut byte = 0x12;
    let mut word = 0x3456;
    let mut dword = 0x789a_bcde;
    let mut wide = 0x1122_3344_5566_7788;
    let mut uuid = libsmb2_dcerpc::DceRpcUuid {
        v1: 0x0102_0304,
        v2: 0x0506,
        v3: 0x0708,
        v4: [9, 10, 11, 12, 13, 14, 15, 16],
    };
    let mut handle = libsmb2_dcerpc::NdrContextHandle {
        context_handle_attributes: 0xaabb_ccdd,
        context_handle_uuid: uuid,
    };
    let mut text = libsmb2_dcerpc::DceRpcUtf16 {
        utf8: Some("hi".to_owned()),
        ..libsmb2_dcerpc::DceRpcUtf16::default()
    };
    let mut payload = libsmb2_dcerpc::DceRpcPayload {
        data: vec![1, 2, 3, 4],
    };

    libsmb2_dcerpc::dcerpc_uint8_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut byte)
        .unwrap();
    libsmb2_dcerpc::dcerpc_uint16_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut word)
        .unwrap();
    libsmb2_dcerpc::dcerpc_uint32_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut dword)
        .unwrap();
    libsmb2_dcerpc::dcerpc_uint3264_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut wide)
        .unwrap();
    libsmb2_dcerpc::dcerpc_uuid_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut uuid)
        .unwrap();
    libsmb2_dcerpc::dcerpc_context_handle_coder(
        &mut dce,
        &mut pdu,
        &mut iov,
        &mut offset,
        &mut handle,
    )
    .unwrap();
    libsmb2_dcerpc::dcerpc_utf16z_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut text)
        .unwrap();
    libsmb2_dcerpc::dcerpc_carray_coder(
        &mut dce,
        &mut pdu,
        &mut iov,
        &mut offset,
        4,
        &mut payload,
        1,
        |_dce, _pdu, _iov, _offset, _payload| 0,
    )
    .unwrap();

    let encoded = iov.data.clone();
    let mut decoded_pdu =
        libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, libsmb2_dcerpc::DCERPC_DECODE, 0).unwrap();
    let mut decoded_iov = libsmb2_dcerpc::Smb2Iovec { data: encoded };
    let mut decoded_offset = 0;
    let mut decoded_byte = 0;
    let mut decoded_word = 0;
    let mut decoded_dword = 0;
    let mut decoded_wide = 0;
    let mut decoded_uuid = libsmb2_dcerpc::DceRpcUuid::default();
    let mut decoded_handle = libsmb2_dcerpc::NdrContextHandle::default();
    let mut decoded_text = libsmb2_dcerpc::DceRpcUtf16::default();
    let mut decoded_payload = libsmb2_dcerpc::DceRpcPayload::default();

    libsmb2_dcerpc::dcerpc_uint8_coder(
        &mut dce,
        &mut decoded_pdu,
        &mut decoded_iov,
        &mut decoded_offset,
        &mut decoded_byte,
    )
    .unwrap();
    libsmb2_dcerpc::dcerpc_uint16_coder(
        &mut dce,
        &mut decoded_pdu,
        &mut decoded_iov,
        &mut decoded_offset,
        &mut decoded_word,
    )
    .unwrap();
    libsmb2_dcerpc::dcerpc_uint32_coder(
        &mut dce,
        &mut decoded_pdu,
        &mut decoded_iov,
        &mut decoded_offset,
        &mut decoded_dword,
    )
    .unwrap();
    libsmb2_dcerpc::dcerpc_uint3264_coder(
        &mut dce,
        &mut decoded_pdu,
        &mut decoded_iov,
        &mut decoded_offset,
        &mut decoded_wide,
    )
    .unwrap();
    libsmb2_dcerpc::dcerpc_uuid_coder(
        &mut dce,
        &mut decoded_pdu,
        &mut decoded_iov,
        &mut decoded_offset,
        &mut decoded_uuid,
    )
    .unwrap();
    libsmb2_dcerpc::dcerpc_context_handle_coder(
        &mut dce,
        &mut decoded_pdu,
        &mut decoded_iov,
        &mut decoded_offset,
        &mut decoded_handle,
    )
    .unwrap();
    libsmb2_dcerpc::dcerpc_utf16z_coder(
        &mut dce,
        &mut decoded_pdu,
        &mut decoded_iov,
        &mut decoded_offset,
        &mut decoded_text,
    )
    .unwrap();
    libsmb2_dcerpc::dcerpc_carray_coder(
        &mut dce,
        &mut decoded_pdu,
        &mut decoded_iov,
        &mut decoded_offset,
        4,
        &mut decoded_payload,
        1,
        |_dce, _pdu, _iov, _offset, _payload| 0,
    )
    .unwrap();

    assert_eq!(decoded_byte, 0x12);
    assert_eq!(decoded_word, 0x3456);
    assert_eq!(decoded_dword, 0x789a_bcde);
    assert_eq!(decoded_wide, 0x5566_7788);
    assert_eq!(decoded_uuid.v4, [9, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(decoded_handle.context_handle_attributes, 0xaabb_ccdd);
    assert_eq!(decoded_text.utf8.as_deref(), Some("hi"));
    assert_eq!(decoded_payload.data, vec![1, 2, 3, 4]);
}

#[test]
fn test_smoke_libsmb2_dcerpc_callback_harness() {
    // Smoke source: include/smb2/libsmb2-dcerpc.h; target: dcerpc_cb safe callback lifecycle.
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    libsmb2_dcerpc::dcerpc_invoke_callback(
        &mut dce,
        0,
        libsmb2_dcerpc::DceRpcPayload { data: vec![9] },
        Box::new(|ctx, status, payload| {
            assert_eq!(status, 0);
            assert_eq!(payload.data, vec![9]);
            assert!(libsmb2_dcerpc::dcerpc_get_smb2_context(ctx));
        }),
    );

    assert_eq!(libsmb2_dcerpc::dcerpc_callback_count(&dce), 1);
}

#[test]
fn test_smoke_libsmb2_dcerpc_srvsvc_safe_harnesses() {
    // Smoke source: lib/dcerpc-srvsvc.c; target: SRVSVC offline coder harnesses.
    assert_eq!(libsmb2_dcerpc_srvsvc::SRVSVC_NETRSHAREENUM, 0x0f);
    assert_eq!(libsmb2_dcerpc_srvsvc::SRVSVC_NETRSHAREGETINFO, 0x10);

    let share = libsmb2_dcerpc_srvsvc::SrvsvcShareInfo1 {
        netname: libsmb2_dcerpc_srvsvc::DcerpcUtf16 {
            value: Some("IPC$".to_string()),
        },
        share_type: libsmb2_dcerpc_srvsvc::SHARE_TYPE_IPC
            | libsmb2_dcerpc_srvsvc::SHARE_TYPE_HIDDEN,
        remark: libsmb2_dcerpc_srvsvc::DcerpcUtf16 {
            value: Some("Remote IPC".to_string()),
        },
    };

    let bytes = libsmb2_dcerpc_srvsvc::srvsvc_share_info_1_coder_harness(&share).unwrap();
    let decoded = libsmb2_dcerpc_srvsvc::srvsvc_share_info_1_decoder_harness(&bytes).unwrap();
    assert_eq!(decoded, share);

    let boundary = libsmb2_dcerpc_srvsvc::share_enum_network_boundary();
    assert!(boundary.requires_ipc_share);
    assert!(boundary.requires_smb2_transport);
    assert!(boundary.requires_dcerpc_bind);
    assert!(!boundary.safe_offline_smoke_available);
}

#[test]
fn test_smoke_errors_status_conversion() {
    // Smoke source: lib/errors.c; target: nterror conversion helpers.
    assert_eq!(
        errors::nt_error_to_str(smb2_errors::SMB2_STATUS_SUCCESS),
        "STATUS_SUCCESS"
    );
    assert_eq!(
        errors::nt_error_to_str(smb2_errors::SMB2_STATUS_INVALID_PARAMETER),
        "STATUS_INVALID_PARAMETER"
    );
    assert_eq!(errors::nt_error_to_str(0x1234_5678), "Unknown");
    assert_eq!(
        errors::nt_error_to_errno(smb2_errors::SMB2_STATUS_SUCCESS),
        0
    );
}

#[test]
fn test_smoke_hmac_md5_rfc2104_vector() {
    // Smoke source: lib/hmac-md5.c; target: RFC2104 HMAC-MD5 one-shot digest.
    let digest = hmac_md5::digest(b"Hi There", &[0x0b; 16]);
    assert_eq!(
        digest,
        [
            0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b,
            0xfc, 0x9d,
        ]
    );
}

#[test]
fn test_smoke_md4_rfc1320_vector() {
    // Smoke source: lib/md4c.c; target: MD4 one-shot wrapper.
    assert_eq!(
        md4::digest(b"abc"),
        [
            0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6,
            0x72, 0x9d,
        ]
    );
}

#[test]
fn test_smoke_md5_rfc1321_vector() {
    // Smoke source: lib/md5.c; target: MD5 one-shot wrapper.
    assert_eq!(
        md5::digest(b"abc"),
        [
            0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
            0x7f, 0x72,
        ]
    );
}

#[test]
fn test_smoke_sha1_fips180_vector() {
    // Smoke source: lib/sha1.c; target: SHA-1 one-shot wrapper.
    assert_eq!(
        sha::sha1(b"abc"),
        [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ]
    );
}

#[test]
fn test_smoke_sha224_fips180_vector() {
    // Smoke source: lib/sha224-256.c; target: SHA-224 one-shot wrapper.
    assert_eq!(
        sha::sha224(b"abc"),
        [
            0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
            0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
        ]
    );
}

#[test]
fn test_smoke_sha256_fips180_vector() {
    // Smoke source: lib/sha224-256.c; target: SHA-256 one-shot wrapper.
    assert_eq!(
        sha::sha256(b"abc"),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );
}

#[test]
fn test_smoke_sha512_fips180_vector() {
    // Smoke source: lib/sha384-512.c; target: SHA-512 one-shot wrapper.
    assert_eq!(
        sha::sha512(b"abc"),
        [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ]
    );
}

#[test]
fn test_smoke_sha384_fips180_vector() {
    // Smoke source: lib/sha384-512.c; target: SHA-384 one-shot wrapper.
    assert_eq!(
        sha::sha384(b"abc"),
        [
            0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6,
            0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a,
            0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba,
            0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
        ]
    );
}

#[test]
fn test_smoke_hmac_sha256_rfc4231_vector() {
    // Smoke source: lib/hmac.c; target: HMAC-SHA256 one-shot wrapper.
    assert_eq!(
        sha::hmac_sha256(b"Hi There", &[0x0b; 20]),
        [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ]
    );
}

#[test]
fn test_smoke_timestamps_round_trip_unix_epoch() {
    // Smoke source: lib/timestamps.c; target: SMB2/Windows timestamp conversion.
    let timeval = timestamps::Smb2Timeval {
        seconds: 0,
        microseconds: 123_456,
    };
    let windows_time = timestamps::timeval_to_windows_time(timeval);
    assert_eq!(windows_time, 116_444_736_001_234_560);
    assert_eq!(timestamps::windows_time_to_timeval(windows_time), timeval);
}

#[test]
fn test_smoke_unicode_utf8_utf16_round_trip() {
    // Smoke source: lib/unicode.c; target: UTF-8/UTF-16LE conversion ownership path.
    let utf16 = unicode::utf8_to_utf16_units("A\u{0142}").unwrap();
    assert_eq!(utf16, [0x0041, 0x0142]);
    assert_eq!(unicode::utf16_units_to_utf8(&utf16).unwrap(), "A\u{0142}");
}

#[test]
fn test_smoke_compat_resolver_vector_io_poll_and_strdup() {
    // Smoke source: lib/compat.c + lib/compat.h; target: host-buildable compat shims.
    assert_eq!(compat::CLOSE_COMPAT_TARGETS.winsock_use_winsock, "_close");
    assert_eq!(compat::CLOSE_COMPAT_TARGETS.winsock_default, "closesocket");
    assert_eq!(compat::CLOSE_COMPAT_TARGETS.amiga, "CloseSocket");
    assert_eq!(compat::CLOSE_COMPAT_TARGETS.ps2_iop, "lwip_close");
    assert_eq!(compat::SRANDOM_NON_IOP_DELEGATE, "smb2_srandom");
    assert_eq!(compat::RANDOM_NON_IOP_DELEGATE, "smb2_random");
    assert_eq!(compat::ps2_iop_random_after_seed(1), 16_838);
    assert_eq!(compat::GETPID_COMPAT_TARGETS.windows_target, "GetCurrentProcessId");
    assert_eq!(compat::GETPID_COMPAT_TARGETS.xbox_value, 0);
    assert_eq!(compat::GETPID_COMPAT_TARGETS.ps2_iop_value, 27);
    assert_eq!(compat::GETLOGIN_COMPAT_TARGETS.default_status, "ENXIO");
    assert_eq!(compat::GETLOGIN_COMPAT_TARGETS.xbox_status, 0);
    assert_eq!(compat::GETLOGIN_COMPAT_TARGETS.pico_status, 1);
    assert!(!compat::GETLOGIN_COMPAT_TARGETS.writes_buffer);

    let addrinfo = compat::resolve_ipv4_addrinfo("127.0.0.1", Some("445")).unwrap();
    assert_eq!(addrinfo.family, compat::AF_INET_FAMILY);
    assert!(addrinfo.addr_len > 0);
    assert!(addrinfo.next_is_null);
    assert_eq!(addrinfo.port, 445);
    assert_eq!(addrinfo.ipv4_addr, 0x7f00_0001);

    let (written, write_output, write_errno) = compat::writev_to_pipe(&[b"SM", b"B2"]).unwrap();
    assert_eq!(written, 4);
    assert_eq!(write_output, b"SMB2");
    assert_eq!(write_errno, 0);
    assert!(compat::writev_overflow_sets_einval());

    let (read, read_output, read_errno) = compat::readv_from_pipe(b"abcdef", &[2, 4]).unwrap();
    assert_eq!(read, 6);
    assert_eq!(read_output, b"abcdef");
    assert_eq!(read_errno, 0);
    assert!(compat::readv_overflow_sets_einval());

    let readable = compat::poll_readable_pipe().unwrap();
    assert!(readable.rc > 0);
    assert_eq!(readable.errno, 0);
    assert_eq!(
        readable.revents & compat::POLLIN_EVENT,
        compat::POLLIN_EVENT
    );
    let writable = compat::poll_writable_pipe().unwrap();
    assert!(writable.rc > 0);
    assert_eq!(writable.errno, 0);
    assert_eq!(
        writable.revents & compat::POLLOUT_EVENT,
        compat::POLLOUT_EVENT
    );

    assert_eq!(compat::strdup_matches("compat-owned").unwrap(), 12);
}
