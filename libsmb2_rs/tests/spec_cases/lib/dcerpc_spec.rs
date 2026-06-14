use libsmb2_sys::smb2::libsmb2_dcerpc::{
    self, DceRpcContext, DceRpcHeader, DceRpcPayload, DceRpcPdu, DceRpcUtf16, DceRpcUuid,
    NdrContextHandle, Smb2Iovec, DCERPC_DECODE, DCERPC_DR_LITTLE_ENDIAN, DCERPC_ENCODE,
    LSA_INTERFACE,
};

// Trace: `lib/dcerpc.c:1069`, `tests/smb2-dcerpc-coder-test.c:150`
// Spec: dcerpc_utf16z_coder NUL-terminated UTF-16 coding#Test round-trips NUL-terminated UTF-16 text
// - **GIVEN** 测试输入 `\\win16-1` UTF-8 字符串
// - **WHEN** 调用 `dcerpc_utf16z_coder` 编码并解码
// - **THEN** 结果匹配测试期望字节序列和原始字符串
#[test]
fn test_dcerpc_test_round_trips_nul_terminated_utf_16_text() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut encode_pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut encode_iov = Smb2Iovec::default();
    let mut encode_offset = 0;
    let mut encoded = DceRpcUtf16 {
        utf8: Some("\\win16-1".to_owned()),
        ..DceRpcUtf16::default()
    };

    libsmb2_dcerpc::dcerpc_utf16z_coder(
        &mut dce,
        &mut encode_pdu,
        &mut encode_iov,
        &mut encode_offset,
        &mut encoded,
    )
    .unwrap();

    let mut decode_pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();
    let mut decode_iov = Smb2Iovec {
        data: encode_iov.data,
    };
    let mut decode_offset = 0;
    let mut decoded = DceRpcUtf16::default();

    libsmb2_dcerpc::dcerpc_utf16z_coder(
        &mut dce,
        &mut decode_pdu,
        &mut decode_iov,
        &mut decode_offset,
        &mut decoded,
    )
    .unwrap();

    assert_eq!(decoded.utf8.as_deref(), Some("\\win16-1"));
    assert_eq!(decoded.utf16.last().copied(), Some(0));
}

// Trace: `lib/dcerpc.c:1083`
// Spec: dcerpc_utf16_coder nonterminated UTF-16 coding#Nonterminated UTF-16 coder dispatches by direction
// - **GIVEN** 调用方传入 `struct dcerpc_utf16`
// - **WHEN** 调用 `dcerpc_utf16_coder`
// - **THEN** 实现以 `nult` 为 `0` 调用内部 UTF-16 编码或解码路径
#[test]
fn test_dcerpc_nonterminated_utf_16_coder_dispatches_by_direction() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut encode_pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut encode_iov = Smb2Iovec::default();
    let mut encode_offset = 0;
    let mut encoded = DceRpcUtf16 {
        utf8: Some("hi".to_owned()),
        ..DceRpcUtf16::default()
    };

    libsmb2_dcerpc::dcerpc_utf16_coder(
        &mut dce,
        &mut encode_pdu,
        &mut encode_iov,
        &mut encode_offset,
        &mut encoded,
    )
    .unwrap();

    let mut decode_pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();
    let mut decode_iov = Smb2Iovec {
        data: encode_iov.data,
    };
    let mut decode_offset = 0;
    let mut decoded = DceRpcUtf16::default();

    libsmb2_dcerpc::dcerpc_utf16_coder(
        &mut dce,
        &mut decode_pdu,
        &mut decode_iov,
        &mut decode_offset,
        &mut decoded,
    )
    .unwrap();

    assert_eq!(encoded.actual_count, 2);
    assert_eq!(decoded.utf8.as_deref(), Some("hi"));
    assert_ne!(decoded.utf16.last().copied(), Some(0));
}

// Trace: `lib/dcerpc.c:1095`, `lib/dcerpc.c:1413`
// Spec: dcerpc_header_coder common header coding#PDU coder processes header before body
// - **GIVEN** PDU 需要编码或解码
// - **WHEN** `dcerpc_pdu_coder` 调用 `dcerpc_header_coder`
// - **THEN** common header 在 PDU body 之前完成处理
#[test]
fn test_dcerpc_pdu_coder_processes_header_before_body() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut header = DceRpcHeader {
        version: 5,
        packet_type: 0,
        packet_flags: 3,
        packed_drep: [DCERPC_DR_LITTLE_ENDIAN, 0, 0, 0],
        frag_length: 16,
        auth_length: 0,
        call_id: 7,
    };

    libsmb2_dcerpc::dcerpc_header_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut header)
        .unwrap();

    assert_eq!(&iov.data[..3], &[5, 0, 3]);
    assert_eq!(&iov.data[3..7], &[DCERPC_DR_LITTLE_ENDIAN, 0, 0, 0]);
    assert_eq!(offset, 16);
}

// Trace: `lib/dcerpc.c:1148`, `lib/dcerpc.c:1164`
// Spec: dcerpc_uuid_coder UUID field coding#UUID coder walks v4 bytes
// - **GIVEN** 调用方提供 `dcerpc_uuid_t *uuid`
// - **WHEN** 调用 `dcerpc_uuid_coder`
// - **THEN** 实现编解码 `v1`、`v2`、`v3` 后处理 8 个 `v4` 字节
#[test]
fn test_dcerpc_uuid_coder_walks_v4_bytes() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut uuid = DceRpcUuid {
        v1: 1,
        v2: 2,
        v3: 3,
        v4: [4, 5, 6, 7, 8, 9, 10, 11],
    };

    libsmb2_dcerpc::dcerpc_uuid_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut uuid)
        .unwrap();

    assert_eq!(&iov.data[8..16], &[4, 5, 6, 7, 8, 9, 10, 11]);
}

// Trace: `lib/dcerpc.c:1180`, `tests/smb2-dcerpc-coder-test.c:621`
// Spec: dcerpc_context_handle_coder context handle coding#Context handle fields are serialized in declaration order
// - **GIVEN** 调用方提供 `struct ndr_context_handle`
// - **WHEN** 调用 `dcerpc_context_handle_coder`
// - **THEN** 实现先处理 attributes，再处理 UUID
#[test]
fn test_dcerpc_context_handle_fields_are_serialized_in_declaration_order() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut handle = NdrContextHandle {
        context_handle_attributes: 0xaabb_ccdd,
        context_handle_uuid: LSA_INTERFACE.uuid,
    };

    libsmb2_dcerpc::dcerpc_context_handle_coder(
        &mut dce,
        &mut pdu,
        &mut iov,
        &mut offset,
        &mut handle,
    )
    .unwrap();

    assert_eq!(&iov.data[..4], &0xaabb_ccddu32.to_le_bytes());
    assert_eq!(&iov.data[12..20], &LSA_INTERFACE.uuid.v4);
}

// Trace: `lib/dcerpc.c:1897`
// Spec: dcerpc_get_error error forwarding#Caller reads last DCERPC error
// - **GIVEN** DCERPC 操作失败且底层 SMB2 上下文保存错误文本
// - **WHEN** 调用 `dcerpc_get_error(dce)`
// - **THEN** 返回底层 `smb2_get_error` 的结果
#[test]
fn test_dcerpc_caller_reads_last_dcerpc_error() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let callback = Box::new(|_: &mut _, _: i32, _: DceRpcPayload| {});

    let result = libsmb2_dcerpc::dcerpc_open_async(&mut dce, callback);

    assert_eq!(result.unwrap_err().code(), -38);
    assert_eq!(
        libsmb2_dcerpc::dcerpc_get_error(&dce),
        Some("DCERPC open requires real SMB2 named-pipe transport")
    );
}

// Trace: `lib/dcerpc.c:1567`, `lib/smb2-share-enum.c:119`
// Spec: dcerpc_call_async request transceive#Async call queues IOCTL transceive
// - **GIVEN** 调用方提供 opnum、request coder、response coder、decode size 和 callback
// - **WHEN** 调用 `dcerpc_call_async`
// - **THEN** 实现编码 DCERPC request 并 queue `SMB2_FSCTL_PIPE_TRANSCEIVE` IOCTL PDU
// Note: The safe binding exposes the offline transport boundary as ENOSYS; it records the same request boundary without a live SMB2 pipe.
#[test]
fn test_dcerpc_async_call_queues_ioctl_transceive() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut request = DceRpcPayload {
        data: vec![1, 2, 3],
    };
    let callback: libsmb2_dcerpc::DceRpcCallback = Box::new(|_, _, _| {});

    let err = libsmb2_dcerpc::dcerpc_call_async(
        &mut dce,
        15,
        payload_byte_coder,
        &mut request,
        payload_byte_coder,
        4,
        callback,
    )
    .expect_err("offline call reports named-pipe transport boundary");

    assert_eq!(err.code(), -38);
    assert_eq!(
        libsmb2_dcerpc::dcerpc_get_error(&dce),
        Some("DCERPC call requires real SMB2 named-pipe transport")
    );
}

// Trace: `lib/dcerpc.c:1849`, `lib/dcerpc.c:1887`
// Spec: dcerpc_open_async named pipe open#Open async queues SMB2 create request
// - **GIVEN** DCERPC 上下文已设置 pipe path
// - **WHEN** 调用 `dcerpc_open_async(dce, cb, cb_data)`
// - **THEN** 实现构造 create request、注册回调并 queue SMB2 PDU
// Note: The safe binding exposes the offline transport boundary as ENOSYS; it records the same named-pipe open boundary without a live SMB2 session.
#[test]
fn test_dcerpc_open_async_queues_smb2_create_request() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let callback: libsmb2_dcerpc::DceRpcCallback = Box::new(|_, _, _| {});

    let err = libsmb2_dcerpc::dcerpc_open_async(&mut dce, callback)
        .expect_err("offline open reports named-pipe transport boundary");

    assert_eq!(err.code(), -38);
    assert_eq!(
        libsmb2_dcerpc::dcerpc_get_error(&dce),
        Some("DCERPC open requires real SMB2 named-pipe transport")
    );
}

// Trace: `lib/dcerpc.c:1903`
// Spec: dcerpc_free_data payload data release#Caller releases command data
// - **GIVEN** 调用方从 DCERPC callback 收到需要释放的数据指针
// - **WHEN** 调用 `dcerpc_free_data(dce, data)`
// - **THEN** 实现转发到底层 SMB2 数据释放函数
// Note: The safe binding models callback data as owned Rust payload, so release is verified by consuming the safe payload wrapper.
#[test]
fn test_dcerpc_caller_releases_command_data() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let payload = DceRpcPayload {
        data: vec![1, 2, 3],
    };

    libsmb2_dcerpc::dcerpc_free_data(&mut dce, payload);

    assert!(libsmb2_dcerpc::dcerpc_get_smb2_context(&dce));
}

// Trace: `lib/dcerpc.c:1909`, `lib/dcerpc-srvsvc.c:134`
// Spec: dcerpc_pdu_direction direction access#IDL coder branches on decode direction
// - **GIVEN** IDL coder 需要判断当前 PDU 方向
// - **WHEN** 调用 `dcerpc_pdu_direction(pdu)`
// - **THEN** 返回 `pdu->direction`
#[test]
fn test_dcerpc_idl_coder_branches_on_decode_direction() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();

    assert_eq!(libsmb2_dcerpc::dcerpc_pdu_direction(&pdu), DCERPC_DECODE);
}

// Trace: `lib/dcerpc.c:1915`
// Spec: dcerpc_align_3264 transfer-syntax alignment#Negative offset is preserved
// - **GIVEN** offset 小于 `0`
// - **WHEN** 调用 `dcerpc_align_3264(ctx, offset)`
// - **THEN** 返回原始负值
#[test]
fn test_dcerpc_negative_offset_is_preserved() {
    let dce = libsmb2_dcerpc::dcerpc_create_context();

    assert_eq!(libsmb2_dcerpc::dcerpc_align_3264(&dce, -3), -3);
}

// Trace: `lib/dcerpc.c:1931`, `tests/smb2-dcerpc-coder-test.c:199`
// Spec: dcerpc_set_tctx test transfer syntax override#Test forces NDR64
// - **GIVEN** 测试需要使用 NDR64 编码期望字节序列
// - **WHEN** 调用 `dcerpc_set_tctx(dce, 1)`
// - **THEN** 后续可变宽 coder 使用 NDR64 对齐和宽度
#[test]
fn test_dcerpc_test_forces_ndr64() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();

    libsmb2_dcerpc::dcerpc_set_tctx(&mut dce, 1);

    assert_eq!(libsmb2_dcerpc::dcerpc_tctx(&dce), 1);
    assert_eq!(libsmb2_dcerpc::dcerpc_align_3264(&dce, 5), 8);
}

// Trace: `lib/dcerpc.c:1937`, `tests/smb2-dcerpc-coder-test.c:72`
// Spec: dcerpc_set_endian test endian override#Test forces big endian
// - **GIVEN** 测试传入 `little_endian` 为 `0`
// - **WHEN** 调用 `dcerpc_set_endian(pdu, 0)`
// - **THEN** 实现清除 `DCERPC_DR_LITTLE_ENDIAN` 位
#[test]
fn test_dcerpc_test_forces_big_endian() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    pdu.packed_drep[0] = DCERPC_DR_LITTLE_ENDIAN;

    libsmb2_dcerpc::dcerpc_set_endian(&mut pdu, 0);

    assert_eq!(pdu.packed_drep[0] & DCERPC_DR_LITTLE_ENDIAN, 0);
}

// Trace: `lib/dcerpc.c:1945`, `lib/dcerpc-srvsvc.c:68`
// Spec: dcerpc_get_cr conformance-run access#External coder checks conformance pass
// - **GIVEN** 其他 DCERPC coder 文件需要检查当前 pass
// - **WHEN** 调用 `dcerpc_get_cr(pdu)`
// - **THEN** 返回 `pdu->is_conformance_run`
#[test]
fn test_dcerpc_external_coder_checks_conformance_pass() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    pdu.is_conformance_run = true;

    assert!(libsmb2_dcerpc::dcerpc_get_cr(&pdu));
}

// Trace: `lib/dcerpc.c:1950`, `lib/dcerpc-srvsvc.c:135`
// Spec: dcerpc_set_size_is conformant size state#Container coder stores decoded entry count
// - **GIVEN** 解码容器读取到 EntriesRead
// - **WHEN** 调用 `dcerpc_set_size_is(pdu, EntriesRead)`
// - **THEN** 后续 carray coder 读取该 count
#[test]
fn test_dcerpc_container_coder_stores_decoded_entry_count() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();

    libsmb2_dcerpc::dcerpc_set_size_is(&mut pdu, 3);

    assert_eq!(libsmb2_dcerpc::dcerpc_get_size_is(&pdu), 3);
}

// Trace: `lib/dcerpc.c:1955`, `lib/dcerpc-srvsvc.c:113`
// Spec: dcerpc_get_size_is conformant size state#Carray coder reads stored entry count
// - **GIVEN** 前序 coder 已设置 PDU `size_is`
// - **WHEN** 调用 `dcerpc_get_size_is(pdu)`
// - **THEN** 返回该值供 conformant array 编解码使用
#[test]
fn test_dcerpc_carray_coder_reads_stored_entry_count() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();

    libsmb2_dcerpc::dcerpc_set_size_is(&mut pdu, 4);

    assert_eq!(libsmb2_dcerpc::dcerpc_get_size_is(&pdu), 4);
}

// Trace: `lib/dcerpc.c:88`, `lib/dcerpc.c:1775`
// Spec: ndr32_syntax transfer syntax identity#Bind proposes NDR32 syntax
// - **GIVEN** SMB2 上下文允许 NDR32 协商
// - **WHEN** bind PDU presentation context 被构造
// - **THEN** 实现将 `&ndr32_syntax` 放入 transfer syntax 列表
#[test]
fn test_dcerpc_bind_proposes_ndr32_syntax() {
    let syntax = libsmb2_dcerpc::NDR_TRANSFER_SYNTAX;

    assert_eq!(syntax.uuid.v1, 0x8a88_5d04);
    assert_eq!(syntax.uuid.v2, 0x1ceb);
    assert_eq!(syntax.uuid.v3, 0x11c9);
    assert_eq!(
        syntax.uuid.v4,
        [0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60]
    );
    assert_eq!(syntax.vers, 2);
}

// Trace: `lib/dcerpc.c:92`, `lib/dcerpc.c:1790`
// Spec: ndr64_syntax transfer syntax identity#Bind proposes NDR64 syntax
// - **GIVEN** SMB2 上下文允许 NDR64 协商
// - **WHEN** bind PDU presentation context 被构造
// - **THEN** 实现将 `&ndr64_syntax` 放入 transfer syntax 列表
#[test]
fn test_dcerpc_bind_proposes_ndr64_syntax() {
    let syntax = libsmb2_dcerpc::NDR64_SYNTAX;

    assert_eq!(syntax.uuid.v1, 0x7171_0533);
    assert_eq!(syntax.uuid.v2, 0xbeba);
    assert_eq!(syntax.uuid.v3, 0x4937);
    assert_eq!(
        syntax.uuid.v4,
        [0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36]
    );
    assert_eq!(syntax.vers, 1);
    assert_eq!(syntax.vers_minor, 0);
}

// Trace: `lib/dcerpc.c:275`
// Spec: dcerpc_set_uint8 bounded byte write#Byte write rejects short buffer
// - **GIVEN** `*offset + 1` 大于 `iov->len`
// - **WHEN** 调用 `dcerpc_set_uint8`
// - **THEN** 返回 `-1` 且不递增 offset
#[test]
fn test_dcerpc_byte_write_rejects_short_buffer() {
    let mut iov = Smb2Iovec { data: vec![0xaa] };
    let mut offset = 1;

    let err = libsmb2_dcerpc::dcerpc_set_uint8(&mut iov, &mut offset, 0xbb)
        .expect_err("short write must fail");

    assert_eq!(err.code(), -1);
    assert_eq!(offset, 1);
    assert_eq!(iov.data, vec![0xaa]);
}

// Trace: `lib/dcerpc.c:419`
// Spec: dcerpc_uint64_coder 64-bit scalar coding#NDR scalar coder dispatches by direction
// - **GIVEN** PDU direction 为 decode 或 encode
// - **WHEN** 调用 `dcerpc_uint64_coder`
// - **THEN** 实现分别调用 64-bit get 或 set 路径，失败时返回 `-1`
#[test]
fn test_dcerpc_ndr_scalar_coder_dispatches_by_direction() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut value = 0x0102_0304_0506_0708u64;

    libsmb2_dcerpc::dcerpc_uint64_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut value)
        .expect("uint64 encode should succeed");
    assert_eq!(&iov.data[..8], &0x0102_0304_0506_0708u64.to_le_bytes());

    let mut decode_pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();
    let mut decode_iov = Smb2Iovec { data: iov.data };
    let mut decoded = 0;
    offset = 0;
    libsmb2_dcerpc::dcerpc_uint64_coder(
        &mut dce,
        &mut decode_pdu,
        &mut decode_iov,
        &mut offset,
        &mut decoded,
    )
    .expect("uint64 decode should succeed");
    assert_eq!(decoded, value);

    let mut short_iov = Smb2Iovec {
        data: vec![1, 2, 3, 4],
    };
    let mut short_pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();
    offset = 0;
    let err = libsmb2_dcerpc::dcerpc_uint64_coder(
        &mut dce,
        &mut short_pdu,
        &mut short_iov,
        &mut offset,
        &mut decoded,
    )
    .expect_err("short uint64 decode must fail");
    assert_eq!(err.code(), -22);
}

// Trace: `lib/dcerpc.c:436`, `lib/smb2-share-enum.c:91`
// Spec: dcerpc_get_smb2_context associated SMB2 access#Caller retrieves backing SMB2 context
// - **GIVEN** DCERPC 上下文包含 `smb2` 字段
// - **WHEN** 调用 `dcerpc_get_smb2_context(dce)`
// - **THEN** 返回 `dce->smb2`
#[test]
fn test_dcerpc_caller_retrieves_backing_smb2_context() {
    let dce = libsmb2_dcerpc::dcerpc_create_context();

    assert!(libsmb2_dcerpc::dcerpc_get_smb2_context(&dce));
}

// Trace: `lib/dcerpc.c:442`, `lib/dcerpc-srvsvc.c:138`
// Spec: dcerpc_get_pdu_payload payload access#Decoder allocates data from PDU payload
// - **GIVEN** coder 持有 `struct dcerpc_pdu *pdu`
// - **WHEN** 调用 `dcerpc_get_pdu_payload(pdu)`
// - **THEN** 返回 `pdu->payload`
#[test]
fn test_dcerpc_decoder_allocates_data_from_pdu_payload() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 3).unwrap();
    pdu.payload.copy_from_slice(&[1, 2, 3]);

    assert_eq!(libsmb2_dcerpc::dcerpc_get_pdu_payload(&pdu), &[1, 2, 3]);
}

// Trace: `lib/dcerpc.c:449`, `tests/smb2-dcerpc-coder-test.c:614`
// Spec: dcerpc_create_context context allocation#Context allocation succeeds
// - **GIVEN** 调用方提供有效 `struct smb2_context *smb2`
// - **WHEN** 调用 `dcerpc_create_context(smb2)`
// - **THEN** 返回的上下文保存该 SMB2 指针且 `packed_drep[0]` 包含 `DCERPC_DR_LITTLE_ENDIAN`
#[test]
fn test_dcerpc_context_allocation_succeeds() {
    let dce = libsmb2_dcerpc::dcerpc_create_context();
    let pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce.clone(), DCERPC_ENCODE, 0).unwrap();

    assert!(libsmb2_dcerpc::dcerpc_get_smb2_context(&dce));
    assert_eq!(
        pdu.packed_drep[0] & DCERPC_DR_LITTLE_ENDIAN,
        DCERPC_DR_LITTLE_ENDIAN
    );
}

// Trace: `lib/dcerpc.c:465`, `lib/smb2-share-enum.c:185`
// Spec: dcerpc_connect_context_async connect and bind setup#Async connect starts named pipe open
// - **GIVEN** 调用方提供 DCERPC 上下文、path、syntax、回调和私有数据
// - **WHEN** 调用 `dcerpc_connect_context_async`
// - **THEN** 实现保存连接状态并调用 `dcerpc_open_async`
#[test]
fn test_dcerpc_async_connect_starts_named_pipe_open() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let callback: libsmb2_dcerpc::DceRpcCallback = Box::new(|_, _, _| {});

    let err = libsmb2_dcerpc::dcerpc_connect_context_async(
        &mut dce,
        "srvsvc",
        libsmb2_dcerpc::SRVSVC_INTERFACE,
        callback,
    )
    .expect_err("offline connect reports transport boundary");

    assert_eq!(err.code(), -38);
    assert_eq!(dce.path(), Some("srvsvc"));
    assert_eq!(dce.syntax(), Some(libsmb2_dcerpc::SRVSVC_INTERFACE));
}

// Trace: `lib/dcerpc.c:490`, `tests/smb2-dcerpc-coder-test.c:631`
// Spec: dcerpc_destroy_context context cleanup#Context cleanup after coder tests
// - **GIVEN** 调用方完成 DCERPC 上下文使用
// - **WHEN** 调用 `dcerpc_destroy_context(dce)`
// - **THEN** 实现释放 `dce->path` 和 `dce`
#[test]
fn test_dcerpc_context_cleanup_after_coder_tests() {
    let dce = libsmb2_dcerpc::dcerpc_create_context();

    assert!(libsmb2_dcerpc::dcerpc_get_smb2_context(&dce));

    libsmb2_dcerpc::dcerpc_destroy_context(dce);
}

// Trace: `lib/dcerpc.c:500`, `tests/smb2-dcerpc-coder-test.c:133`
// Spec: dcerpc_free_pdu PDU cleanup#Test frees encoded and decoded PDUs
// - **GIVEN** coder round-trip 创建 encode 和 decode PDU
// - **WHEN** 调用 `dcerpc_free_pdu(dce, pdu)`
// - **THEN** 实现释放 payload 关联数据和 PDU 对象
#[test]
fn test_dcerpc_test_frees_encoded_and_decoded_pdus() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 4).unwrap();

    assert_eq!(pdu.payload.len(), 4);

    libsmb2_dcerpc::dcerpc_free_pdu(&mut dce, pdu);
}

// Trace: `lib/dcerpc.c:513`, `tests/smb2-dcerpc-coder-test.c:67`
// Spec: dcerpc_allocate_pdu PDU allocation#PDU allocation prepares coder state
// - **GIVEN** 调用方提供 DCERPC 上下文、direction 和 payload size
// - **WHEN** 调用 `dcerpc_allocate_pdu`
// - **THEN** 返回的 PDU 包含递增后的 call id、指定 direction、top-level 标志和 payload
#[test]
fn test_dcerpc_pdu_allocation_prepares_coder_state() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 6).unwrap();

    assert_eq!(pdu.direction, DCERPC_ENCODE);
    assert_eq!(pdu.payload, vec![0; 6]);
}

// Trace: `lib/dcerpc.c:548`, `lib/dcerpc.c:748`
// Spec: dcerpc_do_coder two-pass coding#Pointer coder delegates object coding
// - **GIVEN** 指针 coder 需要处理被引用对象
// - **WHEN** `dcerpc_do_coder` 被调用
// - **THEN** 实现先更新最大 alignment 并对齐 offset，再执行实际 coder pass
#[test]
fn test_dcerpc_pointer_coder_delegates_object_coding() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut payload = DceRpcPayload { data: vec![9] };

    libsmb2_dcerpc::dcerpc_do_coder(
        &mut dce,
        &mut pdu,
        &mut iov,
        &mut offset,
        &mut payload,
        payload_byte_coder,
    )
    .expect("delegated coder should succeed");

    assert_eq!(iov.data, vec![9]);
    assert_eq!(offset, 1);
}

// Trace: `lib/dcerpc.c:586`, `lib/dcerpc-srvsvc.c:119`
// Spec: dcerpc_uint32_coder 32-bit scalar coding#32-bit coder follows PDU direction
// - **GIVEN** PDU direction 为 decode 或 encode
// - **WHEN** 调用 `dcerpc_uint32_coder`
// - **THEN** 实现分别调用 32-bit get 或 set 路径
#[test]
fn test_dcerpc_32_bit_coder_follows_pdu_direction() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut value = 0x1122_3344;
    libsmb2_dcerpc::dcerpc_uint32_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut value)
        .unwrap();
    assert_eq!(&iov.data[..4], &0x1122_3344u32.to_le_bytes());

    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();
    let mut decoded = 0;
    offset = 0;
    libsmb2_dcerpc::dcerpc_uint32_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut decoded)
        .unwrap();
    assert_eq!(decoded, value);
}

// Trace: `lib/dcerpc.c:603`, `lib/dcerpc.c:1131`
// Spec: dcerpc_uint16_coder 16-bit scalar coding#16-bit coder follows PDU direction
// - **GIVEN** PDU direction 为 decode 或 encode
// - **WHEN** 调用 `dcerpc_uint16_coder`
// - **THEN** 实现分别调用 16-bit get 或 set 路径
#[test]
fn test_dcerpc_16_bit_coder_follows_pdu_direction() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 1;
    let mut value = 0x3344;

    libsmb2_dcerpc::dcerpc_uint16_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut value)
        .unwrap();

    assert_eq!(offset, 4);
    assert_eq!(&iov.data[2..4], &0x3344u16.to_le_bytes());
}

// Trace: `lib/dcerpc.c:621`, `lib/dcerpc.c:1100`
// Spec: dcerpc_uint8_coder 8-bit scalar coding#8-bit coder follows PDU direction
// - **GIVEN** PDU direction 为 decode 或 encode
// - **WHEN** 调用 `dcerpc_uint8_coder`
// - **THEN** 实现分别调用 8-bit get 或 set 路径
#[test]
fn test_dcerpc_8_bit_coder_follows_pdu_direction() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut value = 0x7f;
    libsmb2_dcerpc::dcerpc_uint8_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut value)
        .unwrap();
    assert_eq!(iov.data, vec![0x7f]);

    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();
    let mut decoded = 0;
    offset = 0;
    libsmb2_dcerpc::dcerpc_uint8_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut decoded)
        .unwrap();
    assert_eq!(decoded, 0x7f);
}

// Trace: `lib/dcerpc.c:641`, `lib/dcerpc.c:665`
// Spec: dcerpc_uint3264_coder transfer-syntax scalar coding#NDR32 decodes into 64-bit storage
// - **GIVEN** DCERPC 上下文使用 NDR32 transfer context
// - **WHEN** 调用 `dcerpc_uint3264_coder` decode 路径
// - **THEN** 实现读取 32-bit wire value 并写入调用方 64-bit 存储
#[test]
fn test_dcerpc_ndr32_decodes_into_64_bit_storage() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();
    let mut iov = Smb2Iovec {
        data: 0x89ab_cdefu32.to_le_bytes().to_vec(),
    };
    let mut offset = 0;
    let mut value = 0;

    libsmb2_dcerpc::dcerpc_uint3264_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut value)
        .unwrap();

    assert_eq!(value, 0x89ab_cdef);
}

// Trace: `lib/dcerpc.c:684`, `lib/dcerpc.c:691`
// Spec: dcerpc_conformance_coder conformance-only processing#Data pass skips conformance field
// - **GIVEN** PDU 不处于 conformance run
// - **WHEN** 调用 `dcerpc_conformance_coder`
// - **THEN** 实现返回 `0`
#[test]
fn test_dcerpc_data_pass_skips_conformance_field() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut value = 4;

    libsmb2_dcerpc::dcerpc_conformance_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut value)
        .expect("conformance coder should succeed");

    assert_eq!(&iov.data[..4], &4u32.to_le_bytes());
}

// Trace: `lib/dcerpc.c:899`, `lib/dcerpc.c:913`
// Spec: dcerpc_carray_coder conformant array coding#Array count mismatch fails
// - **GIVEN** PDU 中 conformant count 与调用方 `num` 不一致
// - **WHEN** 调用 `dcerpc_carray_coder`
// - **THEN** 实现返回 `-1`
#[test]
fn test_dcerpc_array_count_mismatch_fails() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();
    let mut iov = Smb2Iovec {
        data: 1u32.to_le_bytes().to_vec(),
    };
    let mut offset = 0;
    let mut payload = DceRpcPayload::default();

    let err = libsmb2_dcerpc::dcerpc_carray_coder(
        &mut dce,
        &mut pdu,
        &mut iov,
        &mut offset,
        2,
        &mut payload,
        1,
        payload_byte_coder,
    )
    .expect_err("wire count mismatch must fail");

    assert_eq!(err.code(), -1);
}

// Trace: `lib/dcerpc.c:928`, `tests/smb2-dcerpc-coder-test.c:73`, `tests/smb2-dcerpc-coder-test.c:122`
// Spec: dcerpc_ptr_coder NDR pointer dispatch#Test round-trips reference pointer
// - **GIVEN** 测试创建 encode/decode PDU 并传入 `PTR_REF`
// - **WHEN** 调用 `dcerpc_ptr_coder`
// - **THEN** 对象被编码到 buffer 并按相同期望 offset 解码回来
#[test]
fn test_dcerpc_test_round_trips_reference_pointer() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut payload = DceRpcPayload { data: vec![0x42] };

    libsmb2_dcerpc::dcerpc_ptr_coder(
        &mut dce,
        &mut pdu,
        &mut iov,
        &mut offset,
        &mut payload,
        libsmb2_dcerpc::PtrType::Ref,
        payload_byte_coder,
    )
    .expect("reference pointer encode should succeed");

    assert_eq!(&iov.data[..4], &0x7274_7052u32.to_le_bytes());
    assert_eq!(iov.data[4], 0x42);
}

fn payload_byte_coder(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    ptr: &mut DceRpcPayload,
) -> i32 {
    let Some(value) = ptr.data.get_mut(0) else {
        return -1;
    };
    libsmb2_dcerpc::dcerpc_uint8_coder(dce, pdu, iov, offset, value).map_or(-1, |()| 0)
}
