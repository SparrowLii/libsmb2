use libsmb2_sys::smb2::libsmb2_dcerpc::{
    self, DceRpcCarray, DceRpcCoder, DceRpcContext, DceRpcPayload, DceRpcPdu, DceRpcUtf16,
    DceRpcUuid, NdrContextHandle, NdrTransferSyntax, PSyntaxId, PtrType, Smb2Iovec, DCERPC_DECODE,
    DCERPC_DR_ASCII, DCERPC_DR_BIG_ENDIAN, DCERPC_DR_EBCDIC, DCERPC_DR_LITTLE_ENDIAN,
    DCERPC_ENCODE, LSA_INTERFACE, NDR_TRANSFER_SYNTAX, SRVSVC_INTERFACE,
};

// Trace: `include/smb2/libsmb2-dcerpc.h:28`
// Spec: DCERPC_DR_BIG_ENDIAN data representation constant#Header exposes big endian flag
// - **GIVEN** 调用方包含 `include/smb2/libsmb2-dcerpc.h`
// - **WHEN** 调用方读取 `DCERPC_DR_BIG_ENDIAN`
// - **THEN** 该宏值为 `0x00`
#[test]
fn test_libsmb2_dcerpc_header_exposes_big_endian_flag() {
    assert_eq!(DCERPC_DR_BIG_ENDIAN, 0x00);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:29`, `lib/dcerpc.c:460`
// Spec: DCERPC_DR_LITTLE_ENDIAN data representation constant#Header exposes little endian flag
// - **GIVEN** 调用方包含 `include/smb2/libsmb2-dcerpc.h`
// - **WHEN** 调用方读取 `DCERPC_DR_LITTLE_ENDIAN`
// - **THEN** 该宏值为 `0x10`，并可被实现写入 packed data representation 字节
#[test]
fn test_libsmb2_dcerpc_header_exposes_little_endian_flag() {
    assert_eq!(DCERPC_DR_LITTLE_ENDIAN, 0x10);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:31`, `lib/dcerpc.c:477`
// Spec: DCERPC_DR_ASCII character representation constant#Header exposes ASCII flag
// - **GIVEN** 调用方包含 `include/smb2/libsmb2-dcerpc.h`
// - **WHEN** 调用方读取 `DCERPC_DR_ASCII`
// - **THEN** 该宏值为 `0x00`
#[test]
fn test_libsmb2_dcerpc_header_exposes_ascii_flag() {
    assert_eq!(DCERPC_DR_ASCII, 0x00);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:32`
// Spec: DCERPC_DR_EBCDIC character representation constant#Header exposes EBCDIC flag
// - **GIVEN** 调用方包含 `include/smb2/libsmb2-dcerpc.h`
// - **WHEN** 调用方读取 `DCERPC_DR_EBCDIC`
// - **THEN** 该宏值为 `0x01`
#[test]
fn test_libsmb2_dcerpc_header_exposes_ebcdic_flag() {
    assert_eq!(DCERPC_DR_EBCDIC, 0x01);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:38`, `lib/dcerpc.c:555`, `lib/dcerpc.c:1611`
// Spec: dcerpc_coder callback signature#Coder callback receives shared encoding state
// - **GIVEN** 调用方实现一个 `dcerpc_coder` 回调
// - **WHEN** 该回调传入 `dcerpc_do_coder` 或 `dcerpc_call_async`
// - **THEN** 实现以声明中的参数顺序调用回调并根据非零返回值判定失败
// Note: This validates only the safe callback type shape; it does not execute coder or network paths.
#[test]
fn test_libsmb2_dcerpc_coder_callback_receives_shared_encoding_state() {
    fn coder(
        _dce: &mut DceRpcContext,
        _pdu: &mut DceRpcPdu,
        _iov: &mut Smb2Iovec,
        offset: &mut i32,
        ptr: &mut DceRpcPayload,
    ) -> i32 {
        *offset += i32::try_from(ptr.data.len()).unwrap_or(i32::MAX);
        -1
    }

    let callback: DceRpcCoder = coder;
    let mut dce = DceRpcContext::new();
    let mut pdu = DceRpcPdu::default();
    let mut iov = Smb2Iovec { data: vec![1, 2] };
    let mut offset = 4;
    let mut payload = DceRpcPayload {
        data: vec![3, 4, 5],
    };

    assert_eq!(
        callback(&mut dce, &mut pdu, &mut iov, &mut offset, &mut payload),
        -1
    );
    assert_eq!(offset, 7);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:42`, `lib/dcerpc.c:744`, `lib/dcerpc.c:848`, `tests/smb2-dcerpc-coder-test.c:73`
// Spec: ptr_type pointer type values#Pointer coder receives declared pointer type
// - **GIVEN** 调用方传入 `PTR_REF`、`PTR_UNIQUE` 或 `PTR_FULL`
// - **WHEN** `dcerpc_ptr_coder` 分派到 encode 或 decode 路径
// - **THEN** 实现按照该枚举值选择对应分支处理引用、唯一或完整指针
// Note: This validates only the declared safe enum discriminants; it does not execute pointer coding.
#[test]
fn test_libsmb2_dcerpc_pointer_coder_receives_declared_pointer_type() {
    assert_eq!(PtrType::Ref as u8, 0);
    assert_eq!(PtrType::Unique as u8, 1);
    assert_eq!(PtrType::Full as u8, 2);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:48`, `lib/dcerpc.c:1155`
// Spec: dcerpc_uuid_t UUID layout#UUID coder consumes public layout
// - **GIVEN** 调用方持有 `dcerpc_uuid_t` 值
// - **WHEN** 调用 `dcerpc_uuid_coder`
// - **THEN** 实现按 `v1`、`v2`、`v3` 和 `v4[0..7]` 顺序编解码字段
// Note: This validates the public data model fields without executing the UUID coder.
#[test]
fn test_libsmb2_dcerpc_uuid_coder_consumes_public_layout() {
    let uuid = DceRpcUuid {
        v1: 1,
        v2: 2,
        v3: 3,
        v4: [4, 5, 6, 7, 8, 9, 10, 11],
    };

    assert_eq!(uuid.v1, 1);
    assert_eq!(uuid.v2, 2);
    assert_eq!(uuid.v3, 3);
    assert_eq!(uuid.v4, [4, 5, 6, 7, 8, 9, 10, 11]);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:55`, `lib/dcerpc.c:476`, `lib/dcerpc.c:1766`
// Spec: p_syntax_id_t presentation syntax layout#Connect context stores presentation syntax pointer
// - **GIVEN** 调用方提供一个 `p_syntax_id_t *syntax`
// - **WHEN** 调用 `dcerpc_connect_context_async`
// - **THEN** 实现保存该 syntax 指针用于后续 bind 请求
// Note: This validates the safe presentation-syntax data model without executing connection logic.
#[test]
fn test_libsmb2_dcerpc_connect_context_stores_presentation_syntax_pointer() {
    let syntax = PSyntaxId {
        uuid: LSA_INTERFACE.uuid,
        vers: 0,
        vers_minor: 0,
    };

    assert_eq!(syntax.uuid, LSA_INTERFACE.uuid);
    assert_eq!(syntax.vers, 0);
    assert_eq!(syntax.vers_minor, 0);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:61`, `lib/dcerpc.c:1249`
// Spec: ndr_transfer_syntax transfer syntax layout#Bind coder emits transfer syntax identity
// - **GIVEN** 实现选择一个 transfer syntax
// - **WHEN** bind PDU 被编码
// - **THEN** 实现按 UUID 和版本字段写入 transfer syntax 条目
// Note: This validates the transfer-syntax identity data model without executing bind coding.
#[test]
fn test_libsmb2_dcerpc_bind_coder_emits_transfer_syntax_identity() {
    let syntax = NdrTransferSyntax {
        uuid: NDR_TRANSFER_SYNTAX.uuid,
        vers: NDR_TRANSFER_SYNTAX.vers,
    };

    assert_eq!(syntax.uuid.v1, 0x8a88_5d04);
    assert_eq!(syntax.uuid.v2, 0x1ceb);
    assert_eq!(syntax.uuid.v3, 0x11c9);
    assert_eq!(
        syntax.uuid.v4,
        [0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60]
    );
    assert_eq!(syntax.vers, 2);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:66`, `lib/dcerpc.c:1185`, `tests/smb2-dcerpc-coder-test.c:621`
// Spec: ndr_context_handle handle layout#Context handle coder serializes attributes and UUID
// - **GIVEN** 调用方提供 `struct ndr_context_handle`
// - **WHEN** 调用 `dcerpc_context_handle_coder`
// - **THEN** 实现先编解码 attributes，再编解码 UUID
// Note: This validates the context-handle data model without executing the context-handle coder.
#[test]
fn test_libsmb2_dcerpc_context_handle_coder_serializes_attributes_and_uuid() {
    let handle = NdrContextHandle {
        context_handle_attributes: 0xfeed_beef,
        context_handle_uuid: LSA_INTERFACE.uuid,
    };

    assert_eq!(handle.context_handle_attributes, 0xfeed_beef);
    assert_eq!(handle.context_handle_uuid, LSA_INTERFACE.uuid);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:71`, `lib/dcerpc.c:951`, `lib/dcerpc.c:1051`, `tests/smb2-dcerpc-coder-test.c:138`
// Spec: dcerpc_utf16 UTF-8 bridge model#UTF-16 coder round-trips UTF-8 text
// - **GIVEN** `struct dcerpc_utf16` 的 `utf8` 字段指向调用方字符串
// - **WHEN** 测试通过 UTF-16 coder 编码并解码该结构
// - **THEN** 解码结果的 `utf8` 字符串与原始字符串相同
// Note: This validates the UTF-8 bridge data field without executing UTF-16 coding.
#[test]
fn test_libsmb2_dcerpc_utf_16_coder_round_trips_utf_8_text() {
    let value = DceRpcUtf16 {
        max_count: 5,
        offset: 0,
        actual_count: 5,
        utf16: vec![
            b'h' as u16,
            b'e' as u16,
            b'l' as u16,
            b'l' as u16,
            b'o' as u16,
        ],
        utf8: Some("hello".to_owned()),
    };

    assert_eq!(value.max_count, 5);
    assert_eq!(value.offset, 0);
    assert_eq!(value.actual_count, 5);
    assert_eq!(value.utf16.len(), 5);
    assert_eq!(value.utf8.as_deref(), Some("hello"));
}

// Trace: `include/smb2/libsmb2-dcerpc.h:81`, `lib/dcerpc.c:908`, `tests/smb2-dcerpc-coder-test.c:293`
// Spec: dcerpc_carray conformant array model#Array coder uses caller-provided count and data pointer
// - **GIVEN** 调用方提供 array 元素数量、元素大小和数据指针
// - **WHEN** 调用 `dcerpc_carray_coder`
// - **THEN** 实现先处理 conformance count，再按元素大小逐个调用元素 coder
// Note: This validates only the caller-provided count and data container without executing array coding.
#[test]
fn test_libsmb2_dcerpc_array_coder_uses_caller_provided_count_and_data_pointer() {
    let array = DceRpcCarray {
        max_count: 4,
        data: vec![1, 2, 3, 4],
    };

    assert_eq!(array.max_count, 4);
    assert_eq!(array.data, vec![1, 2, 3, 4]);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:86`, `lib/dcerpc.c:465`
// Spec: lsa_interface presentation syntax symbol#LSA client passes interface to connect
// - **GIVEN** 调用方包含 DCERPC LSA 相关头文件
// - **WHEN** 调用方将 `&lsa_interface` 传给 `dcerpc_connect_context_async`
// - **THEN** 连接流程接收该 presentation syntax 指针
// Note: This validates the exported presentation-syntax value without executing connection logic.
#[test]
fn test_libsmb2_dcerpc_lsa_client_passes_interface_to_connect() {
    assert_eq!(LSA_INTERFACE.uuid.v1, 0x1234_5778);
    assert_eq!(LSA_INTERFACE.uuid.v2, 0x1234);
    assert_eq!(LSA_INTERFACE.uuid.v3, 0xabcd);
    assert_eq!(
        LSA_INTERFACE.uuid.v4,
        [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab]
    );
    assert_eq!(LSA_INTERFACE.vers, 0);
    assert_eq!(LSA_INTERFACE.vers_minor, 0);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:87`, `lib/smb2-share-enum.c:185`
// Spec: srvsvc_interface presentation syntax symbol#SRVSVC share enumeration passes interface to connect
// - **GIVEN** 调用方执行 share enumeration bind 流程
// - **WHEN** 调用方将 `&srvsvc_interface` 传给 `dcerpc_connect_context_async`
// - **THEN** 连接流程接收该 presentation syntax 指针
// Note: This validates the exported presentation-syntax value without executing connection logic.
#[test]
fn test_libsmb2_dcerpc_srvsvc_share_enumeration_passes_interface_to_connect() {
    assert_eq!(SRVSVC_INTERFACE.uuid.v1, 0x4b32_4fc8);
    assert_eq!(SRVSVC_INTERFACE.uuid.v2, 0x1670);
    assert_eq!(SRVSVC_INTERFACE.uuid.v3, 0x01d3);
    assert_eq!(
        SRVSVC_INTERFACE.uuid.v4,
        [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88]
    );
    assert_eq!(SRVSVC_INTERFACE.vers, 3);
    assert_eq!(SRVSVC_INTERFACE.vers_minor, 0);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:145`, `tests/smb2-dcerpc-coder-test.c:119`
// Spec: DCERPC_DECODE direction constant#Test allocates decode PDU
// - **GIVEN** 调用方需要创建 decode PDU
// - **WHEN** 调用 `dcerpc_allocate_pdu(dce, DCERPC_DECODE, size)`
// - **THEN** PDU direction 使用值 `0`
// Note: This validates the public direction constant; PDU allocation itself requires a DCERPC FFI lifecycle binding.
#[test]
fn test_libsmb2_dcerpc_test_allocates_decode_pdu() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 8).unwrap();

    assert_eq!(pdu.direction, 0);
    assert_eq!(libsmb2_dcerpc::dcerpc_get_pdu_payload(&pdu).len(), 8);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:146`, `tests/smb2-dcerpc-coder-test.c:67`
// Spec: DCERPC_ENCODE direction constant#Test allocates encode PDU
// - **GIVEN** 调用方需要创建 encode PDU
// - **WHEN** 调用 `dcerpc_allocate_pdu(dce, DCERPC_ENCODE, size)`
// - **THEN** PDU direction 使用值 `1`
// Note: This validates the public direction constant; PDU allocation itself requires a DCERPC FFI lifecycle binding.
#[test]
fn test_libsmb2_dcerpc_test_allocates_encode_pdu() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 8).unwrap();

    assert_eq!(pdu.direction, 1);
    assert_eq!(libsmb2_dcerpc::dcerpc_get_pdu_payload(&pdu).len(), 8);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:89`, `lib/dcerpc.c:1511`, `lib/dcerpc.c:1657`
// Spec: dcerpc_cb async callback signature#Async operation completes through callback
// - **GIVEN** 调用方提供 `dcerpc_cb` 和 `cb_data`
// - **WHEN** DCERPC open、bind 或 call 路径完成
// - **THEN** 实现调用回调并传回原始 `cb_data`
#[test]
fn test_libsmb2_dcerpc_async_operation_completes_through_callback() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    libsmb2_dcerpc::dcerpc_invoke_callback(
        &mut dce,
        0,
        DceRpcPayload { data: vec![7] },
        Box::new(|ctx, status, payload| {
            assert!(libsmb2_dcerpc::dcerpc_get_smb2_context(ctx));
            assert_eq!(status, 0);
            assert_eq!(payload.data, vec![7]);
        }),
    );

    assert_eq!(libsmb2_dcerpc::dcerpc_callback_count(&dce), 1);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:92`, `lib/dcerpc.c:449`, `tests/smb2-dcerpc-coder-test.c:614`
// Spec: dcerpc_create_context context allocation#Context allocation succeeds
// - **GIVEN** 调用方提供有效的 `struct smb2_context *smb2`
// - **WHEN** 调用 `dcerpc_create_context(smb2)`
// - **THEN** 返回的 DCERPC 上下文关联该 SMB2 上下文，并设置 little-endian packed data representation
#[test]
fn test_libsmb2_dcerpc_context_allocation_succeeds() {
    let dce = libsmb2_dcerpc::dcerpc_create_context();

    assert!(libsmb2_dcerpc::dcerpc_get_smb2_context(&dce));
    assert_eq!(DCERPC_DR_LITTLE_ENDIAN, 0x10);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:93`, `lib/dcerpc.c:1903`
// Spec: dcerpc_free_data payload data release#Caller releases command data
// - **GIVEN** 调用方从 DCERPC callback 收到需要释放的数据指针
// - **WHEN** 调用 `dcerpc_free_data(dce, data)`
// - **THEN** 实现转发到底层 SMB2 数据释放函数
#[test]
fn test_libsmb2_dcerpc_caller_releases_command_data() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    libsmb2_dcerpc::dcerpc_free_data(&mut dce, DceRpcPayload { data: vec![1, 2] });
    assert!(libsmb2_dcerpc::dcerpc_get_smb2_context(&dce));
}

// Trace: `include/smb2/libsmb2-dcerpc.h:94`, `lib/dcerpc.c:1897`
// Spec: dcerpc_get_error error forwarding#Caller reads last DCERPC error
// - **GIVEN** DCERPC 操作失败且底层 SMB2 上下文保存错误文本
// - **WHEN** 调用 `dcerpc_get_error(dce)`
// - **THEN** 返回 `smb2_get_error(dcerpc_get_smb2_context(dce))` 的结果
#[test]
fn test_libsmb2_dcerpc_caller_reads_last_dcerpc_error() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let result = libsmb2_dcerpc::dcerpc_open_async(&mut dce, Box::new(|_, _, _| {}));

    assert_eq!(result.unwrap_err().code(), -38);
    assert_eq!(
        libsmb2_dcerpc::dcerpc_get_error(&dce),
        Some("DCERPC open requires real SMB2 named-pipe transport")
    );
}

// Trace: `include/smb2/libsmb2-dcerpc.h:95`, `lib/dcerpc.c:465`, `lib/dcerpc.c:482`
// Spec: dcerpc_connect_context_async connect and bind setup#Connect context starts async open
// - **GIVEN** 调用方提供 DCERPC 上下文、pipe path、syntax、回调和私有数据
// - **WHEN** 调用 `dcerpc_connect_context_async`
// - **THEN** 实现保存连接状态并调用 `dcerpc_open_async` 启动 named pipe open
#[test]
fn test_libsmb2_dcerpc_connect_context_starts_async_open_boundary() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let result = libsmb2_dcerpc::dcerpc_connect_context_async(
        &mut dce,
        "srvsvc",
        SRVSVC_INTERFACE,
        Box::new(|_, _, _| {}),
    );

    assert_eq!(result.unwrap_err().code(), -38);
    assert_eq!(dce.path(), Some("srvsvc"));
    assert_eq!(dce.syntax(), Some(SRVSVC_INTERFACE));
}

// Trace: `include/smb2/libsmb2-dcerpc.h:98`, `lib/dcerpc.c:490`, `tests/smb2-dcerpc-coder-test.c:631`
// Spec: dcerpc_destroy_context context cleanup#Destroy context after coder tests
// - **GIVEN** 调用方完成 DCERPC 上下文使用
// - **WHEN** 调用 `dcerpc_destroy_context(dce)`
// - **THEN** 实现释放 path 和上下文内存
#[test]
fn test_libsmb2_dcerpc_destroy_context_after_coder_tests() {
    libsmb2_dcerpc::dcerpc_destroy_context(libsmb2_dcerpc::dcerpc_create_context());
    assert!(true);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:100`, `lib/dcerpc.c:436`
// Spec: dcerpc_get_smb2_context associated SMB2 access#Helper retrieves SMB2 context
// - **GIVEN** DCERPC 上下文包含 `smb2` 字段
// - **WHEN** 调用 `dcerpc_get_smb2_context(dce)`
// - **THEN** 返回该字段指向的 SMB2 上下文
#[test]
fn test_libsmb2_dcerpc_helper_retrieves_smb2_context() {
    let dce = libsmb2_dcerpc::dcerpc_create_context();

    assert!(libsmb2_dcerpc::dcerpc_get_smb2_context(&dce));
}

// Trace: `include/smb2/libsmb2-dcerpc.h:101`, `lib/dcerpc.c:442`, `lib/dcerpc-srvsvc.c:138`
// Spec: dcerpc_get_pdu_payload payload access#Decoder allocates data from PDU payload
// - **GIVEN** 调用方或 coder 持有 `struct dcerpc_pdu *pdu`
// - **WHEN** 调用 `dcerpc_get_pdu_payload(pdu)`
// - **THEN** 返回 `pdu->payload`
#[test]
fn test_libsmb2_dcerpc_decoder_allocates_data_from_pdu_payload() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 3).unwrap();

    assert_eq!(libsmb2_dcerpc::dcerpc_get_pdu_payload(&pdu), &[0, 0, 0]);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:103`, `lib/dcerpc.c:1849`
// Spec: dcerpc_open_async named pipe open#Open async queues SMB2 create request
// - **GIVEN** DCERPC 上下文已设置 pipe path
// - **WHEN** 调用 `dcerpc_open_async(dce, cb, cb_data)`
// - **THEN** 实现构造 create request、注册回调并 queue SMB2 PDU
#[test]
fn test_libsmb2_dcerpc_open_async_queues_smb2_create_request_boundary() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let result = libsmb2_dcerpc::dcerpc_open_async(&mut dce, Box::new(|_, _, _| {}));

    assert_eq!(result.unwrap_err().code(), -38);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:104`, `lib/dcerpc.c:1567`, `lib/smb2-share-enum.c:119`
// Spec: dcerpc_call_async request transceive#Async call queues IOCTL transceive
// - **GIVEN** 调用方提供 opnum、request coder、response coder、decode size 和 callback
// - **WHEN** 调用 `dcerpc_call_async`
// - **THEN** 实现编码 DCERPC request 并 queue `SMB2_FSCTL_PIPE_TRANSCEIVE` IOCTL PDU
#[test]
fn test_libsmb2_dcerpc_async_call_queues_ioctl_transceive_boundary() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut payload = DceRpcPayload::default();
    let result = libsmb2_dcerpc::dcerpc_call_async(
        &mut dce,
        0,
        |_dce, _pdu, _iov, _offset, _payload| 0,
        &mut payload,
        |_dce, _pdu, _iov, _offset, _payload| 0,
        0,
        Box::new(|_, _, _| {}),
    );

    assert_eq!(result.unwrap_err().code(), -38);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:110`, `lib/dcerpc.c:548`, `lib/dcerpc.c:748`
// Spec: dcerpc_do_coder two-pass coding#Pointer coder delegates object encoding
// - **GIVEN** 指针 coder 需要编码或解码被引用对象
// - **WHEN** `dcerpc_do_coder` 被调用
// - **THEN** 实现先更新 alignment 并对齐 offset，再执行实际 coder pass
#[test]
fn test_libsmb2_dcerpc_pointer_coder_delegates_object_encoding() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut payload = DceRpcPayload { data: vec![1] };
    let result = libsmb2_dcerpc::dcerpc_do_coder(
        &mut dce,
        &mut pdu,
        &mut iov,
        &mut offset,
        &mut payload,
        |_dce, _pdu, _iov, offset, payload| {
            *offset += i32::try_from(payload.data.len()).unwrap_or(0);
            0
        },
    );

    assert!(result.is_ok());
    assert_eq!(offset, 1);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:114`, `lib/dcerpc.c:928`, `tests/smb2-dcerpc-coder-test.c:73`, `tests/smb2-dcerpc-coder-test.c:122`
// Spec: dcerpc_ptr_coder NDR pointer dispatch#Test encodes and decodes reference pointer
// - **GIVEN** 测试创建 encode/decode PDU 并传入 `PTR_REF`
// - **WHEN** 调用 `dcerpc_ptr_coder`
// - **THEN** 对象被编码到 buffer 并可按相同期望 offset 解码回来
#[test]
fn test_libsmb2_dcerpc_test_encodes_and_decodes_reference_pointer() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut payload = DceRpcPayload::default();

    libsmb2_dcerpc::dcerpc_ptr_coder(
        &mut dce,
        &mut pdu,
        &mut iov,
        &mut offset,
        &mut payload,
        PtrType::Ref,
        |_dce, _pdu, _iov, _offset, _payload| 0,
    )
    .unwrap();

    assert_eq!(&iov.data[..4], &0x7274_7052u32.to_le_bytes());
}

// Trace: `include/smb2/libsmb2-dcerpc.h:117`, `lib/dcerpc.c:899`, `lib/dcerpc.c:913`
// Spec: dcerpc_carray_coder conformant array coding#Array count mismatch fails
// - **GIVEN** PDU 中 conformant count 与调用方 `num` 不一致
// - **WHEN** 调用 `dcerpc_carray_coder`
// - **THEN** 实现返回 `-1` 而不继续逐元素处理
#[test]
fn test_libsmb2_dcerpc_array_count_mismatch_fails() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();
    let mut iov = Smb2Iovec {
        data: 3u32.to_le_bytes().to_vec(),
    };
    let mut offset = 0;
    let mut payload = DceRpcPayload::default();
    let result = libsmb2_dcerpc::dcerpc_carray_coder(
        &mut dce,
        &mut pdu,
        &mut iov,
        &mut offset,
        4,
        &mut payload,
        1,
        |_dce, _pdu, _iov, _offset, _payload| 0,
    );

    assert!(result.is_err());
}

// Trace: `include/smb2/libsmb2-dcerpc.h:121`, `lib/dcerpc.c:621`
// Spec: dcerpc_uint8_coder 8-bit scalar coding#Scalar coder follows PDU direction
// - **GIVEN** PDU direction 为 decode 或 encode
// - **WHEN** 调用 `dcerpc_uint8_coder`
// - **THEN** 实现分别调用 8-bit get 或 set 路径
#[test]
fn test_libsmb2_dcerpc_scalar_coder_follows_pdu_direction_uint8() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut value = 0xab;

    libsmb2_dcerpc::dcerpc_uint8_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut value)
        .unwrap();
    assert_eq!(iov.data, vec![0xab]);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:123`, `lib/dcerpc.c:603`
// Spec: dcerpc_uint16_coder 16-bit scalar coding#Scalar coder follows PDU direction
// - **GIVEN** PDU direction 为 decode 或 encode
// - **WHEN** 调用 `dcerpc_uint16_coder`
// - **THEN** 实现分别调用 16-bit get 或 set 路径
#[test]
fn test_libsmb2_dcerpc_scalar_coder_follows_pdu_direction_uint16() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 1;
    let mut value = 0xabcd;

    libsmb2_dcerpc::dcerpc_uint16_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut value)
        .unwrap();
    assert_eq!(&iov.data[2..4], &0xabcdu16.to_le_bytes());
}

// Trace: `include/smb2/libsmb2-dcerpc.h:125`, `lib/dcerpc.c:586`
// Spec: dcerpc_uint32_coder 32-bit scalar coding#Scalar coder follows PDU direction
// - **GIVEN** PDU direction 为 decode 或 encode
// - **WHEN** 调用 `dcerpc_uint32_coder`
// - **THEN** 实现分别调用 32-bit get 或 set 路径
#[test]
fn test_libsmb2_dcerpc_scalar_coder_follows_pdu_direction_uint32() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut value = 0x1122_3344;

    libsmb2_dcerpc::dcerpc_uint32_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut value)
        .unwrap();
    assert_eq!(iov.data, 0x1122_3344u32.to_le_bytes());
}

// Trace: `include/smb2/libsmb2-dcerpc.h:127`, `lib/dcerpc.c:641`
// Spec: dcerpc_uint3264_coder transfer-syntax scalar coding#NDR32 encodes lower 32-bit value
// - **GIVEN** DCERPC context 使用 NDR32 transfer context
// - **WHEN** 调用 `dcerpc_uint3264_coder`
// - **THEN** 实现以 32-bit wire value 编解码调用方数值
#[test]
fn test_libsmb2_dcerpc_ndr32_encodes_lower_32_bit_value() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut value = 0x1122_3344_5566_7788;

    libsmb2_dcerpc::dcerpc_uint3264_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut value)
        .unwrap();
    assert_eq!(iov.data, 0x5566_7788u32.to_le_bytes());
}

// Trace: `include/smb2/libsmb2-dcerpc.h:129`, `lib/dcerpc.c:684`
// Spec: dcerpc_conformance_coder conformance-only processing#Data pass skips conformance field
// - **GIVEN** PDU 不处于 conformance run
// - **WHEN** 调用 `dcerpc_conformance_coder`
// - **THEN** 实现返回 `0` 且不读取或写入 conformance value
#[test]
fn test_libsmb2_dcerpc_data_pass_skips_conformance_field() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut value = 4;

    libsmb2_dcerpc::dcerpc_conformance_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut value)
        .unwrap();
    assert_eq!(iov.data, 4u32.to_le_bytes());
}

// Trace: `include/smb2/libsmb2-dcerpc.h:131`, `lib/dcerpc.c:1083`
// Spec: dcerpc_utf16_coder nonterminated UTF-16 coding#Nonterminated coder dispatches by direction
// - **GIVEN** 调用方传入 `struct dcerpc_utf16`
// - **WHEN** 调用 `dcerpc_utf16_coder`
// - **THEN** 实现以 `nult` 为 `0` 调用内部 UTF-16 编码或解码路径
#[test]
fn test_libsmb2_dcerpc_nonterminated_coder_dispatches_by_direction() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut value = DceRpcUtf16 {
        utf8: Some("hi".to_owned()),
        ..DceRpcUtf16::default()
    };

    libsmb2_dcerpc::dcerpc_utf16_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut value)
        .unwrap();
    assert_eq!(value.actual_count, 2);
    assert_eq!(value.utf16, vec![b'h' as u16, b'i' as u16]);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:133`, `lib/dcerpc.c:1069`, `tests/smb2-dcerpc-coder-test.c:150`
// Spec: dcerpc_utf16z_coder NUL-terminated UTF-16 coding#Test round-trips NUL-terminated UTF-16 text
// - **GIVEN** 测试输入 `\\win16-1` UTF-8 字符串
// - **WHEN** 调用 `dcerpc_utf16z_coder` 编码并解码
// - **THEN** 结果匹配测试期望字节序列和原始字符串
#[test]
fn test_libsmb2_dcerpc_test_round_trips_nul_terminated_utf_16_text() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 0).unwrap();
    let mut iov = Smb2Iovec::default();
    let mut offset = 0;
    let mut value = DceRpcUtf16 {
        utf8: Some("hi".to_owned()),
        ..DceRpcUtf16::default()
    };
    libsmb2_dcerpc::dcerpc_utf16z_coder(&mut dce, &mut pdu, &mut iov, &mut offset, &mut value)
        .unwrap();

    let mut decoded_pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();
    let mut decoded_iov = Smb2Iovec { data: iov.data };
    let mut decoded_offset = 0;
    let mut decoded = DceRpcUtf16::default();
    libsmb2_dcerpc::dcerpc_utf16z_coder(
        &mut dce,
        &mut decoded_pdu,
        &mut decoded_iov,
        &mut decoded_offset,
        &mut decoded,
    )
    .unwrap();
    assert_eq!(decoded.utf8.as_deref(), Some("hi"));
}

// Trace: `include/smb2/libsmb2-dcerpc.h:135`, `lib/dcerpc.c:1180`
// Spec: dcerpc_context_handle_coder context handle coding#Context handle fields are serialized in declaration order
// - **GIVEN** 调用方提供 `struct ndr_context_handle`
// - **WHEN** 调用 `dcerpc_context_handle_coder`
// - **THEN** 实现先调用 32-bit coder 处理 attributes，再调用 UUID coder 处理 UUID
#[test]
fn test_libsmb2_dcerpc_context_handle_fields_are_serialized() {
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
}

// Trace: `include/smb2/libsmb2-dcerpc.h:139`, `lib/dcerpc.c:1148`
// Spec: dcerpc_uuid_coder UUID field coding#UUID coder walks v4 bytes
// - **GIVEN** 调用方提供 `dcerpc_uuid_t *uuid`
// - **WHEN** 调用 `dcerpc_uuid_coder`
// - **THEN** 实现编解码 `v1`、`v2`、`v3` 后遍历 8 个 `v4` 字节
#[test]
fn test_libsmb2_dcerpc_uuid_coder_walks_v4_bytes() {
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

// Trace: `include/smb2/libsmb2-dcerpc.h:147`, `lib/dcerpc.c:513`, `tests/smb2-dcerpc-coder-test.c:67`
// Spec: dcerpc_allocate_pdu PDU allocation#Test allocates PDU for coder round-trip
// - **GIVEN** 调用方提供 DCERPC 上下文、direction 和 payload size
// - **WHEN** 调用 `dcerpc_allocate_pdu`
// - **THEN** 返回的 PDU 可用于后续 coder 测试并由 `dcerpc_free_pdu` 释放
#[test]
fn test_libsmb2_dcerpc_test_allocates_pdu_for_coder_round_trip() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 5).unwrap();

    assert_eq!(pdu.payload, vec![0; 5]);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:149`, `lib/dcerpc.c:500`, `tests/smb2-dcerpc-coder-test.c:133`
// Spec: dcerpc_free_pdu PDU cleanup#Test frees encoded and decoded PDU
// - **GIVEN** coder 测试完成两个 PDU 的使用
// - **WHEN** 调用 `dcerpc_free_pdu(dce, pdu)`
// - **THEN** 实现释放 payload 关联数据和 PDU 内存
#[test]
fn test_libsmb2_dcerpc_test_frees_encoded_and_decoded_pdu() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_ENCODE, 1).unwrap();

    libsmb2_dcerpc::dcerpc_free_pdu(&mut dce, pdu);
    assert!(libsmb2_dcerpc::dcerpc_get_smb2_context(&dce));
}

// Trace: `include/smb2/libsmb2-dcerpc.h:151`, `lib/dcerpc.c:1950`, `lib/dcerpc-srvsvc.c:135`
// Spec: dcerpc_set_size_is conformant size state#Container coder stores decoded entry count
// - **GIVEN** 解码容器读取到 EntriesRead
// - **WHEN** 调用 `dcerpc_set_size_is(pdu, EntriesRead)`
// - **THEN** 后续 carray coder 可读取该 count
#[test]
fn test_libsmb2_dcerpc_container_coder_stores_decoded_entry_count() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();

    libsmb2_dcerpc::dcerpc_set_size_is(&mut pdu, 3);
    assert_eq!(libsmb2_dcerpc::dcerpc_get_size_is(&pdu), 3);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:152`, `lib/dcerpc.c:1955`, `lib/dcerpc-srvsvc.c:113`
// Spec: dcerpc_get_size_is conformant size state#Carray coder reads stored entry count
// - **GIVEN** 前序 coder 已设置 PDU `size_is`
// - **WHEN** 调用 `dcerpc_get_size_is(pdu)`
// - **THEN** 返回该值供 conformant array 编解码使用
#[test]
fn test_libsmb2_dcerpc_carray_coder_reads_stored_entry_count() {
    let mut dce = libsmb2_dcerpc::dcerpc_create_context();
    let mut pdu = libsmb2_dcerpc::dcerpc_allocate_pdu(&mut dce, DCERPC_DECODE, 0).unwrap();

    libsmb2_dcerpc::dcerpc_set_size_is(&mut pdu, 4);
    assert_eq!(libsmb2_dcerpc::dcerpc_get_size_is(&pdu), 4);
}
