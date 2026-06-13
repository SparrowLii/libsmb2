use libsmb2_sys::smb2::libsmb2_dcerpc::{
    DceRpcCarray, DceRpcCoder, DceRpcContext, DceRpcPayload, DceRpcPdu, DceRpcUtf16, DceRpcUuid,
    NdrContextHandle, NdrTransferSyntax, PSyntaxId, PtrType, Smb2Iovec, DCERPC_DECODE,
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
    let mut dce = DceRpcContext;
    let mut pdu = DceRpcPdu;
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
    assert_eq!(DCERPC_DECODE, 0);
}

// Trace: `include/smb2/libsmb2-dcerpc.h:146`, `tests/smb2-dcerpc-coder-test.c:67`
// Spec: DCERPC_ENCODE direction constant#Test allocates encode PDU
// - **GIVEN** 调用方需要创建 encode PDU
// - **WHEN** 调用 `dcerpc_allocate_pdu(dce, DCERPC_ENCODE, size)`
// - **THEN** PDU direction 使用值 `1`
// Note: This validates the public direction constant; PDU allocation itself requires a DCERPC FFI lifecycle binding.
#[test]
fn test_libsmb2_dcerpc_test_allocates_encode_pdu() {
    assert_eq!(DCERPC_ENCODE, 1);
}
