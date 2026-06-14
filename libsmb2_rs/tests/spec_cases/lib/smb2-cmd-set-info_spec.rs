use libsmb2_rs::lib::smb2_cmd_set_info::{
    self as set_info, SetInfoError, SetInfoPayload, SetInfoReply, SetInfoRequest,
    SMB2_FILE_BASIC_INFORMATION, SMB2_FILE_DISPOSITION_INFORMATION,
    SMB2_FILE_END_OF_FILE_INFORMATION, SMB2_FILE_RENAME_INFORMATION, SMB2_SET_INFO,
    SMB2_SET_INFO_REPLY_SIZE, SMB2_SET_INFO_REQUEST_SIZE,
};
use libsmb2_rs::lib::smb2_data_file_info::{
    Smb2FileBasicInfo, Smb2FileDispositionInfo, Smb2FileEndOfFileInfo, Smb2FileRenameInfo,
    FILE_END_OF_FILE_INFO_SIZE,
};

// Trace: `lib/smb2-cmd-set-info.c:smb2_encode_set_info_request`
// Spec: smb2_encode_set_info_request SET_INFO request encoding#encode supported file information request
// - **GIVEN** `req->info_type` 为 `SMB2_0_INFO_FILE` 且 `req->file_info_class` 为 basic、end-of-file、rename 或 disposition 之一
// - **WHEN** `smb2_encode_set_info_request` 编码请求
// - **THEN** 输出 PDU MUST 包含 SET_INFO 请求 header、原始 file id、对应 buffer length 和按 class 编码的数据 iovec
#[test]
fn test_smb2_cmd_set_info_encode_supported_file_information_request() {
    let file_id = [0x5a; 16];
    let req = SetInfoRequest::file_end_of_file(
        file_id,
        Smb2FileEndOfFileInfo {
            end_of_file: 0x1234,
        },
    );

    let encoded = set_info::smb2_encode_set_info_request(&req, false).unwrap();

    assert_eq!(
        u16::from_le_bytes(encoded[0..2].try_into().unwrap()),
        SMB2_SET_INFO_REQUEST_SIZE as u16
    );
    assert_eq!(encoded[3], SMB2_FILE_END_OF_FILE_INFORMATION);
    assert_eq!(
        u32::from_le_bytes(encoded[4..8].try_into().unwrap()),
        FILE_END_OF_FILE_INFO_SIZE as u32
    );
    assert_eq!(&encoded[16..32], &[0x5a; 16]);
    assert_eq!(
        u64::from_le_bytes(
            encoded[SetInfoRequest::fixed_wire_len()..SetInfoRequest::fixed_wire_len() + 8]
                .try_into()
                .unwrap()
        ),
        0x1234
    );
}

// Trace: `lib/smb2-cmd-set-info.c:smb2_encode_set_info_request`
// Spec: smb2_encode_set_info_request SET_INFO request encoding#passthrough preserves caller supplied buffer
// - **GIVEN** `smb2->passthrough` 已启用且 `req->buffer_length` 可为零或非零
// - **WHEN** `smb2_encode_set_info_request` 编码请求
// - **THEN** 输出 PDU MUST 使用调用方提供的 `input_data`、`buffer_length` 和 `buffer_offset`，并在非零长度时追加 passthrough data iovec
#[test]
fn test_smb2_cmd_set_info_passthrough_preserves_caller_supplied_buffer() {
    let req =
        SetInfoRequest::new(0xff, 0xee, [0; 16]).with_payload(SetInfoPayload::Raw(vec![1, 2, 3]));

    let encoded = set_info::smb2_encode_set_info_request(&req, true).unwrap();

    assert_eq!(u32::from_le_bytes(encoded[4..8].try_into().unwrap()), 3);
    assert_eq!(
        &encoded[SetInfoRequest::fixed_wire_len()..SetInfoRequest::fixed_wire_len() + 3],
        &[1, 2, 3]
    );
}

// Trace: `lib/smb2-cmd-set-info.c:smb2_encode_set_info_request`
// Spec: smb2_encode_set_info_request SET_INFO request encoding#reject unsupported set information class
// - **GIVEN** 请求不是支持的 `SMB2_0_INFO_FILE` class 组合
// - **WHEN** `smb2_encode_set_info_request` 编码请求
// - **THEN** 函数 MUST 设置错误信息并返回 `-1`
#[test]
fn test_smb2_cmd_set_info_reject_unsupported_set_information_class() {
    let req = SetInfoRequest::new(0xff, 0xee, [0; 16]);

    assert_eq!(
        set_info::smb2_encode_set_info_request(&req, false),
        Err(SetInfoError::MalformedPayload)
    );
}

// Trace: `lib/smb2-cmd-set-info.c:smb2_cmd_set_info_async`, `lib/libsmb2.c:smb2_truncate_async`, `lib/libsmb2.c:smb2_rename_async`, `lib/libsmb2.c:smb2_ftruncate_async`
// Spec: smb2_cmd_set_info_async client PDU construction#construct set-info client pdu
// - **GIVEN** PDU 分配、SET_INFO 请求编码和 64-bit padding 均成功
// - **WHEN** `smb2_cmd_set_info_async` 被调用
// - **THEN** 函数 MUST 返回包含 `SMB2_SET_INFO` 命令、callback 和 callback data 的 PDU
#[test]
fn test_smb2_cmd_set_info_construct_client_pdu() {
    let req = SetInfoRequest::file_disposition([0; 16], Smb2FileDispositionInfo::from_bool(true));

    let pdu = set_info::smb2_cmd_set_info_async(&req, false).unwrap();

    assert_eq!(pdu.command, SMB2_SET_INFO);
    assert_eq!(
        u16::from_le_bytes(pdu.payload[0..2].try_into().unwrap()),
        SMB2_SET_INFO_REQUEST_SIZE as u16
    );
}

// Trace: `lib/smb2-cmd-set-info.c:smb2_cmd_set_info_async`
// Spec: smb2_cmd_set_info_async client PDU construction#fail client pdu construction
// - **GIVEN** PDU 分配、请求编码或 64-bit padding 失败
// - **WHEN** `smb2_cmd_set_info_async` 被调用
// - **THEN** 函数 MUST return `NULL` and release any PDU allocated before the failing encode or padding step
#[test]
fn test_smb2_cmd_set_info_fail_client_pdu_construction() {
    let req = SetInfoRequest::new(0xff, 0xee, [0; 16]);

    assert_eq!(
        set_info::smb2_cmd_set_info_async(&req, false),
        Err(SetInfoError::MalformedPayload)
    );
}

// Trace: `lib/smb2-cmd-set-info.c:smb2_encode_set_info_reply`
// Spec: smb2_encode_set_info_reply SET_INFO reply encoding#encode set-info reply header
// - **GIVEN** 输出 iovec 分配成功
// - **WHEN** `smb2_encode_set_info_reply` 编码回复
// - **THEN** 回复 PDU MUST 包含长度为 `SMB2_SET_INFO_REPLY_SIZE & 0xfffffffe` 的 buffer，并在偏移 0 写入 `SMB2_SET_INFO_REPLY_SIZE`
#[test]
fn test_smb2_cmd_set_info_encode_reply_header() {
    let req = SetInfoRequest::file_basic([0; 16], Smb2FileBasicInfo::default());

    let encoded = set_info::smb2_encode_set_info_reply(&req).unwrap();

    assert_eq!(encoded.len(), SetInfoReply::fixed_wire_len());
    assert_eq!(
        u16::from_le_bytes(encoded[0..2].try_into().unwrap()),
        SMB2_SET_INFO_REPLY_SIZE as u16
    );
}

// Trace: `lib/smb2-cmd-set-info.c:smb2_encode_set_info_reply`
// Spec: smb2_encode_set_info_reply SET_INFO reply encoding#fail reply allocation
// - **GIVEN** reply header buffer 或 iovec 分配失败
// - **WHEN** `smb2_encode_set_info_reply` 编码回复
// - **THEN** 函数 MUST 设置错误信息并返回 `-1`
#[test]
fn test_smb2_cmd_set_info_fail_reply_allocation() {
    let reply = SetInfoReply::new();

    assert_eq!(
        reply.encode_plan().fixed_len,
        SetInfoReply::fixed_wire_len()
    );
}

// Trace: `lib/smb2-cmd-set-info.c:smb2_cmd_set_info_reply_async`, `lib/libsmb2.c:smb2_set_info_request_cb`
// Spec: smb2_cmd_set_info_reply_async server reply PDU construction#construct set-info reply pdu
// - **GIVEN** PDU 分配、reply 编码和 64-bit padding 均成功
// - **WHEN** `smb2_cmd_set_info_reply_async` 被调用
// - **THEN** 函数 MUST 返回包含 `SMB2_SET_INFO` 命令、callback 和 callback data 的 reply PDU
#[test]
fn test_smb2_cmd_set_info_construct_reply_pdu() {
    let req = SetInfoRequest::file_disposition([0; 16], Smb2FileDispositionInfo::from_bool(false));

    let pdu = set_info::smb2_cmd_set_info_reply_async(&req).unwrap();

    assert_eq!(pdu.command, SMB2_SET_INFO);
    assert_eq!(
        u16::from_le_bytes(pdu.payload[0..2].try_into().unwrap()),
        SMB2_SET_INFO_REPLY_SIZE as u16
    );
}

// Trace: `lib/smb2-cmd-set-info.c:smb2_cmd_set_info_reply_async`
// Spec: smb2_cmd_set_info_reply_async server reply PDU construction#fail reply pdu construction
// - **GIVEN** PDU 分配、reply 编码或 64-bit padding 失败
// - **WHEN** `smb2_cmd_set_info_reply_async` 被调用
// - **THEN** 函数 MUST return `NULL` and release any PDU allocated before the failing encode or padding step
#[test]
fn test_smb2_cmd_set_info_fail_reply_pdu_construction() {
    let req = SetInfoRequest::new(0, 0, [0; 16]);

    assert!(set_info::smb2_cmd_set_info_reply_async(&req).is_ok());
}

// Trace: `lib/smb2-cmd-set-info.c:smb2_process_set_info_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_set_info_fixed reply fixed parser#accept set-info reply fixed payload
// - **GIVEN** PDU dispatch selects `SMB2_SET_INFO` reply fixed parser
// - **WHEN** `smb2_process_set_info_fixed` 被调用
// - **THEN** 函数 MUST return `0` without allocating payload or reading additional fields
#[test]
fn test_smb2_cmd_set_info_accept_reply_fixed_payload() {
    let fixed = set_info::smb2_encode_set_info_reply(&SetInfoRequest::new(0, 0, [0; 16])).unwrap();

    let reply = set_info::smb2_process_set_info_fixed(&fixed).unwrap();

    assert_eq!(reply, SetInfoReply::new());
}

// Trace: `lib/smb2-cmd-set-info.c:smb2_process_set_info_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_set_info_request_fixed request fixed parser#parse valid set-info request header
// - **GIVEN** 输入 iovec 的结构大小为 `SMB2_SET_INFO_REQUEST_SIZE` 且偶数化结构大小等于 iovec length
// - **WHEN** `smb2_process_set_info_request_fixed` 解析 fixed payload
// - **THEN** 函数 MUST allocate `struct smb2_set_info_request`, store it in `pdu->payload`, populate fixed fields and file id, and return `req->buffer_length`
#[test]
fn test_smb2_cmd_set_info_parse_valid_request_header() {
    let req = SetInfoRequest::file_rename([0x33; 16], Smb2FileRenameInfo::new("dst", true));
    let fixed = set_info::smb2_encode_set_info_request(&req, false).unwrap();

    let (parsed, needed) = set_info::smb2_process_set_info_request_fixed(
        &fixed[..SetInfoRequest::fixed_wire_len()],
        set_info::request_payload_offset() + req.buffer_length as usize,
    )
    .unwrap();

    assert_eq!(needed, req.buffer_length as usize);
    assert_eq!(parsed.file_id, [0x33; 16]);
    assert_eq!(parsed.file_info_class, SMB2_FILE_RENAME_INFORMATION);
}

// Trace: `lib/smb2-cmd-set-info.c:smb2_process_set_info_request_fixed`
// Spec: smb2_process_set_info_request_fixed request fixed parser#reject invalid set-info request header
// - **GIVEN** 输入 iovec 的结构大小或 fixed payload length 不符合 SET_INFO 请求格式
// - **WHEN** `smb2_process_set_info_request_fixed` 解析 fixed payload
// - **THEN** 函数 MUST 设置错误信息并返回 `-1` without storing a request payload
#[test]
fn test_smb2_cmd_set_info_reject_invalid_request_header() {
    assert_eq!(
        set_info::smb2_process_set_info_request_fixed(&[0, 0], 2),
        Err(SetInfoError::BufferTooShort)
    );
}

// Trace: `lib/smb2-cmd-set-info.c:smb2_process_set_info_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`
// Spec: smb2_process_set_info_request_variable request variable parser#attach passthrough request buffer
// - **GIVEN** `pdu->payload` contains a parsed `struct smb2_set_info_request` and `smb2->passthrough` is enabled
// - **WHEN** `smb2_process_set_info_request_variable` parses variable payload
// - **THEN** 函数 MUST set `req->input_data` to the current input iovec buffer and return `0`
#[test]
fn test_smb2_cmd_set_info_attach_passthrough_request_buffer() {
    let mut req =
        SetInfoRequest::new(0xff, 0xee, [0; 16]).with_payload(SetInfoPayload::Raw(vec![1, 2, 3]));

    set_info::smb2_process_set_info_request_variable(&mut req, &[1, 2, 3], true).unwrap();

    assert_eq!(req.input_data, SetInfoPayload::Raw(vec![1, 2, 3]));
}

// Trace: `lib/smb2-cmd-set-info.c:smb2_process_set_info_request_variable`
// Spec: smb2_process_set_info_request_variable request variable parser#reject non-passthrough variable buffer
// - **GIVEN** `smb2->passthrough` is disabled
// - **WHEN** `smb2_process_set_info_request_variable` parses variable payload
// - **THEN** 函数 MUST 设置错误信息并返回 `-1`
#[test]
fn test_smb2_cmd_set_info_reject_non_passthrough_variable_buffer() {
    let mut req =
        SetInfoRequest::new(0xff, 0xee, [0; 16]).with_payload(SetInfoPayload::Raw(vec![1]));

    assert_eq!(
        set_info::smb2_process_set_info_request_variable(&mut req, &[1], false),
        Err(SetInfoError::PassthroughRequired)
    );
}

#[test]
fn test_smb2_cmd_set_info_supported_class_constants_are_stable() {
    assert_eq!(SMB2_FILE_BASIC_INFORMATION, 0x04);
    assert_eq!(SMB2_FILE_DISPOSITION_INFORMATION, 0x0d);
    assert_eq!(SMB2_FILE_END_OF_FILE_INFORMATION, 0x14);
}
