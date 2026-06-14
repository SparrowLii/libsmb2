use libsmb2_rs::lib::smb2_cmd_query_directory::{
    self as qd, FileIdFullDirectoryInformation, QueryDirectoryError, QueryDirectoryReply,
    QueryDirectoryRequest,
};

fn file_id() -> [u8; 16] {
    [0x88; 16]
}
fn utf16le(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn full_entry(name: &str) -> Vec<u8> {
    let name_bytes = utf16le(name);
    let mut buf = vec![0; 80 + name_bytes.len()];
    buf[4..8].copy_from_slice(&7_u32.to_le_bytes());
    buf[40..48].copy_from_slice(&8_u64.to_le_bytes());
    buf[48..56].copy_from_slice(&16_u64.to_le_bytes());
    buf[56..60].copy_from_slice(&0x20_u32.to_le_bytes());
    buf[60..64].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    buf[64..68].copy_from_slice(&3_u32.to_le_bytes());
    buf[72..80].copy_from_slice(&9_u64.to_le_bytes());
    buf[80..].copy_from_slice(&name_bytes);
    buf
}

// Trace: `lib/smb2-cmd-query-directory.c:smb2_decode_fileidfulldirectoryinformation`, `include/smb2/smb2.h:smb2_fileidfulldirectoryinformation`
// Spec: smb2_decode_fileidfulldirectoryinformation decode directory entry#decode well-formed entry
// - **GIVEN** `vec` 至少包含 80 字节固定字段以及 `name_len` 指示的 UTF-16 名称数据
// - **WHEN** 调用 `smb2_decode_fileidfulldirectoryinformation` 解码目录项
// - **THEN** 函数返回 `0`，填充 `fs` 的索引、大小、属性、EA、file_id、时间字段和 `name`
#[test]
fn test_smb2_cmd_query_directory_decode_well_formed_entry() {
    let decoded = qd::smb2_decode_fileidfulldirectoryinformation(&full_entry("ab")).unwrap();
    assert_eq!(decoded.file_index, 7);
    assert_eq!(decoded.end_of_file, 8);
    assert_eq!(decoded.name, "ab");
}

// Trace: `lib/smb2-cmd-query-directory.c:smb2_decode_fileidfulldirectoryinformation`
// Spec: smb2_decode_fileidfulldirectoryinformation decode directory entry#reject malformed name span
// - **GIVEN** `name_len` 溢出 `80 + name_len` 或者名称范围超过 `vec->len`
// - **WHEN** 调用 `smb2_decode_fileidfulldirectoryinformation` 解码目录项
// - **THEN** 函数 MUST 设置 SMB2 错误并返回 `-1`
#[test]
fn test_smb2_cmd_query_directory_reject_malformed_name_span() {
    let mut buf = full_entry("ab");
    buf[60..64].copy_from_slice(&100_u32.to_le_bytes());
    assert_eq!(
        qd::smb2_decode_fileidfulldirectoryinformation(&buf),
        Err(QueryDirectoryError::MalformedName)
    );
}

// Trace: `lib/smb2-cmd-query-directory.c:smb2_cmd_query_directory_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_query_directory_async`
// Spec: smb2_cmd_query_directory_async build request PDU#build request with optional name
// - **GIVEN** 调用方提供 `smb2_context`、`smb2_query_directory_request`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_query_directory_async` 创建请求 PDU
// - **THEN** 函数返回已填充并 64-bit 对齐的 PDU，且在请求名称非空时把 UTF-8 名称编码为 UTF-16 附加 iovec
#[test]
fn test_smb2_cmd_query_directory_build_request_with_optional_name() {
    let mut req =
        QueryDirectoryRequest::new(qd::SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION, file_id(), 128);
    req.name = Some("ab".to_string());
    let pdu = qd::smb2_cmd_query_directory_async(&req, false).unwrap();
    assert_eq!(pdu.command, 0x000e);
    assert_eq!(
        &pdu.payload[QueryDirectoryRequest::fixed_wire_len()..],
        &utf16le("ab")
    );
}

// Trace: `lib/smb2-cmd-query-directory.c:smb2_cmd_query_directory_async`
// Spec: smb2_cmd_query_directory_async build request PDU#adjust multi-credit charge
// - **GIVEN** `smb2->supports_multi_credit` 为真且请求指定 `output_buffer_length`
// - **WHEN** `smb2_cmd_query_directory_async` 成功创建 PDU
// - **THEN** 函数 MUST 将 `pdu->header.credit_charge` 设置为 `(output_buffer_length - 1) / 65536 + 1`
#[test]
fn test_smb2_cmd_query_directory_adjust_multi_credit_charge() {
    let req = QueryDirectoryRequest::new(
        qd::SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION,
        file_id(),
        65_537,
    );
    let pdu = qd::smb2_cmd_query_directory_async(&req, true).unwrap();
    assert_eq!(pdu.credit_charge, 2);
}

// Trace: `lib/smb2-cmd-query-directory.c:smb2_cmd_query_directory_reply_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_query_directory_reply_async`
// Spec: smb2_cmd_query_directory_reply_async build reply PDU#build reply PDU
// - **GIVEN** 调用方提供请求、回复、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_query_directory_reply_async` 创建回复 PDU
// - **THEN** 函数返回已编码并 64-bit 对齐的 PDU，回复固定头包含输出缓冲区偏移和长度
#[test]
fn test_smb2_cmd_query_directory_build_reply_pdu() {
    let rep = QueryDirectoryReply::new()
        .with_output_buffer(vec![1, 2, 3])
        .unwrap();
    let pdu = qd::smb2_cmd_query_directory_reply_async(&rep).unwrap();
    assert_eq!(pdu.command, 0x000e);
    assert_eq!(&pdu.payload[4..8], &3_u32.to_le_bytes());
}

// Trace: `lib/smb2-cmd-query-directory.c:smb2_cmd_query_directory_reply_async`, `lib/smb2-cmd-query-directory.c:smb2_encode_query_directory_reply`
// Spec: smb2_cmd_query_directory_reply_async build reply PDU#encode passthrough or structured output
// - **GIVEN** `rep->output_buffer_length` 非零且 `rep->output_buffer` 可用
// - **WHEN** 回复编码 helper 被 `smb2_cmd_query_directory_reply_async` 调用
// - **THEN** 系统 MUST 在 passthrough 模式复制原始输出缓冲区，否则按 FileIdFull 或 FileIdBoth 格式重新编码目录项并维护 next-entry offset
#[test]
fn test_smb2_cmd_query_directory_encode_passthrough_or_structured_output() {
    let entry = FileIdFullDirectoryInformation {
        file_index: 1,
        name: "ab".into(),
        ..Default::default()
    };
    let encoded = qd::smb2_encode_fileidfulldirectoryinformation_entries_vec(&[entry]).unwrap();
    let decoded = qd::smb2_decode_fileidfulldirectoryinformation_entries(&encoded).unwrap();
    assert_eq!(decoded[0].name, "ab");
}

// Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_fixed`, `include/libsmb2-private.h:smb2_process_query_directory_fixed`
// Spec: smb2_process_query_directory_fixed validate reply fixed part#accept valid reply fixed part
// - **GIVEN** 输入 iovec 的结构大小等于 `SMB2_QUERY_DIRECTORY_REPLY_SIZE` 且输出缓冲区范围在 `smb2->spl` 内
// - **WHEN** 调用 `smb2_process_query_directory_fixed` 解析 reply 固定部分
// - **THEN** 函数返回 `0` 或包含 padding 的输出缓冲区长度，并设置 `pdu->payload`
#[test]
fn test_smb2_cmd_query_directory_accept_valid_reply_fixed_part() {
    let rep = QueryDirectoryReply::new()
        .with_output_buffer(vec![1, 2])
        .unwrap();
    let fixed = qd::smb2_encode_query_directory_reply(&rep).unwrap()[..8].to_vec();
    let (parsed, len) = qd::smb2_process_query_directory_fixed(&fixed, 80).unwrap();
    assert_eq!(parsed.output_buffer_length, 2);
    assert_eq!(len, 2);
}

// Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_fixed`
// Spec: smb2_process_query_directory_fixed validate reply fixed part#reject invalid reply bounds
// - **GIVEN** 固定结构大小不匹配、输出缓冲区越过 PDU 末尾、或者非空输出缓冲区偏移重叠固定头
// - **WHEN** 调用 `smb2_process_query_directory_fixed`
// - **THEN** 函数 MUST 设置 SMB2 错误、释放已分配 reply 结构并返回 `-1`
#[test]
fn test_smb2_cmd_query_directory_reject_invalid_reply_bounds() {
    assert_eq!(
        qd::smb2_process_query_directory_fixed(&[0; 8], 80),
        Err(QueryDirectoryError::InvalidStructureSize)
    );
}

// Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_variable`, `include/libsmb2-private.h:smb2_process_query_directory_variable`
// Spec: smb2_process_query_directory_variable bind reply output buffer#bind variable reply buffer
// - **GIVEN** `pdu->payload` 已包含 `smb2_query_directory_reply` 且固定部分解析已计算输出偏移
// - **WHEN** 调用 `smb2_process_query_directory_variable` 解析 reply 可变部分
// - **THEN** 函数返回 `0`，并把 `rep->output_buffer` 设为 `iov->buf[IOV_OFFSET_DIRECTORY]`
#[test]
fn test_smb2_cmd_query_directory_bind_variable_reply_buffer() {
    let mut rep = QueryDirectoryReply {
        output_buffer_offset: 72,
        output_buffer_length: 2,
        output_buffer: Vec::new(),
    };
    qd::smb2_process_query_directory_variable(&mut rep, &[4, 5]).unwrap();
    assert_eq!(rep.output_buffer, vec![4, 5]);
}

// Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_request_fixed`, `include/libsmb2-private.h:smb2_process_query_directory_request_fixed`
// Spec: smb2_process_query_directory_request_fixed validate request fixed part#accept valid request fixed part
// - **GIVEN** 输入 iovec 的结构大小等于 `SMB2_QUERY_DIRECTORY_REQUEST_SIZE` 且名称范围在 PDU 内
// - **WHEN** 调用 `smb2_process_query_directory_request_fixed` 解析 request 固定部分
// - **THEN** 函数返回 `0` 或包含 padding 的名称缓冲区长度，并填充请求信息类别、flags、file index、file id、名称偏移、名称长度和输出长度
#[test]
fn test_smb2_cmd_query_directory_accept_valid_request_fixed_part() {
    let mut req =
        QueryDirectoryRequest::new(qd::SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION, file_id(), 128);
    req.name = Some("ab".into());
    let fixed = qd::smb2_encode_query_directory_request(&req).unwrap()
        [..QueryDirectoryRequest::fixed_wire_len()]
        .to_vec();
    let (parsed, len) = qd::smb2_process_query_directory_request_fixed(&fixed, 104).unwrap();
    assert_eq!(parsed.file_id, file_id());
    assert_eq!(len, 4);
}

// Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_request_fixed`
// Spec: smb2_process_query_directory_request_fixed validate request fixed part#reject invalid request bounds
// - **GIVEN** 固定结构大小不匹配、名称范围越过 PDU 末尾、或者非空名称偏移重叠请求固定头
// - **WHEN** 调用 `smb2_process_query_directory_request_fixed`
// - **THEN** 函数 MUST 设置 SMB2 错误、释放已分配 request 结构并返回 `-1`
#[test]
fn test_smb2_cmd_query_directory_reject_invalid_request_bounds() {
    assert_eq!(
        qd::smb2_process_query_directory_request_fixed(&[0; 32], 80),
        Err(QueryDirectoryError::InvalidStructureSize)
    );
}

// Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_request_variable`, `include/libsmb2-private.h:smb2_process_query_directory_request_variable`
// Spec: smb2_process_query_directory_request_variable convert request name#convert request name
// - **GIVEN** `pdu->payload` 已包含 request 且 `file_name_length` 大于 `0`
// - **WHEN** 调用 `smb2_process_query_directory_request_variable` 解析 request 可变部分
// - **THEN** 函数返回 `0`，并将 `req->name` 指向通过 `smb2_alloc_init` 分配并复制的 UTF-8 字符串
#[test]
fn test_smb2_cmd_query_directory_convert_request_name() {
    let mut req = QueryDirectoryRequest {
        file_name_offset: 96,
        file_name_length: 4,
        ..QueryDirectoryRequest::default()
    };
    qd::smb2_process_query_directory_request_variable(&mut req, &utf16le("ab")).unwrap();
    assert_eq!(req.name.as_deref(), Some("ab"));
}

// Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_request_variable`
// Spec: smb2_process_query_directory_request_variable convert request name#reject name conversion or allocation failure
// - **GIVEN** UTF-16 到 UTF-8 转换失败，或者上下文分配复制缓冲区失败
// - **WHEN** 调用 `smb2_process_query_directory_request_variable`
// - **THEN** 函数 MUST 设置 SMB2 错误并返回 `-1`
#[test]
fn test_smb2_cmd_query_directory_reject_name_conversion_or_allocation_failure() {
    let mut req = QueryDirectoryRequest {
        file_name_offset: 96,
        file_name_length: 4,
        ..QueryDirectoryRequest::default()
    };
    assert_eq!(
        qd::smb2_process_query_directory_request_variable(&mut req, &[0, 1]),
        Err(QueryDirectoryError::BufferTooShort)
    );
}
