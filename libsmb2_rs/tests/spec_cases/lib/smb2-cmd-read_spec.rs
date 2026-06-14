use libsmb2_rs::lib::smb2_cmd_read::{
    ReadCommandError, Smb2ReadReply, Smb2ReadRequest, SMB2_FD_SIZE, SMB2_HEADER_SIZE,
    SMB2_READ_REPLY_SIZE, SMB2_READ_REQUEST_SIZE,
};

// Trace: `lib/smb2-cmd-read.c:smb2_cmd_read_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_read_async`, `lib/libsmb2.c:smb2_pread_async`
// Spec: smb2_cmd_read_async read request PDU construction#构造普通 READ 请求
// - **GIVEN** 调用方提供 `smb2_context`、`smb2_read_request`、回调和回调数据，且请求编码、输入 iovector 和 padding 均成功
// - **WHEN** 调用 `smb2_cmd_read_async`
// - **THEN** 返回的 PDU 使用 `SMB2_READ` 命令并包含 encoded read request；当 `req->length` 非零时，PDU input vector MUST 指向调用方提供的 `req->buf`
#[test]
fn test_smb2_cmd_read_construct_normal_read_request() {
    let mut req = Smb2ReadRequest {
        length: 4,
        file_id: [0x44; SMB2_FD_SIZE],
        reply_buffer_len: Some(4),
        ..Smb2ReadRequest::default()
    };

    let pdu = req.cmd_read_async(false, false).unwrap();

    assert_eq!(
        u16::from_le_bytes([pdu.out[0].as_slice()[0], pdu.out[0].as_slice()[1]]),
        SMB2_READ_REQUEST_SIZE
    );
    assert_eq!(&pdu.out[0].as_slice()[16..32], &[0x44; SMB2_FD_SIZE]);
    assert_eq!(pdu.input[0].len(), 4);
}

// Trace: `lib/smb2-cmd-read.c:smb2_cmd_read_async`, `lib/smb2-cmd-read.c:smb2_encode_read_request`
// Spec: smb2_cmd_read_async read request PDU construction#非 multi-credit 大读取被截断
// - **GIVEN** `smb2->supports_multi_credit` 为 false 且 `req->length` 大于 64 KiB
// - **WHEN** 调用 `smb2_cmd_read_async`
// - **THEN** 请求编码 MUST 将 `req->length` 截断为 64 KiB，并将 `req->minimum_count` 置为 0 后写入请求 PDU
#[test]
fn test_smb2_cmd_read_non_multi_credit_large_read_is_truncated() {
    let mut req = Smb2ReadRequest {
        length: 70_000,
        minimum_count: 99,
        reply_buffer_len: Some(70_000),
        ..Smb2ReadRequest::default()
    };

    let pdu = req.cmd_read_async(false, false).unwrap();

    assert_eq!(
        u32::from_le_bytes(pdu.out[0].as_slice()[4..8].try_into().unwrap()),
        65_536
    );
    assert_eq!(
        u32::from_le_bytes(pdu.out[0].as_slice()[32..36].try_into().unwrap()),
        0
    );
}

// Trace: `lib/smb2-cmd-read.c:smb2_cmd_read_async`
// Spec: smb2_cmd_read_async read request PDU construction#缺少读取数据缓冲区
// - **GIVEN** `req->length` 非零且 `req->buf` 为 `NULL`
// - **WHEN** 调用 `smb2_cmd_read_async`
// - **THEN** 函数 MUST 设置错误 `No buffer for read reply data`、释放已分配 PDU 并返回 `NULL`
#[test]
fn test_smb2_cmd_read_missing_read_data_buffer() {
    let mut req = Smb2ReadRequest {
        length: 1,
        reply_buffer_len: None,
        ..Smb2ReadRequest::default()
    };

    assert_eq!(
        req.cmd_read_async(false, false),
        Err(ReadCommandError::MissingReplyBuffer)
    );
}

// Trace: `lib/smb2-cmd-read.c:smb2_cmd_read_async`
// Spec: smb2_cmd_read_async read request PDU construction#multi-credit credit charge
// - **GIVEN** `smb2->supports_multi_credit` 为 true 且 PDU 构造成功
// - **WHEN** 调用 `smb2_cmd_read_async`
// - **THEN** 返回 PDU 的 `header.credit_charge` MUST 设置为 `(req->length - 1) / 65536 + 1`
#[test]
fn test_smb2_cmd_read_multi_credit_credit_charge() {
    let mut req = Smb2ReadRequest {
        length: 131_073,
        reply_buffer_len: Some(131_073),
        ..Smb2ReadRequest::default()
    };

    let pdu = req.cmd_read_async(true, false).unwrap();

    assert_eq!(pdu.credit_charge, 3);
}

// Trace: `lib/smb2-cmd-read.c:smb2_cmd_read_reply_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_read_reply_async`, `lib/libsmb2.c:smb2_read_request_cb`
// Spec: smb2_cmd_read_reply_async read reply PDU construction#构造 READ 响应
// - **GIVEN** 调用方提供 `smb2_read_reply`，且 PDU 分配、fixed reply 编码和 padding 均成功
// - **WHEN** 调用 `smb2_cmd_read_reply_async`
// - **THEN** 返回的 PDU MUST 包含 READ reply fixed 区域；当 `rep->data_length` 非零且 `rep->data` 非空时，PDU output vector MUST 附加 `rep->data` 并使用 `free` 作为释放回调
#[test]
fn test_smb2_cmd_read_reply_construct_read_response() {
    let mut rep = Smb2ReadReply {
        data_length: 3,
        data: vec![1, 2, 3],
        ..Smb2ReadReply::default()
    };

    let pdu = rep.cmd_read_reply_async();

    assert_eq!(
        u16::from_le_bytes(pdu.out[0].as_slice()[0..2].try_into().unwrap()),
        SMB2_READ_REPLY_SIZE
    );
    assert_eq!(pdu.out[1].as_slice(), &[1, 2, 3]);
}

// Trace: `lib/smb2-cmd-read.c:smb2_cmd_read_reply_async`, `lib/smb2-cmd-read.c:smb2_encode_read_reply`
// Spec: smb2_cmd_read_reply_async read reply PDU construction#空 READ 响应数据
// - **GIVEN** `rep->data_length` 为 0 或 `rep->data` 为 `NULL`
// - **WHEN** 调用 `smb2_cmd_read_reply_async`
// - **THEN** 响应 fixed 区域 MUST 将 `data_offset` 编码为 0，且 MUST NOT 附加 data output vector
#[test]
fn test_smb2_cmd_read_reply_empty_read_response_data() {
    let mut rep = Smb2ReadReply::default();

    let pdu = rep.cmd_read_reply_async();

    assert_eq!(pdu.out[0].as_slice()[2], 0);
    assert_eq!(pdu.out.len(), 1);
}

// Trace: `lib/smb2-cmd-read.c:smb2_process_read_fixed`, `include/libsmb2-private.h:smb2_process_read_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_read_fixed read reply fixed parser#无 READ 数据的响应
// - **GIVEN** 输入 iovector 的 structure size 不大于 `SMB2_READ_REPLY_SIZE`，且 encoded `data_length` 为 0
// - **WHEN** 调用 `smb2_process_read_fixed`
// - **THEN** 函数 MUST 分配 reply payload、填充 `data_offset`、`data_length` 和 `data_remaining`，将 `rep->data` 置为 `NULL`，并返回 0
#[test]
fn test_smb2_process_read_fixed_reply_without_read_data() {
    let mut rep = Smb2ReadReply::default();
    let fixed = rep.encode_reply().remove(0);

    let (parsed, needed) = Smb2ReadReply::process_reply_fixed(fixed.as_slice()).unwrap();

    assert_eq!(needed, 0);
    assert!(parsed.data.is_empty());
}

// Trace: `lib/smb2-cmd-read.c:smb2_process_read_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_read_fixed read reply fixed parser#有 READ 数据的响应
// - **GIVEN** encoded `data_length` 非零且 `data_offset` 等于 `SMB2_HEADER_SIZE + 16`
// - **WHEN** 调用 `smb2_process_read_fixed`
// - **THEN** 函数 MUST 返回 `rep->data_length`，用于请求后续 variable payload 读取
#[test]
fn test_smb2_process_read_fixed_reply_with_read_data() {
    let mut fixed = vec![0_u8; (SMB2_READ_REPLY_SIZE as usize) & !1];
    fixed[0..2].copy_from_slice(&SMB2_READ_REPLY_SIZE.to_le_bytes());
    fixed[2] = (SMB2_HEADER_SIZE + 16) as u8;
    fixed[4..8].copy_from_slice(&5_u32.to_le_bytes());

    let (_parsed, needed) = Smb2ReadReply::process_reply_fixed(&fixed).unwrap();

    assert_eq!(needed, 5);
}

// Trace: `lib/smb2-cmd-read.c:smb2_process_read_fixed`
// Spec: smb2_process_read_fixed read reply fixed parser#READ 响应 fixed 字段非法
// - **GIVEN** structure size 大于 `SMB2_READ_REPLY_SIZE`，或有数据响应的 `data_offset` 不等于 `SMB2_HEADER_SIZE + 16`
// - **WHEN** 调用 `smb2_process_read_fixed`
// - **THEN** 函数 MUST 设置错误并返回 -1；若已分配 payload，MUST 清空 `pdu->payload` 并释放该 payload
#[test]
fn test_smb2_process_read_fixed_invalid_reply_fields() {
    let mut fixed = vec![0_u8; (SMB2_READ_REPLY_SIZE as usize) & !1];
    fixed[0..2].copy_from_slice(&(SMB2_READ_REPLY_SIZE + 1).to_le_bytes());

    assert!(matches!(
        Smb2ReadReply::process_reply_fixed(&fixed),
        Err(ReadCommandError::UnexpectedStructureSize { .. })
    ));
}

// Trace: `lib/smb2-cmd-read.c:smb2_process_read_variable`, `include/libsmb2-private.h:smb2_process_read_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_read_variable read reply variable parser#复制到调用方缓冲区
// - **GIVEN** fixed parser 已设置 `pdu->payload` 为 `smb2_read_reply`，且 `rep->data` 已指向调用方缓冲区
// - **WHEN** 调用 `smb2_process_read_variable`
// - **THEN** 函数 MUST 设置 `pdu->free_payload` 为释放回调，并将输入 iovector 中的 `rep->data_length` 字节复制到 `rep->data`
#[test]
fn test_smb2_process_read_variable_copies_to_caller_buffer() {
    let mut rep = Smb2ReadReply {
        data_length: 3,
        data: vec![0; 3],
        ..Smb2ReadReply::default()
    };

    rep.process_reply_variable(&[4, 5, 6]).unwrap();

    assert_eq!(rep.data, vec![4, 5, 6]);
}

// Trace: `lib/smb2-cmd-read.c:smb2_process_read_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_read_variable read reply variable parser#零拷贝绑定输入缓冲区
// - **GIVEN** fixed parser 已设置 reply payload，且 `rep->data` 为 `NULL`
// - **WHEN** 调用 `smb2_process_read_variable`
// - **THEN** 函数 MUST 将 `rep->data` 指向当前输入 iovector buffer，并返回 0
#[test]
fn test_smb2_process_read_variable_binds_input_buffer_zero_copy() {
    let mut rep = Smb2ReadReply {
        data_length: 2,
        data: Vec::new(),
        ..Smb2ReadReply::default()
    };

    rep.process_reply_variable(&[7, 8]).unwrap();

    assert_eq!(rep.data, vec![7, 8]);
}

// Trace: `lib/smb2-cmd-read.c:smb2_process_read_request_fixed`, `include/libsmb2-private.h:smb2_process_read_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_read_request_fixed read request fixed parser#无 channel info 的 READ 请求
// - **GIVEN** 输入 iovector 的 structure size 不大于 `SMB2_READ_REQUEST_SIZE`，请求长度不超过 `smb2->max_read_size`，且 `read_channel_info_length` 为 0
// - **WHEN** 调用 `smb2_process_read_request_fixed`
// - **THEN** 函数 MUST 分配 request payload、解码 flags、length、offset、file_id、minimum_count、channel 和 remaining_bytes，并返回 0
#[test]
fn test_smb2_process_read_request_fixed_without_channel_info() {
    let mut req = Smb2ReadRequest {
        flags: 3,
        length: 12,
        file_id: [2; SMB2_FD_SIZE],
        ..Smb2ReadRequest::default()
    };
    let fixed = req.encode_request(false, false).unwrap().remove(0);

    let (parsed, needed) = Smb2ReadRequest::process_request_fixed(fixed.as_slice(), 64).unwrap();

    assert_eq!(needed, 0);
    assert_eq!(parsed.flags, 3);
    assert_eq!(parsed.file_id, [2; SMB2_FD_SIZE]);
}

// Trace: `lib/smb2-cmd-read.c:smb2_process_read_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_read_request_fixed read request fixed parser#有 channel info 的 READ 请求
// - **GIVEN** `read_channel_info_length` 非零，读取长度不超过 `smb2->max_read_size`，且 channel info offset 不早于 SMB2 header 加 read request fixed 区域
// - **WHEN** 调用 `smb2_process_read_request_fixed`
// - **THEN** 函数 MUST 返回 `IOVREQ_OFFSET_READ + req->read_channel_info_length`，用于请求后续 variable payload 读取
#[test]
fn test_smb2_process_read_request_fixed_with_channel_info() {
    let mut fixed = vec![0_u8; (SMB2_READ_REQUEST_SIZE as usize) & !1];
    fixed[0..2].copy_from_slice(&SMB2_READ_REQUEST_SIZE.to_le_bytes());
    fixed[4..8].copy_from_slice(&1_u32.to_le_bytes());
    let channel_offset = (SMB2_HEADER_SIZE + fixed.len()) as u16;
    fixed[44..46].copy_from_slice(&channel_offset.to_le_bytes());
    fixed[46..48].copy_from_slice(&3_u16.to_le_bytes());

    let (_parsed, needed) = Smb2ReadRequest::process_request_fixed(&fixed, 64).unwrap();

    assert_eq!(needed, 3);
}

// Trace: `lib/smb2-cmd-read.c:smb2_process_read_request_fixed`
// Spec: smb2_process_read_request_fixed read request fixed parser#READ 请求 fixed 字段非法
// - **GIVEN** structure size 大于 `SMB2_READ_REQUEST_SIZE`，或 `req->length` 大于 `smb2->max_read_size`，或 channel info offset 与 fixed request 区域重叠
// - **WHEN** 调用 `smb2_process_read_request_fixed`
// - **THEN** 函数 MUST 设置错误并返回 -1；若已分配 request payload，MUST 清空 `pdu->payload` 并释放该 payload
#[test]
fn test_smb2_process_read_request_fixed_invalid_fields() {
    let mut fixed = vec![0_u8; (SMB2_READ_REQUEST_SIZE as usize) & !1];
    fixed[0..2].copy_from_slice(&SMB2_READ_REQUEST_SIZE.to_le_bytes());
    fixed[4..8].copy_from_slice(&99_u32.to_le_bytes());

    assert!(matches!(
        Smb2ReadRequest::process_request_fixed(&fixed, 10),
        Err(ReadCommandError::ReadLengthExceedsMaximum { .. })
    ));
}

// Trace: `lib/smb2-cmd-read.c:smb2_process_read_request_variable`, `include/libsmb2-private.h:smb2_process_read_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`
// Spec: smb2_process_read_request_variable read request variable parser#绑定 channel info 数据
// - **GIVEN** fixed parser 已设置 `pdu->payload` 为 `smb2_read_request`，且当前输入 iovector 包含 channel info bytes
// - **WHEN** 调用 `smb2_process_read_request_variable`
// - **THEN** 函数 MUST 将 `req->read_channel_info` 指向当前输入 iovector buffer，并返回 0
#[test]
fn test_smb2_process_read_request_variable_binds_channel_info_data() {
    let mut req = Smb2ReadRequest {
        read_channel_info_offset: (SMB2_HEADER_SIZE + ((SMB2_READ_REQUEST_SIZE as usize) & !1) + 2)
            as u16,
        read_channel_info_length: 3,
        ..Smb2ReadRequest::default()
    };

    req.process_request_variable(&[0, 0, 1, 2, 3]).unwrap();

    assert_eq!(req.read_channel_info, vec![1, 2, 3]);
}
