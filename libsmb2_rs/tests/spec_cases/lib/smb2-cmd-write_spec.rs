use libsmb2_rs::lib::smb2_cmd_write::{
    self as write, Smb2WriteError, Smb2WriteReply, Smb2WriteRequest, WriteBufferOwnership,
    WriteEncodeOptions, SMB2_FD_SIZE, SMB2_WRITE_REPLY_SIZE, SMB2_WRITE_REQUEST_SIZE,
};

// Trace: `lib/smb2-cmd-write.c:smb2_cmd_write_async`, `lib/smb2-cmd-write.c:smb2_encode_write_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_write_async`
// Spec: smb2_cmd_write_async builds write request PDU#write request PDU is encoded successfully
// - **GIVEN** `smb2_allocate_pdu`、固定区编码、padding 和 payload iovec 追加均成功，且调用方提供 `struct smb2_write_request`
// - **WHEN** 调用 `smb2_cmd_write_async(smb2, req, pass_buf_ownership, cb, cb_data)`
// - **THEN** 返回的 PDU 包含 SMB2 WRITE 固定区、按 `req->length` 引用的 payload buffer，并在 `pass_buf_ownership` 非零时将 payload iovec 释放回调设置为 `free`
#[test]
fn test_smb2_cmd_write_request_pdu_is_encoded_successfully() {
    let mut request = Smb2WriteRequest::new([0x44; SMB2_FD_SIZE], 0x1122, &[1, 2, 3]);
    request.flags = 0x5;

    let pdu = write::smb2_cmd_write_async(
        WriteEncodeOptions::default(),
        request,
        WriteBufferOwnership::Borrowed,
    )
    .unwrap();

    assert_eq!(pdu.credit_charge, 1);
    assert_eq!(pdu.buffer_ownership, WriteBufferOwnership::Borrowed);
    assert_eq!(
        u16::from_le_bytes(pdu.out[0][0..2].try_into().unwrap()),
        SMB2_WRITE_REQUEST_SIZE
    );
    assert_eq!(&pdu.out[0][16..32], &[0x44; SMB2_FD_SIZE]);
    assert_eq!(pdu.out[1], vec![1, 2, 3]);
}

// Trace: `lib/smb2-cmd-write.c:smb2_cmd_write_async`
// Spec: smb2_cmd_write_async builds write request PDU#multi-credit write updates credit charge
// - **GIVEN** `smb2->supports_multi_credit` 为真且 WRITE PDU 构造成功
// - **WHEN** `smb2_cmd_write_async` 根据 `req->length` 完成 payload 追加
// - **THEN** 系统 MUST 将 `pdu->header.credit_charge` 设置为 `(req->length - 1) / 65536 + 1`
#[test]
fn test_smb2_cmd_write_multi_credit_updates_credit_charge() {
    let data = vec![0xaa; 131_073];
    let request = Smb2WriteRequest::new([0; SMB2_FD_SIZE], 0, &data);

    let pdu = write::smb2_cmd_write_async(
        WriteEncodeOptions {
            supports_multi_credit: true,
            passthrough: false,
        },
        request,
        WriteBufferOwnership::Transferred,
    )
    .unwrap();

    assert_eq!(pdu.credit_charge, 3);
    assert_eq!(pdu.request.length, 131_073);
    assert_eq!(pdu.buffer_ownership, WriteBufferOwnership::Transferred);
}

// Trace: `lib/smb2-cmd-write.c:smb2_cmd_write_reply_async`, `lib/smb2-cmd-write.c:smb2_encode_write_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_write_reply_async`
// Spec: smb2_cmd_write_reply_async builds write reply PDU#write reply PDU is encoded successfully
// - **GIVEN** PDU 分配、reply 固定区编码和 padding 均成功，且调用方提供 `struct smb2_write_reply`
// - **WHEN** 调用 `smb2_cmd_write_reply_async(smb2, rep, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 包含 WRITE reply 固定区，其中偏移 0 为 `SMB2_WRITE_REPLY_SIZE`、偏移 4 为 `rep->count`、偏移 8 为 `rep->remaining`
#[test]
fn test_smb2_cmd_write_reply_pdu_is_encoded_successfully() {
    let reply = Smb2WriteReply {
        count: 7,
        remaining: 3,
    };
    let encoded = write::encode_write_reply_fixed(write::smb2_cmd_write_reply_async(reply));

    assert_eq!(
        u16::from_le_bytes(encoded[0..2].try_into().unwrap()),
        SMB2_WRITE_REPLY_SIZE
    );
    assert_eq!(u32::from_le_bytes(encoded[4..8].try_into().unwrap()), 7);
    assert_eq!(u32::from_le_bytes(encoded[8..12].try_into().unwrap()), 3);
}

// Trace: `lib/smb2-cmd-write.c:smb2_process_write_fixed`, `include/libsmb2-private.h:smb2_process_write_fixed`
// Spec: smb2_process_write_fixed parses write reply fixed area#valid write reply fixed area populates payload
// - **GIVEN** 当前输入 iovec 的结构大小等于 `SMB2_WRITE_REPLY_SIZE` 且偶数化结构大小等于 iovec 长度
// - **WHEN** `smb2_process_write_fixed(smb2, pdu)` 处理该固定区
// - **THEN** 系统 MUST 分配 `struct smb2_write_reply`，将其保存到 `pdu->payload`，并从偏移 4 和 8 解析 `count` 与 `remaining`
#[test]
fn test_smb2_cmd_write_valid_write_reply_fixed_area_populates_payload() {
    let fixed = write::encode_write_reply_fixed(Smb2WriteReply {
        count: 9,
        remaining: 4,
    });

    let reply = write::smb2_process_write_fixed(&fixed).unwrap();

    assert_eq!(reply.count, 9);
    assert_eq!(reply.remaining, 4);
}

// Trace: `lib/smb2-cmd-write.c:smb2_process_write_fixed`
// Spec: smb2_process_write_fixed parses write reply fixed area#invalid write reply fixed area is rejected
// - **GIVEN** 当前输入 iovec 的结构大小不是 `SMB2_WRITE_REPLY_SIZE` 或偶数化结构大小不等于 iovec 长度
// - **WHEN** `smb2_process_write_fixed(smb2, pdu)` 处理该固定区
// - **THEN** 系统 MUST 设置错误消息并返回 `-1`
#[test]
fn test_smb2_cmd_write_invalid_write_reply_fixed_area_is_rejected() {
    let mut fixed = write::encode_write_reply_fixed(Smb2WriteReply::default());
    fixed[0..2].copy_from_slice(&(SMB2_WRITE_REPLY_SIZE + 2).to_le_bytes());

    assert!(matches!(
        write::smb2_process_write_fixed(&fixed),
        Err(Smb2WriteError::InvalidStructureSize { .. })
    ));
}

// Trace: `lib/smb2-cmd-write.c:smb2_process_write_request_fixed`, `include/libsmb2-private.h:smb2_process_write_request_fixed`
// Spec: smb2_process_write_request_fixed parses write request fixed area#valid write request fixed area populates request
// - **GIVEN** 当前输入 iovec 的结构大小不大于 `SMB2_WRITE_REQUEST_SIZE`
// - **WHEN** `smb2_process_write_request_fixed(smb2, pdu)` 处理该固定区
// - **THEN** 系统 MUST 分配 `struct smb2_write_request`，保存到 `pdu->payload`，解析 data offset、length、file id、channel info、flags 等字段，并将 `req->buf` 初始化为 `NULL`
#[test]
fn test_smb2_cmd_write_valid_write_request_fixed_area_populates_request() {
    let request = Smb2WriteRequest::new([0x33; SMB2_FD_SIZE], 0x1234, &[8, 9]);
    let fixed = write::encode_write_request_fixed(WriteEncodeOptions::default(), &request).unwrap();

    let parsed = write::smb2_process_write_request_fixed(&fixed).unwrap();

    assert_eq!(parsed.file_id, [0x33; SMB2_FD_SIZE]);
    assert_eq!(parsed.offset, 0x1234);
    assert_eq!(parsed.length, 2);
}

// Trace: `lib/smb2-cmd-write.c:smb2_process_write_request_fixed`, `lib/smb2-cmd-write.c:IOVREQ_OFFSET_WRITE`
// Spec: smb2_process_write_request_fixed parses write request fixed area#write request variable length is reported
// - **GIVEN** WRITE request 固定区解析成功
// - **WHEN** `req->length` 或 `req->write_channel_info_length` 非零
// - **THEN** 系统 MUST 返回 channel info 偏移、channel info padding 和 write data 长度组合出的变量区需求；若二者均为零则返回 `0`
#[test]
fn test_smb2_cmd_write_request_variable_length_is_reported() {
    let mut request = Smb2WriteRequest::new([0; SMB2_FD_SIZE], 0, &[1, 2]);
    request.write_channel_info_offset = 128;
    request.write_channel_info_length = 3;

    assert_eq!(request.expected_variable_len().unwrap(), 16 + 8 + 2);
}

// Trace: `lib/smb2-cmd-write.c:smb2_process_write_request_fixed`
// Spec: smb2_process_write_request_fixed parses write request fixed area#overlapping channel info is rejected
// - **GIVEN** `req->write_channel_info_length` 非零且 `req->write_channel_info_offset` 小于 SMB2 header 加 WRITE request 固定区长度
// - **WHEN** `smb2_process_write_request_fixed(smb2, pdu)` 验证 channel info 位置
// - **THEN** 系统 MUST 设置错误消息，清空 `pdu->payload`，释放临时 request，并返回 `-1`
#[test]
fn test_smb2_cmd_write_overlapping_channel_info_is_rejected() {
    let mut request = Smb2WriteRequest::new([0; SMB2_FD_SIZE], 0, &[1]);
    request.write_channel_info_offset = 65;
    request.write_channel_info_length = 1;
    let fixed = write::encode_write_request_fixed(WriteEncodeOptions::default(), &request).unwrap();

    assert_eq!(
        write::smb2_process_write_request_fixed(&fixed),
        Err(Smb2WriteError::ChannelInfoOverlapsRequest)
    );
}

// Trace: `lib/smb2-cmd-write.c:smb2_process_write_request_variable`, `lib/smb2-cmd-write.c:IOVREQ_OFFSET_WRITE`, `include/libsmb2-private.h:smb2_process_write_request_variable`
// Spec: smb2_process_write_request_variable maps write request buffers#variable area maps channel info and write data
// - **GIVEN** `pdu->payload` 指向已由固定区解析创建的 `struct smb2_write_request`
// - **WHEN** `smb2_process_write_request_variable(smb2, pdu)` 处理当前输入 iovec
// - **THEN** 系统 MUST 将 `req->write_channel_info` 指向 `IOVREQ_OFFSET_WRITE` 计算出的变量区起点，并将 `req->buf` 指向 channel info 经过 64-bit padding 后的位置
#[test]
fn test_smb2_cmd_write_variable_area_maps_channel_info_and_write_data() {
    let mut request = Smb2WriteRequest::new([0; SMB2_FD_SIZE], 0, &[0; 2]);
    request.write_channel_info_offset = 128;
    request.write_channel_info_length = 3;
    request.length = 2;
    let mut variable = vec![0; 26];
    variable[16..19].copy_from_slice(&[1, 2, 3]);
    variable[24..26].copy_from_slice(&[4, 5]);

    let mapped = write::smb2_process_write_request_variable(&request, &variable).unwrap();

    assert_eq!(mapped.write_channel_info, &[1, 2, 3]);
    assert_eq!(mapped.buffer, &[4, 5]);
}
