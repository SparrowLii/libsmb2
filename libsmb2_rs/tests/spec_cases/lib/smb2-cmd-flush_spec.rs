use libsmb2_rs::include::smb2::smb2::Command;
use libsmb2_rs::lib::smb2_cmd_flush::{
    smb2_cmd_flush_async, smb2_cmd_flush_reply_async, smb2_process_flush_fixed,
    smb2_process_flush_request_fixed, Smb2FlushPayload, Smb2FlushRequest, SMB2_FD_SIZE,
    SMB2_FLUSH_REPLY_SIZE, SMB2_FLUSH_REQUEST_SIZE,
};

fn fixed(size: u16, len: usize) -> Vec<u8> {
    let mut buf = vec![0; len];
    buf[0..2].copy_from_slice(&size.to_le_bytes());
    buf
}

fn file_id() -> [u8; SMB2_FD_SIZE] {
    [0x5a; SMB2_FD_SIZE]
}

// Trace: `lib/smb2-cmd-flush.c:smb2_cmd_flush_async`, `lib/smb2-cmd-flush.c:smb2_encode_flush_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_flush_async`, `lib/libsmb2.c:smb2_fsync_async`
// Spec: smb2_cmd_flush_async 构造客户端 FLUSH PDU#成功编码 flush request
// - **GIVEN** 调用方提供有效 `smb2_context`、可分配 PDU、可添加 iovector、可完成 64-bit padding，并传入包含 `file_id` 的 `struct smb2_flush_request`
// - **WHEN** 调用 `smb2_cmd_flush_async(smb2, req, cb, cb_data)`
// - **THEN** 返回值 MUST 为非空 PDU，PDU 命令 MUST 为 `SMB2_FLUSH`，输出固定区 MUST 记录 `SMB2_FLUSH_REQUEST_SIZE` 且包含 `req->file_id`
#[test]
fn test_smb2_cmd_flush_success_encode_flush_request() {
    let req = Smb2FlushRequest::new(file_id());
    let pdu = smb2_cmd_flush_async(&req, None).expect("flush request pdu");

    assert_eq!(pdu.header.command, Command::Flush as u16);
    assert_eq!(
        &pdu.out.vectors[0].buf[0..2],
        &SMB2_FLUSH_REQUEST_SIZE.to_le_bytes()
    );
    assert_eq!(&pdu.out.vectors[0].buf[8..24], &file_id());
}

// Trace: `lib/smb2-cmd-flush.c:smb2_cmd_flush_reply_async`, `lib/smb2-cmd-flush.c:smb2_encode_flush_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_flush_reply_async`, `lib/libsmb2.c:smb2_flush_request_cb`
// Spec: smb2_cmd_flush_reply_async 构造服务端 FLUSH reply PDU#成功编码 flush reply
// - **GIVEN** 服务端 flush handler 成功并需要构造 FLUSH reply，且 PDU 分配、iovector 添加和 padding 均成功
// - **WHEN** 调用 `smb2_cmd_flush_reply_async(smb2, cb, cb_data)`
// - **THEN** 返回值 MUST 为非空 PDU，PDU 命令 MUST 为 `SMB2_FLUSH`，reply 固定区 MUST 记录 `SMB2_FLUSH_REPLY_SIZE`
#[test]
fn test_smb2_cmd_flush_success_encode_flush_reply() {
    let pdu = smb2_cmd_flush_reply_async(None).expect("flush reply pdu");

    assert_eq!(pdu.header.command, Command::Flush as u16);
    assert_eq!(pdu.out.vectors[0].buf, fixed(SMB2_FLUSH_REPLY_SIZE, 4));
}

// Trace: `lib/smb2-cmd-flush.c:smb2_process_flush_fixed`, `include/libsmb2-private.h:smb2_process_flush_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_flush_fixed 校验 FLUSH reply 固定区#Reply 固定区大小有效
// - **GIVEN** `smb2->in` 的最后一个 iovector 起始 `StructureSize` 为 `SMB2_FLUSH_REPLY_SIZE`，且 `(StructureSize & 0xfffe)` 等于 iovector 长度
// - **WHEN** 调用 `smb2_process_flush_fixed(smb2, pdu)`
// - **THEN** 函数 MUST 返回 `0`，且不向 PDU payload 附加额外 flush reply 数据
#[test]
fn test_smb2_cmd_flush_reply_fixed_size_valid() {
    assert!(matches!(
        smb2_process_flush_fixed(&fixed(SMB2_FLUSH_REPLY_SIZE, 4)),
        Ok(Smb2FlushPayload::Reply(_))
    ));
}

// Trace: `lib/smb2-cmd-flush.c:smb2_process_flush_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_flush_fixed 校验 FLUSH reply 固定区#Reply 固定区大小无效
// - **GIVEN** `StructureSize` 不等于 `SMB2_FLUSH_REPLY_SIZE` 或 `(StructureSize & 0xfffe)` 不等于 iovector 长度
// - **WHEN** 调用 `smb2_process_flush_fixed(smb2, pdu)`
// - **THEN** 函数 MUST 调用 `smb2_set_error` 记录 unexpected flush reply size，并返回 `-1`
#[test]
fn test_smb2_cmd_flush_reply_fixed_size_invalid() {
    assert!(smb2_process_flush_fixed(&fixed(SMB2_FLUSH_REPLY_SIZE + 2, 2)).is_err());
    assert!(smb2_process_flush_fixed(&fixed(SMB2_FLUSH_REPLY_SIZE, 2)).is_err());
}

// Trace: `lib/smb2-cmd-flush.c:smb2_process_flush_request_fixed`, `include/libsmb2-private.h:smb2_process_flush_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_flush_request_fixed 解析 FLUSH request 固定区#Request 固定区大小有效
// - **GIVEN** `smb2->in` 的最后一个 iovector 起始 `StructureSize` 为 `SMB2_FLUSH_REQUEST_SIZE`，`(StructureSize & 0xfffe)` 等于 iovector 长度，且请求对象分配成功
// - **WHEN** 调用 `smb2_process_flush_request_fixed(smb2, pdu)`
// - **THEN** 函数 MUST 返回 `0`，`pdu->payload` MUST 指向新分配的 `struct smb2_flush_request`，且其 `file_id` MUST 等于输入缓冲区偏移 8 的 `SMB2_FD_SIZE` 字节
#[test]
fn test_smb2_cmd_flush_request_fixed_size_valid() {
    let mut buf = fixed(SMB2_FLUSH_REQUEST_SIZE, 24);
    buf[8..24].copy_from_slice(&file_id());

    let payload = smb2_process_flush_request_fixed(&buf).expect("flush request payload");

    assert!(matches!(payload, Smb2FlushPayload::Request(req) if req.file_id == file_id()));
}

// Trace: `lib/smb2-cmd-flush.c:smb2_process_flush_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_flush_request_fixed 解析 FLUSH request 固定区#Request 固定区大小无效或分配失败
// - **GIVEN** `StructureSize` 不等于 `SMB2_FLUSH_REQUEST_SIZE`、偶数化长度不匹配，或 `struct smb2_flush_request` 分配失败
// - **WHEN** 调用 `smb2_process_flush_request_fixed(smb2, pdu)`
// - **THEN** 函数 MUST 返回 `-1`，大小无效时 MUST 记录 unexpected flush request size，分配失败时 MUST 记录 failed to allocate flush request
#[test]
fn test_smb2_cmd_flush_request_fixed_size_invalid_or_allocation_failure() {
    assert!(smb2_process_flush_request_fixed(&fixed(SMB2_FLUSH_REQUEST_SIZE + 2, 24)).is_err());
    assert!(smb2_process_flush_request_fixed(&fixed(SMB2_FLUSH_REQUEST_SIZE, 22)).is_err());
}
