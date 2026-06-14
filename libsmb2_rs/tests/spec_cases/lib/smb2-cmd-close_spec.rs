use libsmb2_rs::include::smb2::smb2::Command;
use libsmb2_rs::lib::smb2_cmd_close::{
    smb2_cmd_close_async, smb2_cmd_close_reply_async, smb2_process_close_fixed,
    smb2_process_close_request_fixed, Smb2ClosePayload, Smb2CloseReply, Smb2CloseRequest,
    SMB2_CLOSE_REPLY_SIZE, SMB2_CLOSE_REQUEST_SIZE, SMB2_FD_SIZE,
};

fn file_id() -> [u8; SMB2_FD_SIZE] {
    [0x7b; SMB2_FD_SIZE]
}

// Trace: `lib/smb2-cmd-close.c:smb2_cmd_close_async`, `lib/smb2-cmd-close.c:smb2_encode_close_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_close_async`
// Spec: smb2_cmd_close_async close request PDU construction#successful close request PDU
// - **GIVEN** 调用方提供有效的 `smb2_context`、`smb2_close_request`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_close_async`
// - **THEN** 返回值 MUST 是包含 `SMB2_CLOSE` command、24-byte fixed request payload、flags 和 file_id 字段以及 64-bit padding 后输出向量的 PDU
#[test]
fn test_smb2_cmd_close_successful_close_request_pdu() {
    let req = Smb2CloseRequest::new(0x0001, file_id());
    let pdu = smb2_cmd_close_async(&req, None).unwrap();

    assert_eq!(pdu.header.command, Command::Close as u16);
    assert_eq!(pdu.out.vectors.len(), 1);
    assert_eq!(
        pdu.out.vectors[0].buf.len(),
        SMB2_CLOSE_REQUEST_SIZE as usize
    );
    let decoded = Smb2CloseRequest::decode_fixed(&pdu.out.vectors[0].buf).unwrap();
    assert_eq!(decoded, req);
}

// Trace: `lib/smb2-cmd-close.c:smb2_cmd_close_reply_async`, `lib/smb2-cmd-close.c:smb2_encode_close_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_close_reply_async`
// Spec: smb2_cmd_close_reply_async close reply PDU construction#successful close reply PDU
// - **GIVEN** 调用方提供有效的 `smb2_context`、`smb2_close_reply`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_close_reply_async`
// - **THEN** 返回值 MUST 是包含 `SMB2_CLOSE` command、60-byte fixed reply payload、flags、时间戳、allocation size、EOF 和 file attributes 字段以及 64-bit padding 后输出向量的 PDU
#[test]
fn test_smb2_cmd_close_successful_close_reply_pdu() {
    let rep = Smb2CloseReply {
        flags: 1,
        creation_time: 2,
        last_access_time: 3,
        last_write_time: 4,
        change_time: 5,
        allocation_size: 6,
        end_of_file: 7,
        file_attributes: 8,
    };
    let pdu = smb2_cmd_close_reply_async(&rep, None).unwrap();

    assert_eq!(pdu.header.command, Command::Close as u16);
    assert_eq!(pdu.out.vectors.len(), 1);
    assert_eq!(pdu.out.vectors[0].buf.len(), SMB2_CLOSE_REPLY_SIZE as usize);
    let decoded = Smb2CloseReply::decode_fixed(&pdu.out.vectors[0].buf).unwrap();
    assert_eq!(decoded, rep);
}

// Trace: `lib/smb2-cmd-close.c:smb2_process_close_fixed`
// Spec: smb2_process_close_fixed close reply fixed payload parsing#invalid close reply fixed payload size
// - **GIVEN** close reply fixed payload 的 struct size 不是 `SMB2_CLOSE_REPLY_SIZE` 或输入 iovec 长度不匹配 `(struct_size & 0xfffe)`
// - **WHEN** 调用 `smb2_process_close_fixed`
// - **THEN** 函数 MUST 设置错误消息并返回 `-1`，且不分配 close reply payload
#[test]
fn test_smb2_cmd_close_invalid_close_reply_fixed_payload_size() {
    assert!(smb2_process_close_fixed(&(SMB2_CLOSE_REPLY_SIZE + 2).to_le_bytes()).is_err());
}

// Trace: `lib/smb2-cmd-close.c:smb2_process_close_request_fixed`, `include/libsmb2-private.h:smb2_process_close_request_fixed`
// Spec: smb2_process_close_request_fixed close request fixed payload parsing#valid close request fixed payload
// - **GIVEN** `smb2->in` 的最后一个 iovec 包含 struct size `SMB2_CLOSE_REQUEST_SIZE` 且长度匹配 `(struct_size & 0xfffe)`
// - **WHEN** 调用 `smb2_process_close_request_fixed`
// - **THEN** 函数 MUST 返回 `0`，分配 close request payload，并解码 flags 和 file_id 字段
#[test]
fn test_smb2_cmd_close_valid_close_request_fixed_payload() {
    let req = Smb2CloseRequest::new(0x0001, file_id());
    let payload = smb2_process_close_request_fixed(&req.encode_fixed().unwrap()).unwrap();

    assert!(matches!(payload, Smb2ClosePayload::Request(decoded) if decoded == req));
}

// Trace: `lib/smb2-cmd-close.c:smb2_process_close_request_fixed`
// Spec: smb2_process_close_request_fixed close request fixed payload parsing#invalid close request fixed payload size
// - **GIVEN** close request fixed payload 的 struct size 不是 `SMB2_CLOSE_REQUEST_SIZE` 或输入 iovec 长度不匹配 `(struct_size & 0xfffe)`
// - **WHEN** 调用 `smb2_process_close_request_fixed`
// - **THEN** 函数 MUST 设置错误消息并返回 `-1`，且不分配 close request payload
#[test]
fn test_smb2_cmd_close_invalid_close_request_fixed_payload_size() {
    assert!(
        smb2_process_close_request_fixed(&(SMB2_CLOSE_REQUEST_SIZE + 2).to_le_bytes()).is_err()
    );
}

// Trace: `lib/smb2-cmd-close.c:smb2_process_close_fixed`, `include/libsmb2-private.h:smb2_process_close_fixed`
// Spec: smb2_process_close_fixed close reply fixed payload parsing#valid close reply fixed payload
// - **GIVEN** `smb2->in` 的最后一个 iovec 包含 struct size `SMB2_CLOSE_REPLY_SIZE` 且长度匹配 `(struct_size & 0xfffe)`
// - **WHEN** 调用 `smb2_process_close_fixed`
// - **THEN** 函数 MUST 返回 `0`，分配 close reply payload，并解码 flags、四个时间戳、allocation size、EOF 和 file attributes 字段
#[test]
fn test_smb2_cmd_close_valid_close_reply_fixed_payload() {
    let rep = Smb2CloseReply {
        flags: 1,
        creation_time: 2,
        last_access_time: 3,
        last_write_time: 4,
        change_time: 5,
        allocation_size: 6,
        end_of_file: 7,
        file_attributes: 8,
    };
    let payload = smb2_process_close_fixed(&rep.encode_fixed().unwrap()).unwrap();

    assert!(matches!(payload, Smb2ClosePayload::Reply(decoded) if decoded == rep));
}
