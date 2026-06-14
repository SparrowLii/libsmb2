use libsmb2_rs::lib::smb2_cmd_error::{
    smb2_cmd_error_reply_async, smb2_process_error_fixed, smb2_process_error_variable,
    Smb2ErrorPayload, Smb2ErrorReply, SMB2_ERROR_REPLY_SIZE,
};

// Trace: `lib/smb2-cmd-error.c:smb2_cmd_error_reply_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_error_reply_async`
// Spec: smb2_cmd_error_reply_async build SMB2 error response PDU#Successful error reply construction
// - **GIVEN** 调用方提供有效 `smb2_context`、`smb2_error_reply`、causing command、status、回调和回调数据。
// - **WHEN** 调用方调用 `smb2_cmd_error_reply_async(smb2, rep, causing_command, status, cb, cb_data)`，且 PDU 分配、error reply 编码和 64-bit padding 均成功。
// - **THEN** 函数返回新建 PDU，PDU header status 等于输入 status，输出 iovec 包含 `SMB2_ERROR_REPLY_SIZE`、`rep->error_context_count` 和 `rep->byte_count` 字段。
#[test]
fn test_smb2_cmd_error_successful_error_reply_construction() {
    let rep = Smb2ErrorReply::new(2, 4);
    let pdu = smb2_cmd_error_reply_async(&rep, 0x05, 0xc000_000d, None).unwrap();

    assert_eq!(pdu.header.status, 0xc000_000d);
    assert_eq!(pdu.header.command, 0x05);
    assert_eq!(
        &pdu.out.vectors[0].buf[0..2],
        &SMB2_ERROR_REPLY_SIZE.to_le_bytes()
    );
    assert_eq!(pdu.out.vectors[0].buf[2], 2);
    assert_eq!(&pdu.out.vectors[0].buf[4..8], &4_u32.to_le_bytes());
}

// Trace: `lib/smb2-cmd-error.c:smb2_process_error_fixed`, `include/libsmb2-private.h:smb2_process_error_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_error_fixed validate and decode fixed error reply#Valid fixed error payload
// - **GIVEN** 当前输入 iovec 的固定区域包含 struct size `SMB2_ERROR_REPLY_SIZE`，且 `(struct_size & 0xfffe)` 等于 iovec length。
// - **WHEN** `lib/pdu.c:smb2_process_reply_payload_fixed` 分派调用 `smb2_process_error_fixed(smb2, pdu)`。
// - **THEN** 函数分配 `struct smb2_error_reply` 到 `pdu->payload`，从 offset 2 解码 `error_context_count`，从 offset 4 解码 `byte_count`，并返回 `byte_count`。
#[test]
fn test_smb2_cmd_error_valid_fixed_error_payload() {
    let rep = Smb2ErrorReply::new(3, 5);
    let payload = smb2_process_error_fixed(&rep.encode_fixed().unwrap()).unwrap();

    assert!(
        matches!(payload, Smb2ErrorPayload::Fixed(decoded) if decoded.error_context_count == 3 && decoded.byte_count == 5)
    );
}

// Trace: `lib/smb2-cmd-error.c:smb2_process_error_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_error_fixed validate and decode fixed error reply#Invalid fixed error payload size
// - **GIVEN** 当前输入 iovec 的 struct size 不等于 `SMB2_ERROR_REPLY_SIZE`，或 `(struct_size & 0xfffe)` 不等于 iovec length。
// - **WHEN** `smb2_process_error_fixed(smb2, pdu)` 解析该 fixed payload。
// - **THEN** 函数设置上下文错误消息并返回 `-1`，且不分配 error reply payload。
#[test]
fn test_smb2_cmd_error_invalid_fixed_error_payload_size() {
    assert!(smb2_process_error_fixed(&(SMB2_ERROR_REPLY_SIZE + 2).to_le_bytes()).is_err());
}

// Trace: `lib/smb2-cmd-error.c:smb2_process_error_variable`, `include/libsmb2-private.h:smb2_process_error_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_error_variable attach variable error data#Variable error payload attachment
// - **GIVEN** `pdu->payload` 已由 fixed 阶段设置为 `struct smb2_error_reply`，且当前输入 iovec 表示 error reply variable payload。
// - **WHEN** `lib/pdu.c:smb2_process_reply_payload_variable` 分派调用 `smb2_process_error_variable(smb2, pdu)`。
// - **THEN** 函数将 `rep->error_data` 设置为 `&iov->buf[0]`，并返回 `0`。
#[test]
fn test_smb2_cmd_error_variable_error_payload_attachment() {
    let rep = Smb2ErrorReply::new(0, 3);
    let payload = smb2_process_error_variable(rep, &[1, 2, 3]);

    assert!(
        matches!(payload, Smb2ErrorPayload::Variable(decoded) if decoded.error_data == vec![1, 2, 3])
    );
}
