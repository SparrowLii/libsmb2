use libsmb2_rs::lib::smb2_cmd_logoff::{self as logoff, Smb2LogoffPayload};

// Trace: `lib/smb2-cmd-logoff.c:smb2_cmd_logoff_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_logoff_async`, `include/smb2/smb2.h:SMB2_LOGOFF_REQUEST_SIZE`, `lib/libsmb2.c:disconnect_cb_1`
// Spec: smb2_cmd_logoff_async build logoff request PDU#构造 logoff 请求
// - **GIVEN** 调用方提供 `struct smb2_context *smb2`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_logoff_async(smb2, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 `SMB2_LOGOFF` command，并将 fixed command data 的 structure size 写为 `SMB2_LOGOFF_REQUEST_SIZE`
#[test]
fn test_smb2_cmd_logoff_build_logoff_request() {
    let pdu = logoff::smb2_cmd_logoff_async(None).unwrap();
    assert_eq!(pdu.header.command, logoff::SMB2_LOGOFF);
    assert_eq!(
        &pdu.out.vectors[0].buf[0..2],
        &logoff::SMB2_LOGOFF_REQUEST_SIZE.to_le_bytes()
    );
}

// Trace: `lib/smb2-cmd-logoff.c:smb2_cmd_logoff_reply_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_logoff_reply_async`, `include/smb2/smb2.h:SMB2_LOGOFF_REPLY_SIZE`, `lib/libsmb2.c:smb2_logoff_request_cb`
// Spec: smb2_cmd_logoff_reply_async build logoff reply PDU#构造 logoff 响应
// - **GIVEN** server logoff handler 接受请求并需要发送成功响应
// - **WHEN** 调用 `smb2_cmd_logoff_reply_async(smb2, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 `SMB2_LOGOFF` command，并将 fixed command data 的 structure size 写为 `SMB2_LOGOFF_REPLY_SIZE`
#[test]
fn test_smb2_cmd_logoff_build_logoff_reply() {
    let pdu = logoff::smb2_cmd_logoff_reply_async(None).unwrap();
    assert_eq!(pdu.header.command, logoff::SMB2_LOGOFF);
    assert_eq!(
        &pdu.out.vectors[0].buf[0..2],
        &logoff::SMB2_LOGOFF_REPLY_SIZE.to_le_bytes()
    );
}

// Trace: `lib/smb2-cmd-logoff.c:smb2_process_logoff_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_logoff_fixed accept empty logoff reply payload#处理 logoff reply fixed payload
// - **GIVEN** PDU dispatch 在客户端 reply 路径收到 `SMB2_LOGOFF` command
// - **WHEN** 调用 `smb2_process_logoff_fixed(smb2, pdu)`
// - **THEN** 函数 MUST 返回 `0` 且不设置 PDU payload
#[test]
fn test_smb2_cmd_logoff_process_reply_fixed_payload() {
    let fixed = logoff::Smb2LogoffReply::new().encode_fixed().unwrap();
    assert!(matches!(
        logoff::smb2_process_logoff_fixed(&fixed).unwrap(),
        Smb2LogoffPayload::Reply(_)
    ));
}

// Trace: `lib/smb2-cmd-logoff.c:smb2_process_logoff_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_logoff_request_fixed validate and attach logoff request payload#接受合法 logoff request fixed payload
// - **GIVEN** 当前输入 iovector 的 structure size 字段和长度满足 LOGOFF request fixed payload 检查
// - **WHEN** 调用 `smb2_process_logoff_request_fixed(smb2, pdu)`
// - **THEN** 函数 MUST 分配 `struct smb2_logoff_request` 并将其保存到 `pdu->payload` 后返回 `0`
#[test]
fn test_smb2_cmd_logoff_accept_valid_request_fixed_payload() {
    let fixed = logoff::Smb2LogoffRequest::new().encode_fixed().unwrap();
    assert!(matches!(
        logoff::smb2_process_logoff_request_fixed(&fixed).unwrap(),
        Smb2LogoffPayload::Request(_)
    ));
}

// Trace: `lib/smb2-cmd-logoff.c:smb2_process_logoff_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_logoff_request_fixed validate and attach logoff request payload#拒绝不匹配的 logoff request fixed payload 大小
// - **GIVEN** 当前输入 iovector 的 structure size 字段或长度不满足实现中的 fixed payload 检查
// - **WHEN** 调用 `smb2_process_logoff_request_fixed(smb2, pdu)`
// - **THEN** 函数 MUST 设置错误信息并返回 `-1`
#[test]
fn test_smb2_cmd_logoff_reject_invalid_request_fixed_size() {
    assert!(logoff::smb2_process_logoff_request_fixed(&[0, 0]).is_err());
}
