use libsmb2_rs::include::smb2::smb2::Command;
use libsmb2_rs::lib::smb2_cmd_session_setup::{
    self as session, SessionSetupError, Smb2SessionSetupReply, Smb2SessionSetupRequest,
    SMB2_SESSION_SETUP_REPLY_SIZE, SMB2_SESSION_SETUP_REQUEST_SIZE,
};

// Trace: `lib/smb2-cmd-session-setup.c:smb2_cmd_session_setup_async`, `lib/smb2-cmd-session-setup.c:smb2_encode_session_setup_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_session_setup_async`
// Spec: smb2_cmd_session_setup_async request PDU construction#成功构造 session setup request
// - **GIVEN** 调用方提供有效的 `smb2_context`、`smb2_session_setup_request`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_session_setup_async`
// - **THEN** 返回的 PDU MUST 使用 `SMB2_SESSION_SETUP` 命令，写入 request fixed fields，追加 security buffer，并完成 64-bit padding
#[test]
fn test_smb2_cmd_session_setup_successful_request() {
    let req = Smb2SessionSetupRequest::new(1, 2, 3, 4, 5, vec![9, 8, 7]);

    let pdu = session::smb2_cmd_session_setup_async(&req).unwrap();

    assert_eq!(pdu.command, Command::SessionSetup);
    assert_eq!(
        u16::from_le_bytes(pdu.fixed[0..2].try_into().unwrap()),
        SMB2_SESSION_SETUP_REQUEST_SIZE
    );
    assert_eq!(pdu.security_buffer, vec![9, 8, 7]);
}

// Trace: `lib/smb2-cmd-session-setup.c:smb2_cmd_session_setup_async`
// Spec: smb2_cmd_session_setup_async request PDU construction#request 编码失败释放 PDU
// - **GIVEN** PDU 已分配但 request 编码或 padding 失败
// - **WHEN** `smb2_cmd_session_setup_async` 处理失败返回
// - **THEN** 函数 MUST 释放已分配 PDU 并返回 `NULL`
#[test]
fn test_smb2_cmd_session_setup_request_encoding_failure_releases_pdu() {
    let req = Smb2SessionSetupRequest::new(0, 0, 0, 0, 0, vec![0; usize::from(u16::MAX) + 1]);

    assert!(matches!(
        session::smb2_cmd_session_setup_async(&req),
        Err(SessionSetupError::SecurityBufferTooLarge { .. })
    ));
}

// Trace: `lib/smb2-cmd-session-setup.c:smb2_cmd_session_setup_reply_async`, `lib/smb2-cmd-session-setup.c:smb2_encode_session_setup_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_session_setup_reply_async`
// Spec: smb2_cmd_session_setup_reply_async reply PDU construction#成功构造 session setup reply
// - **GIVEN** 调用方提供有效的 `smb2_session_setup_reply`
// - **WHEN** 调用 `smb2_cmd_session_setup_reply_async`
// - **THEN** 返回的 PDU MUST 包含 fixed reply header，设置 `security_buffer_offset` 为 fixed header 后的 SMB2 payload offset，并对变长 security buffer 使用 32-bit padding 后再进行 64-bit PDU padding
#[test]
fn test_smb2_cmd_session_setup_successful_reply() {
    let mut reply = Smb2SessionSetupReply::new(0x12, vec![1, 2, 3]);

    let pdu = session::smb2_cmd_session_setup_reply_async(&mut reply).unwrap();

    assert_eq!(pdu.command, Command::SessionSetup);
    assert_eq!(
        u16::from_le_bytes(pdu.fixed[0..2].try_into().unwrap()),
        SMB2_SESSION_SETUP_REPLY_SIZE
    );
    assert_eq!(
        u16::from_le_bytes(pdu.fixed[4..6].try_into().unwrap()),
        reply.security_buffer_offset
    );
    assert_eq!(pdu.security_buffer, vec![1, 2, 3, 0]);
}

// Trace: `lib/smb2-cmd-session-setup.c:smb2_cmd_session_setup_reply_async`
// Spec: smb2_cmd_session_setup_reply_async reply PDU construction#reply 编码失败释放 PDU
// - **GIVEN** PDU 已分配但 reply 编码或 padding 失败
// - **WHEN** `smb2_cmd_session_setup_reply_async` 处理失败返回
// - **THEN** 函数 MUST 释放已分配 PDU 并返回 `NULL`
#[test]
fn test_smb2_cmd_session_setup_reply_encoding_failure_releases_pdu() {
    let mut reply = Smb2SessionSetupReply::new(0, vec![0; usize::from(u16::MAX) + 1]);

    assert!(matches!(
        session::smb2_cmd_session_setup_reply_async(&mut reply),
        Err(SessionSetupError::SecurityBufferTooLarge { .. })
    ));
}

// Trace: `lib/smb2-cmd-session-setup.c:smb2_process_session_setup_fixed`, `include/libsmb2-private.h:smb2_process_session_setup_fixed`
// Spec: smb2_process_session_setup_fixed reply fixed parser#reply fixed header 有效且无 security buffer
// - **GIVEN** 输入 iovector 长度匹配 `SMB2_SESSION_SETUP_REPLY_SIZE & 0xfffe` 且 wire structure size 为 `SMB2_SESSION_SETUP_REPLY_SIZE`
// - **WHEN** 调用 `smb2_process_session_setup_fixed`
// - **THEN** 函数 MUST 分配 `smb2_session_setup_reply` 到 `pdu->payload`，读取 session flags、offset 和 length，更新 context session id，并在 security buffer length 为 0 时返回 0
#[test]
fn test_smb2_process_session_setup_fixed_valid_without_security_buffer() {
    let mut reply = Smb2SessionSetupReply::new(0x22, Vec::new());
    let fixed = reply.encode_fixed().unwrap();

    let parsed = Smb2SessionSetupReply::decode_fixed(&fixed).unwrap();

    assert_eq!(parsed.session_flags, 0x22);
    assert!(parsed.security_buffer.is_empty());
}

// Trace: `lib/smb2-cmd-session-setup.c:smb2_process_session_setup_fixed`
// Spec: smb2_process_session_setup_fixed reply fixed parser#reply security buffer 边界非法
// - **GIVEN** fixed header 声明的 security buffer 超出 PDU 长度或 offset 落入 fixed header 区域
// - **WHEN** 调用 `smb2_process_session_setup_fixed`
// - **THEN** 函数 MUST 设置错误、清空 `pdu->payload`、释放已分配 reply payload，并返回 -1
#[test]
fn test_smb2_process_session_setup_fixed_invalid_security_buffer_bounds() {
    let mut reply = Smb2SessionSetupReply::new(0, vec![1, 2]);
    let fixed = reply.encode_fixed().unwrap();
    let mut parsed = Smb2SessionSetupReply::decode_fixed(&fixed).unwrap();

    assert!(matches!(
        parsed.attach_variable_from_pdu(&fixed, 2),
        Err(SessionSetupError::SecurityBufferOutOfBounds { .. })
    ));
}

// Trace: `lib/smb2-cmd-session-setup.c:smb2_process_session_setup_variable`, `include/libsmb2-private.h:smb2_process_session_setup_variable`
// Spec: smb2_process_session_setup_variable reply variable parser#绑定 reply security buffer 指针
// - **GIVEN** `pdu->payload` 已包含由 fixed parser 填充的 `smb2_session_setup_reply`
// - **WHEN** 调用 `smb2_process_session_setup_variable`
// - **THEN** 函数 MUST 将 `rep->security_buffer` 指向当前输入 iovector 的 `IOV_OFFSET_SESSION` 位置并返回 0
#[test]
fn test_smb2_process_session_setup_variable_binds_reply_security_buffer() {
    let mut reply = Smb2SessionSetupReply::new(0, vec![4, 5, 6]);
    let mut pdu = vec![0; reply.security_buffer_offset as usize];
    let fixed = reply.encode_fixed().unwrap();
    let mut parsed = Smb2SessionSetupReply::decode_fixed(&fixed).unwrap();
    pdu.resize(reply.security_buffer_offset as usize, 0);
    pdu.extend_from_slice(&[4, 5, 6]);

    parsed.attach_variable_from_pdu(&pdu, 3).unwrap();

    assert_eq!(parsed.security_buffer, vec![4, 5, 6]);
}

// Trace: `lib/smb2-cmd-session-setup.c:smb2_process_session_setup_request_fixed`, `include/libsmb2-private.h:smb2_process_session_setup_request_fixed`
// Spec: smb2_process_session_setup_request_fixed request fixed parser#request fixed header 有效
// - **GIVEN** 输入 iovector 长度匹配 `SMB2_SESSION_SETUP_REQUEST_SIZE & 0xfffe` 且 wire structure size 为 `SMB2_SESSION_SETUP_REQUEST_SIZE`
// - **WHEN** 调用 `smb2_process_session_setup_request_fixed`
// - **THEN** 函数 MUST 分配 `smb2_session_setup_request` 到 `pdu->payload`，读取 flags、security mode、capabilities、channel、security buffer length 和 previous session id，并返回 `security_buffer_length`
#[test]
fn test_smb2_process_session_setup_request_fixed_valid() {
    let req = Smb2SessionSetupRequest::new(1, 2, 3, 4, 5, vec![7, 8]);
    let fixed = req.encode_fixed().unwrap();

    let parsed = Smb2SessionSetupRequest::decode_fixed(&fixed).unwrap();

    assert_eq!(parsed.flags, 1);
    assert_eq!(parsed.security_mode, 2);
    assert_eq!(req.security_buffer_length().unwrap(), 2);
}

// Trace: `lib/smb2-cmd-session-setup.c:smb2_process_session_setup_request_fixed`
// Spec: smb2_process_session_setup_request_fixed request fixed parser#request fixed header size 非法
// - **GIVEN** 输入 fixed payload 的 structure size 或 iovector 长度与 SESSION_SETUP request size 不匹配
// - **WHEN** 调用 `smb2_process_session_setup_request_fixed`
// - **THEN** 函数 MUST 设置错误且返回 -1
#[test]
fn test_smb2_process_session_setup_request_fixed_invalid_size() {
    assert!(matches!(
        Smb2SessionSetupRequest::decode_fixed(&[0, 0]),
        Err(SessionSetupError::UnexpectedFixedSize { .. })
    ));
}

// Trace: `lib/smb2-cmd-session-setup.c:smb2_process_session_setup_request_variable`, `include/libsmb2-private.h:smb2_process_session_setup_request_variable`
// Spec: smb2_process_session_setup_request_variable request variable parser#绑定 request security buffer 指针
// - **GIVEN** `pdu->payload` 已包含由 fixed parser 分配的 `smb2_session_setup_request`
// - **WHEN** 调用 `smb2_process_session_setup_request_variable`
// - **THEN** 函数 MUST 将 `req->security_buffer` 指向当前输入 iovector buffer 并返回 0
#[test]
fn test_smb2_process_session_setup_request_variable_binds_request_security_buffer() {
    let mut req = Smb2SessionSetupRequest::new(0, 0, 0, 0, 0, Vec::new());

    req.attach_security_buffer(&[1, 2, 3]);

    assert_eq!(req.security_buffer, vec![1, 2, 3]);
}
