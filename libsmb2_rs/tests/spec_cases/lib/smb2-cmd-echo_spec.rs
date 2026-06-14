use libsmb2_rs::include::smb2::smb2::Command;
use libsmb2_rs::lib::smb2_cmd_echo::{
    smb2_cmd_echo_async, smb2_cmd_echo_reply_async, smb2_process_echo_fixed,
    smb2_process_echo_request_fixed, Smb2EchoPayload, SMB2_ECHO_REPLY_SIZE, SMB2_ECHO_REQUEST_SIZE,
};

fn fixed(size: u16) -> Vec<u8> {
    let mut buf = vec![0; usize::from(size & 0xfffe)];
    buf[0..2].copy_from_slice(&size.to_le_bytes());
    buf
}

// Trace: `lib/smb2-cmd-echo.c:smb2_cmd_echo_async`, `lib/smb2-cmd-echo.c:smb2_encode_echo_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_echo_async`
// Spec: smb2_cmd_echo_async build echo request PDU#成功构造 echo request
// - **GIVEN** 调用方提供有效的 `smb2_context`、回调函数和回调数据
// - **WHEN** 调用 `smb2_cmd_echo_async` 构造 ECHO 请求 PDU
// - **THEN** 返回值 MUST 是命令码为 `SMB2_ECHO`、输出固定段大小字段为 `SMB2_ECHO_REQUEST_SIZE` 且已执行 64-bit padding 的 PDU
#[test]
fn test_smb2_cmd_echo_success_request() {
    let pdu = smb2_cmd_echo_async(None).expect("echo request pdu");

    assert_eq!(pdu.header.command, Command::Echo as u16);
    assert_eq!(pdu.out.vectors[0].buf, fixed(SMB2_ECHO_REQUEST_SIZE));
    assert_eq!(pdu.out.total_size, 4);
}

// Trace: `lib/smb2-cmd-echo.c:smb2_cmd_echo_reply_async`, `lib/smb2-cmd-echo.c:smb2_encode_echo_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_echo_reply_async`
// Spec: smb2_cmd_echo_reply_async build echo reply PDU#成功构造 echo reply
// - **GIVEN** 服务端请求处理路径提供有效的 `smb2_context`、回调函数和回调数据
// - **WHEN** 调用 `smb2_cmd_echo_reply_async` 构造 ECHO 回复 PDU
// - **THEN** 返回值 MUST 是命令码为 `SMB2_ECHO`、输出固定段大小字段为 `SMB2_ECHO_REPLY_SIZE` 且已执行 64-bit padding 的 PDU
#[test]
fn test_smb2_cmd_echo_success_reply() {
    let pdu = smb2_cmd_echo_reply_async(None).expect("echo reply pdu");

    assert_eq!(pdu.header.command, Command::Echo as u16);
    assert_eq!(pdu.out.vectors[0].buf, fixed(SMB2_ECHO_REPLY_SIZE));
    assert_eq!(pdu.out.total_size, 4);
}

// Trace: `lib/smb2-cmd-echo.c:smb2_process_echo_fixed`, `include/libsmb2-private.h:smb2_process_echo_fixed`
// Spec: smb2_process_echo_fixed validate echo reply fixed segment#reply fixed segment size accepted
// - **GIVEN** 当前输入 iovector 的固定段大小字段为 `SMB2_ECHO_REPLY_SIZE` 且掩码后的结构大小等于 iovector 长度
// - **WHEN** `smb2_process_echo_fixed` 解析 ECHO reply 固定段
// - **THEN** 函数 MUST 返回 `0` 且不分配额外 payload
#[test]
fn test_smb2_cmd_echo_reply_fixed_segment_size_accepted() {
    assert!(matches!(
        smb2_process_echo_fixed(&fixed(SMB2_ECHO_REPLY_SIZE)),
        Ok(Smb2EchoPayload::Reply(_))
    ));
}

// Trace: `lib/smb2-cmd-echo.c:smb2_process_echo_fixed`, `include/libsmb2-private.h:smb2_process_echo_fixed`
// Spec: smb2_process_echo_fixed validate echo reply fixed segment#reply fixed segment size rejected
// - **GIVEN** 当前输入 iovector 的固定段大小字段不是 `SMB2_ECHO_REPLY_SIZE` 或掩码后的结构大小不等于 iovector 长度
// - **WHEN** `smb2_process_echo_fixed` 解析 ECHO reply 固定段
// - **THEN** 函数 MUST 调用 `smb2_set_error` 记录 unexpected size 错误并返回 `-1`
#[test]
fn test_smb2_cmd_echo_reply_fixed_segment_size_rejected() {
    assert!(smb2_process_echo_fixed(&fixed(SMB2_ECHO_REPLY_SIZE + 2)).is_err());
    assert!(smb2_process_echo_fixed(&[SMB2_ECHO_REPLY_SIZE as u8]).is_err());
}

// Trace: `lib/smb2-cmd-echo.c:smb2_process_echo_request_fixed`, `include/libsmb2-private.h:smb2_process_echo_request_fixed`, `include/smb2/smb2.h:struct smb2_echo_request`
// Spec: smb2_process_echo_request_fixed validate echo request fixed segment#request fixed segment size accepted and payload allocated
// - **GIVEN** 当前输入 iovector 的固定段大小字段为 `SMB2_ECHO_REQUEST_SIZE` 且掩码后的结构大小等于 iovector 长度
// - **WHEN** `smb2_process_echo_request_fixed` 解析 ECHO request 固定段
// - **THEN** 函数 MUST 分配 `struct smb2_echo_request`、把该分配结果赋值给 `pdu->payload` 并返回 `0`
#[test]
fn test_smb2_cmd_echo_request_fixed_segment_size_accepted_and_payload_allocated() {
    assert!(matches!(
        smb2_process_echo_request_fixed(&fixed(SMB2_ECHO_REQUEST_SIZE)),
        Ok(Smb2EchoPayload::Request(_))
    ));
}

// Trace: `lib/smb2-cmd-echo.c:smb2_process_echo_request_fixed`, `include/libsmb2-private.h:smb2_process_echo_request_fixed`
// Spec: smb2_process_echo_request_fixed validate echo request fixed segment#request fixed segment size rejected
// - **GIVEN** 当前输入 iovector 的固定段大小字段不是 `SMB2_ECHO_REQUEST_SIZE` 或掩码后的结构大小不等于 iovector 长度
// - **WHEN** `smb2_process_echo_request_fixed` 解析 ECHO request 固定段
// - **THEN** 函数 MUST 调用 `smb2_set_error` 记录 unexpected size 错误并返回 `-1`
#[test]
fn test_smb2_cmd_echo_request_fixed_segment_size_rejected() {
    assert!(smb2_process_echo_request_fixed(&fixed(SMB2_ECHO_REQUEST_SIZE + 2)).is_err());
    assert!(smb2_process_echo_request_fixed(&[SMB2_ECHO_REQUEST_SIZE as u8]).is_err());
}
