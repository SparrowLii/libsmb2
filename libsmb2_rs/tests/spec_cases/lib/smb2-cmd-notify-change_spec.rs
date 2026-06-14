use libsmb2_rs::lib::smb2_cmd_notify_change::{
    self as notify, ChangeNotifyError, ChangeNotifyReply, ChangeNotifyRequest,
};

fn file_id() -> [u8; 16] {
    [0x44; 16]
}

// Trace: `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_async`, `lib/smb2-cmd-notify-change.c:smb2_encode_change_notify_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_change_notify_async`
// Spec: smb2_cmd_change_notify_async request PDU construction#successful request PDU
// - **GIVEN** 调用方提供有效的 `smb2_context`、`smb2_change_notify_request`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_change_notify_async`
// - **THEN** 返回的 PDU MUST 包含 SMB2_CHANGE_NOTIFY 命令、32 字节请求 fixed payload、请求 flags、output_buffer_length、file_id、completion_filter，并完成 64-bit padding
#[test]
fn test_smb2_cmd_notify_change_successful_request_pdu() {
    let req = ChangeNotifyRequest::new(
        file_id(),
        notify::SMB2_WATCH_TREE,
        64,
        notify::SMB2_NOTIFY_CHANGE_FILE_NAME,
    );
    let pdu = notify::smb2_cmd_change_notify_async(&req).unwrap();
    assert_eq!(pdu.command, notify::SMB2_CHANGE_NOTIFY_COMMAND);
    assert_eq!(pdu.payload.len(), ChangeNotifyRequest::fixed_wire_len());
    assert_eq!(&pdu.payload[8..24], &file_id());
}

// Trace: `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_reply_async`, `lib/smb2-cmd-notify-change.c:smb2_encode_change_notify_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_change_notify_reply_async`
// Spec: smb2_cmd_change_notify_reply_async reply PDU construction#zero-length reply output
// - **GIVEN** `rep->output_buffer_length` 为 0
// - **WHEN** 调用 `smb2_cmd_change_notify_reply_async`
// - **THEN** 返回的 PDU MUST 包含 change-notify 回复 fixed payload，设置 output_buffer_offset 和 output_buffer_length，并完成 64-bit padding
#[test]
fn test_smb2_cmd_notify_change_zero_length_reply_output() {
    let pdu = notify::smb2_cmd_change_notify_reply_async(&ChangeNotifyReply::new()).unwrap();
    assert_eq!(pdu.command, notify::SMB2_CHANGE_NOTIFY_COMMAND);
    assert_eq!(
        &pdu.payload[0..2],
        &(notify::SMB2_CHANGE_NOTIFY_REPLY_SIZE as u16).to_le_bytes()
    );
    assert_eq!(&pdu.payload[4..8], &0_u32.to_le_bytes());
}

// Trace: `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_reply_async`, `lib/smb2-cmd-notify-change.c:smb2_encode_change_notify_reply`
// Spec: smb2_cmd_change_notify_reply_async reply PDU construction#passthrough reply output
// - **GIVEN** `rep->output_buffer_length` 大于 0 且 `smb2->passthrough` 为真
// - **WHEN** 调用 `smb2_cmd_change_notify_reply_async`
// - **THEN** 接口 MUST 分配 32-bit padding 后的输出缓冲区，复制 `rep->output` 的实际长度内容，清零 padding 字节，并将 iovector 长度设为未 padding 的输出长度
#[test]
fn test_smb2_cmd_notify_change_passthrough_reply_output() {
    let rep = ChangeNotifyReply::new().with_output(vec![1, 2, 3]).unwrap();
    let pdu = notify::smb2_cmd_change_notify_reply_async(&rep).unwrap();
    assert_eq!(&pdu.payload[8..11], &[1, 2, 3]);
    assert_eq!(pdu.payload[11], 0);
}

// Trace: `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_reply_async`, `lib/smb2-cmd-notify-change.c:smb2_encode_change_notify_reply`
// Spec: smb2_cmd_change_notify_reply_async reply PDU construction#non-passthrough reply output
// - **GIVEN** `rep->output_buffer_length` 大于 0 且 `smb2->passthrough` 为假
// - **WHEN** 调用 `smb2_cmd_change_notify_reply_async`
// - **THEN** 接口 MUST 设置 `Change-notify buffer packing not implemented` 错误，释放已分配 PDU，并返回 `NULL`
#[test]
fn test_smb2_cmd_notify_change_non_passthrough_reply_output() {
    let rep = ChangeNotifyReply::new().with_output(vec![1, 2, 3]).unwrap();

    assert_eq!(
        notify::smb2_cmd_change_notify_reply_async_with_passthrough(&rep, false),
        Err(ChangeNotifyError::NonPassthroughOutputUnsupported)
    );
}

// Trace: `lib/smb2-cmd-notify-change.c:smb2_process_change_notify_fixed`, `include/libsmb2-private.h:smb2_process_change_notify_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_change_notify_fixed reply fixed parser#valid reply fixed payload
// - **GIVEN** 当前输入 iovector 的结构大小字段等于 `SMB2_CHANGE_NOTIFY_REPLY_SIZE` 且偶数掩码后的大小等于 iovector 长度
// - **WHEN** 调用 `smb2_process_change_notify_fixed`
// - **THEN** 接口 MUST 分配 `struct smb2_change_notify_reply`，保存到 `pdu->payload`，解析 output_buffer_offset 和 output_buffer_length，并返回 output_buffer_length
#[test]
fn test_smb2_cmd_notify_change_valid_reply_fixed_payload() {
    let fixed = notify::smb2_encode_change_notify_reply(
        &ChangeNotifyReply::new().with_output(vec![1, 2]).unwrap(),
    )
    .unwrap()[..8]
        .to_vec();
    let (rep, len) = notify::smb2_process_change_notify_fixed(&fixed, 80).unwrap();
    assert_eq!(rep.output_buffer_length, 2);
    assert_eq!(len, 2);
}

// Trace: `lib/smb2-cmd-notify-change.c:smb2_process_change_notify_fixed`
// Spec: smb2_process_change_notify_fixed reply fixed parser#invalid reply fixed payload size
// - **GIVEN** 当前输入 iovector 的结构大小字段不等于 `SMB2_CHANGE_NOTIFY_REPLY_SIZE` 或掩码后大小不等于 iovector 长度
// - **WHEN** 调用 `smb2_process_change_notify_fixed`
// - **THEN** 接口 MUST 设置 unexpected-size 错误并返回 `-1`
#[test]
fn test_smb2_cmd_notify_change_invalid_reply_fixed_payload_size() {
    assert_eq!(
        notify::smb2_process_change_notify_fixed(&[0; 8], 80),
        Err(ChangeNotifyError::InvalidStructureSize)
    );
}

// Trace: `lib/smb2-cmd-notify-change.c:smb2_process_change_notify_variable`, `include/libsmb2-private.h:smb2_process_change_notify_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_change_notify_variable reply output binding#reply variable payload assignment
// - **GIVEN** `pdu->payload` 指向已由 fixed parser 分配的 `struct smb2_change_notify_reply`
// - **WHEN** 调用 `smb2_process_change_notify_variable`
// - **THEN** 接口 MUST 将 `rep->output` 设置为当前输入 iovector 的缓冲区地址，并返回 0
#[test]
fn test_smb2_cmd_notify_change_reply_variable_payload_assignment() {
    let mut rep = ChangeNotifyReply {
        output_buffer_offset: 72,
        output_buffer_length: 2,
        output: Vec::new(),
    };
    notify::smb2_process_change_notify_variable(&mut rep, &[9, 8]).unwrap();
    assert_eq!(rep.output, vec![9, 8]);
}

// Trace: `lib/smb2-cmd-notify-change.c:smb2_process_change_notify_request_fixed`, `include/libsmb2-private.h:smb2_process_change_notify_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_change_notify_request_fixed request fixed parser#valid request fixed payload
// - **GIVEN** 当前输入 iovector 的结构大小字段等于 `SMB2_CHANGE_NOTIFY_REQUEST_SIZE` 且偶数掩码后的大小等于 iovector 长度
// - **WHEN** 调用 `smb2_process_change_notify_request_fixed`
// - **THEN** 接口 MUST 分配 `struct smb2_change_notify_request`，保存到 `pdu->payload`，解析 flags 和 completion_filter，并复制 file_id
#[test]
fn test_smb2_cmd_notify_change_valid_request_fixed_payload() {
    let req = ChangeNotifyRequest::new(
        file_id(),
        notify::SMB2_WATCH_TREE,
        64,
        notify::SMB2_NOTIFY_CHANGE_FILE_NAME,
    );
    let fixed = notify::smb2_encode_change_notify_request(&req).unwrap();
    assert_eq!(
        notify::smb2_process_change_notify_request_fixed(&fixed).unwrap(),
        req
    );
}

// Trace: `lib/smb2-cmd-notify-change.c:smb2_process_change_notify_request_fixed`
// Spec: smb2_process_change_notify_request_fixed request fixed parser#invalid request fixed payload size
// - **GIVEN** 当前输入 iovector 的结构大小字段不等于 `SMB2_CHANGE_NOTIFY_REQUEST_SIZE` 或掩码后大小不等于 iovector 长度
// - **WHEN** 调用 `smb2_process_change_notify_request_fixed`
// - **THEN** 接口 MUST 设置 unexpected-size 错误并返回 `-1`
#[test]
fn test_smb2_cmd_notify_change_invalid_request_fixed_payload_size() {
    assert_eq!(
        notify::smb2_process_change_notify_request_fixed(&[0; 32]),
        Err(ChangeNotifyError::InvalidStructureSize)
    );
}
