use libsmb2_rs::lib::smb2_cmd_oplock_break::{
    self as oplock, Smb2BreakType, Smb2LeaseBreakBody, Smb2LeaseBreakNotification,
    Smb2OplockBreakBody, Smb2OplockOrLeaseBreakReplyLock, Smb2OplockOrLeaseBreakRequestLock,
};

fn file_id() -> [u8; 16] {
    [0x66; 16]
}
fn lease_key() -> [u8; 16] {
    [0x77; 16]
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_oplock_break_acknowledgement`
// Spec: smb2_cmd_oplock_break_async builds acknowledgement PDU#构造 acknowledgement 成功
// - **GIVEN** 调用方提供可用的 `smb2_context`、`smb2_oplock_break_acknowledgement`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_oplock_break_async`
// - **THEN** 返回的 PDU 使用 SMB2_OPLOCK_BREAK 命令，并包含 acknowledgement 结构大小、oplock level 和 file id
#[test]
fn test_smb2_cmd_oplock_break_acknowledgement_success() {
    let body = Smb2OplockBreakBody::new(oplock::SMB2_OPLOCK_LEVEL_II, file_id());
    let pdu = oplock::smb2_cmd_oplock_break_async(&body, None).unwrap();
    assert_eq!(pdu.header.command, 18);
    assert_eq!(
        &pdu.out.vectors[0].buf[0..2],
        &oplock::SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE.to_le_bytes()
    );
    assert_eq!(pdu.out.vectors[0].buf[2], oplock::SMB2_OPLOCK_LEVEL_II);
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_reply_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_oplock_break_reply`
// Spec: smb2_cmd_oplock_break_reply_async builds reply PDU#构造 reply 成功
// - **GIVEN** 调用方提供可用的 `smb2_oplock_break_reply` 数据
// - **WHEN** 调用 `smb2_cmd_oplock_break_reply_async`
// - **THEN** 返回的 PDU MUST 包含 reply 固定结构大小、oplock level 和 file id，并完成 64-bit padding
#[test]
fn test_smb2_cmd_oplock_break_reply_success() {
    let body = Smb2OplockBreakBody::new(oplock::SMB2_OPLOCK_LEVEL_EXCLUSIVE, file_id());
    let pdu = oplock::smb2_cmd_oplock_break_reply_async(&body, None).unwrap();
    assert_eq!(
        &pdu.out.vectors[0].buf[0..2],
        &oplock::SMB2_OPLOCK_BREAK_REPLY_SIZE.to_le_bytes()
    );
    assert_eq!(&pdu.out.vectors[0].buf[8..24], &file_id());
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_notification_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_oplock_break_notification`
// Spec: smb2_cmd_oplock_break_notification_async builds notification PDU#构造 notification 成功
// - **GIVEN** 调用方提供可用的 `smb2_oplock_break_notification` 数据
// - **WHEN** 调用 `smb2_cmd_oplock_break_notification_async`
// - **THEN** 返回的 PDU MUST 包含 `SMB2_OPLOCK_BREAK_REPLY_SIZE` 结构大小、oplock level 和 file id，并完成 64-bit padding
#[test]
fn test_smb2_cmd_oplock_break_notification_success() {
    let body = Smb2OplockBreakBody::new(oplock::SMB2_OPLOCK_LEVEL_NONE, file_id());
    let pdu = oplock::smb2_cmd_oplock_break_notification_async(&body, None).unwrap();
    assert_eq!(
        &pdu.out.vectors[0].buf[0..2],
        &oplock::SMB2_OPLOCK_BREAK_NOTIFICATION_SIZE.to_le_bytes()
    );
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_lease_break_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_lease_break_acknowledgement`
// Spec: smb2_cmd_lease_break_async builds lease acknowledgement PDU#构造 lease acknowledgement 成功
// - **GIVEN** 调用方提供可用的 `smb2_lease_break_acknowledgement` 数据
// - **WHEN** 调用 `smb2_cmd_lease_break_async`
// - **THEN** 返回的 PDU MUST 使用 SMB2_OPLOCK_BREAK 命令并附带 lease acknowledgement payload
#[test]
fn test_smb2_cmd_oplock_break_lease_acknowledgement_success() {
    let body = Smb2LeaseBreakBody::new(1, lease_key(), oplock::SMB2_LEASE_READ_CACHING, 9);
    let pdu = oplock::smb2_cmd_lease_break_async(&body, None).unwrap();
    assert_eq!(
        &pdu.out.vectors[0].buf[0..2],
        &oplock::SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE.to_le_bytes()
    );
    assert_eq!(&pdu.out.vectors[0].buf[8..24], &lease_key());
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_lease_break_reply_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_lease_break_reply`
// Spec: smb2_cmd_lease_break_reply_async builds lease reply PDU#构造 lease reply 成功
// - **GIVEN** 调用方提供可用的 `smb2_lease_break_reply` 数据
// - **WHEN** 调用 `smb2_cmd_lease_break_reply_async`
// - **THEN** 返回的 PDU MUST 包含 lease reply payload 并完成 64-bit padding
#[test]
fn test_smb2_cmd_oplock_break_lease_reply_success() {
    let body = Smb2LeaseBreakBody::new(2, lease_key(), oplock::SMB2_LEASE_WRITE_CACHING, 10);
    let pdu = oplock::smb2_cmd_lease_break_reply_async(&body, None).unwrap();
    assert_eq!(
        &pdu.out.vectors[0].buf[0..2],
        &oplock::SMB2_LEASE_BREAK_REPLY_SIZE.to_le_bytes()
    );
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_lease_break_notification_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_lease_break_notification`
// Spec: smb2_cmd_lease_break_notification_async builds lease notification PDU#构造 lease notification 成功
// - **GIVEN** 调用方提供可用的 `smb2_lease_break_notification` 数据
// - **WHEN** 调用 `smb2_cmd_lease_break_notification_async`
// - **THEN** 返回的 PDU MUST 包含 lease notification payload 并完成 64-bit padding
#[test]
fn test_smb2_cmd_oplock_break_lease_notification_success() {
    let body = Smb2LeaseBreakNotification {
        new_epoch: 3,
        flags: 4,
        lease_key: lease_key(),
        current_lease_state: 1,
        new_lease_state: 2,
        break_reason: 5,
        access_mask_hint: 6,
        share_mask_hint: 7,
    };
    let pdu = oplock::smb2_cmd_lease_break_notification_async(&body, None).unwrap();
    assert_eq!(
        &pdu.out.vectors[0].buf[0..2],
        &oplock::SMB2_LEASE_BREAK_NOTIFICATION_SIZE.to_le_bytes()
    );
    assert_eq!(&pdu.out.vectors[0].buf[8..24], &lease_key());
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_oplock_break_fixed validates reply structure size#reply fixed size accepted
// - **GIVEN** 输入 iovector 的结构大小为 `SMB2_OPLOCK_BREAK_REPLY_SIZE`、`SMB2_LEASE_BREAK_NOTIFICATION_SIZE` 或 `SMB2_LEASE_BREAK_REPLY_SIZE`
// - **WHEN** `smb2_process_oplock_break_fixed` 处理 fixed payload
// - **THEN** 函数 MUST 将 payload 附加到 PDU，并返回结构大小减去 `sizeof(uint16_t)` 的 variable payload 长度
#[test]
fn test_smb2_cmd_oplock_break_reply_fixed_size_accepted() {
    let mut fixed = [0; 2];
    fixed.copy_from_slice(&oplock::SMB2_LEASE_BREAK_REPLY_SIZE.to_le_bytes());
    let (rep, len) = oplock::smb2_process_oplock_break_fixed(&fixed).unwrap();
    assert_eq!(rep.struct_size, oplock::SMB2_LEASE_BREAK_REPLY_SIZE);
    assert_eq!(len, 34);
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_oplock_break_fixed validates reply structure size#reply fixed size rejected
// - **GIVEN** 输入 iovector 的结构大小不是已支持的 oplock/lease break reply 或 notification 大小
// - **WHEN** `smb2_process_oplock_break_fixed` 处理 fixed payload
// - **THEN** 函数 MUST 设置错误、清空 `pdu->payload`、释放临时 payload 并返回 -1
#[test]
fn test_smb2_cmd_oplock_break_reply_fixed_size_rejected() {
    assert!(oplock::smb2_process_oplock_break_fixed(&0_u16.to_le_bytes()).is_err());
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_oplock_break_variable decodes reply fields#decode oplock response or notification
// - **GIVEN** `pdu->payload` 的结构大小为 `SMB2_OPLOCK_BREAK_NOTIFICATION_SIZE`
// - **WHEN** `smb2_process_oplock_break_variable` 解码 variable payload
// - **THEN** 函数 MUST 根据 message id 选择 `SMB2_BREAK_TYPE_OPLOCK_NOTIFICATION` 或 `SMB2_BREAK_TYPE_OPLOCK_RESPONSE`，并填充 oplock level 和 file id
#[test]
fn test_smb2_cmd_oplock_break_decode_oplock_response_or_notification() {
    let mut fixed = [0; 2];
    fixed.copy_from_slice(&oplock::SMB2_OPLOCK_BREAK_NOTIFICATION_SIZE.to_le_bytes());
    let (mut rep, _) = oplock::smb2_process_oplock_break_fixed(&fixed).unwrap();
    let body = Smb2OplockBreakBody::new(oplock::SMB2_OPLOCK_LEVEL_II, file_id())
        .encode_fixed(oplock::SMB2_OPLOCK_BREAK_NOTIFICATION_SIZE)
        .unwrap();
    oplock::smb2_process_oplock_break_variable(&mut rep, &body[2..], u64::MAX).unwrap();
    assert_eq!(rep.break_type, Some(Smb2BreakType::OplockNotification));
    assert!(matches!(
        rep.lock,
        Some(Smb2OplockOrLeaseBreakReplyLock::OplockNotification(_))
    ));
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_oplock_break_variable decodes reply fields#decode lease notification or response
// - **GIVEN** `pdu->payload` 的结构大小为 lease break notification 或 lease break reply 大小
// - **WHEN** `smb2_process_oplock_break_variable` 解码 variable payload
// - **THEN** 函数 MUST 设置 lease notification 或 lease response break type，并填充对应 union 字段
#[test]
fn test_smb2_cmd_oplock_break_decode_lease_notification_or_response() {
    let mut fixed = [0; 2];
    fixed.copy_from_slice(&oplock::SMB2_LEASE_BREAK_REPLY_SIZE.to_le_bytes());
    let (mut rep, _) = oplock::smb2_process_oplock_break_fixed(&fixed).unwrap();
    let body = Smb2LeaseBreakBody::new(1, lease_key(), oplock::SMB2_LEASE_HANDLE_CACHING, 10)
        .encode_fixed(oplock::SMB2_LEASE_BREAK_REPLY_SIZE)
        .unwrap();
    oplock::smb2_process_oplock_break_variable(&mut rep, &body[2..], 1).unwrap();
    assert_eq!(rep.break_type, Some(Smb2BreakType::LeaseResponse));
    assert!(matches!(
        rep.lock,
        Some(Smb2OplockOrLeaseBreakReplyLock::LeaseResponse(_))
    ));
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_oplock_break_request_fixed validates acknowledgement structure size#request fixed size accepted
// - **GIVEN** 输入 iovector 的结构大小为 `SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE` 或 `SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE`
// - **WHEN** `smb2_process_oplock_break_request_fixed` 处理 fixed payload
// - **THEN** 函数 MUST 将 payload 附加到 PDU，并返回结构大小减去 `sizeof(uint16_t)` 的 variable payload 长度
#[test]
fn test_smb2_cmd_oplock_break_request_fixed_size_accepted() {
    let (req, len) = oplock::smb2_process_oplock_break_request_fixed(
        &oplock::SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE.to_le_bytes(),
    )
    .unwrap();
    assert_eq!(req.struct_size, oplock::SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE);
    assert_eq!(len, 22);
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_oplock_break_request_fixed validates acknowledgement structure size#request fixed size rejected
// - **GIVEN** 输入 iovector 的结构大小不是已支持的 acknowledgement 大小
// - **WHEN** `smb2_process_oplock_break_request_fixed` 处理 fixed payload
// - **THEN** 函数 MUST 设置错误、清空 `pdu->payload`、释放临时 payload 并返回 -1
#[test]
fn test_smb2_cmd_oplock_break_request_fixed_size_rejected() {
    assert!(oplock::smb2_process_oplock_break_request_fixed(&0_u16.to_le_bytes()).is_err());
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`
// Spec: smb2_process_oplock_break_request_variable decodes acknowledgement fields#decode oplock acknowledgement
// - **GIVEN** `pdu->payload` 的结构大小为 `SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE`
// - **WHEN** `smb2_process_oplock_break_request_variable` 解码 variable payload
// - **THEN** 函数 MUST 设置 `SMB2_BREAK_TYPE_OPLOCK_ACKNOWLEDGE`，并填充 oplock level 和 file id
#[test]
fn test_smb2_cmd_oplock_break_decode_oplock_acknowledgement() {
    let (mut req, _) = oplock::smb2_process_oplock_break_request_fixed(
        &oplock::SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE.to_le_bytes(),
    )
    .unwrap();
    let body = Smb2OplockBreakBody::new(oplock::SMB2_OPLOCK_LEVEL_II, file_id())
        .encode_fixed(oplock::SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE)
        .unwrap();
    oplock::smb2_process_oplock_break_request_variable(&mut req, &body[2..]).unwrap();
    assert_eq!(req.break_type, Some(Smb2BreakType::OplockAcknowledge));
    assert!(matches!(
        req.lock,
        Some(Smb2OplockOrLeaseBreakRequestLock::OplockAcknowledge(_))
    ));
}

// Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`
// Spec: smb2_process_oplock_break_request_variable decodes acknowledgement fields#decode lease acknowledgement
// - **GIVEN** `pdu->payload` 的结构大小为 `SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE`
// - **WHEN** `smb2_process_oplock_break_request_variable` 解码 variable payload
// - **THEN** 函数 MUST 设置 `SMB2_BREAK_TYPE_LEASE_ACKNOWLEDGE`，并填充 flags、lease key、lease state 和 lease duration
#[test]
fn test_smb2_cmd_oplock_break_decode_lease_acknowledgement() {
    let (mut req, _) = oplock::smb2_process_oplock_break_request_fixed(
        &oplock::SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE.to_le_bytes(),
    )
    .unwrap();
    let body = Smb2LeaseBreakBody::new(1, lease_key(), oplock::SMB2_LEASE_READ_CACHING, 10)
        .encode_fixed(oplock::SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE)
        .unwrap();
    oplock::smb2_process_oplock_break_request_variable(&mut req, &body[2..]).unwrap();
    assert_eq!(req.break_type, Some(Smb2BreakType::LeaseAcknowledge));
    assert!(matches!(
        req.lock,
        Some(Smb2OplockOrLeaseBreakRequestLock::LeaseAcknowledge(_))
    ));
}
