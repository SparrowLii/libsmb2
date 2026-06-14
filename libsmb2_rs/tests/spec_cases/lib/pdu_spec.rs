use libsmb2_rs::include::libsmb2_private::ServerRef;
use libsmb2_rs::include::libsmb2_private::{Context, IoVec, IoVectors};
use libsmb2_rs::lib::pdu::*;

fn allocated_pdu(command: Smb2Command) -> libsmb2_rs::include::libsmb2_private::Pdu {
    smb2_allocate_pdu(&Context::new(), command, None)
}

// Trace: `lib/pdu.c:smb2_pad_to_64bit`
// Spec: smb2_pad_to_64bit append alignment padding#aligned vector returns success
// - **GIVEN** `struct smb2_io_vectors` 中所有 `iov` 长度总和已经 8 字节对齐
// - **WHEN** 调用 `smb2_pad_to_64bit(smb2, v)`
// - **THEN** 函数返回 `0` 且不调用新增 I/O vector 路径
#[test]
fn test_pdu_aligned_vector_returns_success() {
    let mut vectors = IoVectors::new();
    vectors.vectors.push(IoVec::new(vec![1, 2, 3, 4]));
    vectors.vectors.push(IoVec::new(vec![5, 6, 7, 8]));
    vectors.total_size = 8;
    let original_vectors = vectors.vectors.clone();

    assert_eq!(smb2_pad_to_64bit(&mut vectors), 0);
    assert_eq!(vectors.vectors, original_vectors);
}

// Trace: `lib/pdu.c:smb2_pad_to_64bit`
// Spec: smb2_pad_to_64bit append alignment padding#unaligned vector appends zeros
// - **GIVEN** `struct smb2_io_vectors` 中所有 `iov` 长度总和不是 8 字节对齐
// - **WHEN** 调用 `smb2_pad_to_64bit(smb2, v)` 且 `smb2_add_iovector` 成功
// - **THEN** 函数返回 `0` 并追加长度为 `8 - (len & 0x07)` 的零填充
#[test]
fn test_pdu_unaligned_vector_appends_zeros() {
    let mut vectors = IoVectors::new();
    vectors.vectors.push(IoVec::new(vec![1, 2, 3]));
    vectors.total_size = 3;
    assert_eq!(smb2_pad_to_64bit(&mut vectors), 5);
    assert_eq!(vectors.vectors.last().unwrap().buf, vec![0; 5]);
}

// Trace: `lib/pdu.c:smb2_allocate_pdu`, GitNexus `context smb2_allocate_pdu`
// Spec: smb2_allocate_pdu initialize outbound PDU#successful PDU allocation
// - **GIVEN** 上下文 `smb2`、命令、回调和回调数据有效，且内存和 header iovec 添加成功
// - **WHEN** 调用 `smb2_allocate_pdu(smb2, command, cb, cb_data)`
// - **THEN** 返回的 PDU header 包含 SMB2 magic、`SMB2_HEADER_SIZE`、命令、credit 规则、tree/session 规则、回调数据和可编码 header iovec
#[test]
fn test_pdu_successful_pdu_allocation() {
    let mut context = Context::new();
    context.session_id = 0x55aa;
    context.tree_ids.push(7);
    let pdu = smb2_allocate_pdu(&context, Smb2Command::Read, None);
    assert_eq!(pdu.header.protocol_id, SMB2_PROTOCOL_ID);
    assert_eq!(pdu.header.command, Smb2Command::Read.as_u16());
    assert_eq!(pdu.header.credit_charge, 1);
    assert_eq!(pdu.header.tree_id, 7);
    assert_eq!(pdu.header.session_id, 0x55aa);
    assert_eq!(pdu.out.vectors.len(), 1);
}

// Trace: `lib/pdu.c:smb2_allocate_pdu`
// Spec: smb2_allocate_pdu initialize outbound PDU#allocation failure records error
// - **GIVEN** `calloc` 无法分配 `struct smb2_pdu`
// - **WHEN** 调用 `smb2_allocate_pdu(smb2, command, cb, cb_data)`
// - **THEN** 函数返回 `NULL` 并通过 `smb2_set_error` 记录 `Failed to allocate pdu`
#[test]
fn test_pdu_allocation_failure_records_error() {
    let mut context = Context::new();

    assert_eq!(
        smb2_allocate_pdu_allocation_failure(&mut context, Smb2Command::Read).unwrap_err(),
        PduError::AllocationFailed
    );
    assert_eq!(context.error(), "Failed to allocate pdu");
}

// Trace: `lib/pdu.c:smb2_select_tree_id`, `include/smb2/libsmb2.h:smb2_select_tree_id`
// Spec: smb2_select_tree_id select connected tree#existing tree id is selected
// - **GIVEN** `smb2->tree_id` 栈中存在目标 `tree_id`
// - **WHEN** 调用 `smb2_select_tree_id(smb2, tree_id)`
// - **THEN** 函数返回 `0` 并将 `smb2->tree_id_cur` 设置为匹配槽位
#[test]
fn test_pdu_existing_tree_id_is_selected() {
    let mut context = Context::new();
    context.tree_ids = vec![1, 2, 3];
    smb2_select_tree_id(&mut context, 3).unwrap();
    assert_eq!(context.current_tree_id(), 3);
}

// Trace: `lib/pdu.c:smb2_get_tree_id_for_pdu`, `include/smb2/libsmb2.h:smb2_get_tree_id_for_pdu`
// Spec: smb2_get_tree_id_for_pdu resolve effective tree id#control PDU returns zero tree id
// - **GIVEN** PDU 命令是 negotiate、session setup、logoff、echo 或 tree connect
// - **WHEN** 调用 `smb2_get_tree_id_for_pdu(smb2, pdu, tree_id)`
// - **THEN** 函数返回 `0` 并写入 `*tree_id == 0`
#[test]
fn test_pdu_control_pdu_returns_zero_tree_id() {
    let context = Context::new();
    let pdu = allocated_pdu(Smb2Command::Echo);
    assert_eq!(smb2_get_tree_id_for_pdu(&context, Some(&pdu)).unwrap(), 0);
}

// Trace: `lib/pdu.c:smb2_set_tree_id_for_pdu`, `include/smb2/libsmb2.h:smb2_set_tree_id_for_pdu`
// Spec: smb2_set_tree_id_for_pdu update synchronous PDU tree id#data PDU tree id is updated
// - **GIVEN** PDU 非空、不是 async，并且命令不是 negotiate、session setup、logoff、echo 或 tree connect
// - **WHEN** 调用 `smb2_set_tree_id_for_pdu(smb2, pdu, tree_id)`
// - **THEN** 函数返回 `0` 并写入 `pdu->header.sync.tree_id`
#[test]
fn test_pdu_data_pdu_tree_id_is_updated() {
    let mut pdu = allocated_pdu(Smb2Command::Read);
    smb2_set_tree_id_for_pdu(Some(&mut pdu), 42).unwrap();
    assert_eq!(pdu.header.tree_id, 42);
}

// Trace: `lib/pdu.c:smb2_get_session_id`, `include/smb2/libsmb2.h:smb2_get_session_id`
// Spec: smb2_get_session_id expose context session id#session id is copied
// - **GIVEN** `session_id` 指向可写 `uint64_t`
// - **WHEN** 调用 `smb2_get_session_id(smb2, session_id)`
// - **THEN** `*session_id` 等于 `smb2->session_id` 且函数返回 `0`
#[test]
fn test_pdu_session_id_is_copied() {
    let mut context = Context::new();
    context.session_id = 0x0102_0304;
    assert_eq!(smb2_get_session_id(&context), 0x0102_0304);
}

// Trace: `lib/pdu.c:smb2_connect_tree_id`
// Spec: smb2_connect_tree_id push connected tree id#tree id is pushed and selected
// - **GIVEN** `smb2->tree_id_top < (SMB2_MAX_TREE_NESTING - 1)`
// - **WHEN** 调用 `smb2_connect_tree_id(smb2, tree_id)`
// - **THEN** 函数返回 `0`、递增 `tree_id_top`、写入 tree-id 并将 `tree_id_cur` 指向新槽位
#[test]
fn test_pdu_tree_id_is_pushed_and_selected() {
    let mut context = Context::new();
    smb2_connect_tree_id(&mut context, 9).unwrap();
    assert_eq!(context.current_tree_id(), 9);
}

// Trace: `lib/pdu.c:smb2_disconnect_tree_id`
// Spec: smb2_disconnect_tree_id remove connected tree id#tree id is removed
// - **GIVEN** `smb2->tree_id` 栈中存在目标 `tree_id`
// - **WHEN** 调用 `smb2_disconnect_tree_id(smb2, tree_id)`
// - **THEN** 函数返回 `0`、移除该槽位、压缩后续槽位，并保证 `tree_id_cur` 不超过新的 `tree_id_top`
#[test]
fn test_pdu_tree_id_is_removed() {
    let mut context = Context::new();
    context.tree_ids = vec![1, 2, 3];
    smb2_disconnect_tree_id(&mut context, 2).unwrap();
    assert_eq!(context.tree_ids, vec![1, 3]);
}

// Trace: `lib/pdu.c:smb2_pdu_is_compound`, `include/smb2/libsmb2.h:smb2_pdu_is_compound`
// Spec: smb2_pdu_is_compound report current receive compound state#compound state is detected
// - **GIVEN** `smb2` 非空且 `smb2->hdr.next_command != 0`
// - **WHEN** 调用 `smb2_pdu_is_compound(smb2)`
// - **THEN** 函数返回非零值
#[test]
fn test_pdu_compound_state_is_detected() {
    let mut context = Context::new();
    context.header.next_command = 64;
    assert!(smb2_pdu_is_compound(&context));
}

// Trace: `lib/pdu.c:smb2_add_compound_pdu`, `include/smb2/libsmb2.h:smb2_add_compound_pdu`, GitNexus `context smb2_add_compound_pdu`
// Spec: smb2_add_compound_pdu link and mark compound PDUs#next PDU is appended to chain tail
// - **GIVEN** `pdu` 可能已有 compound 后继且 `next_pdu` 是待追加 PDU
// - **WHEN** 调用 `smb2_add_compound_pdu(smb2, pdu, next_pdu)`
// - **THEN** 函数找到链尾、设置链尾 `next_compound`、更新链尾 header offset，并更新后续 PDU flags
#[test]
fn test_pdu_next_pdu_is_appended_to_chain_tail() {
    let mut first = allocated_pdu(Smb2Command::Read);
    let second = allocated_pdu(Smb2Command::Write);
    let appended = smb2_append_compound_pdu(&mut first, second).unwrap();
    assert!(appended.compound);
    assert_eq!(
        appended.header.flags & SMB2_FLAGS_RELATED_OPERATIONS,
        SMB2_FLAGS_RELATED_OPERATIONS
    );
    assert!(smb2_get_compound_pdu(&first).is_some());
}

// Trace: `lib/pdu.c:smb2_free_pdu`, `include/smb2/libsmb2.h:smb2_free_pdu`
// Spec: smb2_free_pdu release PDU resources#PDU resources are released
// - **GIVEN** PDU 可位于 outqueue、waitqueue 或 compound 链，并可携带 free callbacks、payload 和 crypt buffer
// - **WHEN** 调用 `smb2_free_pdu(smb2, pdu)`
// - **THEN** PDU 从相关队列移除，关联资源按源码定义释放
#[test]
fn test_pdu_pdu_resources_are_released() {
    let mut context = Context::new();
    let mut pdu = allocated_pdu(Smb2Command::Read);
    smb2_set_pdu_message_id(&mut pdu, 77);
    context.push_waitqueue(allocated_pdu(Smb2Command::Write));
    context.waitqueue[0].header.message_id = 77;
    smb2_set_pdu_payload(&mut pdu, vec![1, 2, 3]);
    smb2_free_pdu(&mut context, &mut pdu);
    assert!(context.find_waiting_pdu(77).is_none());
    assert_eq!(smb2_pdu_payload_state(&pdu), PduPayloadState::Empty);
}

// Trace: `lib/pdu.c:smb2_set_uint8`
// Spec: smb2_set_uint8 write bounded byte#byte write succeeds in bounds
// - **GIVEN** `offset + sizeof(uint8_t) <= iov->len`
// - **WHEN** 调用 `smb2_set_uint8(iov, offset, value)`
// - **THEN** `iov->buf[offset]` 被设置为 `value` 且返回 `0`
#[test]
fn test_pdu_byte_write_succeeds_in_bounds() {
    let mut iov = IoVec::new(vec![0; 2]);
    smb2_set_uint8(&mut iov, 1, 0xab).unwrap();
    assert_eq!(iov.buf[1], 0xab);
}

// Trace: `lib/pdu.c:smb2_set_uint16`
// Spec: smb2_set_uint16 write bounded little-endian value#uint16 write succeeds in bounds
// - **GIVEN** `offset + sizeof(uint16_t) <= iov->len`
// - **WHEN** 调用 `smb2_set_uint16(iov, offset, value)`
// - **THEN** 缓冲区对应位置包含 `htole16(value)` 且返回 `0`
#[test]
fn test_pdu_uint16_write_succeeds_in_bounds() {
    let mut iov = IoVec::new(vec![0; 3]);
    smb2_set_uint16(&mut iov, 1, 0x1234).unwrap();
    assert_eq!(&iov.buf[1..3], &0x1234u16.to_le_bytes());
}

// Trace: `lib/pdu.c:smb2_set_uint32`
// Spec: smb2_set_uint32 write bounded little-endian value#uint32 write succeeds in bounds
// - **GIVEN** `offset + sizeof(uint32_t) <= iov->len`
// - **WHEN** 调用 `smb2_set_uint32(iov, offset, value)`
// - **THEN** 缓冲区对应位置包含 `htole32(value)` 且返回 `0`
#[test]
fn test_pdu_uint32_write_succeeds_in_bounds() {
    let mut iov = IoVec::new(vec![0; 5]);
    smb2_set_uint32(&mut iov, 1, 0x1234_5678).unwrap();
    assert_eq!(&iov.buf[1..5], &0x1234_5678u32.to_le_bytes());
}

// Trace: `lib/pdu.c:smb2_set_uint64`
// Spec: smb2_set_uint64 write bounded little-endian value#uint64 write succeeds in bounds
// - **GIVEN** `offset + sizeof(uint64_t) <= iov->len`
// - **WHEN** 调用 `smb2_set_uint64(iov, offset, value)`
// - **THEN** 缓冲区对应位置包含 `htole64(value)` 且返回 `0`
#[test]
fn test_pdu_uint64_write_succeeds_in_bounds() {
    let mut iov = IoVec::new(vec![0; 9]);
    smb2_set_uint64(&mut iov, 1, 0x0102_0304_0506_0708).unwrap();
    assert_eq!(&iov.buf[1..9], &0x0102_0304_0506_0708u64.to_le_bytes());
}

// Trace: `lib/pdu.c:smb2_get_uint8`
// Spec: smb2_get_uint8 read bounded byte#byte read succeeds in bounds
// - **GIVEN** `offset + sizeof(uint8_t) <= iov->len`
// - **WHEN** 调用 `smb2_get_uint8(iov, offset, value)`
// - **THEN** `*value` 等于缓冲区对应字节且返回 `0`
#[test]
fn test_pdu_byte_read_succeeds_in_bounds() {
    assert_eq!(smb2_get_uint8(&IoVec::new(vec![0, 0xab]), 1).unwrap(), 0xab);
}

// Trace: `lib/pdu.c:smb2_get_uint16`
// Spec: smb2_get_uint16 read bounded little-endian value#uint16 read succeeds in bounds
// - **GIVEN** `offset + sizeof(uint16_t) <= iov->len`
// - **WHEN** 调用 `smb2_get_uint16(iov, offset, value)`
// - **THEN** `*value` 等于 `le16toh` 转换后的缓冲区值且返回 `0`
#[test]
fn test_pdu_uint16_read_succeeds_in_bounds() {
    assert_eq!(
        smb2_get_uint16(&IoVec::new(vec![0, 0x34, 0x12]), 1).unwrap(),
        0x1234
    );
}

// Trace: `lib/pdu.c:smb2_get_uint32`
// Spec: smb2_get_uint32 read bounded little-endian value#uint32 read succeeds in bounds
// - **GIVEN** `offset + sizeof(uint32_t) <= iov->len`
// - **WHEN** 调用 `smb2_get_uint32(iov, offset, value)`
// - **THEN** `*value` 等于 `le32toh` 转换后的缓冲区值且返回 `0`
#[test]
fn test_pdu_uint32_read_succeeds_in_bounds() {
    assert_eq!(
        smb2_get_uint32(&IoVec::new(vec![0, 0x78, 0x56, 0x34, 0x12]), 1).unwrap(),
        0x1234_5678
    );
}

// Trace: `lib/pdu.c:smb2_get_uint64`
// Spec: smb2_get_uint64 read bounded little-endian value#uint64 read succeeds in bounds
// - **GIVEN** `offset + sizeof(uint64_t) <= iov->len`
// - **WHEN** 调用 `smb2_get_uint64(iov, offset, value)`
// - **THEN** `*value` 等于 `le64toh` 转换后的缓冲区值且返回 `0`
#[test]
fn test_pdu_uint64_read_succeeds_in_bounds() {
    let bytes = [0, 8, 7, 6, 5, 4, 3, 2, 1];
    assert_eq!(
        smb2_get_uint64(&IoVec::new(bytes.to_vec()), 1).unwrap(),
        0x0102_0304_0506_0708
    );
}

// Trace: `lib/pdu.c:smb2_decode_header`, GitNexus `context smb2_decode_header`
// Spec: smb2_decode_header parse SMB header#SMB2 header is decoded
// - **GIVEN** iovec 长度至少为 `SMB2_HEADER_SIZE` 且前 4 字节是 SMB2 magic
// - **WHEN** 调用 `smb2_decode_header(smb2, iov, hdr)`
// - **THEN** 函数解码 header 字段、处理 async/sync union、复制 signature，并返回 `0`
#[test]
fn test_pdu_smb2_header_is_decoded() {
    let mut header = smb2_header_for_command(Smb2Command::Read);
    header.message_id = 123;
    let mut bytes = vec![0; SMB2_HEADER_STRUCT_SIZE as usize];
    smb2_encode_header_bytes(&mut bytes, &header).unwrap();
    let decoded = smb2_decode_header_bytes(&bytes).unwrap();
    assert_eq!(decoded.message_id, 123);
    assert_eq!(decoded.command, Smb2Command::Read.as_u16());
}

// Trace: `lib/pdu.c:smb2_decode_header`
// Spec: smb2_decode_header parse SMB header#SMB1 negotiate is allowed
// - **GIVEN** iovec 前 4 字节是 SMB1 magic 且命令字节是 `SMB1_NEGOTIATE`
// - **WHEN** 调用 `smb2_decode_header(smb2, iov, hdr)`
// - **THEN** 函数清零 header、设置 `hdr->command = SMB1_NEGOTIATE` 并返回 `0`
#[test]
fn test_pdu_smb1_negotiate_is_allowed() {
    let mut bytes = vec![0; SMB2_HEADER_STRUCT_SIZE as usize];
    bytes[..4].copy_from_slice(&SMB1_PROTOCOL_ID);
    bytes[4] = SMB1_NEGOTIATE;
    let decoded = smb2_decode_header_bytes(&bytes).unwrap();
    assert_eq!(decoded.protocol_id, SMB1_PROTOCOL_ID);
}

// Trace: `lib/pdu.c:smb2_queue_pdu`, `include/smb2/libsmb2.h:smb2_queue_pdu`, GitNexus `context smb2_queue_pdu`, GitNexus `impact Function:lib/pdu.c:smb2_queue_pdu`
// Spec: smb2_queue_pdu encode and enqueue outbound PDU chain#client PDU chain is queued
// - **GIVEN** `smb2` 不是 server，PDU 链可编码，并且签名/加密条件由上下文和命令决定
// - **WHEN** 调用 `smb2_queue_pdu(smb2, pdu)`
// - **THEN** 每个 PDU header 被编码，`prev_compound_mid` 保留顺序，必要时添加签名，链头经过加密处理后加入 outqueue
#[test]
fn test_pdu_client_pdu_chain_is_queued() {
    let mut context = Context::new();
    let pdu = allocated_pdu(Smb2Command::Read);
    smb2_queue_pdu(&mut context, pdu).unwrap();
    assert_eq!(context.outqueue.len(), 1);
    assert_eq!(context.message_id, 1);
}

// Trace: `lib/pdu.c:smb2_queue_pdu`
// Spec: smb2_queue_pdu encode and enqueue outbound PDU chain#server PDU without message id is rejected
// - **GIVEN** `smb2` 是 server、PDU command 不是 negotiate、且 PDU message-id 为 0
// - **WHEN** 调用 `smb2_queue_pdu(smb2, pdu)`
// - **THEN** 函数设置错误、释放该 PDU 并提前返回，不将其加入 outqueue
#[test]
fn test_pdu_server_pdu_without_message_id_is_rejected() {
    let mut context = Context::new();
    context.private.owning_server = Some(ServerRef { id: Some(1) });
    let pdu = allocated_pdu(Smb2Command::Read);

    assert_eq!(
        smb2_queue_pdu(&mut context, pdu).unwrap_err(),
        PduError::MissingMessageId
    );
    assert_eq!(context.error(), "Queued pdu has no message id");
    assert!(context.outqueue.is_empty());
}

// Trace: `lib/pdu.c:smb2_get_compound_pdu`, `include/smb2/libsmb2.h:smb2_get_compound_pdu`
// Spec: smb2_get_compound_pdu return next compound PDU#next compound PDU exists
// - **GIVEN** `pdu` 非空且 `pdu->next_compound` 非空
// - **WHEN** 调用 `smb2_get_compound_pdu(smb2, pdu)`
// - **THEN** 函数返回 `pdu->next_compound`
#[test]
fn test_pdu_next_compound_pdu_exists() {
    let mut first = allocated_pdu(Smb2Command::Read);
    smb2_append_compound_pdu(&mut first, allocated_pdu(Smb2Command::Write)).unwrap();
    assert!(smb2_get_compound_pdu(&first).is_some());
}

// Trace: `lib/pdu.c:smb2_set_pdu_status`, `include/smb2/libsmb2.h:smb2_set_pdu_status`
// Spec: smb2_set_pdu_status update PDU status#PDU status is set
// - **GIVEN** PDU 指针有效
// - **WHEN** 调用 `smb2_set_pdu_status(smb2, pdu, status)`
// - **THEN** `pdu->header.status` 等于传入 status
#[test]
fn test_pdu_pdu_status_is_set() {
    let mut pdu = allocated_pdu(Smb2Command::Read);
    smb2_set_pdu_status(&mut pdu, 0xc000_0001);
    assert_eq!(pdu.header.status, 0xc000_0001);
}

// Trace: `lib/pdu.c:smb2_set_pdu_message_id`, `include/smb2/libsmb2.h:smb2_set_pdu_message_id`
// Spec: smb2_set_pdu_message_id update PDU message id#PDU message id is set
// - **GIVEN** PDU 指针有效
// - **WHEN** 调用 `smb2_set_pdu_message_id(smb2, pdu, message_id)`
// - **THEN** `pdu->header.message_id` 等于传入 message-id
#[test]
fn test_pdu_pdu_message_id_is_set() {
    let mut pdu = allocated_pdu(Smb2Command::Read);
    smb2_set_pdu_message_id(&mut pdu, 99);
    assert_eq!(pdu.header.message_id, 99);
}

// Trace: `lib/pdu.c:smb2_get_pdu_message_id`, `include/smb2/libsmb2.h:smb2_get_pdu_message_id`
// Spec: smb2_get_pdu_message_id return PDU message id#PDU message id is returned
// - **GIVEN** PDU 指针有效
// - **WHEN** 调用 `smb2_get_pdu_message_id(smb2, pdu)`
// - **THEN** 返回值等于 `pdu->header.message_id`
#[test]
fn test_pdu_pdu_message_id_is_returned() {
    let mut pdu = allocated_pdu(Smb2Command::Read);
    smb2_set_pdu_message_id(&mut pdu, 99);
    assert_eq!(smb2_get_pdu_message_id(Some(&pdu)), 99);
}

// Trace: `lib/pdu.c:smb2_get_last_request_message_id`, `include/smb2/libsmb2.h:smb2_get_last_request_message_id`
// Spec: smb2_get_last_request_message_id return context request cursor#last request message id is returned
// - **GIVEN** `smb2` 非空
// - **WHEN** 调用 `smb2_get_last_request_message_id(smb2)`
// - **THEN** 返回值等于 `smb2->message_id`
#[test]
fn test_pdu_last_request_message_id_is_returned() {
    let mut context = Context::new();
    context.message_id = 44;
    assert_eq!(smb2_get_last_request_message_id(&context), 44);
}

// Trace: `lib/pdu.c:smb2_get_last_reply_message_id`, `include/smb2/libsmb2.h:smb2_get_last_reply_message_id`
// Spec: smb2_get_last_reply_message_id return decoded reply message id#last reply message id is returned
// - **GIVEN** `smb2` 非空
// - **WHEN** 调用 `smb2_get_last_reply_message_id(smb2)`
// - **THEN** 返回值等于 `smb2->hdr.message_id`
#[test]
fn test_pdu_last_reply_message_id_is_returned() {
    let mut context = Context::new();
    context.header.message_id = 55;
    assert_eq!(smb2_get_last_reply_message_id(&context), 55);
}

// Trace: `lib/pdu.c:smb2_find_pdu`
// Spec: smb2_find_pdu locate waiting request by message id#matching PDU is found
// - **GIVEN** `smb2->waitqueue` 中存在 `header.message_id == message_id` 的 PDU
// - **WHEN** 调用 `smb2_find_pdu(smb2, message_id)`
// - **THEN** 函数返回该 PDU 指针
#[test]
fn test_pdu_matching_pdu_is_found() {
    let mut context = Context::new();
    let mut pdu = allocated_pdu(Smb2Command::Read);
    smb2_set_pdu_message_id(&mut pdu, 11);
    context.push_waitqueue(pdu);
    assert_eq!(smb2_find_pdu(&context, 11).unwrap().header.message_id, 11);
}

// Trace: `lib/pdu.c:smb2_get_fixed_reply_size`
// Spec: smb2_get_fixed_reply_size map reply command sizes#known reply command returns fixed size
// - **GIVEN** PDU command 是源码 switch 中列出的 SMB2 reply 命令且当前 header 不是错误响应
// - **WHEN** 调用 `smb2_get_fixed_reply_size(smb2, pdu)`
// - **THEN** 函数返回该命令对应的 `SMB2_*_REPLY_SIZE`
#[test]
fn test_pdu_known_reply_command_returns_fixed_size() {
    assert!(smb2_get_fixed_reply_size(&Context::new(), Smb2Command::Echo) > 0);
}

// Trace: `lib/pdu.c:smb2_get_fixed_request_size`
// Spec: smb2_get_fixed_request_size map request command sizes#known request command returns fixed size
// - **GIVEN** PDU command 是源码 switch 中列出的 SMB2 request 命令
// - **WHEN** 调用 `smb2_get_fixed_request_size(smb2, pdu)`
// - **THEN** 函数返回该命令对应的 `SMB2_*_REQUEST_SIZE`
#[test]
fn test_pdu_known_request_command_returns_fixed_size() {
    assert!(smb2_get_fixed_request_size(Smb2Command::Echo) > 0);
}

// Trace: `lib/pdu.c:smb2_get_fixed_size`
// Spec: smb2_get_fixed_size dispatch by context role#server mode dispatches request size
// - **GIVEN** `smb2_is_server(smb2)` 返回非零
// - **WHEN** 调用 `smb2_get_fixed_size(smb2, pdu)`
// - **THEN** 返回值等于 `smb2_get_fixed_request_size(smb2, pdu)`
#[test]
fn test_pdu_server_mode_dispatches_request_size() {
    assert_eq!(
        smb2_get_fixed_size(Smb2Command::Echo, true),
        smb2_get_fixed_request_size(Smb2Command::Echo)
    );
}

// Trace: `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_reply_payload_fixed dispatch fixed reply parser#fixed reply command dispatches parser
// - **GIVEN** 当前 header 不是错误响应且 PDU command 是源码 switch 中列出的 reply 命令
// - **WHEN** 调用 `smb2_process_reply_payload_fixed(smb2, pdu)`
// - **THEN** 函数返回对应 `smb2_process_*_fixed` 处理器的返回值
#[test]
fn test_pdu_fixed_reply_command_dispatches_parser() {
    assert_eq!(
        smb2_payload_handler(Smb2Command::Echo).unwrap().reply_fixed,
        "smb2_process_echo"
    );
}

// Trace: `lib/pdu.c:smb2_process_reply_payload_variable`
// Spec: smb2_process_reply_payload_variable dispatch variable reply parser#variable reply command dispatches parser
// - **GIVEN** 当前 header 不是错误响应且 PDU command 是源码 switch 中映射到 variable parser 的 reply 命令
// - **WHEN** 调用 `smb2_process_reply_payload_variable(smb2, pdu)`
// - **THEN** 函数返回对应 `smb2_process_*_variable` 处理器的返回值
#[test]
fn test_pdu_variable_reply_command_dispatches_parser() {
    assert_eq!(
        smb2_payload_handler(Smb2Command::QueryInfo)
            .unwrap()
            .reply_variable,
        "smb2_process_query_info"
    );
}

// Trace: `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_request_payload_fixed dispatch fixed request parser#fixed request command dispatches parser
// - **GIVEN** PDU command 是源码 switch 中映射到 fixed request parser 的命令
// - **WHEN** 调用 `smb2_process_request_payload_fixed(smb2, pdu)`
// - **THEN** 函数返回对应 `smb2_process_*_request_fixed` 处理器的返回值
#[test]
fn test_pdu_fixed_request_command_dispatches_parser() {
    assert_eq!(
        smb2_payload_handler(Smb2Command::Echo)
            .unwrap()
            .request_fixed,
        "smb2_process_echo"
    );
}

// Trace: `lib/pdu.c:smb2_process_request_payload_variable`
// Spec: smb2_process_request_payload_variable dispatch variable request parser#variable request command dispatches parser
// - **GIVEN** PDU command 是源码 switch 中映射到 variable request parser 的命令
// - **WHEN** 调用 `smb2_process_request_payload_variable(smb2, pdu)`
// - **THEN** 函数返回对应 `smb2_process_*_request_variable` 处理器的返回值
#[test]
fn test_pdu_variable_request_command_dispatches_parser() {
    assert_eq!(
        smb2_payload_handler(Smb2Command::QueryInfo)
            .unwrap()
            .request_variable,
        "smb2_process_query_info"
    );
}

// Trace: `lib/pdu.c:smb2_process_payload_fixed`, GitNexus `context smb2_process_payload_fixed`
// Spec: smb2_process_payload_fixed dispatch fixed payload by role#fixed payload dispatches by role
// - **GIVEN** `smb2` 上下文处于 server 或 client 角色
// - **WHEN** 调用 `smb2_process_payload_fixed(smb2, pdu)`
// - **THEN** 返回值来自对应 request 或 reply fixed payload 分派函数
#[test]
fn test_pdu_fixed_payload_dispatches_by_role() {
    assert_eq!(
        smb2_get_fixed_size(Smb2Command::Echo, true),
        smb2_get_fixed_request_size(Smb2Command::Echo)
    );
    assert_eq!(
        smb2_get_fixed_size(Smb2Command::Echo, false),
        smb2_get_fixed_reply_size(&Context::new(), Smb2Command::Echo)
    );
}

// Trace: `lib/pdu.c:smb2_process_payload_variable`
// Spec: smb2_process_payload_variable dispatch variable payload by role#variable payload dispatches by role
// - **GIVEN** `smb2` 上下文处于 server 或 client 角色
// - **WHEN** 调用 `smb2_process_payload_variable(smb2, pdu)`
// - **THEN** 返回值来自对应 request 或 reply variable payload 分派函数
#[test]
fn test_pdu_variable_payload_dispatches_by_role() {
    assert_eq!(
        smb2_payload_handler(Smb2Command::QueryInfo)
            .unwrap()
            .request_variable,
        "smb2_process_query_info"
    );
    assert_eq!(
        smb2_payload_handler(Smb2Command::QueryInfo)
            .unwrap()
            .reply_variable,
        "smb2_process_query_info"
    );
}

// Trace: `lib/pdu.c:smb2_timeout_pdus`, GitNexus `context smb2_timeout_pdus`
// Spec: smb2_timeout_pdus expire queued PDUs#expired queued PDU times out
// - **GIVEN** outqueue 或 waitqueue 中的 PDU 设置了 timeout 且 timeout 小于当前 `time(NULL)`
// - **WHEN** 调用 `smb2_timeout_pdus(smb2)`
// - **THEN** 该 PDU 从队列移除，回调收到 `SMB2_STATUS_IO_TIMEOUT`、`NULL` command data 和原始 cb_data，并释放该 PDU
#[test]
fn test_pdu_expired_queued_pdu_times_out() {
    let mut context = Context::new();
    let mut pdu = allocated_pdu(Smb2Command::Read);
    smb2_set_pdu_timeout(&mut pdu, Some(10));
    context.push_waitqueue(pdu);
    smb2_timeout_pdus(&mut context, 11);
    assert!(context.waitqueue.is_empty());
}
