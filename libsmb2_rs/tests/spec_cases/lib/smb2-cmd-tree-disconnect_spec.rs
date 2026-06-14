use libsmb2_rs::lib::smb2_cmd_tree_disconnect::{
    self as tree, Smb2TreeDisconnectContext, Smb2TreeDisconnectPdu, TreeDisconnectError,
    SMB2_TREE_DISCONNECT, SMB2_TREE_DISCONNECT_REPLY_SIZE, SMB2_TREE_DISCONNECT_REQUEST_SIZE,
};

// Trace: `lib/smb2-cmd-tree-disconnect.c:smb2_cmd_tree_disconnect_async`, `include/smb2/libsmb2-raw.h:128`
// Spec: smb2_cmd_tree_disconnect_async request PDU creation#创建请求 PDU 成功
// - **GIVEN** 调用方提供有效的 `smb2_context`、回调函数和回调数据
// - **WHEN** 调用 `smb2_cmd_tree_disconnect_async`
// - **THEN** 返回值 MUST 是使用 `SMB2_TREE_DISCONNECT` 命令码创建、包含 4 字节 tree-disconnect 请求结构并完成 64 位填充的 `struct smb2_pdu *`
#[test]
fn test_smb2_cmd_tree_disconnect_request_pdu_success() {
    let pdu = tree::smb2_cmd_tree_disconnect_async().unwrap();

    assert_eq!(pdu.command, SMB2_TREE_DISCONNECT);
    assert_eq!(u16::from_le_bytes(pdu.out[0][0..2].try_into().unwrap()), 4);
    assert_eq!(pdu.out.iter().map(Vec::len).sum::<usize>() % 8, 0);
}

// Trace: `lib/smb2-cmd-tree-disconnect.c:smb2_cmd_tree_disconnect_reply_async`, `include/smb2/libsmb2-raw.h:131`
// Spec: smb2_cmd_tree_disconnect_reply_async reply PDU creation#创建响应 PDU 成功
// - **GIVEN** 调用方提供有效的 `smb2_context`、回调函数和回调数据
// - **WHEN** 调用 `smb2_cmd_tree_disconnect_reply_async`
// - **THEN** 返回值 MUST 是使用 `SMB2_TREE_DISCONNECT` 命令码创建、包含 4 字节 tree-disconnect 响应结构并完成 64 位填充的 `struct smb2_pdu *`
#[test]
fn test_smb2_cmd_tree_disconnect_reply_pdu_success() {
    let pdu = tree::smb2_cmd_tree_disconnect_reply_async().unwrap();

    assert_eq!(pdu.command, SMB2_TREE_DISCONNECT);
    assert_eq!(
        u16::from_le_bytes(pdu.out[0][0..2].try_into().unwrap()),
        SMB2_TREE_DISCONNECT_REPLY_SIZE
    );
    assert_eq!(pdu.out.iter().map(Vec::len).sum::<usize>() % 8, 0);
}

// Trace: `lib/smb2-cmd-tree-disconnect.c:smb2_process_tree_disconnect_fixed`, `include/libsmb2-private.h:469`
// Spec: smb2_process_tree_disconnect_fixed reply state update#处理 tree-disconnect 响应固定载荷
// - **GIVEN** `smb2->hdr.sync.tree_id` 包含待断开的 tree id
// - **WHEN** 调用 `smb2_process_tree_disconnect_fixed`
// - **THEN** 函数 MUST 调用 `smb2_disconnect_tree_id(smb2, smb2->hdr.sync.tree_id)` 并返回 `0`
#[test]
fn test_smb2_cmd_tree_disconnect_reply_state_update() {
    let mut context = Smb2TreeDisconnectContext::new();
    let mut pdu = Smb2TreeDisconnectPdu::new_tree_disconnect();
    let fixed = tree::smb2_encode_tree_disconnect_reply().unwrap();
    context.connect_tree_id(0x55).unwrap();

    tree::smb2_process_tree_disconnect_fixed(&mut context, &mut pdu, &fixed, 0x55).unwrap();

    assert!(context.tree_ids().is_empty());
    assert!(pdu.reply.is_some());
}

// Trace: `lib/smb2-cmd-tree-disconnect.c:smb2_process_tree_disconnect_request_fixed`, `include/libsmb2-private.h:471`
// Spec: smb2_process_tree_disconnect_request_fixed request no-op success#处理 tree-disconnect 请求固定载荷
// - **GIVEN** 服务端请求处理路径收到 tree-disconnect 固定载荷
// - **WHEN** 调用 `smb2_process_tree_disconnect_request_fixed`
// - **THEN** 函数 MUST 返回 `0`，且源码中不访问 `pdu` 或修改 `smb2` 状态
#[test]
fn test_smb2_cmd_tree_disconnect_request_no_op_success() {
    let mut pdu = Smb2TreeDisconnectPdu::new_tree_disconnect();
    let fixed = tree::smb2_encode_tree_disconnect_request().unwrap();

    tree::smb2_process_tree_disconnect_request_fixed(&mut pdu, &fixed).unwrap();

    assert!(pdu.request.is_some());
}

#[test]
fn test_smb2_cmd_tree_disconnect_rejects_invalid_fixed_sizes() {
    let mut context = Smb2TreeDisconnectContext::new();
    let mut pdu = Smb2TreeDisconnectPdu::new_tree_disconnect();
    context.connect_tree_id(1).unwrap();

    assert!(matches!(
        tree::smb2_process_tree_disconnect_fixed(&mut context, &mut pdu, &[0, 0], 1),
        Err(TreeDisconnectError::BufferTooShort { .. })
    ));
    assert_eq!(context.tree_id(), 1);
    assert!(matches!(
        tree::smb2_process_tree_disconnect_request_fixed(
            &mut pdu,
            &SMB2_TREE_DISCONNECT_REQUEST_SIZE.to_le_bytes()
        ),
        Err(TreeDisconnectError::InvalidStructureSize { .. })
    ));
}
