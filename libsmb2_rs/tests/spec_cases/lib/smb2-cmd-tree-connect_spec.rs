use libsmb2_rs::lib::smb2_cmd_tree_connect::{
    self as tree, Smb2TreeConnectContext, Smb2TreeConnectPdu, Smb2TreeConnectReply,
    Smb2TreeConnectRequest, TreeConnectError, SMB2_SHAREFLAG_ENCRYPT_DATA, SMB2_TREE_CONNECT,
    SMB2_TREE_CONNECT_REPLY_SIZE, SMB2_TREE_CONNECT_REQUEST_SIZE,
};

// Trace: `lib/smb2-cmd-tree-connect.c:smb2_cmd_tree_connect_async`, `lib/smb2-cmd-tree-connect.c:smb2_encode_tree_connect_request`
// Spec: smb2_cmd_tree_connect_async builds a Tree Connect request PDU#成功编码请求
// - **GIVEN** 调用方提供有效的 `smb2_context`、Tree Connect request、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_tree_connect_async`
// - **THEN** 返回的 PDU MUST 使用 `SMB2_TREE_CONNECT` 命令、包含大小为 `SMB2_TREE_CONNECT_REQUEST_SIZE` 的固定区、设置 flags/path offset/path length，并追加原始路径字节后按 64 位边界填充
#[test]
fn test_smb2_cmd_tree_connect_successful_request_encoding() {
    let path = br"\\server\share".to_vec();
    let request = Smb2TreeConnectRequest::new(0x12, path.clone()).unwrap();

    let pdu = tree::smb2_cmd_tree_connect_async(&request).unwrap();

    assert_eq!(pdu.command, SMB2_TREE_CONNECT);
    assert_eq!(
        u16::from_le_bytes([pdu.out[0][0], pdu.out[0][1]]),
        SMB2_TREE_CONNECT_REQUEST_SIZE
    );
    assert_eq!(u16::from_le_bytes([pdu.out[0][2], pdu.out[0][3]]), 0x12);
    assert_eq!(
        u16::from_le_bytes([pdu.out[0][6], pdu.out[0][7]]),
        path.len() as u16
    );
    assert_eq!(pdu.out[1], path);
    assert_eq!(pdu.out.iter().map(Vec::len).sum::<usize>() % 8, 0);
}

// Trace: `lib/smb2-cmd-tree-connect.c:smb2_cmd_tree_connect_async`, `include/smb2/libsmb2-raw.h:87`
// Spec: smb2_cmd_tree_connect_async builds a Tree Connect request PDU#编码或填充失败
// - **GIVEN** PDU 分配成功但固定区、路径 iovec 或 64 位填充无法完成
// - **WHEN** 调用 `smb2_cmd_tree_connect_async`
// - **THEN** 函数 MUST 释放已分配的 PDU 并返回 `NULL`，且不会调用传入回调
#[test]
fn test_smb2_cmd_tree_connect_encoding_or_padding_failure() {
    let path = vec![0_u8; usize::from(u16::MAX) + 1];

    let error = Smb2TreeConnectRequest::new(0, path).unwrap_err();

    assert_eq!(
        error,
        TreeConnectError::PathTooLong {
            length: usize::from(u16::MAX) + 1
        }
    );
}

// Trace: `lib/smb2-cmd-tree-connect.c:smb2_cmd_tree_connect_reply_async`, `lib/smb2-cmd-tree-connect.c:smb2_encode_tree_connect_reply`
// Spec: smb2_cmd_tree_connect_reply_async builds a Tree Connect reply PDU#调用方提供 tree id
// - **GIVEN** 调用方提供非零 `tree_id` 和 Tree Connect reply 数据
// - **WHEN** 调用 `smb2_cmd_tree_connect_reply_async`
// - **THEN** 函数 MUST 连接该 tree id，将 PDU header 的 `tree_id` 设置为当前上下文 tree id，并编码 share type、share flags、capabilities 和 maximal access
#[test]
fn test_smb2_cmd_tree_connect_reply_caller_provided_tree_id() {
    let mut context = Smb2TreeConnectContext::new();
    let reply = Smb2TreeConnectReply::new(1, 2, 3, 4);

    let pdu = tree::smb2_cmd_tree_connect_reply_async(&mut context, &reply, 0x44).unwrap();

    assert_eq!(context.tree_id(), 0x44);
    assert_eq!(pdu.tree_id, 0x44);
    assert_eq!(
        u16::from_le_bytes([pdu.out[0][0], pdu.out[0][1]]),
        SMB2_TREE_CONNECT_REPLY_SIZE
    );
    assert_eq!(pdu.out[0][2], 1);
    assert_eq!(
        u32::from_le_bytes([pdu.out[0][4], pdu.out[0][5], pdu.out[0][6], pdu.out[0][7]]),
        2
    );
}

// Trace: `lib/smb2-cmd-tree-connect.c:smb2_cmd_tree_connect_reply_async`
// Spec: smb2_cmd_tree_connect_reply_async builds a Tree Connect reply PDU#调用方未提供 tree id
// - **GIVEN** 调用方传入 `tree_id` 为 0
// - **WHEN** 调用 `smb2_cmd_tree_connect_reply_async`
// - **THEN** 函数 MUST 从静态递增种子生成替代 tree id，并按生成的 tree id 连接上下文和设置 PDU header
#[test]
fn test_smb2_cmd_tree_connect_reply_generates_tree_id() {
    let mut context = Smb2TreeConnectContext::new();
    let reply = Smb2TreeConnectReply::new(1, 0, 0, 0);

    let pdu = tree::smb2_cmd_tree_connect_reply_async(&mut context, &reply, 0).unwrap();

    assert_ne!(pdu.tree_id, 0);
    assert_eq!(pdu.tree_id, context.tree_id());
}

// Trace: `lib/smb2-cmd-tree-connect.c:smb2_cmd_tree_connect_reply_async`
// Spec: smb2_cmd_tree_connect_reply_async builds a Tree Connect reply PDU#reply 编码或填充失败
// - **GIVEN** PDU 分配成功但 reply 编码或 64 位填充无法完成
// - **WHEN** 调用 `smb2_cmd_tree_connect_reply_async`
// - **THEN** 函数 MUST 释放已分配的 PDU 并返回 `NULL`
#[test]
fn test_smb2_cmd_tree_connect_reply_encoding_or_padding_failure() {
    let mut context = Smb2TreeConnectContext::new();
    for tree_id in 1..=tree::SMB2_MAX_TREE_NESTING as u32 {
        context.connect_tree_id(tree_id).unwrap();
    }

    let error = tree::smb2_cmd_tree_connect_reply_async(
        &mut context,
        &Smb2TreeConnectReply::new(1, 0, 0, 0),
        99,
    )
    .unwrap_err();

    assert_eq!(error, TreeConnectError::TreeNestingTooDeep);
}

// Trace: `lib/smb2-cmd-tree-connect.c:smb2_process_tree_connect_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`
// Spec: smb2_process_tree_connect_fixed decodes a fixed Tree Connect reply#固定 reply 有效
// - **GIVEN** 当前输入 iovec 的结构大小等于 `SMB2_TREE_CONNECT_REPLY_SIZE` 且偶数化结构大小等于 iovec 长度
// - **WHEN** 调用 `smb2_process_tree_connect_fixed`
// - **THEN** 函数 MUST 分配 `struct smb2_tree_connect_reply` 到 `pdu->payload`，连接 `smb2->hdr.sync.tree_id`，解码 share type、share flags、capabilities 和 maximal access，并返回 0
#[test]
fn test_smb2_cmd_tree_connect_fixed_valid_reply() {
    let mut context = Smb2TreeConnectContext::new();
    let mut pdu = Smb2TreeConnectPdu::new_tree_connect();
    let fixed =
        tree::smb2_encode_tree_connect_reply(&Smb2TreeConnectReply::new(2, 3, 4, 5)).unwrap();

    tree::smb2_process_tree_connect_fixed(&mut context, &mut pdu, &fixed, 0x77).unwrap();

    assert_eq!(context.tree_id(), 0x77);
    assert_eq!(pdu.reply.as_ref().unwrap().share_type, 2);
    assert_eq!(pdu.reply.as_ref().unwrap().share_flags, 3);
}

// Trace: `lib/smb2-cmd-tree-connect.c:smb2_process_tree_connect_fixed`
// Spec: smb2_process_tree_connect_fixed decodes a fixed Tree Connect reply#reply 大小无效或内存不足
// - **GIVEN** 当前输入 iovec 的结构大小不匹配、长度不匹配或 reply payload 分配失败
// - **WHEN** 调用 `smb2_process_tree_connect_fixed`
// - **THEN** 函数 MUST 设置错误信息并返回 -1
#[test]
fn test_smb2_cmd_tree_connect_fixed_invalid_reply_size() {
    let mut context = Smb2TreeConnectContext::new();
    let mut pdu = Smb2TreeConnectPdu::new_tree_connect();
    let fixed = [0_u8; 4];

    let error =
        tree::smb2_process_tree_connect_fixed(&mut context, &mut pdu, &fixed, 1).unwrap_err();

    assert!(matches!(
        error,
        TreeConnectError::InvalidStructureSize { .. }
    ));
}

// Trace: `lib/smb2-cmd-tree-connect.c:smb2_process_tree_connect_fixed`, `include/smb2/smb2.h:209`
// Spec: smb2_process_tree_connect_fixed decodes a fixed Tree Connect reply#share 要求加密且上下文尚未 sealing
// - **GIVEN** 当前上下文 `smb2->seal` 为 false 且 reply `share_flags` 包含 `SMB2_SHAREFLAG_ENCRYPT_DATA`
// - **WHEN** `smb2_process_tree_connect_fixed` 解码 reply
// - **THEN** 函数 MUST 将 `smb2->seal` 设置为 true
#[test]
fn test_smb2_cmd_tree_connect_fixed_enables_sealing() {
    let mut context = Smb2TreeConnectContext::new();
    let mut pdu = Smb2TreeConnectPdu::new_tree_connect();
    let fixed = tree::smb2_encode_tree_connect_reply(&Smb2TreeConnectReply::new(
        1,
        SMB2_SHAREFLAG_ENCRYPT_DATA,
        0,
        0,
    ))
    .unwrap();

    tree::smb2_process_tree_connect_fixed(&mut context, &mut pdu, &fixed, 1).unwrap();

    assert!(context.seal());
}

// Trace: `lib/smb2-cmd-tree-connect.c:smb2_process_tree_connect_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`
// Spec: smb2_process_tree_connect_request_fixed decodes a fixed Tree Connect request#固定 request 有效
// - **GIVEN** 当前输入 iovec 的结构大小等于 `SMB2_TREE_CONNECT_REQUEST_SIZE` 且偶数化结构大小等于 iovec 长度
// - **WHEN** 调用 `smb2_process_tree_connect_request_fixed`
// - **THEN** 函数 MUST 分配 `struct smb2_tree_connect_request` 到 `pdu->payload`，解码 flags、path offset 和 path length，并返回 `req->path_length`
#[test]
fn test_smb2_cmd_tree_connect_request_fixed_valid() {
    let request = Smb2TreeConnectRequest::new(3, vec![1, 2, 3, 4]).unwrap();
    let fixed = tree::smb2_encode_tree_connect_request(&request)
        .unwrap()
        .remove(0);
    let mut pdu = Smb2TreeConnectPdu::new_tree_connect();

    let needed = tree::smb2_process_tree_connect_request_fixed(&mut pdu, &fixed).unwrap();

    assert_eq!(needed, 4);
    assert_eq!(pdu.request.as_ref().unwrap().flags, 3);
}

// Trace: `lib/smb2-cmd-tree-connect.c:smb2_process_tree_connect_request_fixed`
// Spec: smb2_process_tree_connect_request_fixed decodes a fixed Tree Connect request#request 大小无效或内存不足
// - **GIVEN** 当前输入 iovec 的结构大小不匹配、长度不匹配或 request payload 分配失败
// - **WHEN** 调用 `smb2_process_tree_connect_request_fixed`
// - **THEN** 函数 MUST 设置错误信息并返回 -1
#[test]
fn test_smb2_cmd_tree_connect_request_fixed_invalid_size() {
    let mut pdu = Smb2TreeConnectPdu::new_tree_connect();

    let error = tree::smb2_process_tree_connect_request_fixed(&mut pdu, &[0, 0]).unwrap_err();

    assert!(matches!(
        error,
        TreeConnectError::InvalidStructureSize { .. }
    ));
}

// Trace: `lib/smb2-cmd-tree-connect.c:smb2_process_tree_connect_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`
// Spec: smb2_process_tree_connect_request_variable binds the request path buffer#变量路径区已读取
// - **GIVEN** `pdu->payload` 指向已分配的 `struct smb2_tree_connect_request`，当前输入 iovec 包含路径变量区
// - **WHEN** 调用 `smb2_process_tree_connect_request_variable`
// - **THEN** 函数 MUST 将 `req->path` 指向当前 iovec 的 `buf`，并返回 0
#[test]
fn test_smb2_cmd_tree_connect_request_variable_binds_path() {
    let request = Smb2TreeConnectRequest::new(0, vec![9, 8, 7]).unwrap();
    let fixed = tree::smb2_encode_tree_connect_request(&request)
        .unwrap()
        .remove(0);
    let mut pdu = Smb2TreeConnectPdu::new_tree_connect();
    tree::smb2_process_tree_connect_request_fixed(&mut pdu, &fixed).unwrap();

    tree::smb2_process_tree_connect_request_variable(&mut pdu, &[9, 8, 7]).unwrap();

    assert_eq!(pdu.request.as_ref().unwrap().path, vec![9, 8, 7]);
}
