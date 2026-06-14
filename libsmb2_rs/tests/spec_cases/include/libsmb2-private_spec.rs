use libsmb2_sys::include::libsmb2_private::{
    context_layout, directory_layout, discard_const_addr, header_layout, io_vectors_layout,
    is_server_for_owning_server, min_i32, pad_to_32bit, pad_to_64bit, pdu_layout,
    private_constants, sizeof_smb2_context, sizeof_smb2_pdu, sizeof_smb2dir, sync_cb_data_layout,
    tree_id_for_current_index, RecvState,
};

// Trace: `include/libsmb2-private.h:MIN`
// Spec: MIN choose smaller expression value#left expression is smaller
// - **GIVEN** 调用方包含 `include/libsmb2-private.h` 且传入两个可比较表达式
// - **WHEN** 调用 `MIN(a,b)` 且 `a < b` 为真
// - **THEN** 宏展开 MUST 选择 `a` 表达式结果
#[test]
fn test_libsmb2_private_left_expression_is_smaller() {
    assert_eq!(min_i32(-7, 3), -7);
    assert_eq!(min_i32(12, 99), 12);
}

// Trace: `include/libsmb2-private.h:discard_const`
// Spec: discard_const convert pointer through intptr_t#const pointer is discarded
// - **GIVEN** 调用方传入一个指针表达式 `ptr`
// - **WHEN** 调用 `discard_const(ptr)`
// - **THEN** 宏展开 MUST 产生类型为 `void *` 的结果
#[test]
fn test_libsmb2_private_const_pointer_is_discarded() {
    let value = 0x5a_u8;
    let ptr = &value as *const u8;

    assert_eq!(discard_const_addr(ptr), ptr as usize);
}

// Trace: `include/libsmb2-private.h:MAX_ERROR_SIZE`, `include/libsmb2-private.h:smb2_context`
// Spec: MAX_ERROR_SIZE fix error buffer capacity#context stores error string buffer
// - **GIVEN** `smb2_context` 定义包含 `char error_string[MAX_ERROR_SIZE]`
// - **WHEN** 编译包含该 header 的实现文件
// - **THEN** `error_string` 数组大小 MUST 由 `MAX_ERROR_SIZE` 的 256 字节定义决定
#[test]
fn test_libsmb2_private_context_stores_error_string_buffer() {
    let constants = private_constants();
    let layout = context_layout();

    assert_eq!(constants.max_error_size, 256);
    assert_eq!(layout.error_string_len, constants.max_error_size as usize);
}

// Trace: `include/libsmb2-private.h:PAD_TO_32BIT`
// Spec: PAD_TO_32BIT align length to four-byte boundary#unaligned length is padded to 32-bit boundary
// - **GIVEN** 调用方传入长度表达式 `len`
// - **WHEN** 调用 `PAD_TO_32BIT(len)`
// - **THEN** 结果 MUST 清除低两位并表示不小于原长度的 4 字节对齐长度
#[test]
fn test_libsmb2_private_unaligned_length_is_padded_to_32_bit_boundary() {
    for len in [0_u32, 1, 2, 3, 4, 5, 6, 7, 255, 256, 257] {
        let padded = pad_to_32bit(len);

        assert_eq!(padded & 0x03, 0);
        assert!(padded >= len);
        assert!(padded - len < 4);
    }
}

// Trace: `include/libsmb2-private.h:PAD_TO_64BIT`
// Spec: PAD_TO_64BIT align length to eight-byte boundary#unaligned length is padded to 64-bit boundary
// - **GIVEN** 调用方传入长度表达式 `len`
// - **WHEN** 调用 `PAD_TO_64BIT(len)`
// - **THEN** 结果 MUST 清除低三位并表示不小于原长度的 8 字节对齐长度
#[test]
fn test_libsmb2_private_unaligned_length_is_padded_to_64_bit_boundary() {
    for len in [0_u32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 256, 257] {
        let padded = pad_to_64bit(len);

        assert_eq!(padded & 0x07, 0);
        assert!(padded >= len);
        assert!(padded - len < 8);
    }
}

// Trace: `include/libsmb2-private.h:SMB2_SPL_SIZE`, `include/libsmb2-private.h:smb2_recv_state`
// Spec: SMB2_SPL_SIZE define SPL read size#receive state starts with SPL
// - **GIVEN** 接收状态机处于 `SMB2_RECV_SPL`
// - **WHEN** 实现代码需要 SPL 字段大小
// - **THEN** `SMB2_SPL_SIZE` MUST 提供值 `4`
#[test]
fn test_libsmb2_private_receive_state_starts_with_spl() {
    assert_eq!(private_constants().spl_size, 4);
    assert_eq!(RecvState::Spl.value(), Some(0));
}

// Trace: `include/libsmb2-private.h:SMB2_HEADER_SIZE`, `include/libsmb2-private.h:smb2_context`, `include/libsmb2-private.h:smb2_pdu`
// Spec: SMB2_HEADER_SIZE define fixed header size#context and PDU allocate inline header buffers
// - **GIVEN** `smb2_context.header` 和 `smb2_pdu.hdr` 声明为 `uint8_t[SMB2_HEADER_SIZE]`
// - **WHEN** 编译包含该 header 的实现文件
// - **THEN** 这些 header 缓冲区容量 MUST 为 64 字节
#[test]
fn test_libsmb2_private_context_and_pdu_allocate_inline_header_buffers() {
    let constants = private_constants();
    let context = context_layout();
    let pdu = pdu_layout();

    assert_eq!(constants.header_size, 64);
    assert_eq!(context.header_len, constants.header_size as usize);
    assert_eq!(pdu.hdr_len, constants.header_size as usize);
}

// Trace: `include/libsmb2-private.h:SMB2_SIGNATURE_SIZE`
// Spec: SMB2_SIGNATURE_SIZE define signature byte count#signature size is referenced by callers
// - **GIVEN** 调用方需要 SMB2 signature 字节数
// - **WHEN** 读取 `SMB2_SIGNATURE_SIZE`
// - **THEN** 宏值 MUST 为 `16`
#[test]
fn test_libsmb2_private_signature_size_is_referenced_by_callers() {
    assert_eq!(private_constants().signature_size, 16);
}

// Trace: `include/libsmb2-private.h:SMB2_KEY_SIZE`, `include/libsmb2-private.h:smb2_context`
// Spec: SMB2_KEY_SIZE define crypto key byte count#context stores signing and sealing keys
// - **GIVEN** `smb2_context` 包含 `signing_key`、`serverin_key` 和 `serverout_key`
// - **WHEN** 编译包含该 header 的实现文件
// - **THEN** 每个 key 数组大小 MUST 由 `SMB2_KEY_SIZE` 的 16 字节定义决定
#[test]
fn test_libsmb2_private_context_stores_signing_and_sealing_keys() {
    let constants = private_constants();
    let layout = context_layout();

    assert_eq!(constants.key_size, 16);
    assert_eq!(layout.signing_key_len, constants.key_size as usize);
    assert_eq!(layout.serverin_key_len, constants.key_size as usize);
    assert_eq!(layout.serverout_key_len, constants.key_size as usize);
}

// Trace: `include/libsmb2-private.h:SMB2_MAX_VECTORS`, `include/libsmb2-private.h:smb2_io_vectors`
// Spec: SMB2_MAX_VECTORS bound io vector array#io vector container is compiled
// - **GIVEN** `struct smb2_io_vectors` 被包含方使用
// - **WHEN** 编译 `iov[SMB2_MAX_VECTORS]` 字段
// - **THEN** `iov` 数组容量 MUST 为 256 个元素
#[test]
fn test_libsmb2_private_io_vector_container_is_compiled() {
    let constants = private_constants();
    let layout = io_vectors_layout();

    assert_eq!(constants.max_vectors, 256);
    assert_eq!(layout.iov_len, constants.max_vectors as usize);
}

// Trace: `include/libsmb2-private.h:smb2_io_vectors`, `include/libsmb2-private.h:smb2_pdu`
// Spec: smb2_io_vectors track vector progress and capacity#PDU contains send and receive vectors
// - **GIVEN** `smb2_pdu` 需要发送和接收缓冲区集合
// - **WHEN** 使用 `out` 或 `in` 字段
// - **THEN** 每个字段 MUST 提供 `num_done`、`total_size`、`niov` 和 `iov` 成员
#[test]
fn test_libsmb2_private_pdu_contains_send_and_receive_vectors() {
    let io_vectors = io_vectors_layout();
    let pdu = pdu_layout();

    assert!(io_vectors.has_num_done);
    assert!(io_vectors.has_total_size);
    assert!(io_vectors.has_niov);
    assert!(io_vectors.iov_len > 0);
    assert!(pdu.has_out_vectors);
    assert!(pdu.has_in_vectors);
}

// Trace: `include/libsmb2-private.h:smb2_async`, `include/libsmb2-private.h:smb2_header`
// Spec: smb2_async store asynchronous header id#header uses async union member
// - **GIVEN** `smb2_header` 的匿名 union 选择异步形式
// - **WHEN** 访问 `async` 成员
// - **THEN** 该成员 MUST 提供 `uint64_t async_id`
#[test]
fn test_libsmb2_private_header_uses_async_union_member() {
    assert!(header_layout().has_async_id);
}

// Trace: `include/libsmb2-private.h:smb2_sync`, `include/libsmb2-private.h:smb2_header`
// Spec: smb2_sync store process and tree identifiers#header uses sync union member
// - **GIVEN** `smb2_header` 的匿名 union 选择同步形式
// - **WHEN** 访问 `sync` 成员
// - **THEN** 该成员 MUST 提供 `uint32_t process_id` 和 `uint32_t tree_id`
#[test]
fn test_libsmb2_private_header_uses_sync_union_member() {
    let layout = header_layout();

    assert!(layout.has_process_id);
    assert!(layout.has_tree_id);
}

// Trace: `include/libsmb2-private.h:smb2_header`, `lib/pdu.c:smb2_tree_id`
// Spec: smb2_header preserve SMB2 wire header fields#header is decoded or encoded by PDU logic
// - **GIVEN** PDU 处理逻辑持有 `struct smb2_header`
// - **WHEN** 访问 header 字段
// - **THEN** 结构体 MUST 提供声明中的固定字段和匿名同步/异步 union
#[test]
fn test_libsmb2_private_header_is_decoded_or_encoded_by_pdu_logic() {
    let constants = private_constants();
    let layout = header_layout();

    assert_eq!(layout.protocol_id_len, 4);
    assert_eq!(layout.signature_len, constants.signature_size as usize);
    assert!(layout.has_async_id);
    assert!(layout.has_process_id);
    assert!(layout.has_tree_id);
}

// Trace: `include/libsmb2-private.h:smb2_recv_state`, `lib/socket.c:recv_state`
// Spec: smb2_recv_state enumerate receive state machine stages#socket receive loop dispatches state
// - **GIVEN** `lib/socket.c` 按 `smb2->recv_state` 分派接收流程
// - **WHEN** 状态机进入 SPL、header、fixed、variable、pad、transform 或 unknown 阶段
// - **THEN** `smb2_recv_state` MUST 提供对应枚举值 `SMB2_RECV_SPL`、`SMB2_RECV_HEADER`、`SMB2_RECV_FIXED`、`SMB2_RECV_VARIABLE`、`SMB2_RECV_PAD`、`SMB2_RECV_TRFM` 和 `SMB2_RECV_UNKNOWN`
#[test]
fn test_libsmb2_private_socket_receive_loop_dispatches_state() {
    assert_eq!(RecvState::Spl.value(), Some(0));
    assert_eq!(RecvState::Header.value(), Some(1));
    assert_eq!(RecvState::Fixed.value(), Some(2));
    assert_eq!(RecvState::Variable.value(), Some(3));
    assert_eq!(RecvState::Pad.value(), Some(4));
    assert_eq!(RecvState::Transform.value(), Some(5));
    assert_eq!(RecvState::Unknown.value(), Some(6));
}

// Trace: `include/libsmb2-private.h:MAX_CREDITS`
// Spec: MAX_CREDITS define credit ceiling#credit-related logic needs maximum value
// - **GIVEN** 实现代码需要内部 credit 上限
// - **WHEN** 读取 `MAX_CREDITS`
// - **THEN** 宏值 MUST 为 `1024`
#[test]
fn test_libsmb2_private_credit_related_logic_needs_maximum_value() {
    assert_eq!(private_constants().max_credits, 1024);
}

// Trace: `include/libsmb2-private.h:SMB2_MAX_TREE_NESTING`, `include/libsmb2-private.h:smb2_context`
// Spec: SMB2_MAX_TREE_NESTING bound tree id stack#context stores nested tree ids
// - **GIVEN** `smb2_context` 声明 `tree_id[SMB2_MAX_TREE_NESTING]`
// - **WHEN** 编译包含该 header 的实现文件
// - **THEN** tree id 栈容量 MUST 为 32 个槽位
#[test]
fn test_libsmb2_private_context_stores_nested_tree_ids() {
    let constants = private_constants();
    let layout = context_layout();

    assert_eq!(constants.max_tree_nesting, 32);
    assert_eq!(layout.tree_id_len, constants.max_tree_nesting as usize);
}

// Trace: `include/libsmb2-private.h:smb2_tree_id`, `lib/pdu.c:smb2_tree_id`, `lib/smb2-cmd-tree-connect.c:smb2_tree_id`, `lib/libsmb2.c:smb2_tree_id`
// Spec: smb2_tree_id return active tree id or sentinel#caller encodes a request header
// - **GIVEN** `smb2_context.tree_id_cur` 表示当前 tree id 栈位置
// - **WHEN** 调用 `smb2_tree_id(smb2)`
// - **THEN** 宏 MUST 返回当前 tree id 或无当前项时的 `0xdeadbeef` 哨兵值
#[test]
fn test_libsmb2_private_caller_encodes_a_request_header() {
    assert_eq!(tree_id_for_current_index(0, 0x1122_3344), 0x1122_3344);
    assert_eq!(tree_id_for_current_index(-1, 0x1122_3344), 0xdead_beef);
}

// Trace: `include/libsmb2-private.h:SMB2_SALT_SIZE`, `include/libsmb2-private.h:smb2_context`
// Spec: SMB2_SALT_SIZE define salt byte count#context stores SMB3 salt
// - **GIVEN** `smb2_context` 声明 `uint8_t salt[SMB2_SALT_SIZE]`
// - **WHEN** 编译包含该 header 的实现文件
// - **THEN** salt 数组大小 MUST 为 32 字节
#[test]
fn test_libsmb2_private_context_stores_smb3_salt() {
    let constants = private_constants();
    let layout = context_layout();

    assert_eq!(constants.salt_size, 32);
    assert_eq!(layout.salt_len, constants.salt_size as usize);
}

// Trace: `include/libsmb2-private.h:sync_cb_data`, `include/libsmb2-private.h:smb2_context`
// Spec: sync_cb_data store synchronous callback result#context embeds connect callback data
// - **GIVEN** `smb2_context` 声明 `struct sync_cb_data connect_cb_data`
// - **WHEN** 同步连接流程需要记录回调结果
// - **THEN** 数据结构 MUST 提供 `is_finished`、`status` 和 `ptr` 成员
#[test]
fn test_libsmb2_private_context_embeds_connect_callback_data() {
    let context = context_layout();
    let callback = sync_cb_data_layout();

    assert!(context.has_connect_cb_data);
    assert!(callback.has_is_finished);
    assert!(callback.has_status);
    assert!(callback.has_ptr);
}

// Trace: `include/libsmb2-private.h:smb2_context`, `lib/socket.c:recv_state`, `lib/pdu.c:outqueue`, `lib/init.c:outqueue`
// Spec: smb2_context aggregate connection protocol and callback state#socket and PDU code share a context
// - **GIVEN** socket、PDU、认证和命令处理代码接收 `struct smb2_context *smb2`
// - **WHEN** 这些实现访问连接、队列、状态机、加密或回调字段
// - **THEN** `smb2_context` MUST 提供对应声明字段作为共享内部状态容器
#[test]
fn test_libsmb2_private_socket_and_pdu_code_share_a_context() {
    let layout = context_layout();

    assert!(sizeof_smb2_context() > 0);
    assert!(layout.header_len > 0);
    assert!(layout.has_connecting_fds);
    assert!(layout.has_addrinfos);
    assert!(layout.has_security_mode);
    assert!(layout.has_tree_id_cur);
    assert!(layout.has_outqueue);
    assert!(layout.has_waitqueue);
    assert!(layout.has_io_vectors);
    assert!(layout.has_recv_state);
    assert!(layout.has_connect_cb_data);
    assert!(layout.has_error_string);
    assert!(layout.has_owning_server);
}

// Trace: `include/libsmb2-private.h:smb2_free_payload`, `include/libsmb2-private.h:smb2_pdu`
// Spec: smb2_free_payload define payload cleanup callback shape#PDU stores payload cleanup callback
// - **GIVEN** `smb2_pdu` 包含 `smb2_free_payload free_payload`
// - **WHEN** PDU 清理逻辑需要释放 payload 附加分配
// - **THEN** 回调类型 MUST 匹配 `void (*)(struct smb2_context *smb2, void *payload)`
#[test]
fn test_libsmb2_private_pdu_stores_payload_cleanup_callback() {
    let layout = pdu_layout();

    assert!(layout.has_payload);
    assert!(layout.has_free_payload);
}

// Trace: `include/libsmb2-private.h:SMB2_MAX_PDU_SIZE`
// Spec: SMB2_MAX_PDU_SIZE define maximum PDU expression#implementation checks or allocates PDU size
// - **GIVEN** 实现代码需要内部最大 PDU 大小
// - **WHEN** 读取 `SMB2_MAX_PDU_SIZE`
// - **THEN** 宏表达式 MUST 为 `16*1024*1024`
#[test]
fn test_libsmb2_private_implementation_checks_or_allocates_pdu_size() {
    assert_eq!(private_constants().max_pdu_size, 16 * 1024 * 1024);
}

// Trace: `include/libsmb2-private.h:smb2_pdu`, `lib/socket.c:outqueue`, `lib/pdu.c:waitqueue`
// Spec: smb2_pdu preserve request reply and buffer state#PDU queue and socket code process a PDU
// - **GIVEN** PDU 被加入 `outqueue` 或 `waitqueue`
// - **WHEN** socket/PDU 处理逻辑访问 header、payload、vectors、callback 或加密字段
// - **THEN** `smb2_pdu` MUST 提供声明中的对应成员
#[test]
fn test_libsmb2_private_pdu_queue_and_socket_code_process_a_pdu() {
    let constants = private_constants();
    let layout = pdu_layout();

    assert!(sizeof_smb2_pdu() > 0);
    assert_eq!(layout.hdr_len, constants.header_size as usize);
    assert!(layout.has_header);
    assert!(layout.has_payload);
    assert!(layout.has_free_payload);
    assert!(layout.has_out_vectors);
    assert!(layout.has_in_vectors);
}

// Trace: `include/libsmb2-private.h:smb2_dirent_internal`, `include/libsmb2-private.h:smb2dir`
// Spec: smb2_dirent_internal link directory entries#directory context stores decoded entries
// - **GIVEN** 目录读取逻辑需要保存多个目录项
// - **WHEN** 使用内部目录项节点
// - **THEN** 节点 MUST 提供 `next` 指针和 `struct smb2dirent dirent` 成员
#[test]
fn test_libsmb2_private_directory_context_stores_decoded_entries() {
    let layout = directory_layout();

    assert!(layout.has_internal_next);
    assert!(layout.has_internal_dirent);
}

// Trace: `include/libsmb2-private.h:smb2dir`
// Spec: smb2dir preserve directory traversal state#directory API iterates decoded entries
// - **GIVEN** 目录上下文包含已解码目录项
// - **WHEN** 调用方或实现推进目录遍历
// - **THEN** `smb2dir` MUST 提供 entries、current_entry 和 index 以保存遍历状态
#[test]
fn test_libsmb2_private_directory_api_iterates_decoded_entries() {
    let layout = directory_layout();

    assert!(sizeof_smb2dir() > 0);
    assert!(layout.has_entries);
    assert!(layout.has_current_entry);
    assert!(layout.has_index);
}

// Trace: `include/libsmb2-private.h:smb2_is_server`, `lib/socket.c:smb2_is_server`, `lib/pdu.c:smb2_is_server`, `lib/ntlmssp.c:smb2_is_server`, `lib/libsmb2.c:smb2_is_server`
// Spec: smb2_is_server classify context mode#socket and PDU paths branch on mode
// - **GIVEN** 一个 `struct smb2_context *ctx`
// - **WHEN** 调用 `smb2_is_server(ctx)`
// - **THEN** 宏 MUST 在 `owning_server` 非空时返回真值，在为空时返回假值
#[test]
fn test_libsmb2_private_socket_and_pdu_paths_branch_on_mode() {
    assert!(!is_server_for_owning_server(false));
    assert!(is_server_for_owning_server(true));
}
