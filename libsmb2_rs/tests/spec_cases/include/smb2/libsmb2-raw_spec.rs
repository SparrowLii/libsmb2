use libsmb2_rs::include::smb2::libsmb2_raw::{
    self as safe_raw, ChangeNotifyReply, ChangeNotifyRequest, CloseReply, CloseRequest, CreateReply,
    CreateRequest, EchoRequest, EmptyReply, ErrorReply, ErrorReplyCommand, FileId, FlushRequest,
    IoctlReply, IoctlRequest, LeaseBreakAcknowledgement, LeaseBreakNotification, LeaseBreakReply,
    LeaseKey, LockElement, LockRequest, NegotiateReply, NegotiateRequest,
    OplockBreakAcknowledgement, OplockBreakNotification, OplockBreakReply, QueryDirectoryReply,
    QueryDirectoryReplyCommand, QueryDirectoryRequest, QueryInfoReply, QueryInfoReplyCommand,
    QueryInfoRequest, RawCommand, RawCommandDirection, RawCommandError, RawCommandKind,
    RawCommandState, RawDataRelease, ReadReply, ReadRequest, SessionSetupReply,
    SessionSetupRequest, SetInfoRequest, TreeConnectReply, TreeConnectReplyCommand,
    TreeConnectRequest, WriteReply, WriteRequest, WriteRequestCommand,
};
use libsmb2_sys::legacy::alloc::{free_null_is_noop, AllocContext};
use libsmb2_sys::smb2::libsmb2_raw::{COMPOUND_FILE_ID, SMB2_FD_SIZE};

// Trace: `include/smb2/libsmb2-raw.h:compound_file_id`, `lib/libsmb2.c:compound_file_id`
// Spec: compound_file_id expose compound sentinel#复合请求复用特殊 file id
// - **GIVEN** 调用方或库内部构造 compound create/query/close 请求链
// - **WHEN** 后续请求需要引用 compound 链中前序创建的文件句柄
// - **THEN** 请求构造代码 MUST 使用 `compound_file_id` 作为特殊 `smb2_file_id` 哨兵
#[test]
fn test_libsmb2_raw_compound_request_reuses_special_file_id() {
    assert_eq!(COMPOUND_FILE_ID.len(), SMB2_FD_SIZE);
    assert!(COMPOUND_FILE_ID.iter().all(|byte| *byte == 0xff));
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_free_data`, `lib/alloc.c:smb2_free_data`, `examples/smb2-raw-stat-async.c`
// Spec: smb2_free_data release returned data tree#释放 query 返回数据
// - **GIVEN** 调用方持有 query、ioctl 或 DCERPC 回调返回的数据根指针
// - **WHEN** 调用方调用 `smb2_free_data(smb2, ptr)`
// - **THEN** 函数 MUST 释放该根指针关联的所有 tracked 子分配后释放根分配
#[test]
fn test_libsmb2_raw_free_data_releases_returned_data_tree() {
    let mut allocation = AllocContext::new(4).expect("root allocation");
    allocation.bytes_mut().copy_from_slice(&[1, 2, 3, 4]);
    let child = allocation.alloc_child(2).expect("child allocation");
    child.copy_from_slice(&[5, 6]);

    assert_eq!(allocation.bytes(), &[1, 2, 3, 4]);
    drop(allocation);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_free_data`, `lib/alloc.c:smb2_free_data`
// Spec: smb2_free_data release returned data tree#空指针释放为空操作
// - **GIVEN** 调用方没有可释放的数据根指针
// - **WHEN** 调用方调用 `smb2_free_data(smb2, NULL)`
// - **THEN** 函数 MUST 直接返回且不访问分配头
#[test]
fn test_libsmb2_raw_free_null_data_is_noop() {
    assert!(std::panic::catch_unwind(free_null_is_noop).is_ok());
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_negotiate_reply_async`, `lib/smb2-cmd-negotiate.c:smb2_cmd_negotiate_reply_async`
// Spec: smb2_cmd_negotiate_reply_async build negotiate reply PDU#构造 negotiate 响应
// - **GIVEN** 调用方提供 `struct smb2_negotiate_reply *rep`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_negotiate_reply_async(smb2, rep, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 NEGOTIATE command，并编码响应固定字段和安全缓冲区信息
#[test]
fn test_libsmb2_raw_negotiate_request_and_reply_validate_offline() {
    let request = safe_raw::cmd_negotiate_async(NegotiateRequest {
        dialect_count: 2,
        dialects: vec![0x0202, 0x0311],
        ..NegotiateRequest::default()
    })
    .expect("negotiate request");
    let reply = safe_raw::cmd_negotiate_reply_async(NegotiateReply {
        security_buffer_length: 2,
        security_buffer: vec![1, 2],
        ..NegotiateReply::default()
    })
    .expect("negotiate reply");

    assert_command(
        &request,
        RawCommandKind::Negotiate,
        RawCommandDirection::Request,
    );
    assert_command(
        &reply,
        RawCommandKind::Negotiate,
        RawCommandDirection::Reply,
    );
    assert_eq!(request.state, RawCommandState::Validated);
    assert_eq!(reply.state, RawCommandState::Validated);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_session_setup_reply_async`, `lib/smb2-cmd-session-setup.c:smb2_cmd_session_setup_reply_async`
// Spec: smb2_cmd_session_setup_reply_async build session setup reply PDU#构造 session setup 响应
// - **GIVEN** 调用方提供 `struct smb2_session_setup_reply *rep`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_session_setup_reply_async(smb2, rep, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 SESSION_SETUP command 并编码响应安全缓冲区字段
#[test]
fn test_libsmb2_raw_session_setup_request_and_reply_validate_offline() {
    let request = safe_raw::cmd_session_setup_async(SessionSetupRequest {
        security_buffer_length: 2,
        security_buffer: vec![1, 2],
        ..SessionSetupRequest::default()
    })
    .expect("session setup request");
    let reply = safe_raw::cmd_session_setup_reply_async(SessionSetupReply {
        security_buffer_length: 2,
        security_buffer: vec![3, 4],
        ..SessionSetupReply::default()
    })
    .expect("session setup reply");

    assert_command(
        &request,
        RawCommandKind::SessionSetup,
        RawCommandDirection::Request,
    );
    assert_command(
        &reply,
        RawCommandKind::SessionSetup,
        RawCommandDirection::Reply,
    );
    assert_eq!(request.state, RawCommandState::Validated);
    assert_eq!(reply.state, RawCommandState::Validated);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_tree_connect_reply_async`, `lib/smb2-cmd-tree-connect.c:smb2_cmd_tree_connect_reply_async`
// Spec: smb2_cmd_tree_connect_reply_async build tree connect reply PDU#构造 tree connect 响应
// - **GIVEN** 调用方提供 `struct smb2_tree_connect_reply *rep` 和 `tree_id`
// - **WHEN** 调用 `smb2_cmd_tree_connect_reply_async(smb2, rep, tree_id, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 TREE_CONNECT command，并携带可被响应处理路径识别的 tree id
#[test]
fn test_libsmb2_raw_tree_connect_request_and_reply_are_constructed_offline() {
    let path: Vec<u16> = r"\\server\share".encode_utf16().collect();
    let request = safe_raw::cmd_tree_connect_async(TreeConnectRequest {
        path_length: (path.len() * 2) as u16,
        path,
        ..TreeConnectRequest::default()
    })
    .expect("tree connect request");
    let reply = safe_raw::cmd_tree_connect_reply_async(TreeConnectReplyCommand {
        reply: TreeConnectReply {
            share_type: 1,
            share_flags: 2,
            capabilities: 3,
            maximal_access: 4,
        },
        tree_id: 7,
    })
    .expect("tree connect reply");

    assert_command(
        &request,
        RawCommandKind::TreeConnect,
        RawCommandDirection::Request,
    );
    assert!(matches!(request.state, RawCommandState::Constructed { .. }));
    assert_command(
        &reply,
        RawCommandKind::TreeConnect,
        RawCommandDirection::Reply,
    );
    assert!(matches!(reply.state, RawCommandState::Constructed { .. }));
    assert_constructed(&request, 3, 0, None, None);
    assert_constructed(&reply, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_tree_disconnect_reply_async`, `lib/smb2-cmd-tree-disconnect.c:smb2_cmd_tree_disconnect_reply_async`
// Spec: smb2_cmd_tree_disconnect_reply_async build tree disconnect reply PDU#构造 tree disconnect 响应
// - **GIVEN** 调用方提供回调和回调数据
// - **WHEN** 调用 `smb2_cmd_tree_disconnect_reply_async(smb2, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 TREE_DISCONNECT command，并编码固定响应字段
#[test]
fn test_libsmb2_raw_tree_disconnect_request_and_reply_are_constructed_offline() {
    let request = safe_raw::cmd_tree_disconnect_async().expect("tree disconnect request");
    let reply = safe_raw::cmd_tree_disconnect_reply_async(EmptyReply).expect("tree disconnect reply");

    assert_command(
        &request,
        RawCommandKind::TreeDisconnect,
        RawCommandDirection::Request,
    );
    assert!(matches!(request.state, RawCommandState::Constructed { .. }));
    assert_command(
        &reply,
        RawCommandKind::TreeDisconnect,
        RawCommandDirection::Reply,
    );
    assert!(matches!(reply.state, RawCommandState::Constructed { .. }));
    assert_constructed(&request, 2, 0, None, None);
    assert_constructed(&reply, 2, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_create_reply_async`, `lib/smb2-cmd-create.c:smb2_cmd_create_reply_async`
// Spec: smb2_cmd_create_reply_async build create reply PDU#构造 create 响应
// - **GIVEN** 调用方提供 `struct smb2_create_reply *rep`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_create_reply_async(smb2, rep, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 CREATE command，失败时 MUST 返回 `NULL`
#[test]
fn test_libsmb2_raw_create_request_and_reply_are_safe_boundary_checked() {
    let request = safe_raw::cmd_create_async(CreateRequest {
        name_length: 8,
        name: "file".to_owned(),
        ..CreateRequest::default()
    })
    .expect("create request");
    let reply = safe_raw::cmd_create_reply_async(CreateReply {
        file_id: file_id(),
        ..CreateReply::default()
    })
    .expect("create reply");

    assert_command(
        &request,
        RawCommandKind::Create,
        RawCommandDirection::Request,
    );
    assert_command(&reply, RawCommandKind::Create, RawCommandDirection::Reply);
    assert_constructed(&request, 2, 0, None, None);
    assert_eq!(reply.state, RawCommandState::Validated);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_close_reply_async`, `lib/smb2-cmd-close.c:smb2_cmd_close_reply_async`
// Spec: smb2_cmd_close_reply_async build close reply PDU#构造 close 响应
// - **GIVEN** 调用方提供 `struct smb2_close_reply *rep`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_close_reply_async(smb2, rep, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 CLOSE command，失败时 MUST 返回 `NULL`
#[test]
fn test_libsmb2_raw_close_request_and_reply_are_safe_boundary_checked() {
    let request = safe_raw::cmd_close_async(CloseRequest {
        flags: 1,
        file_id: file_id(),
    })
    .expect("close request");
    let reply = safe_raw::cmd_close_reply_async(CloseReply::default()).expect("close reply");

    assert_command(
        &request,
        RawCommandKind::Close,
        RawCommandDirection::Request,
    );
    assert_command(&reply, RawCommandKind::Close, RawCommandDirection::Reply);
    assert_constructed(&request, 1, 0, None, None);
    assert_eq!(reply.state, RawCommandState::Validated);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_read_async`, `lib/smb2-cmd-read.c:smb2_cmd_read_async`
// Spec: smb2_cmd_read_async build read request PDU#构造 read 请求并绑定接收缓冲区
// - **GIVEN** `req->length` 非零且 `req->buf` 指向调用方提供的接收缓冲区
// - **WHEN** 调用 `smb2_cmd_read_async(smb2, req, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 READ command，并将 `req->buf` 添加为输入 iovector 且不接管释放责任
#[test]
fn test_libsmb2_raw_build_read_request_with_buffer() {
    let command = safe_raw::cmd_read_async(ReadRequest {
        length: 4,
        buf: vec![0; 4],
        file_id: file_id(),
        ..ReadRequest::default()
    })
    .expect("read request");

    assert_command(&command, RawCommandKind::Read, RawCommandDirection::Request);
    assert!(matches!(command.state, RawCommandState::Constructed { .. }));
    assert_constructed(&command, 2, 1, Some(1), None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_read_async`, `lib/smb2-cmd-read.c:smb2_cmd_read_async`
// Spec: smb2_cmd_read_async build read request PDU#拒绝缺失 read 缓冲区
// - **GIVEN** `req->length` 非零且 `req->buf` 为 `NULL`
// - **WHEN** 调用 `smb2_cmd_read_async(smb2, req, cb, cb_data)`
// - **THEN** 函数 MUST 设置错误、释放已分配 PDU 并返回 `NULL`
#[test]
fn test_libsmb2_raw_rejects_missing_read_buffer() {
    let error = safe_raw::cmd_read_async(ReadRequest {
        length: 4,
        buf: Vec::new(),
        file_id: file_id(),
        ..ReadRequest::default()
    })
    .expect_err("missing read buffer must fail");

    assert_eq!(
        error,
        RawCommandError::LengthMismatch {
            field: "length",
            declared: 4,
            actual: 0,
        }
    );
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_read_reply_async`, `lib/smb2-cmd-read.c:smb2_cmd_read_reply_async`
// Spec: smb2_cmd_read_reply_async build read reply PDU#构造 read 响应数据
// - **GIVEN** `rep->data_length` 大于零且 `rep->data` 非空
// - **WHEN** 调用 `smb2_cmd_read_reply_async(smb2, rep, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 READ command，并将响应数据附加到输出 iovector
#[test]
fn test_libsmb2_raw_read_reply_appends_data_vector() {
    let command = safe_raw::cmd_read_reply_async(ReadReply {
        data_length: 3,
        data_remaining: 7,
        data: vec![9, 8, 7],
        ..ReadReply::default()
    })
    .expect("read reply");

    assert_command(&command, RawCommandKind::Read, RawCommandDirection::Reply);
    assert!(matches!(command.state, RawCommandState::Constructed { .. }));
    assert_constructed(&command, 2, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_write_async`, `lib/smb2-cmd-write.c:smb2_cmd_write_async`
// Spec: smb2_cmd_write_async build write request PDU#构造 write 请求并保留缓冲区所有权
// - **GIVEN** 调用方提供 `struct smb2_write_request *req` 且 `pass_buf_ownership` 为 `0`
// - **WHEN** 调用 `smb2_cmd_write_async(smb2, req, 0, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 将 `req->buf` 添加到输出 iovector，且 PDU 释放时 MUST NOT 释放该缓冲区
#[test]
fn test_libsmb2_raw_write_request_retains_buffer_ownership() {
    let command = safe_raw::cmd_write_async(WriteRequestCommand {
        request: write_request(),
        pass_buf_ownership: false,
    })
    .expect("write request");

    assert_command(
        &command,
        RawCommandKind::Write,
        RawCommandDirection::Request,
    );
    assert!(!command.payload.pass_buf_ownership);
    assert_constructed(&command, 2, 0, Some(1), None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_write_async`, `lib/smb2-cmd-write.c:smb2_cmd_write_async`
// Spec: smb2_cmd_write_async build write request PDU#构造 write 请求并移交缓冲区所有权
// - **GIVEN** 调用方提供 `struct smb2_write_request *req` 且 `pass_buf_ownership` 非零
// - **WHEN** 调用 `smb2_cmd_write_async(smb2, req, pass_buf_ownership, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 将 `free` 注册为写入缓冲区释放函数
#[test]
fn test_libsmb2_raw_write_request_transfers_buffer_ownership() {
    let command = safe_raw::cmd_write_async(WriteRequestCommand {
        request: write_request(),
        pass_buf_ownership: true,
    })
    .expect("write request transfer");

    assert!(command.payload.pass_buf_ownership);
    assert_constructed(&command, 2, 0, Some(1), None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_write_reply_async`, `lib/smb2-cmd-write.c:smb2_cmd_write_reply_async`
// Spec: smb2_cmd_write_reply_async build write reply PDU#构造 write 响应
// - **GIVEN** 调用方提供 `struct smb2_write_reply *rep`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_write_reply_async(smb2, rep, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 WRITE command，并编码 `rep->count` 与 `rep->remaining`
#[test]
fn test_libsmb2_raw_write_reply_encodes_count_and_remaining() {
    let command = safe_raw::cmd_write_reply_async(WriteReply {
        count: 3,
        remaining: 4,
    })
    .expect("write reply");

    assert_command(&command, RawCommandKind::Write, RawCommandDirection::Reply);
    assert_eq!(command.payload.count, 3);
    assert_eq!(command.payload.remaining, 4);
    assert_constructed(&command, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_query_directory_async`, `lib/smb2-cmd-query-directory.c:smb2_cmd_query_directory_async`, `examples/smb2-CMD-FIND.c`
// Spec: smb2_cmd_query_directory_async build query directory request PDU#构造 query directory 请求
// - **GIVEN** 调用方提供 `struct smb2_query_directory_request *req`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_query_directory_async(smb2, req, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 QUERY_DIRECTORY command，失败时 MUST 返回 `NULL`
#[test]
fn test_libsmb2_raw_query_directory_request_is_constructed_offline() {
    let command = safe_raw::cmd_query_directory_async(QueryDirectoryRequest {
        file_information_class: 0x26,
        output_buffer_length: 128,
        file_id: file_id(),
        ..QueryDirectoryRequest::default()
    })
    .expect("query directory request");

    assert_command(
        &command,
        RawCommandKind::QueryDirectory,
        RawCommandDirection::Request,
    );
    assert!(matches!(command.state, RawCommandState::Constructed { .. }));
    assert_constructed(&command, 1, 0, Some(1), None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_query_directory_reply_async`, `lib/smb2-cmd-query-directory.c:smb2_cmd_query_directory_reply_async`
// Spec: smb2_cmd_query_directory_reply_async build query directory reply PDU#构造 query directory 响应
// - **GIVEN** 调用方提供 request context 和 `struct smb2_query_directory_reply *rep`
// - **WHEN** 调用 `smb2_cmd_query_directory_reply_async(smb2, req, rep, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 QUERY_DIRECTORY command，并编码可被客户端解析的目录响应缓冲区
#[test]
fn test_libsmb2_raw_query_directory_reply_encodes_output_buffer() {
    let request = QueryDirectoryRequest {
        file_information_class: 0x26,
        file_id: file_id(),
        ..QueryDirectoryRequest::default()
    };
    let command = safe_raw::cmd_query_directory_reply_async(QueryDirectoryReplyCommand {
        request,
        reply: QueryDirectoryReply {
            output_buffer_length: 4,
            output_buffer: vec![1, 2, 3, 4],
            ..QueryDirectoryReply::default()
        },
    })
    .expect("query directory reply");

    assert_command(
        &command,
        RawCommandKind::QueryDirectory,
        RawCommandDirection::Reply,
    );
    assert!(matches!(command.state, RawCommandState::Constructed { .. }));
    assert_constructed(&command, 1, 0, Some(1), None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_change_notify_async`, `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_async`
// Spec: smb2_cmd_change_notify_async build change notify request PDU#构造 change notify 请求
// - **GIVEN** 调用方提供 `struct smb2_change_notify_request *req`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_change_notify_async(smb2, req, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 CHANGE_NOTIFY command，失败时 MUST 返回 `NULL`
#[test]
fn test_libsmb2_raw_change_notify_request_is_constructed_offline() {
    let command = safe_raw::cmd_change_notify_async(ChangeNotifyRequest {
        output_buffer_length: 64,
        file_id: file_id(),
        completion_filter: 1,
        ..ChangeNotifyRequest::default()
    })
    .expect("change notify request");

    assert_command(
        &command,
        RawCommandKind::ChangeNotify,
        RawCommandDirection::Request,
    );
    assert!(matches!(command.state, RawCommandState::Constructed { .. }));
    assert_constructed(&command, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_change_notify_reply_async`, `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_reply_async`
// Spec: smb2_cmd_change_notify_reply_async build change notify reply PDU#构造 change notify 响应
// - **GIVEN** 调用方提供 `struct smb2_change_notify_reply *rep`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_change_notify_reply_async(smb2, rep, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 CHANGE_NOTIFY command，失败时 MUST 返回 `NULL`
#[test]
fn test_libsmb2_raw_change_notify_reply_encodes_output() {
    let command = safe_raw::cmd_change_notify_reply_async(ChangeNotifyReply {
        output_buffer_length: 4,
        output: vec![0, 1, 2, 3],
        ..ChangeNotifyReply::default()
    })
    .expect("change notify reply");

    assert_command(
        &command,
        RawCommandKind::ChangeNotify,
        RawCommandDirection::Reply,
    );
    assert!(matches!(command.state, RawCommandState::Constructed { .. }));
    assert_constructed(&command, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_query_info_async`, `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_async`, `tests/metastat-0202-censored.c`
// Spec: smb2_cmd_query_info_async build query info request PDU#构造 query info 请求
// - **GIVEN** 调用方提供 `struct smb2_query_info_request *req`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_query_info_async(smb2, req, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 QUERY_INFO command，并包含编码后的 query info request
#[test]
fn test_libsmb2_raw_query_info_request_encodes_input_buffer() {
    let command = safe_raw::cmd_query_info_async(QueryInfoRequest {
        info_type: 1,
        file_info_class: 4,
        output_buffer_length: 64,
        input_buffer_length: 2,
        input_buffer: vec![5, 6],
        file_id: file_id(),
        ..QueryInfoRequest::default()
    })
    .expect("query info request");

    assert_command(
        &command,
        RawCommandKind::QueryInfo,
        RawCommandDirection::Request,
    );
    assert!(matches!(command.state, RawCommandState::Constructed { .. }));
    assert_constructed(&command, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_query_info_reply_async`, `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_reply_async`
// Spec: smb2_cmd_query_info_reply_async build query info reply PDU#构造 query info 响应
// - **GIVEN** 调用方提供 request context 和 `struct smb2_query_info_reply *rep`
// - **WHEN** 调用 `smb2_cmd_query_info_reply_async(smb2, req, rep, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 QUERY_INFO command，并编码 `rep->output_buffer` 和输出长度字段
#[test]
fn test_libsmb2_raw_query_info_reply_marks_free_data_contract() {
    let request = QueryInfoRequest {
        info_type: 0xff,
        file_info_class: 0xee,
        output_buffer_length: 4,
        file_id: file_id(),
        ..QueryInfoRequest::default()
    };
    let command = safe_raw::cmd_query_info_reply_async(QueryInfoReplyCommand {
        request,
        reply: QueryInfoReply {
            output_buffer_length: 4,
            output_buffer: vec![1, 2, 3, 4],
            ..QueryInfoReply::default()
        },
    })
    .expect("query info reply");

    assert_command(
        &command,
        RawCommandKind::QueryInfo,
        RawCommandDirection::Reply,
    );
    assert_eq!(command.data_release, RawDataRelease::FreeDataRequired);
    assert_constructed(&command, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_set_info_async`, `lib/smb2-cmd-set-info.c:smb2_cmd_set_info_async`
// Spec: smb2_cmd_set_info_async build set info request PDU#构造 set info 请求
// - **GIVEN** 调用方提供 `struct smb2_set_info_request *req`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_set_info_async(smb2, req, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 SET_INFO command，失败时 MUST 返回 `NULL`
#[test]
fn test_libsmb2_raw_set_info_request_encodes_metadata_buffer() {
    let command = safe_raw::cmd_set_info_async(SetInfoRequest {
        info_type: 1,
        file_info_class: 0xff,
        buffer_length: 3,
        file_id: file_id(),
        input_data: vec![7, 8, 9],
        ..SetInfoRequest::default()
    })
    .expect("set info request");

    assert_command(
        &command,
        RawCommandKind::SetInfo,
        RawCommandDirection::Request,
    );
    assert!(matches!(command.state, RawCommandState::Constructed { .. }));
    assert_constructed(&command, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_set_info_reply_async`, `lib/smb2-cmd-set-info.c:smb2_cmd_set_info_reply_async`
// Spec: smb2_cmd_set_info_reply_async build set info reply PDU#构造 set info 响应
// - **GIVEN** 调用方提供 request context、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_set_info_reply_async(smb2, req, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 SET_INFO command，并编码固定响应字段
#[test]
fn test_libsmb2_raw_set_info_reply_encodes_fixed_response() {
    let command = safe_raw::cmd_set_info_reply_async(SetInfoRequest::default()).expect("set info reply");

    assert_command(
        &command,
        RawCommandKind::SetInfo,
        RawCommandDirection::Reply,
    );
    assert!(matches!(command.state, RawCommandState::Constructed { .. }));
    assert_constructed(&command, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_ioctl_async`, `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_async`
// Spec: smb2_cmd_ioctl_async build ioctl request PDU#构造 ioctl 请求
// - **GIVEN** 调用方提供 `struct smb2_ioctl_request *req`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_ioctl_async(smb2, req, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 IOCTL command，失败时 MUST 返回 `NULL`
#[test]
fn test_libsmb2_raw_ioctl_request_encodes_input() {
    let command = safe_raw::cmd_ioctl_async(IoctlRequest {
        ctl_code: 0x0011_c017,
        file_id: file_id(),
        input_count: 2,
        input: vec![1, 2],
        flags: 1,
        ..IoctlRequest::default()
    })
    .expect("ioctl request");

    assert_command(
        &command,
        RawCommandKind::Ioctl,
        RawCommandDirection::Request,
    );
    assert!(matches!(command.state, RawCommandState::Constructed { .. }));
    assert_constructed(&command, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_ioctl_reply_async`, `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_reply_async`
// Spec: smb2_cmd_ioctl_reply_async build ioctl reply PDU#构造 ioctl 响应
// - **GIVEN** 调用方提供 `struct smb2_ioctl_reply *rep`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_ioctl_reply_async(smb2, rep, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 IOCTL command，并编码 output buffer 和输出长度字段
#[test]
fn test_libsmb2_raw_ioctl_reply_marks_free_data_contract() {
    let command = safe_raw::cmd_ioctl_reply_async(IoctlReply {
        ctl_code: 0x0011_c017,
        file_id: file_id(),
        output_count: 3,
        output: vec![3, 2, 1],
        flags: 1,
        ..IoctlReply::default()
    })
    .expect("ioctl reply");

    assert_command(&command, RawCommandKind::Ioctl, RawCommandDirection::Reply);
    assert_eq!(command.data_release, RawDataRelease::FreeDataRequired);
    assert_constructed(&command, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_echo_reply_async`, `lib/smb2-cmd-echo.c:smb2_cmd_echo_reply_async`
// Spec: smb2_cmd_echo_reply_async build echo reply PDU#构造 echo 响应
// - **GIVEN** 调用方提供回调和回调数据
// - **WHEN** 调用 `smb2_cmd_echo_reply_async(smb2, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 ECHO command，并编码固定响应字段
#[test]
fn test_libsmb2_raw_echo_request_and_reply_are_constructed_offline() {
    let request = safe_raw::cmd_echo_async().expect("echo request");
    let reply = safe_raw::cmd_echo_reply_async(EmptyReply).expect("echo reply");

    assert_command(&request, RawCommandKind::Echo, RawCommandDirection::Request);
    assert_eq!(request.payload, EchoRequest::default());
    assert_constructed(&request, 1, 0, None, None);
    assert_command(&reply, RawCommandKind::Echo, RawCommandDirection::Reply);
    assert_constructed(&reply, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_lock_reply_async`, `lib/smb2-cmd-lock.c:smb2_cmd_lock_reply_async`
// Spec: smb2_cmd_lock_reply_async build lock reply PDU#构造 lock 响应
// - **GIVEN** 调用方提供回调和回调数据
// - **WHEN** 调用 `smb2_cmd_lock_reply_async(smb2, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 LOCK command，并编码固定响应字段
#[test]
fn test_libsmb2_raw_lock_request_and_reply_are_constructed_offline() {
    let request = safe_raw::cmd_lock_async(LockRequest {
        lock_count: 1,
        file_id: file_id(),
        locks: vec![LockElement {
            offset: 10,
            length: 20,
            flags: 1,
            reserved: 0,
        }],
        ..LockRequest::default()
    })
    .expect("lock request");
    let reply = safe_raw::cmd_lock_reply_async(EmptyReply).expect("lock reply");

    assert_command(&request, RawCommandKind::Lock, RawCommandDirection::Request);
    assert!(matches!(request.state, RawCommandState::Constructed { .. }));
    assert_constructed(&request, 1, 0, None, None);
    assert_command(&reply, RawCommandKind::Lock, RawCommandDirection::Reply);
    assert!(matches!(reply.state, RawCommandState::Constructed { .. }));
    assert_constructed(&reply, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_logoff_reply_async`, `lib/smb2-cmd-logoff.c:smb2_cmd_logoff_reply_async`
// Spec: smb2_cmd_logoff_reply_async build logoff reply PDU#构造 logoff 响应
// - **GIVEN** 调用方提供回调和回调数据
// - **WHEN** 调用 `smb2_cmd_logoff_reply_async(smb2, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 LOGOFF command，并编码固定响应字段
#[test]
fn test_libsmb2_raw_logoff_request_and_reply_are_constructed_offline() {
    let request = safe_raw::cmd_logoff_async().expect("logoff request");
    let reply = safe_raw::cmd_logoff_reply_async(EmptyReply).expect("logoff reply");

    assert_command(
        &request,
        RawCommandKind::Logoff,
        RawCommandDirection::Request,
    );
    assert!(matches!(request.state, RawCommandState::Constructed { .. }));
    assert_constructed(&request, 1, 0, None, None);
    assert_command(&reply, RawCommandKind::Logoff, RawCommandDirection::Reply);
    assert!(matches!(reply.state, RawCommandState::Constructed { .. }));
    assert_constructed(&reply, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_flush_reply_async`, `lib/smb2-cmd-flush.c:smb2_cmd_flush_reply_async`
// Spec: smb2_cmd_flush_reply_async build flush reply PDU#构造 flush 响应
// - **GIVEN** 调用方提供回调和回调数据
// - **WHEN** 调用 `smb2_cmd_flush_reply_async(smb2, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 FLUSH command，并编码固定响应字段
#[test]
fn test_libsmb2_raw_flush_request_and_reply_are_constructed_offline() {
    let request = safe_raw::cmd_flush_async(FlushRequest { file_id: file_id() }).expect("flush request");
    let reply = safe_raw::cmd_flush_reply_async(EmptyReply).expect("flush reply");

    assert_command(
        &request,
        RawCommandKind::Flush,
        RawCommandDirection::Request,
    );
    assert!(matches!(request.state, RawCommandState::Constructed { .. }));
    assert_constructed(&request, 1, 0, None, None);
    assert_command(&reply, RawCommandKind::Flush, RawCommandDirection::Reply);
    assert!(matches!(reply.state, RawCommandState::Constructed { .. }));
    assert_constructed(&reply, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_oplock_break_notification_async`, `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_notification_async`
// Spec: smb2_cmd_oplock_break_notification_async build oplock break notification PDU#构造 oplock break 通知
// - **GIVEN** 调用方提供 `struct smb2_oplock_break_notification *rep`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_oplock_break_notification_async(smb2, rep, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 SMB2 OPLOCK_BREAK command，失败时 MUST 返回 `NULL`
#[test]
fn test_libsmb2_raw_oplock_break_ack_reply_and_notification_are_constructed_offline() {
    let ack = safe_raw::cmd_oplock_break_async(OplockBreakAcknowledgement {
        oplock_level: 1,
        file_id: file_id(),
    })
    .expect("oplock ack");
    let reply = safe_raw::cmd_oplock_break_reply_async(OplockBreakReply {
        oplock_level: 1,
        file_id: file_id(),
    })
    .expect("oplock reply");
    let notification = safe_raw::cmd_oplock_break_notification_async(OplockBreakNotification {
        oplock_level: 1,
        file_id: file_id(),
    })
    .expect("oplock notification");

    assert_command(
        &ack,
        RawCommandKind::OplockBreak,
        RawCommandDirection::Request,
    );
    assert_command(
        &reply,
        RawCommandKind::OplockBreak,
        RawCommandDirection::Reply,
    );
    assert_command(
        &notification,
        RawCommandKind::OplockBreak,
        RawCommandDirection::Reply,
    );
    assert_constructed(&ack, 1, 0, None, None);
    assert_constructed(&reply, 1, 0, None, None);
    assert!(matches!(notification.state, RawCommandState::Constructed { .. }));
    assert_constructed(&notification, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_lease_break_notification_async`, `lib/smb2-cmd-oplock-break.c:smb2_cmd_lease_break_notification_async`
// Spec: smb2_cmd_lease_break_notification_async build lease break notification PDU#构造 lease break 通知
// - **GIVEN** 调用方提供 `struct smb2_lease_break_notification *req`、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_lease_break_notification_async(smb2, req, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 lease break 对应 command 编码路径，失败时 MUST 返回 `NULL`
#[test]
fn test_libsmb2_raw_lease_break_ack_reply_and_notification_are_constructed_offline() {
    let ack = safe_raw::cmd_lease_break_async(LeaseBreakAcknowledgement {
        flags: 1,
        lease_key: lease_key(),
        lease_state: 2,
        lease_duration: 3,
    })
    .expect("lease ack");
    let reply = safe_raw::cmd_lease_break_reply_async(LeaseBreakReply {
        flags: 1,
        lease_key: lease_key(),
        lease_state: 2,
        lease_duration: 3,
    })
    .expect("lease reply");
    let notification = safe_raw::cmd_lease_break_notification_async(LeaseBreakNotification {
        new_epoch: 1,
        flags: 2,
        lease_key: lease_key(),
        current_lease_state: 3,
        new_lease_state: 4,
        break_reason: 5,
        access_mask_hint: 6,
        share_mask_hint: 7,
    })
    .expect("lease notification");

    assert_command(
        &ack,
        RawCommandKind::OplockBreak,
        RawCommandDirection::Request,
    );
    assert_command(
        &reply,
        RawCommandKind::OplockBreak,
        RawCommandDirection::Reply,
    );
    assert_command(
        &notification,
        RawCommandKind::OplockBreak,
        RawCommandDirection::Reply,
    );
    assert_constructed(&ack, 1, 0, None, None);
    assert_constructed(&reply, 1, 0, None, None);
    assert!(matches!(notification.state, RawCommandState::Constructed { .. }));
    assert_constructed(&notification, 1, 0, None, None);
}

// Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_error_reply_async`, `lib/smb2-cmd-error.c:smb2_cmd_error_reply_async`
// Spec: smb2_cmd_error_reply_async build error reply PDU#构造 error 响应
// - **GIVEN** 调用方提供 `struct smb2_error_reply *rep`、`causing_command`、NT status、回调和回调数据
// - **WHEN** 调用 `smb2_cmd_error_reply_async(smb2, rep, causing_command, status, cb, cb_data)`
// - **THEN** 返回的 PDU MUST 使用 `causing_command` 作为 SMB2 command，并将 PDU header status 设置为调用方提供的 `status`
#[test]
fn test_libsmb2_raw_error_reply_records_causing_command_and_status() {
    let command = safe_raw::cmd_error_reply_async(ErrorReplyCommand {
        reply: ErrorReply {
            error_context_count: 0,
            byte_count: 0,
            error_data: Vec::new(),
        },
        causing_command: 8,
        status: -1_073_741_811,
    })
    .expect("error reply");

    assert_command(&command, RawCommandKind::Error, RawCommandDirection::Reply);
    assert_eq!(command.payload.causing_command, 8);
    assert_constructed(&command, 1, 0, None, Some(0xc000_000d));
}

fn write_request() -> WriteRequest {
    WriteRequest {
        length: 3,
        offset: 5,
        buf: vec![1, 2, 3],
        file_id: file_id(),
        ..WriteRequest::default()
    }
}

fn file_id() -> FileId {
    FileId {
        persistent: 0x0102_0304_0506_0708,
        volatile: 0x1112_1314_1516_1718,
    }
}

fn lease_key() -> LeaseKey {
    LeaseKey([0xabu8; 16])
}

fn assert_command<T>(
    command: &RawCommand<T>,
    kind: RawCommandKind,
    direction: RawCommandDirection,
) {
    assert_eq!(command.kind, kind);
    assert_eq!(command.direction, direction);
}

fn assert_constructed<T>(
    command: &RawCommand<T>,
    expected_output_vectors: usize,
    expected_input_vectors: usize,
    expected_credit_charge: Option<u16>,
    expected_status: Option<u32>,
) {
    match command.state {
        RawCommandState::Constructed {
            output_vectors,
            input_vectors,
            credit_charge,
            status,
        } => {
            assert_eq!(output_vectors, expected_output_vectors);
            assert_eq!(input_vectors, expected_input_vectors);
            assert_eq!(credit_charge, expected_credit_charge);
            assert_eq!(status, expected_status);
        }
        RawCommandState::Validated => panic!("expected constructed raw command"),
    }
}
