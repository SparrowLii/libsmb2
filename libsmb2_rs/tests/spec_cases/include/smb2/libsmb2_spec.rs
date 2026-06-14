use libsmb2_sys::legacy::unicode;

use libsmb2_rs::include::smb2::libsmb2::{
    self as public_api, AuthenticationMethod, ErrorCode, FileType, NegotiateVersion, PduHandle,
    Smb2Client, Smb2ClientState, Smb2OperationResult, SMB2_POLLERR, SMB2_POLLIN, SMB2_POLLOUT,
};
use libsmb2_rs::lib::sync::{self, PathOperation, SyncPayload, SyncRequestKind};
use libsmb2_sys::smb2::smb2_errors::SMB2_STATUS_INVALID_PARAMETER;

// Trace: `include/smb2/libsmb2.h:smb2_context_lifecycle_api`, `lib/init.c:smb2_destroy_context`, `tests/prog_cat_cancel.c`
// Spec: smb2_context_lifecycle_api manage context lifetime#销毁 context 取消未完成命令
// - **GIVEN** context 仍持有打开的 `struct smb2fh`、`struct smb2dir` 或 pending async command
// - **WHEN** 调用方调用 `smb2_destroy_context(smb2)`
// - **THEN** 系统 MUST 释放关联资源，并以 shutdown/cancel 状态完成可回调的待处理命令
#[test]
fn test_libsmb2_context_create_default() {
    let mut client = Smb2Client::new();

    assert!(client.is_active());
    assert_eq!(client.state(), Smb2ClientState::Active);
    assert_eq!(client.last_request_message_id(), 0);

    client.destroy_context();
    assert_eq!(client.state(), Smb2ClientState::Destroyed);
    assert!(!client.is_active());
}

// Trace: `include/smb2/libsmb2.h:smb2_event_integration_api`, `lib/libsmb2.c:smb2_serve_port`, `examples/smb2-ls-epoll.c`
// Spec: smb2_event_integration_api integrate external event loops#轮询并处理 context 事件
// - **GIVEN** 调用方持有已初始化或正在连接的 context
// - **WHEN** 调用方读取 `smb2_get_fd()`、`smb2_which_events()` 并在事件就绪后调用 `smb2_service()` 或 `smb2_service_fd()`
// - **THEN** service 成功时 MUST 返回 `0`，不可恢复失败时 MUST 返回负值且调用方需要销毁 context
#[test]
fn test_libsmb2_poll_and_service_context_events() {
    let mut client = Smb2Client::new();

    client.connect_share("server", "share").unwrap();
    assert_eq!(client.fd(), -1);
    assert_eq!(client.which_events(), SMB2_POLLOUT);

    client.service(SMB2_POLLOUT).unwrap();
    assert_eq!(client.fd(), 0);
    assert_eq!(client.which_events(), SMB2_POLLIN);

    client.service_fd(client.fd(), SMB2_POLLIN).unwrap();
    assert!(matches!(
        client
            .last_completed_result()
            .map(|completion| &completion.result),
        Some(Ok(Smb2OperationResult::ConnectShare { .. }))
    ));

    assert_eq!(client.service(SMB2_POLLERR).unwrap_err().code(), -22);
    client.destroy_context();
    assert_eq!(client.state(), Smb2ClientState::Destroyed);
}

// Trace: `include/smb2/libsmb2.h:smb2_configuration_api`, `lib/init.c:smb2_set_error`, `lib/libsmb2.c:smb2_connect_share_async`
// Spec: smb2_configuration_api configure context behavior#设置并读取 context 属性
// - **GIVEN** 调用方持有一个有效 context
// - **WHEN** 调用方调用 setter 配置用户、domain、workstation、opaque、passthrough、version 或 security 选项
// - **THEN** 对应 getter 或后续连接流程 MUST 使用该 context 中保存的最新配置值
#[test]
fn test_libsmb2_configuration_set_read() {
    let mut client = Smb2Client::new();
    let opaque = 0x1234usize;
    let guid = [0x42; 16];

    client.set_passthrough(true);
    client.set_version(NegotiateVersion::V0311);
    client.set_security_mode(1);
    client.set_seal(true);
    client.set_sign(true);
    client.set_authentication(AuthenticationMethod::NtlmSsp);
    client.set_user("alice");
    client.set_domain("DOMAIN");
    client.set_workstation("WORKSTATION");
    client.set_opaque(Some(opaque));
    client.set_client_guid(guid);

    assert!(client.passthrough());
    assert_eq!(client.version(), NegotiateVersion::V0311);
    assert_eq!(client.security_mode(), 1);
    assert!(client.seal());
    assert!(client.sign());
    assert_eq!(client.authentication(), AuthenticationMethod::NtlmSsp);
    assert_eq!(client.user(), Some("alice"));
    assert_eq!(client.domain(), Some("DOMAIN"));
    assert_eq!(client.workstation(), Some("WORKSTATION"));
    assert_eq!(client.opaque(), Some(opaque));
    assert_eq!(client.client_guid(), Some(guid));
}

// Trace: `include/smb2/libsmb2.h:smb2_connection_api`, `lib/libsmb2.c:smb2_connect_share_async`, `tests/prog_cat.c`
// Spec: smb2_connection_api connect and manage SMB sessions#异步连接 share
// - **GIVEN** 调用方提供非空 context、server、share、回调和回调数据
// - **WHEN** 调用方调用 `smb2_connect_share_async(smb2, server, share, user, cb, cb_data)`
// - **THEN** 启动成功时 MUST 返回 `0` 并通过回调报告连接结果，启动失败时 MUST 返回负 errno 且不调用该命令回调
#[test]
fn test_libsmb2_async_connect_share_queues_request_and_callback_boundary() {
    let mut client = Smb2Client::new();

    client.connect_share_async("server", "share", Some("alice"));

    assert!(matches!(
        client.queued_operations(),
        [public_api::Smb2Operation::ConnectShare { server, share, user }]
            if server == "server" && share == "share" && user.as_deref() == Some("alice")
    ));
    assert_eq!(client.user(), Some("alice"));
    assert!(client.error().is_none());
}

// Trace: `include/smb2/libsmb2.h:smb2_connection_api`, `lib/sync.c:smb2_connect_share`, `tests/metastat-0202-censored.c`
// Spec: smb2_connection_api connect and manage SMB sessions#同步连接 share
// - **GIVEN** 调用方提供 context、server、share 和可选 user
// - **WHEN** 调用方调用 `smb2_connect_share(smb2, server, share, user)`
// - **THEN** 成功连接时 MUST 返回 `0`，失败时 MUST 返回负 errno 或协议错误映射值
#[test]
fn test_libsmb2_sync_connect_share_returns_status() {
    let mut client = Smb2Client::new();

    let request = sync::smb2_connect_share(&mut client, "server", "share", Some("alice")).unwrap();

    assert!(matches!(
        request.kind(),
        SyncRequestKind::ConnectShare {
            server,
            share,
            user: Some(user),
        } if server == "server" && share == "share" && user == "alice"
    ));
    assert_eq!(client.server(), Some("server"));
    assert_eq!(client.share(), Some("share"));
    assert_eq!(client.user(), Some("alice"));
    assert_eq!(client.last_completed_result().unwrap().status, 0);
    assert_eq!(
        sync::smb2_connect_share(&mut client, "server", "share", None)
            .unwrap_err()
            .code(),
        -106
    );
}

// Trace: `include/smb2/libsmb2.h:smb2_url_error_api`, `lib/init.c:smb2_parse_url`, `lib/init.c:smb2_destroy_url`, `tests/prog_mkdir.c`
// Spec: smb2_url_error_api expose URL and error helpers#解析并释放 SMB2 URL
// - **GIVEN** 调用方提供形如 `smb2://[domain;][user@]server/share/path` 的 URL 字符串
// - **WHEN** 调用方调用 `smb2_parse_url(smb2, url)` 后使用返回的 `struct smb2_url *`
// - **THEN** 成功时 MUST 填充 domain、user、server、share 和 path 字段，调用方 MUST 使用 `smb2_destroy_url()` 释放返回结构
#[test]
fn test_libsmb2_url_parse_free() {
    let mut client = Smb2Client::new();
    let parsed = client
        .parse_url("smb://DOMAIN;alice@example/share/path/to/file")
        .unwrap();

    assert_eq!(parsed.domain.as_deref(), Some("DOMAIN"));
    assert_eq!(parsed.user.as_deref(), Some("alice"));
    assert_eq!(parsed.server, "example");
    assert_eq!(parsed.share, "share");
    assert_eq!(parsed.path.as_deref(), Some("path/to/file"));
}

// Trace: `include/smb2/libsmb2.h:smb2_url_error_api`, `lib/init.c:smb2_parse_url`, `lib/errors.c:nterror_to_errno`
// Spec: smb2_url_error_api expose URL and error helpers#error/status helpers
// - **GIVEN** context 记录最近错误或调用方提供 NTSTATUS
// - **WHEN** 调用方读取 `smb2_get_error()`、`smb2_get_nterror()` 或转换 NTSTATUS
// - **THEN** safe API MUST 暴露稳定错误字符串和 errno/status 映射
#[test]
fn test_libsmb2_error_status_helpers() {
    let mut client = Smb2Client::new();

    assert!(client.parse_url("http://example/share").is_err());
    assert_eq!(client.error(), Some("URL does not start with 'smb://'"));
    assert_eq!(client.nterror(), -22);
    assert_eq!(libsmb2_rs::lib::errors::nterror_to_str(0), "STATUS_SUCCESS");
    assert_eq!(
        libsmb2_rs::lib::errors::nterror_to_errno(SMB2_STATUS_INVALID_PARAMETER),
        22
    );
}

// Trace: `include/smb2/libsmb2.h:smb2_compound_pdu_api`, `include/smb2/libsmb2-raw.h:compound_file_id`, `examples/smb2-raw-stat-async.c`
// Spec: smb2_compound_pdu_api manage compound and public PDU state#构造 compound request chain
// - **GIVEN** 调用方持有一个 first PDU 和后续 PDU
// - **WHEN** 调用方调用 `smb2_add_compound_pdu(smb2, pdu, next_pdu)` 并最终调用 `smb2_queue_pdu(smb2, pdu)`
// - **THEN** 系统 MUST 将后续 PDU 链接为 compound 命令链并允许后续请求复用 compound file id 语义
#[test]
fn test_libsmb2_compound_request_chain_sets_public_state() {
    let mut client = Smb2Client::new();
    let mut first = PduHandle::default();
    let mut next = PduHandle::default();

    client.add_compound_pdu(&mut first, &mut next);
    client.queue_pdu(&mut first);
    client.queue_pdu(&mut next);

    assert!(client.pdu_is_compound(&first));
    assert!(client.pdu_is_compound(&next));
    assert_eq!(client.pdu_message_id(&first), Some(1));
    assert_eq!(client.pdu_message_id(&next), Some(2));
    assert_eq!(client.last_request_message_id(), 2);
}

// Trace: `include/smb2/libsmb2.h:smb2_directory_api`, `lib/sync.c:smb2_opendir`, `tests/prog_ls.c`
// Spec: smb2_directory_api provide directory traversal#同步打开并读取目录
// - **GIVEN** 调用方持有已连接 share 的 context 和目录路径
// - **WHEN** 调用方调用 `smb2_opendir()`、重复调用 `smb2_readdir()` 并最终调用 `smb2_closedir()`
// - **THEN** 成功打开时 MUST 返回目录句柄，读取时 MUST 返回目录项或结束标记，关闭时 MUST 释放目录句柄资源
#[test]
fn test_libsmb2_directory_sync_open_read_traverses_local_entries() {
    let mut client = Smb2Client::new();
    client.connect_share_local("server", "share").unwrap();
    client.mkdir("dir").unwrap();
    client.truncate("dir/file.txt", 3).unwrap();

    let request = sync::smb2_opendir(&mut client, "dir").unwrap();

    assert!(matches!(
        request.kind(),
        SyncRequestKind::OpenDir { path } if path == "dir"
    ));
    assert!(matches!(
        request.payload(),
        SyncPayload::Directory(handle) if handle.id() != [0; 16]
    ));
    let entries = match client.last_completed_result().unwrap().result.as_ref().unwrap() {
        Smb2OperationResult::Directory { entries, .. } => entries,
        other => panic!("unexpected directory completion: {other:?}"),
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "file.txt");
}

// Trace: `include/smb2/libsmb2.h:smb2_file_io_api`, `lib/libsmb2.c:smb2_open_async`, `tests/prog_cat.c`
// Spec: smb2_file_io_api provide file handle IO#异步打开文件
// - **GIVEN** 调用方提供 context、路径、flags、回调和回调数据
// - **WHEN** 调用方调用 `smb2_open_async(smb2, path, flags, cb, cb_data)`
// - **THEN** 启动成功时 MUST 返回 `0` 并在回调成功时传递 `struct smb2fh *`，启动失败时 MUST 返回负值且不安排成功回调
#[test]
fn test_libsmb2_async_open_file_queues_request_boundary() {
    let mut client = Smb2Client::new();
    client.connect_share_local("server", "share").unwrap();

    client.open_async("file.txt", 0);

    assert!(matches!(
        client.queued_operations().last(),
        Some(public_api::Smb2Operation::Open { path, flags, .. }) if path == "file.txt" && *flags == 0
    ));
    assert!(matches!(
        client.command_records().last().map(|record| &record.descriptor),
        Some(public_api::Smb2CommandDescriptor::Create { path, .. }) if path == "file.txt"
    ));
}

// Trace: `include/smb2/libsmb2.h:smb2_file_io_api`, `lib/libsmb2.c:smb2_read_async`, `lib/libsmb2.c:smb2_write_async`, `tests/prog_cat.c`
// Spec: smb2_file_io_api provide file handle IO#同步读写更新文件 offset
// - **GIVEN** 调用方持有已打开文件句柄和缓冲区
// - **WHEN** 调用方通过 `smb2_read()` 或 `smb2_write()` 传输数据
// - **THEN** 成功时返回值 MUST 表示读写字节数，并按实现路径更新句柄当前 offset
#[test]
fn test_libsmb2_sync_read_write_updates_file_offset() {
    let mut client = Smb2Client::new();
    client.connect_share_local("server", "share").unwrap();
    let handle = client.open("file.txt", 0).unwrap();

    let write = sync::smb2_write(&mut client, &handle, &[1, 2, 3, 4], 4).unwrap();
    let mut read_buffer = [0_u8; 4];
    let read = sync::smb2_read(&mut client, &handle, &mut read_buffer, 4).unwrap();

    assert!(matches!(
        write.payload(),
        SyncPayload::Write { file_id, count: 4, offset: 0 } if *file_id == handle.id()
    ));
    assert!(matches!(
        read.payload(),
        SyncPayload::Read { file_id, count: 0, offset: 4, data } if *file_id == handle.id() && data.is_empty()
    ));
    assert_eq!(client.local_handle_offset(handle.id()), Some(4));
}

// Trace: `include/smb2/libsmb2.h:smb2_filesystem_mutation_api`, `lib/sync.c`, `tests/prog_mkdir.c`
// Spec: smb2_filesystem_mutation_api operate filesystem metadata#执行路径状态变更
// - **GIVEN** 调用方持有已连接 share 的 context 和目标路径
// - **WHEN** 调用方调用 mkdir、rmdir、unlink、rename、truncate 或 readlink 相关接口
// - **THEN** 成功时 MUST 按接口填充输出或返回 `0`，失败时 MUST 返回负 errno 或在异步回调中报告错误状态
#[test]
fn test_libsmb2_filesystem_mutation_returns_status_and_payload() {
    let mut client = Smb2Client::new();
    client.connect_share_local("server", "share").unwrap();

    let mkdir = sync::smb2_mkdir(&mut client, "dir").unwrap();
    assert!(matches!(
        mkdir.kind(),
        SyncRequestKind::PathOperation {
            operation: PathOperation::Mkdir,
            path,
        } if path == "dir"
    ));
    assert_eq!(client.stat("dir").unwrap().file_type, FileType::Directory);

    let rename = sync::smb2_rename(&mut client, "dir", "renamed").unwrap();
    assert!(matches!(
        rename.kind(),
        SyncRequestKind::Rename { oldpath, newpath }
            if oldpath == "dir" && newpath == "renamed"
    ));
    assert_eq!(
        client.stat("renamed").unwrap().file_type,
        FileType::Directory
    );

    let truncate = sync::smb2_truncate(&mut client, "renamed", 7).unwrap();
    assert!(matches!(
        truncate.kind(),
        SyncRequestKind::Truncate { path, length } if path == "renamed" && *length == 7
    ));
    assert_eq!(client.stat("renamed").unwrap().size, 7);

    let readlink = sync::smb2_readlink(&mut client, "renamed", 4).unwrap();
    assert!(matches!(
        readlink.kind(),
        SyncRequestKind::Readlink { path, len } if path == "renamed" && *len == 4
    ));
    assert!(matches!(readlink.payload(), SyncPayload::None));
    assert_eq!(client.last_completed_result().unwrap().status, 0);

    assert_eq!(
        sync::smb2_unlink(&mut client, "renamed").unwrap().payload(),
        &SyncPayload::None
    );
    assert_eq!(sync::smb2_mkdir(&mut client, "").unwrap_err().code(), -22);
}

// Trace: `include/smb2/libsmb2.h:smb2_echo_notify_api`, `lib/libsmb2.c`, `examples/smb2-notify.c`
// Spec: smb2_echo_notify_api support echo and change notification#同步获取目录变更通知
// - **GIVEN** 调用方持有 context、目录路径、flags 和 filter
// - **WHEN** 调用方调用 `smb2_notify_change(smb2, path, flags, filter)`
// - **THEN** 成功时 MUST 返回 `struct smb2_file_notify_change_information *` 链，调用方 MUST 使用 `free_smb2_file_notify_change_information()` 释放结果
#[test]
fn test_libsmb2_sync_notify_change_returns_request_boundary() {
    let mut client = Smb2Client::new();
    client.connect_share_local("server", "share").unwrap();

    let request = sync::smb2_notify_change(&mut client, "dir", 1, 0x10).unwrap();

    assert!(matches!(
        request.kind(),
        SyncRequestKind::NotifyChange { path, flags: 1, filter: 0x10 } if path == "dir"
    ));
    assert_eq!(request.payload(), &SyncPayload::None);
    assert!(matches!(
        client.last_completed_result().unwrap().result,
        Ok(Smb2OperationResult::Complete)
    ));
}

// Trace: `include/smb2/libsmb2.h:smb2_server_api`, `lib/libsmb2.c:smb2_serve_port`, `examples/smb2-server-sync.c`
// Spec: smb2_server_api serve SMB2 connections#同步服务端主循环
// - **GIVEN** 调用方提供初始化的 `struct smb2_server *server`、最大连接数、新连接回调和回调数据
// - **WHEN** 调用方调用 `smb2_serve_port(server, max_connections, cb, cb_data)`
// - **THEN** 系统 MUST 绑定监听 server port、accept 新连接、为每个 client context 分派可读/可写事件，并在错误导致循环退出时返回负 errno
#[test]
fn test_libsmb2_server_loop_reports_safe_boundary_status() {
    let server = public_api::bind_and_listen(445, 1).unwrap();

    assert_eq!(public_api::serve_port(&server, 1), Err(ErrorCode::new(-22)));
    assert_eq!(public_api::serve_port(&server, -1), Err(ErrorCode::new(-22)));
}

// Trace: `include/smb2/libsmb2.h:smb2_unicode_api`, `lib/unicode.c:smb2_utf8_to_utf16`
// Spec: smb2_unicode_api convert UTF encodings#UTF-8 转 UTF-16LE
// - **GIVEN** 调用方提供有效 UTF-8 字符串
// - **WHEN** 调用方调用 `smb2_utf8_to_utf16(utf8)`
// - **THEN** 成功时 MUST 返回包含 UTF-16 code unit 长度和 little-endian code units 的 `struct smb2_utf16 *`，失败时 MUST 返回 `NULL`
#[test]
fn test_libsmb2_utf8_to_utf16le() {
    assert_eq!(
        unicode::utf8_to_utf16_units("Aé你"),
        Some(vec![0x0041, 0x00e9, 0x4f60])
    );
}

// Trace: `include/smb2/libsmb2.h:smb2_unicode_api`, `lib/unicode.c:smb2_utf16_to_utf8`
// Spec: smb2_unicode_api convert UTF encodings#UTF-16LE 转 UTF-8
// - **GIVEN** 调用方提供 UTF-16LE code unit 指针和长度
// - **WHEN** 调用方调用 `smb2_utf16_to_utf8(str, len)`
// - **THEN** 成功时 MUST 返回可由 `free()` 释放的 UTF-8 字符串
#[test]
fn test_libsmb2_utf16le_to_utf8() {
    assert_eq!(
        unicode::utf16_units_to_utf8(&[0x0041, 0x00e9, 0x4f60]),
        Some(String::from("Aé你"))
    );
}
