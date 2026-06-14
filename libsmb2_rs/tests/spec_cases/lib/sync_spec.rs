use libsmb2_sys::legacy::sync::{self as c_sync, SyncOperation};

fn run_status(operation: SyncOperation, expected: i32) -> c_sync::StatusResult {
    c_sync::run_status(operation, expected)
}

fn run_status_start_failure(operation: SyncOperation) -> c_sync::StatusResult {
    c_sync::run_status_start_failure(operation, -5)
}

fn run_pointer(operation: SyncOperation) -> c_sync::PointerResult {
    c_sync::run_pointer(operation)
}

// Trace: `lib/sync.c:smb2_connect_share`, `include/smb2/libsmb2.h:smb2_connect_share`, `tests/prog_ls.c:main`
// Spec: smb2_connect_share synchronous share connection#connection completes through async callback
// - **GIVEN** 调用方提供 `smb2`、`server`、`share` 和 `user` 参数，且异步连接成功发起
// - **WHEN** 调用方调用 `smb2_connect_share`
// - **THEN** 函数返回 `sync_connect_cb` 写入的状态值
#[test]
fn test_sync_connection_completes_through_async_callback() {
    let result = run_status(SyncOperation::ConnectShare, 0);

    assert_eq!(result.rc, 0, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 0);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_connect_share`, `lib/sync.c:wait_for_reply`
// Spec: smb2_connect_share synchronous share connection#wait fails after connect request
// - **GIVEN** 异步连接请求已经发起，但轮询或 service 路径返回错误
// - **WHEN** `wait_for_reply` 返回负值
// - **THEN** 函数将同步回调状态标记为 `SMB2_STATUS_CANCELLED` 并返回该负错误码
#[test]
fn test_sync_wait_fails_after_connect_request() {
    let result = run_status_start_failure(SyncOperation::ConnectShare);

    assert!(result.rc < 0, "unexpected success: {result:?}");
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_disconnect_share`, `include/smb2/libsmb2.h:smb2_disconnect_share`, `tests/prog_mkdir.c:main`
// Spec: smb2_disconnect_share synchronous share disconnection#disconnect completes through async callback
// - **GIVEN** 调用方提供已初始化的 `smb2` 上下文
// - **WHEN** 调用方调用 `smb2_disconnect_share`
// - **THEN** 函数返回 `sync_connect_cb` 写入的断开状态
#[test]
fn test_sync_disconnect_completes_through_async_callback() {
    let result = run_status(SyncOperation::DisconnectShare, 0);

    assert_eq!(result.rc, 0, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 0);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_opendir`, `include/smb2/libsmb2.h:smb2_opendir`, `tests/prog_ls.c:main`
// Spec: smb2_opendir synchronous directory open#directory handle returned
// - **GIVEN** 异步目录打开返回 PDU 且回调提供非空目录指针
// - **WHEN** 调用方调用 `smb2_opendir`
// - **THEN** 函数返回该目录指针，并将回调数据释放函数交给目录对象生命周期
#[test]
fn test_sync_directory_handle_returned() {
    let result = run_pointer(SyncOperation::Opendir);

    assert!(result.returned_pointer, "expected pointer result: {result:?}");
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_opendir`
// Spec: smb2_opendir synchronous directory open#opendir setup or wait fails
// - **GIVEN** 回调数据分配、异步 PDU 创建或等待过程失败
// - **WHEN** `smb2_opendir` 检测到失败
// - **THEN** 函数返回 `NULL`，并释放已分配的回调数据和 PDU
#[test]
fn test_sync_opendir_setup_or_wait_fails() {
    let result = c_sync::run_pointer_start_failure(SyncOperation::Opendir, -5);

    assert!(!result.returned_pointer);
    assert!(result.rc < 0);
}

// Trace: `lib/sync.c:smb2_open`, `include/smb2/libsmb2.h:smb2_open`
// Spec: smb2_open synchronous file open#file handle returned
// - **GIVEN** 异步 open PDU 创建成功且回调提供文件句柄
// - **WHEN** 调用方调用 `smb2_open`
// - **THEN** 函数返回回调提供的 `struct smb2fh *`，并在释放 PDU 前清空回调数据中的指针所有权
#[test]
fn test_sync_file_handle_returned() {
    let result = run_pointer(SyncOperation::Open);

    assert!(result.returned_pointer, "expected pointer result: {result:?}");
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_open`
// Spec: smb2_open synchronous file open#open setup fails
// - **GIVEN** 回调数据分配失败或 `smb2_open_async_pdu` 返回 `NULL`
// - **WHEN** 调用方调用 `smb2_open`
// - **THEN** 函数返回 `NULL`，并设置错误消息说明本地失败原因
#[test]
fn test_sync_open_setup_fails() {
    let result = c_sync::run_pointer_start_failure(SyncOperation::Open, -5);

    assert!(!result.returned_pointer);
    assert!(result.rc < 0);
}

// Trace: `lib/sync.c:smb2_close`, `include/smb2/libsmb2.h:smb2_close`
// Spec: smb2_close synchronous file close#close returns callback status
// - **GIVEN** 调用方提供文件句柄且异步 close 请求启动成功
// - **WHEN** 调用方调用 `smb2_close`
// - **THEN** 函数返回 close 回调写入的状态并释放同步回调数据
#[test]
fn test_sync_close_returns_callback_status() {
    let result = run_status(SyncOperation::Close, -7);

    assert_eq!(result.rc, -7, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, -7);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_fsync`, `include/smb2/libsmb2.h:smb2_fsync`
// Spec: smb2_fsync synchronous flush#fsync returns callback status
// - **GIVEN** 调用方提供文件句柄且异步 fsync 请求启动成功
// - **WHEN** 调用方调用 `smb2_fsync`
// - **THEN** 函数返回 fsync 回调写入的状态并释放同步回调数据
#[test]
fn test_sync_fsync_returns_callback_status() {
    let result = run_status(SyncOperation::Fsync, -8);

    assert_eq!(result.rc, -8, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, -8);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_pread`, `include/smb2/libsmb2.h:smb2_pread`
// Spec: smb2_pread synchronous positioned read#positioned read completes
// - **GIVEN** 调用方提供文件句柄、输出缓冲区、读取长度和 offset
// - **WHEN** 调用方调用 `smb2_pread`
// - **THEN** 函数返回同步回调保存的字节数或负错误码
#[test]
fn test_sync_positioned_read_completes() {
    let result = run_status(SyncOperation::Pread, 8);

    assert_eq!(result.rc, 8, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 8);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_pwrite`, `include/smb2/libsmb2.h:smb2_pwrite`
// Spec: smb2_pwrite synchronous positioned write#positioned write completes
// - **GIVEN** 调用方提供文件句柄、输入缓冲区、写入长度和 offset
// - **WHEN** 调用方调用 `smb2_pwrite`
// - **THEN** 函数返回同步回调保存的字节数或负错误码
#[test]
fn test_sync_positioned_write_completes() {
    let result = run_status(SyncOperation::Pwrite, 8);

    assert_eq!(result.rc, 8, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 8);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_read`, `include/smb2/libsmb2.h:smb2_read`
// Spec: smb2_read synchronous sequential read#sequential read completes
// - **GIVEN** 调用方提供文件句柄、输出缓冲区和读取长度
// - **WHEN** 调用方调用 `smb2_read`
// - **THEN** 函数返回同步回调保存的字节数或负错误码
#[test]
fn test_sync_sequential_read_completes() {
    let result = run_status(SyncOperation::Read, 8);

    assert_eq!(result.rc, 8, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 8);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_write`, `include/smb2/libsmb2.h:smb2_write`
// Spec: smb2_write synchronous sequential write#sequential write completes
// - **GIVEN** 调用方提供文件句柄、输入缓冲区和写入长度
// - **WHEN** 调用方调用 `smb2_write`
// - **THEN** 函数返回同步回调保存的字节数或负错误码
#[test]
fn test_sync_sequential_write_completes() {
    let result = run_status(SyncOperation::Write, 8);

    assert_eq!(result.rc, 8, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 8);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_unlink`, `include/smb2/libsmb2.h:smb2_unlink`
// Spec: smb2_unlink synchronous file removal#unlink completes
// - **GIVEN** 调用方提供目标路径
// - **WHEN** 调用方调用 `smb2_unlink`
// - **THEN** 函数返回 unlink 回调写入的状态并释放同步回调数据
#[test]
fn test_sync_unlink_completes() {
    let result = run_status(SyncOperation::Unlink, 0);

    assert_eq!(result.rc, 0, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 0);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_rmdir`, `include/smb2/libsmb2.h:smb2_rmdir`, `tests/prog_rmdir.c:main`
// Spec: smb2_rmdir synchronous directory removal#rmdir completes
// - **GIVEN** 调用方提供目标目录路径
// - **WHEN** 调用方调用 `smb2_rmdir`
// - **THEN** 函数返回 rmdir 回调写入的状态并释放同步回调数据
#[test]
fn test_sync_rmdir_completes() {
    let result = run_status(SyncOperation::Rmdir, 0);

    assert_eq!(result.rc, 0, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 0);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_mkdir`, `include/smb2/libsmb2.h:smb2_mkdir`, `tests/prog_mkdir.c:main`
// Spec: smb2_mkdir synchronous directory creation#mkdir completes
// - **GIVEN** 调用方提供目标目录路径
// - **WHEN** 调用方调用 `smb2_mkdir`
// - **THEN** 函数返回 mkdir 回调写入的状态并释放同步回调数据
#[test]
fn test_sync_mkdir_completes() {
    let result = run_status(SyncOperation::Mkdir, 0);

    assert_eq!(result.rc, 0, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 0);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_fstat`, `include/smb2/libsmb2.h:smb2_fstat`
// Spec: smb2_fstat synchronous file-handle stat#fstat completes
// - **GIVEN** 调用方提供文件句柄和 `struct smb2_stat_64 *st`
// - **WHEN** 调用方调用 `smb2_fstat`
// - **THEN** 函数返回 fstat 回调写入的状态并释放同步回调数据
#[test]
fn test_sync_fstat_completes() {
    let result = run_status(SyncOperation::Fstat, 0);

    assert_eq!(result.rc, 0, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 0);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_stat`, `include/smb2/libsmb2.h:smb2_stat`
// Spec: smb2_stat synchronous path stat#stat completes
// - **GIVEN** 调用方提供路径和 `struct smb2_stat_64 *st`
// - **WHEN** 调用方调用 `smb2_stat`
// - **THEN** 函数返回 stat 回调写入的状态并释放同步回调数据
#[test]
fn test_sync_stat_completes() {
    let result = run_status(SyncOperation::Stat, 0);

    assert_eq!(result.rc, 0, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 0);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_rename`, `include/smb2/libsmb2.h:smb2_rename`
// Spec: smb2_rename synchronous path rename#rename completes
// - **GIVEN** 调用方提供旧路径和新路径
// - **WHEN** 调用方调用 `smb2_rename`
// - **THEN** 函数返回 rename 回调写入的状态并释放同步回调数据
#[test]
fn test_sync_rename_completes() {
    let result = run_status(SyncOperation::Rename, 0);

    assert_eq!(result.rc, 0, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 0);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_statvfs`, `include/smb2/libsmb2.h:smb2_statvfs`
// Spec: smb2_statvfs synchronous filesystem stat#statvfs completes
// - **GIVEN** 调用方提供路径和 `struct smb2_statvfs *statvfs`
// - **WHEN** 调用方调用 `smb2_statvfs`
// - **THEN** 函数返回 statvfs 回调写入的状态并释放同步回调数据
#[test]
fn test_sync_statvfs_completes() {
    let result = run_status(SyncOperation::Statvfs, 0);

    assert_eq!(result.rc, 0, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 0);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_truncate`, `include/smb2/libsmb2.h:smb2_truncate`
// Spec: smb2_truncate synchronous path truncation#truncate completes
// - **GIVEN** 调用方提供路径和目标长度
// - **WHEN** 调用方调用 `smb2_truncate`
// - **THEN** 函数返回 truncate 回调写入的状态并释放同步回调数据
#[test]
fn test_sync_truncate_completes() {
    let result = run_status(SyncOperation::Truncate, 0);

    assert_eq!(result.rc, 0, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 0);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_ftruncate`, `include/smb2/libsmb2.h:smb2_ftruncate`
// Spec: smb2_ftruncate synchronous file-handle truncation#ftruncate completes
// - **GIVEN** 调用方提供文件句柄和目标长度
// - **WHEN** 调用方调用 `smb2_ftruncate`
// - **THEN** 函数返回 ftruncate 回调写入的状态并释放同步回调数据
#[test]
fn test_sync_ftruncate_completes() {
    let result = run_status(SyncOperation::Ftruncate, 0);

    assert_eq!(result.rc, 0, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 0);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_readlink`, `include/smb2/libsmb2.h:smb2_readlink`, `tests/prog_ls.c:main`
// Spec: smb2_readlink synchronous link read#readlink copies response text
// - **GIVEN** 调用方提供路径、输出缓冲区和缓冲区长度
// - **WHEN** 调用方调用 `smb2_readlink` 且异步 readlink 成功返回链接内容
// - **THEN** 函数将回调内容复制到 `buf`，返回回调状态，并释放同步回调数据
#[test]
fn test_sync_readlink_copies_response_text() {
    let result = run_status(SyncOperation::Readlink, 0);

    assert_eq!(result.rc, 0, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 0);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_echo`, `include/smb2/libsmb2.h:smb2_echo`
// Spec: smb2_echo synchronous echo command#echo rejects disconnected context
// - **GIVEN** `smb2->fd` 不是有效 socket
// - **WHEN** 调用方调用 `smb2_echo`
// - **THEN** 函数设置 `Not Connected to Server` 错误并返回 `-ENOMEM`
#[test]
fn test_sync_echo_rejects_disconnected_context() {
    let result = c_sync::run_disconnected(SyncOperation::Echo);

    assert!(result.rc < 0);
}

// Trace: `lib/sync.c:smb2_echo`, `include/smb2/libsmb2.h:smb2_echo`
// Spec: smb2_echo synchronous echo command#echo completes while connected
// - **GIVEN** `smb2->fd` 是有效 socket 且异步 echo 启动成功
// - **WHEN** 调用方调用 `smb2_echo`
// - **THEN** 函数返回 echo 回调写入的状态并释放同步回调数据
#[test]
fn test_sync_echo_completes_while_connected() {
    let result = run_status(SyncOperation::Echo, 0);

    assert_eq!(result.rc, 0, "unexpected result: {result:?}");
    assert_eq!(result.callback_status, 0);
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_notify_change`, `include/smb2/libsmb2.h:smb2_notify_change`
// Spec: smb2_notify_change synchronous one-off notification#notify change returns response chain
// - **GIVEN** 调用方提供路径、flags 和 filter，且异步 notify change 完成
// - **WHEN** 调用方调用 `smb2_notify_change`
// - **THEN** 函数返回回调提供的通知响应指针并释放同步回调数据
#[test]
fn test_sync_notify_change_returns_response_chain() {
    let result = run_pointer(SyncOperation::NotifyChange);

    assert!(result.returned_pointer, "expected pointer result: {result:?}");
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}

// Trace: `lib/sync.c:smb2_share_enum_sync`, `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_sync`
// Spec: smb2_share_enum_sync synchronous SRVSVC share enumeration#share enum rejects disconnected context
// - **GIVEN** `smb2->fd` 不是有效 socket
// - **WHEN** 调用方调用 `smb2_share_enum_sync`
// - **THEN** 函数设置 `Not Connected to Server` 错误并返回 `NULL`
#[test]
fn test_sync_share_enum_rejects_disconnected_context() {
    let result = c_sync::run_disconnected(SyncOperation::ShareEnum);

    assert!(!result.returned_pointer);
    assert!(result.rc < 0);
}

// Trace: `lib/sync.c:smb2_share_enum_sync`, `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_sync`
// Spec: smb2_share_enum_sync synchronous SRVSVC share enumeration#share enum returns response
// - **GIVEN** context 已连接到可执行 SRVSVC ShareEnum 的 share，且异步请求完成
// - **WHEN** 调用方调用 `smb2_share_enum_sync`
// - **THEN** 函数返回 `struct srvsvc_NetrShareEnum_rep *` 响应指针并释放同步回调数据
#[test]
fn test_sync_share_enum_returns_response() {
    let result = run_pointer(SyncOperation::ShareEnum);

    assert!(result.returned_pointer, "expected pointer result: {result:?}");
    assert!(result.async_called >= 1, "async path was not called: {result:?}");
}
