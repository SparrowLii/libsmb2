# lib/sync.c Specification

## Source Context

- Source: `lib/sync.c`
- Related Headers: `include/smb2/libsmb2.h`, `include/smb2/libsmb2-dcerpc-srvsvc.h`, `include/smb2/smb2.h`, `include/smb2/libsmb2-raw.h`, `include/smb2/libsmb2-private.h`
- Related Tests: `tests/prog_ls.c`, `tests/prog_mkdir.c`, `tests/prog_rmdir.c`, `tests/metastat-0202-censored.c`
- Related Dependencies: `smb2_connect_share_async`, `smb2_disconnect_share_async`, `smb2_opendir_async_pdu`, `smb2_open_async_pdu`, `smb2_close_async`, `smb2_fsync_async`, `smb2_pread_async`, `smb2_pwrite_async`, `smb2_read_async`, `smb2_write_async`, `smb2_unlink_async`, `smb2_rmdir_async`, `smb2_mkdir_async`, `smb2_fstat_async`, `smb2_stat_async`, `smb2_rename_async`, `smb2_statvfs_async`, `smb2_truncate_async`, `smb2_ftruncate_async`, `smb2_readlink_async`, `smb2_echo_async`, `smb2_notify_change_async`, `smb2_share_enum_async`, `smb2_service`, `smb2_timeout_pdus`
- Build/Compile Context: `CMakeLists.txt` and `configure.ac` build a C library; `lib/sync.c` conditionally includes config, stdint, stdlib, poll, string, time, and sys/time headers based on configure macros.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| wait_for_reply | function | static int wait_for_reply(struct smb2_context *smb2, struct sync_cb_data *cb_data) | Skip | 内部阻塞轮询 helper，无独立公开 ABI；其轮询、超时和 service 错误语义归属到各同步 wrapper。 |
| sync_connect_cb | function | static void sync_connect_cb(struct smb2_context *smb2, int status, void *command_data, void *private_data) | Skip | 内部回调，仅搬运异步状态到同步等待数据。 |
| smb2_connect_share | function | int smb2_connect_share(struct smb2_context *smb2, const char *server, const char *share, const char *user) | Include | 公开同步连接入口，封装异步连接和阻塞等待。 |
| smb2_disconnect_share | function | int smb2_disconnect_share(struct smb2_context *smb2) | Include | 公开同步断开入口，封装异步断开和阻塞等待。 |
| sync_opendir_cb | function | static void sync_opendir_cb(struct smb2_context *smb2, int status, void *command_data, void *private_data) | Skip | 内部回调，仅将目录结果和状态写入同步等待数据。 |
| smb2_opendir | function | struct smb2dir *smb2_opendir(struct smb2_context *smb2, const char *path) | Include | 公开同步目录打开入口，返回需由调用方关闭的目录句柄。 |
| sync_open_cb | function | static void sync_open_cb(struct smb2_context *smb2, int status, void *command_data, void *private_data) | Skip | 内部回调，仅保存打开结果指针。 |
| smb2_open | function | struct smb2fh *smb2_open(struct smb2_context *smb2, const char *path, int flags) | Include | 公开同步文件打开入口，返回需由调用方关闭的文件句柄。 |
| sync_close_cb | function | static void sync_close_cb(struct smb2_context *smb2, int status, void *command_data, void *private_data) | Skip | 内部回调，仅保存 close 状态并处理取消释放。 |
| smb2_close | function | int smb2_close(struct smb2_context *smb2, struct smb2fh *fh) | Include | 公开同步文件关闭入口，返回异步 close 状态。 |
| sync_fsync_cb | function | static void sync_fsync_cb(struct smb2_context *smb2, int status, void *command_data, void *private_data) | Skip | 内部回调，仅保存 fsync 状态并处理取消释放。 |
| smb2_fsync | function | int smb2_fsync(struct smb2_context *smb2, struct smb2fh *fh) | Include | 公开同步 flush 入口，返回异步 fsync 状态。 |
| sync_generic_status_cb | function | static void sync_generic_status_cb(struct smb2_context *smb2, int status, void *command_data, void *private_data) | Skip | 内部通用状态回调，语义归属到各公开同步 wrapper。 |
| smb2_pread | function | int smb2_pread(struct smb2_context *smb2, struct smb2fh *fh, uint8_t *buf, uint32_t count, uint64_t offset) | Include | 公开同步按偏移读取入口，返回字节数或负 errno。 |
| smb2_pwrite | function | int smb2_pwrite(struct smb2_context *smb2, struct smb2fh *fh, const uint8_t *buf, uint32_t count, uint64_t offset) | Include | 公开同步按偏移写入入口，返回字节数或负 errno。 |
| smb2_read | function | int smb2_read(struct smb2_context *smb2, struct smb2fh *fh, uint8_t *buf, uint32_t count) | Include | 公开同步顺序读取入口，返回字节数或负 errno。 |
| smb2_write | function | int smb2_write(struct smb2_context *smb2, struct smb2fh *fh, const uint8_t *buf, uint32_t count) | Include | 公开同步顺序写入入口，返回字节数或负 errno。 |
| smb2_unlink | function | int smb2_unlink(struct smb2_context *smb2, const char *path) | Include | 公开同步删除文件入口，返回异步 unlink 状态。 |
| smb2_rmdir | function | int smb2_rmdir(struct smb2_context *smb2, const char *path) | Include | 公开同步删除目录入口，返回异步 rmdir 状态。 |
| smb2_mkdir | function | int smb2_mkdir(struct smb2_context *smb2, const char *path) | Include | 公开同步创建目录入口，返回异步 mkdir 状态。 |
| smb2_fstat | function | int smb2_fstat(struct smb2_context *smb2, struct smb2fh *fh, struct smb2_stat_64 *st) | Include | 公开同步文件句柄 stat 入口，将结果写入调用方缓冲区。 |
| smb2_stat | function | int smb2_stat(struct smb2_context *smb2, const char *path, struct smb2_stat_64 *st) | Include | 公开同步路径 stat 入口，将结果写入调用方缓冲区。 |
| smb2_rename | function | int smb2_rename(struct smb2_context *smb2, const char *oldpath, const char *newpath) | Include | 公开同步重命名入口，返回异步 rename 状态。 |
| smb2_statvfs | function | int smb2_statvfs(struct smb2_context *smb2, const char *path, struct smb2_statvfs *statvfs) | Include | 公开同步文件系统 stat 入口，将结果写入调用方缓冲区。 |
| smb2_truncate | function | int smb2_truncate(struct smb2_context *smb2, const char *path, uint64_t length) | Include | 公开同步路径截断入口，返回异步 truncate 状态。 |
| smb2_ftruncate | function | int smb2_ftruncate(struct smb2_context *smb2, struct smb2fh *fh, uint64_t length) | Include | 公开同步文件句柄截断入口，返回异步 ftruncate 状态。 |
| sync_readlink_cb_data | type | struct sync_readlink_cb_data { char *buf; int len; }; | Skip | 文件内部 callback 数据结构，不对调用方暴露 ABI。 |
| readlink_cb | function | static void readlink_cb(struct smb2_context *smb2, int status, void *command_data, void *private_data) | Skip | 内部回调，将 readlink 响应复制到调用方缓冲区。 |
| smb2_readlink | function | int smb2_readlink(struct smb2_context *smb2, const char *path, char *buf, uint32_t bufsiz) | Include | 公开同步 readlink 入口，将链接内容复制到调用方缓冲区。 |
| sync_echo_cb | function | static void sync_echo_cb(struct smb2_context *smb2, int status, void *command_data, void *private_data) | Skip | 内部回调，仅保存 echo 状态。 |
| smb2_echo | function | int smb2_echo(struct smb2_context *smb2) | Include | 公开同步 echo 入口，包含未连接检查。 |
| sync_notify_change_cb | function | static void sync_notify_change_cb(struct smb2_context *smb2, int status, void *command_data, void *private_data) | Skip | 内部回调，仅保存 notify change 响应指针。 |
| smb2_notify_change | function | struct smb2_file_notify_change_information *smb2_notify_change(struct smb2_context *smb2, const char *path, uint16_t flags, uint32_t filter) | Include | 公开一次性同步 notify change 入口，返回需调用方释放的响应链。 |
| sync_share_enum_cb | function | static void sync_share_enum_cb(struct smb2_context *smb2, int status, void *command_data, void *private_data) | Skip | 内部回调，仅保存 share enum 响应和状态。 |
| smb2_share_enum_sync | function | struct srvsvc_NetrShareEnum_rep *smb2_share_enum_sync(struct smb2_context *smb2, enum SHARE_INFO_enum level) | Include | 公开同步 SRVSVC ShareEnum 入口，要求 IPC$ share 上下文。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| sync_readlink_cb_data | struct | lib/sync.c:782 | 内部 readlink 回调数据，保存调用方输出缓冲区指针和长度。 |

## ADDED Requirements

### Requirement: smb2_connect_share synchronous share connection
系统 MUST 通过 `smb2_connect_share_async` 发起连接，并在回调完成前阻塞服务 SMB2 事件；成功时返回回调状态，启动失败或等待失败时返回负错误码。

#### Scenario: connection completes through async callback
- **GIVEN** 调用方提供 `smb2`、`server`、`share` 和 `user` 参数，且异步连接成功发起
- **WHEN** 调用方调用 `smb2_connect_share`
- **THEN** 函数返回 `sync_connect_cb` 写入的状态值

Trace: `lib/sync.c:smb2_connect_share`, `include/smb2/libsmb2.h:smb2_connect_share`, `tests/prog_ls.c:main`

#### Scenario: wait fails after connect request
- **GIVEN** 异步连接请求已经发起，但轮询或 service 路径返回错误
- **WHEN** `wait_for_reply` 返回负值
- **THEN** 函数将同步回调状态标记为 `SMB2_STATUS_CANCELLED` 并返回该负错误码

Trace: `lib/sync.c:smb2_connect_share`, `lib/sync.c:wait_for_reply`

### Requirement: smb2_disconnect_share synchronous share disconnection
系统 MUST 通过 `smb2_disconnect_share_async` 发起断开并阻塞等待回调完成；成功时返回回调状态，启动失败或等待失败时返回负错误码。

#### Scenario: disconnect completes through async callback
- **GIVEN** 调用方提供已初始化的 `smb2` 上下文
- **WHEN** 调用方调用 `smb2_disconnect_share`
- **THEN** 函数返回 `sync_connect_cb` 写入的断开状态

Trace: `lib/sync.c:smb2_disconnect_share`, `include/smb2/libsmb2.h:smb2_disconnect_share`, `tests/prog_mkdir.c:main`

### Requirement: smb2_opendir synchronous directory open
系统 MUST 分配同步回调数据并通过 `smb2_opendir_async_pdu` 发起目录打开；成功时返回目录句柄，失败时返回 `NULL` 并释放本函数持有的临时资源。

#### Scenario: directory handle returned
- **GIVEN** 异步目录打开返回 PDU 且回调提供非空目录指针
- **WHEN** 调用方调用 `smb2_opendir`
- **THEN** 函数返回该目录指针，并将回调数据释放函数交给目录对象生命周期

Trace: `lib/sync.c:smb2_opendir`, `include/smb2/libsmb2.h:smb2_opendir`, `tests/prog_ls.c:main`

#### Scenario: opendir setup or wait fails
- **GIVEN** 回调数据分配、异步 PDU 创建或等待过程失败
- **WHEN** `smb2_opendir` 检测到失败
- **THEN** 函数返回 `NULL`，并释放已分配的回调数据和 PDU

Trace: `lib/sync.c:smb2_opendir`

### Requirement: smb2_open synchronous file open
系统 MUST 通过 `smb2_open_async_pdu` 发起打开请求；成功时返回文件句柄指针，失败时返回 `NULL` 并通过 context error 记录本地启动失败。

#### Scenario: file handle returned
- **GIVEN** 异步 open PDU 创建成功且回调提供文件句柄
- **WHEN** 调用方调用 `smb2_open`
- **THEN** 函数返回回调提供的 `struct smb2fh *`，并在释放 PDU 前清空回调数据中的指针所有权

Trace: `lib/sync.c:smb2_open`, `include/smb2/libsmb2.h:smb2_open`

#### Scenario: open setup fails
- **GIVEN** 回调数据分配失败或 `smb2_open_async_pdu` 返回 `NULL`
- **WHEN** 调用方调用 `smb2_open`
- **THEN** 函数返回 `NULL`，并设置错误消息说明本地失败原因

Trace: `lib/sync.c:smb2_open`

### Requirement: smb2_close synchronous file close
系统 MUST 通过 `smb2_close_async` 发起关闭请求，阻塞等待完成，并返回回调状态或本地负错误码。

#### Scenario: close returns callback status
- **GIVEN** 调用方提供文件句柄且异步 close 请求启动成功
- **WHEN** 调用方调用 `smb2_close`
- **THEN** 函数返回 close 回调写入的状态并释放同步回调数据

Trace: `lib/sync.c:smb2_close`, `include/smb2/libsmb2.h:smb2_close`

### Requirement: smb2_fsync synchronous flush
系统 MUST 通过 `smb2_fsync_async` 发起 flush 请求，阻塞等待完成，并返回回调状态或本地负错误码。

#### Scenario: fsync returns callback status
- **GIVEN** 调用方提供文件句柄且异步 fsync 请求启动成功
- **WHEN** 调用方调用 `smb2_fsync`
- **THEN** 函数返回 fsync 回调写入的状态并释放同步回调数据

Trace: `lib/sync.c:smb2_fsync`, `include/smb2/libsmb2.h:smb2_fsync`

### Requirement: smb2_pread synchronous positioned read
系统 MUST 通过 `smb2_pread_async` 发起带 offset 的读取请求，并返回回调状态；成功状态按公开异步契约表示读取字节数。

#### Scenario: positioned read completes
- **GIVEN** 调用方提供文件句柄、输出缓冲区、读取长度和 offset
- **WHEN** 调用方调用 `smb2_pread`
- **THEN** 函数返回同步回调保存的字节数或负错误码

Trace: `lib/sync.c:smb2_pread`, `include/smb2/libsmb2.h:smb2_pread`

### Requirement: smb2_pwrite synchronous positioned write
系统 MUST 通过 `smb2_pwrite_async` 发起带 offset 的写入请求，并返回回调状态；成功状态按公开异步契约表示写入字节数。

#### Scenario: positioned write completes
- **GIVEN** 调用方提供文件句柄、输入缓冲区、写入长度和 offset
- **WHEN** 调用方调用 `smb2_pwrite`
- **THEN** 函数返回同步回调保存的字节数或负错误码

Trace: `lib/sync.c:smb2_pwrite`, `include/smb2/libsmb2.h:smb2_pwrite`

### Requirement: smb2_read synchronous sequential read
系统 MUST 通过 `smb2_read_async` 发起顺序读取请求，并返回回调状态；成功状态按公开异步契约表示读取字节数。

#### Scenario: sequential read completes
- **GIVEN** 调用方提供文件句柄、输出缓冲区和读取长度
- **WHEN** 调用方调用 `smb2_read`
- **THEN** 函数返回同步回调保存的字节数或负错误码

Trace: `lib/sync.c:smb2_read`, `include/smb2/libsmb2.h:smb2_read`

### Requirement: smb2_write synchronous sequential write
系统 MUST 通过 `smb2_write_async` 发起顺序写入请求，并返回回调状态；成功状态按公开异步契约表示写入字节数。

#### Scenario: sequential write completes
- **GIVEN** 调用方提供文件句柄、输入缓冲区和写入长度
- **WHEN** 调用方调用 `smb2_write`
- **THEN** 函数返回同步回调保存的字节数或负错误码

Trace: `lib/sync.c:smb2_write`, `include/smb2/libsmb2.h:smb2_write`

### Requirement: smb2_unlink synchronous file removal
系统 MUST 通过 `smb2_unlink_async` 发起路径删除请求，阻塞等待完成，并返回回调状态或本地负错误码。

#### Scenario: unlink completes
- **GIVEN** 调用方提供目标路径
- **WHEN** 调用方调用 `smb2_unlink`
- **THEN** 函数返回 unlink 回调写入的状态并释放同步回调数据

Trace: `lib/sync.c:smb2_unlink`, `include/smb2/libsmb2.h:smb2_unlink`

### Requirement: smb2_rmdir synchronous directory removal
系统 MUST 通过 `smb2_rmdir_async` 发起目录删除请求，阻塞等待完成，并返回回调状态或本地负错误码。

#### Scenario: rmdir completes
- **GIVEN** 调用方提供目标目录路径
- **WHEN** 调用方调用 `smb2_rmdir`
- **THEN** 函数返回 rmdir 回调写入的状态并释放同步回调数据

Trace: `lib/sync.c:smb2_rmdir`, `include/smb2/libsmb2.h:smb2_rmdir`, `tests/prog_rmdir.c:main`

### Requirement: smb2_mkdir synchronous directory creation
系统 MUST 通过 `smb2_mkdir_async` 发起目录创建请求，阻塞等待完成，并返回回调状态或本地负错误码。

#### Scenario: mkdir completes
- **GIVEN** 调用方提供目标目录路径
- **WHEN** 调用方调用 `smb2_mkdir`
- **THEN** 函数返回 mkdir 回调写入的状态并释放同步回调数据

Trace: `lib/sync.c:smb2_mkdir`, `include/smb2/libsmb2.h:smb2_mkdir`, `tests/prog_mkdir.c:main`

### Requirement: smb2_fstat synchronous file-handle stat
系统 MUST 通过 `smb2_fstat_async` 发起文件句柄 stat 请求，并将成功结果交由异步层写入调用方提供的 `struct smb2_stat_64`。

#### Scenario: fstat completes
- **GIVEN** 调用方提供文件句柄和 `struct smb2_stat_64 *st`
- **WHEN** 调用方调用 `smb2_fstat`
- **THEN** 函数返回 fstat 回调写入的状态并释放同步回调数据

Trace: `lib/sync.c:smb2_fstat`, `include/smb2/libsmb2.h:smb2_fstat`

### Requirement: smb2_stat synchronous path stat
系统 MUST 通过 `smb2_stat_async` 发起路径 stat 请求，并将成功结果交由异步层写入调用方提供的 `struct smb2_stat_64`。

#### Scenario: stat completes
- **GIVEN** 调用方提供路径和 `struct smb2_stat_64 *st`
- **WHEN** 调用方调用 `smb2_stat`
- **THEN** 函数返回 stat 回调写入的状态并释放同步回调数据

Trace: `lib/sync.c:smb2_stat`, `include/smb2/libsmb2.h:smb2_stat`

### Requirement: smb2_rename synchronous path rename
系统 MUST 通过 `smb2_rename_async` 发起路径重命名请求，阻塞等待完成，并返回回调状态或本地负错误码。

#### Scenario: rename completes
- **GIVEN** 调用方提供旧路径和新路径
- **WHEN** 调用方调用 `smb2_rename`
- **THEN** 函数返回 rename 回调写入的状态并释放同步回调数据

Trace: `lib/sync.c:smb2_rename`, `include/smb2/libsmb2.h:smb2_rename`

### Requirement: smb2_statvfs synchronous filesystem stat
系统 MUST 通过 `smb2_statvfs_async` 发起文件系统 stat 请求，并将成功结果交由异步层写入调用方提供的 `struct smb2_statvfs`。

#### Scenario: statvfs completes
- **GIVEN** 调用方提供路径和 `struct smb2_statvfs *statvfs`
- **WHEN** 调用方调用 `smb2_statvfs`
- **THEN** 函数返回 statvfs 回调写入的状态并释放同步回调数据

Trace: `lib/sync.c:smb2_statvfs`, `include/smb2/libsmb2.h:smb2_statvfs`

### Requirement: smb2_truncate synchronous path truncation
系统 MUST 通过 `smb2_truncate_async` 发起路径截断请求，阻塞等待完成，并返回回调状态或本地负错误码。

#### Scenario: truncate completes
- **GIVEN** 调用方提供路径和目标长度
- **WHEN** 调用方调用 `smb2_truncate`
- **THEN** 函数返回 truncate 回调写入的状态并释放同步回调数据

Trace: `lib/sync.c:smb2_truncate`, `include/smb2/libsmb2.h:smb2_truncate`

### Requirement: smb2_ftruncate synchronous file-handle truncation
系统 MUST 通过 `smb2_ftruncate_async` 发起文件句柄截断请求，阻塞等待完成，并返回回调状态或本地负错误码。

#### Scenario: ftruncate completes
- **GIVEN** 调用方提供文件句柄和目标长度
- **WHEN** 调用方调用 `smb2_ftruncate`
- **THEN** 函数返回 ftruncate 回调写入的状态并释放同步回调数据

Trace: `lib/sync.c:smb2_ftruncate`, `include/smb2/libsmb2.h:smb2_ftruncate`

### Requirement: smb2_readlink synchronous link read
系统 MUST 通过 `smb2_readlink_async` 发起 readlink 请求；成功回调时将返回文本按调用方缓冲区长度复制到 `buf` 并返回回调状态。

#### Scenario: readlink copies response text
- **GIVEN** 调用方提供路径、输出缓冲区和缓冲区长度
- **WHEN** 调用方调用 `smb2_readlink` 且异步 readlink 成功返回链接内容
- **THEN** 函数将回调内容复制到 `buf`，返回回调状态，并释放同步回调数据

Trace: `lib/sync.c:smb2_readlink`, `include/smb2/libsmb2.h:smb2_readlink`, `tests/prog_ls.c:main`

### Requirement: smb2_echo synchronous echo command
系统 MUST 在发送 echo 前检查 context socket 是否有效；未连接时设置错误消息并返回 `-ENOMEM`，已连接时通过 `smb2_echo_async` 发起请求并返回回调状态。

#### Scenario: echo rejects disconnected context
- **GIVEN** `smb2->fd` 不是有效 socket
- **WHEN** 调用方调用 `smb2_echo`
- **THEN** 函数设置 `Not Connected to Server` 错误并返回 `-ENOMEM`

Trace: `lib/sync.c:smb2_echo`, `include/smb2/libsmb2.h:smb2_echo`

#### Scenario: echo completes while connected
- **GIVEN** `smb2->fd` 是有效 socket 且异步 echo 启动成功
- **WHEN** 调用方调用 `smb2_echo`
- **THEN** 函数返回 echo 回调写入的状态并释放同步回调数据

Trace: `lib/sync.c:smb2_echo`, `include/smb2/libsmb2.h:smb2_echo`

### Requirement: smb2_notify_change synchronous one-off notification
系统 MUST 通过 `smb2_notify_change_async` 发起非循环 notify change 请求；成功时返回回调提供的 `struct smb2_file_notify_change_information *`，失败时返回 `NULL`。

#### Scenario: notify change returns response chain
- **GIVEN** 调用方提供路径、flags 和 filter，且异步 notify change 完成
- **WHEN** 调用方调用 `smb2_notify_change`
- **THEN** 函数返回回调提供的通知响应指针并释放同步回调数据

Trace: `lib/sync.c:smb2_notify_change`, `include/smb2/libsmb2.h:smb2_notify_change`

### Requirement: smb2_share_enum_sync synchronous SRVSVC share enumeration
系统 MUST 在发送 ShareEnum 前检查 context socket 是否有效；未连接时设置错误消息并返回 `NULL`，已连接时通过 `smb2_share_enum_async` 发起请求并返回回调响应指针。

#### Scenario: share enum rejects disconnected context
- **GIVEN** `smb2->fd` 不是有效 socket
- **WHEN** 调用方调用 `smb2_share_enum_sync`
- **THEN** 函数设置 `Not Connected to Server` 错误并返回 `NULL`

Trace: `lib/sync.c:smb2_share_enum_sync`, `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_sync`

#### Scenario: share enum returns response
- **GIVEN** context 已连接到可执行 SRVSVC ShareEnum 的 share，且异步请求完成
- **WHEN** 调用方调用 `smb2_share_enum_sync`
- **THEN** 函数返回 `struct srvsvc_NetrShareEnum_rep *` 响应指针并释放同步回调数据

Trace: `lib/sync.c:smb2_share_enum_sync`, `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_sync`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `wait_for_reply` 在等待失败路径中部分 wrapper 直接返回而不释放 `cb_data`，这些路径是否依赖取消回调释放仍待确认。 | smb2_fsync`, `smb2_pread`, `smb2_pwrite`, `smb2_read`, `smb2_write`, `smb2_unlink`, `smb2_rmdir`, `smb2_mkdir`, `smb2_fstat`, `smb2_stat`, `smb2_rename`, `smb2_statvfs`, `smb2_truncate`, `smb2_ftruncate`, `smb2_readlink`, `smb2_echo | 源码存在 `cb_data->status = SMB2_STATUS_CANCELLED; return rc;` 早退，释放责任需要结合异步回调/PDU 生命周期确认。 |
| Q-002 | `smb2_readlink` 使用 `strncpy(rl_data->buf, command_data, rl_data->len)` 时是否保证 NUL 终止仍待确认。 | smb2_readlink | 源码按长度复制，但 public header 只声明 `bufsiz`，未说明终止规则。 |
| Q-003 | `smb2_echo` 未连接时返回 `-ENOMEM` 是否为稳定 ABI 语义仍待确认。 | smb2_echo | 源码对未连接设置 `Not Connected to Server` 后返回 `-ENOMEM`，错误码与语义名称不一致。 |
| Q-004 | `smb2_share_enum_sync` 等待失败路径未设置 `SMB2_STATUS_CANCELLED` 且直接返回 `NULL`，是否存在回调数据生命周期差异仍待确认。 | smb2_share_enum_sync | 源码与多数同步 wrapper 的取消处理不一致。 |
