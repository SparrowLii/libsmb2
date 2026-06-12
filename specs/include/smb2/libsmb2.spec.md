# include/smb2/libsmb2.h Specification

## Source Context

- Source: `include/smb2/libsmb2.h`
- Related Headers: `include/smb2/smb2.h`, `include/smb2/libsmb2-dcerpc-srvsvc.h`
- Related Tests: `tests/prog_cat.c`, `tests/prog_cat_cancel.c`, `tests/prog_ls.c`, `tests/prog_mkdir.c`, `tests/prog_rmdir.c`, `tests/metastat-0202-censored.c`, `tests/ntlmssp_generate_blob.c`, `tests/smb2-dcerpc-coder-test.c`; example evidence in `examples/smb2-*.c` and utility evidence in `utils/smb2-cp.c`, `utils/smb2-ls.c`.
- Related Dependencies: GitNexus `context` resolved declaration symbols in this header and implementations in `lib/init.c`, `lib/libsmb2.c`, `lib/sync.c`, `lib/timestamps.c`, and `lib/unicode.c`; upstream impact found CRITICAL risk for implementation `smb2_init_context`, MEDIUM risk for `smb2_connect_share_async`, and LOW risk for `smb2_open_async` and `smb2_serve_port`.
- Build/Compile Context: C public API header guarded by `_LIBSMB2_H_`, exposes `extern "C"` linkage for C++ callers, conditionally defines `t_socket` as platform `SOCKET` on Windows/Xbox or `int` otherwise, and includes SRVSVC compatibility declarations through `<smb2/libsmb2-dcerpc-srvsvc.h>`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_context_lifecycle_api | function group | `struct smb2_context *smb2_init_context(void);` and context lifecycle declarations through `int smb2_context_active(struct smb2_context *smb2);` | Include | 公开 context 创建、关闭、销毁和活动列表观察入口，资源生命周期对所有调用方可见。 |
| smb2_event_integration_api | function group | `t_socket smb2_get_fd(struct smb2_context *smb2);` through `int smb2_service_fd(struct smb2_context *smb2, t_socket fd, int revents);` | Include | 公开事件循环集成入口，调用方依赖 fd、事件掩码和 service 返回语义。 |
| smb2_configuration_api | function group | `void smb2_set_timeout(struct smb2_context *smb2, int seconds);` through `int smb2_delegate_credentials(struct smb2_context *in, struct smb2_context *out);` | Include | 公开连接前后配置、认证、错误、opaque、client guid 和凭证委托语义。 |
| smb2_connection_api | function group | `int smb2_connect_async(struct smb2_context *smb2, const char *server, smb2_command_cb cb, void *cb_data);` through `int smb2_get_session_id(struct smb2_context *smb2, uint64_t *session_id);` | Include | 公开 TCP/share 连接、断开、tree/session id 和错误查询入口，GitNexus impact 显示连接路径有 MEDIUM 上游风险。 |
| smb2_url_error_api | function group | `const char *smb2_get_error(struct smb2_context *smb2);` through `void smb2_destroy_url(struct smb2_url *url);` | Include | 公开错误字符串、NTSTATUS 转换和 SMB2 URL 解析/释放资源契约。 |
| smb2_compound_pdu_api | function group | `void smb2_add_compound_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_pdu *next_pdu);` through `int smb2_pdu_is_compound(struct smb2_context *smb2);` | Include | 公开 compound PDU、PDU 状态和 message id 操作入口，影响 raw/高级请求链。 |
| smb2_directory_api | function group | `struct smb2_pdu *smb2_opendir_async_pdu(struct smb2_context *smb2, const char *path, smb2_command_cb cb, void *cb_data, void (*free_cb)(void *));` through `void smb2_seekdir(struct smb2_context *smb2, struct smb2dir *smb2dir, long loc);` | Include | 公开目录打开、枚举、定位和关闭接口，调用方可观察同步/异步资源所有权。 |
| smb2_file_io_api | function group | `struct smb2_pdu *smb2_open_async_pdu(struct smb2_context *smb2, const char *path, int flags, smb2_command_cb cb, void *cb_data, void (*free_cb)(void *));` through `int64_t smb2_lseek(struct smb2_context *smb2, struct smb2fh *fh, int64_t offset, int whence, uint64_t *current_offset);` | Include | 公开文件 open/close/fsync/read/write/lseek 入口，GitNexus impact 显示 `smb2_open_async` 影响测试和示例。 |
| smb2_filesystem_mutation_api | function group | `int smb2_unlink_async(struct smb2_context *smb2, const char *path, smb2_command_cb cb, void *cb_data);` through `int smb2_readlink(struct smb2_context *smb2, const char *path, char *buf, uint32_t bufsiz);` | Include | 公开 unlink/rmdir/mkdir/stat/statvfs/rename/truncate/readlink 等文件系统操作及状态回调语义。 |
| smb2_echo_notify_api | function group | `int smb2_echo_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data);` through `struct smb2_file_notify_change_information *smb2_notify_change(struct smb2_context *smb2, const char *path, uint16_t flags, uint32_t filter);` | Include | 公开 echo 和目录变更通知接口，涉及连接探测和通知结果释放责任。 |
| smb2_unicode_api | function group | `struct smb2_utf16 *smb2_utf8_to_utf16(const char *utf8);` and `const char *smb2_utf16_to_utf8(const uint16_t *str, size_t len);` | Include | 公开 UTF-8/UTF-16LE 转换工具，调用方承担 `free()` 释放责任。 |
| smb2_server_api | function group | `int smb2_bind_and_listen(const uint16_t port, const int max_connections, int *out_fd);` through `int smb2_serve_port(struct smb2_server *server, const int max_connections, smb2_client_connection cb, void *cb_data);` | Include | 公开服务端监听、accept、serve loop 和 handler 回调数据模型，GitNexus impact 显示 `smb2_serve_port` 被服务端示例直接调用。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| LIBSMB2_SHARE_ENUM_V2 | macro | include/smb2/libsmb2.h:26 | 公开 share enum ABI/feature 标志。 |
| smb2_iovec | struct | include/smb2/libsmb2.h:28 | 公开 buffer、长度和释放回调三元组，用于数据向量和回调数据。 |
| smb2_command_cb / smb2_error_cb / smb2_accepted_cb / smb2_client_connection / smb2_oplock_or_lease_break_cb | typedef | include/smb2/libsmb2.h:40 | 公开异步命令、错误、accept、新连接和 oplock/lease break 回调签名。 |
| SMB2_TYPE_FILE / SMB2_TYPE_DIRECTORY / SMB2_TYPE_LINK | macro | include/smb2/libsmb2.h:75 | 公开 stat type 常量。 |
| smb2_stat_64 / smb2_statvfs / smb2dirent | struct | include/smb2/libsmb2.h:78 | 公开文件属性、文件系统属性和目录项结果数据模型。 |
| t_socket | typedef | include/smb2/libsmb2.h:125 | Windows/Xbox 使用 `SOCKET`，其他平台默认使用 `int`，受 `T_SOCKET_DEFINED` 保护。 |
| SMB2_ADD_FD / SMB2_DEL_FD | macro | include/smb2/libsmb2.h:227 | 公开 fd 变化回调命令常量。 |
| smb2_negotiate_version / SMB2_VERSION_WILDCARD | enum/macro | include/smb2/libsmb2.h:300 | 公开 SMB dialect 选择常量和 wildcard 值。 |
| LIBSMB2_MAJOR_VERSION / LIBSMB2_MINOR_VERSION / LIBSMB2_PATCH_VERSION / smb2_libversion | macro/struct | include/smb2/libsmb2.h:319 | 公开链接库版本号和输出结构。 |
| smb2_sec | enum | include/smb2/libsmb2.h:364 | 公开认证方式枚举，覆盖 undefined、NTLMSSP 和 KRB5。 |
| smb2_url | struct | include/smb2/libsmb2.h:598 | 公开 SMB2 URL 解析结果字段，包括 domain、user、server、share、path。 |
| smb2_read_cb_data / smb2_write_cb_data | struct | include/smb2/libsmb2.h:854 | 公开异步 read/write 回调 command_data 内容。 |
| smb2_utf16 | struct | include/smb2/libsmb2.h:1283 | 公开 UTF-16LE 字符串长度和 flexible storage 模型。 |
| smb2_server_request_handlers / smb2_server | struct | include/smb2/libsmb2.h:1306 | 公开服务端请求 handler 表、server 配置和运行时状态字段。 |

## ADDED Requirements

### Requirement: smb2_context_lifecycle_api manage context lifetime
系统 MUST 提供创建、关闭、销毁和活动性查询 `struct smb2_context` 的公开生命周期入口，并保持销毁后已打开文件句柄、目录句柄和待处理 async command 的资源收尾语义。

#### Scenario: 创建默认 context
- **GIVEN** 调用方准备开始 SMB2 client 或 server 会话
- **WHEN** 调用方调用 `smb2_init_context()`
- **THEN** 成功时返回非空 context，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2.h:smb2_context_lifecycle_api`, `lib/init.c:smb2_init_context`, `tests/prog_ls.c`

#### Scenario: 销毁 context 取消未完成命令
- **GIVEN** context 仍持有打开的 `struct smb2fh`、`struct smb2dir` 或 pending async command
- **WHEN** 调用方调用 `smb2_destroy_context(smb2)`
- **THEN** 系统 MUST 释放关联资源，并以 shutdown/cancel 状态完成可回调的待处理命令

Trace: `include/smb2/libsmb2.h:smb2_context_lifecycle_api`, `lib/init.c:smb2_destroy_context`, `tests/prog_cat_cancel.c`

### Requirement: smb2_event_integration_api integrate external event loops
系统 MUST 公开当前 socket、待轮询事件和 service 入口，使调用方可以把 libsmb2 context 驱动接入 `select`、`poll`、`epoll` 或 callback-based event loop。

#### Scenario: 轮询并处理 context 事件
- **GIVEN** 调用方持有已初始化或正在连接的 context
- **WHEN** 调用方读取 `smb2_get_fd()`、`smb2_which_events()` 并在事件就绪后调用 `smb2_service()` 或 `smb2_service_fd()`
- **THEN** service 成功时 MUST 返回 `0`，不可恢复失败时 MUST 返回负值且调用方需要销毁 context

Trace: `include/smb2/libsmb2.h:smb2_event_integration_api`, `lib/libsmb2.c:smb2_serve_port`, `examples/smb2-ls-epoll.c`

### Requirement: smb2_configuration_api configure context behavior
系统 MUST 允许调用方配置 timeout、passthrough、dialect、security mode、seal/sign、authentication、身份字段、错误回调、oplock/lease break 回调、opaque 指针、client guid 和 credential delegation 等 context 属性。

#### Scenario: 设置并读取 context 属性
- **GIVEN** 调用方持有一个有效 context
- **WHEN** 调用方调用 setter 配置用户、domain、workstation、opaque、passthrough、version 或 security 选项
- **THEN** 对应 getter 或后续连接流程 MUST 使用该 context 中保存的最新配置值

Trace: `include/smb2/libsmb2.h:smb2_configuration_api`, `lib/init.c:smb2_set_error`, `lib/libsmb2.c:smb2_connect_share_async`

### Requirement: smb2_connection_api connect and manage SMB sessions
系统 MUST 提供异步和同步连接、share 连接、断开、tree id、PDU tree id、session id 和错误状态访问入口，并以返回码和 callback status 表达启动失败与协议完成结果。

#### Scenario: 异步连接 share
- **GIVEN** 调用方提供非空 context、server、share、回调和回调数据
- **WHEN** 调用方调用 `smb2_connect_share_async(smb2, server, share, user, cb, cb_data)`
- **THEN** 启动成功时 MUST 返回 `0` 并通过回调报告连接结果，启动失败时 MUST 返回负 errno 且不调用该命令回调

Trace: `include/smb2/libsmb2.h:smb2_connection_api`, `lib/libsmb2.c:smb2_connect_share_async`, `tests/prog_cat.c`

#### Scenario: 同步连接 share
- **GIVEN** 调用方提供 context、server、share 和可选 user
- **WHEN** 调用方调用 `smb2_connect_share(smb2, server, share, user)`
- **THEN** 成功连接时 MUST 返回 `0`，失败时 MUST 返回负 errno 或协议错误映射值

Trace: `include/smb2/libsmb2.h:smb2_connection_api`, `lib/sync.c:smb2_connect_share`, `tests/metastat-0202-censored.c`

### Requirement: smb2_url_error_api expose URL and error helpers
系统 MUST 公开最近错误字符串、NTSTATUS 到字符串/errno 的转换，以及 SMB2 URL 解析和释放接口。

#### Scenario: 解析并释放 SMB2 URL
- **GIVEN** 调用方提供形如 `smb2://[domain;][user@]server/share/path` 的 URL 字符串
- **WHEN** 调用方调用 `smb2_parse_url(smb2, url)` 后使用返回的 `struct smb2_url *`
- **THEN** 成功时 MUST 填充 domain、user、server、share 和 path 字段，调用方 MUST 使用 `smb2_destroy_url()` 释放返回结构

Trace: `include/smb2/libsmb2.h:smb2_url_error_api`, `lib/init.c:smb2_parse_url`, `lib/init.c:smb2_destroy_url`, `tests/prog_mkdir.c`

### Requirement: smb2_compound_pdu_api manage compound and public PDU state
系统 MUST 提供 compound PDU 链接、PDU 释放/排队、compound PDU 查找、状态/message id 设置和读取入口，以支持低级命令链和代理场景。

#### Scenario: 构造 compound request chain
- **GIVEN** 调用方持有一个 first PDU 和后续 PDU
- **WHEN** 调用方调用 `smb2_add_compound_pdu(smb2, pdu, next_pdu)` 并最终调用 `smb2_queue_pdu(smb2, pdu)`
- **THEN** 系统 MUST 将后续 PDU 链接为 compound 命令链并允许后续请求复用 compound file id 语义

Trace: `include/smb2/libsmb2.h:smb2_compound_pdu_api`, `include/smb2/libsmb2-raw.h:compound_file_id`, `examples/smb2-raw-stat-async.c`

### Requirement: smb2_directory_api provide directory traversal
系统 MUST 提供目录异步打开 PDU、同步/异步打开、关闭、读取、rewind、tell 和 seek 操作，并维持 `struct smb2dir` 与 `struct smb2dirent` 的调用方可观察遍历状态。

#### Scenario: 同步打开并读取目录
- **GIVEN** 调用方持有已连接 share 的 context 和目录路径
- **WHEN** 调用方调用 `smb2_opendir()`、重复调用 `smb2_readdir()` 并最终调用 `smb2_closedir()`
- **THEN** 成功打开时 MUST 返回目录句柄，读取时 MUST 返回目录项或结束标记，关闭时 MUST 释放目录句柄资源

Trace: `include/smb2/libsmb2.h:smb2_directory_api`, `lib/sync.c:smb2_opendir`, `tests/prog_ls.c`

### Requirement: smb2_file_io_api provide file handle IO
系统 MUST 提供文件打开、关闭、fsync、最大读写尺寸查询、pread/pwrite、read/write 和 lseek 的同步/异步入口，并通过返回值、callback status 和 command_data 传递文件句柄或传输字节数。

#### Scenario: 异步打开文件
- **GIVEN** 调用方提供 context、路径、flags、回调和回调数据
- **WHEN** 调用方调用 `smb2_open_async(smb2, path, flags, cb, cb_data)`
- **THEN** 启动成功时 MUST 返回 `0` 并在回调成功时传递 `struct smb2fh *`，启动失败时 MUST 返回负值且不安排成功回调

Trace: `include/smb2/libsmb2.h:smb2_file_io_api`, `lib/libsmb2.c:smb2_open_async`, `tests/prog_cat.c`

#### Scenario: 同步读写更新文件 offset
- **GIVEN** 调用方持有已打开文件句柄和缓冲区
- **WHEN** 调用方通过 `smb2_read()` 或 `smb2_write()` 传输数据
- **THEN** 成功时返回值 MUST 表示读写字节数，并按实现路径更新句柄当前 offset

Trace: `include/smb2/libsmb2.h:smb2_file_io_api`, `lib/libsmb2.c:smb2_read_async`, `lib/libsmb2.c:smb2_write_async`, `tests/prog_cat.c`

### Requirement: smb2_filesystem_mutation_api operate filesystem metadata
系统 MUST 提供 unlink、rmdir、mkdir、statvfs、fstat、stat、rename、truncate、ftruncate 和 readlink 的同步/异步入口，并保持成功为 `0` 或数据填充、失败为负 errno 的公开语义。

#### Scenario: 执行路径状态变更
- **GIVEN** 调用方持有已连接 share 的 context 和目标路径
- **WHEN** 调用方调用 mkdir、rmdir、unlink、rename、truncate 或 readlink 相关接口
- **THEN** 成功时 MUST 按接口填充输出或返回 `0`，失败时 MUST 返回负 errno 或在异步回调中报告错误状态

Trace: `include/smb2/libsmb2.h:smb2_filesystem_mutation_api`, `lib/sync.c`, `tests/prog_mkdir.c`

### Requirement: smb2_echo_notify_api support echo and change notification
系统 MUST 提供 echo 连接探测以及目录 change notify 的异步、filehandle async 和同步入口，并公开 notify result 的释放函数。

#### Scenario: 同步获取目录变更通知
- **GIVEN** 调用方持有 context、目录路径、flags 和 filter
- **WHEN** 调用方调用 `smb2_notify_change(smb2, path, flags, filter)`
- **THEN** 成功时 MUST 返回 `struct smb2_file_notify_change_information *` 链，调用方 MUST 使用 `free_smb2_file_notify_change_information()` 释放结果

Trace: `include/smb2/libsmb2.h:smb2_echo_notify_api`, `lib/libsmb2.c`, `examples/smb2-notify.c`

### Requirement: smb2_unicode_api convert UTF encodings
系统 MUST 公开 SMB little-endian UTF-16 与 UTF-8 转换工具，并要求调用方用 `free()` 释放成功返回的转换字符串。

#### Scenario: UTF-8 转 UTF-16LE
- **GIVEN** 调用方提供有效 UTF-8 字符串
- **WHEN** 调用方调用 `smb2_utf8_to_utf16(utf8)`
- **THEN** 成功时 MUST 返回包含 UTF-16 code unit 长度和 little-endian code units 的 `struct smb2_utf16 *`，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2.h:smb2_unicode_api`, `lib/unicode.c:smb2_utf8_to_utf16`

#### Scenario: UTF-16LE 转 UTF-8
- **GIVEN** 调用方提供 UTF-16LE code unit 指针和长度
- **WHEN** 调用方调用 `smb2_utf16_to_utf8(str, len)`
- **THEN** 成功时 MUST 返回可由 `free()` 释放的 UTF-8 字符串

Trace: `include/smb2/libsmb2.h:smb2_unicode_api`, `lib/unicode.c:smb2_utf16_to_utf8`

### Requirement: smb2_server_api serve SMB2 connections
系统 MUST 公开服务端绑定监听、异步 accept、异步 serve-port accept wrapper 和同步 serve loop，并通过 `smb2_server_request_handlers` 将协议请求分派给调用方提供的 handler 表。

#### Scenario: 同步服务端主循环
- **GIVEN** 调用方提供初始化的 `struct smb2_server *server`、最大连接数、新连接回调和回调数据
- **WHEN** 调用方调用 `smb2_serve_port(server, max_connections, cb, cb_data)`
- **THEN** 系统 MUST 绑定监听 server port、accept 新连接、为每个 client context 分派可读/可写事件，并在错误导致循环退出时返回负 errno

Trace: `include/smb2/libsmb2.h:smb2_server_api`, `lib/libsmb2.c:smb2_serve_port`, `examples/smb2-server-sync.c`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `include/smb2/libsmb2.h` 暴露大量公开声明，本 spec 将相关声明按 API family 聚合为 interface group；是否需要后续拆分为逐函数独立 Requirement 需要确认。 | file-level | worker 输入只允许处理单个 spec 文件，逐函数完整展开会产生超大规格且与已有 implementation spec 重叠。 |
| Q-002 | `smb2_open_async_pdu` 的 `free_cb` 参数在当前实现中传入 helper 但未独立使用，其公开所有权语义是否只依赖 `caller_frees_pdu` 需要确认。 | smb2_file_io_api | 头文件声明包含 `free_cb`，实现主要通过 PDU/同步 wrapper 管理 cb_data 释放。 |
| Q-003 | `smb2_readlink` 同步接口的返回值与 `buf` 填充边界在头文件注释中未说明，具体成功返回长度或状态码语义需要实现 spec 继续确认。 | smb2_filesystem_mutation_api | 头文件只给出签名，未描述返回值和截断语义。 |
