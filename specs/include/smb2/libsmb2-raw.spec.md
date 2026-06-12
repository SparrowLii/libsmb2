# include/smb2/libsmb2-raw.h Specification

## Source Context

- Source: `include/smb2/libsmb2-raw.h`
- Related Headers: `include/smb2/libsmb2.h`, `include/smb2/smb2.h`, `include/libsmb2-private.h`
- Related Tests: `tests/metastat-0202-censored.c` through `smb2_cmd_query_info_async`; example evidence in `examples/smb2-CMD-FIND.c`, `examples/smb2-raw-stat-async.c`, `examples/smb2-raw-fsstat-async.c`, `examples/smb2-raw-getsd-async.c`, `examples/smb2-share-enum.c`, and `examples/smb2-share-enum-sync.c`.
- Related Dependencies: GitNexus `context` found raw command declarations in this header and implementations in `lib/smb2-cmd-*.c`; `smb2_free_data` implementation is in `lib/alloc.c`; `compound_file_id` is defined in `lib/libsmb2.c`; raw command builders call `smb2_allocate_pdu`, per-command encoders, `smb2_pad_to_64bit`, and `smb2_free_pdu` on failure. GitNexus impact reported CRITICAL upstream risk for `smb2_free_data` and HIGH upstream risk for `smb2_cmd_query_info_async`.
- Build/Compile Context: C public raw SMB2 header guarded by `_LIBSMB2_RAW_H_`, exposes `extern "C"` linkage for C++ callers, and depends on SMB2 request/reply structures and `smb2_command_cb` declarations from sibling public headers.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| compound_file_id | variable | extern const smb2_file_id compound_file_id; | Include | 公开 compound command 使用的固定 file id 常量，调用方和内部复合请求可观察其字节语义。 |
| smb2_free_data | function | void smb2_free_data(struct smb2_context *smb2, void *ptr); | Include | 公开释放 query/DCERPC 返回数据的资源管理接口，GitNexus upstream impact 为 CRITICAL。 |
| smb2_cmd_negotiate_async | function | struct smb2_pdu *smb2_cmd_negotiate_async(struct smb2_context *smb2, struct smb2_negotiate_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW negotiate 请求构造入口，回调和失败返回语义对调用方可见。 |
| smb2_cmd_negotiate_reply_async | function | struct smb2_pdu *smb2_cmd_negotiate_reply_async(struct smb2_context *smb2, struct smb2_negotiate_reply *rep, smb2_command_cb cb, void *cb_data); | Include | RAW negotiate reply 构造入口，服务端响应路径可观察。 |
| smb2_cmd_session_setup_async | function | struct smb2_pdu *smb2_cmd_session_setup_async(struct smb2_context *smb2, struct smb2_session_setup_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW session setup 请求构造入口，认证流程依赖其 PDU 和回调语义。 |
| smb2_cmd_session_setup_reply_async | function | struct smb2_pdu *smb2_cmd_session_setup_reply_async(struct smb2_context *smb2, struct smb2_session_setup_reply *rep, smb2_command_cb cb, void *cb_data); | Include | RAW session setup reply 构造入口，服务端响应路径可观察。 |
| smb2_cmd_tree_connect_async | function | struct smb2_pdu *smb2_cmd_tree_connect_async(struct smb2_context *smb2, struct smb2_tree_connect_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW tree connect 请求构造入口，share 连接流程依赖其回调状态。 |
| smb2_cmd_tree_connect_reply_async | function | struct smb2_pdu *smb2_cmd_tree_connect_reply_async(struct smb2_context *smb2, struct smb2_tree_connect_reply *rep, uint32_t tree_id, smb2_command_cb cb, void *cb_data); | Include | RAW tree connect reply 构造入口，额外暴露 `tree_id` 响应语义。 |
| smb2_cmd_tree_disconnect_async | function | struct smb2_pdu *smb2_cmd_tree_disconnect_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data); | Include | RAW tree disconnect 请求构造入口，无请求结构但仍有 PDU 失败和回调语义。 |
| smb2_cmd_tree_disconnect_reply_async | function | struct smb2_pdu *smb2_cmd_tree_disconnect_reply_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data); | Include | RAW tree disconnect reply 构造入口，服务端响应路径可观察。 |
| smb2_cmd_create_async | function | struct smb2_pdu *smb2_cmd_create_async(struct smb2_context *smb2, struct smb2_create_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW create 请求构造入口，被高级 open/stat/dcerpc/example 路径调用。 |
| smb2_cmd_create_reply_async | function | struct smb2_pdu *smb2_cmd_create_reply_async(struct smb2_context *smb2, struct smb2_create_reply *rep, smb2_command_cb cb, void *cb_data); | Include | RAW create reply 构造入口，服务端响应路径可观察。 |
| smb2_cmd_close_async | function | struct smb2_pdu *smb2_cmd_close_async(struct smb2_context *smb2, struct smb2_close_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW close 请求构造入口，文件句柄生命周期依赖其回调状态。 |
| smb2_cmd_close_reply_async | function | struct smb2_pdu *smb2_cmd_close_reply_async(struct smb2_context *smb2, struct smb2_close_reply *rep, smb2_command_cb cb, void *cb_data); | Include | RAW close reply 构造入口，服务端响应路径可观察。 |
| smb2_cmd_read_async | function | struct smb2_pdu *smb2_cmd_read_async(struct smb2_context *smb2, struct smb2_read_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW read 请求构造入口，涉及调用方提供读缓冲区和 multi-credit 行为。 |
| smb2_cmd_read_reply_async | function | struct smb2_pdu *smb2_cmd_read_reply_async(struct smb2_context *smb2, struct smb2_read_reply *rep, smb2_command_cb cb, void *cb_data); | Include | RAW read reply 构造入口，服务端响应数据缓冲区可观察。 |
| smb2_cmd_write_async | function | struct smb2_pdu *smb2_cmd_write_async(struct smb2_context *smb2, struct smb2_write_request *req, int pass_buf_ownership, smb2_command_cb cb, void *cb_data); | Include | RAW write 请求构造入口，涉及写入缓冲区所有权和 multi-credit 行为。 |
| smb2_cmd_write_reply_async | function | struct smb2_pdu *smb2_cmd_write_reply_async(struct smb2_context *smb2, struct smb2_write_reply *rep, smb2_command_cb cb, void *cb_data); | Include | RAW write reply 构造入口，服务端响应路径可观察。 |
| smb2_cmd_query_directory_async | function | struct smb2_pdu *smb2_cmd_query_directory_async(struct smb2_context *smb2, struct smb2_query_directory_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW query directory 请求构造入口，目录枚举和示例路径依赖。 |
| smb2_cmd_query_directory_reply_async | function | struct smb2_pdu *smb2_cmd_query_directory_reply_async(struct smb2_context *smb2, struct smb2_query_directory_request *req, struct smb2_query_directory_reply *rep, smb2_command_cb cb, void *cb_data); | Include | RAW query directory reply 构造入口，服务端目录响应路径可观察。 |
| smb2_cmd_change_notify_async | function | struct smb2_pdu *smb2_cmd_change_notify_async(struct smb2_context *smb2, struct smb2_change_notify_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW change notify 请求构造入口，异步通知流程依赖。 |
| smb2_cmd_change_notify_reply_async | function | struct smb2_pdu *smb2_cmd_change_notify_reply_async(struct smb2_context *smb2, struct smb2_change_notify_reply *rep, smb2_command_cb cb, void *cb_data); | Include | RAW change notify reply 构造入口，通知响应数据可观察。 |
| smb2_cmd_query_info_async | function | struct smb2_pdu *smb2_cmd_query_info_async(struct smb2_context *smb2, struct smb2_query_info_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW query info 请求构造入口，GitNexus upstream impact 为 HIGH，stat/getinfo 路径依赖。 |
| smb2_cmd_query_info_reply_async | function | struct smb2_pdu *smb2_cmd_query_info_reply_async(struct smb2_context *smb2, struct smb2_query_info_request *req, struct smb2_query_info_reply *rep, smb2_command_cb cb, void *cb_data); | Include | RAW query info reply 构造入口，输出缓冲区释放责任对调用方可见。 |
| smb2_cmd_set_info_async | function | struct smb2_pdu *smb2_cmd_set_info_async(struct smb2_context *smb2, struct smb2_set_info_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW set info 请求构造入口，truncate/rename 等状态变更路径依赖。 |
| smb2_cmd_set_info_reply_async | function | struct smb2_pdu *smb2_cmd_set_info_reply_async(struct smb2_context *smb2, struct smb2_set_info_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW set info reply 构造入口，服务端响应路径可观察。 |
| smb2_cmd_ioctl_async | function | struct smb2_pdu *smb2_cmd_ioctl_async(struct smb2_context *smb2, struct smb2_ioctl_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW ioctl 请求构造入口，reparse/readlink 和 FSCTL 路径依赖。 |
| smb2_cmd_ioctl_reply_async | function | struct smb2_pdu *smb2_cmd_ioctl_reply_async(struct smb2_context *smb2, struct smb2_ioctl_reply *rep, smb2_command_cb cb, void *cb_data); | Include | RAW ioctl reply 构造入口，输出缓冲区释放责任对调用方可见。 |
| smb2_cmd_echo_async | function | struct smb2_pdu *smb2_cmd_echo_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data); | Include | RAW echo 请求构造入口，用于连接探测。 |
| smb2_cmd_echo_reply_async | function | struct smb2_pdu *smb2_cmd_echo_reply_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data); | Include | RAW echo reply 构造入口，服务端响应路径可观察。 |
| smb2_cmd_lock_async | function | struct smb2_pdu *smb2_cmd_lock_async(struct smb2_context *smb2, struct smb2_lock_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW lock 请求构造入口，文件锁状态变更依赖。 |
| smb2_cmd_lock_reply_async | function | struct smb2_pdu *smb2_cmd_lock_reply_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data); | Include | RAW lock reply 构造入口，服务端响应路径可观察。 |
| smb2_cmd_logoff_async | function | struct smb2_pdu *smb2_cmd_logoff_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data); | Include | RAW logoff 请求构造入口，会话生命周期依赖。 |
| smb2_cmd_logoff_reply_async | function | struct smb2_pdu *smb2_cmd_logoff_reply_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data); | Include | RAW logoff reply 构造入口，服务端响应路径可观察。 |
| smb2_cmd_flush_async | function | struct smb2_pdu *smb2_cmd_flush_async(struct smb2_context *smb2, struct smb2_flush_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW flush 请求构造入口，fsync 路径依赖。 |
| smb2_cmd_flush_reply_async | function | struct smb2_pdu *smb2_cmd_flush_reply_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data); | Include | RAW flush reply 构造入口，服务端响应路径可观察。 |
| smb2_cmd_oplock_break_async | function | struct smb2_pdu *smb2_cmd_oplock_break_async(struct smb2_context *smb2, struct smb2_oplock_break_acknowledgement *req, smb2_command_cb cb, void *cb_data); | Include | RAW oplock break acknowledgement 构造入口，锁状态协议依赖。 |
| smb2_cmd_oplock_break_reply_async | function | struct smb2_pdu *smb2_cmd_oplock_break_reply_async(struct smb2_context *smb2, struct smb2_oplock_break_reply *rep, smb2_command_cb cb, void *cb_data); | Include | RAW oplock break reply 构造入口，服务端响应路径可观察。 |
| smb2_cmd_oplock_break_notification_async | function | struct smb2_pdu *smb2_cmd_oplock_break_notification_async(struct smb2_context *smb2, struct smb2_oplock_break_notification *rep, smb2_command_cb cb, void *cb_data); | Include | RAW oplock break notification 构造入口，服务端通知路径可观察。 |
| smb2_cmd_lease_break_async | function | struct smb2_pdu *smb2_cmd_lease_break_async(struct smb2_context *smb2, struct smb2_lease_break_acknowledgement *req, smb2_command_cb cb, void *cb_data); | Include | RAW lease break acknowledgement 构造入口，lease 状态协议依赖。 |
| smb2_cmd_lease_break_reply_async | function | struct smb2_pdu *smb2_cmd_lease_break_reply_async(struct smb2_context *smb2, struct smb2_lease_break_reply *rep, smb2_command_cb cb, void *cb_data); | Include | RAW lease break reply 构造入口，服务端响应路径可观察。 |
| smb2_cmd_lease_break_notification_async | function | struct smb2_pdu *smb2_cmd_lease_break_notification_async(struct smb2_context *smb2, struct smb2_lease_break_notification *req, smb2_command_cb cb, void *cb_data); | Include | RAW lease break notification 构造入口，服务端通知路径可观察。 |
| smb2_cmd_error_reply_async | function | struct smb2_pdu *smb2_cmd_error_reply_async(struct smb2_context *smb2, struct smb2_error_reply *rep, uint8_t causing_command, int status, smb2_command_cb cb, void *cb_data); | Include | RAW error reply 构造入口，暴露 causing command 和 NT status 响应语义。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| 无 | none | none | 本头文件不定义新的公开类型或宏；`compound_file_id` 作为公开变量在 Interface Summary 中记录，request/reply 数据模型归属到 `include/smb2/smb2.h` spec。 |

## ADDED Requirements

### Requirement: compound_file_id expose compound sentinel
系统 MUST 公开一个稳定的 `compound_file_id` 常量供 compound SMB2 命令在后续请求中复用。

#### Scenario: 复合请求复用特殊 file id
- **GIVEN** 调用方或库内部构造 compound create/query/close 请求链
- **WHEN** 后续请求需要引用 compound 链中前序创建的文件句柄
- **THEN** 请求构造代码 MUST 使用 `compound_file_id` 作为特殊 `smb2_file_id` 哨兵

Trace: `include/smb2/libsmb2-raw.h:compound_file_id`, `lib/libsmb2.c:compound_file_id`

### Requirement: smb2_free_data release returned data tree
系统 MUST 接受由 libsmb2 数据分配器返回的根指针，并释放该根对象关联的子分配链和根分配。

#### Scenario: 释放 query 返回数据
- **GIVEN** 调用方持有 query、ioctl 或 DCERPC 回调返回的数据根指针
- **WHEN** 调用方调用 `smb2_free_data(smb2, ptr)`
- **THEN** 函数 MUST 释放该根指针关联的所有 tracked 子分配后释放根分配

Trace: `include/smb2/libsmb2-raw.h:smb2_free_data`, `lib/alloc.c:smb2_free_data`, `examples/smb2-raw-stat-async.c`

#### Scenario: 空指针释放为空操作
- **GIVEN** 调用方没有可释放的数据根指针
- **WHEN** 调用方调用 `smb2_free_data(smb2, NULL)`
- **THEN** 函数 MUST 直接返回且不访问分配头

Trace: `include/smb2/libsmb2-raw.h:smb2_free_data`, `lib/alloc.c:smb2_free_data`

### Requirement: smb2_cmd_negotiate_async build negotiate request PDU
系统 MUST 构造 SMB2 NEGOTIATE 请求 PDU，成功时返回可提交的 `struct smb2_pdu *`，构造或编码失败时返回 `NULL`。

#### Scenario: 构造 negotiate 请求
- **GIVEN** 调用方提供 `struct smb2_negotiate_request *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_negotiate_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 NEGOTIATE command，并保存回调和回调数据

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_negotiate_async`, `lib/smb2-cmd-negotiate.c:smb2_cmd_negotiate_async`

### Requirement: smb2_cmd_negotiate_reply_async build negotiate reply PDU
系统 MUST 构造 SMB2 NEGOTIATE reply PDU，并在 SMB 3.1.1 相关 dialect 条件下包含可编码的 negotiate context 信息。

#### Scenario: 构造 negotiate 响应
- **GIVEN** 调用方提供 `struct smb2_negotiate_reply *rep`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_negotiate_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 NEGOTIATE command，并编码响应固定字段和安全缓冲区信息

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_negotiate_reply_async`, `lib/smb2-cmd-negotiate.c:smb2_cmd_negotiate_reply_async`

### Requirement: smb2_cmd_session_setup_async build session setup request PDU
系统 MUST 构造 SMB2 SESSION_SETUP 请求 PDU，成功时通过后续回调报告 session setup 结果。

#### Scenario: 构造 session setup 请求
- **GIVEN** 调用方提供 `struct smb2_session_setup_request *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_session_setup_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 SESSION_SETUP command，失败时 MUST 返回 `NULL` 且不安排回调

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_session_setup_async`, `lib/smb2-cmd-session-setup.c:smb2_cmd_session_setup_async`

### Requirement: smb2_cmd_session_setup_reply_async build session setup reply PDU
系统 MUST 构造 SMB2 SESSION_SETUP reply PDU，用于服务端或模拟响应路径。

#### Scenario: 构造 session setup 响应
- **GIVEN** 调用方提供 `struct smb2_session_setup_reply *rep`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_session_setup_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 SESSION_SETUP command 并编码响应安全缓冲区字段

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_session_setup_reply_async`, `lib/smb2-cmd-session-setup.c:smb2_cmd_session_setup_reply_async`

### Requirement: smb2_cmd_tree_connect_async build tree connect request PDU
系统 MUST 构造 SMB2 TREE_CONNECT 请求 PDU，成功时通过后续回调报告 tree connect 结果。

#### Scenario: 构造 tree connect 请求
- **GIVEN** 调用方提供 `struct smb2_tree_connect_request *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_tree_connect_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 TREE_CONNECT command，失败时 MUST 返回 `NULL` 且不安排回调

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_tree_connect_async`, `lib/smb2-cmd-tree-connect.c:smb2_cmd_tree_connect_async`

### Requirement: smb2_cmd_tree_connect_reply_async build tree connect reply PDU
系统 MUST 构造 SMB2 TREE_CONNECT reply PDU，并将调用方提供的 tree id 关联到响应头语义。

#### Scenario: 构造 tree connect 响应
- **GIVEN** 调用方提供 `struct smb2_tree_connect_reply *rep` 和 `tree_id`
- **WHEN** 调用 `smb2_cmd_tree_connect_reply_async(smb2, rep, tree_id, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 TREE_CONNECT command，并携带可被响应处理路径识别的 tree id

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_tree_connect_reply_async`, `lib/smb2-cmd-tree-connect.c:smb2_cmd_tree_connect_reply_async`

### Requirement: smb2_cmd_tree_disconnect_async build tree disconnect request PDU
系统 MUST 构造 SMB2 TREE_DISCONNECT 请求 PDU，且该接口不要求调用方提供请求结构。

#### Scenario: 构造 tree disconnect 请求
- **GIVEN** 调用方提供回调和回调数据
- **WHEN** 调用 `smb2_cmd_tree_disconnect_async(smb2, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 TREE_DISCONNECT command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_tree_disconnect_async`, `lib/smb2-cmd-tree-disconnect.c:smb2_cmd_tree_disconnect_async`

### Requirement: smb2_cmd_tree_disconnect_reply_async build tree disconnect reply PDU
系统 MUST 构造 SMB2 TREE_DISCONNECT reply PDU，且响应 command_data 语义为空。

#### Scenario: 构造 tree disconnect 响应
- **GIVEN** 调用方提供回调和回调数据
- **WHEN** 调用 `smb2_cmd_tree_disconnect_reply_async(smb2, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 TREE_DISCONNECT command，并编码固定响应字段

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_tree_disconnect_reply_async`, `lib/smb2-cmd-tree-disconnect.c:smb2_cmd_tree_disconnect_reply_async`

### Requirement: smb2_cmd_create_async build create request PDU
系统 MUST 构造 SMB2 CREATE 请求 PDU，成功时返回可提交的 PDU，编码或 padding 失败时释放 PDU 并返回 `NULL`。

#### Scenario: 构造 create 请求
- **GIVEN** 调用方提供 `struct smb2_create_request *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_create_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 CREATE command，并包含编码后的 create request

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_create_async`, `lib/smb2-cmd-create.c:smb2_cmd_create_async`, `examples/smb2-CMD-FIND.c`

### Requirement: smb2_cmd_create_reply_async build create reply PDU
系统 MUST 构造 SMB2 CREATE reply PDU，并编码 create reply 中的 file id、时间戳和 create context 字段。

#### Scenario: 构造 create 响应
- **GIVEN** 调用方提供 `struct smb2_create_reply *rep`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_create_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 CREATE command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_create_reply_async`, `lib/smb2-cmd-create.c:smb2_cmd_create_reply_async`

### Requirement: smb2_cmd_close_async build close request PDU
系统 MUST 构造 SMB2 CLOSE 请求 PDU，用于结束文件句柄生命周期。

#### Scenario: 构造 close 请求
- **GIVEN** 调用方提供 `struct smb2_close_request *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_close_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 CLOSE command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_close_async`, `lib/smb2-cmd-close.c:smb2_cmd_close_async`

### Requirement: smb2_cmd_close_reply_async build close reply PDU
系统 MUST 构造 SMB2 CLOSE reply PDU，并编码 close reply 的属性和时间字段。

#### Scenario: 构造 close 响应
- **GIVEN** 调用方提供 `struct smb2_close_reply *rep`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_close_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 CLOSE command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_close_reply_async`, `lib/smb2-cmd-close.c:smb2_cmd_close_reply_async`

### Requirement: smb2_cmd_read_async build read request PDU
系统 MUST 构造 SMB2 READ 请求 PDU；当请求长度非零时，调用方 SHALL 提供接收缓冲区。

#### Scenario: 构造 read 请求并绑定接收缓冲区
- **GIVEN** `req->length` 非零且 `req->buf` 指向调用方提供的接收缓冲区
- **WHEN** 调用 `smb2_cmd_read_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 READ command，并将 `req->buf` 添加为输入 iovector 且不接管释放责任

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_read_async`, `lib/smb2-cmd-read.c:smb2_cmd_read_async`

#### Scenario: 拒绝缺失 read 缓冲区
- **GIVEN** `req->length` 非零且 `req->buf` 为 `NULL`
- **WHEN** 调用 `smb2_cmd_read_async(smb2, req, cb, cb_data)`
- **THEN** 函数 MUST 设置错误、释放已分配 PDU 并返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_read_async`, `lib/smb2-cmd-read.c:smb2_cmd_read_async`

### Requirement: smb2_cmd_read_reply_async build read reply PDU
系统 MUST 构造 SMB2 READ reply PDU，并在响应包含数据时追加数据 iovector。

#### Scenario: 构造 read 响应数据
- **GIVEN** `rep->data_length` 大于零且 `rep->data` 非空
- **WHEN** 调用 `smb2_cmd_read_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 READ command，并将响应数据附加到输出 iovector

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_read_reply_async`, `lib/smb2-cmd-read.c:smb2_cmd_read_reply_async`

### Requirement: smb2_cmd_write_async build write request PDU
系统 MUST 构造 SMB2 WRITE 请求 PDU，并根据 `pass_buf_ownership` 决定 PDU 释放时是否释放写入缓冲区。

#### Scenario: 构造 write 请求并保留缓冲区所有权
- **GIVEN** 调用方提供 `struct smb2_write_request *req` 且 `pass_buf_ownership` 为 `0`
- **WHEN** 调用 `smb2_cmd_write_async(smb2, req, 0, cb, cb_data)`
- **THEN** 返回的 PDU MUST 将 `req->buf` 添加到输出 iovector，且 PDU 释放时 MUST NOT 释放该缓冲区

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_write_async`, `lib/smb2-cmd-write.c:smb2_cmd_write_async`

#### Scenario: 构造 write 请求并移交缓冲区所有权
- **GIVEN** 调用方提供 `struct smb2_write_request *req` 且 `pass_buf_ownership` 非零
- **WHEN** 调用 `smb2_cmd_write_async(smb2, req, pass_buf_ownership, cb, cb_data)`
- **THEN** 返回的 PDU MUST 将 `free` 注册为写入缓冲区释放函数

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_write_async`, `lib/smb2-cmd-write.c:smb2_cmd_write_async`

### Requirement: smb2_cmd_write_reply_async build write reply PDU
系统 MUST 构造 SMB2 WRITE reply PDU，并编码写入字节数和 remaining 字段。

#### Scenario: 构造 write 响应
- **GIVEN** 调用方提供 `struct smb2_write_reply *rep`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_write_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 WRITE command，并编码 `rep->count` 与 `rep->remaining`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_write_reply_async`, `lib/smb2-cmd-write.c:smb2_cmd_write_reply_async`

### Requirement: smb2_cmd_query_directory_async build query directory request PDU
系统 MUST 构造 SMB2 QUERY_DIRECTORY 请求 PDU，用于目录枚举和 raw find 示例路径。

#### Scenario: 构造 query directory 请求
- **GIVEN** 调用方提供 `struct smb2_query_directory_request *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_query_directory_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 QUERY_DIRECTORY command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_query_directory_async`, `lib/smb2-cmd-query-directory.c:smb2_cmd_query_directory_async`, `examples/smb2-CMD-FIND.c`

### Requirement: smb2_cmd_query_directory_reply_async build query directory reply PDU
系统 MUST 构造 SMB2 QUERY_DIRECTORY reply PDU，并按请求类型和响应数据编码目录枚举输出。

#### Scenario: 构造 query directory 响应
- **GIVEN** 调用方提供 request context 和 `struct smb2_query_directory_reply *rep`
- **WHEN** 调用 `smb2_cmd_query_directory_reply_async(smb2, req, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 QUERY_DIRECTORY command，并编码可被客户端解析的目录响应缓冲区

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_query_directory_reply_async`, `lib/smb2-cmd-query-directory.c:smb2_cmd_query_directory_reply_async`

### Requirement: smb2_cmd_change_notify_async build change notify request PDU
系统 MUST 构造 SMB2 CHANGE_NOTIFY 请求 PDU，用于异步目录变更通知。

#### Scenario: 构造 change notify 请求
- **GIVEN** 调用方提供 `struct smb2_change_notify_request *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_change_notify_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 CHANGE_NOTIFY command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_change_notify_async`, `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_async`

### Requirement: smb2_cmd_change_notify_reply_async build change notify reply PDU
系统 MUST 构造 SMB2 CHANGE_NOTIFY reply PDU，并编码通知响应输出缓冲区。

#### Scenario: 构造 change notify 响应
- **GIVEN** 调用方提供 `struct smb2_change_notify_reply *rep`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_change_notify_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 CHANGE_NOTIFY command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_change_notify_reply_async`, `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_reply_async`

### Requirement: smb2_cmd_query_info_async build query info request PDU
系统 MUST 构造 SMB2 QUERY_INFO 请求 PDU，成功时返回可提交的 PDU，编码或 padding 失败时释放 PDU 并返回 `NULL`。

#### Scenario: 构造 query info 请求
- **GIVEN** 调用方提供 `struct smb2_query_info_request *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_query_info_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 QUERY_INFO command，并包含编码后的 query info request

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_query_info_async`, `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_async`, `tests/metastat-0202-censored.c`

### Requirement: smb2_cmd_query_info_reply_async build query info reply PDU
系统 MUST 构造 SMB2 QUERY_INFO reply PDU，并向调用方暴露 output buffer 由 `smb2_free_data` 释放的资源契约。

#### Scenario: 构造 query info 响应
- **GIVEN** 调用方提供 request context 和 `struct smb2_query_info_reply *rep`
- **WHEN** 调用 `smb2_cmd_query_info_reply_async(smb2, req, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 QUERY_INFO command，并编码 `rep->output_buffer` 和输出长度字段

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_query_info_reply_async`, `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_reply_async`

### Requirement: smb2_cmd_set_info_async build set info request PDU
系统 MUST 构造 SMB2 SET_INFO 请求 PDU，用于 rename、truncate 等元数据变更流程。

#### Scenario: 构造 set info 请求
- **GIVEN** 调用方提供 `struct smb2_set_info_request *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_set_info_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 SET_INFO command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_set_info_async`, `lib/smb2-cmd-set-info.c:smb2_cmd_set_info_async`

### Requirement: smb2_cmd_set_info_reply_async build set info reply PDU
系统 MUST 构造 SMB2 SET_INFO reply PDU，且响应 command_data 语义为空。

#### Scenario: 构造 set info 响应
- **GIVEN** 调用方提供 request context、回调和回调数据
- **WHEN** 调用 `smb2_cmd_set_info_reply_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 SET_INFO command，并编码固定响应字段

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_set_info_reply_async`, `lib/smb2-cmd-set-info.c:smb2_cmd_set_info_reply_async`

### Requirement: smb2_cmd_ioctl_async build ioctl request PDU
系统 MUST 构造 SMB2 IOCTL 请求 PDU，用于 FSCTL 和 reparse/readlink 等控制操作。

#### Scenario: 构造 ioctl 请求
- **GIVEN** 调用方提供 `struct smb2_ioctl_request *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_ioctl_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 IOCTL command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_ioctl_async`, `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_async`

### Requirement: smb2_cmd_ioctl_reply_async build ioctl reply PDU
系统 MUST 构造 SMB2 IOCTL reply PDU，并向调用方暴露 output 数据由 `smb2_free_data` 释放的资源契约。

#### Scenario: 构造 ioctl 响应
- **GIVEN** 调用方提供 `struct smb2_ioctl_reply *rep`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_ioctl_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 IOCTL command，并编码 output buffer 和输出长度字段

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_ioctl_reply_async`, `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_reply_async`

### Requirement: smb2_cmd_echo_async build echo request PDU
系统 MUST 构造 SMB2 ECHO 请求 PDU，用于连接可用性探测。

#### Scenario: 构造 echo 请求
- **GIVEN** 调用方提供回调和回调数据
- **WHEN** 调用 `smb2_cmd_echo_async(smb2, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 ECHO command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_echo_async`, `lib/smb2-cmd-echo.c:smb2_cmd_echo_async`

### Requirement: smb2_cmd_echo_reply_async build echo reply PDU
系统 MUST 构造 SMB2 ECHO reply PDU，且响应 command_data 语义为空。

#### Scenario: 构造 echo 响应
- **GIVEN** 调用方提供回调和回调数据
- **WHEN** 调用 `smb2_cmd_echo_reply_async(smb2, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 ECHO command，并编码固定响应字段

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_echo_reply_async`, `lib/smb2-cmd-echo.c:smb2_cmd_echo_reply_async`

### Requirement: smb2_cmd_lock_async build lock request PDU
系统 MUST 构造 SMB2 LOCK 请求 PDU，用于提交一个或多个 lock element。

#### Scenario: 构造 lock 请求
- **GIVEN** 调用方提供 `struct smb2_lock_request *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_lock_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 LOCK command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_lock_async`, `lib/smb2-cmd-lock.c:smb2_cmd_lock_async`

### Requirement: smb2_cmd_lock_reply_async build lock reply PDU
系统 MUST 构造 SMB2 LOCK reply PDU，且响应 command_data 语义为空。

#### Scenario: 构造 lock 响应
- **GIVEN** 调用方提供回调和回调数据
- **WHEN** 调用 `smb2_cmd_lock_reply_async(smb2, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 LOCK command，并编码固定响应字段

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_lock_reply_async`, `lib/smb2-cmd-lock.c:smb2_cmd_lock_reply_async`

### Requirement: smb2_cmd_logoff_async build logoff request PDU
系统 MUST 构造 SMB2 LOGOFF 请求 PDU，用于结束当前 session。

#### Scenario: 构造 logoff 请求
- **GIVEN** 调用方提供回调和回调数据
- **WHEN** 调用 `smb2_cmd_logoff_async(smb2, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 LOGOFF command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_logoff_async`, `lib/smb2-cmd-logoff.c:smb2_cmd_logoff_async`

### Requirement: smb2_cmd_logoff_reply_async build logoff reply PDU
系统 MUST 构造 SMB2 LOGOFF reply PDU，且响应 command_data 语义为空。

#### Scenario: 构造 logoff 响应
- **GIVEN** 调用方提供回调和回调数据
- **WHEN** 调用 `smb2_cmd_logoff_reply_async(smb2, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 LOGOFF command，并编码固定响应字段

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_logoff_reply_async`, `lib/smb2-cmd-logoff.c:smb2_cmd_logoff_reply_async`

### Requirement: smb2_cmd_flush_async build flush request PDU
系统 MUST 构造 SMB2 FLUSH 请求 PDU，用于持久化 file id 关联的远端写入状态。

#### Scenario: 构造 flush 请求
- **GIVEN** 调用方提供 `struct smb2_flush_request *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_flush_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 FLUSH command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_flush_async`, `lib/smb2-cmd-flush.c:smb2_cmd_flush_async`

### Requirement: smb2_cmd_flush_reply_async build flush reply PDU
系统 MUST 构造 SMB2 FLUSH reply PDU，且响应 command_data 语义为空。

#### Scenario: 构造 flush 响应
- **GIVEN** 调用方提供回调和回调数据
- **WHEN** 调用 `smb2_cmd_flush_reply_async(smb2, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 FLUSH command，并编码固定响应字段

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_flush_reply_async`, `lib/smb2-cmd-flush.c:smb2_cmd_flush_reply_async`

### Requirement: smb2_cmd_oplock_break_async build oplock break acknowledgement PDU
系统 MUST 构造 SMB2 OPLOCK_BREAK acknowledgement PDU，用于回应 oplock break 通知。

#### Scenario: 构造 oplock break acknowledgement
- **GIVEN** 调用方提供 `struct smb2_oplock_break_acknowledgement *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_oplock_break_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 OPLOCK_BREAK command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_oplock_break_async`, `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_async`

### Requirement: smb2_cmd_oplock_break_reply_async build oplock break reply PDU
系统 MUST 构造 SMB2 OPLOCK_BREAK reply PDU，用于服务端确认 oplock acknowledgement。

#### Scenario: 构造 oplock break 响应
- **GIVEN** 调用方提供 `struct smb2_oplock_break_reply *rep`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_oplock_break_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 OPLOCK_BREAK command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_oplock_break_reply_async`, `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_reply_async`

### Requirement: smb2_cmd_oplock_break_notification_async build oplock break notification PDU
系统 MUST 构造 SMB2 OPLOCK_BREAK notification PDU，用于服务端主动通知客户端 oplock 状态变化。

#### Scenario: 构造 oplock break 通知
- **GIVEN** 调用方提供 `struct smb2_oplock_break_notification *rep`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_oplock_break_notification_async(smb2, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 SMB2 OPLOCK_BREAK command，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_oplock_break_notification_async`, `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_notification_async`

### Requirement: smb2_cmd_lease_break_async build lease break acknowledgement PDU
系统 MUST 构造 SMB2 LEASE_BREAK acknowledgement PDU，用于回应 lease break 通知。

#### Scenario: 构造 lease break acknowledgement
- **GIVEN** 调用方提供 `struct smb2_lease_break_acknowledgement *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_lease_break_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 lease break 对应 command 编码路径，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_lease_break_async`, `lib/smb2-cmd-oplock-break.c:smb2_cmd_lease_break_async`

### Requirement: smb2_cmd_lease_break_reply_async build lease break reply PDU
系统 MUST 构造 SMB2 LEASE_BREAK reply PDU，用于服务端确认 lease acknowledgement。

#### Scenario: 构造 lease break 响应
- **GIVEN** 调用方提供 `struct smb2_lease_break_reply *rep`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_lease_break_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 lease break 对应 command 编码路径，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_lease_break_reply_async`, `lib/smb2-cmd-oplock-break.c:smb2_cmd_lease_break_reply_async`

### Requirement: smb2_cmd_lease_break_notification_async build lease break notification PDU
系统 MUST 构造 SMB2 LEASE_BREAK notification PDU，用于服务端主动通知客户端 lease 状态变化。

#### Scenario: 构造 lease break 通知
- **GIVEN** 调用方提供 `struct smb2_lease_break_notification *req`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_lease_break_notification_async(smb2, req, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 lease break 对应 command 编码路径，失败时 MUST 返回 `NULL`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_lease_break_notification_async`, `lib/smb2-cmd-oplock-break.c:smb2_cmd_lease_break_notification_async`

### Requirement: smb2_cmd_error_reply_async build error reply PDU
系统 MUST 构造 SMB2 error reply PDU，并将调用方提供的 `causing_command` 和 `status` 写入响应语义。

#### Scenario: 构造 error 响应
- **GIVEN** 调用方提供 `struct smb2_error_reply *rep`、`causing_command`、NT status、回调和回调数据
- **WHEN** 调用 `smb2_cmd_error_reply_async(smb2, rep, causing_command, status, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 `causing_command` 作为 SMB2 command，并将 PDU header status 设置为调用方提供的 `status`

Trace: `include/smb2/libsmb2-raw.h:smb2_cmd_error_reply_async`, `lib/smb2-cmd-error.c:smb2_cmd_error_reply_async`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_cmd_lease_break_*` 系列在实现中复用 `lib/smb2-cmd-oplock-break.c`，其 wire command 常量归属和命名是否需要在公开文档中拆分确认。 | smb2_cmd_lease_break_async, smb2_cmd_lease_break_reply_async, smb2_cmd_lease_break_notification_async | 头文件声明为 lease break，源码文件和相邻 oplock break 实现复用同一模块。 |
| Q-002 | 多数 reply builder 的服务端使用场景是否属于稳定公开 API 需要确认。 | reply builder functions | 头文件公开声明 reply builder，但主要生产路径集中在内部 server/response 分支。 |
| Q-003 | `smb2_cmd_negotiate_reply_async` 中 `seclen` 在 security buffer 分支前的默认值来源需要确认。 | smb2_cmd_negotiate_reply_async | 源码 `rep->negotiate_context_offset = len + seclen + SMB2_HEADER_SIZE` 依赖局部变量，未在无 security buffer 路径看到明确初始化证据。 |
