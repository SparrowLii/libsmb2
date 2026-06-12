# lib/smb2-cmd-tree-connect.c Specification

## Source Context

- Source: `lib/smb2-cmd-tree-connect.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/smb2/smb2.h`, `include/libsmb2-private.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context shows callers `lib/libsmb2.c:session_setup_cb`, `lib/libsmb2.c:smb2_tree_connect_request_cb`, `lib/pdu.c:smb2_process_reply_payload_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`, and `lib/pdu.c:smb2_process_request_payload_variable`; dependencies include `smb2_allocate_pdu`, `smb2_add_iovector`, `smb2_pad_to_64bit`, `smb2_free_pdu`, `smb2_connect_tree_id`, `smb2_tree_id`, `smb2_set_error`, and integer field accessors in `lib/pdu.c`.
- Build/Compile Context: C source compiled as part of the core `smb2` library; guarded includes depend on `HAVE_CONFIG_H`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_tree_connect_request | function | static int smb2_encode_tree_connect_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_tree_connect_request *req) | Skip | 静态编码 helper，仅由同文件公开入口调用，行为归属到 `smb2_cmd_tree_connect_async`。 |
| smb2_cmd_tree_connect_async | function | struct smb2_pdu *smb2_cmd_tree_connect_async(struct smb2_context *smb2, struct smb2_tree_connect_request *req, smb2_command_cb cb, void *cb_data) | Include | 原始公开异步 Tree Connect 请求入口，负责分配 PDU、编码请求和返回错误。 |
| smb2_encode_tree_connect_reply | function | static int smb2_encode_tree_connect_reply(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_tree_connect_reply *rep) | Skip | 静态编码 helper，仅由同文件 reply 入口调用，行为归属到 `smb2_cmd_tree_connect_reply_async`。 |
| smb2_cmd_tree_connect_reply_async | function | struct smb2_pdu *smb2_cmd_tree_connect_reply_async(struct smb2_context *smb2, struct smb2_tree_connect_reply *rep, uint32_t tree_id, smb2_command_cb cb, void *cb_data) | Include | 原始公开异步 Tree Connect reply 构造入口，设置 tree id 并编码 reply PDU。 |
| smb2_process_tree_connect_fixed | function | int smb2_process_tree_connect_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | 内部固定部分 reply 解码入口，被 PDU 解析流程跨文件调用并更新连接状态与 sealing 状态。 |
| smb2_process_tree_connect_request_fixed | function | int smb2_process_tree_connect_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | 内部固定部分 request 解码入口，被服务端请求解析流程跨文件调用并返回变量区长度。 |
| smb2_process_tree_connect_request_variable | function | int smb2_process_tree_connect_request_variable(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | 内部变量部分 request 解码入口，被服务端请求解析流程跨文件调用并绑定路径缓冲区。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_TREE_CONNECT_REQUEST_SIZE | macro | include/smb2/smb2.h:181 | Tree Connect request 固定结构大小为 9 字节，编码时按偶数字节长度放入 fixed iovec。 |
| struct smb2_tree_connect_request | struct | include/smb2/smb2.h:185 | request 数据包含 `flags`、`path_offset`、`path_length` 和 UTF-16 路径指针。 |
| SMB2_SHAREFLAG_ENCRYPT_DATA | macro | include/smb2/smb2.h:209 | reply 解码时用于在未启用 sealing 时根据 share flags 打开 `smb2->seal`。 |
| SMB2_TREE_CONNECT_REPLY_SIZE | macro | include/smb2/smb2.h:217 | Tree Connect reply 固定结构大小为 16 字节。 |
| struct smb2_tree_connect_reply | struct | include/smb2/smb2.h:219 | reply 数据包含 share type、share flags、capabilities 和 maximal access。 |

## ADDED Requirements

### Requirement: smb2_cmd_tree_connect_async builds a Tree Connect request PDU
系统 MUST 为调用方构造 `SMB2_TREE_CONNECT` 请求 PDU，并在请求固定区后追加 `req->path_length` 字节路径数据。

#### Scenario: 成功编码请求
- **GIVEN** 调用方提供有效的 `smb2_context`、Tree Connect request、回调和回调数据
- **WHEN** 调用 `smb2_cmd_tree_connect_async`
- **THEN** 返回的 PDU MUST 使用 `SMB2_TREE_CONNECT` 命令、包含大小为 `SMB2_TREE_CONNECT_REQUEST_SIZE` 的固定区、设置 flags/path offset/path length，并追加原始路径字节后按 64 位边界填充

Trace: `lib/smb2-cmd-tree-connect.c:smb2_cmd_tree_connect_async`, `lib/smb2-cmd-tree-connect.c:smb2_encode_tree_connect_request`

#### Scenario: 编码或填充失败
- **GIVEN** PDU 分配成功但固定区、路径 iovec 或 64 位填充无法完成
- **WHEN** 调用 `smb2_cmd_tree_connect_async`
- **THEN** 函数 MUST 释放已分配的 PDU 并返回 `NULL`，且不会调用传入回调

Trace: `lib/smb2-cmd-tree-connect.c:smb2_cmd_tree_connect_async`, `include/smb2/libsmb2-raw.h:87`

### Requirement: smb2_cmd_tree_connect_reply_async builds a Tree Connect reply PDU
系统 MUST 为 Tree Connect reply 构造 `SMB2_TREE_CONNECT` PDU，并确保连接上下文和 PDU header 使用有效 tree id。

#### Scenario: 调用方提供 tree id
- **GIVEN** 调用方提供非零 `tree_id` 和 Tree Connect reply 数据
- **WHEN** 调用 `smb2_cmd_tree_connect_reply_async`
- **THEN** 函数 MUST 连接该 tree id，将 PDU header 的 `tree_id` 设置为当前上下文 tree id，并编码 share type、share flags、capabilities 和 maximal access

Trace: `lib/smb2-cmd-tree-connect.c:smb2_cmd_tree_connect_reply_async`, `lib/smb2-cmd-tree-connect.c:smb2_encode_tree_connect_reply`

#### Scenario: 调用方未提供 tree id
- **GIVEN** 调用方传入 `tree_id` 为 0
- **WHEN** 调用 `smb2_cmd_tree_connect_reply_async`
- **THEN** 函数 MUST 从静态递增种子生成替代 tree id，并按生成的 tree id 连接上下文和设置 PDU header

Trace: `lib/smb2-cmd-tree-connect.c:smb2_cmd_tree_connect_reply_async`

#### Scenario: reply 编码或填充失败
- **GIVEN** PDU 分配成功但 reply 编码或 64 位填充无法完成
- **WHEN** 调用 `smb2_cmd_tree_connect_reply_async`
- **THEN** 函数 MUST 释放已分配的 PDU 并返回 `NULL`

Trace: `lib/smb2-cmd-tree-connect.c:smb2_cmd_tree_connect_reply_async`

### Requirement: smb2_process_tree_connect_fixed decodes a fixed Tree Connect reply
系统 MUST 验证 Tree Connect reply 固定区大小，成功时分配 reply payload、连接响应 header 中的 tree id，并解码 share 属性。

#### Scenario: 固定 reply 有效
- **GIVEN** 当前输入 iovec 的结构大小等于 `SMB2_TREE_CONNECT_REPLY_SIZE` 且偶数化结构大小等于 iovec 长度
- **WHEN** 调用 `smb2_process_tree_connect_fixed`
- **THEN** 函数 MUST 分配 `struct smb2_tree_connect_reply` 到 `pdu->payload`，连接 `smb2->hdr.sync.tree_id`，解码 share type、share flags、capabilities 和 maximal access，并返回 0

Trace: `lib/smb2-cmd-tree-connect.c:smb2_process_tree_connect_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

#### Scenario: reply 大小无效或内存不足
- **GIVEN** 当前输入 iovec 的结构大小不匹配、长度不匹配或 reply payload 分配失败
- **WHEN** 调用 `smb2_process_tree_connect_fixed`
- **THEN** 函数 MUST 设置错误信息并返回 -1

Trace: `lib/smb2-cmd-tree-connect.c:smb2_process_tree_connect_fixed`

#### Scenario: share 要求加密且上下文尚未 sealing
- **GIVEN** 当前上下文 `smb2->seal` 为 false 且 reply `share_flags` 包含 `SMB2_SHAREFLAG_ENCRYPT_DATA`
- **WHEN** `smb2_process_tree_connect_fixed` 解码 reply
- **THEN** 函数 MUST 将 `smb2->seal` 设置为 true

Trace: `lib/smb2-cmd-tree-connect.c:smb2_process_tree_connect_fixed`, `include/smb2/smb2.h:209`

### Requirement: smb2_process_tree_connect_request_fixed decodes a fixed Tree Connect request
系统 MUST 验证 Tree Connect request 固定区大小，成功时分配 request payload、解码固定字段并返回变量路径长度。

#### Scenario: 固定 request 有效
- **GIVEN** 当前输入 iovec 的结构大小等于 `SMB2_TREE_CONNECT_REQUEST_SIZE` 且偶数化结构大小等于 iovec 长度
- **WHEN** 调用 `smb2_process_tree_connect_request_fixed`
- **THEN** 函数 MUST 分配 `struct smb2_tree_connect_request` 到 `pdu->payload`，解码 flags、path offset 和 path length，并返回 `req->path_length`

Trace: `lib/smb2-cmd-tree-connect.c:smb2_process_tree_connect_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

#### Scenario: request 大小无效或内存不足
- **GIVEN** 当前输入 iovec 的结构大小不匹配、长度不匹配或 request payload 分配失败
- **WHEN** 调用 `smb2_process_tree_connect_request_fixed`
- **THEN** 函数 MUST 设置错误信息并返回 -1

Trace: `lib/smb2-cmd-tree-connect.c:smb2_process_tree_connect_request_fixed`

### Requirement: smb2_process_tree_connect_request_variable binds the request path buffer
系统 MUST 将 Tree Connect request 的变量区 iovec 缓冲区作为 request path 暴露给后续处理。

#### Scenario: 变量路径区已读取
- **GIVEN** `pdu->payload` 指向已分配的 `struct smb2_tree_connect_request`，当前输入 iovec 包含路径变量区
- **WHEN** 调用 `smb2_process_tree_connect_request_variable`
- **THEN** 函数 MUST 将 `req->path` 指向当前 iovec 的 `buf`，并返回 0

Trace: `lib/smb2-cmd-tree-connect.c:smb2_process_tree_connect_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | 是否存在专门覆盖 Tree Connect PDU 编解码错误路径的测试用例？ | file-level | GitNexus context 未返回 test callers，当前批次未发现直接测试证据。 |
