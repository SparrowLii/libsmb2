# lib/smb2-cmd-tree-disconnect.c Specification

## Source Context

- Source: `lib/smb2-cmd-tree-disconnect.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: `smb2_allocate_pdu`, `smb2_add_iovector`, `smb2_pad_to_64bit`, `smb2_free_pdu`, `smb2_disconnect_tree_id`, `smb2_set_error`, `smb2_set_uint16`
- Build/Compile Context: `CMakeLists.txt` and `configure.ac` build C sources; file conditionally includes config and platform headers via `HAVE_CONFIG_H`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_cmd_tree_disconnect_async | function | `struct smb2_pdu *smb2_cmd_tree_disconnect_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data);` | Include | 公开 raw API 声明在 `include/smb2/libsmb2-raw.h`，创建 SMB2 TREE_DISCONNECT 请求 PDU 并定义失败返回语义。 |
| smb2_cmd_tree_disconnect_reply_async | function | `struct smb2_pdu *smb2_cmd_tree_disconnect_reply_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data);` | Include | 公开 raw API 声明在 `include/smb2/libsmb2-raw.h`，创建 SMB2 TREE_DISCONNECT 响应 PDU 并定义失败返回语义。 |
| smb2_process_tree_disconnect_fixed | function | `int smb2_process_tree_disconnect_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 内部处理入口声明在 `include/libsmb2-private.h`，由 PDU 固定载荷处理路径调用并更新 tree id 状态。 |
| smb2_process_tree_disconnect_request_fixed | function | `int smb2_process_tree_disconnect_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 内部处理入口声明在 `include/libsmb2-private.h`，服务端请求固定载荷路径需要稳定的空操作成功语义。 |
| smb2_encode_tree_disconnect_request | function | `static int smb2_encode_tree_disconnect_request(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Skip | 静态编码 helper，仅由 `smb2_cmd_tree_disconnect_async` 调用，资源和错误语义归属公开创建接口。 |
| smb2_encode_tree_disconnect_reply | function | `static int smb2_encode_tree_disconnect_reply(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Skip | 静态编码 helper，仅由 `smb2_cmd_tree_disconnect_reply_async` 调用，资源和错误语义归属公开创建接口。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_TREE_DISCONNECT_REQUEST_SIZE | macro | `include/smb2/smb2.h:1242` | 请求固定结构大小为 4 字节，写入请求 iovec 偏移 0。 |
| SMB2_TREE_DISCONNECT_REPLY_SIZE | macro | `include/smb2/smb2.h:1243` | 响应固定结构大小为 4 字节，写入响应 iovec 偏移 0。 |
| SMB2_TREE_DISCONNECT | enum | `include/smb2/smb2.h:62` | PDU 分配使用的 SMB2 命令码。 |

## ADDED Requirements

### Requirement: smb2_cmd_tree_disconnect_async request PDU creation
系统 MUST 为调用方创建 SMB2 TREE_DISCONNECT 请求 PDU，并在任一分配、编码或 64 位填充步骤失败时释放已分配 PDU 后返回 `NULL`。

#### Scenario: 创建请求 PDU 成功
- **GIVEN** 调用方提供有效的 `smb2_context`、回调函数和回调数据
- **WHEN** 调用 `smb2_cmd_tree_disconnect_async`
- **THEN** 返回值 MUST 是使用 `SMB2_TREE_DISCONNECT` 命令码创建、包含 4 字节 tree-disconnect 请求结构并完成 64 位填充的 `struct smb2_pdu *`

Trace: `lib/smb2-cmd-tree-disconnect.c:smb2_cmd_tree_disconnect_async`, `include/smb2/libsmb2-raw.h:128`

#### Scenario: 创建请求 PDU 失败
- **GIVEN** PDU 分配、请求编码或 64 位填充任一步骤失败
- **WHEN** 调用 `smb2_cmd_tree_disconnect_async`
- **THEN** 函数 MUST 返回 `NULL`，并且在 PDU 已分配的失败路径上 MUST 调用 `smb2_free_pdu` 释放该 PDU

Trace: `lib/smb2-cmd-tree-disconnect.c:smb2_cmd_tree_disconnect_async`, `lib/smb2-cmd-tree-disconnect.c:smb2_encode_tree_disconnect_request`

### Requirement: smb2_cmd_tree_disconnect_reply_async reply PDU creation
系统 MUST 为调用方创建 SMB2 TREE_DISCONNECT 响应 PDU，并在任一分配、编码或 64 位填充步骤失败时释放已分配 PDU 后返回 `NULL`。

#### Scenario: 创建响应 PDU 成功
- **GIVEN** 调用方提供有效的 `smb2_context`、回调函数和回调数据
- **WHEN** 调用 `smb2_cmd_tree_disconnect_reply_async`
- **THEN** 返回值 MUST 是使用 `SMB2_TREE_DISCONNECT` 命令码创建、包含 4 字节 tree-disconnect 响应结构并完成 64 位填充的 `struct smb2_pdu *`

Trace: `lib/smb2-cmd-tree-disconnect.c:smb2_cmd_tree_disconnect_reply_async`, `include/smb2/libsmb2-raw.h:131`

#### Scenario: 创建响应 PDU 失败
- **GIVEN** PDU 分配、响应编码或 64 位填充任一步骤失败
- **WHEN** 调用 `smb2_cmd_tree_disconnect_reply_async`
- **THEN** 函数 MUST 返回 `NULL`，并且在 PDU 已分配的失败路径上 MUST 调用 `smb2_free_pdu` 释放该 PDU

Trace: `lib/smb2-cmd-tree-disconnect.c:smb2_cmd_tree_disconnect_reply_async`, `lib/smb2-cmd-tree-disconnect.c:smb2_encode_tree_disconnect_reply`

### Requirement: smb2_process_tree_disconnect_fixed reply state update
系统 MUST 在处理 tree-disconnect 固定响应载荷时断开当前同步头中的 tree id，并以成功状态返回。

#### Scenario: 处理 tree-disconnect 响应固定载荷
- **GIVEN** `smb2->hdr.sync.tree_id` 包含待断开的 tree id
- **WHEN** 调用 `smb2_process_tree_disconnect_fixed`
- **THEN** 函数 MUST 调用 `smb2_disconnect_tree_id(smb2, smb2->hdr.sync.tree_id)` 并返回 `0`

Trace: `lib/smb2-cmd-tree-disconnect.c:smb2_process_tree_disconnect_fixed`, `include/libsmb2-private.h:469`

### Requirement: smb2_process_tree_disconnect_request_fixed request no-op success
系统 MUST 将 tree-disconnect 请求固定载荷处理为无额外状态变更的成功路径。

#### Scenario: 处理 tree-disconnect 请求固定载荷
- **GIVEN** 服务端请求处理路径收到 tree-disconnect 固定载荷
- **WHEN** 调用 `smb2_process_tree_disconnect_request_fixed`
- **THEN** 函数 MUST 返回 `0`，且源码中不访问 `pdu` 或修改 `smb2` 状态

Trace: `lib/smb2-cmd-tree-disconnect.c:smb2_process_tree_disconnect_request_fixed`, `include/libsmb2-private.h:471`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | GitNexus `impact` 当前 CLI 对同名声明和实现返回 ambiguous，且不支持本次尝试的 `--target-uid` 或 `--file` 参数；需要确认可用的精确 impact 参数以记录完整风险级别。 | file-level | 已通过 `context` 确认调用关系，但 impact 风险级别未能精确解析。 |
| Q-002 | 未定位到直接测试覆盖 tree-disconnect PDU 编码、释放失败路径或固定载荷处理的测试用例。 | file-level | GitNexus context 未返回 test callers，源码和头文件可确认行为但缺少测试断言证据。 |
