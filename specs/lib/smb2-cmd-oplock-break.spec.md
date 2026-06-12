# lib/smb2-cmd-oplock-break.c Specification

## Source Context

- Source: `lib/smb2-cmd-oplock-break.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`, `include/smb2/libsmb2.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context reports parser callers from `lib/pdu.c` and reply builders called from `lib/libsmb2.c`; builders depend on `smb2_allocate_pdu`, `smb2_add_iovector`, `smb2_pad_to_64bit`, `smb2_free_pdu`, and integer codec helpers from `lib/pdu.c`.
- Build/Compile Context: C source compiled through the core libsmb2 library; conditional includes depend on `HAVE_CONFIG_H`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_oplock_break_acknowledgement | function | `static int smb2_encode_oplock_break_acknowledgement(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_oplock_break_acknowledgement *req)` | Skip | 静态编码 helper，仅由同文件公开 builder 调用，行为归属到 `smb2_cmd_oplock_break_async`。 |
| smb2_cmd_oplock_break_async | function | `struct smb2_pdu *smb2_cmd_oplock_break_async(struct smb2_context *smb2, struct smb2_oplock_break_acknowledgement *req, smb2_command_cb cb, void *cb_data)` | Include | RAW 头文件声明的异步 Oplock Break acknowledgement PDU 构造入口，调用方可观察返回 PDU 或 NULL。 |
| smb2_encode_oplock_break_reply | function | `static int smb2_encode_oplock_break_reply(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_oplock_break_reply *rep)` | Skip | 静态编码 helper，仅由同文件 reply builder 调用，行为归属到 `smb2_cmd_oplock_break_reply_async`。 |
| smb2_cmd_oplock_break_reply_async | function | `struct smb2_pdu *smb2_cmd_oplock_break_reply_async(struct smb2_context *smb2, struct smb2_oplock_break_reply *rep, smb2_command_cb cb, void *cb_data)` | Include | RAW 头文件声明的 Oplock Break reply PDU 构造入口，并被 `lib/libsmb2.c` 的通知处理路径调用。 |
| smb2_encode_oplock_break_notification | function | `static int smb2_encode_oplock_break_notification(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_oplock_break_notification *rep)` | Skip | 静态编码 helper，仅由同文件 notification builder 调用，行为归属到 `smb2_cmd_oplock_break_notification_async`。 |
| smb2_cmd_oplock_break_notification_async | function | `struct smb2_pdu *smb2_cmd_oplock_break_notification_async(struct smb2_context *smb2, struct smb2_oplock_break_notification *rep, smb2_command_cb cb, void *cb_data)` | Include | RAW 头文件声明的 Oplock Break notification PDU 构造入口，构造可发送的 SMB2_OPLOCK_BREAK PDU。 |
| smb2_encode_lease_break_acknowledgement | function | `static int smb2_encode_lease_break_acknowledgement(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_lease_break_acknowledgement *req)` | Skip | 静态编码 helper，仅由同文件 lease acknowledgement builder 调用，行为归属到 `smb2_cmd_lease_break_async`。 |
| smb2_cmd_lease_break_async | function | `struct smb2_pdu *smb2_cmd_lease_break_async(struct smb2_context *smb2, struct smb2_lease_break_acknowledgement *req, smb2_command_cb cb, void *cb_data)` | Include | RAW 头文件声明的 Lease Break acknowledgement PDU 构造入口，调用方可观察 PDU 构造成功或失败。 |
| smb2_encode_lease_break_reply | function | `static int smb2_encode_lease_break_reply(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_lease_break_reply *rep)` | Skip | 静态编码 helper，仅由同文件 lease reply builder 调用，行为归属到 `smb2_cmd_lease_break_reply_async`。 |
| smb2_cmd_lease_break_reply_async | function | `struct smb2_pdu *smb2_cmd_lease_break_reply_async(struct smb2_context *smb2, struct smb2_lease_break_reply *rep, smb2_command_cb cb, void *cb_data)` | Include | RAW 头文件声明的 Lease Break reply PDU 构造入口，并被 `lib/libsmb2.c` 的通知处理路径调用。 |
| smb2_encode_lease_break_notification | function | `static int smb2_encode_lease_break_notification(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_lease_break_notification *req)` | Skip | 静态编码 helper，仅由同文件 lease notification builder 调用，行为归属到 `smb2_cmd_lease_break_notification_async`。 |
| smb2_cmd_lease_break_notification_async | function | `struct smb2_pdu *smb2_cmd_lease_break_notification_async(struct smb2_context *smb2, struct smb2_lease_break_notification *req, smb2_command_cb cb, void *cb_data)` | Include | RAW 头文件声明的 Lease Break notification PDU 构造入口，构造可发送的 SMB2_OPLOCK_BREAK PDU。 |
| smb2_process_oplock_break_fixed | function | `int smb2_process_oplock_break_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有 parser 入口，由 `lib/pdu.c` 固定载荷分派调用，分配 reply payload 并校验结构大小。 |
| smb2_process_oplock_break_variable | function | `int smb2_process_oplock_break_variable(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有 parser 入口，由 `lib/pdu.c` variable 载荷分派调用，按已解析结构大小填充 break 类型和字段。 |
| smb2_process_oplock_break_request_fixed | function | `int smb2_process_oplock_break_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有 server-side request parser 入口，由 `lib/pdu.c` request fixed 分派调用，分配 request payload 并校验 acknowledge 结构大小。 |
| smb2_process_oplock_break_request_variable | function | `int smb2_process_oplock_break_request_variable(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有 server-side request parser 入口，由 `lib/pdu.c` request variable 分派调用，按 acknowledge 类型填充请求字段。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_OPLOCK_BREAK_NOTIFICATION_SIZE | macro | `include/smb2/smb2.h:1096` | Oplock break notification 固定结构大小为 24。 |
| SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE | macro | `include/smb2/smb2.h:1103` | Oplock break acknowledgement 固定结构大小为 24。 |
| SMB2_OPLOCK_BREAK_REPLY_SIZE | macro | `include/smb2/smb2.h:1110` | Oplock break reply 固定结构大小为 24。 |
| SMB2_LEASE_BREAK_NOTIFICATION_SIZE | macro | `include/smb2/smb2.h:1130` | Lease break notification 固定结构大小为 44。 |
| SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE | macro | `include/smb2/smb2.h:1143` | Lease break acknowledgement 固定结构大小为 36。 |
| SMB2_LEASE_BREAK_REPLY_SIZE | macro | `include/smb2/smb2.h:1152` | Lease break reply 固定结构大小为 36。 |
| struct smb2_oplock_break_notification | struct | `include/smb2/smb2.h:1098` | 包含 oplock level 与 file id。 |
| struct smb2_oplock_break_acknowledgement | struct | `include/smb2/smb2.h:1105` | 包含 acknowledgement oplock level 与 file id。 |
| struct smb2_oplock_break_reply | struct | `include/smb2/smb2.h:1112` | 包含 reply oplock level 与 file id。 |
| struct smb2_lease_break_notification | struct | `include/smb2/smb2.h:1132` | 包含 epoch、flags、lease key、lease state 和 mask hint 字段。 |
| struct smb2_lease_break_acknowledgement | struct | `include/smb2/smb2.h:1145` | 包含 flags、lease key、lease state 和 lease duration。 |
| struct smb2_lease_break_reply | struct | `include/smb2/smb2.h:1154` | 包含 flags、lease key、lease state 和 lease duration。 |
| struct smb2_oplock_or_lease_break_reply | struct | `include/smb2/smb2.h:1164` | Parser payload union，用 `break_type` 标识 oplock/lease notification 或 response。 |
| struct smb2_oplock_or_lease_break_request | struct | `include/smb2/smb2.h:1176` | Server-side request parser payload union，用 `break_type` 标识 acknowledgement 类型。 |

## ADDED Requirements

### Requirement: smb2_cmd_oplock_break_async builds acknowledgement PDU
系统 MUST 为 Oplock Break acknowledgement 分配 `SMB2_OPLOCK_BREAK` PDU，编码 `SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE`、`oplock_level` 和 `file_id`，并在编码和 64-bit padding 全部成功后返回该 PDU。

#### Scenario: 构造 acknowledgement 成功
- **GIVEN** 调用方提供可用的 `smb2_context`、`smb2_oplock_break_acknowledgement`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_oplock_break_async`
- **THEN** 返回的 PDU 使用 SMB2_OPLOCK_BREAK 命令，并包含 acknowledgement 结构大小、oplock level 和 file id

Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_oplock_break_acknowledgement`

#### Scenario: 构造 acknowledgement 失败
- **GIVEN** PDU 分配、payload iovector 添加或 64-bit padding 任一步骤失败
- **WHEN** 调用 `smb2_cmd_oplock_break_async`
- **THEN** 函数 MUST 返回 NULL，且在已分配 PDU 后发生失败时释放该 PDU

Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_oplock_break_acknowledgement`

### Requirement: smb2_cmd_oplock_break_reply_async builds reply PDU
系统 MUST 为 Oplock Break reply 分配 `SMB2_OPLOCK_BREAK` PDU，编码 `SMB2_OPLOCK_BREAK_REPLY_SIZE`、`oplock_level` 和 `file_id`，并在失败路径返回 NULL。

#### Scenario: 构造 reply 成功
- **GIVEN** 调用方提供可用的 `smb2_oplock_break_reply` 数据
- **WHEN** 调用 `smb2_cmd_oplock_break_reply_async`
- **THEN** 返回的 PDU MUST 包含 reply 固定结构大小、oplock level 和 file id，并完成 64-bit padding

Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_reply_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_oplock_break_reply`

#### Scenario: 构造 reply 失败
- **GIVEN** PDU 分配、reply buffer 分配、iovector 添加或 padding 失败
- **WHEN** 调用 `smb2_cmd_oplock_break_reply_async`
- **THEN** 函数 MUST 返回 NULL，且已分配 PDU 的失败路径释放 PDU

Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_reply_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_oplock_break_reply`

### Requirement: smb2_cmd_oplock_break_notification_async builds notification PDU
系统 MUST 为 Oplock Break notification 分配 `SMB2_OPLOCK_BREAK` PDU，使用与 oplock reply 相同的 24 字节 wire 结构编码 `oplock_level` 和 `file_id`。

#### Scenario: 构造 notification 成功
- **GIVEN** 调用方提供可用的 `smb2_oplock_break_notification` 数据
- **WHEN** 调用 `smb2_cmd_oplock_break_notification_async`
- **THEN** 返回的 PDU MUST 包含 `SMB2_OPLOCK_BREAK_REPLY_SIZE` 结构大小、oplock level 和 file id，并完成 64-bit padding

Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_oplock_break_notification_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_oplock_break_notification`

### Requirement: smb2_cmd_lease_break_async builds lease acknowledgement PDU
系统 MUST 为 Lease Break acknowledgement 分配 `SMB2_OPLOCK_BREAK` PDU，编码 `SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE`、flags、lease key、lease state 和 lease duration，并在失败路径返回 NULL。

#### Scenario: 构造 lease acknowledgement 成功
- **GIVEN** 调用方提供可用的 `smb2_lease_break_acknowledgement` 数据
- **WHEN** 调用 `smb2_cmd_lease_break_async`
- **THEN** 返回的 PDU MUST 使用 SMB2_OPLOCK_BREAK 命令并附带 lease acknowledgement payload

Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_lease_break_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_lease_break_acknowledgement`

#### Scenario: 构造 lease acknowledgement 失败
- **GIVEN** PDU 分配、buffer 分配、iovector 添加或 padding 失败
- **WHEN** 调用 `smb2_cmd_lease_break_async`
- **THEN** 函数 MUST 返回 NULL，且已分配 PDU 的失败路径释放 PDU

Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_lease_break_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_lease_break_acknowledgement`

### Requirement: smb2_cmd_lease_break_reply_async builds lease reply PDU
系统 MUST 为 Lease Break reply 分配 `SMB2_OPLOCK_BREAK` PDU，编码 `SMB2_LEASE_BREAK_REPLY_SIZE`、flags、lease key、lease state 和 lease duration。

#### Scenario: 构造 lease reply 成功
- **GIVEN** 调用方提供可用的 `smb2_lease_break_reply` 数据
- **WHEN** 调用 `smb2_cmd_lease_break_reply_async`
- **THEN** 返回的 PDU MUST 包含 lease reply payload 并完成 64-bit padding

Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_lease_break_reply_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_lease_break_reply`

### Requirement: smb2_cmd_lease_break_notification_async builds lease notification PDU
系统 MUST 为 Lease Break notification 分配 `SMB2_OPLOCK_BREAK` PDU，编码 `SMB2_LEASE_BREAK_NOTIFICATION_SIZE`、new epoch、flags、lease key、lease state、break reason 和 mask hint 字段。

#### Scenario: 构造 lease notification 成功
- **GIVEN** 调用方提供可用的 `smb2_lease_break_notification` 数据
- **WHEN** 调用 `smb2_cmd_lease_break_notification_async`
- **THEN** 返回的 PDU MUST 包含 lease notification payload 并完成 64-bit padding

Trace: `lib/smb2-cmd-oplock-break.c:smb2_cmd_lease_break_notification_async`, `lib/smb2-cmd-oplock-break.c:smb2_encode_lease_break_notification`

### Requirement: smb2_process_oplock_break_fixed validates reply structure size
系统 MUST 为 reply/notification parser 分配 `smb2_oplock_or_lease_break_reply` payload，并只接受 Oplock Break reply、Lease Break notification 或 Lease Break reply 的结构大小。

#### Scenario: reply fixed size accepted
- **GIVEN** 输入 iovector 的结构大小为 `SMB2_OPLOCK_BREAK_REPLY_SIZE`、`SMB2_LEASE_BREAK_NOTIFICATION_SIZE` 或 `SMB2_LEASE_BREAK_REPLY_SIZE`
- **WHEN** `smb2_process_oplock_break_fixed` 处理 fixed payload
- **THEN** 函数 MUST 将 payload 附加到 PDU，并返回结构大小减去 `sizeof(uint16_t)` 的 variable payload 长度

Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

#### Scenario: reply fixed size rejected
- **GIVEN** 输入 iovector 的结构大小不是已支持的 oplock/lease break reply 或 notification 大小
- **WHEN** `smb2_process_oplock_break_fixed` 处理 fixed payload
- **THEN** 函数 MUST 设置错误、清空 `pdu->payload`、释放临时 payload 并返回 -1

Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

### Requirement: smb2_process_oplock_break_variable decodes reply fields
系统 MUST 根据 fixed 阶段保存的 `struct_size` 解码 oplock 或 lease break reply/notification 字段，并设置可观察的 `break_type`。

#### Scenario: decode oplock response or notification
- **GIVEN** `pdu->payload` 的结构大小为 `SMB2_OPLOCK_BREAK_NOTIFICATION_SIZE`
- **WHEN** `smb2_process_oplock_break_variable` 解码 variable payload
- **THEN** 函数 MUST 根据 message id 选择 `SMB2_BREAK_TYPE_OPLOCK_NOTIFICATION` 或 `SMB2_BREAK_TYPE_OPLOCK_RESPONSE`，并填充 oplock level 和 file id

Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`

#### Scenario: decode lease notification or response
- **GIVEN** `pdu->payload` 的结构大小为 lease break notification 或 lease break reply 大小
- **WHEN** `smb2_process_oplock_break_variable` 解码 variable payload
- **THEN** 函数 MUST 设置 lease notification 或 lease response break type，并填充对应 union 字段

Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`

### Requirement: smb2_process_oplock_break_request_fixed validates acknowledgement structure size
系统 MUST 为 server-side request parser 分配 `smb2_oplock_or_lease_break_request` payload，并只接受 Oplock Break acknowledgement 或 Lease Break acknowledgement 的结构大小。

#### Scenario: request fixed size accepted
- **GIVEN** 输入 iovector 的结构大小为 `SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE` 或 `SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE`
- **WHEN** `smb2_process_oplock_break_request_fixed` 处理 fixed payload
- **THEN** 函数 MUST 将 payload 附加到 PDU，并返回结构大小减去 `sizeof(uint16_t)` 的 variable payload 长度

Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

#### Scenario: request fixed size rejected
- **GIVEN** 输入 iovector 的结构大小不是已支持的 acknowledgement 大小
- **WHEN** `smb2_process_oplock_break_request_fixed` 处理 fixed payload
- **THEN** 函数 MUST 设置错误、清空 `pdu->payload`、释放临时 payload 并返回 -1

Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

### Requirement: smb2_process_oplock_break_request_variable decodes acknowledgement fields
系统 MUST 根据 fixed 阶段保存的 `struct_size` 解码 oplock 或 lease acknowledgement 字段，并设置 acknowledgement `break_type`。

#### Scenario: decode oplock acknowledgement
- **GIVEN** `pdu->payload` 的结构大小为 `SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE`
- **WHEN** `smb2_process_oplock_break_request_variable` 解码 variable payload
- **THEN** 函数 MUST 设置 `SMB2_BREAK_TYPE_OPLOCK_ACKNOWLEDGE`，并填充 oplock level 和 file id

Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`

#### Scenario: decode lease acknowledgement
- **GIVEN** `pdu->payload` 的结构大小为 `SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE`
- **WHEN** `smb2_process_oplock_break_request_variable` 解码 variable payload
- **THEN** 函数 MUST 设置 `SMB2_BREAK_TYPE_LEASE_ACKNOWLEDGE`，并填充 flags、lease key、lease state 和 lease duration

Trace: `lib/smb2-cmd-oplock-break.c:smb2_process_oplock_break_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | Lease acknowledgement 和 lease notification 编码实现多次写 offset 4，是否为既有 wire 契约还是实现缺陷需要进一步确认？ | smb2_cmd_lease_break_async, smb2_cmd_lease_break_notification_async | 源码显示多个字段写入同一偏移，但缺少测试或协议注释确认调用方可观察语义。 |
| Q-002 | `smb2_cmd_oplock_break_notification_async` 使用 `SMB2_OPLOCK_BREAK_REPLY_SIZE` 而不是 `SMB2_OPLOCK_BREAK_NOTIFICATION_SIZE` 是否依赖二者同值的协议契约？ | smb2_cmd_oplock_break_notification_async | 源码注释说明 notification 和 response 使用相同结构，但未在测试中确认。 |
| Q-003 | GitNexus impact 对同名声明和定义返回 ambiguous，具体 blast radius 需按 UID 或文件路径在后续主 Agent 收尾时复核。 | file-level | `gitnexus impact` 对 `smb2_cmd_oplock_break_reply_async` 和 `smb2_process_oplock_break_fixed` 同时匹配头文件声明与源文件定义。 |
