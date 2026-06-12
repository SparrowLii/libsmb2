# lib/pdu.c Specification

## Source Context

- Source: `lib/pdu.c`
- Related Headers: `include/smb2/libsmb2.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`, `lib/smb2-signing.h`, `lib/smb3-seal.h`
- Related Tests: `tests/prog_cat.c`, `tests/prog_cat_cancel.c`, `tests/metastat-0202-censored.c`, `tests/prog_ls.c`, `tests/prog_mkdir.c`, `tests/prog_rmdir.c`
- Related Dependencies: GitNexus contexts for `smb2_allocate_pdu`, `smb2_add_compound_pdu`, `smb2_decode_header`, `smb2_queue_pdu`, `smb2_process_payload_fixed`, and `smb2_timeout_pdus`; impact for `Function:lib/pdu.c:smb2_queue_pdu` reported CRITICAL risk, 53 direct callers, 34 affected processes, and 11 affected modules.
- Build/Compile Context: C library implementation with optional `HAVE_CONFIG_H`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STDIO_H`, `HAVE_STRING_H`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H`; public declarations are split between `include/smb2/libsmb2.h` and `include/libsmb2-private.h`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_pad_to_64bit | function | `int smb2_pad_to_64bit(struct smb2_context *smb2, struct smb2_io_vectors *v);` | Include | 内部跨文件 I/O vector 对齐接口，影响 PDU 编码长度。 |
| smb2_allocate_pdu | function | `struct smb2_pdu *smb2_allocate_pdu(struct smb2_context *smb2, enum smb2_command command, smb2_command_cb cb, void *cb_data);` | Include | 内部跨文件 PDU 创建入口，被 SMB2 命令构造和服务端回复路径调用。 |
| smb2_select_tree_id | function | `int smb2_select_tree_id(struct smb2_context *smb2, uint32_t tree_id);` | Include | 公开 tree-id 选择 API，改变后续请求上下文。 |
| smb2_get_tree_id_for_pdu | function | `int smb2_get_tree_id_for_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu, uint32_t *tree_id);` | Include | 公开 PDU/tree-id 查询 API，供应用和代理使用。 |
| smb2_set_tree_id_for_pdu | function | `int smb2_set_tree_id_for_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu, uint32_t tree_id);` | Include | 公开 PDU/tree-id 修改 API，影响发送头部。 |
| smb2_get_session_id | function | `int smb2_get_session_id(struct smb2_context *smb2, uint64_t *session_id);` | Include | 公开 session-id 查询 API。 |
| smb2_connect_tree_id | function | `int smb2_connect_tree_id(struct smb2_context *smb2, uint32_t tree_id);` | Include | 内部 tree-id 栈生命周期接口。 |
| smb2_disconnect_tree_id | function | `int smb2_disconnect_tree_id(struct smb2_context *smb2, uint32_t tree_id);` | Include | 内部 tree-id 栈移除接口。 |
| smb2_pdu_is_compound | function | `int smb2_pdu_is_compound(struct smb2_context *smb2);` | Include | 公开 compound receive-state 查询 API。 |
| smb2_add_compound_pdu | function | `void smb2_add_compound_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_pdu *next_pdu);` | Include | 公开 compound chain 组装 API。 |
| smb2_free_pdu | function | `void smb2_free_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 公开/内部 PDU 释放 API，负责队列移除和 payload 释放。 |
| smb2_set_uint8 | function | `int smb2_set_uint8(struct smb2_iovec *iov, int offset, uint8_t value);` | Include | 内部 wire buffer 写入基础接口，存在边界检查语义。 |
| smb2_set_uint16 | function | `int smb2_set_uint16(struct smb2_iovec *iov, int offset, uint16_t value);` | Include | 内部 little-endian wire buffer 写入接口。 |
| smb2_set_uint32 | function | `int smb2_set_uint32(struct smb2_iovec *iov, int offset, uint32_t value);` | Include | 内部 little-endian wire buffer 写入接口，被 compound/header 编码使用。 |
| smb2_set_uint64 | function | `int smb2_set_uint64(struct smb2_iovec *iov, int offset, uint64_t value);` | Include | 内部 little-endian wire buffer 写入接口。 |
| smb2_get_uint8 | function | `int smb2_get_uint8(struct smb2_iovec *iov, int offset, uint8_t *value);` | Include | 内部 wire buffer 读取基础接口。 |
| smb2_get_uint16 | function | `int smb2_get_uint16(struct smb2_iovec *iov, int offset, uint16_t *value);` | Include | 内部 little-endian wire buffer 读取接口。 |
| smb2_get_uint32 | function | `int smb2_get_uint32(struct smb2_iovec *iov, int offset, uint32_t *value);` | Include | 内部 little-endian wire buffer 读取接口。 |
| smb2_get_uint64 | function | `int smb2_get_uint64(struct smb2_iovec *iov, int offset, uint64_t *value);` | Include | 内部 little-endian wire buffer 读取接口。 |
| smb2_decode_header | function | `int smb2_decode_header(struct smb2_context *smb2, struct smb2_iovec *iov, struct smb2_header *hdr);` | Include | 内部 header 解码和上下文同步入口。 |
| smb2_queue_pdu | function | `void smb2_queue_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 公开发送队列入口，CRITICAL impact，覆盖签名、加密、message-id、outqueue。 |
| smb2_get_compound_pdu | function | `struct smb2_pdu *smb2_get_compound_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 公开 compound 链遍历 API。 |
| smb2_set_pdu_status | function | `void smb2_set_pdu_status(struct smb2_context *smb2, struct smb2_pdu *pdu, int status);` | Include | 公开 PDU 状态修改 API。 |
| smb2_set_pdu_message_id | function | `void smb2_set_pdu_message_id(struct smb2_context *smb2, struct smb2_pdu *pdu, uint64_t message_id);` | Include | 公开 PDU message-id 修改 API。 |
| smb2_get_pdu_message_id | function | `uint64_t smb2_get_pdu_message_id(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 公开 PDU message-id 查询 API。 |
| smb2_get_last_request_message_id | function | `uint64_t smb2_get_last_request_message_id(struct smb2_context *smb2);` | Include | 公开最近请求 message-id 查询 API。 |
| smb2_get_last_reply_message_id | function | `uint64_t smb2_get_last_reply_message_id(struct smb2_context *smb2);` | Include | 公开最近回复 message-id 查询 API。 |
| smb2_find_pdu | function | `struct smb2_pdu *smb2_find_pdu(struct smb2_context *smb2, uint64_t message_id);` | Include | 内部 waitqueue 关联查找接口。 |
| smb2_get_fixed_reply_size | function | `int smb2_get_fixed_reply_size(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 内部按命令选择 reply fixed payload 长度。 |
| smb2_get_fixed_request_size | function | `int smb2_get_fixed_request_size(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 内部按命令选择 request fixed payload 长度。 |
| smb2_get_fixed_size | function | `int smb2_get_fixed_size(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 内部 client/server 分派 fixed payload 长度。 |
| smb2_process_reply_payload_fixed | function | `int smb2_process_reply_payload_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 内部 reply fixed payload 分派入口。 |
| smb2_process_reply_payload_variable | function | `int smb2_process_reply_payload_variable(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 内部 reply variable payload 分派入口。 |
| smb2_process_request_payload_fixed | function | `int smb2_process_request_payload_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 内部 server request fixed payload 分派入口。 |
| smb2_process_request_payload_variable | function | `int smb2_process_request_payload_variable(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 内部 server request variable payload 分派入口。 |
| smb2_process_payload_fixed | function | `int smb2_process_payload_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 内部 client/server fixed payload 总分派入口。 |
| smb2_process_payload_variable | function | `int smb2_process_payload_variable(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | 内部 client/server variable payload 总分派入口。 |
| smb2_timeout_pdus | function | `void smb2_timeout_pdus(struct smb2_context *smb2);` | Include | 内部超时扫描入口，会调用回调并释放 PDU。 |
| smb2_encode_header | function | `static void smb2_encode_header(struct smb2_context *smb2, struct smb2_iovec *iov, struct smb2_header *hdr);` | Skip | 静态 helper，仅由 `smb2_queue_pdu` 使用，行为归入发送队列 Requirement。 |
| smb2_add_to_outqueue | function | `static void smb2_add_to_outqueue(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Skip | 静态 helper，仅封装 outqueue 添加和事件更新，归入 `smb2_queue_pdu`。 |
| smb2_correlate_reply | function | `static int smb2_correlate_reply(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Skip | 静态 server reply 关联 helper，归入 `smb2_queue_pdu`。 |
| smb2_is_error_response | function | `static int smb2_is_error_response(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Skip | 静态错误判定 helper，归入 fixed-size 和 payload 分派接口。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| struct smb2_header | struct | `include/libsmb2-private.h:74` | PDU header 的协议号、credit、命令、flags、message-id、tree/session-id 和 signature 布局。 |
| struct smb2_context | struct | `include/libsmb2-private.h:141` | PDU 创建、队列、message-id、tree-id、签名、加密和超时状态来源。 |
| struct smb2_pdu | struct | `include/libsmb2-private.h` | PDU 队列节点、header、iov、payload、callback、compound、timeout、crypto 状态；具体行号待 GitNexus/源码完整回读确认。 |
| struct smb2_iovec | struct | `include/libsmb2-private.h` | wire buffer 读写接口的输入模型；具体行号待确认。 |
| SMB2_MAX_TREE_NESTING | macro | `include/libsmb2-private.h:129` | tree-id 栈上限，索引 0 不使用。 |
| smb2_tree_id | macro | `include/libsmb2-private.h:130` | 当前 tree-id 查询宏，未选择时返回 `0xdeadbeef`。 |
| MAX_CREDITS | macro | `include/libsmb2-private.h:132` | PDU credit request 计算上限。 |
| SMB2_FLAGS_SERVER_TO_REDIR | macro | `include/smb2/smb2.h:49` | 服务端回复 header flag。 |
| SMB2_FLAGS_ASYNC_COMMAND | macro | `include/smb2/smb2.h:50` | async command header flag。 |
| SMB2_FLAGS_RELATED_OPERATIONS | macro | `include/smb2/smb2.h:51` | compound 后续 PDU header flag。 |

## ADDED Requirements

### Requirement: smb2_pad_to_64bit append alignment padding
系统 MUST 在当前 I/O vector 总长度非 8 字节对齐时追加 1 到 7 个零字节，并在已对齐时返回成功且不追加数据。

#### Scenario: aligned vector returns success
- **GIVEN** `struct smb2_io_vectors` 中所有 `iov` 长度总和已经 8 字节对齐
- **WHEN** 调用 `smb2_pad_to_64bit(smb2, v)`
- **THEN** 函数返回 `0` 且不调用新增 I/O vector 路径

Trace: `lib/pdu.c:smb2_pad_to_64bit`

#### Scenario: unaligned vector appends zeros
- **GIVEN** `struct smb2_io_vectors` 中所有 `iov` 长度总和不是 8 字节对齐
- **WHEN** 调用 `smb2_pad_to_64bit(smb2, v)` 且 `smb2_add_iovector` 成功
- **THEN** 函数返回 `0` 并追加长度为 `8 - (len & 0x07)` 的零填充

Trace: `lib/pdu.c:smb2_pad_to_64bit`

### Requirement: smb2_allocate_pdu initialize outbound PDU
系统 MUST 分配并初始化 SMB2 PDU header、回调、输出 header iovec、credit、tree-id、session-id、seal 和 timeout 状态；分配或 header iovec 添加失败时 MUST 返回 `NULL` 并设置错误。

#### Scenario: successful PDU allocation
- **GIVEN** 上下文 `smb2`、命令、回调和回调数据有效，且内存和 header iovec 添加成功
- **WHEN** 调用 `smb2_allocate_pdu(smb2, command, cb, cb_data)`
- **THEN** 返回的 PDU header 包含 SMB2 magic、`SMB2_HEADER_SIZE`、命令、credit 规则、tree/session 规则、回调数据和可编码 header iovec

Trace: `lib/pdu.c:smb2_allocate_pdu`, GitNexus `context smb2_allocate_pdu`

#### Scenario: allocation failure records error
- **GIVEN** `calloc` 无法分配 `struct smb2_pdu`
- **WHEN** 调用 `smb2_allocate_pdu(smb2, command, cb, cb_data)`
- **THEN** 函数返回 `NULL` 并通过 `smb2_set_error` 记录 `Failed to allocate pdu`

Trace: `lib/pdu.c:smb2_allocate_pdu`

### Requirement: smb2_select_tree_id select connected tree
系统 MUST 仅在请求的 tree-id 已存在于上下文 tree-id 栈时更新当前 tree-id；未找到时 MUST 返回 `-1` 并设置错误。

#### Scenario: existing tree id is selected
- **GIVEN** `smb2->tree_id` 栈中存在目标 `tree_id`
- **WHEN** 调用 `smb2_select_tree_id(smb2, tree_id)`
- **THEN** 函数返回 `0` 并将 `smb2->tree_id_cur` 设置为匹配槽位

Trace: `lib/pdu.c:smb2_select_tree_id`, `include/smb2/libsmb2.h:smb2_select_tree_id`

### Requirement: smb2_get_tree_id_for_pdu resolve effective tree id
系统 MUST 对无 tree 的控制命令返回 tree-id `0`，对其他 PDU 或空 PDU 返回当前已连接 tree-id；无已连接 tree-id 时 MUST 返回 `-1`、输出 `0xdeadbeef` 并设置错误。

#### Scenario: control PDU returns zero tree id
- **GIVEN** PDU 命令是 negotiate、session setup、logoff、echo 或 tree connect
- **WHEN** 调用 `smb2_get_tree_id_for_pdu(smb2, pdu, tree_id)`
- **THEN** 函数返回 `0` 并写入 `*tree_id == 0`

Trace: `lib/pdu.c:smb2_get_tree_id_for_pdu`, `include/smb2/libsmb2.h:smb2_get_tree_id_for_pdu`

### Requirement: smb2_set_tree_id_for_pdu update synchronous PDU tree id
系统 MUST 对非 async 且需要 tree-id 的 PDU 写入 `pdu->header.sync.tree_id`，对 async PDU MUST 设置错误但保持返回 `0`，对空 PDU MUST 返回 `-1`。

#### Scenario: data PDU tree id is updated
- **GIVEN** PDU 非空、不是 async，并且命令不是 negotiate、session setup、logoff、echo 或 tree connect
- **WHEN** 调用 `smb2_set_tree_id_for_pdu(smb2, pdu, tree_id)`
- **THEN** 函数返回 `0` 并写入 `pdu->header.sync.tree_id`

Trace: `lib/pdu.c:smb2_set_tree_id_for_pdu`, `include/smb2/libsmb2.h:smb2_set_tree_id_for_pdu`

### Requirement: smb2_get_session_id expose context session id
系统 MUST 将 `smb2->session_id` 写入调用方提供的输出参数并返回 `0`。

#### Scenario: session id is copied
- **GIVEN** `session_id` 指向可写 `uint64_t`
- **WHEN** 调用 `smb2_get_session_id(smb2, session_id)`
- **THEN** `*session_id` 等于 `smb2->session_id` 且函数返回 `0`

Trace: `lib/pdu.c:smb2_get_session_id`, `include/smb2/libsmb2.h:smb2_get_session_id`

### Requirement: smb2_connect_tree_id push connected tree id
系统 MUST 在 tree-id 栈未达到 `SMB2_MAX_TREE_NESTING - 1` 时追加 tree-id 并选择它；栈满时 MUST 返回 `-1` 并设置错误。

#### Scenario: tree id is pushed and selected
- **GIVEN** `smb2->tree_id_top < (SMB2_MAX_TREE_NESTING - 1)`
- **WHEN** 调用 `smb2_connect_tree_id(smb2, tree_id)`
- **THEN** 函数返回 `0`、递增 `tree_id_top`、写入 tree-id 并将 `tree_id_cur` 指向新槽位

Trace: `lib/pdu.c:smb2_connect_tree_id`

### Requirement: smb2_disconnect_tree_id remove connected tree id
系统 MUST 从 tree-id 栈移除匹配项并压缩后续项；未找到时 MUST 返回 `-1` 并设置错误。

#### Scenario: tree id is removed
- **GIVEN** `smb2->tree_id` 栈中存在目标 `tree_id`
- **WHEN** 调用 `smb2_disconnect_tree_id(smb2, tree_id)`
- **THEN** 函数返回 `0`、移除该槽位、压缩后续槽位，并保证 `tree_id_cur` 不超过新的 `tree_id_top`

Trace: `lib/pdu.c:smb2_disconnect_tree_id`

### Requirement: smb2_pdu_is_compound report current receive compound state
系统 MUST 在上下文非空且当前 decoded header 的 `next_command` 非零时返回非零，否则返回 `0`。

#### Scenario: compound state is detected
- **GIVEN** `smb2` 非空且 `smb2->hdr.next_command != 0`
- **WHEN** 调用 `smb2_pdu_is_compound(smb2)`
- **THEN** 函数返回非零值

Trace: `lib/pdu.c:smb2_pdu_is_compound`, `include/smb2/libsmb2.h:smb2_pdu_is_compound`

### Requirement: smb2_add_compound_pdu link and mark compound PDUs
系统 MUST 将 `next_pdu` 附加到 compound 链尾、将当前链尾 header `next_command` 设置为其输出 iovec 总长度，并在后续 PDU header 中设置 `SMB2_FLAGS_RELATED_OPERATIONS`。

#### Scenario: next PDU is appended to chain tail
- **GIVEN** `pdu` 可能已有 compound 后继且 `next_pdu` 是待追加 PDU
- **WHEN** 调用 `smb2_add_compound_pdu(smb2, pdu, next_pdu)`
- **THEN** 函数找到链尾、设置链尾 `next_compound`、更新链尾 header offset，并更新后续 PDU flags

Trace: `lib/pdu.c:smb2_add_compound_pdu`, `include/smb2/libsmb2.h:smb2_add_compound_pdu`, GitNexus `context smb2_add_compound_pdu`

### Requirement: smb2_free_pdu release PDU resources
系统 MUST 从 outqueue 和 waitqueue 移除 PDU，递归释放 compound 后继，释放输入/输出 iovec，调用可选回调释放器，释放 payload、crypt 和 PDU 本体。

#### Scenario: PDU resources are released
- **GIVEN** PDU 可位于 outqueue、waitqueue 或 compound 链，并可携带 free callbacks、payload 和 crypt buffer
- **WHEN** 调用 `smb2_free_pdu(smb2, pdu)`
- **THEN** PDU 从相关队列移除，关联资源按源码定义释放

Trace: `lib/pdu.c:smb2_free_pdu`, `include/smb2/libsmb2.h:smb2_free_pdu`

### Requirement: smb2_set_uint8 write bounded byte
系统 MUST 在 `offset + sizeof(uint8_t)` 不超过 iovec 长度时写入字节并返回 `0`；越界时 MUST 返回 `-1`。

#### Scenario: byte write succeeds in bounds
- **GIVEN** `offset + sizeof(uint8_t) <= iov->len`
- **WHEN** 调用 `smb2_set_uint8(iov, offset, value)`
- **THEN** `iov->buf[offset]` 被设置为 `value` 且返回 `0`

Trace: `lib/pdu.c:smb2_set_uint8`

### Requirement: smb2_set_uint16 write bounded little-endian value
系统 MUST 在边界检查通过后以 little-endian 形式写入 16 位值；越界时 MUST 返回 `-1`。

#### Scenario: uint16 write succeeds in bounds
- **GIVEN** `offset + sizeof(uint16_t) <= iov->len`
- **WHEN** 调用 `smb2_set_uint16(iov, offset, value)`
- **THEN** 缓冲区对应位置包含 `htole16(value)` 且返回 `0`

Trace: `lib/pdu.c:smb2_set_uint16`

### Requirement: smb2_set_uint32 write bounded little-endian value
系统 MUST 在边界检查通过后以 little-endian 形式写入 32 位值；越界时 MUST 返回 `-1`。

#### Scenario: uint32 write succeeds in bounds
- **GIVEN** `offset + sizeof(uint32_t) <= iov->len`
- **WHEN** 调用 `smb2_set_uint32(iov, offset, value)`
- **THEN** 缓冲区对应位置包含 `htole32(value)` 且返回 `0`

Trace: `lib/pdu.c:smb2_set_uint32`

### Requirement: smb2_set_uint64 write bounded little-endian value
系统 MUST 在边界检查通过后以 little-endian 形式写入 64 位值；越界时 MUST 返回 `-1`。

#### Scenario: uint64 write succeeds in bounds
- **GIVEN** `offset + sizeof(uint64_t) <= iov->len`
- **WHEN** 调用 `smb2_set_uint64(iov, offset, value)`
- **THEN** 缓冲区对应位置包含 `htole64(value)` 且返回 `0`

Trace: `lib/pdu.c:smb2_set_uint64`

### Requirement: smb2_get_uint8 read bounded byte
系统 MUST 在边界检查通过后读取 8 位值；越界时 MUST 返回 `-1`。

#### Scenario: byte read succeeds in bounds
- **GIVEN** `offset + sizeof(uint8_t) <= iov->len`
- **WHEN** 调用 `smb2_get_uint8(iov, offset, value)`
- **THEN** `*value` 等于缓冲区对应字节且返回 `0`

Trace: `lib/pdu.c:smb2_get_uint8`

### Requirement: smb2_get_uint16 read bounded little-endian value
系统 MUST 在边界检查通过后读取 little-endian 16 位值并转换为 host endian；越界时 MUST 返回 `-1`。

#### Scenario: uint16 read succeeds in bounds
- **GIVEN** `offset + sizeof(uint16_t) <= iov->len`
- **WHEN** 调用 `smb2_get_uint16(iov, offset, value)`
- **THEN** `*value` 等于 `le16toh` 转换后的缓冲区值且返回 `0`

Trace: `lib/pdu.c:smb2_get_uint16`

### Requirement: smb2_get_uint32 read bounded little-endian value
系统 MUST 在边界检查通过后读取 little-endian 32 位值并转换为 host endian；越界时 MUST 返回 `-1`。

#### Scenario: uint32 read succeeds in bounds
- **GIVEN** `offset + sizeof(uint32_t) <= iov->len`
- **WHEN** 调用 `smb2_get_uint32(iov, offset, value)`
- **THEN** `*value` 等于 `le32toh` 转换后的缓冲区值且返回 `0`

Trace: `lib/pdu.c:smb2_get_uint32`

### Requirement: smb2_get_uint64 read bounded little-endian value
系统 MUST 在边界检查通过后读取 little-endian 64 位值并转换为 host endian；越界时 MUST 返回 `-1`。

#### Scenario: uint64 read succeeds in bounds
- **GIVEN** `offset + sizeof(uint64_t) <= iov->len`
- **WHEN** 调用 `smb2_get_uint64(iov, offset, value)`
- **THEN** `*value` 等于 `le64toh` 转换后的缓冲区值且返回 `0`

Trace: `lib/pdu.c:smb2_get_uint64`

### Requirement: smb2_decode_header parse SMB header
系统 MUST 拒绝过短 header、非 SMB2 signature 和非 negotiate SMB1 请求；有效 SMB2 header MUST 解码字段并在服务端模式保存 message-id。

#### Scenario: SMB2 header is decoded
- **GIVEN** iovec 长度至少为 `SMB2_HEADER_SIZE` 且前 4 字节是 SMB2 magic
- **WHEN** 调用 `smb2_decode_header(smb2, iov, hdr)`
- **THEN** 函数解码 header 字段、处理 async/sync union、复制 signature，并返回 `0`

Trace: `lib/pdu.c:smb2_decode_header`, GitNexus `context smb2_decode_header`

#### Scenario: SMB1 negotiate is allowed
- **GIVEN** iovec 前 4 字节是 SMB1 magic 且命令字节是 `SMB1_NEGOTIATE`
- **WHEN** 调用 `smb2_decode_header(smb2, iov, hdr)`
- **THEN** 函数清零 header、设置 `hdr->command = SMB1_NEGOTIATE` 并返回 `0`

Trace: `lib/pdu.c:smb2_decode_header`

### Requirement: smb2_queue_pdu encode and enqueue outbound PDU chain
系统 MUST 编码 compound 链中每个 PDU header，在客户端模式递增 message-id 并记录 compound 顺序，在需要签名时添加签名，在发送前执行 SMB3 加密，并将链头加入 outqueue。

#### Scenario: client PDU chain is queued
- **GIVEN** `smb2` 不是 server，PDU 链可编码，并且签名/加密条件由上下文和命令决定
- **WHEN** 调用 `smb2_queue_pdu(smb2, pdu)`
- **THEN** 每个 PDU header 被编码，`prev_compound_mid` 保留顺序，必要时添加签名，链头经过加密处理后加入 outqueue

Trace: `lib/pdu.c:smb2_queue_pdu`, `include/smb2/libsmb2.h:smb2_queue_pdu`, GitNexus `context smb2_queue_pdu`, GitNexus `impact Function:lib/pdu.c:smb2_queue_pdu`

#### Scenario: server PDU without message id is rejected
- **GIVEN** `smb2` 是 server、PDU command 不是 negotiate、且 PDU message-id 为 0
- **WHEN** 调用 `smb2_queue_pdu(smb2, pdu)`
- **THEN** 函数设置错误、释放该 PDU 并提前返回，不将其加入 outqueue

Trace: `lib/pdu.c:smb2_queue_pdu`

### Requirement: smb2_get_compound_pdu return next compound PDU
系统 MUST 在 PDU 非空且存在 `next_compound` 时返回该后继，否则返回 `NULL`。

#### Scenario: next compound PDU exists
- **GIVEN** `pdu` 非空且 `pdu->next_compound` 非空
- **WHEN** 调用 `smb2_get_compound_pdu(smb2, pdu)`
- **THEN** 函数返回 `pdu->next_compound`

Trace: `lib/pdu.c:smb2_get_compound_pdu`, `include/smb2/libsmb2.h:smb2_get_compound_pdu`

### Requirement: smb2_set_pdu_status update PDU status
系统 MUST 将传入 status 写入 `pdu->header.status`。

#### Scenario: PDU status is set
- **GIVEN** PDU 指针有效
- **WHEN** 调用 `smb2_set_pdu_status(smb2, pdu, status)`
- **THEN** `pdu->header.status` 等于传入 status

Trace: `lib/pdu.c:smb2_set_pdu_status`, `include/smb2/libsmb2.h:smb2_set_pdu_status`

### Requirement: smb2_set_pdu_message_id update PDU message id
系统 MUST 将传入 message-id 写入 `pdu->header.message_id`。

#### Scenario: PDU message id is set
- **GIVEN** PDU 指针有效
- **WHEN** 调用 `smb2_set_pdu_message_id(smb2, pdu, message_id)`
- **THEN** `pdu->header.message_id` 等于传入 message-id

Trace: `lib/pdu.c:smb2_set_pdu_message_id`, `include/smb2/libsmb2.h:smb2_set_pdu_message_id`

### Requirement: smb2_get_pdu_message_id return PDU message id
系统 MUST 在 PDU 非空时返回 `pdu->header.message_id`，PDU 为空时 MUST 返回 `0`。

#### Scenario: PDU message id is returned
- **GIVEN** PDU 指针有效
- **WHEN** 调用 `smb2_get_pdu_message_id(smb2, pdu)`
- **THEN** 返回值等于 `pdu->header.message_id`

Trace: `lib/pdu.c:smb2_get_pdu_message_id`, `include/smb2/libsmb2.h:smb2_get_pdu_message_id`

### Requirement: smb2_get_last_request_message_id return context request cursor
系统 MUST 在上下文非空时返回 `smb2->message_id`，上下文为空时 MUST 返回 `0`。

#### Scenario: last request message id is returned
- **GIVEN** `smb2` 非空
- **WHEN** 调用 `smb2_get_last_request_message_id(smb2)`
- **THEN** 返回值等于 `smb2->message_id`

Trace: `lib/pdu.c:smb2_get_last_request_message_id`, `include/smb2/libsmb2.h:smb2_get_last_request_message_id`

### Requirement: smb2_get_last_reply_message_id return decoded reply message id
系统 MUST 在上下文非空时返回 `smb2->hdr.message_id`，上下文为空时 MUST 返回 `0`。

#### Scenario: last reply message id is returned
- **GIVEN** `smb2` 非空
- **WHEN** 调用 `smb2_get_last_reply_message_id(smb2)`
- **THEN** 返回值等于 `smb2->hdr.message_id`

Trace: `lib/pdu.c:smb2_get_last_reply_message_id`, `include/smb2/libsmb2.h:smb2_get_last_reply_message_id`

### Requirement: smb2_find_pdu locate waiting request by message id
系统 MUST 遍历 waitqueue 并返回第一个 header message-id 匹配的 PDU；未找到时 MUST 返回 `NULL`。

#### Scenario: matching PDU is found
- **GIVEN** `smb2->waitqueue` 中存在 `header.message_id == message_id` 的 PDU
- **WHEN** 调用 `smb2_find_pdu(smb2, message_id)`
- **THEN** 函数返回该 PDU 指针

Trace: `lib/pdu.c:smb2_find_pdu`

### Requirement: smb2_get_fixed_reply_size map reply command sizes
系统 MUST 对错误响应返回 SMB2 error reply fixed size，对已知 reply 命令返回对应 fixed size，对未知命令返回 `-1`。

#### Scenario: known reply command returns fixed size
- **GIVEN** PDU command 是源码 switch 中列出的 SMB2 reply 命令且当前 header 不是错误响应
- **WHEN** 调用 `smb2_get_fixed_reply_size(smb2, pdu)`
- **THEN** 函数返回该命令对应的 `SMB2_*_REPLY_SIZE`

Trace: `lib/pdu.c:smb2_get_fixed_reply_size`

### Requirement: smb2_get_fixed_request_size map request command sizes
系统 MUST 对已知 request 命令返回对应 fixed size，对 unknown 命令返回 `-1`。

#### Scenario: known request command returns fixed size
- **GIVEN** PDU command 是源码 switch 中列出的 SMB2 request 命令
- **WHEN** 调用 `smb2_get_fixed_request_size(smb2, pdu)`
- **THEN** 函数返回该命令对应的 `SMB2_*_REQUEST_SIZE`

Trace: `lib/pdu.c:smb2_get_fixed_request_size`

### Requirement: smb2_get_fixed_size dispatch by context role
系统 MUST 在 server 模式使用 request fixed-size 映射，在 client 模式使用 reply fixed-size 映射。

#### Scenario: server mode dispatches request size
- **GIVEN** `smb2_is_server(smb2)` 返回非零
- **WHEN** 调用 `smb2_get_fixed_size(smb2, pdu)`
- **THEN** 返回值等于 `smb2_get_fixed_request_size(smb2, pdu)`

Trace: `lib/pdu.c:smb2_get_fixed_size`

### Requirement: smb2_process_reply_payload_fixed dispatch fixed reply parser
系统 MUST 对错误响应调用 error fixed parser，对已知 reply 命令调用对应 fixed parser，对未列出命令返回 `0`。

#### Scenario: fixed reply command dispatches parser
- **GIVEN** 当前 header 不是错误响应且 PDU command 是源码 switch 中列出的 reply 命令
- **WHEN** 调用 `smb2_process_reply_payload_fixed(smb2, pdu)`
- **THEN** 函数返回对应 `smb2_process_*_fixed` 处理器的返回值

Trace: `lib/pdu.c:smb2_process_reply_payload_fixed`

### Requirement: smb2_process_reply_payload_variable dispatch variable reply parser
系统 MUST 对错误响应调用 error variable parser，对有 variable payload 的 reply 命令调用对应 parser，对无 variable payload 的命令返回 `0`。

#### Scenario: variable reply command dispatches parser
- **GIVEN** 当前 header 不是错误响应且 PDU command 是源码 switch 中映射到 variable parser 的 reply 命令
- **WHEN** 调用 `smb2_process_reply_payload_variable(smb2, pdu)`
- **THEN** 函数返回对应 `smb2_process_*_variable` 处理器的返回值

Trace: `lib/pdu.c:smb2_process_reply_payload_variable`

### Requirement: smb2_process_request_payload_fixed dispatch fixed request parser
系统 MUST 对已知 server request 命令调用对应 fixed request parser，对未知命令 MUST 设置错误并返回 `-1`。

#### Scenario: fixed request command dispatches parser
- **GIVEN** PDU command 是源码 switch 中映射到 fixed request parser 的命令
- **WHEN** 调用 `smb2_process_request_payload_fixed(smb2, pdu)`
- **THEN** 函数返回对应 `smb2_process_*_request_fixed` 处理器的返回值

Trace: `lib/pdu.c:smb2_process_request_payload_fixed`

### Requirement: smb2_process_request_payload_variable dispatch variable request parser
系统 MUST 对已知 server request 命令调用对应 variable request parser 或返回 `0` 表示无 variable payload；未知命令 MUST 设置错误并返回 `-1`。

#### Scenario: variable request command dispatches parser
- **GIVEN** PDU command 是源码 switch 中映射到 variable request parser 的命令
- **WHEN** 调用 `smb2_process_request_payload_variable(smb2, pdu)`
- **THEN** 函数返回对应 `smb2_process_*_request_variable` 处理器的返回值

Trace: `lib/pdu.c:smb2_process_request_payload_variable`

### Requirement: smb2_process_payload_fixed dispatch fixed payload by role
系统 MUST 在 server 模式处理 request fixed payload，在 client 模式处理 reply fixed payload。

#### Scenario: fixed payload dispatches by role
- **GIVEN** `smb2` 上下文处于 server 或 client 角色
- **WHEN** 调用 `smb2_process_payload_fixed(smb2, pdu)`
- **THEN** 返回值来自对应 request 或 reply fixed payload 分派函数

Trace: `lib/pdu.c:smb2_process_payload_fixed`, GitNexus `context smb2_process_payload_fixed`

### Requirement: smb2_process_payload_variable dispatch variable payload by role
系统 MUST 在 server 模式处理 request variable payload，在 client 模式处理 reply variable payload。

#### Scenario: variable payload dispatches by role
- **GIVEN** `smb2` 上下文处于 server 或 client 角色
- **WHEN** 调用 `smb2_process_payload_variable(smb2, pdu)`
- **THEN** 返回值来自对应 request 或 reply variable payload 分派函数

Trace: `lib/pdu.c:smb2_process_payload_variable`

### Requirement: smb2_timeout_pdus expire queued PDUs
系统 MUST 扫描 outqueue 和 waitqueue，针对已设置 timeout 且过期的 PDU 调用回调并释放 PDU。

#### Scenario: expired queued PDU times out
- **GIVEN** outqueue 或 waitqueue 中的 PDU 设置了 timeout 且 timeout 小于当前 `time(NULL)`
- **WHEN** 调用 `smb2_timeout_pdus(smb2)`
- **THEN** 该 PDU 从队列移除，回调收到 `SMB2_STATUS_IO_TIMEOUT`、`NULL` command data 和原始 cb_data，并释放该 PDU

Trace: `lib/pdu.c:smb2_timeout_pdus`, GitNexus `context smb2_timeout_pdus`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_queue_pdu` server 分支在循环中多处使用链头 `pdu` 而非当前迭代 `p`，这是有意只校验/设置链头，还是 compound server reply 的潜在缺陷？ | smb2_queue_pdu | 源码行为明确但设计意图未由注释或测试确认。 |
| Q-002 | `smb2_decode_header` 调用 `smb2_select_tree_id` 的返回值被忽略，未知 tree-id 请求是否允许继续处理？ | smb2_decode_header | 注释含 TODO，错误传播语义待确认。 |
| Q-003 | `smb2_set_tree_id_for_pdu` 对 async PDU 设置错误但返回 `0` 是否为兼容行为？ | smb2_set_tree_id_for_pdu | 公开头注释描述 `-errno`，实现返回值不同。 |
| Q-004 | `smb2_get_tree_id_for_pdu` 和 `smb2_get_session_id` 对空输出指针是否要求调用方保证非空？ | smb2_get_tree_id_for_pdu, smb2_get_session_id | 源码未做空指针检查。 |
| Q-005 | `struct smb2_pdu` 与 `struct smb2_iovec` 的公开/内部字段行号需在后续批次完整归属到 `include/libsmb2-private.h` 或 `include/smb2/smb2.h`。 | file-level | 当前 worker 只修改 `lib/pdu.c` spec，保留跨文件数据模型细节到后续 header spec 回读。 |
| Q-006 | GitNexus public API query 返回大量跨文件候选并发生内容截断，未逐一消歧所有 private helper 的调用者测试归属。 | file-level | 为避免消息和 spec 过载，本 spec 记录核心公开/跨文件接口，低层分派细节以后续命令文件 spec 补足。 |
