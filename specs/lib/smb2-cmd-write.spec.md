# lib/smb2-cmd-write.c Specification

## Source Context

- Source: `lib/smb2-cmd-write.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context shows `smb2_cmd_write_async` is called by `lib/libsmb2.c:smb2_pwrite_async`; `smb2_cmd_write_reply_async` is called by `lib/libsmb2.c:smb2_write_request_cb`; fixed and variable write processors are called by `lib/pdu.c` payload processors and depend on PDU integer accessors plus `smb2_set_error`.
- Build/Compile Context: C project with optional `HAVE_CONFIG_H`, `_GNU_SOURCE`, standard header probes, and core library build from `lib/CMakeLists.txt`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_write_request | function | static int smb2_encode_write_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_write_request *req) | Skip | 静态编码 helper，仅由 `smb2_cmd_write_async` 调用，行为归属到公开 RAW write PDU 构造入口。 |
| smb2_cmd_write_async | function | struct smb2_pdu *smb2_cmd_write_async(struct smb2_context *smb2, struct smb2_write_request *req, int pass_buf_ownership, smb2_command_cb cb, void *cb_data); | Include | RAW 头文件声明的异步 WRITE 请求构造入口，被高层 write API 调用，调用方可观察 PDU、NULL、buffer 所有权和 credit charge。 |
| smb2_encode_write_reply | function | static int smb2_encode_write_reply(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_write_reply *rep) | Skip | 静态编码 helper，仅由 `smb2_cmd_write_reply_async` 调用，行为归属到 reply PDU 构造入口。 |
| smb2_cmd_write_reply_async | function | struct smb2_pdu *smb2_cmd_write_reply_async(struct smb2_context *smb2, struct smb2_write_reply *rep, smb2_command_cb cb, void *cb_data); | Include | RAW 头文件声明的 WRITE reply 构造入口，被服务端 write request callback 调用。 |
| smb2_process_write_fixed | function | int smb2_process_write_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 私有 PDU dispatcher 入口，解析 WRITE reply 固定区并向调用方暴露 `struct smb2_write_reply` payload。 |
| IOVREQ_OFFSET_WRITE | macro | #define IOVREQ_OFFSET_WRITE (req->write_channel_info_length ? (req->write_channel_info_offset - SMB2_HEADER_SIZE - (SMB2_WRITE_REQUEST_SIZE & 0xfffe)):0) | Skip | 仅供本文件 request 固定区和变量区解析使用，无独立跨文件契约。 |
| smb2_process_write_request_fixed | function | int smb2_process_write_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 私有 PDU dispatcher 入口，解析服务端收到的 WRITE request 固定区并返回变量区所需长度。 |
| smb2_process_write_request_variable | function | int smb2_process_write_request_variable(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 私有 PDU dispatcher 入口，将服务端 WRITE request 的 channel info 和 data 指针映射到接收缓冲区。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_WRITE_REQUEST_SIZE | macro | include/smb2/smb2.h:1186 | WRITE request 固定区大小为 49，编码时按偶数固定区长度写入 iovec。 |
| SMB2_WRITEFLAG_WRITE_THROUGH | macro | include/smb2/smb2.h:1188 | WRITE request flags 可见标志，值为 `0x00000001`。 |
| SMB2_WRITEFLAG_WRITE_UNBUFFERED | macro | include/smb2/smb2.h:1189 | WRITE request flags 可见标志，值为 `0x00000002`。 |
| struct smb2_write_request | struct | include/smb2/smb2.h:1191 | WRITE request 数据模型，包含 data offset、length、offset、buffer、file id、channel info 和 flags。 |
| SMB2_WRITE_REPLY_SIZE | macro | include/smb2/smb2.h:1205 | WRITE reply 固定区大小为 17。 |
| struct smb2_write_reply | struct | include/smb2/smb2.h:1207 | WRITE reply 数据模型，包含已写入字节数 `count` 和 `remaining`。 |
| IOVREQ_OFFSET_WRITE | macro | lib/smb2-cmd-write.c:246 | 计算 request 变量区中 write data 相对位置的内部宏。 |

## ADDED Requirements

### Requirement: smb2_cmd_write_async builds write request PDU
系统 MUST 在 `smb2_cmd_write_async` 成功时返回命令码为 `SMB2_WRITE` 的 PDU，编码 WRITE 固定区字段，追加 64-bit padding 后将 `req->buf` 作为写入 payload iovec，并按 `pass_buf_ownership` 决定该 iovec 是否在释放时调用 `free`。

#### Scenario: write request PDU is encoded successfully
- **GIVEN** `smb2_allocate_pdu`、固定区编码、padding 和 payload iovec 追加均成功，且调用方提供 `struct smb2_write_request`
- **WHEN** 调用 `smb2_cmd_write_async(smb2, req, pass_buf_ownership, cb, cb_data)`
- **THEN** 返回的 PDU 包含 SMB2 WRITE 固定区、按 `req->length` 引用的 payload buffer，并在 `pass_buf_ownership` 非零时将 payload iovec 释放回调设置为 `free`

Trace: `lib/smb2-cmd-write.c:smb2_cmd_write_async`, `lib/smb2-cmd-write.c:smb2_encode_write_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_write_async`

#### Scenario: write request construction failure returns NULL
- **GIVEN** PDU 分配、固定区编码、padding 或 payload iovec 追加任一步失败
- **WHEN** 调用 `smb2_cmd_write_async(smb2, req, pass_buf_ownership, cb, cb_data)`
- **THEN** 系统 MUST 释放已分配的 PDU 并返回 `NULL`，且不会返回部分构造的 WRITE PDU

Trace: `lib/smb2-cmd-write.c:smb2_cmd_write_async`, `lib/smb2-cmd-write.c:smb2_encode_write_request`

#### Scenario: multi-credit write updates credit charge
- **GIVEN** `smb2->supports_multi_credit` 为真且 WRITE PDU 构造成功
- **WHEN** `smb2_cmd_write_async` 根据 `req->length` 完成 payload 追加
- **THEN** 系统 MUST 将 `pdu->header.credit_charge` 设置为 `(req->length - 1) / 65536 + 1`

Trace: `lib/smb2-cmd-write.c:smb2_cmd_write_async`

### Requirement: smb2_cmd_write_reply_async builds write reply PDU
系统 MUST 在 `smb2_cmd_write_reply_async` 成功时返回命令码为 `SMB2_WRITE` 的 reply PDU，编码 `SMB2_WRITE_REPLY_SIZE`、`rep->count` 和 `rep->remaining`，并在输出缓冲区上执行 64-bit padding。

#### Scenario: write reply PDU is encoded successfully
- **GIVEN** PDU 分配、reply 固定区编码和 padding 均成功，且调用方提供 `struct smb2_write_reply`
- **WHEN** 调用 `smb2_cmd_write_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 包含 WRITE reply 固定区，其中偏移 0 为 `SMB2_WRITE_REPLY_SIZE`、偏移 4 为 `rep->count`、偏移 8 为 `rep->remaining`

Trace: `lib/smb2-cmd-write.c:smb2_cmd_write_reply_async`, `lib/smb2-cmd-write.c:smb2_encode_write_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_write_reply_async`

#### Scenario: write reply construction failure returns NULL
- **GIVEN** PDU 分配、reply 固定区编码或 padding 失败
- **WHEN** 调用 `smb2_cmd_write_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 系统 MUST 释放已分配的 PDU 并返回 `NULL`

Trace: `lib/smb2-cmd-write.c:smb2_cmd_write_reply_async`, `lib/smb2-cmd-write.c:smb2_encode_write_reply`

### Requirement: smb2_process_write_fixed parses write reply fixed area
系统 MUST 在 `smb2_process_write_fixed` 接收合法 WRITE reply 固定区时分配 `struct smb2_write_reply` payload，解析 `count` 与 `remaining`，并在结构大小或分配失败时返回错误。

#### Scenario: valid write reply fixed area populates payload
- **GIVEN** 当前输入 iovec 的结构大小等于 `SMB2_WRITE_REPLY_SIZE` 且偶数化结构大小等于 iovec 长度
- **WHEN** `smb2_process_write_fixed(smb2, pdu)` 处理该固定区
- **THEN** 系统 MUST 分配 `struct smb2_write_reply`，将其保存到 `pdu->payload`，并从偏移 4 和 8 解析 `count` 与 `remaining`

Trace: `lib/smb2-cmd-write.c:smb2_process_write_fixed`, `include/libsmb2-private.h:smb2_process_write_fixed`

#### Scenario: invalid write reply fixed area is rejected
- **GIVEN** 当前输入 iovec 的结构大小不是 `SMB2_WRITE_REPLY_SIZE` 或偶数化结构大小不等于 iovec 长度
- **WHEN** `smb2_process_write_fixed(smb2, pdu)` 处理该固定区
- **THEN** 系统 MUST 设置错误消息并返回 `-1`

Trace: `lib/smb2-cmd-write.c:smb2_process_write_fixed`

### Requirement: smb2_process_write_request_fixed parses write request fixed area
系统 MUST 在 `smb2_process_write_request_fixed` 接收合法 WRITE request 固定区时分配 `struct smb2_write_request` payload，解析固定区字段，并返回后续变量区需要的字节数。

#### Scenario: valid write request fixed area populates request
- **GIVEN** 当前输入 iovec 的结构大小不大于 `SMB2_WRITE_REQUEST_SIZE`
- **WHEN** `smb2_process_write_request_fixed(smb2, pdu)` 处理该固定区
- **THEN** 系统 MUST 分配 `struct smb2_write_request`，保存到 `pdu->payload`，解析 data offset、length、file id、channel info、flags 等字段，并将 `req->buf` 初始化为 `NULL`

Trace: `lib/smb2-cmd-write.c:smb2_process_write_request_fixed`, `include/libsmb2-private.h:smb2_process_write_request_fixed`

#### Scenario: write request variable length is reported
- **GIVEN** WRITE request 固定区解析成功
- **WHEN** `req->length` 或 `req->write_channel_info_length` 非零
- **THEN** 系统 MUST 返回 channel info 偏移、channel info padding 和 write data 长度组合出的变量区需求；若二者均为零则返回 `0`

Trace: `lib/smb2-cmd-write.c:smb2_process_write_request_fixed`, `lib/smb2-cmd-write.c:IOVREQ_OFFSET_WRITE`

#### Scenario: overlapping channel info is rejected
- **GIVEN** `req->write_channel_info_length` 非零且 `req->write_channel_info_offset` 小于 SMB2 header 加 WRITE request 固定区长度
- **WHEN** `smb2_process_write_request_fixed(smb2, pdu)` 验证 channel info 位置
- **THEN** 系统 MUST 设置错误消息，清空 `pdu->payload`，释放临时 request，并返回 `-1`

Trace: `lib/smb2-cmd-write.c:smb2_process_write_request_fixed`

### Requirement: smb2_process_write_request_variable maps write request buffers
系统 MUST 在 `smb2_process_write_request_variable` 中对已解析的 WRITE request payload 执行零拷贝映射，将 channel info 和 write data 指针定位到当前输入 iovec 内部。

#### Scenario: variable area maps channel info and write data
- **GIVEN** `pdu->payload` 指向已由固定区解析创建的 `struct smb2_write_request`
- **WHEN** `smb2_process_write_request_variable(smb2, pdu)` 处理当前输入 iovec
- **THEN** 系统 MUST 将 `req->write_channel_info` 指向 `IOVREQ_OFFSET_WRITE` 计算出的变量区起点，并将 `req->buf` 指向 channel info 经过 64-bit padding 后的位置

Trace: `lib/smb2-cmd-write.c:smb2_process_write_request_variable`, `lib/smb2-cmd-write.c:IOVREQ_OFFSET_WRITE`, `include/libsmb2-private.h:smb2_process_write_request_variable`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_encode_write_request` 在 channel info passthrough 分支使用 `SMB2_READ_REQUEST_SIZE` 计算 `write_channel_info_offset` 是否为有意 wire 兼容行为？ | smb2_cmd_write_async | 源码位于 WRITE 编码路径，但偏移表达式引用 READ request size，当前文件和 GitNexus context 未提供测试或协议注释确认。 |
| Q-002 | `smb2_process_write_request_fixed` 只拒绝 `struct_size > SMB2_WRITE_REQUEST_SIZE`，没有要求等于 49 或偶数化长度匹配，是否为服务端兼容旧客户端的既有契约？ | smb2_process_write_request_fixed | 源码行为明确，但缺少测试或注释说明该宽松校验的意图。 |
