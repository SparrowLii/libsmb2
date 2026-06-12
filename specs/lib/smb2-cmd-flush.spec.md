# lib/smb2-cmd-flush.c Specification

## Source Context

- Source: `lib/smb2-cmd-flush.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`, `include/smb2/libsmb2.h`
- Related Tests: `none`
- Related Dependencies: `smb2_fsync_async` in `lib/libsmb2.c`, `smb2_flush_request_cb` in `lib/libsmb2.c`, `smb2_process_reply_payload_fixed` in `lib/pdu.c`, `smb2_process_request_payload_fixed` in `lib/pdu.c`, `smb2_allocate_pdu`, `smb2_add_iovector`, `smb2_pad_to_64bit`, `smb2_free_pdu`, `smb2_get_uint16`, `smb2_set_error`
- Build/Compile Context: `CMakeLists.txt` project `libsmb2` builds C sources through `lib/CMakeLists.txt`; source includes `config.h` under `HAVE_CONFIG_H`, `_GNU_SOURCE`, standard headers under `HAVE_STDINT_H`/`HAVE_STDLIB_H`/`HAVE_STRING_H`/`STDC_HEADERS`/`HAVE_TIME_H`/`HAVE_SYS_TIME_H`, and SMB2 private/public headers.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_flush_request | function | static int smb2_encode_flush_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_flush_request *req) | Skip | 静态编码 helper，仅由本文件 `smb2_cmd_flush_async` 调用，行为归入公开 flush 命令构造契约。 |
| smb2_cmd_flush_async | function | struct smb2_pdu *smb2_cmd_flush_async(struct smb2_context *smb2, struct smb2_flush_request *req, smb2_command_cb cb, void *cb_data) | Include | 原型在 `include/smb2/libsmb2-raw.h` 声明，被 `smb2_fsync_async` 调用，构造客户端 SMB2 FLUSH PDU。 |
| smb2_encode_flush_reply | function | static int smb2_encode_flush_reply(struct smb2_context *smb2, struct smb2_pdu *pdu) | Skip | 静态编码 helper，仅由本文件 `smb2_cmd_flush_reply_async` 调用，行为归入 reply 构造契约。 |
| smb2_cmd_flush_reply_async | function | struct smb2_pdu *smb2_cmd_flush_reply_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data) | Include | 原型在 `include/smb2/libsmb2-raw.h` 声明，被服务端 flush request callback 调用，构造 SMB2 FLUSH reply PDU。 |
| smb2_process_flush_fixed | function | int smb2_process_flush_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | 私有解析入口在 `include/libsmb2-private.h` 声明，由 reply fixed payload dispatcher 调用，校验 FLUSH reply 固定区。 |
| smb2_process_flush_request_fixed | function | int smb2_process_flush_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | 私有解析入口在 `include/libsmb2-private.h` 声明，由 request fixed payload dispatcher 调用，解析服务端收到的 FLUSH request。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_FLUSH_REQUEST_SIZE | macro | include/smb2/smb2.h:400 | FLUSH request 固定结构大小为 24，编码和 request 解析均使用该值并按偶数长度校验。 |
| struct smb2_flush_request | struct | include/smb2/smb2.h:402 | FLUSH request 对外数据模型，仅包含 `smb2_file_id file_id`。 |
| SMB2_FLUSH_REPLY_SIZE | macro | include/smb2/smb2.h:418 | FLUSH reply 固定结构大小为 4，reply 编码和 reply 解析均使用该值并按偶数长度校验。 |

## ADDED Requirements

### Requirement: smb2_cmd_flush_async 构造客户端 FLUSH PDU
系统 MUST 在 `smb2_cmd_flush_async` 成功时返回命令码为 `SMB2_FLUSH` 的 PDU，并将 `SMB2_FLUSH_REQUEST_SIZE` 写入固定区起始字段、将请求的 `file_id` 复制到固定区偏移 8，且输出缓冲区 MUST 经过 64-bit padding。

#### Scenario: 成功编码 flush request
- **GIVEN** 调用方提供有效 `smb2_context`、可分配 PDU、可添加 iovector、可完成 64-bit padding，并传入包含 `file_id` 的 `struct smb2_flush_request`
- **WHEN** 调用 `smb2_cmd_flush_async(smb2, req, cb, cb_data)`
- **THEN** 返回值 MUST 为非空 PDU，PDU 命令 MUST 为 `SMB2_FLUSH`，输出固定区 MUST 记录 `SMB2_FLUSH_REQUEST_SIZE` 且包含 `req->file_id`

Trace: `lib/smb2-cmd-flush.c:smb2_cmd_flush_async`, `lib/smb2-cmd-flush.c:smb2_encode_flush_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_flush_async`, `lib/libsmb2.c:smb2_fsync_async`

#### Scenario: PDU 分配或编码失败
- **GIVEN** PDU 分配、flush request 缓冲区分配、iovector 添加或 64-bit padding 任一步失败
- **WHEN** 调用 `smb2_cmd_flush_async(smb2, req, cb, cb_data)`
- **THEN** 返回值 MUST 为 `NULL`，且已分配的 PDU MUST 在编码或 padding 失败路径释放

Trace: `lib/smb2-cmd-flush.c:smb2_cmd_flush_async`, `lib/smb2-cmd-flush.c:smb2_encode_flush_request`

### Requirement: smb2_cmd_flush_reply_async 构造服务端 FLUSH reply PDU
系统 MUST 在 `smb2_cmd_flush_reply_async` 成功时返回命令码为 `SMB2_FLUSH` 的 PDU，并将 `SMB2_FLUSH_REPLY_SIZE` 写入 reply 固定区起始字段，且输出缓冲区 MUST 经过 64-bit padding。

#### Scenario: 成功编码 flush reply
- **GIVEN** 服务端 flush handler 成功并需要构造 FLUSH reply，且 PDU 分配、iovector 添加和 padding 均成功
- **WHEN** 调用 `smb2_cmd_flush_reply_async(smb2, cb, cb_data)`
- **THEN** 返回值 MUST 为非空 PDU，PDU 命令 MUST 为 `SMB2_FLUSH`，reply 固定区 MUST 记录 `SMB2_FLUSH_REPLY_SIZE`

Trace: `lib/smb2-cmd-flush.c:smb2_cmd_flush_reply_async`, `lib/smb2-cmd-flush.c:smb2_encode_flush_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_flush_reply_async`, `lib/libsmb2.c:smb2_flush_request_cb`

#### Scenario: Reply 构造失败
- **GIVEN** PDU 分配、flush reply 缓冲区分配、iovector 添加或 64-bit padding 任一步失败
- **WHEN** 调用 `smb2_cmd_flush_reply_async(smb2, cb, cb_data)`
- **THEN** 返回值 MUST 为 `NULL`，且已分配的 PDU MUST 在编码或 padding 失败路径释放

Trace: `lib/smb2-cmd-flush.c:smb2_cmd_flush_reply_async`, `lib/smb2-cmd-flush.c:smb2_encode_flush_reply`

### Requirement: smb2_process_flush_fixed 校验 FLUSH reply 固定区
系统 MUST 在 `smb2_process_flush_fixed` 处理客户端收到的 FLUSH reply 时校验最后一个输入 iovector 的结构大小和偶数化长度均匹配 `SMB2_FLUSH_REPLY_SIZE`，不匹配时 MUST 设置错误并返回 `-1`。

#### Scenario: Reply 固定区大小有效
- **GIVEN** `smb2->in` 的最后一个 iovector 起始 `StructureSize` 为 `SMB2_FLUSH_REPLY_SIZE`，且 `(StructureSize & 0xfffe)` 等于 iovector 长度
- **WHEN** 调用 `smb2_process_flush_fixed(smb2, pdu)`
- **THEN** 函数 MUST 返回 `0`，且不向 PDU payload 附加额外 flush reply 数据

Trace: `lib/smb2-cmd-flush.c:smb2_process_flush_fixed`, `include/libsmb2-private.h:smb2_process_flush_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

#### Scenario: Reply 固定区大小无效
- **GIVEN** `StructureSize` 不等于 `SMB2_FLUSH_REPLY_SIZE` 或 `(StructureSize & 0xfffe)` 不等于 iovector 长度
- **WHEN** 调用 `smb2_process_flush_fixed(smb2, pdu)`
- **THEN** 函数 MUST 调用 `smb2_set_error` 记录 unexpected flush reply size，并返回 `-1`

Trace: `lib/smb2-cmd-flush.c:smb2_process_flush_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

### Requirement: smb2_process_flush_request_fixed 解析 FLUSH request 固定区
系统 MUST 在 `smb2_process_flush_request_fixed` 处理服务端收到的 FLUSH request 时校验固定区大小，成功后 MUST 分配 `struct smb2_flush_request`、从偏移 8 复制 `SMB2_FD_SIZE` 字节 file id，并把分配的请求对象存入 `pdu->payload`。

#### Scenario: Request 固定区大小有效
- **GIVEN** `smb2->in` 的最后一个 iovector 起始 `StructureSize` 为 `SMB2_FLUSH_REQUEST_SIZE`，`(StructureSize & 0xfffe)` 等于 iovector 长度，且请求对象分配成功
- **WHEN** 调用 `smb2_process_flush_request_fixed(smb2, pdu)`
- **THEN** 函数 MUST 返回 `0`，`pdu->payload` MUST 指向新分配的 `struct smb2_flush_request`，且其 `file_id` MUST 等于输入缓冲区偏移 8 的 `SMB2_FD_SIZE` 字节

Trace: `lib/smb2-cmd-flush.c:smb2_process_flush_request_fixed`, `include/libsmb2-private.h:smb2_process_flush_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

#### Scenario: Request 固定区大小无效或分配失败
- **GIVEN** `StructureSize` 不等于 `SMB2_FLUSH_REQUEST_SIZE`、偶数化长度不匹配，或 `struct smb2_flush_request` 分配失败
- **WHEN** 调用 `smb2_process_flush_request_fixed(smb2, pdu)`
- **THEN** 函数 MUST 返回 `-1`，大小无效时 MUST 记录 unexpected flush request size，分配失败时 MUST 记录 failed to allocate flush request

Trace: `lib/smb2-cmd-flush.c:smb2_process_flush_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_cmd_flush_async` 对 `req == NULL` 或 `req->file_id` 无效输入的调用方前置条件是否需要由公开 API 文档明确约束？ | smb2_cmd_flush_async | 实现直接解引用 `req->file_id`，源码未提供防御式检查，头文件注释未说明空指针语义。 |
| Q-002 | `smb2_process_flush_request_fixed` 分配的 `pdu->payload` 释放责任由哪个 PDU 生命周期函数承担是否需要在共享生命周期 spec 中显式追踪？ | smb2_process_flush_request_fixed | 当前文件只分配并挂载 payload，释放路径在 PDU 生命周期实现中，需跨文件确认。 |
