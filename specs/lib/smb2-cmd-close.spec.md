# lib/smb2-cmd-close.c Specification

## Source Context

- Source: `lib/smb2-cmd-close.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/smb2/smb2.h`, `include/libsmb2-private.h`
- Related Tests: `tests/prog_cat.c`, `tests/prog_cat_cancel.c`, `tests/metastat-0202-censored.c`, `tests/prog_ls.c`, `tests/prog_mkdir.c`
- Related Dependencies: GitNexus context shows close PDU builders are called by `lib/libsmb2.c` high-level close/stat/metadata operations and raw examples; fixed payload parsers are called by `lib/pdu.c` payload dispatch. `smb2_cmd_close_async` upstream impact is CRITICAL with 11 direct callers, 13 affected processes, and 5 affected modules; reply builder and fixed parsers are LOW risk.
- Build/Compile Context: C library source compiled through `lib/CMakeLists.txt` and Autotools; file-level conditions include `HAVE_CONFIG_H`, `_GNU_SOURCE`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_close_request | function | `static int smb2_encode_close_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_close_request *req)` | Skip | 静态内部编码 helper，仅由同文件 `smb2_cmd_close_async` 调用，外部可观察契约归属到公开 PDU builder。 |
| smb2_cmd_close_async | function | `struct smb2_pdu *smb2_cmd_close_async(struct smb2_context *smb2, struct smb2_close_request *req, smb2_command_cb cb, void *cb_data)` | Include | RAW close request PDU 构造入口，在 `include/smb2/libsmb2-raw.h` 声明并被高层 close/stat/rename 等流程调用。 |
| smb2_encode_close_reply | function | `static int smb2_encode_close_reply(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_close_reply *rep)` | Skip | 静态内部编码 helper，仅服务 close reply builder，外部可观察契约归属到 `smb2_cmd_close_reply_async`。 |
| smb2_cmd_close_reply_async | function | `struct smb2_pdu *smb2_cmd_close_reply_async(struct smb2_context *smb2, struct smb2_close_reply *rep, smb2_command_cb cb, void *cb_data)` | Include | Close reply PDU 构造入口，在 raw header 声明并由服务端 close request callback 调用。 |
| smb2_process_close_fixed | function | `int smb2_process_close_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | Close reply fixed payload parser，在私有 header 声明并由 PDU reply dispatch 调用，承担尺寸校验、payload 分配和字段解码契约。 |
| smb2_process_close_request_fixed | function | `int smb2_process_close_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | Close request fixed payload parser，在私有 header 声明并由 PDU request dispatch 调用，承担尺寸校验、payload 分配和字段解码契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_CLOSE_REQUEST_SIZE | macro | `include/smb2/smb2.h:378` | Close request fixed struct size 为 24，编码与解析均使用偶数长度 `SMB2_CLOSE_REQUEST_SIZE & 0xfffffffe` / `struct_size & 0xfffe` 校验。 |
| SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB | macro | `include/smb2/smb2.h:380` | Close request/reply flags 的公开标志值，影响是否返回关闭后的属性。 |
| struct smb2_close_request | struct | `include/smb2/smb2.h:382` | Close request 包含 `flags` 和 `file_id`，编码写入 offset 2 和 offset 8。 |
| SMB2_CLOSE_REPLY_SIZE | macro | `include/smb2/smb2.h:387` | Close reply fixed struct size 为 60，编码与解析均以偶数长度 60 校验。 |
| struct smb2_close_reply | struct | `include/smb2/smb2.h:389` | Close reply 包含 flags、时间戳、allocation size、EOF 和 file attributes 字段，解析后挂载到 `pdu->payload`。 |

## ADDED Requirements

### Requirement: smb2_cmd_close_async close request PDU construction
系统 MUST 为 SMB2 Close request 创建 `SMB2_CLOSE` PDU，编码 close request fixed payload，并在任一构造、编码或 64-bit padding 失败时返回 `NULL` 且不保留半构造 PDU。

#### Scenario: successful close request PDU
- **GIVEN** 调用方提供有效的 `smb2_context`、`smb2_close_request`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_close_async`
- **THEN** 返回值 MUST 是包含 `SMB2_CLOSE` command、24-byte fixed request payload、flags 和 file_id 字段以及 64-bit padding 后输出向量的 PDU

Trace: `lib/smb2-cmd-close.c:smb2_cmd_close_async`, `lib/smb2-cmd-close.c:smb2_encode_close_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_close_async`

#### Scenario: close request allocation or padding failure
- **GIVEN** PDU 分配、close request buffer/iovector 分配或 64-bit padding 任一步失败
- **WHEN** 调用 `smb2_cmd_close_async`
- **THEN** 函数 MUST 返回 `NULL`，并在已分配 PDU 的失败路径释放该 PDU

Trace: `lib/smb2-cmd-close.c:smb2_cmd_close_async`, `lib/smb2-cmd-close.c:smb2_encode_close_request`

### Requirement: smb2_cmd_close_reply_async close reply PDU construction
系统 MUST 为 SMB2 Close reply 创建 `SMB2_CLOSE` PDU，编码 close reply fixed payload，并在任一构造、编码或 64-bit padding 失败时返回 `NULL` 且释放已分配 PDU。

#### Scenario: successful close reply PDU
- **GIVEN** 调用方提供有效的 `smb2_context`、`smb2_close_reply`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_close_reply_async`
- **THEN** 返回值 MUST 是包含 `SMB2_CLOSE` command、60-byte fixed reply payload、flags、时间戳、allocation size、EOF 和 file attributes 字段以及 64-bit padding 后输出向量的 PDU

Trace: `lib/smb2-cmd-close.c:smb2_cmd_close_reply_async`, `lib/smb2-cmd-close.c:smb2_encode_close_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_close_reply_async`

#### Scenario: close reply allocation or padding failure
- **GIVEN** PDU 分配、close reply buffer/iovector 分配或 64-bit padding 任一步失败
- **WHEN** 调用 `smb2_cmd_close_reply_async`
- **THEN** 函数 MUST 返回 `NULL`，并在已分配 PDU 的失败路径释放该 PDU

Trace: `lib/smb2-cmd-close.c:smb2_cmd_close_reply_async`, `lib/smb2-cmd-close.c:smb2_encode_close_reply`

### Requirement: smb2_process_close_fixed close reply fixed payload parsing
系统 MUST 校验 close reply fixed payload 的结构大小和输入向量长度，成功时分配 `struct smb2_close_reply` 并按 SMB2 wire offsets 解码到 `pdu->payload`。

#### Scenario: valid close reply fixed payload
- **GIVEN** `smb2->in` 的最后一个 iovec 包含 struct size `SMB2_CLOSE_REPLY_SIZE` 且长度匹配 `(struct_size & 0xfffe)`
- **WHEN** 调用 `smb2_process_close_fixed`
- **THEN** 函数 MUST 返回 `0`，分配 close reply payload，并解码 flags、四个时间戳、allocation size、EOF 和 file attributes 字段

Trace: `lib/smb2-cmd-close.c:smb2_process_close_fixed`, `include/libsmb2-private.h:smb2_process_close_fixed`

#### Scenario: invalid close reply fixed payload size
- **GIVEN** close reply fixed payload 的 struct size 不是 `SMB2_CLOSE_REPLY_SIZE` 或输入 iovec 长度不匹配 `(struct_size & 0xfffe)`
- **WHEN** 调用 `smb2_process_close_fixed`
- **THEN** 函数 MUST 设置错误消息并返回 `-1`，且不分配 close reply payload

Trace: `lib/smb2-cmd-close.c:smb2_process_close_fixed`

#### Scenario: close reply payload allocation failure
- **GIVEN** close reply fixed payload 尺寸有效但 `malloc(sizeof(*rep))` 失败
- **WHEN** 调用 `smb2_process_close_fixed`
- **THEN** 函数 MUST 设置 `Failed to allocate close reply` 错误消息并返回 `-1`

Trace: `lib/smb2-cmd-close.c:smb2_process_close_fixed`

### Requirement: smb2_process_close_request_fixed close request fixed payload parsing
系统 MUST 校验 close request fixed payload 的结构大小和输入向量长度，成功时分配 `struct smb2_close_request` 并按 SMB2 wire offsets 解码到 `pdu->payload`。

#### Scenario: valid close request fixed payload
- **GIVEN** `smb2->in` 的最后一个 iovec 包含 struct size `SMB2_CLOSE_REQUEST_SIZE` 且长度匹配 `(struct_size & 0xfffe)`
- **WHEN** 调用 `smb2_process_close_request_fixed`
- **THEN** 函数 MUST 返回 `0`，分配 close request payload，并解码 flags 和 file_id 字段

Trace: `lib/smb2-cmd-close.c:smb2_process_close_request_fixed`, `include/libsmb2-private.h:smb2_process_close_request_fixed`

#### Scenario: invalid close request fixed payload size
- **GIVEN** close request fixed payload 的 struct size 不是 `SMB2_CLOSE_REQUEST_SIZE` 或输入 iovec 长度不匹配 `(struct_size & 0xfffe)`
- **WHEN** 调用 `smb2_process_close_request_fixed`
- **THEN** 函数 MUST 设置错误消息并返回 `-1`，且不分配 close request payload

Trace: `lib/smb2-cmd-close.c:smb2_process_close_request_fixed`

#### Scenario: close request payload allocation failure
- **GIVEN** close request fixed payload 尺寸有效但 `malloc(sizeof(*req))` 失败
- **WHEN** 调用 `smb2_process_close_request_fixed`
- **THEN** 函数 MUST 设置 `Failed to allocate close request` 错误消息并返回 `-1`

Trace: `lib/smb2-cmd-close.c:smb2_process_close_request_fixed`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_cmd_close_async` 和 `smb2_cmd_close_reply_async` 是否要求 `req`/`rep` 非空由调用方保证？ | smb2_cmd_close_async, smb2_cmd_close_reply_async | 源码直接解引用输入结构体且无空指针检查，头文件注释未声明前置条件。 |
| Q-002 | parser 成功分配的 `pdu->payload` 释放责任是否完全由通用 PDU 生命周期处理？ | smb2_process_close_fixed, smb2_process_close_request_fixed | 当前文件只分配并挂载 payload，释放路径位于其他模块，需由 PDU 生命周期 spec 归属确认。 |
