# lib/smb2-cmd-set-info.c Specification

## Source Context

- Source: `lib/smb2-cmd-set-info.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context reports callers from `lib/libsmb2.c` for `smb2_cmd_set_info_async` and `smb2_cmd_set_info_reply_async`; request/reply parsers are dispatched from `lib/pdu.c`.
- Build/Compile Context: C library source built by `lib/CMakeLists.txt`; compile-time includes depend on `HAVE_CONFIG_H`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_set_info_request | function | static int smb2_encode_set_info_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_set_info_request *req) | Include | 内部编码器承载 SET_INFO 请求头、数据缓冲区、passthrough 和错误路径语义，影响公开 PDU 构造接口。 |
| smb2_cmd_set_info_async | function | struct smb2_pdu *smb2_cmd_set_info_async(struct smb2_context *smb2, struct smb2_set_info_request *req, smb2_command_cb cb, void *cb_data) | Include | 头文件声明的 RAW SET_INFO 客户端构造入口，被 truncate、rename 和 ftruncate 流程调用。 |
| smb2_encode_set_info_reply | function | static int smb2_encode_set_info_reply(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_set_info_request *req) | Include | 内部回复编码器承载服务端 SET_INFO 成功响应的结构大小和分配失败语义。 |
| smb2_cmd_set_info_reply_async | function | struct smb2_pdu *smb2_cmd_set_info_reply_async(struct smb2_context *smb2, struct smb2_set_info_request *req, smb2_command_cb cb, void *cb_data) | Include | 头文件声明的 RAW SET_INFO 回复构造入口，被服务端 set-info request callback 调用。 |
| smb2_process_set_info_fixed | function | int smb2_process_set_info_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | 私有 PDU 分发入口，定义 SET_INFO 成功回复 fixed parser 无 payload 行为。 |
| smb2_process_set_info_request_fixed | function | int smb2_process_set_info_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | 私有服务端请求 fixed parser，解析 wire header、分配 payload 并返回 variable 长度。 |
| smb2_process_set_info_request_variable | function | int smb2_process_set_info_request_variable(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | 私有服务端请求 variable parser，定义 passthrough-only buffer 归属和非 passthrough 错误。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_SET_INFO_REQUEST_SIZE | macro | include/smb2/smb2.h:720 | SET_INFO 请求固定结构大小为 33，编码时按偶数长度分配 header 缓冲。 |
| struct smb2_set_info_request | struct | include/smb2/smb2.h:722 | 携带 info type、file info class、buffer 长度/偏移、additional information、file id 和 input_data。 |
| SMB2_SET_INFO_REPLY_SIZE | macro | include/smb2/smb2.h:732 | SET_INFO 成功回复固定结构大小为 2，回复编码器写入该结构大小。 |

## ADDED Requirements

### Requirement: smb2_encode_set_info_request SET_INFO request encoding
系统 MUST 为 SET_INFO 请求生成 SMB2_SET_INFO 头部，并按非 passthrough 支持的 file information class 编码调用方可观察的输入数据。

#### Scenario: encode supported file information request
- **GIVEN** `req->info_type` 为 `SMB2_0_INFO_FILE` 且 `req->file_info_class` 为 basic、end-of-file、rename 或 disposition 之一
- **WHEN** `smb2_encode_set_info_request` 编码请求
- **THEN** 输出 PDU MUST 包含 SET_INFO 请求 header、原始 file id、对应 buffer length 和按 class 编码的数据 iovec

Trace: `lib/smb2-cmd-set-info.c:smb2_encode_set_info_request`

#### Scenario: passthrough preserves caller supplied buffer
- **GIVEN** `smb2->passthrough` 已启用且 `req->buffer_length` 可为零或非零
- **WHEN** `smb2_encode_set_info_request` 编码请求
- **THEN** 输出 PDU MUST 使用调用方提供的 `input_data`、`buffer_length` 和 `buffer_offset`，并在非零长度时追加 passthrough data iovec

Trace: `lib/smb2-cmd-set-info.c:smb2_encode_set_info_request`

#### Scenario: reject unsupported set information class
- **GIVEN** 请求不是支持的 `SMB2_0_INFO_FILE` class 组合
- **WHEN** `smb2_encode_set_info_request` 编码请求
- **THEN** 函数 MUST 设置错误信息并返回 `-1`

Trace: `lib/smb2-cmd-set-info.c:smb2_encode_set_info_request`

### Requirement: smb2_cmd_set_info_async client PDU construction
系统 MUST 将 SET_INFO 请求编码为可排队的 `SMB2_SET_INFO` PDU，并在编码或对齐失败时释放已分配 PDU。

#### Scenario: construct set-info client pdu
- **GIVEN** PDU 分配、SET_INFO 请求编码和 64-bit padding 均成功
- **WHEN** `smb2_cmd_set_info_async` 被调用
- **THEN** 函数 MUST 返回包含 `SMB2_SET_INFO` 命令、callback 和 callback data 的 PDU

Trace: `lib/smb2-cmd-set-info.c:smb2_cmd_set_info_async`, `lib/libsmb2.c:smb2_truncate_async`, `lib/libsmb2.c:smb2_rename_async`, `lib/libsmb2.c:smb2_ftruncate_async`

#### Scenario: fail client pdu construction
- **GIVEN** PDU 分配、请求编码或 64-bit padding 失败
- **WHEN** `smb2_cmd_set_info_async` 被调用
- **THEN** 函数 MUST return `NULL` and release any PDU allocated before the failing encode or padding step

Trace: `lib/smb2-cmd-set-info.c:smb2_cmd_set_info_async`

### Requirement: smb2_encode_set_info_reply SET_INFO reply encoding
系统 MUST 为 SET_INFO 成功响应生成仅包含固定回复结构的 SMB2_SET_INFO reply payload。

#### Scenario: encode set-info reply header
- **GIVEN** 输出 iovec 分配成功
- **WHEN** `smb2_encode_set_info_reply` 编码回复
- **THEN** 回复 PDU MUST 包含长度为 `SMB2_SET_INFO_REPLY_SIZE & 0xfffffffe` 的 buffer，并在偏移 0 写入 `SMB2_SET_INFO_REPLY_SIZE`

Trace: `lib/smb2-cmd-set-info.c:smb2_encode_set_info_reply`

#### Scenario: fail reply allocation
- **GIVEN** reply header buffer 或 iovec 分配失败
- **WHEN** `smb2_encode_set_info_reply` 编码回复
- **THEN** 函数 MUST 设置错误信息并返回 `-1`

Trace: `lib/smb2-cmd-set-info.c:smb2_encode_set_info_reply`

### Requirement: smb2_cmd_set_info_reply_async server reply PDU construction
系统 MUST 将服务端 SET_INFO 成功处理结果编码为可排队的 `SMB2_SET_INFO` reply PDU。

#### Scenario: construct set-info reply pdu
- **GIVEN** PDU 分配、reply 编码和 64-bit padding 均成功
- **WHEN** `smb2_cmd_set_info_reply_async` 被调用
- **THEN** 函数 MUST 返回包含 `SMB2_SET_INFO` 命令、callback 和 callback data 的 reply PDU

Trace: `lib/smb2-cmd-set-info.c:smb2_cmd_set_info_reply_async`, `lib/libsmb2.c:smb2_set_info_request_cb`

#### Scenario: fail reply pdu construction
- **GIVEN** PDU 分配、reply 编码或 64-bit padding 失败
- **WHEN** `smb2_cmd_set_info_reply_async` 被调用
- **THEN** 函数 MUST return `NULL` and release any PDU allocated before the failing encode or padding step

Trace: `lib/smb2-cmd-set-info.c:smb2_cmd_set_info_reply_async`

### Requirement: smb2_process_set_info_fixed reply fixed parser
系统 MUST treat successful SET_INFO replies as having no decoded payload beyond fixed dispatch success.

#### Scenario: accept set-info reply fixed payload
- **GIVEN** PDU dispatch selects `SMB2_SET_INFO` reply fixed parser
- **WHEN** `smb2_process_set_info_fixed` 被调用
- **THEN** 函数 MUST return `0` without allocating payload or reading additional fields

Trace: `lib/smb2-cmd-set-info.c:smb2_process_set_info_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

### Requirement: smb2_process_set_info_request_fixed request fixed parser
系统 MUST validate the SET_INFO request fixed structure before exposing parsed fields through `pdu->payload`.

#### Scenario: parse valid set-info request header
- **GIVEN** 输入 iovec 的结构大小为 `SMB2_SET_INFO_REQUEST_SIZE` 且偶数化结构大小等于 iovec length
- **WHEN** `smb2_process_set_info_request_fixed` 解析 fixed payload
- **THEN** 函数 MUST allocate `struct smb2_set_info_request`, store it in `pdu->payload`, populate fixed fields and file id, and return `req->buffer_length`

Trace: `lib/smb2-cmd-set-info.c:smb2_process_set_info_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

#### Scenario: reject invalid set-info request header
- **GIVEN** 输入 iovec 的结构大小或 fixed payload length 不符合 SET_INFO 请求格式
- **WHEN** `smb2_process_set_info_request_fixed` 解析 fixed payload
- **THEN** 函数 MUST 设置错误信息并返回 `-1` without storing a request payload

Trace: `lib/smb2-cmd-set-info.c:smb2_process_set_info_request_fixed`

### Requirement: smb2_process_set_info_request_variable request variable parser
系统 MUST expose SET_INFO request variable data only when passthrough parsing is enabled.

#### Scenario: attach passthrough request buffer
- **GIVEN** `pdu->payload` contains a parsed `struct smb2_set_info_request` and `smb2->passthrough` is enabled
- **WHEN** `smb2_process_set_info_request_variable` parses variable payload
- **THEN** 函数 MUST set `req->input_data` to the current input iovec buffer and return `0`

Trace: `lib/smb2-cmd-set-info.c:smb2_process_set_info_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`

#### Scenario: reject non-passthrough variable buffer
- **GIVEN** `smb2->passthrough` is disabled
- **WHEN** `smb2_process_set_info_request_variable` parses variable payload
- **THEN** 函数 MUST 设置错误信息并返回 `-1`

Trace: `lib/smb2-cmd-set-info.c:smb2_process_set_info_request_variable`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_encode_set_info_request` 在 `smb2_add_iovector` 失败后是否转移并释放刚分配的 buffer 所有权需要确认。 | smb2_encode_set_info_request | 源码错误路径直接返回，所有权依赖 `smb2_add_iovector` 失败语义，当前文件无法确认。 |
| Q-002 | rename 编码是否应包含根目录 file id 或 28-byte layout 中保留字段的精确定义需要协议级确认。 | smb2_encode_set_info_request | 源码固定写 0 并从 offset 20 写入文件名，未在当前文件说明字段布局。 |
| Q-003 | `smb2_process_set_info_request_variable` 将 `input_data` 指向输入 iovec buffer 后的生命周期由哪个层级保证需要确认。 | smb2_process_set_info_request_variable | 当前文件只赋值不复制，释放归属依赖 PDU/input buffer 生命周期。 |
