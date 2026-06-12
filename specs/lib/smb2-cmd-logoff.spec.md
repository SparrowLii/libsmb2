# lib/smb2-cmd-logoff.c Specification

## Source Context

- Source: `lib/smb2-cmd-logoff.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: GitNexus `context` found `smb2_cmd_logoff_async` called by `lib/libsmb2.c:disconnect_cb_1`, `smb2_cmd_logoff_reply_async` called by `lib/libsmb2.c:smb2_logoff_request_cb`, `smb2_process_logoff_fixed` called by `lib/pdu.c:smb2_process_reply_payload_fixed`, and `smb2_process_logoff_request_fixed` called by `lib/pdu.c:smb2_process_request_payload_fixed`. GitNexus impact reported LOW upstream risk for all four included implementation interfaces.
- Build/Compile Context: C implementation compiled with optional `HAVE_CONFIG_H`, `_GNU_SOURCE`, and platform header probes such as `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H`; C standard unknown.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_logoff_request | function | static int smb2_encode_logoff_request(struct smb2_context *smb2, struct smb2_pdu *pdu); | Skip | 静态内部编码 helper，仅服务 `smb2_cmd_logoff_async`，无独立跨文件契约。 |
| smb2_cmd_logoff_async | function | struct smb2_pdu *smb2_cmd_logoff_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data); | Include | RAW logoff 请求构造入口，公开头文件声明且会话断开流程依赖其 PDU 和失败返回语义。 |
| smb2_encode_logoff_reply | function | static int smb2_encode_logoff_reply(struct smb2_context *smb2, struct smb2_pdu *pdu); | Skip | 静态内部 reply 编码 helper，仅服务 `smb2_cmd_logoff_reply_async`，无独立跨文件契约。 |
| smb2_cmd_logoff_reply_async | function | struct smb2_pdu *smb2_cmd_logoff_reply_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data); | Include | RAW logoff reply 构造入口，公开头文件声明且 server logoff 响应路径依赖。 |
| smb2_process_logoff_fixed | function | int smb2_process_logoff_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | LOGOFF reply fixed payload 处理入口，被 PDU dispatch 跨文件调用。 |
| smb2_process_logoff_request_fixed | function | int smb2_process_logoff_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | LOGOFF request fixed payload 处理入口，被 server-side PDU dispatch 跨文件调用并分配 payload。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_LOGOFF_REQUEST_SIZE | macro | include/smb2/smb2.h:1239 | LOGOFF request fixed command data 大小为 4 字节。 |
| SMB2_LOGOFF_REPLY_SIZE | macro | include/smb2/smb2.h:1240 | LOGOFF reply fixed command data 大小为 4 字节。 |
| SMB2_LOGOFF | enum | include/smb2/smb2.h:60 | SMB2 command id，用于请求和响应 PDU 分派。 |

## ADDED Requirements

### Requirement: smb2_cmd_logoff_async build logoff request PDU
系统 MUST 构造 SMB2 LOGOFF 请求 PDU，成功时返回可排队发送的 `struct smb2_pdu *`，分配、编码或 padding 失败时返回 `NULL`。

#### Scenario: 构造 logoff 请求
- **GIVEN** 调用方提供 `struct smb2_context *smb2`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_logoff_async(smb2, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 `SMB2_LOGOFF` command，并将 fixed command data 的 structure size 写为 `SMB2_LOGOFF_REQUEST_SIZE`

Trace: `lib/smb2-cmd-logoff.c:smb2_cmd_logoff_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_logoff_async`, `include/smb2/smb2.h:SMB2_LOGOFF_REQUEST_SIZE`, `lib/libsmb2.c:disconnect_cb_1`

#### Scenario: logoff 请求构造失败释放 PDU
- **GIVEN** LOGOFF PDU 已分配但 request 编码或 64-bit padding 失败
- **WHEN** `smb2_cmd_logoff_async` 处理该失败路径
- **THEN** 函数 MUST 释放已分配 PDU 并返回 `NULL`

Trace: `lib/smb2-cmd-logoff.c:smb2_cmd_logoff_async`, `lib/smb2-cmd-logoff.c:smb2_encode_logoff_request`

### Requirement: smb2_cmd_logoff_reply_async build logoff reply PDU
系统 MUST 构造 SMB2 LOGOFF reply PDU，成功时返回可排队发送的 `struct smb2_pdu *`，分配、编码或 padding 失败时返回 `NULL`。

#### Scenario: 构造 logoff 响应
- **GIVEN** server logoff handler 接受请求并需要发送成功响应
- **WHEN** 调用 `smb2_cmd_logoff_reply_async(smb2, cb, cb_data)`
- **THEN** 返回的 PDU MUST 使用 `SMB2_LOGOFF` command，并将 fixed command data 的 structure size 写为 `SMB2_LOGOFF_REPLY_SIZE`

Trace: `lib/smb2-cmd-logoff.c:smb2_cmd_logoff_reply_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_logoff_reply_async`, `include/smb2/smb2.h:SMB2_LOGOFF_REPLY_SIZE`, `lib/libsmb2.c:smb2_logoff_request_cb`

#### Scenario: logoff 响应构造失败释放 PDU
- **GIVEN** LOGOFF reply PDU 已分配但 reply 编码或 64-bit padding 失败
- **WHEN** `smb2_cmd_logoff_reply_async` 处理该失败路径
- **THEN** 函数 MUST 释放已分配 PDU 并返回 `NULL`

Trace: `lib/smb2-cmd-logoff.c:smb2_cmd_logoff_reply_async`, `lib/smb2-cmd-logoff.c:smb2_encode_logoff_reply`

### Requirement: smb2_process_logoff_fixed accept empty logoff reply payload
系统 MUST 将 SMB2 LOGOFF reply fixed payload 处理为无附加解析成功路径，并返回 `0`。

#### Scenario: 处理 logoff reply fixed payload
- **GIVEN** PDU dispatch 在客户端 reply 路径收到 `SMB2_LOGOFF` command
- **WHEN** 调用 `smb2_process_logoff_fixed(smb2, pdu)`
- **THEN** 函数 MUST 返回 `0` 且不设置 PDU payload

Trace: `lib/smb2-cmd-logoff.c:smb2_process_logoff_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

### Requirement: smb2_process_logoff_request_fixed validate and attach logoff request payload
系统 MUST 验证 server-side LOGOFF request fixed command data 大小，并在验证通过时为 PDU 附加 `struct smb2_logoff_request` payload。

#### Scenario: 接受合法 logoff request fixed payload
- **GIVEN** 当前输入 iovector 的 structure size 字段和长度满足 LOGOFF request fixed payload 检查
- **WHEN** 调用 `smb2_process_logoff_request_fixed(smb2, pdu)`
- **THEN** 函数 MUST 分配 `struct smb2_logoff_request` 并将其保存到 `pdu->payload` 后返回 `0`

Trace: `lib/smb2-cmd-logoff.c:smb2_process_logoff_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

#### Scenario: 拒绝不匹配的 logoff request fixed payload 大小
- **GIVEN** 当前输入 iovector 的 structure size 字段或长度不满足实现中的 fixed payload 检查
- **WHEN** 调用 `smb2_process_logoff_request_fixed(smb2, pdu)`
- **THEN** 函数 MUST 设置错误信息并返回 `-1`

Trace: `lib/smb2-cmd-logoff.c:smb2_process_logoff_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

#### Scenario: logoff request payload 分配失败
- **GIVEN** fixed payload 大小检查通过但 `struct smb2_logoff_request` 分配失败
- **WHEN** 调用 `smb2_process_logoff_request_fixed(smb2, pdu)`
- **THEN** 函数 MUST 设置错误信息并返回 `-1`

Trace: `lib/smb2-cmd-logoff.c:smb2_process_logoff_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_process_logoff_request_fixed` 的大小检查使用 `SMB2_ECHO_REQUEST_SIZE` 和 echo 错误字符串，是否应视为 LOGOFF 兼容复用还是实现命名错误需要确认。 | smb2_process_logoff_request_fixed | 源码比较 `SMB2_ECHO_REQUEST_SIZE`，而同文件编码路径和协议宏定义存在 `SMB2_LOGOFF_REQUEST_SIZE`。 |
| Q-002 | LOGOFF request payload 分配后的字段初始化是否需要稳定为全零或未初始化状态需要确认。 | smb2_process_logoff_request_fixed | 源码使用 `malloc(sizeof(*req))` 后直接赋给 `pdu->payload`，未看到字段写入。 |
