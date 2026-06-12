# lib/smb2-cmd-notify-change.c Specification

## Source Context

- Source: `lib/smb2-cmd-notify-change.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context reports callers in `lib/libsmb2.c:smb2_notify_change_filehandle_async`, `lib/libsmb2.c:smb2_change_notify_request_cb`, `lib/pdu.c:smb2_process_reply_payload_fixed`, `lib/pdu.c:smb2_process_reply_payload_variable`, and `lib/pdu.c:smb2_process_request_payload_fixed`; parser helpers call `smb2_set_error`, `smb2_get_uint16`, and `smb2_get_uint32`.
- Build/Compile Context: C project; conditional includes use `HAVE_CONFIG_H`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H`; `_GNU_SOURCE` is defined locally when absent.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_change_notify_request | function | static int smb2_encode_change_notify_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_change_notify_request *req) | Skip | 静态 helper，仅服务 `smb2_cmd_change_notify_async` 的请求缓冲区编码，无独立跨文件契约。 |
| smb2_cmd_change_notify_async | function | struct smb2_pdu *smb2_cmd_change_notify_async(struct smb2_context *smb2, struct smb2_change_notify_request *req, smb2_command_cb cb, void *cb_data) | Include | RAW 头文件声明的跨模块 PDU 构造入口，被客户端 notify-change API 调用。 |
| smb2_encode_change_notify_reply | function | static int smb2_encode_change_notify_reply(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_change_notify_reply *rep) | Skip | 静态 helper，仅服务 `smb2_cmd_change_notify_reply_async` 的服务端回复缓冲区编码，无独立跨文件契约。 |
| smb2_cmd_change_notify_reply_async | function | struct smb2_pdu *smb2_cmd_change_notify_reply_async(struct smb2_context *smb2, struct smb2_change_notify_reply *rep, smb2_command_cb cb, void *cb_data) | Include | RAW 头文件声明的跨模块服务端回复 PDU 构造入口，被 change-notify 请求回调调用。 |
| smb2_process_change_notify_fixed | function | int smb2_process_change_notify_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | 私有头文件声明的回复 fixed payload 解析入口，由 PDU 分发器按 SMB2_CHANGE_NOTIFY 调用。 |
| smb2_process_change_notify_variable | function | int smb2_process_change_notify_variable(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | 私有头文件声明的回复 variable payload 解析入口，由 PDU 分发器按 SMB2_CHANGE_NOTIFY 调用。 |
| smb2_process_change_notify_request_fixed | function | int smb2_process_change_notify_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | 私有头文件声明的服务端请求 fixed payload 解析入口，由请求 PDU 分发器调用。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_CHANGE_NOTIFY_REQUEST_SIZE | macro | include/smb2/smb2.h:1053 | 请求 fixed payload 结构大小常量，编码和解析均使用该值。 |
| SMB2_CHANGE_NOTIFY_REPLY_SIZE | macro | include/smb2/smb2.h:1071 | 回复 fixed payload 结构大小常量，编码和解析均使用该值。 |
| struct smb2_change_notify_request | struct | include/smb2/smb2.h:1064 | 请求数据模型包含 flags、output_buffer_length、file_id 和 completion_filter。 |
| struct smb2_change_notify_reply | struct | include/smb2/smb2.h:1073 | 回复数据模型包含 output_buffer_offset、output_buffer_length 和 output 指针。 |

## ADDED Requirements

### Requirement: smb2_cmd_change_notify_async request PDU construction
系统 MUST 为 change-notify 请求创建 SMB2_CHANGE_NOTIFY PDU，编码请求 fixed payload，并在任何编码或 64-bit padding 失败时释放已分配 PDU 且返回 `NULL`。

#### Scenario: successful request PDU
- **GIVEN** 调用方提供有效的 `smb2_context`、`smb2_change_notify_request`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_change_notify_async`
- **THEN** 返回的 PDU MUST 包含 SMB2_CHANGE_NOTIFY 命令、32 字节请求 fixed payload、请求 flags、output_buffer_length、file_id、completion_filter，并完成 64-bit padding

Trace: `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_async`, `lib/smb2-cmd-notify-change.c:smb2_encode_change_notify_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_change_notify_async`

#### Scenario: request PDU allocation or encoding failure
- **GIVEN** PDU 分配、请求缓冲区分配、iovector 添加或 64-bit padding 任一环节失败
- **WHEN** 调用 `smb2_cmd_change_notify_async`
- **THEN** 接口 MUST 返回 `NULL`，并且在 PDU 已分配时释放该 PDU

Trace: `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_async`, `lib/smb2-cmd-notify-change.c:smb2_encode_change_notify_request`

### Requirement: smb2_cmd_change_notify_reply_async reply PDU construction
系统 MUST 为 change-notify 回复创建 SMB2_CHANGE_NOTIFY PDU，编码回复 fixed payload，并在非 passthrough 输出打包路径设置错误后失败。

#### Scenario: zero-length reply output
- **GIVEN** `rep->output_buffer_length` 为 0
- **WHEN** 调用 `smb2_cmd_change_notify_reply_async`
- **THEN** 返回的 PDU MUST 包含 change-notify 回复 fixed payload，设置 output_buffer_offset 和 output_buffer_length，并完成 64-bit padding

Trace: `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_reply_async`, `lib/smb2-cmd-notify-change.c:smb2_encode_change_notify_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_change_notify_reply_async`

#### Scenario: passthrough reply output
- **GIVEN** `rep->output_buffer_length` 大于 0 且 `smb2->passthrough` 为真
- **WHEN** 调用 `smb2_cmd_change_notify_reply_async`
- **THEN** 接口 MUST 分配 32-bit padding 后的输出缓冲区，复制 `rep->output` 的实际长度内容，清零 padding 字节，并将 iovector 长度设为未 padding 的输出长度

Trace: `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_reply_async`, `lib/smb2-cmd-notify-change.c:smb2_encode_change_notify_reply`

#### Scenario: non-passthrough reply output
- **GIVEN** `rep->output_buffer_length` 大于 0 且 `smb2->passthrough` 为假
- **WHEN** 调用 `smb2_cmd_change_notify_reply_async`
- **THEN** 接口 MUST 设置 `Change-notify buffer packing not implemented` 错误，释放已分配 PDU，并返回 `NULL`

Trace: `lib/smb2-cmd-notify-change.c:smb2_cmd_change_notify_reply_async`, `lib/smb2-cmd-notify-change.c:smb2_encode_change_notify_reply`

### Requirement: smb2_process_change_notify_fixed reply fixed parser
系统 MUST 校验 change-notify 回复 fixed payload 的结构大小，分配回复 payload，并返回后续 variable payload 的长度。

#### Scenario: valid reply fixed payload
- **GIVEN** 当前输入 iovector 的结构大小字段等于 `SMB2_CHANGE_NOTIFY_REPLY_SIZE` 且偶数掩码后的大小等于 iovector 长度
- **WHEN** 调用 `smb2_process_change_notify_fixed`
- **THEN** 接口 MUST 分配 `struct smb2_change_notify_reply`，保存到 `pdu->payload`，解析 output_buffer_offset 和 output_buffer_length，并返回 output_buffer_length

Trace: `lib/smb2-cmd-notify-change.c:smb2_process_change_notify_fixed`, `include/libsmb2-private.h:smb2_process_change_notify_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

#### Scenario: invalid reply fixed payload size
- **GIVEN** 当前输入 iovector 的结构大小字段不等于 `SMB2_CHANGE_NOTIFY_REPLY_SIZE` 或掩码后大小不等于 iovector 长度
- **WHEN** 调用 `smb2_process_change_notify_fixed`
- **THEN** 接口 MUST 设置 unexpected-size 错误并返回 `-1`

Trace: `lib/smb2-cmd-notify-change.c:smb2_process_change_notify_fixed`

### Requirement: smb2_process_change_notify_variable reply output binding
系统 MUST 将 change-notify variable payload 的输入缓冲区绑定到已解析回复 payload 的 output 指针。

#### Scenario: reply variable payload assignment
- **GIVEN** `pdu->payload` 指向已由 fixed parser 分配的 `struct smb2_change_notify_reply`
- **WHEN** 调用 `smb2_process_change_notify_variable`
- **THEN** 接口 MUST 将 `rep->output` 设置为当前输入 iovector 的缓冲区地址，并返回 0

Trace: `lib/smb2-cmd-notify-change.c:smb2_process_change_notify_variable`, `include/libsmb2-private.h:smb2_process_change_notify_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`

### Requirement: smb2_process_change_notify_request_fixed request fixed parser
系统 MUST 校验服务端收到的 change-notify 请求 fixed payload，分配请求 payload，并提取 flags、file_id 和 completion_filter 字段。

#### Scenario: valid request fixed payload
- **GIVEN** 当前输入 iovector 的结构大小字段等于 `SMB2_CHANGE_NOTIFY_REQUEST_SIZE` 且偶数掩码后的大小等于 iovector 长度
- **WHEN** 调用 `smb2_process_change_notify_request_fixed`
- **THEN** 接口 MUST 分配 `struct smb2_change_notify_request`，保存到 `pdu->payload`，解析 flags 和 completion_filter，并复制 file_id

Trace: `lib/smb2-cmd-notify-change.c:smb2_process_change_notify_request_fixed`, `include/libsmb2-private.h:smb2_process_change_notify_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

#### Scenario: invalid request fixed payload size
- **GIVEN** 当前输入 iovector 的结构大小字段不等于 `SMB2_CHANGE_NOTIFY_REQUEST_SIZE` 或掩码后大小不等于 iovector 长度
- **WHEN** 调用 `smb2_process_change_notify_request_fixed`
- **THEN** 接口 MUST 设置 unexpected-size 错误并返回 `-1`

Trace: `lib/smb2-cmd-notify-change.c:smb2_process_change_notify_request_fixed`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_encode_change_notify_reply` 使用 `SMB2_HEADER_SIZE + SMB2_CHANGE_NOTIFY_REQUEST_SIZE` 计算回复 output_buffer_offset，是否应基于 `SMB2_CHANGE_NOTIFY_REPLY_SIZE` 仍待确认。 | smb2_cmd_change_notify_reply_async | 源码行为明确，但未找到测试或协议注释解释该偏移选择。 |
| Q-002 | 请求编码失败时 `smb2_encode_change_notify_request` 在 `smb2_add_iovector` 失败后未直接释放局部分配的 `buf`，释放责任是否由 PDU 清理覆盖仍待确认。 | smb2_cmd_change_notify_async | 源码只设置错误并返回 -1，PDU 释放路径可能释放已挂接资源，但 iovector 添加失败的所有权不明确。 |
| Q-003 | 解析请求 fixed payload 时未读取 `output_buffer_length` 字段，服务端 handler 是否依赖该字段或是否应保持为零仍待确认。 | smb2_process_change_notify_request_fixed | `struct smb2_change_notify_request` 包含 output_buffer_length，但当前 parser 只解析 flags、file_id 和 completion_filter。 |
