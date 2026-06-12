# lib/smb2-cmd-echo.c Specification

## Source Context

- Source: `lib/smb2-cmd-echo.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context shows `smb2_cmd_echo_async` is called by `lib/libsmb2.c:smb2_echo_async`; `smb2_cmd_echo_reply_async` is called by `lib/libsmb2.c:smb2_echo_request_cb`; `smb2_process_echo_fixed` is called by `lib/pdu.c:smb2_process_reply_payload_fixed`; `smb2_process_echo_request_fixed` is called by `lib/pdu.c:smb2_process_request_payload_fixed`; fixed-size processors call `lib/pdu.c:smb2_get_uint16` and `lib/init.c:smb2_set_error`.
- Build/Compile Context: C project; `HAVE_CONFIG_H`, `_GNU_SOURCE`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H` conditionally affect included headers.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_echo_request | function | `static int smb2_encode_echo_request(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Skip | 静态内部编码 helper，仅服务 `smb2_cmd_echo_async` 的请求 PDU 构造，外部可观察契约归属到调用接口。 |
| smb2_cmd_echo_async | function | `struct smb2_pdu *smb2_cmd_echo_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data)` | Include | 原始 SMB2 ECHO 请求构造入口声明在 `include/smb2/libsmb2-raw.h`，由高层 echo API 调用并返回调用方可发送的 PDU。 |
| smb2_encode_echo_reply | function | `static int smb2_encode_echo_reply(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Skip | 静态内部编码 helper，仅服务 `smb2_cmd_echo_reply_async` 的回复 PDU 构造，外部可观察契约归属到调用接口。 |
| smb2_cmd_echo_reply_async | function | `struct smb2_pdu *smb2_cmd_echo_reply_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data)` | Include | 原始 SMB2 ECHO 回复构造入口声明在 `include/smb2/libsmb2-raw.h`，由服务端请求回调路径调用并返回调用方可发送的 PDU。 |
| smb2_process_echo_fixed | function | `int smb2_process_echo_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有 PDU 固定段解析入口声明在 `include/libsmb2-private.h`，由回复解析分发调用并定义 ECHO reply 尺寸校验错误语义。 |
| smb2_process_echo_request_fixed | function | `int smb2_process_echo_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有 PDU 固定段解析入口声明在 `include/libsmb2-private.h`，由请求解析分发调用并定义 ECHO request 尺寸校验与 payload 分配语义。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_ECHO_REQUEST_SIZE | macro | `include/smb2/smb2.h:412`, `include/smb2/smb2.h:1235` | ECHO request 固定段结构大小为 4 字节，本文件用于编码与请求解析尺寸校验。 |
| SMB2_ECHO_REPLY_SIZE | macro | `include/smb2/smb2.h:1236` | ECHO reply 固定段结构大小为 4 字节，本文件用于编码与回复解析尺寸校验。 |
| struct smb2_echo_request | struct | `include/smb2/smb2.h:414` | 请求解析成功时为 `pdu->payload` 分配该结构；当前公开字段仅包含 `reserved`。 |

## ADDED Requirements

### Requirement: smb2_cmd_echo_async build echo request PDU
系统 MUST 为异步 SMB2 ECHO 请求构造一个命令为 `SMB2_ECHO` 的 PDU，并在固定段中写入 `SMB2_ECHO_REQUEST_SIZE`；如果 PDU 分配、固定段缓冲区分配、iovector 添加或 64-bit padding 失败，系统 MUST 释放已分配的 PDU 并返回 `NULL`。

#### Scenario: 成功构造 echo request
- **GIVEN** 调用方提供有效的 `smb2_context`、回调函数和回调数据
- **WHEN** 调用 `smb2_cmd_echo_async` 构造 ECHO 请求 PDU
- **THEN** 返回值 MUST 是命令码为 `SMB2_ECHO`、输出固定段大小字段为 `SMB2_ECHO_REQUEST_SIZE` 且已执行 64-bit padding 的 PDU

Trace: `lib/smb2-cmd-echo.c:smb2_cmd_echo_async`, `lib/smb2-cmd-echo.c:smb2_encode_echo_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_echo_async`

#### Scenario: request 构造失败释放 PDU
- **GIVEN** PDU 已分配但 echo request 编码或 64-bit padding 返回失败
- **WHEN** `smb2_cmd_echo_async` 处理该失败路径
- **THEN** 系统 MUST 调用 `smb2_free_pdu` 释放该 PDU 并返回 `NULL`

Trace: `lib/smb2-cmd-echo.c:smb2_cmd_echo_async`, `lib/smb2-cmd-echo.c:smb2_encode_echo_request`

### Requirement: smb2_cmd_echo_reply_async build echo reply PDU
系统 MUST 为 SMB2 ECHO 回复构造一个命令为 `SMB2_ECHO` 的 PDU，并在固定段中写入 `SMB2_ECHO_REPLY_SIZE`；如果 PDU 分配、固定段缓冲区分配、iovector 添加或 64-bit padding 失败，系统 MUST 释放已分配的 PDU 并返回 `NULL`。

#### Scenario: 成功构造 echo reply
- **GIVEN** 服务端请求处理路径提供有效的 `smb2_context`、回调函数和回调数据
- **WHEN** 调用 `smb2_cmd_echo_reply_async` 构造 ECHO 回复 PDU
- **THEN** 返回值 MUST 是命令码为 `SMB2_ECHO`、输出固定段大小字段为 `SMB2_ECHO_REPLY_SIZE` 且已执行 64-bit padding 的 PDU

Trace: `lib/smb2-cmd-echo.c:smb2_cmd_echo_reply_async`, `lib/smb2-cmd-echo.c:smb2_encode_echo_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_echo_reply_async`

#### Scenario: reply 构造失败释放 PDU
- **GIVEN** PDU 已分配但 echo reply 编码或 64-bit padding 返回失败
- **WHEN** `smb2_cmd_echo_reply_async` 处理该失败路径
- **THEN** 系统 MUST 调用 `smb2_free_pdu` 释放该 PDU 并返回 `NULL`

Trace: `lib/smb2-cmd-echo.c:smb2_cmd_echo_reply_async`, `lib/smb2-cmd-echo.c:smb2_encode_echo_reply`

### Requirement: smb2_process_echo_fixed validate echo reply fixed segment
系统 MUST 从当前输入 iovector 的偏移 0 读取 ECHO reply 固定段大小，并且只有当大小等于 `SMB2_ECHO_REPLY_SIZE` 且 `(struct_size & 0xfffe)` 等于当前 iovector 长度时返回成功；尺寸不匹配时系统 MUST 设置错误消息并返回 `-1`。

#### Scenario: reply fixed segment size accepted
- **GIVEN** 当前输入 iovector 的固定段大小字段为 `SMB2_ECHO_REPLY_SIZE` 且掩码后的结构大小等于 iovector 长度
- **WHEN** `smb2_process_echo_fixed` 解析 ECHO reply 固定段
- **THEN** 函数 MUST 返回 `0` 且不分配额外 payload

Trace: `lib/smb2-cmd-echo.c:smb2_process_echo_fixed`, `include/libsmb2-private.h:smb2_process_echo_fixed`

#### Scenario: reply fixed segment size rejected
- **GIVEN** 当前输入 iovector 的固定段大小字段不是 `SMB2_ECHO_REPLY_SIZE` 或掩码后的结构大小不等于 iovector 长度
- **WHEN** `smb2_process_echo_fixed` 解析 ECHO reply 固定段
- **THEN** 函数 MUST 调用 `smb2_set_error` 记录 unexpected size 错误并返回 `-1`

Trace: `lib/smb2-cmd-echo.c:smb2_process_echo_fixed`, `include/libsmb2-private.h:smb2_process_echo_fixed`

### Requirement: smb2_process_echo_request_fixed validate echo request fixed segment
系统 MUST 从当前输入 iovector 的偏移 0 读取 ECHO request 固定段大小，并且只有当大小等于 `SMB2_ECHO_REQUEST_SIZE` 且 `(struct_size & 0xfffe)` 等于当前 iovector 长度时继续分配 `struct smb2_echo_request` payload；尺寸不匹配或 payload 分配失败时系统 MUST 设置错误消息并返回 `-1`。

#### Scenario: request fixed segment size accepted and payload allocated
- **GIVEN** 当前输入 iovector 的固定段大小字段为 `SMB2_ECHO_REQUEST_SIZE` 且掩码后的结构大小等于 iovector 长度
- **WHEN** `smb2_process_echo_request_fixed` 解析 ECHO request 固定段
- **THEN** 函数 MUST 分配 `struct smb2_echo_request`、把该分配结果赋值给 `pdu->payload` 并返回 `0`

Trace: `lib/smb2-cmd-echo.c:smb2_process_echo_request_fixed`, `include/libsmb2-private.h:smb2_process_echo_request_fixed`, `include/smb2/smb2.h:struct smb2_echo_request`

#### Scenario: request fixed segment size rejected
- **GIVEN** 当前输入 iovector 的固定段大小字段不是 `SMB2_ECHO_REQUEST_SIZE` 或掩码后的结构大小不等于 iovector 长度
- **WHEN** `smb2_process_echo_request_fixed` 解析 ECHO request 固定段
- **THEN** 函数 MUST 调用 `smb2_set_error` 记录 unexpected size 错误并返回 `-1`

Trace: `lib/smb2-cmd-echo.c:smb2_process_echo_request_fixed`, `include/libsmb2-private.h:smb2_process_echo_request_fixed`

#### Scenario: request payload allocation failure
- **GIVEN** ECHO request 固定段尺寸校验通过但 `malloc(sizeof(*req))` 返回 `NULL`
- **WHEN** `smb2_process_echo_request_fixed` 分配请求 payload
- **THEN** 函数 MUST 调用 `smb2_set_error` 记录 allocation failure 并返回 `-1`

Trace: `lib/smb2-cmd-echo.c:smb2_process_echo_request_fixed`, `include/libsmb2-private.h:smb2_process_echo_request_fixed`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | GitNexus impact 对四个 echo 接口按符号名查询时在声明和定义之间返回 ambiguous；是否需要按 UID 增强 impact 记录能力？ | file-level | 当前 CLI `gitnexus impact` 未暴露 UID 参数，已通过 `context --file` 确认直接调用者，但 impact 风险级别只能记录为歧义。 |
| Q-002 | `smb2_encode_echo_request` 和 `smb2_encode_echo_reply` 在 `smb2_add_iovector` 失败时未释放刚分配的 `buf`；该所有权在失败路径是否由 callee 接管？ | smb2_cmd_echo_async, smb2_cmd_echo_reply_async | 当前文件只显示失败后返回 `-1`，需要 `smb2_add_iovector` 失败路径证据确认是否存在泄漏或由下游释放。 |
