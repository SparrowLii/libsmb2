# lib/smb2-cmd-error.c Specification

## Source Context

- Source: `lib/smb2-cmd-error.c`
- Related Headers: `include/smb2/smb2.h`, `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/libsmb2.h`, `include/libsmb2-private.h`, `lib/compat.h`
- Related Tests: `none`
- Related Dependencies: `smb2_cmd_error_reply_async` is called by 19 server request callbacks in `lib/libsmb2.c`; `smb2_process_error_fixed` is called by `lib/pdu.c:smb2_process_reply_payload_fixed`; `smb2_process_error_variable` is called by `lib/pdu.c:smb2_process_reply_payload_variable`; error reply encoding depends on `smb2_allocate_pdu`, `smb2_add_iovector`, integer field setters, `smb2_pad_to_64bit`, `smb2_free_pdu`, and `smb2_set_error`.
- Build/Compile Context: C project; includes `config.h` when `HAVE_CONFIG_H` is defined, defines `_GNU_SOURCE` if absent, conditionally includes standard headers by configure probes, and depends on SMB2 protocol constants and internal PDU helpers.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_error_reply | function | `static int smb2_encode_error_reply(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_error_reply *rep);` | Skip | 文件内部编码 helper，仅由 `smb2_cmd_error_reply_async` 调用，错误与资源语义归属到公开 reply builder。 |
| smb2_cmd_error_reply_async | function | `struct smb2_pdu *smb2_cmd_error_reply_async(struct smb2_context *smb2, struct smb2_error_reply *rep, uint8_t causing_command, int status, smb2_command_cb cb, void *cb_data);` | Include | `include/smb2/libsmb2-raw.h` 公开声明的 SMB2 error response PDU builder，被多种 server request callback 直接调用。 |
| smb2_process_error_fixed | function | `int smb2_process_error_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | `include/libsmb2-private.h` 声明的内部回复解析入口，被通用固定 payload 分派调用并承担错误回复结构校验和 payload 分配。 |
| smb2_process_error_variable | function | `int smb2_process_error_variable(struct smb2_context *smb2, struct smb2_pdu *pdu);` | Include | `include/libsmb2-private.h` 声明的内部 variable payload 解析入口，被通用 variable payload 分派调用并设置 error data 指针。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_ERROR_REPLY_SIZE | macro | `include/smb2/smb2.h:40` | SMB2 error reply 固定结构大小为 9；固定 payload 读取使用 `SMB2_ERROR_REPLY_SIZE & 0xfffe`，编码字段写入 9。 |
| struct smb2_error_reply | struct | `include/smb2/smb2.h:42` | 保存 `error_context_count`、`byte_count` 和指向 variable error data 的 `error_data`。 |

## ADDED Requirements

### Requirement: smb2_cmd_error_reply_async build SMB2 error response PDU
系统 MUST 为指定 causing command 和 status 构造 SMB2 error response PDU，并 MUST 在分配、编码或 64-bit padding 失败时释放已分配 PDU 后返回 `NULL`。

#### Scenario: Successful error reply construction
- **GIVEN** 调用方提供有效 `smb2_context`、`smb2_error_reply`、causing command、status、回调和回调数据。
- **WHEN** 调用方调用 `smb2_cmd_error_reply_async(smb2, rep, causing_command, status, cb, cb_data)`，且 PDU 分配、error reply 编码和 64-bit padding 均成功。
- **THEN** 函数返回新建 PDU，PDU header status 等于输入 status，输出 iovec 包含 `SMB2_ERROR_REPLY_SIZE`、`rep->error_context_count` 和 `rep->byte_count` 字段。

Trace: `lib/smb2-cmd-error.c:smb2_cmd_error_reply_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_error_reply_async`

#### Scenario: Allocation or encoding failure
- **GIVEN** PDU 分配、error reply buffer 分配、iovector 添加或 64-bit padding 任一步失败。
- **WHEN** 调用方调用 `smb2_cmd_error_reply_async(smb2, rep, causing_command, status, cb, cb_data)`。
- **THEN** 函数返回 `NULL`，并在已分配 PDU 后发生失败时释放该 PDU。

Trace: `lib/smb2-cmd-error.c:smb2_cmd_error_reply_async`, `lib/smb2-cmd-error.c:smb2_encode_error_reply`

### Requirement: smb2_process_error_fixed validate and decode fixed error reply
系统 MUST 只接受固定结构大小为 `SMB2_ERROR_REPLY_SIZE` 且低位对齐长度匹配当前 iovec length 的 error reply，并 MUST 在成功时分配 payload、解码 fixed 字段并返回 `byte_count`。

#### Scenario: Valid fixed error payload
- **GIVEN** 当前输入 iovec 的固定区域包含 struct size `SMB2_ERROR_REPLY_SIZE`，且 `(struct_size & 0xfffe)` 等于 iovec length。
- **WHEN** `lib/pdu.c:smb2_process_reply_payload_fixed` 分派调用 `smb2_process_error_fixed(smb2, pdu)`。
- **THEN** 函数分配 `struct smb2_error_reply` 到 `pdu->payload`，从 offset 2 解码 `error_context_count`，从 offset 4 解码 `byte_count`，并返回 `byte_count`。

Trace: `lib/smb2-cmd-error.c:smb2_process_error_fixed`, `include/libsmb2-private.h:smb2_process_error_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

#### Scenario: Invalid fixed error payload size
- **GIVEN** 当前输入 iovec 的 struct size 不等于 `SMB2_ERROR_REPLY_SIZE`，或 `(struct_size & 0xfffe)` 不等于 iovec length。
- **WHEN** `smb2_process_error_fixed(smb2, pdu)` 解析该 fixed payload。
- **THEN** 函数设置上下文错误消息并返回 `-1`，且不分配 error reply payload。

Trace: `lib/smb2-cmd-error.c:smb2_process_error_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

#### Scenario: Payload allocation failure
- **GIVEN** fixed payload size 校验通过，但分配 `struct smb2_error_reply` 失败。
- **WHEN** `smb2_process_error_fixed(smb2, pdu)` 继续处理 payload。
- **THEN** 函数设置上下文错误消息 `Failed to allocate error reply` 并返回 `-1`。

Trace: `lib/smb2-cmd-error.c:smb2_process_error_fixed`

### Requirement: smb2_process_error_variable attach variable error data
系统 MUST 将当前 variable payload iovec buffer 的起始地址保存为已解析 error reply 的 `error_data`，并 MUST 在完成赋值后返回 `0`。

#### Scenario: Variable error payload attachment
- **GIVEN** `pdu->payload` 已由 fixed 阶段设置为 `struct smb2_error_reply`，且当前输入 iovec 表示 error reply variable payload。
- **WHEN** `lib/pdu.c:smb2_process_reply_payload_variable` 分派调用 `smb2_process_error_variable(smb2, pdu)`。
- **THEN** 函数将 `rep->error_data` 设置为 `&iov->buf[0]`，并返回 `0`。

Trace: `lib/smb2-cmd-error.c:smb2_process_error_variable`, `include/libsmb2-private.h:smb2_process_error_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_encode_error_reply` 中 TODO 标注的 error data 是否需要根据 `rep->byte_count` 编码 variable error data？ | smb2_cmd_error_reply_async | 源码只写 fixed 字段，注释 `TODO - handle error data?` 表明 variable error data 编码语义未确认。 |
| Q-002 | `smb2_process_error_variable` 在 `pdu->payload` 为 `NULL` 或 fixed 阶段失败后被调用时是否存在调用方前置保证？ | smb2_process_error_variable | 源码直接解引用 `pdu->payload`，未在当前函数内做空指针防护。 |
| Q-003 | `smb2_process_error_fixed` 返回 `byte_count` 是否总是用于驱动后续 variable payload 读取长度？ | smb2_process_error_fixed | GitNexus 显示由 `lib/pdu.c` 固定 payload 分派调用，但完整长度消费契约需结合 PDU 读取流程确认。 |
