# lib/smb2-cmd-session-setup.c Specification

## Source Context

- Source: `lib/smb2-cmd-session-setup.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `tests/ntlmssp_generate_blob.c`
- Related Dependencies: GitNexus context reports callers from `lib/libsmb2.c` for PDU builders and from `lib/pdu.c` for fixed/variable payload parsers; callees include PDU allocation/free, iovector, padding, endian get/set helpers, and `smb2_set_error`.
- Build/Compile Context: C source compiled into the core `smb2` library; includes `config.h` under `HAVE_CONFIG_H` and platform header probes from `PROJECT_CONTEXT.md`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_session_setup_request | function | `static int smb2_encode_session_setup_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_session_setup_request *req)` | Skip | 文件内部编码 helper；行为通过公开 `smb2_cmd_session_setup_async` 体现。 |
| smb2_cmd_session_setup_async | function | `struct smb2_pdu *smb2_cmd_session_setup_async(struct smb2_context *smb2, struct smb2_session_setup_request *req, smb2_command_cb cb, void *cb_data)` | Include | 公开 RAW API，构造客户端 SESSION_SETUP 请求 PDU 并定义失败返回语义。 |
| smb2_encode_session_setup_reply | function | `static int smb2_encode_session_setup_reply(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_session_setup_reply *rep)` | Skip | 文件内部编码 helper；行为通过 `smb2_cmd_session_setup_reply_async` 体现。 |
| smb2_cmd_session_setup_reply_async | function | `struct smb2_pdu *smb2_cmd_session_setup_reply_async(struct smb2_context *smb2, struct smb2_session_setup_reply *rep, smb2_command_cb cb, void *cb_data)` | Include | 跨模块服务端/响应路径入口，构造 SESSION_SETUP reply PDU。 |
| IOV_OFFSET_SESSION | macro | `#define IOV_OFFSET_SESSION (rep->security_buffer_offset - SMB2_HEADER_SIZE - (SMB2_SESSION_SETUP_REPLY_SIZE & 0xfffe))` | Skip | 文件内部 offset 计算宏，无独立外部调用契约。 |
| smb2_process_session_setup_fixed | function | `int smb2_process_session_setup_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有跨文件 reply fixed parser，被 PDU dispatcher 调用并更新会话状态。 |
| smb2_process_session_setup_variable | function | `int smb2_process_session_setup_variable(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有跨文件 reply variable parser，绑定 security buffer 指针。 |
| smb2_process_session_setup_request_fixed | function | `int smb2_process_session_setup_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有跨文件 request fixed parser，被服务端 request dispatcher 调用。 |
| smb2_process_session_setup_request_variable | function | `int smb2_process_session_setup_request_variable(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有跨文件 request variable parser，绑定 request security buffer。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_SESSION_SETUP_REQUEST_SIZE | macro | `include/smb2/smb2.h:156` | SESSION_SETUP request fixed structure size is 25, with even-length wire header checks using `& 0xfffe`. |
| smb2_session_setup_request | struct | `include/smb2/smb2.h:158` | Carries request flags, security mode, capabilities, channel, previous session id, security buffer length, and security buffer pointer. |
| SMB2_SESSION_SETUP_REPLY_SIZE | macro | `include/smb2/smb2.h:172` | SESSION_SETUP reply fixed structure size is 9, with even-length wire header checks using `& 0xfffe`. |
| smb2_session_setup_reply | struct | `include/smb2/smb2.h:174` | Carries reply session flags, security buffer length, offset, and security buffer pointer. |

## ADDED Requirements

### Requirement: smb2_cmd_session_setup_async request PDU construction
系统 MUST 为 SMB2_SESSION_SETUP 命令构造包含 fixed request header 与 security buffer 的输出 PDU，并在任一分配、iovector 追加、编码或 64-bit padding 失败时返回 `NULL` 且不交付半成品 PDU。

#### Scenario: 成功构造 session setup request
- **GIVEN** 调用方提供有效的 `smb2_context`、`smb2_session_setup_request`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_session_setup_async`
- **THEN** 返回的 PDU MUST 使用 `SMB2_SESSION_SETUP` 命令，写入 request fixed fields，追加 security buffer，并完成 64-bit padding

Trace: `lib/smb2-cmd-session-setup.c:smb2_cmd_session_setup_async`, `lib/smb2-cmd-session-setup.c:smb2_encode_session_setup_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_session_setup_async`

#### Scenario: request 编码失败释放 PDU
- **GIVEN** PDU 已分配但 request 编码或 padding 失败
- **WHEN** `smb2_cmd_session_setup_async` 处理失败返回
- **THEN** 函数 MUST 释放已分配 PDU 并返回 `NULL`

Trace: `lib/smb2-cmd-session-setup.c:smb2_cmd_session_setup_async`

### Requirement: smb2_cmd_session_setup_reply_async reply PDU construction
系统 MUST 为 SMB2_SESSION_SETUP 命令构造 reply PDU，写入 session flags、security buffer offset/length，并仅在 security buffer length 非零时追加 padded security buffer。

#### Scenario: 成功构造 session setup reply
- **GIVEN** 调用方提供有效的 `smb2_session_setup_reply`
- **WHEN** 调用 `smb2_cmd_session_setup_reply_async`
- **THEN** 返回的 PDU MUST 包含 fixed reply header，设置 `security_buffer_offset` 为 fixed header 后的 SMB2 payload offset，并对变长 security buffer 使用 32-bit padding 后再进行 64-bit PDU padding

Trace: `lib/smb2-cmd-session-setup.c:smb2_cmd_session_setup_reply_async`, `lib/smb2-cmd-session-setup.c:smb2_encode_session_setup_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_session_setup_reply_async`

#### Scenario: reply 编码失败释放 PDU
- **GIVEN** PDU 已分配但 reply 编码或 padding 失败
- **WHEN** `smb2_cmd_session_setup_reply_async` 处理失败返回
- **THEN** 函数 MUST 释放已分配 PDU 并返回 `NULL`

Trace: `lib/smb2-cmd-session-setup.c:smb2_cmd_session_setup_reply_async`

### Requirement: smb2_process_session_setup_fixed reply fixed parser
系统 MUST 校验 SESSION_SETUP reply fixed payload size，分配并填充 reply payload，拒绝越界或重叠的 security buffer，并在成功解析 fixed header 时更新 `smb2->session_id`。

#### Scenario: reply fixed header 有效且无 security buffer
- **GIVEN** 输入 iovector 长度匹配 `SMB2_SESSION_SETUP_REPLY_SIZE & 0xfffe` 且 wire structure size 为 `SMB2_SESSION_SETUP_REPLY_SIZE`
- **WHEN** 调用 `smb2_process_session_setup_fixed`
- **THEN** 函数 MUST 分配 `smb2_session_setup_reply` 到 `pdu->payload`，读取 session flags、offset 和 length，更新 context session id，并在 security buffer length 为 0 时返回 0

Trace: `lib/smb2-cmd-session-setup.c:smb2_process_session_setup_fixed`, `include/libsmb2-private.h:smb2_process_session_setup_fixed`

#### Scenario: reply security buffer 边界非法
- **GIVEN** fixed header 声明的 security buffer 超出 PDU 长度或 offset 落入 fixed header 区域
- **WHEN** 调用 `smb2_process_session_setup_fixed`
- **THEN** 函数 MUST 设置错误、清空 `pdu->payload`、释放已分配 reply payload，并返回 -1

Trace: `lib/smb2-cmd-session-setup.c:smb2_process_session_setup_fixed`

### Requirement: smb2_process_session_setup_variable reply variable parser
系统 MUST 将 SESSION_SETUP reply 的 security buffer 指针解析为 variable iovector 中由 fixed parser 计算出的偏移位置。

#### Scenario: 绑定 reply security buffer 指针
- **GIVEN** `pdu->payload` 已包含由 fixed parser 填充的 `smb2_session_setup_reply`
- **WHEN** 调用 `smb2_process_session_setup_variable`
- **THEN** 函数 MUST 将 `rep->security_buffer` 指向当前输入 iovector 的 `IOV_OFFSET_SESSION` 位置并返回 0

Trace: `lib/smb2-cmd-session-setup.c:smb2_process_session_setup_variable`, `include/libsmb2-private.h:smb2_process_session_setup_variable`

### Requirement: smb2_process_session_setup_request_fixed request fixed parser
系统 MUST 校验 SESSION_SETUP request fixed payload size，分配 request payload，读取固定字段，并返回后续 variable security buffer 的声明长度。

#### Scenario: request fixed header 有效
- **GIVEN** 输入 iovector 长度匹配 `SMB2_SESSION_SETUP_REQUEST_SIZE & 0xfffe` 且 wire structure size 为 `SMB2_SESSION_SETUP_REQUEST_SIZE`
- **WHEN** 调用 `smb2_process_session_setup_request_fixed`
- **THEN** 函数 MUST 分配 `smb2_session_setup_request` 到 `pdu->payload`，读取 flags、security mode、capabilities、channel、security buffer length 和 previous session id，并返回 `security_buffer_length`

Trace: `lib/smb2-cmd-session-setup.c:smb2_process_session_setup_request_fixed`, `include/libsmb2-private.h:smb2_process_session_setup_request_fixed`

#### Scenario: request fixed header size 非法
- **GIVEN** 输入 fixed payload 的 structure size 或 iovector 长度与 SESSION_SETUP request size 不匹配
- **WHEN** 调用 `smb2_process_session_setup_request_fixed`
- **THEN** 函数 MUST 设置错误且返回 -1

Trace: `lib/smb2-cmd-session-setup.c:smb2_process_session_setup_request_fixed`

### Requirement: smb2_process_session_setup_request_variable request variable parser
系统 MUST 将 SESSION_SETUP request 的 security buffer 指针绑定到当前 variable iovector 的起始地址。

#### Scenario: 绑定 request security buffer 指针
- **GIVEN** `pdu->payload` 已包含由 fixed parser 分配的 `smb2_session_setup_request`
- **WHEN** 调用 `smb2_process_session_setup_request_variable`
- **THEN** 函数 MUST 将 `req->security_buffer` 指向当前输入 iovector buffer 并返回 0

Trace: `lib/smb2-cmd-session-setup.c:smb2_process_session_setup_request_variable`, `include/libsmb2-private.h:smb2_process_session_setup_request_variable`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_process_session_setup_request_fixed` 从 offset 18 读取 `previous_session_id`，但 request encoder 在 offset 16 写入；该差异是协议兼容需求还是实现缺陷待确认。 | smb2_process_session_setup_request_fixed | 源码存在偏移不一致，未发现测试覆盖。 |
| Q-002 | request/reply builder 在追加 iovector 失败时是否由 `smb2_free_pdu` 接管此前 buffer 释放，仍需结合 `smb2_add_iovector` 失败路径确认。 | smb2_cmd_session_setup_async, smb2_cmd_session_setup_reply_async | 当前文件只释放 PDU，内部 buffer 所有权依赖 `lib/pdu.c`。 |
| Q-003 | GitNexus impact 对同名声明和定义返回 ambiguous，需后续批次在共享索引中记录声明/定义消歧方式。 | file-level | CLI 不支持 `impact --uid`，本 worker 仅能记录 context callers。 |
