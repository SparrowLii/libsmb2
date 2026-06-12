# lib/smb2-signing.h Specification

## Source Context

- Source: `lib/smb2-signing.h`
- Related Headers: `include/slist.h`, `include/smb2/smb2.h`, `include/smb2/libsmb2.h`, `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`
- Related Tests: `tests/prog_cat.c`, `tests/prog_cat_cancel.c`
- Related Dependencies: GitNexus context for `smb2_pdu_add_signature` in this header shows the declaration only; implementation context in `lib/smb2-signing.c` shows one direct caller `lib/pdu.c:smb2_queue_pdu` and callees `smb2_set_error`, `smb2_set_uint32`, and `smb2_calc_signature`. GitNexus impact for implementation UID `Function:lib/smb2-signing.c:smb2_pdu_add_signature` reports CRITICAL risk with 101 impacted symbols, 34 affected processes, and 11 affected modules. GitNexus context for `smb2_pdu_check_signature` shows no callers or callees and implementation impact is LOW.
- Build/Compile Context: C header guarded by `_SMB2_SIGNING_H_`; `HAVE_CONFIG_H` controls inclusion of `config.h`; `_GNU_SOURCE` is defined when absent; declarations are exposed with `extern "C"` for C++ callers.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_pdu_add_signature | function | int smb2_pdu_add_signature(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 该头文件暴露 PDU 签名入口，`lib/pdu.c:smb2_queue_pdu` 跨文件调用该接口，返回码、签名副作用和跳过签名条件影响所有出站 SMB2 PDU。 |
| smb2_pdu_check_signature | function | int smb2_pdu_check_signature(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 该头文件暴露 PDU 签名校验入口，当前实现为成功占位返回，调用方可观察的稳定行为需要独立记录以防后续实现改变。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| _SMB2_SIGNING_H_ | macro | lib/smb2-signing.h:2 | 头文件 include guard，防止重复声明。 |
| _GNU_SOURCE | macro | lib/smb2-signing.h:25 | 当调用方尚未定义时启用 GNU 扩展宏，影响后续系统头声明可见性。 |

## ADDED Requirements

### Requirement: smb2_pdu_add_signature declares outbound PDU signing entry
系统 MUST 通过 `lib/smb2-signing.h` 暴露 `smb2_pdu_add_signature` 声明，使内部调用方能够请求对 `struct smb2_pdu` 的出站 SMB2 头部签名字段和签名标志进行更新，并通过整数返回值观察成功、跳过或失败结果。

#### Scenario: declaration is available for queue-time signing
- **GIVEN** C 或 C++ 翻译单元包含 `lib/smb2-signing.h` 且可见 `struct smb2_context` 与 `struct smb2_pdu` 类型
- **WHEN** 调用方按 `int smb2_pdu_add_signature(struct smb2_context *smb2, struct smb2_pdu *pdu);` 声明编译调用
- **THEN** 头文件 SHALL 提供该函数原型，并保留 `int` 返回类型与两个指针参数的 ABI

Trace: `lib/smb2-signing.h:smb2_pdu_add_signature`, `lib/smb2-signing.c:smb2_pdu_add_signature`, `lib/pdu.c:smb2_queue_pdu`

#### Scenario: implementation signs eligible outbound PDUs
- **GIVEN** 调用方传入具有至少两个输出 iovec、首个 iovec 长度为 `SMB2_HEADER_SIZE`、非零 `session_id` 且非零 `session_key_size` 的 PDU
- **WHEN** `smb2_pdu_add_signature` 被调用且底层签名计算成功
- **THEN** 系统 MUST 设置 `SMB2_FLAGS_SIGNED` 标志，更新输出 SMB2 头部 flags 字段，将计算出的 16 字节签名复制到 `pdu->header.signature` 和输出缓冲区偏移 48，并返回 `0`

Trace: `lib/smb2-signing.h:smb2_pdu_add_signature`, `lib/smb2-signing.c:smb2_pdu_add_signature`, `lib/smb2-signing.c:smb2_calc_signature`

#### Scenario: implementation skips unsigned session setup and anonymous sessions
- **GIVEN** PDU 是非成功或非 server-to-redir 的 `SMB2_SESSION_SETUP`，或 SMB2 上下文的 `session_id` 为 `0`
- **WHEN** `smb2_pdu_add_signature` 被调用
- **THEN** 系统 MUST 返回 `0` 且不要求写入签名字段；这些路径表示签名被跳过而非签名失败

Trace: `lib/smb2-signing.h:smb2_pdu_add_signature`, `lib/smb2-signing.c:smb2_pdu_add_signature`

#### Scenario: implementation reports signing precondition failures
- **GIVEN** PDU 输出 iovec 少于两个、首个 iovec 长度不是 `SMB2_HEADER_SIZE`、会话密钥大小为 `0`，或签名计算分配失败
- **WHEN** `smb2_pdu_add_signature` 被调用
- **THEN** 系统 MUST 返回 `-1`；对 iovec 数量和头部长度错误，系统 SHALL 通过 `smb2_set_error` 记录错误文本

Trace: `lib/smb2-signing.h:smb2_pdu_add_signature`, `lib/smb2-signing.c:smb2_pdu_add_signature`, `lib/init.c:smb2_set_error`

### Requirement: smb2_pdu_check_signature declares inbound PDU signature check entry
系统 MUST 通过 `lib/smb2-signing.h` 暴露 `smb2_pdu_check_signature` 声明，使内部调用方能够请求对 `struct smb2_pdu` 执行签名校验，并通过整数返回值观察校验结果。

#### Scenario: declaration is available for inbound signature checks
- **GIVEN** C 或 C++ 翻译单元包含 `lib/smb2-signing.h` 且可见 `struct smb2_context` 与 `struct smb2_pdu` 类型
- **WHEN** 调用方按 `int smb2_pdu_check_signature(struct smb2_context *smb2, struct smb2_pdu *pdu);` 声明编译调用
- **THEN** 头文件 SHALL 提供该函数原型，并保留 `int` 返回类型与两个指针参数的 ABI

Trace: `lib/smb2-signing.h:smb2_pdu_check_signature`, `lib/smb2-signing.c:smb2_pdu_check_signature`

#### Scenario: current implementation accepts all PDUs
- **GIVEN** 调用方传入任意 `smb2` 与 `pdu` 指针组合
- **WHEN** `smb2_pdu_check_signature` 被调用
- **THEN** 当前实现 MUST 返回 `0`，且不会读取、修改或验证签名字段

Trace: `lib/smb2-signing.h:smb2_pdu_check_signature`, `lib/smb2-signing.c:smb2_pdu_check_signature`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_pdu_add_signature` 是否允许 `smb2`、`pdu`、`pdu->out.iov` 或首个 iovec 缓冲区为 `NULL`？ | smb2_pdu_add_signature | 头文件和实现未显式检查空指针，调用方前置条件只能从当前无防护解引用推断。 |
| Q-002 | `session_key_size == 0` 返回 `-1` 时是否也应设置 `smb2_set_error`？ | smb2_pdu_add_signature | 当前实现直接返回 `-1`，未记录错误文本，缺少测试或文档确认这是有意行为。 |
| Q-003 | `smb2_pdu_check_signature` 的总是成功行为是否为临时占位，还是入站签名校验明确不在当前版本执行？ | smb2_pdu_check_signature | 头文件暴露校验入口，但实现仅返回 `0`，GitNexus 未发现调用者或测试证据。 |
