# lib/hmac-md5.h Specification

## Source Context

- Source: `lib/hmac-md5.h`
- Related Headers: `config.h`, `stdint.h`, `sys/types.h`
- Related Tests: `none`
- Related Dependencies: `lib/hmac-md5.c:smb2_hmac_md5`, `lib/md5.h:MD5Init`, `lib/md5.h:MD5Update`, `lib/md5.h:MD5Final`, `lib/ntlmssp.c` callers identified by source search; GitNexus context for header declaration has no incoming or outgoing edges.
- Build/Compile Context: C project; `HAVE_CONFIG_H` includes `config.h`, `HAVE_STDINT_H` controls `stdint.h`, `__BYTE_ORDER == __BIG_ENDIAN` or `XBOX_360_PLATFORM` defines `WORDS_BIGENDIAN`, `!defined(__PS2__) && !defined(PICO_PLATFORM)` controls `UWORD32` typedef, `__cplusplus` wraps the declaration in `extern "C"`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_hmac_md5 | function | `void smb2_hmac_md5(unsigned char *text, int text_len, unsigned char *key, unsigned int key_len, unsigned char *digest);` | Include | 公开声明供 NTLMSSP 认证路径调用，调用方可观察 digest 输出契约。 |
| UWORD32 | type | `typedef uint32_t UWORD32;` | Include | 头文件在非 `__PS2__` 且非 `PICO_PLATFORM` 条件下暴露兼容整型别名，并受 `UWORD32_DEFINED` include guard 约束。 |
| WORDS_BIGENDIAN | macro | `#define WORDS_BIGENDIAN 1` | Include | 头文件在大端或 Xbox 360 条件下暴露 endian 编译宏，影响共享 MD5 兼容类型上下文。 |
| HMAC_MD5_H | macro | `#define HMAC_MD5_H` | Skip | 头文件 include guard，无独立调用方可观察行为契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| UWORD32 | typedef | `lib/hmac-md5.h:25` | 在 `!defined(__PS2__) && !defined(PICO_PLATFORM)` 且未定义 `UWORD32_DEFINED` 时别名为 `uint32_t`。 |
| WORDS_BIGENDIAN | macro | `lib/hmac-md5.h:19` | 在 `__BYTE_ORDER == __BIG_ENDIAN` 或 `defined(XBOX_360_PLATFORM)` 时定义为 `1`。 |

## ADDED Requirements

### Requirement: smb2_hmac_md5 computes RFC2104-compatible MD5 HMAC
系统 MUST 将 `text`、`text_len`、`key` 和 `key_len` 组合为 HMAC-MD5，并将 16 字节摘要写入调用方提供的 `digest` 缓冲区。

#### Scenario: key length within block size
- **GIVEN** 调用方提供不超过 64 字节的 `key`、对应 `key_len`、`text`、`text_len` 和至少 16 字节的 `digest` 缓冲区
- **WHEN** 调用方调用 `smb2_hmac_md5(text, text_len, key, key_len, digest)`
- **THEN** 实现使用原始 key 构造 ipad/opad，并将内部 MD5 和外部 MD5 的最终 16 字节结果写入 `digest`

Trace: `lib/hmac-md5.h:smb2_hmac_md5`, `lib/hmac-md5.c:smb2_hmac_md5`

#### Scenario: key length exceeds block size
- **GIVEN** 调用方提供大于 64 字节的 `key` 和有效 `digest` 缓冲区
- **WHEN** 调用方调用 `smb2_hmac_md5(text, text_len, key, key_len, digest)`
- **THEN** 实现 MUST 先对 key 执行 MD5 压缩为 16 字节临时 key，再基于该临时 key 计算 HMAC-MD5 摘要

Trace: `lib/hmac-md5.h:smb2_hmac_md5`, `lib/hmac-md5.c:smb2_hmac_md5`

### Requirement: UWORD32 exposes a guarded 32-bit compatibility alias
系统 MUST 在非 `__PS2__` 且非 `PICO_PLATFORM` 构建中，仅当 `UWORD32_DEFINED` 尚未定义时将 `UWORD32` 声明为 `uint32_t` 并定义 `UWORD32_DEFINED`。

#### Scenario: compatible platform without existing alias
- **GIVEN** 编译环境未定义 `__PS2__`、未定义 `PICO_PLATFORM` 且未定义 `UWORD32_DEFINED`
- **WHEN** 调用方包含 `lib/hmac-md5.h`
- **THEN** 头文件声明 `typedef uint32_t UWORD32;` 并定义 `UWORD32_DEFINED` 以避免重复 typedef

Trace: `lib/hmac-md5.h:UWORD32`

### Requirement: WORDS_BIGENDIAN exposes big-endian compile context
系统 MUST 在 `__BYTE_ORDER == __BIG_ENDIAN` 或定义 `XBOX_360_PLATFORM` 时将 `WORDS_BIGENDIAN` 定义为 `1`。

#### Scenario: big-endian or Xbox 360 platform
- **GIVEN** 编译环境满足 `__BYTE_ORDER == __BIG_ENDIAN` 或已定义 `XBOX_360_PLATFORM`
- **WHEN** 调用方包含 `lib/hmac-md5.h`
- **THEN** 头文件提供值为 `1` 的 `WORDS_BIGENDIAN` 宏供后续 MD5 兼容代码使用

Trace: `lib/hmac-md5.h:WORDS_BIGENDIAN`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_hmac_md5` 对 `NULL` 指针、负数 `text_len` 或无效缓冲区是否有调用方前置约束？ | smb2_hmac_md5 | 头文件和实现没有显式检查，现有证据只能确认正常输入路径。 |
| Q-002 | `UWORD32` 在 `__PS2__` 或 `PICO_PLATFORM` 构建中由哪个头文件提供等价类型？ | UWORD32 | 当前头文件在这些平台跳过 typedef，未在本条目中确认替代定义来源。 |
