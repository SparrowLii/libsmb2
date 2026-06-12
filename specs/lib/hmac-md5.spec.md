# lib/hmac-md5.c Specification

## Source Context

- Source: `lib/hmac-md5.c`
- Related Headers: `lib/hmac-md5.h`, `lib/md5.h`, `lib/compat.h`
- Related Tests: `tests/ntlmssp_generate_blob.c`
- Related Dependencies: GitNexus context shows incoming callers `NTOWFv2`, `encode_ntlm_auth`, and `ntlmssp_authenticate_blob` in `lib/ntlmssp.c`; outgoing dependencies are `MD5Init`, `MD5Update`, and `MD5Final` in `lib/md5.c`.
- Build/Compile Context: C project; `lib/hmac-md5.c` conditionally includes `<strings.h>` under `HAVE_STRINGS_H`, includes `compat.h` and `md5.h`, and relies on MD5 context declarations from `lib/md5.h`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_hmac_md5 | function | `void smb2_hmac_md5(unsigned char *text, int text_len, unsigned char *key, unsigned int key_len, unsigned char *digest);` | Include | 该函数由 `lib/hmac-md5.h` 声明并被 NTLMSSP 认证路径跨文件调用，输出调用方可观察的 16 字节 HMAC-MD5 摘要。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| 无 | none | none | 无公开数据模型。 |

## ADDED Requirements

### Requirement: smb2_hmac_md5 compute RFC2104 MD5 HMAC
系统 MUST 对调用方提供的消息和密钥计算 HMAC-MD5，并将 16 字节结果写入 `digest` 指向的缓冲区。

#### Scenario: 短密钥直接参与内外层 MD5
- **GIVEN** 调用方提供长度不超过 64 字节的 `key`、`key_len`、`text`、`text_len` 和至少 16 字节的 `digest` 输出缓冲区
- **WHEN** 调用方调用 `smb2_hmac_md5`
- **THEN** 实现 MUST 用原始密钥填充 64 字节内外层 pad，分别应用 `0x36` 和 `0x5c` 异或，并按 `MD5(K XOR opad, MD5(K XOR ipad, text))` 生成 16 字节摘要

Trace: `lib/hmac-md5.c:smb2_hmac_md5`, `lib/hmac-md5.h:smb2_hmac_md5`, `tests/ntlmssp_generate_blob.c:main`

#### Scenario: 长密钥先折叠为 MD5 摘要
- **GIVEN** 调用方提供长度大于 64 字节的 `key` 和对应 `key_len`
- **WHEN** 调用方调用 `smb2_hmac_md5`
- **THEN** 实现 MUST 先对原始密钥执行 MD5，将临时 16 字节摘要作为 HMAC 密钥，再执行内外层 HMAC-MD5 计算

Trace: `lib/hmac-md5.c:smb2_hmac_md5`, `lib/md5.c:MD5Init`, `lib/md5.c:MD5Update`, `lib/md5.c:MD5Final`

#### Scenario: NTLMSSP 调用路径获得稳定摘要
- **GIVEN** NTLMSSP 代码使用用户域、挑战响应或 NTProofStr 作为 `text`，并使用 16 字节响应密钥作为 `key`
- **WHEN** `NTOWFv2`、`encode_ntlm_auth` 或 `ntlmssp_authenticate_blob` 调用 `smb2_hmac_md5`
- **THEN** 输出摘要 MUST 可用于 NTLMv2 hash、NTProofStr 和导出会话密钥计算，使固定测试输入生成预期 NTLMSSP authenticate blob

Trace: `lib/hmac-md5.c:smb2_hmac_md5`, `lib/ntlmssp.c:NTOWFv2`, `lib/ntlmssp.c:encode_ntlm_auth`, `lib/ntlmssp.c:ntlmssp_authenticate_blob`, `tests/ntlmssp_generate_blob.c:main`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `text`、`key` 或 `digest` 为空指针时的行为是否由调用方前置条件约束，还是需要接口显式处理？ | smb2_hmac_md5 | 源码直接传入 MD5 和 `memmove`，未发现空指针检查。 |
| Q-002 | `text_len` 为负数时是否属于未定义调用方输入？ | smb2_hmac_md5 | 形参类型为 `int`，源码直接传递给 `MD5Update` 的 unsigned 长度参数，未发现范围检查。 |
