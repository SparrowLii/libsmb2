# lib/aes128ccm.h Specification

## Source Context

- Source: `lib/aes128ccm.h`
- Related Headers: `lib/aes128ccm.c`, `lib/aes.h`, `include/portable-endian.h`, `lib/compat.h`
- Related Tests: `tests/aes128ccm-test.c`
- Related Dependencies: `GitNexus context found header declarations for aes128ccm_encrypt and aes128ccm_decrypt with no indexed incoming/outgoing relationships; source review confirms implementation in lib/aes128ccm.c and runtime use from lib/smb3-seal.c.`
- Build/Compile Context: `C project; lib/Makefile.am lists aes128ccm.h; lib/aes128ccm.c conditionally includes config/stdint/arpa inet headers and depends on AES128_ECB_encrypt plus endian conversion helpers.`

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| aes128ccm_encrypt | function | void aes128ccm_encrypt(unsigned char *key, unsigned char *nonce, size_t nlen, unsigned char *aad, size_t alen, unsigned char *p, size_t plen, unsigned char *m, size_t mlen); | Include | 公开头文件声明的 AES-128-CCM 加密入口，会原地转换 payload 并写出认证标签，SMB3 sealing 和 AES-CCM 测试直接依赖。 |
| aes128ccm_decrypt | function | int aes128ccm_decrypt(unsigned char *key, unsigned char *nonce, size_t nlen, unsigned char *aad, size_t alen, unsigned char *p, size_t plen, unsigned char *m, size_t mlen); | Include | 公开头文件声明的 AES-128-CCM 解密入口，会原地转换 payload 并返回标签比较结果，SMB3 unsealing 和 AES-CCM 测试直接依赖。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| 无 | none | none | 无公开数据模型。 |

## ADDED Requirements

### Requirement: aes128ccm_encrypt 原地加密并生成认证标签
系统 MUST 使用调用方提供的 128-bit key、nonce、AAD、payload 和认证标签长度生成 AES-128-CCM 认证标签，并 MUST 将 payload 缓冲区原地转换为密文。

#### Scenario: RFC 样例 4 字节认证标签
- **GIVEN** 调用方提供 16 字节 key、7 字节 nonce、8 字节 AAD、4 字节 payload、4 字节认证标签缓冲区和可写 payload 缓冲区
- **WHEN** 调用 `aes128ccm_encrypt` 处理该输入
- **THEN** payload 后接认证标签的输出 MUST 匹配测试向量 `71 62 01 5b 4d ac 25 5d`

Trace: `lib/aes128ccm.h:aes128ccm_encrypt`, `lib/aes128ccm.c:aes128ccm_encrypt`, `tests/aes128ccm-test.c:test_1`

#### Scenario: 多块 AAD 和 payload 的 8 字节认证标签
- **GIVEN** 调用方提供 16 字节 key、12 字节 nonce、20 字节 AAD、24 字节 payload、8 字节认证标签缓冲区和可写 payload 缓冲区
- **WHEN** 调用 `aes128ccm_encrypt` 处理该输入
- **THEN** payload 后接认证标签的输出 MUST 匹配测试向量 `e3 b2 01 a9 f5 b7 1a 7a 9b 1c ea ec cd 97 e7 0b 61 76 aa d9 a4 42 8a a5 48 43 92 fb c1 b0 99 51`

Trace: `lib/aes128ccm.h:aes128ccm_encrypt`, `lib/aes128ccm.c:aes128ccm_encrypt`, `tests/aes128ccm-test.c:test_2`

#### Scenario: SMB3 transform header sealing
- **GIVEN** SMB3 sealing passes an 11 字节 nonce、32 字节 AAD、明文 transform payload、16 字节 tag 缓冲区和 server input key
- **WHEN** `smb3_encrypt_pdu` 调用 `aes128ccm_encrypt`
- **THEN** 该接口 MUST 在 transform payload 缓冲区中产生密文，并 MUST 在 transform header 的 signature 字段写入 16 字节认证标签

Trace: `lib/aes128ccm.h:aes128ccm_encrypt`, `lib/smb3-seal.c:smb3_encrypt_pdu`

### Requirement: aes128ccm_decrypt 原地解密并校验认证标签
系统 MUST 使用调用方提供的 128-bit key、nonce、AAD、payload 和认证标签长度原地解密 payload，并 MUST 返回计算出的认证标签与调用方提供标签的字节比较结果。

#### Scenario: 加密输出可成功解密
- **GIVEN** 调用方先使用相同 key、nonce、AAD、payload 和 tag 长度生成 AES-128-CCM 密文与认证标签
- **WHEN** 调用 `aes128ccm_decrypt` 处理该密文和认证标签
- **THEN** 返回值 MUST 为 `0`，并且 payload 缓冲区 MUST 恢复为原始明文

Trace: `lib/aes128ccm.h:aes128ccm_decrypt`, `lib/aes128ccm.c:aes128ccm_decrypt`, `tests/aes128ccm-test.c:test_1`, `tests/aes128ccm-test.c:test_2`

#### Scenario: SMB3 transform header unsealing
- **GIVEN** SMB3 unsealing提供 transform header 中的 11 字节 nonce、32 字节 AAD、密文 payload、16 字节 signature 和 server output key
- **WHEN** `smb3_decrypt_pdu` 调用 `aes128ccm_decrypt`
- **THEN** 返回值 MUST 为 `0` 才允许上层继续解析解密后的 payload；非零返回值 MUST 被调用方视为解密失败

Trace: `lib/aes128ccm.h:aes128ccm_decrypt`, `lib/smb3-seal.c:smb3_decrypt_pdu`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `aes128ccm_encrypt` 和 `aes128ccm_decrypt` 对 `NULL` 指针、非法 `nlen`、非 CCM 标准 `mlen` 或过大长度是否有调用前置约束？ | aes128ccm_encrypt, aes128ccm_decrypt | 头文件未声明参数约束，实现直接进行指针运算、`memcpy` 和固定块处理，测试只覆盖有效输入。 |
| Q-002 | GitNexus impact 对 `aes128ccm_encrypt` 和 `aes128ccm_decrypt` 返回同名声明/定义歧义，是否需要在索引或 CLI 中支持按 UID/file 精确 impact？ | aes128ccm_encrypt, aes128ccm_decrypt | `gitnexus impact --include-tests` 报告声明和定义两个候选，当前 CLI help 未提供 UID/file disambiguation 选项。 |
