# lib/aes128ccm.c Specification

## Source Context

- Source: `lib/aes128ccm.c`
- Related Headers: `lib/aes128ccm.h`, `lib/aes.h`, `include/portable-endian.h`, `lib/compat.h`
- Related Tests: `tests/aes128ccm-test.c`
- Related Dependencies: `AES128_ECB_encrypt`, `smb3_encrypt_pdu`, `smb3_decrypt_pdu`, `tests/aes128ccm-test.c:test_1`, `tests/aes128ccm-test.c:test_2`
- Build/Compile Context: `CMakeLists.txt` and `lib/CMakeLists.txt` build the C library; `HAVE_CONFIG_H`, `HAVE_STDINT_H`, and `HAVE_ARPA_INET_H` conditionally include platform headers.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| aes128ccm_encrypt | function | void aes128ccm_encrypt(unsigned char *key, unsigned char *nonce, size_t nlen, unsigned char *aad, size_t alen, unsigned char *p, size_t plen, unsigned char *m, size_t mlen); | Include | 头文件声明的跨文件 AES-128-CCM 加密入口，被 SMB3 sealing 和 AES-CCM 测试调用，具有可观察的密文和认证标签输出。 |
| aes128ccm_decrypt | function | int aes128ccm_decrypt(unsigned char *key, unsigned char *nonce, size_t nlen, unsigned char *aad, size_t alen, unsigned char *p, size_t plen, unsigned char *m, size_t mlen); | Include | 头文件声明的跨文件 AES-128-CCM 解密入口，被 SMB3 sealing 和 AES-CCM 测试调用，具有可观察的明文恢复和认证标签校验返回值。 |
| aes_ccm_generate_b0 | function | static void aes_ccm_generate_b0(unsigned char *nonce, size_t nlen, size_t alen, size_t plen, size_t mlen, unsigned char *buf) | Skip | 文件内静态 helper，仅构造 CCM B0 块，行为并入公开加解密接口。 |
| bxory | function | static inline void bxory(unsigned char *b, unsigned char *y, size_t num) | Skip | 文件内静态 helper，仅执行缓冲区异或，行为并入公开加解密接口。 |
| ccm_generate_T | function | static void ccm_generate_T(unsigned char *key, unsigned char *nonce, size_t nlen, unsigned char *aad, size_t alen, unsigned char *p, size_t plen, unsigned char *m, size_t mlen) | Skip | 文件内静态 helper，仅生成认证中间值，行为并入公开加解密接口。 |
| ccm_generate_s | function | static void ccm_generate_s(unsigned char *key, unsigned char *nonce, size_t nlen, size_t plen, int i, unsigned char *s) | Skip | 文件内静态 helper，仅生成 CCM counter keystream 块，行为并入公开加解密接口。 |
| aes_ccm_crypt | function | static void aes_ccm_crypt(unsigned char *key, unsigned char *nonce, size_t nlen, unsigned char *p, size_t plen) | Skip | 文件内静态 helper，仅对 payload 原地异或 keystream，行为并入公开加解密接口。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| 无 | none | none | 无公开数据模型。 |

## ADDED Requirements

### Requirement: aes128ccm_encrypt AES-128-CCM payload encryption and tag generation
系统 MUST 使用给定 key、nonce、AAD、payload 和 tag 长度计算 AES-128-CCM 认证标签，并 MUST 原地加密 `p` 指向的 payload 缓冲区，同时把加密后的认证标签写入 `m` 指向的缓冲区。

#### Scenario: 已知向量生成密文和标签
- **GIVEN** 调用方提供 16 字节 AES key、nonce、AAD、明文 payload、可写 payload 缓冲区和可写 tag 缓冲区
- **WHEN** 调用方执行 `aes128ccm_encrypt(key, nonce, nlen, aad, alen, p, plen, m, mlen)`
- **THEN** payload 缓冲区 MUST 被原地转换为 AES-128-CCM 密文，tag 缓冲区 MUST 包含与输入 key、nonce、AAD、payload 和 `mlen` 对应的认证标签

Trace: `lib/aes128ccm.c:aes128ccm_encrypt`, `tests/aes128ccm-test.c:test_1`, `tests/aes128ccm-test.c:test_2`

#### Scenario: SMB3 sealing 使用 11 字节 nonce、32 字节 AAD 和 16 字节标签
- **GIVEN** SMB3 transform header 已包含随机 nonce、AAD 字段和待加密 PDU payload
- **WHEN** `smb3_encrypt_pdu` 调用 `aes128ccm_encrypt` 并传入 `nlen == 11`、`alen == 32`、`mlen == 16`
- **THEN** 函数 MUST 加密 transform header 后的 payload，并 MUST 在 transform header signature 字段写入 16 字节认证标签

Trace: `lib/aes128ccm.c:aes128ccm_encrypt`, `lib/smb3-seal.c:smb3_encrypt_pdu`

### Requirement: aes128ccm_decrypt AES-128-CCM payload decryption and tag verification
系统 MUST 使用给定 key、nonce、AAD、payload 和 tag 长度原地解密 `p` 指向的 payload 缓冲区，并 MUST 返回计算得到的认证标签与 `m` 指向标签之间的 `memcmp` 比较结果。

#### Scenario: 有效标签恢复明文并返回零
- **GIVEN** payload 缓冲区包含由 `aes128ccm_encrypt` 使用相同 key、nonce、AAD 和 tag 长度生成的密文，`m` 指向对应认证标签
- **WHEN** 调用方执行 `aes128ccm_decrypt(key, nonce, nlen, aad, alen, p, plen, m, mlen)`
- **THEN** payload 缓冲区 MUST 被原地恢复为原始明文，并且返回值 MUST 为 `0`

Trace: `lib/aes128ccm.c:aes128ccm_decrypt`, `tests/aes128ccm-test.c:test_1`, `tests/aes128ccm-test.c:test_2`

#### Scenario: 认证标签不匹配时返回非零比较结果
- **GIVEN** payload、key、nonce、AAD 或 tag 与用于生成 `m` 的输入不匹配
- **WHEN** 调用方执行 `aes128ccm_decrypt(key, nonce, nlen, aad, alen, p, plen, m, mlen)`
- **THEN** 函数 MUST 返回 `memcmp(tmp, m, mlen)` 的非零比较结果，调用方 MUST 将非零结果视为认证或解密失败

Trace: `lib/aes128ccm.c:aes128ccm_decrypt`, `lib/smb3-seal.c:smb3_decrypt_pdu`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `nlen`、`mlen` 和 `plen` 的允许范围是否由调用方保证，尤其是 `nlen > 14`、`mlen > 16` 或超出 CCM 规范范围时的行为未在源码中显式防护。 | aes128ccm_encrypt, aes128ccm_decrypt | 源码直接使用栈上 16 字节缓冲区、`memcpy` 和 CCM 长度字段，测试只覆盖 7/12 字节 nonce 与 4/8 字节 tag。 |
| Q-002 | 认证失败时 `aes128ccm_decrypt` 已经原地解密 payload，调用方是否需要在失败后丢弃或清理该缓冲区未由接口声明说明。 | aes128ccm_decrypt | 源码先执行 `aes_ccm_crypt` 再比较 tag，SMB3 调用方返回错误但未在本文件定义缓冲区后续生命周期。 |
