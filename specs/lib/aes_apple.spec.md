# lib/aes_apple.c Specification

## Source Context

- Source: `lib/aes_apple.c`
- Related Headers: `lib/aes_apple.h`
- Related Tests: `none`
- Related Dependencies: `lib/aes.c:AES128_ECB_encrypt` calls `AES128_ECB_encrypt_apple` on Apple builds; GitNexus process `Smb3_decrypt_pdu -> AES128_ECB_encrypt_apple` includes this implementation in the AES signing/decryption flow; Apple CommonCrypto provides `CCCryptorCreate`, `CCCryptorUpdate`, and `CCCryptorRelease`.
- Build/Compile Context: C project; implementation and declaration are compiled only when `__APPLE__` is defined; `HAVE_STDINT_H` controls `stdint.h` inclusion in `lib/aes_apple.h`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| AES128_ECB_encrypt_apple | function | void AES128_ECB_encrypt_apple(const uint8_t *input, const uint8_t *key, uint8_t *output) | Include | Apple 平台 AES-128 ECB 加密入口，被 `AES128_ECB_encrypt` 作为平台后端调用，影响 SMB 签名和解密相关流程。 |
| AES128_KEY_LEN | macro | #define AES128_KEY_LEN 16 | Skip | 文件内部 CommonCrypto key 长度常量，仅服务 `AES128_ECB_encrypt_apple` 的实现约束。 |
| AES128_BLOCK_SIZE | macro | #define AES128_BLOCK_SIZE 16 | Skip | 文件内部块大小常量，仅服务 `AES128_ECB_encrypt_apple` 的输入和输出长度约束。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| AES128_KEY_LEN | macro | lib/aes_apple.c:27 | Apple CommonCrypto AES-128 key 长度固定为 16 字节。 |
| AES128_BLOCK_SIZE | macro | lib/aes_apple.c:28 | Apple CommonCrypto ECB 单块输入和输出长度固定为 16 字节。 |

## ADDED Requirements

### Requirement: AES128_ECB_encrypt_apple encrypts one AES-128 ECB block on Apple
系统 MUST 在 Apple 构建中把 `input` 指向的 16 字节明文、`key` 指向的 16 字节 AES-128 key 和 `output` 指向的输出缓冲区传递给 CommonCrypto ECB 加密后端，并以单块 16 字节大小执行加密。

#### Scenario: Apple CommonCrypto encryption succeeds
- **GIVEN** `__APPLE__` 已定义，调用方提供非空的 16 字节 `input`、16 字节 `key` 和至少 16 字节 `output` 缓冲区
- **WHEN** 调用方执行 `AES128_ECB_encrypt_apple(input, key, output)` 且 `CCCryptorCreate` 返回 `kCCSuccess`
- **THEN** 函数使用 `kCCEncrypt`、`kCCAlgorithmAES`、`kCCOptionECBMode` 和 16 字节 key 创建 cryptor，调用 `CCCryptorUpdate` 处理 16 字节输入并把结果写入 `output`，随后释放 cryptor

Trace: `lib/aes_apple.c:AES128_ECB_encrypt_apple`, `lib/aes_apple.h:AES128_ECB_encrypt_apple`

#### Scenario: Apple CommonCrypto context creation fails
- **GIVEN** `__APPLE__` 已定义，调用方提供 `input`、`key` 和 `output` 参数
- **WHEN** 调用方执行 `AES128_ECB_encrypt_apple(input, key, output)` 且 `CCCryptorCreate` 返回非 `kCCSuccess`
- **THEN** 函数 MUST 立即返回，不调用 `CCCryptorUpdate`，且不通过返回值或错误输出向调用方报告失败

Trace: `lib/aes_apple.c:AES128_ECB_encrypt_apple`

#### Scenario: Non-Apple builds exclude implementation
- **GIVEN** `__APPLE__` 未定义
- **WHEN** 编译 `lib/aes_apple.c` 和包含 `lib/aes_apple.h`
- **THEN** 文件 MUST NOT 暴露 `AES128_ECB_encrypt_apple` 的声明或实现给该编译单元

Trace: `lib/aes_apple.c:AES128_ECB_encrypt_apple`, `lib/aes_apple.h:AES128_ECB_encrypt_apple`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `CCCryptorUpdate` 返回非成功状态或写出字节数不是 16 时，调用方是否需要可观察的失败语义？ | AES128_ECB_encrypt_apple | 源码忽略 `CCCryptorUpdate` 的返回状态和 `dataOutMoved`，未发现测试覆盖该错误路径。 |
| Q-002 | `input`、`key` 或 `output` 为空指针时是否属于调用方前置条件违规？ | AES128_ECB_encrypt_apple | 源码未检查空指针，CommonCrypto 行为和项目级契约未在当前文件中说明。 |
