# lib/aes_apple.h Specification

## Source Context

- Source: `lib/aes_apple.h`
- Related Headers: `config.h`, `<stdint.h>`
- Related Tests: `none`
- Related Dependencies: `lib/aes_apple.c:AES128_ECB_encrypt_apple`, `lib/aes.c:AES128_ECB_encrypt`, process `Smb3_decrypt_pdu -> AES128_ECB_encrypt_apple`
- Build/Compile Context: C project; declaration is gated by `__APPLE__`, optional `HAVE_CONFIG_H`, and optional `HAVE_STDINT_H`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| AES128_ECB_encrypt_apple | function | void AES128_ECB_encrypt_apple(const uint8_t* input, const uint8_t* key, uint8_t *output); | Include | Apple 平台 AES-128 ECB 加密入口，供通用 `AES128_ECB_encrypt` 在 `__APPLE__` 构建中转调，影响 SMB3 签名/解密相关流程。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| _AES_APPLE_H_ | macro | lib/aes_apple.h:2 | 头文件 include guard，调用方重复包含时不会重复展开头文件主体。 |

## ADDED Requirements

### Requirement: AES128_ECB_encrypt_apple Apple AES-128 ECB declaration
系统 MUST 仅在 `__APPLE__` 编译条件成立时暴露 `AES128_ECB_encrypt_apple` 声明，并保持 `input`、`key`、`output` 三个字节缓冲区参数的原始指针签名，供 Apple 平台实现和调用方链接同一符号。

#### Scenario: Apple platform exposes AES declaration
- **GIVEN** 编译单元定义 `__APPLE__` 并包含 `lib/aes_apple.h`
- **WHEN** 调用方引用 `AES128_ECB_encrypt_apple` 声明
- **THEN** 头文件提供 `void AES128_ECB_encrypt_apple(const uint8_t* input, const uint8_t* key, uint8_t *output);` 声明且不声明返回错误码

Trace: `lib/aes_apple.h:AES128_ECB_encrypt_apple`, `lib/aes_apple.c:AES128_ECB_encrypt_apple`

#### Scenario: Non-Apple platform hides AES declaration
- **GIVEN** 编译单元未定义 `__APPLE__` 并包含 `lib/aes_apple.h`
- **WHEN** 预处理器处理该头文件
- **THEN** 头文件 MUST NOT 暴露 `AES128_ECB_encrypt_apple` 声明，避免非 Apple 构建依赖 Apple CommonCrypto 后端符号

Trace: `lib/aes_apple.h:AES128_ECB_encrypt_apple`, `lib/aes.c:AES128_ECB_encrypt`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `HAVE_STDINT_H` 未定义时 `uint8_t` 的来源是否由其他平台头保证？ | AES128_ECB_encrypt_apple | 头文件仅在 `HAVE_STDINT_H` 成立时包含 `<stdint.h>`，源码未在本文件内提供备用 typedef。 |
| Q-002 | `AES128_ECB_encrypt_apple` 的失败路径是否允许保持 `output` 未定义或保持原值？ | AES128_ECB_encrypt_apple | 实现文件注释说明 `CCCryptorCreate` 失败时无法向调用方传递错误，但当前头文件签名不表达该行为。 |
