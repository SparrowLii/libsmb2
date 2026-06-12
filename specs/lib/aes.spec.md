# lib/aes.c Specification

## Source Context

- Source: `lib/aes.c`
- Related Headers: `lib/aes.h`, `lib/aes_apple.h`, `lib/aes_reference.h`
- Related Tests: `tests/aes128ccm-test.c`
- Related Dependencies: `AES128_ECB_encrypt` calls `AES128_ECB_encrypt_apple` on `__APPLE__` builds and `AES128_ECB_encrypt_reference` otherwise; GitNexus upstream impact identifies direct callers in `lib/aes128ccm.c` and `lib/smb2-signing.c`.
- Build/Compile Context: `CMakeLists.txt` builds C sources through `lib/CMakeLists.txt`; `lib/aes.c` selects the Apple CommonCrypto backend when `__APPLE__` is defined and the reference backend otherwise.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| AES128_ECB_encrypt | function | void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t *output); | Include | 跨文件公开包装入口，被 AES-CCM 与 SMB2 签名调用，平台分派和输出缓冲语义对调用方可见。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| 无 | none | none | 无公开数据模型。 |

## ADDED Requirements

### Requirement: AES128_ECB_encrypt platform backend dispatch
系统 MUST 根据编译期 `__APPLE__` 条件把单块 AES-128 ECB 加密请求分派到对应后端，并保持 `void` 返回和调用方提供缓冲区的接口契约。

#### Scenario: Apple build dispatches to CommonCrypto backend
- **GIVEN** 调用方提供 16 字节输入缓冲区、16 字节 AES-128 key 和可写输出缓冲区，且编译环境定义 `__APPLE__`
- **WHEN** 调用方调用 `AES128_ECB_encrypt(input, key, output)`
- **THEN** 实现 MUST 调用 `AES128_ECB_encrypt_apple(input, key, output)` 并通过调用方提供的 `output` 返回后端产生的密文块

Trace: `lib/aes.c:AES128_ECB_encrypt`, `lib/aes_apple.c:AES128_ECB_encrypt_apple`

#### Scenario: Non-Apple build dispatches to reference backend
- **GIVEN** 调用方提供 16 字节输入缓冲区、16 字节 AES-128 key 和可写输出缓冲区，且编译环境未定义 `__APPLE__`
- **WHEN** 调用方调用 `AES128_ECB_encrypt(input, key, output)`
- **THEN** 实现 MUST 调用 `AES128_ECB_encrypt_reference(input, key, output)` 并通过调用方提供的 `output` 返回 reference 后端产生的密文块

Trace: `lib/aes.c:AES128_ECB_encrypt`, `lib/aes_reference.c:AES128_ECB_encrypt_reference`, `tests/aes128ccm-test.c:test_1`, `tests/aes128ccm-test.c:test_2`

#### Scenario: AES-CCM callers rely on deterministic block encryption
- **GIVEN** AES-CCM 认证加密或解密逻辑正在生成认证块或计数器流块
- **WHEN** `ccm_generate_T` 或 `ccm_generate_s` 调用 `AES128_ECB_encrypt` 处理 16 字节中间块
- **THEN** 该接口 MUST 为相同的输入块和 key 产生稳定的 AES-128 ECB 输出，使 `aes128ccm_encrypt` 与 `aes128ccm_decrypt` 能通过已知向量和回环校验

Trace: `lib/aes.c:AES128_ECB_encrypt`, `lib/aes128ccm.c:ccm_generate_T`, `lib/aes128ccm.c:ccm_generate_s`, `tests/aes128ccm-test.c:test_1`, `tests/aes128ccm-test.c:test_2`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | Apple 后端在 `CCCryptorCreate` 失败时直接返回且不写错误码，调用方是否依赖 `output` 保持原值或允许未定义内容？ | AES128_ECB_encrypt | `lib/aes_apple.c` 注释说明无法向调用方报告失败，但未声明失败时输出缓冲区的稳定语义。 |
| Q-002 | `AES128_ECB_encrypt` 是否要求 `input`、`key`、`output` 均非 NULL 且至少覆盖 16 字节？ | AES128_ECB_encrypt | 源码和头文件未执行参数校验，调用方均按 16 字节块传入，但契约未显式声明。 |
