# lib/aes_reference.h Specification

## Source Context

- Source: `lib/aes_reference.h`
- Related Headers: `lib/aes_reference.c`, `lib/aes.h`
- Related Tests: `tests/aes128ccm-test.c`
- Related Dependencies: `lib/aes.c` calls `AES128_ECB_encrypt_reference` on non-Apple builds; GitNexus context found declarations for `AES128_ECB_encrypt_reference`, `AES128_ECB_decrypt_reference`, `AES128_CBC_encrypt_buffer_reference`, and `AES128_CBC_decrypt_buffer_reference` but no header-level callers.
- Build/Compile Context: C project; `HAVE_CONFIG_H` includes `config.h`, `HAVE_STDINT_H` includes `<stdint.h>`, `ECB` defaults to `1`, and `CBC` defaults to `0` unless overridden before inclusion or at compile time.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| CBC | macro | #define CBC 0 | Include | 公开编译期开关，控制 CBC reference API 是否声明，调用方可通过预定义覆盖默认值。 |
| ECB | macro | #define ECB 1 | Include | 公开编译期开关，控制 ECB reference API 是否声明，调用方可通过预定义覆盖默认值。 |
| AES128_ECB_encrypt_reference | function | void AES128_ECB_encrypt_reference(uint8_t* input, const uint8_t* key, uint8_t *output); | Include | 在 `ECB` 为真时公开 AES-128 ECB 单块加密 reference 声明，并被非 Apple `lib/aes.c` 包装调用。 |
| AES128_ECB_decrypt_reference | function | void AES128_ECB_decrypt_reference(uint8_t* input, const uint8_t* key, uint8_t *output); | Include | 在 `ECB` 为真时公开 AES-128 ECB 单块解密 reference 声明。 |
| AES128_CBC_encrypt_buffer_reference | function | void AES128_CBC_encrypt_buffer_reference(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, uint8_t* iv); | Include | 在 `CBC` 为真时公开 AES-128 CBC buffer 加密 reference 声明。 |
| AES128_CBC_decrypt_buffer_reference | function | void AES128_CBC_decrypt_buffer_reference(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, uint8_t* iv); | Include | 在 `CBC` 为真时公开 AES-128 CBC buffer 解密 reference 声明。 |
| _AES_REFERENCE_H_ | macro | #define _AES_REFERENCE_H_ | Skip | include guard 仅防止重复包含，无独立调用方可观察加密行为。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| CBC | macro | lib/aes_reference.h:22 | 默认关闭 CBC 声明；调用方可在包含前或编译命令中覆盖。 |
| ECB | macro | lib/aes_reference.h:26 | 默认开启 ECB 声明；调用方可在包含前或编译命令中覆盖。 |
| _AES_REFERENCE_H_ | macro | lib/aes_reference.h:5 | include guard，不生成 Requirement。 |

## ADDED Requirements

### Requirement: CBC compile-time declaration switch
系统 MUST 在调用方未预定义 `CBC` 时提供默认值 `0`，并且仅当 `defined(CBC) && CBC` 为真时声明 CBC reference API。

#### Scenario: 默认关闭 CBC declarations
- **GIVEN** 调用方包含 `lib/aes_reference.h` 前未定义 `CBC`
- **WHEN** 预处理器处理 `CBC` 相关声明区域
- **THEN** 头文件提供 `CBC` 的默认值 `0`，且不会声明 CBC encrypt/decrypt reference 函数

Trace: `lib/aes_reference.h:CBC`

#### Scenario: 外部开启 CBC declarations
- **GIVEN** 调用方包含 `lib/aes_reference.h` 前将 `CBC` 定义为真值
- **WHEN** 预处理器处理 `#if defined(CBC) && CBC` 区域
- **THEN** 头文件 MUST 暴露 `AES128_CBC_encrypt_buffer_reference` 和 `AES128_CBC_decrypt_buffer_reference` 声明

Trace: `lib/aes_reference.h:CBC`

### Requirement: ECB compile-time declaration switch
系统 MUST 在调用方未预定义 `ECB` 时提供默认值 `1`，并且仅当 `defined(ECB) && ECB` 为真时声明 ECB reference API。

#### Scenario: 默认开启 ECB declarations
- **GIVEN** 调用方包含 `lib/aes_reference.h` 前未定义 `ECB`
- **WHEN** 预处理器处理 `ECB` 相关声明区域
- **THEN** 头文件提供 `ECB` 的默认值 `1`，并声明 ECB encrypt/decrypt reference 函数

Trace: `lib/aes_reference.h:ECB`

#### Scenario: 外部关闭 ECB declarations
- **GIVEN** 调用方包含 `lib/aes_reference.h` 前将 `ECB` 定义为 `0`
- **WHEN** 预处理器处理 `#if defined(ECB) && ECB` 区域
- **THEN** 头文件 MUST NOT 暴露 `AES128_ECB_encrypt_reference` 或 `AES128_ECB_decrypt_reference` 声明

Trace: `lib/aes_reference.h:ECB`

### Requirement: AES128_ECB_encrypt_reference ECB block encryption declaration
系统 MUST 在 `ECB` 为真时声明 `AES128_ECB_encrypt_reference`，使调用方传入 16 字节输入块、128 位 key 和输出缓冲区执行 reference ECB 加密。

#### Scenario: 声明 ECB encrypt reference function
- **GIVEN** `ECB` 编译期开关为真且 `uint8_t` 可用
- **WHEN** 调用方包含 `lib/aes_reference.h`
- **THEN** 调用方可见 `AES128_ECB_encrypt_reference` 的三参数 `void` 声明，且该声明不返回错误码或状态值

Trace: `lib/aes_reference.h:AES128_ECB_encrypt_reference`, `lib/aes_reference.c:AES128_ECB_encrypt_reference`

### Requirement: AES128_ECB_decrypt_reference ECB block decryption declaration
系统 MUST 在 `ECB` 为真时声明 `AES128_ECB_decrypt_reference`，使调用方传入 16 字节输入块、128 位 key 和输出缓冲区执行 reference ECB 解密。

#### Scenario: 声明 ECB decrypt reference function
- **GIVEN** `ECB` 编译期开关为真且 `uint8_t` 可用
- **WHEN** 调用方包含 `lib/aes_reference.h`
- **THEN** 调用方可见 `AES128_ECB_decrypt_reference` 的三参数 `void` 声明，且该声明不返回错误码或状态值

Trace: `lib/aes_reference.h:AES128_ECB_decrypt_reference`, `lib/aes_reference.c:AES128_ECB_decrypt_reference`

### Requirement: AES128_CBC_encrypt_buffer_reference CBC buffer encryption declaration
系统 MUST 在 `CBC` 为真时声明 `AES128_CBC_encrypt_buffer_reference`，使调用方传入 output、input、length、key 和 iv 以 reference CBC 模式处理 buffer。

#### Scenario: 声明 CBC encrypt buffer reference function
- **GIVEN** `CBC` 编译期开关为真且 `uint32_t` 与 `uint8_t` 可用
- **WHEN** 调用方包含 `lib/aes_reference.h`
- **THEN** 调用方可见 `AES128_CBC_encrypt_buffer_reference` 的五参数 `void` 声明，且该声明不返回错误码或状态值

Trace: `lib/aes_reference.h:AES128_CBC_encrypt_buffer_reference`, `lib/aes_reference.c:AES128_CBC_encrypt_buffer_reference`

### Requirement: AES128_CBC_decrypt_buffer_reference CBC buffer decryption declaration
系统 MUST 在 `CBC` 为真时声明 `AES128_CBC_decrypt_buffer_reference`，使调用方传入 output、input、length、key 和 iv 以 reference CBC 模式处理 buffer。

#### Scenario: 声明 CBC decrypt buffer reference function
- **GIVEN** `CBC` 编译期开关为真且 `uint32_t` 与 `uint8_t` 可用
- **WHEN** 调用方包含 `lib/aes_reference.h`
- **THEN** 调用方可见 `AES128_CBC_decrypt_buffer_reference` 的五参数 `void` 声明，且该声明不返回错误码或状态值

Trace: `lib/aes_reference.h:AES128_CBC_decrypt_buffer_reference`, `lib/aes_reference.c:AES128_CBC_decrypt_buffer_reference`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `CBC` 为真时，`AES128_CBC_encrypt_buffer_reference` 和 `AES128_CBC_decrypt_buffer_reference` 中 `key == NULL` 路径是否为受支持的复用 roundKey 模式，还是未定义行为？ | AES128_CBC_encrypt_buffer_reference, AES128_CBC_decrypt_buffer_reference | 实现会跳过 key expansion，但 header 未描述调用前置条件。 |
| Q-002 | `length` 非 16 字节倍数时 CBC encrypt/decrypt reference 的零填充语义是否属于稳定 API 契约？ | AES128_CBC_encrypt_buffer_reference, AES128_CBC_decrypt_buffer_reference | 实现文件注释和代码存在零填充行为，header 未说明调用方应如何配置输出缓冲区大小。 |
| Q-003 | GitNexus `impact` 对四个声明返回同名声明/实现歧义且 CLI 不支持 UID/file disambiguation，调用方影响范围需在实现文件 spec 中继续确认。 | file-level | Header context 未返回调用者；源码 grep 显示 `lib/aes.c` 调用 `AES128_ECB_encrypt_reference`。 |
