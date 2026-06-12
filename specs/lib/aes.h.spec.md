# lib/aes.h Specification

## Source Context

- Source: `lib/aes.h`
- Related Headers: `lib/compat.h`, `lib/aes_apple.h`, `lib/aes_reference.h`
- Related Tests: `none`
- Related Dependencies: `AES128_ECB_encrypt` is declared in this header and implemented by `lib/aes.c`; GitNexus implementation context shows callers from `lib/aes128ccm.c` and `lib/smb2-signing.c`, and implementation dispatch to `AES128_ECB_encrypt_apple` on `__APPLE__` builds or `AES128_ECB_encrypt_reference` otherwise.
- Build/Compile Context: C header included by `lib/aes.c`; `HAVE_CONFIG_H` controls inclusion of `config.h`; `compat.h` supplies `uint8_t`; `__APPLE__` affects the implementation selected by `lib/aes.c`, not this header declaration.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| AES128_ECB_encrypt | function | void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t *output); | Include | 该头文件暴露 AES-128 ECB 单块加密入口，被 CCM、CMAC 和签名路径跨文件调用，输入、密钥和输出缓冲区契约对调用方可见。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| _AES_H_ | macro | lib/aes.h:1 | 头文件 include guard，防止重复声明。 |

## ADDED Requirements

### Requirement: AES128_ECB_encrypt provides AES-128 ECB block encryption declaration
系统 MUST 通过 `lib/aes.h` 暴露 `AES128_ECB_encrypt` 声明，使调用方传入 16 字节输入块、16 字节密钥和可写输出块后获得一个 AES-128 ECB 加密块；该接口 SHALL 不返回状态码或拥有传入缓冲区。

#### Scenario: declaration is available to C translation units
- **GIVEN** C 源文件包含 `lib/aes.h`，且 `compat.h` 提供 `uint8_t` 类型
- **WHEN** 调用方按 `void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t *output);` 声明编译调用
- **THEN** 头文件提供该函数原型，调用方负责提供有效的输入、密钥和输出缓冲区，函数调用本身不产生返回值

Trace: `lib/aes.h:AES128_ECB_encrypt`, `lib/aes.c:AES128_ECB_encrypt`

#### Scenario: implementation selection remains transparent to the header caller
- **GIVEN** 调用方仅依赖 `lib/aes.h` 中的 `AES128_ECB_encrypt` 声明
- **WHEN** 链接到 `lib/aes.c` 提供的实现
- **THEN** Apple 构建 SHALL 通过 `AES128_ECB_encrypt_apple` 执行加密，非 Apple 构建 SHALL 通过 `AES128_ECB_encrypt_reference` 执行加密，且头文件声明保持相同 ABI

Trace: `lib/aes.h:AES128_ECB_encrypt`, `lib/aes.c:AES128_ECB_encrypt`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `AES128_ECB_encrypt` 是否要求 `input`、`key` 和 `output` 均指向至少 16 字节且不可为 `NULL` 的缓冲区？ | AES128_ECB_encrypt | 头文件和 `lib/aes.c` 未显式校验参数，底层 Apple/reference 实现的错误行为需要在对应实现 spec 中确认。 |
| Q-002 | Apple 路径 `AES128_ECB_encrypt_apple` 在 CommonCrypto 创建或更新失败时无状态返回，调用方是否接受输出缓冲区保持未定义或旧内容？ | AES128_ECB_encrypt | `lib/aes_apple.c` 注释说明失败无法传达给调用方，但当前头文件没有错误契约或测试证据。 |
| Q-003 | GitNexus `impact AES128_ECB_encrypt --include-tests` 因 `lib/aes.h` 声明和 `lib/aes.c` 定义同名而返回歧义，是否需要以实现符号为准补录完整上游影响？ | AES128_ECB_encrypt | CLI 不支持按 UID 运行 impact；上下文可见调用者，但 impact 风险级别未能精确解析。 |
