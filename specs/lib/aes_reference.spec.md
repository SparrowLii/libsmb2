# lib/aes_reference.c Specification

## Source Context

- Source: `lib/aes_reference.c`
- Related Headers: `lib/aes_reference.h`, `lib/compat.h`
- Related Tests: `tests/aes128ccm-test.c`
- Related Dependencies: `AES128_ECB_encrypt_reference` is called by `lib/aes.c:AES128_ECB_encrypt`, which feeds `lib/aes128ccm.c` AES-CCM helpers and `lib/smb2-signing.c` CMAC/signature paths; GitNexus reports downstream helper calls to `smb2_KeyExpansion`, `smb2_Cipher`, `smb2_InvCipher`, `BlockCopy`, and `XorWithIv`.
- Build/Compile Context: `lib/CMakeLists.txt` and `lib/Makefile.am` include `aes_reference.c`; `lib/aes_reference.h` defaults `ECB` to `1` and `CBC` to `0`, so ECB reference entry points are emitted by default while CBC entry points require `CBC` truthy at preprocessing time.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| AES128_ECB_encrypt_reference | function | void AES128_ECB_encrypt_reference(uint8_t* input, const uint8_t* key, uint8_t *output); | Include | 默认 `ECB=1` 时公开的 AES-128 ECB 参考加密入口，被 `AES128_ECB_encrypt` 包装并影响 AES-CCM 与 SMB 签名链路。 |
| AES128_ECB_decrypt_reference | function | void AES128_ECB_decrypt_reference(uint8_t* input, const uint8_t* key, uint8_t *output); | Include | 默认 `ECB=1` 时公开的 AES-128 ECB 参考解密入口，提供 16 字节块解密行为。 |
| AES128_CBC_encrypt_buffer_reference | function | void AES128_CBC_encrypt_buffer_reference(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, uint8_t* iv); | Include | `CBC` 构建条件启用时公开的 AES-128 CBC buffer 加密入口，包含 IV 链接和尾块零填充行为。 |
| AES128_CBC_decrypt_buffer_reference | function | void AES128_CBC_decrypt_buffer_reference(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, uint8_t* iv); | Include | `CBC` 构建条件启用时公开的 AES-128 CBC buffer 解密入口，包含 IV 链接和尾块零填充行为。 |
| smb2_KeyExpansion | function | static void smb2_KeyExpansion(const uint8_t* Key, uint8_t* roundKey) | Skip | 文件内部 AES round key helper，仅由本文件公开入口间接调用，无独立外部调用契约。 |
| smb2_Cipher | function | static void smb2_Cipher(uint8_t* roundKey, smb2_state_t* state) | Skip | 文件内部 AES block 加密 helper，行为归属到公开 ECB/CBC 加密入口。 |
| smb2_InvCipher | function | static void smb2_InvCipher(uint8_t* roundKey, smb2_state_t* state) | Skip | 文件内部 AES block 解密 helper，行为归属到公开 ECB/CBC 解密入口。 |
| BlockCopy | function | static void BlockCopy(uint8_t* output, uint8_t* input) | Skip | 文件内部 16 字节复制 helper，无独立外部可见 API。 |
| XorWithIv | function | static void XorWithIv(uint8_t* buf, uint8_t* iv) | Skip | `CBC` 条件下的文件内部 IV XOR helper，行为归属到 CBC 入口。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| Nb | macro | lib/aes_reference.c:49 | AES state column数固定为 `4`。 |
| Nk | macro | lib/aes_reference.c:51 | AES-128 key word 数固定为 `4`。 |
| KEYLEN | macro | lib/aes_reference.c:53 | AES-128 key/block 字节数固定为 `16`，也用于 CBC 分块和零填充。 |
| Nr | macro | lib/aes_reference.c:55 | AES-128 round 数固定为 `10`。 |
| MULTIPLY_AS_A_FUNCTION | macro | lib/aes_reference.c:60 | 未预定义时默认为 `0`，控制 `smb2_Multiply` 作为宏或静态函数实现。 |
| smb2_state_t | typedef | lib/aes_reference.c:66 | 内部 AES state 表示为 `uint8_t[4][4]`。 |
| CBC | macro | lib/aes_reference.h:22 | 未预定义时默认为 `0`，控制 CBC reference API 是否声明和编译。 |
| ECB | macro | lib/aes_reference.h:26 | 未预定义时默认为 `1`，控制 ECB reference API 是否声明和编译。 |

## ADDED Requirements

### Requirement: AES128_ECB_encrypt_reference encrypts one AES-128 block
系统 MUST 在 `ECB` 条件启用时提供 `AES128_ECB_encrypt_reference`，并 SHALL 将 `input` 指向的 16 字节明文复制到 `output` 后使用 `key` 展开的 AES-128 round keys 原地加密 `output`。

#### Scenario: encrypt a single ECB block
- **GIVEN** `ECB` 预处理条件为真，`input` 指向至少 16 字节明文，`key` 指向 16 字节 AES-128 key，且 `output` 指向至少 16 字节可写缓冲区
- **WHEN** 调用 `AES128_ECB_encrypt_reference(input, key, output)`
- **THEN** 函数先复制 16 字节输入到输出缓冲区，再执行 AES-128 key expansion 和 AES cipher，使 `output` 包含该单块明文的 ECB 密文

Trace: `lib/aes_reference.c:AES128_ECB_encrypt_reference`, `lib/aes_reference.h:AES128_ECB_encrypt_reference`, `tests/aes128ccm-test.c:main`

### Requirement: AES128_ECB_decrypt_reference decrypts one AES-128 block
系统 MUST 在 `ECB` 条件启用时提供 `AES128_ECB_decrypt_reference`，并 SHALL 将 `input` 指向的 16 字节密文复制到 `output` 后使用 `key` 展开的 AES-128 round keys 原地解密 `output`。

#### Scenario: decrypt a single ECB block
- **GIVEN** `ECB` 预处理条件为真，`input` 指向至少 16 字节密文，`key` 指向 16 字节 AES-128 key，且 `output` 指向至少 16 字节可写缓冲区
- **WHEN** 调用 `AES128_ECB_decrypt_reference(input, key, output)`
- **THEN** 函数先复制 16 字节输入到输出缓冲区，再执行 AES-128 key expansion 和 inverse AES cipher，使 `output` 包含该单块密文的 ECB 明文

Trace: `lib/aes_reference.c:AES128_ECB_decrypt_reference`, `lib/aes_reference.h:AES128_ECB_decrypt_reference`

### Requirement: AES128_CBC_encrypt_buffer_reference encrypts CBC buffers with zero padding
系统 MUST 在 `CBC` 条件启用时提供 `AES128_CBC_encrypt_buffer_reference`，并 SHALL 按 16 字节块执行 IV XOR、AES-128 block 加密和 CBC 链接；当 `length % 16 != 0` 时，尾块 MUST 使用零字节填充到 16 字节后再加密。

#### Scenario: encrypt full CBC blocks
- **GIVEN** `CBC` 预处理条件为真，`length` 为 16 的整数倍，`input` 与 `output` 覆盖 `length` 字节，`key` 指向 16 字节 AES-128 key，且 `iv` 指向 16 字节初始向量
- **WHEN** 调用 `AES128_CBC_encrypt_buffer_reference(output, input, length, key, iv)`
- **THEN** 每个 16 字节明文块先与当前 IV 或前一密文块 XOR，再被 AES-128 加密写入对应输出块

Trace: `lib/aes_reference.c:AES128_CBC_encrypt_buffer_reference`, `lib/aes_reference.h:AES128_CBC_encrypt_buffer_reference`

#### Scenario: encrypt partial final CBC block
- **GIVEN** `CBC` 预处理条件为真，`length % 16 != 0`，且输入缓冲区在尾部剩余不足 16 字节
- **WHEN** 调用 `AES128_CBC_encrypt_buffer_reference(output, input, length, key, iv)`
- **THEN** 函数复制尾部剩余字节到输出尾块，将剩余位置填充为零，并对该 16 字节尾块执行 AES-128 加密

Trace: `lib/aes_reference.c:AES128_CBC_encrypt_buffer_reference`, `lib/aes_reference.h:AES128_CBC_encrypt_buffer_reference`

### Requirement: AES128_CBC_decrypt_buffer_reference decrypts CBC buffers with zero-filled tail handling
系统 MUST 在 `CBC` 条件启用时提供 `AES128_CBC_decrypt_buffer_reference`，并 SHALL 按 16 字节块执行 AES-128 inverse cipher、IV XOR 和 CBC 链接；当 `length % 16 != 0` 时，尾块 MUST 先用零字节补齐到 16 字节后再执行 inverse cipher。

#### Scenario: decrypt full CBC blocks
- **GIVEN** `CBC` 预处理条件为真，`length` 为 16 的整数倍，`input` 与 `output` 覆盖 `length` 字节，`key` 指向 16 字节 AES-128 key，且 `iv` 指向 16 字节初始向量
- **WHEN** 调用 `AES128_CBC_decrypt_buffer_reference(output, input, length, key, iv)`
- **THEN** 每个 16 字节密文块先被 AES-128 inverse cipher 解密，再与当前 IV 或前一密文块 XOR 写入对应输出块

Trace: `lib/aes_reference.c:AES128_CBC_decrypt_buffer_reference`, `lib/aes_reference.h:AES128_CBC_decrypt_buffer_reference`

#### Scenario: decrypt partial final CBC block
- **GIVEN** `CBC` 预处理条件为真，`length % 16 != 0`，且输入缓冲区在尾部剩余不足 16 字节
- **WHEN** 调用 `AES128_CBC_decrypt_buffer_reference(output, input, length, key, iv)`
- **THEN** 函数复制尾部剩余字节到输出尾块，将剩余位置填充为零，并对该 16 字节尾块执行 AES-128 inverse cipher

Trace: `lib/aes_reference.c:AES128_CBC_decrypt_buffer_reference`, `lib/aes_reference.h:AES128_CBC_decrypt_buffer_reference`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `AES128_CBC_encrypt_buffer_reference` 和 `AES128_CBC_decrypt_buffer_reference` 在 `key == NULL` 时跳过 key expansion 但仍使用栈上 `roundKey`，调用方是否曾依赖预初始化或未定义 round key 状态？ | AES128_CBC_encrypt_buffer_reference, AES128_CBC_decrypt_buffer_reference | 源码存在 `if(0 != key)` 条件，但未发现调用方或测试解释 `key == NULL` 的合法语义。 |
| Q-002 | CBC 解密的 partial final block 路径只执行 inverse cipher，未在尾块路径执行 `XorWithIv`，这是否为有意兼容行为？ | AES128_CBC_decrypt_buffer_reference | 源码显示尾块路径与 full block 路径不同，当前仓库未定位到 CBC 测试证据。 |
| Q-003 | `input` 与 `output` 重叠或相同地址时，ECB/CBC 入口是否承诺安全行为？ | file-level | 源码先复制输入到输出再处理输出，但没有头文件注释或测试定义 aliasing 契约。 |
