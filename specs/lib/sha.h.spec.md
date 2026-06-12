# lib/sha.h Specification

## Source Context

- Source: `lib/sha.h`
- Related Headers: `lib/sha-private.h`, `lib/compat.h`
- Related Tests: `none`
- Related Dependencies: `lib/sha1.c`, `lib/sha224-256.c`, `lib/sha384-512.c`, `lib/usha.c`, `lib/hmac.c`, `lib/smb2-signing.c`, `lib/libsmb2.c`
- Build/Compile Context: `C project; sha.h conditionally includes config.h, stdint.h, and stdlib.h; USE_SHA1 defaults to 0, USE_SHA224 defaults to 0, and USE_SHA384_SHA512 defaults to 1 unless overridden.`

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| USE_SHA1 | macro | `#define USE_SHA1 0` | Include | 公开编译期开关，控制 SHA-1 枚举、上下文和函数声明是否可见。 |
| USE_SHA224 | macro | `#define USE_SHA224 0` | Include | 公开编译期开关，控制 SHA-224 枚举、上下文别名和函数声明是否可见。 |
| USE_SHA384_SHA512 | macro | `#define USE_SHA384_SHA512 1` | Include | 公开编译期开关，控制 SHA-384/SHA-512 枚举、上下文别名和函数声明是否可见。 |
| shaSuccess | enum constant | `shaSuccess = 0` | Include | 所有 SHA/HMAC 接口共享成功返回码。 |
| shaNull | enum constant | `shaNull` | Include | 所有 SHA/HMAC 接口共享空指针参数返回码。 |
| shaInputTooLong | enum constant | `shaInputTooLong` | Include | 头文件声明的输入过长返回码，属于调用方可见错误码集合。 |
| shaStateError | enum constant | `shaStateError` | Include | 所有 SHA/HMAC 输入终结后状态错误返回码。 |
| shaBadParam | enum constant | `shaBadParam` | Include | 统一 SHA 接口用于非法 SHA 版本的返回码。 |
| SHA1Context | typedef struct | `typedef struct SHA1Context { ... } SHA1Context;` | Include | `USE_SHA1` 启用时公开的调用方持有 SHA-1 可变上下文。 |
| SHA256Context | typedef struct | `typedef struct SHA256Context { ... } SHA256Context;` | Include | SHA-256 公开上下文，保存摘要中间状态、长度、消息块和状态标志。 |
| SHA512Context | typedef struct | `typedef struct SHA512Context { ... } SHA512Context;` | Include | SHA-512/SHA-384 公开上下文，布局受 `USE_32BIT_ONLY` 影响。 |
| SHA224Context | typedef | `typedef struct SHA256Context SHA224Context;` | Include | `USE_SHA224` 启用时的 SHA-224 上下文别名，复用 SHA-256 布局。 |
| SHA384Context | typedef | `typedef struct SHA512Context SHA384Context;` | Include | `USE_SHA384_SHA512` 启用时的 SHA-384 上下文别名，复用 SHA-512 布局。 |
| SHAversion | typedef enum | `typedef enum SHAversion { ... } SHAversion;` | Include | 统一 SHA 和 HMAC API 的算法选择枚举，成员随编译期开关变化。 |
| USHAContext | typedef struct | `typedef struct USHAContext { ... } USHAContext;` | Include | 统一 SHA 上下文，保存所选算法和对应具体 SHA context union。 |
| HMACContext | typedef struct | `typedef struct HMACContext { ... } HMACContext;` | Include | 流式 HMAC 上下文，保存算法、尺寸、内层 SHA context 和 outer pad。 |
| SHA1Reset | function | `extern int SHA1Reset (SHA1Context *);` | Include | `USE_SHA1` 启用时声明 SHA-1 reset 入口，实现 spec 已覆盖行为。 |
| SHA1Input | function | `extern int SHA1Input (SHA1Context *, const uint8_t * bytes, size_t bytecount);` | Include | `USE_SHA1` 启用时声明 SHA-1 增量输入入口。 |
| SHA1FinalBits | function | `extern int SHA1FinalBits (SHA1Context *, const uint8_t bits, size_t bitcount);` | Include | `USE_SHA1` 启用时声明 SHA-1 final bits 入口。 |
| SHA1Result | function | `extern int SHA1Result (SHA1Context *, uint8_t Message_Digest[SHA1HashSize]);` | Include | `USE_SHA1` 启用时声明 SHA-1 digest 输出入口。 |
| SHA224Reset | function | `extern int SHA224Reset (SHA224Context *);` | Include | `USE_SHA224` 启用时声明 SHA-224 reset 入口。 |
| SHA224Input | function | `extern int SHA224Input (SHA224Context *, const uint8_t * bytes, size_t bytecount);` | Include | `USE_SHA224` 启用时声明 SHA-224 增量输入入口。 |
| SHA224FinalBits | function | `extern int SHA224FinalBits (SHA224Context *, const uint8_t bits, size_t bitcount);` | Include | `USE_SHA224` 启用时声明 SHA-224 final bits 入口。 |
| SHA224Result | function | `extern int SHA224Result (SHA224Context *, uint8_t Message_Digest[SHA224HashSize]);` | Include | `USE_SHA224` 启用时声明 SHA-224 digest 输出入口。 |
| SHA256Reset | function | `extern int SHA256Reset (SHA256Context *);` | Include | 始终声明的 SHA-256 reset 入口。 |
| SHA256Input | function | `extern int SHA256Input (SHA256Context *, const uint8_t * bytes, size_t bytecount);` | Include | 始终声明的 SHA-256 增量输入入口。 |
| SHA256FinalBits | function | `extern int SHA256FinalBits (SHA256Context *, const uint8_t bits, size_t bitcount);` | Include | 始终声明的 SHA-256 final bits 入口。 |
| SHA256Result | function | `extern int SHA256Result (SHA256Context *, uint8_t Message_Digest[SHA256HashSize]);` | Include | 始终声明的 SHA-256 digest 输出入口。 |
| SHA384Reset | function | `extern int SHA384Reset (SHA384Context *);` | Include | `USE_SHA384_SHA512` 启用时声明 SHA-384 reset 入口。 |
| SHA384Input | function | `extern int SHA384Input (SHA384Context *, const uint8_t * bytes, size_t bytecount);` | Include | `USE_SHA384_SHA512` 启用时声明 SHA-384 增量输入入口。 |
| SHA384FinalBits | function | `extern int SHA384FinalBits (SHA384Context *, const uint8_t bits, size_t bitcount);` | Include | `USE_SHA384_SHA512` 启用时声明 SHA-384 final bits 入口。 |
| SHA384Result | function | `extern int SHA384Result (SHA384Context *, uint8_t Message_Digest[SHA384HashSize]);` | Include | `USE_SHA384_SHA512` 启用时声明 SHA-384 digest 输出入口。 |
| SHA512Reset | function | `extern int SHA512Reset (SHA512Context *);` | Include | `USE_SHA384_SHA512` 启用时声明 SHA-512 reset 入口。 |
| SHA512Input | function | `extern int SHA512Input (SHA512Context *, const uint8_t * bytes, size_t bytecount);` | Include | `USE_SHA384_SHA512` 启用时声明 SHA-512 增量输入入口。 |
| SHA512FinalBits | function | `extern int SHA512FinalBits (SHA512Context *, const uint8_t bits, size_t bitcount);` | Include | `USE_SHA384_SHA512` 启用时声明 SHA-512 final bits 入口。 |
| SHA512Result | function | `extern int SHA512Result (SHA512Context *, uint8_t Message_Digest[SHA512HashSize]);` | Include | `USE_SHA384_SHA512` 启用时声明 SHA-512 digest 输出入口。 |
| USHAReset | function | `extern int USHAReset (USHAContext *, SHAversion whichSha);` | Include | 声明统一 SHA reset 分派入口。 |
| USHAInput | function | `extern int USHAInput (USHAContext *, const uint8_t * bytes, size_t bytecount);` | Include | 声明统一 SHA 增量输入分派入口。 |
| USHAFinalBits | function | `extern int USHAFinalBits (USHAContext *, const uint8_t bits, size_t bitcount);` | Include | 声明统一 SHA final bits 分派入口。 |
| USHAResult | function | `extern int USHAResult (USHAContext *, uint8_t Message_Digest[USHAMaxHashSize]);` | Include | 声明统一 SHA digest 输出分派入口。 |
| USHABlockSize | function | `extern int USHABlockSize (enum SHAversion whichSha);` | Include | 声明按算法查询消息块大小的工具入口。 |
| USHAHashSize | function | `extern int USHAHashSize (enum SHAversion whichSha);` | Include | 声明按算法查询 digest 字节数的工具入口。 |
| USHAHashSizeBits | function | `extern int USHAHashSizeBits (enum SHAversion whichSha);` | Include | 声明按算法查询 digest bit 数的工具入口。 |
| hmac | function | `extern int hmac (SHAversion whichSha, const unsigned char *text, size_t text_len, const unsigned char *key, size_t key_len, uint8_t digest[USHAMaxHashSize]);` | Include | 声明一次性 HMAC keyed-hash 入口。 |
| hmacReset | function | `extern int hmacReset (HMACContext * ctx, enum SHAversion whichSha, const unsigned char *key, size_t key_len);` | Include | 声明流式 HMAC 初始化入口。 |
| hmacInput | function | `extern int hmacInput (HMACContext * ctx, const unsigned char *text, size_t text_len);` | Include | 声明流式 HMAC 消息输入入口。 |
| hmacFinalBits | function | `extern int hmacFinalBits (HMACContext * ctx, const uint8_t bits, size_t bitcount);` | Include | 声明流式 HMAC final bits 输入入口。 |
| hmacResult | function | `extern int hmacResult (HMACContext * ctx, uint8_t *digest);` | Include | 声明流式 HMAC digest 输出入口。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| USE_SHA1 | macro | `lib/sha.h:6` | 默认关闭 SHA-1 声明，除非构建或调用方预定义为非零。 |
| USE_SHA224 | macro | `lib/sha.h:10` | 默认关闭 SHA-224 声明，除非构建或调用方预定义为非零。 |
| USE_SHA384_SHA512 | macro | `lib/sha.h:14` | 默认启用 SHA-384/SHA-512 声明，除非构建或调用方覆盖。 |
| shaSuccess, shaNull, shaInputTooLong, shaStateError, shaBadParam | enum constants | `lib/sha.h:67` | 所有 SHA、USHA 和 HMAC 接口共享的返回码枚举。 |
| SHA*_Message_Block_Size, SHA*HashSize, SHA*HashSizeBits | enum constants | `lib/sha.h:81` | 各 SHA 算法的消息块大小、digest 字节数和 digest bit 数常量。 |
| SHAversion | typedef enum | `lib/sha.h:113` | 统一 SHA/HMAC 算法选择枚举，成员随 `USE_SHA1`、`USE_SHA224`、`USE_SHA384_SHA512` 条件变化。 |
| SHA1Context | typedef struct | `lib/sha.h:133` | `USE_SHA1` 启用时的 SHA-1 mutable context。 |
| SHA256Context | typedef struct | `lib/sha.h:153` | SHA-256 mutable context；SHA-224 通过 typedef 复用该布局。 |
| SHA512Context | typedef struct | `lib/sha.h:172` | SHA-512 mutable context；`USE_32BIT_ONLY` 改变长度和中间 hash 字段表示。 |
| SHA224Context | typedef | `lib/sha.h:194` | `USE_SHA224` 启用时映射到 `SHA256Context`。 |
| SHA384Context | typedef | `lib/sha.h:202` | `USE_SHA384_SHA512` 启用时映射到 `SHA512Context`。 |
| USHAContext | typedef struct | `lib/sha.h:209` | 保存 `whichSha` 和对应 concrete context union。 |
| HMACContext | typedef struct | `lib/sha.h:232` | 保存 HMAC 算法、尺寸、内部 SHA context 和 outer pad。 |

## ADDED Requirements

### Requirement: USE_SHA1 conditional SHA-1 API surface
系统 MUST 在调用方未预定义 `USE_SHA1` 时将其默认定义为 0，并 MUST 仅在 `defined(USE_SHA1) && USE_SHA1` 为真时暴露 SHA-1 专属常量、上下文和函数声明。

#### Scenario: SHA-1 declarations follow compile-time switch
- **GIVEN** 编译单元包含 `lib/sha.h`
- **WHEN** `USE_SHA1` 未定义或定义为 0
- **THEN** 头文件不声明 `SHA1Context`、`SHA1`、`SHA1Reset`、`SHA1Input`、`SHA1FinalBits` 或 `SHA1Result`

Trace: `lib/sha.h:USE_SHA1`, `lib/sha.h:SHA1Context`, `lib/sha.h:SHA1Reset`

### Requirement: USE_SHA224 conditional SHA-224 API surface
系统 MUST 在调用方未预定义 `USE_SHA224` 时将其默认定义为 0，并 MUST 仅在 `defined(USE_SHA224) && USE_SHA224` 为真时暴露 SHA-224 专属常量、上下文别名和函数声明。

#### Scenario: SHA-224 declarations follow compile-time switch
- **GIVEN** 编译单元包含 `lib/sha.h`
- **WHEN** `USE_SHA224` 未定义或定义为 0
- **THEN** 头文件不声明 `SHA224Context`、`SHA224`、`SHA224Reset`、`SHA224Input`、`SHA224FinalBits` 或 `SHA224Result`

Trace: `lib/sha.h:USE_SHA224`, `lib/sha.h:SHA224Context`, `lib/sha.h:SHA224Reset`

### Requirement: USE_SHA384_SHA512 conditional SHA-384 and SHA-512 API surface
系统 MUST 在调用方未预定义 `USE_SHA384_SHA512` 时将其默认定义为 1，并 MUST 仅在该宏为真时暴露 SHA-384 和 SHA-512 专属枚举、上下文和函数声明。

#### Scenario: SHA-384 and SHA-512 declarations are enabled by default
- **GIVEN** 编译单元包含 `lib/sha.h` 且未预定义 `USE_SHA384_SHA512`
- **WHEN** 预处理头文件
- **THEN** `SHA384Context`、`SHA512Context`、`SHA384Reset` 和 `SHA512Reset` 对调用方可见

Trace: `lib/sha.h:USE_SHA384_SHA512`, `lib/sha.h:SHA384Context`, `lib/sha.h:SHA512Reset`

### Requirement: shaSuccess success return code
系统 MUST 将 `shaSuccess` 定义为数值 0，供 SHA、USHA 和 HMAC 接口表示成功完成。

#### Scenario: success code is zero
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方比较 SHA 系列接口返回值和 `shaSuccess`
- **THEN** `shaSuccess` 的值为 0

Trace: `lib/sha.h:shaSuccess`

### Requirement: shaNull null pointer return code
系统 MUST 在共享 SHA 返回码枚举中提供 `shaNull`，供实现对空指针参数错误进行调用方可见报告。

#### Scenario: null error code is part of public enum
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方引用 `shaNull`
- **THEN** 该枚举常量可用于区分空指针参数错误

Trace: `lib/sha.h:shaNull`, `lib/sha1.c:SHA1Reset`, `lib/hmac.c:hmacReset`

### Requirement: shaInputTooLong input length error code
系统 MUST 在共享 SHA 返回码枚举中提供 `shaInputTooLong`，用于表示输入数据长度超出算法可表示范围的公开错误分类。

#### Scenario: input-too-long error code is part of public enum
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方引用 `shaInputTooLong`
- **THEN** 该枚举常量可用于表达输入数据过长错误类别

Trace: `lib/sha.h:shaInputTooLong`, `lib/sha224-256.c:SHA224_256AddLength`, `lib/sha384-512.c:SHA384_512AddLength`

### Requirement: shaStateError state error return code
系统 MUST 在共享 SHA 返回码枚举中提供 `shaStateError`，用于表示调用方在 Result 或 FinalBits 之后继续输入等非法状态转换。

#### Scenario: state error code is part of public enum
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方引用 `shaStateError`
- **THEN** 该枚举常量可用于识别 SHA context 状态错误

Trace: `lib/sha.h:shaStateError`, `lib/sha224-256.c:SHA256Input`

### Requirement: shaBadParam bad parameter return code
系统 MUST 在共享 SHA 返回码枚举中提供 `shaBadParam`，用于统一 SHA 分派接口报告不支持或非法的 `SHAversion`。

#### Scenario: bad parameter code is part of public enum
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方引用 `shaBadParam`
- **THEN** 该枚举常量可用于识别非法算法选择

Trace: `lib/sha.h:shaBadParam`, `lib/usha.c:USHAReset`

### Requirement: SHA1Context public SHA-1 context layout
系统 MUST 在 `USE_SHA1` 启用时提供 `SHA1Context`，并 MUST 包含中间 hash、bit 长度、消息块、`Computed` 和 `Corrupted` 状态字段。

#### Scenario: SHA-1 context is caller-owned state
- **GIVEN** `USE_SHA1` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方定义 `SHA1Context context`
- **THEN** 该类型可由 `SHA1Reset` 初始化并由 SHA-1 输入和结果函数持续更新

Trace: `lib/sha.h:SHA1Context`, `lib/sha1.c:SHA1Reset`

### Requirement: SHA256Context public SHA-256 context layout
系统 MUST 提供 `SHA256Context`，并 MUST 包含 SHA-256 中间 hash、64-bit 分拆长度、消息块、`Computed` 和 `Corrupted` 状态字段。

#### Scenario: SHA-256 context is caller-owned state
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方定义 `SHA256Context context`
- **THEN** 该类型可由 `SHA256Reset` 初始化并由 SHA-256 输入和结果函数持续更新

Trace: `lib/sha.h:SHA256Context`, `lib/sha224-256.c:SHA256Reset`

### Requirement: SHA512Context public SHA-512 context layout
系统 MUST 提供 `SHA512Context`，并 MUST 根据 `USE_32BIT_ONLY` 选择 32-bit emulation 字段或 native `uint64_t` 字段，同时保持调用方可见类型名稳定。

#### Scenario: SHA-512 context layout follows compile branch
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** `USE_32BIT_ONLY` 启用或未启用
- **THEN** `SHA512Context` 均提供消息块索引、消息块、`Computed` 和 `Corrupted` 字段，并可被 SHA-512/SHA-384 实现使用

Trace: `lib/sha.h:SHA512Context`, `lib/sha384-512.c:SHA512Reset`

### Requirement: SHA224Context SHA-256-backed context alias
系统 MUST 在 `USE_SHA224` 启用时将 `SHA224Context` 定义为 `SHA256Context` 的 typedef，使 SHA-224 公开 API 复用 SHA-256 上下文布局。

#### Scenario: SHA-224 context aliases SHA-256 context
- **GIVEN** `USE_SHA224` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方定义 `SHA224Context context`
- **THEN** 该对象具有 `SHA256Context` 布局并可传递给 SHA-224 wrapper 函数

Trace: `lib/sha.h:SHA224Context`, `lib/sha224-256.c:SHA224Reset`

### Requirement: SHA384Context SHA-512-backed context alias
系统 MUST 在 `USE_SHA384_SHA512` 启用时将 `SHA384Context` 定义为 `SHA512Context` 的 typedef，使 SHA-384 公开 API 复用 SHA-512 上下文布局。

#### Scenario: SHA-384 context aliases SHA-512 context
- **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方定义 `SHA384Context context`
- **THEN** 该对象具有 `SHA512Context` 布局并可传递给 SHA-384 wrapper 函数

Trace: `lib/sha.h:SHA384Context`, `lib/sha384-512.c:SHA384Reset`

### Requirement: SHAversion algorithm selector
系统 MUST 提供 `SHAversion` 枚举作为 USHA 和 HMAC 的算法选择输入，并 MUST 仅包含当前编译期开关启用的 SHA1、SHA224、SHA384、SHA512 成员以及始终可用的 SHA256 成员。

#### Scenario: algorithm enum follows enabled algorithms
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 预处理 `SHAversion` 定义
- **THEN** `SHA256` 始终可见，其他算法枚举成员按对应 `USE_*` 宏可见

Trace: `lib/sha.h:SHAversion`, `lib/usha.c:USHAReset`

### Requirement: USHAContext unified SHA context union
系统 MUST 提供 `USHAContext`，并 MUST 保存所选 `SHAversion` 以及与启用算法匹配的 concrete SHA context union 成员。

#### Scenario: unified context stores selected SHA state
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方定义 `USHAContext ctx` 并通过 `USHAReset` 设置算法
- **THEN** `ctx.whichSha` 记录算法，`ctx.ctx` union 保存对应 SHA 实现上下文

Trace: `lib/sha.h:USHAContext`, `lib/usha.c:USHAReset`

### Requirement: HMACContext streaming HMAC context
系统 MUST 提供 `HMACContext`，并 MUST 保存 HMAC 所需算法、hash size、block size、inner SHA context 和 outer padding 缓冲区。

#### Scenario: HMAC context carries stream state
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方定义 `HMACContext ctx` 并调用 `hmacReset`
- **THEN** 该 context 可被 `hmacInput`、`hmacFinalBits` 和 `hmacResult` 持续使用

Trace: `lib/sha.h:HMACContext`, `lib/hmac.c:hmacReset`

### Requirement: SHA1Reset declaration contract
系统 MUST 在 `USE_SHA1` 启用时声明 `SHA1Reset`，并 SHALL 让调用方通过该声明初始化 `SHA1Context`。

#### Scenario: SHA-1 reset declaration is visible when enabled
- **GIVEN** `USE_SHA1` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA1Reset` 的调用
- **THEN** 声明接受 `SHA1Context *` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA1Reset`, `lib/sha1.c:SHA1Reset`

### Requirement: SHA1Input declaration contract
系统 MUST 在 `USE_SHA1` 启用时声明 `SHA1Input`，并 SHALL 让调用方追加字节输入到 `SHA1Context`。

#### Scenario: SHA-1 input declaration is visible when enabled
- **GIVEN** `USE_SHA1` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA1Input` 的调用
- **THEN** 声明接受 `SHA1Context *`、`const uint8_t *` 和 `size_t` 长度并返回 SHA 错误码

Trace: `lib/sha.h:SHA1Input`, `lib/sha1.c:SHA1Input`

### Requirement: SHA1FinalBits declaration contract
系统 MUST 在 `USE_SHA1` 启用时声明 `SHA1FinalBits`，并 SHALL 让调用方追加 1 到 7 个最终 bit。

#### Scenario: SHA-1 final bits declaration is visible when enabled
- **GIVEN** `USE_SHA1` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA1FinalBits` 的调用
- **THEN** 声明接受 `SHA1Context *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA1FinalBits`, `lib/sha1.c:SHA1FinalBits`

### Requirement: SHA1Result declaration contract
系统 MUST 在 `USE_SHA1` 启用时声明 `SHA1Result`，并 SHALL 让调用方获取 `SHA1HashSize` 字节摘要。

#### Scenario: SHA-1 result declaration is visible when enabled
- **GIVEN** `USE_SHA1` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA1Result` 的调用
- **THEN** 声明接受 `SHA1Context *` 和 `uint8_t Message_Digest[SHA1HashSize]` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA1Result`, `lib/sha1.c:SHA1Result`

### Requirement: SHA224Reset declaration contract
系统 MUST 在 `USE_SHA224` 启用时声明 `SHA224Reset`，并 SHALL 让调用方初始化 SHA-224 context。

#### Scenario: SHA-224 reset declaration is visible when enabled
- **GIVEN** `USE_SHA224` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA224Reset` 的调用
- **THEN** 声明接受 `SHA224Context *` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA224Reset`, `lib/sha224-256.c:SHA224Reset`

### Requirement: SHA224Input declaration contract
系统 MUST 在 `USE_SHA224` 启用时声明 `SHA224Input`，并 SHALL 让调用方追加字节输入到 SHA-224 context。

#### Scenario: SHA-224 input declaration is visible when enabled
- **GIVEN** `USE_SHA224` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA224Input` 的调用
- **THEN** 声明接受 `SHA224Context *`、`const uint8_t *` 和 `size_t` 长度并返回 SHA 错误码

Trace: `lib/sha.h:SHA224Input`, `lib/sha224-256.c:SHA224Input`

### Requirement: SHA224FinalBits declaration contract
系统 MUST 在 `USE_SHA224` 启用时声明 `SHA224FinalBits`，并 SHALL 让调用方追加 SHA-224 final bits。

#### Scenario: SHA-224 final bits declaration is visible when enabled
- **GIVEN** `USE_SHA224` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA224FinalBits` 的调用
- **THEN** 声明接受 `SHA224Context *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA224FinalBits`, `lib/sha224-256.c:SHA224FinalBits`

### Requirement: SHA224Result declaration contract
系统 MUST 在 `USE_SHA224` 启用时声明 `SHA224Result`，并 SHALL 让调用方获取 `SHA224HashSize` 字节摘要。

#### Scenario: SHA-224 result declaration is visible when enabled
- **GIVEN** `USE_SHA224` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA224Result` 的调用
- **THEN** 声明接受 `SHA224Context *` 和 `uint8_t Message_Digest[SHA224HashSize]` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA224Result`, `lib/sha224-256.c:SHA224Result`

### Requirement: SHA256Reset declaration contract
系统 MUST 声明 `SHA256Reset`，并 SHALL 让调用方初始化 SHA-256 context。

#### Scenario: SHA-256 reset declaration is always visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA256Reset` 的调用
- **THEN** 声明接受 `SHA256Context *` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA256Reset`, `lib/sha224-256.c:SHA256Reset`

### Requirement: SHA256Input declaration contract
系统 MUST 声明 `SHA256Input`，并 SHALL 让调用方追加字节输入到 SHA-256 context。

#### Scenario: SHA-256 input declaration is always visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA256Input` 的调用
- **THEN** 声明接受 `SHA256Context *`、`const uint8_t *` 和 `size_t` 长度并返回 SHA 错误码

Trace: `lib/sha.h:SHA256Input`, `lib/sha224-256.c:SHA256Input`

### Requirement: SHA256FinalBits declaration contract
系统 MUST 声明 `SHA256FinalBits`，并 SHALL 让调用方追加 SHA-256 final bits。

#### Scenario: SHA-256 final bits declaration is always visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA256FinalBits` 的调用
- **THEN** 声明接受 `SHA256Context *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA256FinalBits`, `lib/sha224-256.c:SHA256FinalBits`

### Requirement: SHA256Result declaration contract
系统 MUST 声明 `SHA256Result`，并 SHALL 让调用方获取 `SHA256HashSize` 字节摘要。

#### Scenario: SHA-256 result declaration is always visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA256Result` 的调用
- **THEN** 声明接受 `SHA256Context *` 和 `uint8_t Message_Digest[SHA256HashSize]` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA256Result`, `lib/sha224-256.c:SHA256Result`

### Requirement: SHA384Reset declaration contract
系统 MUST 在 `USE_SHA384_SHA512` 启用时声明 `SHA384Reset`，并 SHALL 让调用方初始化 SHA-384 context。

#### Scenario: SHA-384 reset declaration is visible when enabled
- **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA384Reset` 的调用
- **THEN** 声明接受 `SHA384Context *` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA384Reset`, `lib/sha384-512.c:SHA384Reset`

### Requirement: SHA384Input declaration contract
系统 MUST 在 `USE_SHA384_SHA512` 启用时声明 `SHA384Input`，并 SHALL 让调用方追加字节输入到 SHA-384 context。

#### Scenario: SHA-384 input declaration is visible when enabled
- **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA384Input` 的调用
- **THEN** 声明接受 `SHA384Context *`、`const uint8_t *` 和 `size_t` 长度并返回 SHA 错误码

Trace: `lib/sha.h:SHA384Input`, `lib/sha384-512.c:SHA384Input`

### Requirement: SHA384FinalBits declaration contract
系统 MUST 在 `USE_SHA384_SHA512` 启用时声明 `SHA384FinalBits`，并 SHALL 让调用方追加 SHA-384 final bits。

#### Scenario: SHA-384 final bits declaration is visible when enabled
- **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA384FinalBits` 的调用
- **THEN** 声明接受 `SHA384Context *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA384FinalBits`, `lib/sha384-512.c:SHA384FinalBits`

### Requirement: SHA384Result declaration contract
系统 MUST 在 `USE_SHA384_SHA512` 启用时声明 `SHA384Result`，并 SHALL 让调用方获取 `SHA384HashSize` 字节摘要。

#### Scenario: SHA-384 result declaration is visible when enabled
- **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA384Result` 的调用
- **THEN** 声明接受 `SHA384Context *` 和 `uint8_t Message_Digest[SHA384HashSize]` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA384Result`, `lib/sha384-512.c:SHA384Result`

### Requirement: SHA512Reset declaration contract
系统 MUST 在 `USE_SHA384_SHA512` 启用时声明 `SHA512Reset`，并 SHALL 让调用方初始化 SHA-512 context。

#### Scenario: SHA-512 reset declaration is visible when enabled
- **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA512Reset` 的调用
- **THEN** 声明接受 `SHA512Context *` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA512Reset`, `lib/sha384-512.c:SHA512Reset`

### Requirement: SHA512Input declaration contract
系统 MUST 在 `USE_SHA384_SHA512` 启用时声明 `SHA512Input`，并 SHALL 让调用方追加字节输入到 SHA-512 context。

#### Scenario: SHA-512 input declaration is visible when enabled
- **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA512Input` 的调用
- **THEN** 声明接受 `SHA512Context *`、`const uint8_t *` 和 `size_t` 长度并返回 SHA 错误码

Trace: `lib/sha.h:SHA512Input`, `lib/sha384-512.c:SHA512Input`

### Requirement: SHA512FinalBits declaration contract
系统 MUST 在 `USE_SHA384_SHA512` 启用时声明 `SHA512FinalBits`，并 SHALL 让调用方追加 SHA-512 final bits。

#### Scenario: SHA-512 final bits declaration is visible when enabled
- **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA512FinalBits` 的调用
- **THEN** 声明接受 `SHA512Context *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA512FinalBits`, `lib/sha384-512.c:SHA512FinalBits`

### Requirement: SHA512Result declaration contract
系统 MUST 在 `USE_SHA384_SHA512` 启用时声明 `SHA512Result`，并 SHALL 让调用方获取 `SHA512HashSize` 字节摘要。

#### Scenario: SHA-512 result declaration is visible when enabled
- **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `SHA512Result` 的调用
- **THEN** 声明接受 `SHA512Context *` 和 `uint8_t Message_Digest[SHA512HashSize]` 并返回 SHA 错误码

Trace: `lib/sha.h:SHA512Result`, `lib/sha384-512.c:SHA512Result`

### Requirement: USHAReset declaration contract
系统 MUST 声明 `USHAReset`，并 SHALL 让调用方通过 `SHAversion` 选择具体 SHA 算法初始化 `USHAContext`。

#### Scenario: unified SHA reset declaration is visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `USHAReset` 的调用
- **THEN** 声明接受 `USHAContext *` 和 `SHAversion` 并返回 SHA 错误码

Trace: `lib/sha.h:USHAReset`, `lib/usha.c:USHAReset`

### Requirement: USHAInput declaration contract
系统 MUST 声明 `USHAInput`，并 SHALL 让调用方按 `USHAContext.whichSha` 分派字节输入。

#### Scenario: unified SHA input declaration is visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `USHAInput` 的调用
- **THEN** 声明接受 `USHAContext *`、`const uint8_t *` 和 `size_t` 长度并返回 SHA 错误码

Trace: `lib/sha.h:USHAInput`, `lib/usha.c:USHAInput`

### Requirement: USHAFinalBits declaration contract
系统 MUST 声明 `USHAFinalBits`，并 SHALL 让调用方按 `USHAContext.whichSha` 分派 final bits 输入。

#### Scenario: unified SHA final bits declaration is visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `USHAFinalBits` 的调用
- **THEN** 声明接受 `USHAContext *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码

Trace: `lib/sha.h:USHAFinalBits`, `lib/usha.c:USHAFinalBits`

### Requirement: USHAResult declaration contract
系统 MUST 声明 `USHAResult`，并 SHALL 让调用方按 `USHAContext.whichSha` 输出对应算法 digest。

#### Scenario: unified SHA result declaration is visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `USHAResult` 的调用
- **THEN** 声明接受 `USHAContext *` 和 `uint8_t Message_Digest[USHAMaxHashSize]` 并返回 SHA 错误码

Trace: `lib/sha.h:USHAResult`, `lib/usha.c:USHAResult`

### Requirement: USHABlockSize declaration contract
系统 MUST 声明 `USHABlockSize`，并 SHALL 让调用方按 `SHAversion` 查询 SHA 消息块字节数。

#### Scenario: unified block-size query declaration is visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `USHABlockSize` 的调用
- **THEN** 声明接受 `enum SHAversion` 并返回 `int` block size

Trace: `lib/sha.h:USHABlockSize`, `lib/usha.c:USHABlockSize`

### Requirement: USHAHashSize declaration contract
系统 MUST 声明 `USHAHashSize`，并 SHALL 让调用方按 `SHAversion` 查询 SHA digest 字节数。

#### Scenario: unified hash-size query declaration is visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `USHAHashSize` 的调用
- **THEN** 声明接受 `enum SHAversion` 并返回 `int` digest size

Trace: `lib/sha.h:USHAHashSize`, `lib/usha.c:USHAHashSize`

### Requirement: USHAHashSizeBits declaration contract
系统 MUST 声明 `USHAHashSizeBits`，并 SHALL 让调用方按 `SHAversion` 查询 SHA digest bit 数。

#### Scenario: unified hash-size-bits query declaration is visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `USHAHashSizeBits` 的调用
- **THEN** 声明接受 `enum SHAversion` 并返回 `int` digest bit size

Trace: `lib/sha.h:USHAHashSizeBits`, `lib/usha.c:USHAHashSizeBits`

### Requirement: hmac declaration contract
系统 MUST 声明 `hmac`，并 SHALL 让调用方通过单次调用使用指定 SHA 算法、消息、key 和 digest 缓冲区计算 HMAC。

#### Scenario: one-shot HMAC declaration is visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `hmac` 的调用
- **THEN** 声明接受 `SHAversion`、消息指针和长度、key 指针和长度、`uint8_t digest[USHAMaxHashSize]` 并返回 SHA 错误码

Trace: `lib/sha.h:hmac`, `lib/hmac.c:hmac`

### Requirement: hmacReset declaration contract
系统 MUST 声明 `hmacReset`，并 SHALL 让调用方初始化流式 HMAC context 和 key padding 状态。

#### Scenario: streaming HMAC reset declaration is visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `hmacReset` 的调用
- **THEN** 声明接受 `HMACContext *`、`enum SHAversion`、key 指针和 key 长度并返回 SHA 错误码

Trace: `lib/sha.h:hmacReset`, `lib/hmac.c:hmacReset`

### Requirement: hmacInput declaration contract
系统 MUST 声明 `hmacInput`，并 SHALL 让调用方追加消息字节到已 reset 的 HMAC context。

#### Scenario: streaming HMAC input declaration is visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `hmacInput` 的调用
- **THEN** 声明接受 `HMACContext *`、消息指针和消息长度并返回 SHA 错误码

Trace: `lib/sha.h:hmacInput`, `lib/hmac.c:hmacInput`

### Requirement: hmacFinalBits declaration contract
系统 MUST 声明 `hmacFinalBits`，并 SHALL 让调用方追加 HMAC 消息 final bits 到已 reset 的 HMAC context。

#### Scenario: streaming HMAC final bits declaration is visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `hmacFinalBits` 的调用
- **THEN** 声明接受 `HMACContext *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码

Trace: `lib/sha.h:hmacFinalBits`, `lib/hmac.c:hmacFinalBits`

### Requirement: hmacResult declaration contract
系统 MUST 声明 `hmacResult`，并 SHALL 让调用方从已 reset/input 的 HMAC context 输出 digest。

#### Scenario: streaming HMAC result declaration is visible
- **GIVEN** 调用方包含 `lib/sha.h`
- **WHEN** 调用方编译对 `hmacResult` 的调用
- **THEN** 声明接受 `HMACContext *` 和 digest 输出指针并返回 SHA 错误码

Trace: `lib/sha.h:hmacResult`, `lib/hmac.c:hmacResult`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `USE_SHA1` 和 `USE_SHA224` 默认关闭，但 GitNexus/实现 specs 显示 USHA/HMAC 流程存在条件调用路径；具体发布构建是否启用这些算法待确认。 | USE_SHA1, USE_SHA224, SHAversion | 头文件默认值和实现条件编译可确认，项目级构建覆盖未在本条目完全确认。 |
| Q-002 | `shaInputTooLong` 被头文件声明，但 SHA 实现中的长度溢出宏是否稳定返回该枚举值待确认。 | shaInputTooLong | 既有 SHA implementation specs 记录了溢出错误码映射疑问。 |
| Q-003 | `HMACContext`、`SHA256Context`、`SHA512Context` 等 context 结构体字段是否属于稳定 ABI，还是仅因内部头暴露而可见待确认。 | HMACContext, SHA256Context, SHA512Context | 头文件公开结构布局，但未定位到 ABI 兼容性文档。 |
