# lib/usha.c Specification

## Source Context

- Source: `lib/usha.c`
- Related Headers: `lib/sha.h`, `lib/compat.h`
- Related Tests: `none`
- Related Dependencies: `USHAReset`, `USHAInput`, `USHAFinalBits`, and `USHAResult` dispatch to SHA1/SHA224/SHA256/SHA384/SHA512 backends according to compile-time `USE_SHA1`, `USE_SHA224`, and `USE_SHA384_SHA512`; size helpers return constants from `lib/sha.h`.
- Build/Compile Context: `CMakeLists.txt` and `configure.ac` build C sources; `lib/sha.h` defaults `USE_SHA1` and `USE_SHA224` to 0 and `USE_SHA384_SHA512` to 1 when not defined.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| USHAReset | function | extern int USHAReset (USHAContext *, SHAversion whichSha); | Include | 公开统一 SHA 初始化入口，设置算法选择并委托具体 SHA reset，错误码对调用方可见。 |
| USHAInput | function | extern int USHAInput (USHAContext *, const uint8_t * bytes, size_t bytecount); | Include | 公开统一 SHA 输入入口，按上下文算法分发输入字节并传播后端错误码。 |
| USHAFinalBits | function | extern int USHAFinalBits (USHAContext *, const uint8_t bits, size_t bitcount); | Include | 公开统一 SHA final bits 入口，按上下文算法分发尾随 bit 并传播后端错误码。 |
| USHAResult | function | extern int USHAResult (USHAContext *, uint8_t Message_Digest[USHAMaxHashSize]); | Include | 公开统一 SHA digest 输出入口，按上下文算法分发结果计算并传播后端错误码。 |
| USHABlockSize | function | extern int USHABlockSize (enum SHAversion whichSha); | Include | 公开算法 block size 查询入口，返回值直接影响 HMAC block 处理。 |
| USHAHashSize | function | extern int USHAHashSize (enum SHAversion whichSha); | Include | 公开算法 digest 字节数查询入口，返回值直接影响 HMAC digest 长度。 |
| USHAHashSizeBits | function | extern int USHAHashSizeBits (enum SHAversion whichSha); | Include | 公开算法 digest bit 数查询入口，返回值是调用方可见尺寸契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SHAversion | enum | lib/sha.h:113 | 统一 SHA 算法选择枚举，成员受 `USE_SHA1`、`USE_SHA224`、`USE_SHA384_SHA512` 编译条件影响，`SHA256` 始终存在。 |
| USHAContext | struct | lib/sha.h:209 | 保存当前 `whichSha` 和各 SHA 后端上下文 union，供统一入口分发。 |
| shaSuccess/shaNull/shaInputTooLong/shaStateError/shaBadParam | enum constants | lib/sha.h:67 | SHA 系列接口返回码集合，本文件显式返回 `shaNull` 和 `shaBadParam` 并传播后端返回码。 |
| SHA*_Message_Block_Size | enum constants | lib/sha.h:81 | `USHABlockSize` 返回的算法 block size 常量，部分成员受编译条件影响。 |
| SHA*HashSize | enum constants | lib/sha.h:81 | `USHAHashSize` 返回的算法 digest 字节数常量，部分成员受编译条件影响。 |
| SHA*HashSizeBits | enum constants | lib/sha.h:81 | `USHAHashSizeBits` 返回的算法 digest bit 数常量，部分成员受编译条件影响。 |

## ADDED Requirements

### Requirement: USHAReset unified reset dispatch
系统 MUST 在传入非空 `USHAContext *` 时记录请求的 `whichSha`，并根据该算法选择调用对应 SHA reset 后端；当算法未在当前编译配置中启用或不匹配任何 case 时，系统 MUST 返回 `shaBadParam`。

#### Scenario: non-null context dispatches reset
- **GIVEN** 调用方提供非空 `USHAContext *` 和当前编译配置支持的 `SHAversion`
- **WHEN** 调用方执行 `USHAReset(ctx, whichSha)`
- **THEN** `ctx->whichSha` 被设置为 `whichSha`，返回值为对应 `SHA1Reset`、`SHA224Reset`、`SHA256Reset`、`SHA384Reset` 或 `SHA512Reset` 的返回码

Trace: `lib/usha.c:USHAReset`, `lib/sha.h:USHAReset`

#### Scenario: null context returns shaNull
- **GIVEN** 调用方提供 `ctx == NULL`
- **WHEN** 调用方执行 `USHAReset(ctx, whichSha)`
- **THEN** 函数返回 `shaNull` 且不调用任何 SHA reset 后端

Trace: `lib/usha.c:USHAReset`, `lib/sha.h:USHAReset`

### Requirement: USHAInput unified input dispatch
系统 MUST 使用 `ctx->whichSha` 将输入字节分发到匹配的 SHA input 后端，并 MUST 在 `ctx` 为空时返回 `shaNull`。

#### Scenario: non-null context dispatches input
- **GIVEN** 调用方提供非空 `USHAContext *`，其 `whichSha` 对应当前编译配置支持的 SHA 算法
- **WHEN** 调用方执行 `USHAInput(ctx, bytes, bytecount)`
- **THEN** 函数将 `bytes` 和 `bytecount` 原样传递给对应 SHA input 后端，并返回该后端返回码

Trace: `lib/usha.c:USHAInput`, `lib/sha.h:USHAInput`

#### Scenario: unsupported context algorithm returns shaBadParam
- **GIVEN** 调用方提供非空 `USHAContext *`，其 `whichSha` 不匹配当前编译配置中的任何 input case
- **WHEN** 调用方执行 `USHAInput(ctx, bytes, bytecount)`
- **THEN** 函数返回 `shaBadParam`

Trace: `lib/usha.c:USHAInput`, `lib/sha.h:USHAInput`

### Requirement: USHAFinalBits final-bit dispatch
系统 MUST 使用 `ctx->whichSha` 将尾随 bit 输入分发到匹配的 SHA final-bits 后端，并 MUST 将 `bits` 和 `bitcount` 按调用参数传递。

#### Scenario: supported algorithm dispatches final bits
- **GIVEN** 调用方提供非空 `USHAContext *`，其 `whichSha` 对应当前编译配置支持的 SHA 算法
- **WHEN** 调用方执行 `USHAFinalBits(ctx, bits, bitcount)`
- **THEN** 函数调用对应 SHA final-bits 后端并返回该后端返回码

Trace: `lib/usha.c:USHAFinalBits`, `lib/sha.h:USHAFinalBits`

#### Scenario: null context returns shaNull
- **GIVEN** 调用方提供 `ctx == NULL`
- **WHEN** 调用方执行 `USHAFinalBits(ctx, bits, bitcount)`
- **THEN** 函数返回 `shaNull` 且不调用任何 SHA final-bits 后端

Trace: `lib/usha.c:USHAFinalBits`, `lib/sha.h:USHAFinalBits`

### Requirement: USHAResult digest dispatch
系统 MUST 使用 `ctx->whichSha` 将 digest 计算分发到匹配的 SHA result 后端，并 MUST 将 `Message_Digest` 作为输出缓冲区传递给该后端。

#### Scenario: supported algorithm writes digest through backend
- **GIVEN** 调用方提供非空 `USHAContext *`，其 `whichSha` 对应当前编译配置支持的 SHA 算法，并提供 `Message_Digest` 输出缓冲区
- **WHEN** 调用方执行 `USHAResult(ctx, Message_Digest)`
- **THEN** 函数调用对应 SHA result 后端并返回该后端返回码

Trace: `lib/usha.c:USHAResult`, `lib/sha.h:USHAResult`

#### Scenario: unsupported result algorithm returns shaBadParam
- **GIVEN** 调用方提供非空 `USHAContext *`，其 `whichSha` 不匹配当前编译配置中的任何 result case
- **WHEN** 调用方执行 `USHAResult(ctx, Message_Digest)`
- **THEN** 函数返回 `shaBadParam`

Trace: `lib/usha.c:USHAResult`, `lib/sha.h:USHAResult`

### Requirement: USHABlockSize block-size lookup
系统 MUST 返回所选 SHA 算法的 message block 字节数常量；对于未匹配的 `whichSha`，系统 MUST 返回 `SHA512_Message_Block_Size`。

#### Scenario: supported algorithm returns configured block size
- **GIVEN** 调用方提供当前编译配置支持的 `SHAversion`
- **WHEN** 调用方执行 `USHABlockSize(whichSha)`
- **THEN** 函数返回对应的 `SHA1_Message_Block_Size`、`SHA224_Message_Block_Size`、`SHA256_Message_Block_Size`、`SHA384_Message_Block_Size` 或 `SHA512_Message_Block_Size`

Trace: `lib/usha.c:USHABlockSize`, `lib/sha.h:USHABlockSize`

#### Scenario: unsupported algorithm defaults to SHA512 block size
- **GIVEN** 调用方提供不匹配当前编译配置中任何 case 的 `whichSha`
- **WHEN** 调用方执行 `USHABlockSize(whichSha)`
- **THEN** 函数返回 `SHA512_Message_Block_Size`

Trace: `lib/usha.c:USHABlockSize`, `lib/sha.h:USHABlockSize`

### Requirement: USHAHashSize hash-size lookup
系统 MUST 返回所选 SHA 算法的 digest 字节数常量；对于未匹配的 `whichSha`，系统 MUST 返回 `SHA512HashSize`。

#### Scenario: supported algorithm returns digest byte size
- **GIVEN** 调用方提供当前编译配置支持的 `SHAversion`
- **WHEN** 调用方执行 `USHAHashSize(whichSha)`
- **THEN** 函数返回对应的 `SHA1HashSize`、`SHA224HashSize`、`SHA256HashSize`、`SHA384HashSize` 或 `SHA512HashSize`

Trace: `lib/usha.c:USHAHashSize`, `lib/sha.h:USHAHashSize`

#### Scenario: unsupported algorithm defaults to SHA512 byte size
- **GIVEN** 调用方提供不匹配当前编译配置中任何 case 的 `whichSha`
- **WHEN** 调用方执行 `USHAHashSize(whichSha)`
- **THEN** 函数返回 `SHA512HashSize`

Trace: `lib/usha.c:USHAHashSize`, `lib/sha.h:USHAHashSize`

### Requirement: USHAHashSizeBits hash-size-bits lookup
系统 MUST 返回所选 SHA 算法的 digest bit 数常量；对于未匹配的 `whichSha`，系统 MUST 返回 `SHA512HashSizeBits`。

#### Scenario: supported algorithm returns digest bit size
- **GIVEN** 调用方提供当前编译配置支持的 `SHAversion`
- **WHEN** 调用方执行 `USHAHashSizeBits(whichSha)`
- **THEN** 函数返回对应的 `SHA1HashSizeBits`、`SHA224HashSizeBits`、`SHA256HashSizeBits`、`SHA384HashSizeBits` 或 `SHA512HashSizeBits`

Trace: `lib/usha.c:USHAHashSizeBits`, `lib/sha.h:USHAHashSizeBits`

#### Scenario: unsupported algorithm defaults to SHA512 bit size
- **GIVEN** 调用方提供不匹配当前编译配置中任何 case 的 `whichSha`
- **WHEN** 调用方执行 `USHAHashSizeBits(whichSha)`
- **THEN** 函数返回 `SHA512HashSizeBits`

Trace: `lib/usha.c:USHAHashSizeBits`, `lib/sha.h:USHAHashSizeBits`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | 当前仓库未定位到针对 `lib/usha.c` 统一 SHA 入口的专用测试；是否存在外部 RFC 4634 测试向量或下游集成测试可作为校正证据？ | file-level | GitNexus context 未返回 test callers，本次仅以源码和头文件声明为规格证据。 |
