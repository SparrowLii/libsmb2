# lib/hmac.c Specification

## Source Context

- Source: `lib/hmac.c`
- Related Headers: `lib/sha.h`
- Related Tests: `tests/prog_cat.c`, `tests/prog_cat_cancel.c`
- Related Dependencies: `hmac` calls `hmacReset`, `hmacInput`, and `hmacResult`; streaming HMAC functions call `USHAReset`, `USHAInput`, `USHAFinalBits`, `USHAResult`, `USHABlockSize`, and `USHAHashSize` from `lib/usha.c`; GitNexus upstream impact identifies direct callers in `lib/libsmb2.c:smb2_derive_key` and `lib/smb2-signing.c:smb2_calc_signature` for `hmacReset`, `hmacInput`, and `hmacResult` with CRITICAL risk across SMB2 session setup, signing, examples, and tests.
- Build/Compile Context: `CMakeLists.txt` builds C sources through `lib/CMakeLists.txt`; `lib/hmac.c` conditionally includes `config.h`, `<stdint.h>`, and `<stdlib.h>` through `HAVE_CONFIG_H`, `HAVE_STDINT_H`, and `HAVE_STDLIB_H`, then uses `compat.h` and `sha.h` for SHA/HMAC declarations.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| hmac | function | `extern int hmac (SHAversion whichSha, const unsigned char *text, size_t text_len, const unsigned char *key, size_t key_len, uint8_t digest[USHAMaxHashSize]);` | Include | 一次性 HMAC 公开入口，组合 reset/input/result 并向调用方返回 SHA 错误码。 |
| hmacReset | function | `extern int hmacReset (HMACContext * ctx, enum SHAversion whichSha, const unsigned char *key, size_t key_len);` | Include | 流式 HMAC 初始化入口，被 SMB2 key derivation 与 signing 调用，设置上下文、hash/block size 和内外 pad。 |
| hmacInput | function | `extern int hmacInput (HMACContext * ctx, const unsigned char *text, size_t text_len);` | Include | 流式 HMAC 数据输入入口，被 SMB2 key derivation 与 signing 调用，错误传递对签名结果可见。 |
| hmacFinalBits | function | `extern int hmacFinalBits (HMACContext * ctx, const uint8_t bits, size_t bitcount);` | Include | 流式 HMAC final bits 入口，公开声明且转发 SHA final bits 语义。 |
| hmacResult | function | `extern int hmacResult (HMACContext * ctx, uint8_t *digest);` | Include | 流式 HMAC 结果入口，被 SMB2 key derivation 与 signing 调用，执行 outer hash 并写回 digest。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| HMACContext | typedef | `lib/sha.h:232` | 保存 `whichSha`、`hashSize`、`blockSize`、内部 `USHAContext` 和 outer pad，供流式 HMAC reset/input/result 共享状态。 |
| USHAMaxHashSize | macro | `lib/sha.h:104` | digest 缓冲区最大长度，`hmac` 和内部临时 hash 使用该上限。 |
| USHA_Max_Message_Block_Size | macro | `lib/sha.h:100` | HMAC key pad 缓冲区最大块长，`hmacReset` 用于 inner pad 和 context outer pad。 |

## ADDED Requirements

### Requirement: hmac one-shot digest calculation
系统 MUST 使用指定 SHA 版本、输入消息和认证 key 计算 RFC2104 HMAC，并通过调用方提供的 digest 缓冲区返回结果或传播 SHA 错误码。

#### Scenario: One-shot HMAC succeeds through reset input result sequence
- **GIVEN** 调用方提供有效 `whichSha`、消息缓冲区、key 缓冲区和至少 `USHAMaxHashSize` 可写 digest 缓冲区
- **WHEN** 调用方调用 `hmac(whichSha, text, text_len, key, key_len, digest)`
- **THEN** 实现 MUST 创建本地 `HMACContext`，依次执行 `hmacReset`、`hmacInput` 和 `hmacResult`，并在全部步骤成功时返回 `shaSuccess`

Trace: `lib/hmac.c:hmac`, `lib/sha.h:hmac`

#### Scenario: One-shot HMAC propagates the first SHA error
- **GIVEN** `hmacReset`、`hmacInput` 或 `hmacResult` 中任一步骤返回非零 SHA 错误码
- **WHEN** 调用方调用 `hmac(whichSha, text, text_len, key, key_len, digest)`
- **THEN** 该接口 MUST 通过短路求值返回该非零错误码，并不继续执行后续 HMAC 阶段

Trace: `lib/hmac.c:hmac`, `lib/hmac.c:hmacReset`, `lib/hmac.c:hmacInput`, `lib/hmac.c:hmacResult`

### Requirement: hmacReset context initialization and key padding
系统 MUST 初始化调用方提供的 HMAC context，根据 SHA 版本派生 block/hash size，处理超长 key，并准备 inner/outer HMAC pad。

#### Scenario: Null HMAC context is rejected
- **GIVEN** 调用方传入 `ctx == NULL`
- **WHEN** 调用方调用 `hmacReset(ctx, whichSha, key, key_len)`
- **THEN** 该接口 MUST 返回 `shaNull` 且不访问 context 字段

Trace: `lib/hmac.c:hmacReset`, `lib/sha.h:hmacReset`

#### Scenario: Long key is hashed before pad construction
- **GIVEN** 调用方传入的 `key_len` 大于 `USHABlockSize(whichSha)` 返回的 block size
- **WHEN** `hmacReset` 初始化 HMAC context
- **THEN** 该接口 MUST 使用 `USHAReset`、`USHAInput` 和 `USHAResult` 将 key 压缩为所选 SHA 的 hash 输出，并把后续 HMAC key 长度设置为 `USHAHashSize(whichSha)`

Trace: `lib/hmac.c:hmacReset`, `lib/usha.c:USHAReset`, `lib/usha.c:USHAInput`, `lib/usha.c:USHAResult`

#### Scenario: Pads and inner hash state are initialized
- **GIVEN** 调用方传入非 NULL context，且 key 长度不超过所选 SHA block size或已被压缩
- **WHEN** `hmacReset` 构造 HMAC 初始状态
- **THEN** 该接口 MUST 将 key 字节分别 XOR `0x36` 和 `0x5c` 形成 inner pad 与 `ctx->k_opad`，用 `0x36`/`0x5c` 填充剩余 block 字节，并以 inner pad 作为 `ctx->shaContext` 的首段输入

Trace: `lib/hmac.c:hmacReset`, `lib/sha.h:HMACContext`

### Requirement: hmacInput message streaming
系统 MUST 把调用方提供的消息片段追加到已经 reset 的 HMAC inner SHA context，并保持底层 SHA 输入错误语义。

#### Scenario: Null HMAC context input is rejected
- **GIVEN** 调用方传入 `ctx == NULL`
- **WHEN** 调用方调用 `hmacInput(ctx, text, text_len)`
- **THEN** 该接口 MUST 返回 `shaNull` 且不调用 `USHAInput`

Trace: `lib/hmac.c:hmacInput`, `lib/sha.h:hmacInput`

#### Scenario: Message bytes are forwarded to inner SHA context
- **GIVEN** 调用方已通过 `hmacReset` 初始化 context，并提供消息片段指针和长度
- **WHEN** 调用方调用 `hmacInput(ctx, text, text_len)`
- **THEN** 该接口 MUST 调用 `USHAInput(&ctx->shaContext, text, text_len)`，并返回底层 SHA 输入结果

Trace: `lib/hmac.c:hmacInput`, `lib/usha.c:USHAInput`, `lib/libsmb2.c:smb2_derive_key`, `lib/smb2-signing.c:smb2_calc_signature`

### Requirement: hmacFinalBits final bit streaming
系统 MUST 支持向已初始化的 HMAC inner SHA context 追加 1 到 7 位 final bits，并传播底层 SHA final bits 错误语义。

#### Scenario: Null HMAC context final bits are rejected
- **GIVEN** 调用方传入 `ctx == NULL`
- **WHEN** 调用方调用 `hmacFinalBits(ctx, bits, bitcount)`
- **THEN** 该接口 MUST 返回 `shaNull` 且不调用 `USHAFinalBits`

Trace: `lib/hmac.c:hmacFinalBits`, `lib/sha.h:hmacFinalBits`

#### Scenario: Final bits are forwarded to inner SHA context
- **GIVEN** 调用方已通过 `hmacReset` 初始化 context，并提供位于 byte 高位部分的 final bits 和 bit count
- **WHEN** 调用方调用 `hmacFinalBits(ctx, bits, bitcount)`
- **THEN** 该接口 MUST 调用 `USHAFinalBits(&ctx->shaContext, bits, bitcount)`，并返回底层 SHA final bits 结果

Trace: `lib/hmac.c:hmacFinalBits`, `lib/usha.c:USHAFinalBits`

### Requirement: hmacResult outer digest completion
系统 MUST 完成 HMAC inner hash、执行 outer SHA pass，并把最终 HMAC digest 写入调用方缓冲区。

#### Scenario: Null HMAC context result is rejected
- **GIVEN** 调用方传入 `ctx == NULL`
- **WHEN** 调用方调用 `hmacResult(ctx, digest)`
- **THEN** 该接口 MUST 返回 `shaNull` 且不访问 context 字段或 digest 缓冲区

Trace: `lib/hmac.c:hmacResult`, `lib/sha.h:hmacResult`

#### Scenario: HMAC result writes final digest through outer SHA pass
- **GIVEN** 调用方已通过 `hmacReset` 初始化 context 并通过 `hmacInput` 输入全部消息片段，且提供可写 digest 缓冲区
- **WHEN** 调用方调用 `hmacResult(ctx, digest)`
- **THEN** 该接口 MUST 先用 `USHAResult` 把 inner hash 写入 `digest` 临时缓冲区，再用 `ctx->k_opad`、`ctx->blockSize` 和 `ctx->hashSize` 执行 outer SHA，并把最终 HMAC digest 写回同一 `digest` 缓冲区

Trace: `lib/hmac.c:hmacResult`, `lib/usha.c:USHAResult`, `lib/usha.c:USHAReset`, `lib/usha.c:USHAInput`, `lib/libsmb2.c:smb2_derive_key`, `lib/smb2-signing.c:smb2_calc_signature`, `tests/prog_cat.c:pr_cb`, `tests/prog_cat_cancel.c:pr_cb`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `key == NULL` 且 `key_len > 0`、`text == NULL` 且 `text_len > 0`、或 `digest == NULL` 时是否属于调用方前置条件违规？ | hmac, hmacReset, hmacInput, hmacResult | 源码只显式检查 `ctx`，其他指针被直接传给 SHA 或解引用，头文件未声明空指针契约。 |
| Q-002 | `whichSha` 非可用枚举值时 `USHABlockSize` 或 `USHAHashSize` 的返回值是否需要被 HMAC 层校验？ | hmac, hmacReset | `hmacReset` 直接使用底层返回的 block/hash size，未对非法 SHA 版本添加独立错误处理。 |
| Q-003 | `hmacFinalBits` 的 `bitcount` 是否必须限制为 1 到 7，超出范围完全由 `USHAFinalBits` 处理吗？ | hmacFinalBits | 注释声明 bit count 范围，但 HMAC 层未执行本地校验。 |
