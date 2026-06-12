# lib/sha1.c Specification

## Source Context

- Source: `lib/sha1.c`
- Related Headers: `lib/sha.h`, `lib/sha-private.h`, `lib/compat.h`
- Related Tests: `none`
- Related Dependencies: `USHAReset`, `USHAInput`, `USHAFinalBits`, `USHAResult`, `hmacReset`, `hmacInput`, `hmacFinalBits`, `hmacResult`, `hmac`, `smb3_update_preauth_hash`, `smb2_calc_signature`, `session_setup_cb`, `negotiate_cb`, `smb2_session_setup_request_cb`
- Build/Compile Context: `C project; lib/sha1.c implementation is compiled only when defined(USE_SHA1) && USE_SHA1; sha.h defaults USE_SHA1 to 0 unless overridden.`

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| SHA1Reset | function | `int SHA1Reset (SHA1Context * context)` | Include | 公开 SHA-1 上下文初始化入口，被 USHA、HMAC 和 SMB 认证/签名链路上游调用，返回错误码并重置调用方可见状态。 |
| SHA1Input | function | `int SHA1Input (SHA1Context * context, const uint8_t * message_array, size_t length)` | Include | 公开 SHA-1 增量输入入口，处理零长度、空指针、已终结状态、损坏状态和块压缩，影响摘要结果。 |
| SHA1FinalBits | function | `int SHA1FinalBits (SHA1Context * context, const uint8_t message_bits, size_t length)` | Include | 公开 SHA-1 非整字节尾部输入入口，处理 1 到 7 位最终位并终结摘要，错误语义对调用方可见。 |
| SHA1Result | function | `int SHA1Result (SHA1Context * context, uint8_t Message_Digest[SHA1HashSize])` | Include | 公开 SHA-1 摘要输出入口，按需终结计算并以 20 字节大端顺序写出摘要。 |
| SHA1Finalize | function | `static void SHA1Finalize (SHA1Context * context, uint8_t Pad_Byte)` | Skip | static 内部 helper，仅服务 SHA1FinalBits/SHA1Result padding、清理和 Computed 标记，无独立外部接口。 |
| SHA1PadMessage | function | `static void SHA1PadMessage (SHA1Context * context, uint8_t Pad_Byte)` | Skip | static 内部 padding helper，无外部可调用契约，行为并入公开摘要终结接口。 |
| SHA1ProcessMessageBlock | function | `static void SHA1ProcessMessageBlock (SHA1Context * context)` | Skip | static 内部 512-bit 压缩 helper，无独立外部接口，行为并入 SHA1Input/SHA1Result 摘要契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SHA1Context | typedef struct | `lib/sha.h:133` | SHA-1 调用方持有的可变上下文，保存中间哈希、位长度、消息块、Computed 和 Corrupted 状态。 |
| SHA1_Message_Block_Size | enum constant | `lib/sha.h:84` | USE_SHA1 启用时消息块大小为 64 字节。 |
| SHA1HashSize | enum constant | `lib/sha.h:85` | USE_SHA1 启用时摘要输出大小为 20 字节。 |
| SHA1HashSizeBits | enum constant | `lib/sha.h:86` | USE_SHA1 启用时摘要位数为 160 bit。 |
| shaSuccess | enum constant | `lib/sha.h:69` | SHA 接口成功返回码。 |
| shaNull | enum constant | `lib/sha.h:70` | SHA 接口空指针参数返回码。 |
| shaStateError | enum constant | `lib/sha.h:72` | SHA 接口非法状态调用返回码。 |
| SHA1_ROTL | macro | `lib/sha1.c:48` | SHA-1 32-bit 循环左移内部宏，仅在本实现中使用。 |
| SHA1AddLength | macro | `lib/sha1.c:54` | SHA-1 位长度累加内部宏，低位溢出且高位再溢出时设置 Corrupted。 |

## ADDED Requirements

### Requirement: SHA1Reset context initialization
系统 MUST 在收到非空 `SHA1Context` 时初始化 SHA-1 计算上下文，并在收到空上下文时返回 `shaNull` 且不写入上下文。

#### Scenario: reset rejects null context
- **GIVEN** 调用方没有提供 SHA-1 上下文指针
- **WHEN** 调用 `SHA1Reset(NULL)`
- **THEN** 函数返回 `shaNull`

Trace: `lib/sha1.c:SHA1Reset`, `lib/sha.h:SHA1Reset`

#### Scenario: reset prepares initial FIPS hash state
- **GIVEN** 调用方提供可写的 `SHA1Context`
- **WHEN** 调用 `SHA1Reset(context)`
- **THEN** 函数返回 `shaSuccess`，将长度、消息块索引、Computed 和 Corrupted 清零，并写入 FIPS-180-2 section 5.3.1 的五个初始哈希常量

Trace: `lib/sha1.c:SHA1Reset`, `lib/sha.h:SHA1Context`

### Requirement: SHA1Input incremental octet processing
系统 MUST 接受 SHA-1 消息的字节序列增量输入，并按照上下文状态返回 `shaSuccess`、`shaNull`、`shaStateError` 或已有 Corrupted 错误码。

#### Scenario: input accepts zero length without dereferencing pointers
- **GIVEN** 调用方传入任意 `context` 和 `message_array` 指针组合且 `length` 为 0
- **WHEN** 调用 `SHA1Input(context, message_array, 0)`
- **THEN** 函数返回 `shaSuccess`，并且源码路径在空指针检查前完成零长度返回

Trace: `lib/sha1.c:SHA1Input`, `lib/sha.h:SHA1Input`

#### Scenario: input rejects null active parameters
- **GIVEN** `length` 大于 0 且 `context` 或 `message_array` 为空
- **WHEN** 调用 `SHA1Input(context, message_array, length)`
- **THEN** 函数返回 `shaNull`

Trace: `lib/sha1.c:SHA1Input`, `lib/sha.h:SHA1Input`

#### Scenario: input rejects updates after digest computation
- **GIVEN** `context->Computed` 已经为非零
- **WHEN** 调用 `SHA1Input(context, message_array, length)` 且 `length` 大于 0
- **THEN** 函数将 `context->Corrupted` 置为 `shaStateError` 并返回 `shaStateError`

Trace: `lib/sha1.c:SHA1Input`, `lib/sha.h:SHA1Context`

#### Scenario: input preserves existing corrupted state
- **GIVEN** `context->Corrupted` 已经为非零且 `context->Computed` 为 0
- **WHEN** 调用 `SHA1Input(context, message_array, length)` 且参数非空、`length` 大于 0
- **THEN** 函数返回现有 `context->Corrupted` 值，不处理新的输入字节

Trace: `lib/sha1.c:SHA1Input`, `lib/sha.h:SHA1Context`

#### Scenario: input processes bytes and message blocks
- **GIVEN** `context` 已经由 `SHA1Reset` 初始化且输入指针非空
- **WHEN** 调用 `SHA1Input(context, message_array, length)` 且输入使消息块索引达到 `SHA1_Message_Block_Size`
- **THEN** 函数 MUST 将每个字节写入消息块、按 8 bit 累加长度，并在完整 64 字节块到达时调用内部压缩处理后继续接收后续字节

Trace: `lib/sha1.c:SHA1Input`, `lib/sha1.c:SHA1ProcessMessageBlock`, `lib/sha.h:SHA1_Message_Block_Size`

### Requirement: SHA1FinalBits final partial-bit processing
系统 MUST 支持在 SHA-1 消息末尾追加 1 到 7 个高位排列的最终 bit，并在成功处理后终结摘要计算。

#### Scenario: final bits accepts zero length as no-op
- **GIVEN** 调用方传入任意 `context` 且 `length` 为 0
- **WHEN** 调用 `SHA1FinalBits(context, message_bits, 0)`
- **THEN** 函数返回 `shaSuccess`，并且源码路径在空上下文检查前完成零长度返回

Trace: `lib/sha1.c:SHA1FinalBits`, `lib/sha.h:SHA1FinalBits`

#### Scenario: final bits rejects null context
- **GIVEN** `length` 大于 0 且上下文指针为空
- **WHEN** 调用 `SHA1FinalBits(NULL, message_bits, length)`
- **THEN** 函数返回 `shaNull`

Trace: `lib/sha1.c:SHA1FinalBits`, `lib/sha.h:SHA1FinalBits`

#### Scenario: final bits rejects invalid state or length
- **GIVEN** `context->Computed` 已经为非零，或 `length` 大于等于 8
- **WHEN** 调用 `SHA1FinalBits(context, message_bits, length)`
- **THEN** 函数将 `context->Corrupted` 置为 `shaStateError` 并返回 `shaStateError`

Trace: `lib/sha1.c:SHA1FinalBits`, `lib/sha.h:SHA1Context`

#### Scenario: final bits propagates existing corruption
- **GIVEN** `context->Corrupted` 已经为非零且上下文尚未 computed
- **WHEN** 调用 `SHA1FinalBits(context, message_bits, length)` 且 `length` 在 1 到 7 之间
- **THEN** 函数返回现有 `context->Corrupted` 值，不执行最终 padding

Trace: `lib/sha1.c:SHA1FinalBits`, `lib/sha.h:SHA1Context`

#### Scenario: final bits masks high bits and finalizes digest
- **GIVEN** `context` 有效、未 computed、未 corrupted，且 `length` 在 1 到 7 之间
- **WHEN** 调用 `SHA1FinalBits(context, message_bits, length)`
- **THEN** 函数 MUST 将消息长度增加 `length` bit，保留 `message_bits` 的高 `length` 位并追加标记 bit，然后执行 SHA-1 padding、清空消息块和长度字段、设置 `context->Computed`，并返回 `shaSuccess`

Trace: `lib/sha1.c:SHA1FinalBits`, `lib/sha1.c:SHA1Finalize`, `lib/sha1.c:SHA1PadMessage`

### Requirement: SHA1Result digest output
系统 MUST 将已累计的 SHA-1 上下文转换为 20 字节消息摘要，并按上下文错误状态返回稳定错误码。

#### Scenario: result rejects null parameters
- **GIVEN** `context` 或 `Message_Digest` 为空
- **WHEN** 调用 `SHA1Result(context, Message_Digest)`
- **THEN** 函数返回 `shaNull`

Trace: `lib/sha1.c:SHA1Result`, `lib/sha.h:SHA1Result`

#### Scenario: result returns existing corrupted state
- **GIVEN** `context->Corrupted` 已经为非零且输出缓冲区非空
- **WHEN** 调用 `SHA1Result(context, Message_Digest)`
- **THEN** 函数返回现有 `context->Corrupted` 值，不写出新的摘要字节

Trace: `lib/sha1.c:SHA1Result`, `lib/sha.h:SHA1Context`

#### Scenario: result finalizes an unfinished context
- **GIVEN** `context` 有效、未 corrupted、`context->Computed` 为 0 且输出缓冲区可写
- **WHEN** 调用 `SHA1Result(context, Message_Digest)`
- **THEN** 函数 MUST 使用 `0x80` 作为整字节消息的 padding 起始字节终结上下文，随后写出 `SHA1HashSize` 个摘要字节并返回 `shaSuccess`

Trace: `lib/sha1.c:SHA1Result`, `lib/sha1.c:SHA1Finalize`, `lib/sha.h:SHA1HashSize`

#### Scenario: result emits digest in big-endian hash-word order
- **GIVEN** `context->Intermediate_Hash` 包含已计算的五个 32-bit SHA-1 hash words 且 `context->Computed` 为非零
- **WHEN** 调用 `SHA1Result(context, Message_Digest)`
- **THEN** 函数 MUST 按每个 hash word 的高字节到低字节顺序填充 `Message_Digest[0]` 到 `Message_Digest[19]`，并返回 `shaSuccess`

Trace: `lib/sha1.c:SHA1Result`, `lib/sha.h:SHA1HashSize`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `SHA1AddLength` 在消息长度超过 2^64 bit 时仅设置 `context->Corrupted` 为数值 1，而不是显式 `shaInputTooLong`；该返回码映射是否应视为公开兼容行为？ | SHA1Input, SHA1FinalBits | 源码宏可确认溢出路径，但没有测试或调用方文档确认错误码语义。 |
| Q-002 | `SHA1Input` 在 `SHA1AddLength` 检测到长度溢出时仍可能返回 `shaSuccess`，因为循环退出后未返回 `context->Corrupted`；调用方是否依赖此行为待确认。 | SHA1Input | 源码可确认控制流，但未定位到测试覆盖。 |
| Q-003 | `USE_SHA1` 默认值为 0，但 GitNexus 显示 SHA1 通过 USHA/HMAC/SMB 流程被调用；具体构建配置何处启用 `USE_SHA1` 待确认。 | file-level | `sha.h` 默认关闭，调用链索引显示启用路径，构建宏来源未在本条目中完全确认。 |
