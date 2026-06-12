# lib/md5.c Specification

## Source Context

- Source: `lib/md5.c`
- Related Headers: `lib/md5.h`
- Related Tests: `tests/ntlmssp_generate_blob.c`
- Related Dependencies: `MD5Update` and `MD5Final` call `byteSwap` and `MD5Transform`; GitNexus upstream impact reports direct use by `lib/hmac-md5.c:smb2_hmac_md5` and indirect NTLMSSP authentication/generation flows.
- Build/Compile Context: `CMakeLists.txt` builds C sources through `lib/CMakeLists.txt`; `lib/md5.c` includes `config.h` when `HAVE_CONFIG_H` is defined, `sys/types.h` when `HAVE_SYS_TYPES_H` is defined, and selects byte order conversion with `WORDS_BIGENDIAN`; `ASM_MD5` omits the C `MD5Transform` definition.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| byteSwap | function/macro | void byteSwap(UWORD32 *buf, unsigned words); / #define byteSwap(buf,words) | Include | 平台相关字节序规范化入口；大端平台转换 32 位字输入和 digest 输出，小端平台为空操作，影响 MD5 块处理的跨平台可观察结果。 |
| MD5Init | function | void MD5Init(struct MD5Context *context); | Include | 公开 MD5 生命周期入口，初始化上下文状态并被 HMAC-MD5/NTLMSSP 调用链依赖。 |
| MD5Update | function | void MD5Update(struct MD5Context *context, md5byte const *buf, unsigned len); | Include | 公开增量输入入口，维护字节计数、缓存余量并按 64 字节块驱动压缩。 |
| MD5Final | function | void MD5Final(unsigned char digest[16], struct MD5Context *context); | Include | 公开终结入口，执行 MD5 padding、写出 16 字节 digest 并清零上下文。 |
| MD5Transform | function | void MD5Transform(UWORD32 buf[4], UWORD32 const in[16]); | Include | 公开声明且被 MD5Update/MD5Final 调用的核心压缩函数，直接改变 4 字状态字。 |
| F1 | macro | #define F1(x, y, z) (z ^ (x & (y ^ z))) | Skip | 仅为 `MD5Transform` 内部轮函数 helper，调用方不可直接观察独立契约。 |
| F2 | macro | #define F2(x, y, z) F1(z, x, y) | Skip | 仅为 `MD5Transform` 内部轮函数 helper，调用方不可直接观察独立契约。 |
| F3 | macro | #define F3(x, y, z) (x ^ y ^ z) | Skip | 仅为 `MD5Transform` 内部轮函数 helper，调用方不可直接观察独立契约。 |
| F4 | macro | #define F4(x, y, z) (y ^ (x \| ~z)) | Skip | 仅为 `MD5Transform` 内部轮函数 helper，调用方不可直接观察独立契约。 |
| MD5STEP | macro | #define MD5STEP(f,w,x,y,z,in,s) (w += f(x,y,z) + in, w = (w<<s \| w>>(32-s)) + x) | Skip | 仅为 `MD5Transform` 内部轮步骤 helper，调用方不可直接观察独立契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| md5byte | macro | lib/md5.h:58 | 定义 MD5 字节类型为 `unsigned char`，用于输入、digest 和内部字节视图。 |
| struct MD5Context | struct | lib/md5.h:60 | 公开上下文包含 4 个状态字、2 个字节计数字和 16 个输入块字。 |
| UWORD32 | typedef | lib/md5.h:48 | 在非 `PS2_IOP_PLATFORM` 构建中定义为 `uint32_t`，承载 MD5 32 位状态和输入字。 |
| WORDS_BIGENDIAN | macro | lib/md5.h:41 | 非 Windows 大端字节序或 Xbox 360 平台启用大端转换路径。 |

## ADDED Requirements

### Requirement: byteSwap platform word normalization
系统 MUST 在 `WORDS_BIGENDIAN` 构建中把每个 32 位字从字节数组顺序重组为 MD5 使用的低位优先字值，并在非大端构建中保持调用无副作用。

#### Scenario: Big-endian builds rewrite each word
- **GIVEN** `WORDS_BIGENDIAN` 已定义且调用方传入包含 `words` 个 32 位字的 `buf`
- **WHEN** 调用方调用 `byteSwap(buf, words)`
- **THEN** 实现 MUST 对每个字按 `p[3] p[2] p[1] p[0]` 组合写回，供后续 `MD5Transform` 使用

Trace: `lib/md5.c:byteSwap`, `lib/md5.h:WORDS_BIGENDIAN`

#### Scenario: Little-endian builds do not alter buffers
- **GIVEN** `WORDS_BIGENDIAN` 未定义且 MD5 处理路径调用 `byteSwap(ctx->in, 16)` 或 `byteSwap(ctx->buf, 4)`
- **WHEN** 预处理器展开 `byteSwap(buf,words)`
- **THEN** 该宏 MUST 展开为空操作，使小端平台直接使用已有字节布局

Trace: `lib/md5.c:byteSwap`, `lib/md5.h:WORDS_BIGENDIAN`

### Requirement: MD5Init initializes digest context
系统 MUST 将 `struct MD5Context` 初始化为 MD5 标准初始状态，并把已处理字节计数清零。

#### Scenario: New context starts with MD5 constants
- **GIVEN** 调用方提供可写的 `struct MD5Context *context`
- **WHEN** 调用方调用 `MD5Init(context)`
- **THEN** 实现 MUST 设置 `buf` 为 `0x67452301`, `0xefcdab89`, `0x98badcfe`, `0x10325476`，并将 `bytes[0]` 与 `bytes[1]` 置为 0

Trace: `lib/md5.c:MD5Init`, `lib/md5.h:struct MD5Context`

### Requirement: MD5Update accumulates message bytes
系统 MUST 将传入字节追加到 MD5 上下文，维护 64 位字节计数，并对每个完整 64 字节块执行压缩变换。

#### Scenario: Short update is buffered without transform
- **GIVEN** `context` 已通过 `MD5Init` 初始化且当前输入块剩余空间大于 `len`
- **WHEN** 调用方调用 `MD5Update(context, buf, len)`
- **THEN** 实现 MUST 把 `len` 个字节复制到 `context->in` 的当前偏移，更新 `bytes[0]`/`bytes[1]` 字节计数，并返回而不调用 `MD5Transform`

Trace: `lib/md5.c:MD5Update`, `lib/md5.c:MD5Transform`

#### Scenario: Complete blocks are transformed
- **GIVEN** `context` 已累积部分数据或调用方传入至少补齐一个 64 字节块的数据
- **WHEN** 调用方调用 `MD5Update(context, buf, len)`
- **THEN** 实现 MUST 补齐首个块、按平台需要执行 `byteSwap`、调用 `MD5Transform(context->buf, context->in)`，并继续处理后续每个完整 64 字节块

Trace: `lib/md5.c:MD5Update`, `lib/md5.c:byteSwap`, `lib/md5.c:MD5Transform`

### Requirement: MD5Final emits digest and clears context
系统 MUST 对当前消息执行 MD5 终结填充，输出 16 字节 digest，并在输出后清零上下文存储。

#### Scenario: Finalization writes digest bytes
- **GIVEN** `context` 已通过 `MD5Init` 和零次或多次 `MD5Update` 累积消息数据，且调用方提供 16 字节 `digest` 缓冲区
- **WHEN** 调用方调用 `MD5Final(digest, context)`
- **THEN** 实现 MUST 添加 `0x80` 起始 padding、追加以 bit 为单位的低 64 位消息长度、执行最终 `MD5Transform`，并把 16 字节状态复制到 `digest`

Trace: `lib/md5.c:MD5Final`, `lib/md5.c:MD5Transform`

#### Scenario: Finalization erases context storage
- **GIVEN** `MD5Final` 已完成 digest 写出
- **WHEN** 函数返回给调用方
- **THEN** 实现 MUST 使用零字节覆盖整个 `struct MD5Context` 存储，避免保留中间状态

Trace: `lib/md5.c:MD5Final`, `lib/md5.h:struct MD5Context`

### Requirement: MD5Transform applies MD5 compression round
系统 MUST 对一个 16 字的输入块执行 MD5 四轮压缩，并把结果累加回 4 字状态缓冲区。

#### Scenario: Transform mutates state with one prepared block
- **GIVEN** 调用方传入 4 个 `UWORD32` 状态字 `buf` 和 16 个已按平台字节序规范化的 `UWORD32` 输入字 `in`
- **WHEN** 调用方调用 `MD5Transform(buf, in)`
- **THEN** 实现 MUST 以 `buf[0..3]` 初始化 `a`, `b`, `c`, `d`，按源码常量和移位执行 64 个 MD5STEP 操作，并把最终 `a`, `b`, `c`, `d` 分别累加到 `buf[0..3]`

Trace: `lib/md5.c:MD5Transform`, `lib/md5.c:MD5STEP`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `MD5Update` 在 `len == 0` 时是否允许 `buf == NULL`？ | MD5Update | 源码会调用 `memcpy` 且未显式校验参数，C 标准库对空指针零长度拷贝的可移植契约未在头文件说明。 |
| Q-002 | `ASM_MD5` 构建中的外部 `MD5Transform` 实现是否与本 C 实现完全等价？ | MD5Transform | `lib/md5.c` 在 `ASM_MD5` 下不编译 C 版本，但当前文件未包含汇编实现证据。 |
| Q-003 | `MD5Final` 清零上下文后调用方是否允许继续复用同一上下文而不重新 `MD5Init`？ | MD5Final | 源码执行 `memset(ctx, 0, sizeof(*ctx))`，但头文件只描述终结写 digest，未声明后续生命周期要求。 |
