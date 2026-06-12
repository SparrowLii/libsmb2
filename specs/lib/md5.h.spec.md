# lib/md5.h Specification

## Source Context

- Source: `lib/md5.h`
- Related Headers: `lib/md5.c`, `lib/hmac-md5.c`
- Related Tests: `none`
- Related Dependencies: `MD5Init`, `MD5Update`, `MD5Final`, and `MD5Transform` declarations have GitNexus context in `lib/md5.h`; declaration-level impact is LOW with no indexed direct callers, while source search confirms `lib/hmac-md5.c` uses the lifecycle declarations.
- Build/Compile Context: `HAVE_CONFIG_H`, `HAVE_NETINET_IN_H`, `HAVE_STDINT_H`, `_WIN32`, `__BYTE_ORDER`, `__BIG_ENDIAN`, `XBOX_360_PLATFORM`, `PS2_IOP_PLATFORM`, and `__cplusplus` control included headers, endian macro exposure, `UWORD32` typedef exposure, and C++ linkage.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| `WORDS_BIGENDIAN` | macro | `#define WORDS_BIGENDIAN 1` | Include | 公开头文件根据平台字节序和 Xbox 360 条件暴露该宏，影响 MD5 字节交换路径。 |
| `UWORD32` | type | `typedef uint32_t UWORD32;` | Include | 公开头文件在非 PS2 IOP 平台定义 MD5 状态和块处理使用的 32 位字类型。 |
| `md5byte` | macro | `#define md5byte unsigned char` | Include | 公开头文件定义 MD5 字节缓冲区类型别名，参与 `MD5Update` 和实现签名。 |
| `MD5Context` | type | `struct MD5Context { UWORD32 buf[4]; UWORD32 bytes[2]; UWORD32 in[16]; };` | Include | 调用方必须分配并传递该状态结构以完成 init/update/final 生命周期。 |
| `MD5Init` | function | `void MD5Init(struct MD5Context *context);` | Include | 公开声明初始化 MD5 上下文，是消息摘要生命周期入口。 |
| `MD5Update` | function | `void MD5Update(struct MD5Context *context, md5byte const *buf, unsigned len);` | Include | 公开声明向上下文追加输入字节，是分块消息处理入口。 |
| `MD5Final` | function | `void MD5Final(unsigned char digest[16], struct MD5Context *context);` | Include | 公开声明完成摘要并写入 16 字节结果，同时结束上下文生命周期。 |
| `MD5Transform` | function | `void MD5Transform(UWORD32 buf[4], UWORD32 const in[16]);` | Include | 公开声明单块 MD5 状态转换函数，供实现和潜在调用方直接处理 16 个 32 位输入字。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| `WORDS_BIGENDIAN` | macro | `lib/md5.h:41` | 在非 Windows 大端平台或 Xbox 360 平台定义为 `1`，用于选择字节交换行为。 |
| `UWORD32` | typedef | `lib/md5.h:48` | 非 `PS2_IOP_PLATFORM` 且未定义 `UWORD32_DEFINED` 时公开为 `uint32_t`。 |
| `md5byte` | macro | `lib/md5.h:58` | 公开为 `unsigned char`，用于 MD5 输入和内部字节视图。 |
| `MD5Context` | struct | `lib/md5.h:60` | 包含四个状态字、两个字节计数字和 16 个输入缓冲字。 |

## ADDED Requirements

### Requirement: WORDS_BIGENDIAN endian selection macro
系统 MUST 在 `!defined(_WIN32) && (__BYTE_ORDER == __BIG_ENDIAN)` 或 `defined(XBOX_360_PLATFORM)` 条件成立时将 `WORDS_BIGENDIAN` 暴露为 `1`，以便实现选择大端输入字节交换路径。

#### Scenario: 大端或 Xbox 360 平台暴露字节序宏
- **GIVEN** 编译 `lib/md5.h` 时平台满足大端条件或定义了 `XBOX_360_PLATFORM`
- **WHEN** 调用方包含 `lib/md5.h`
- **THEN** 预处理结果包含值为 `1` 的 `WORDS_BIGENDIAN` 宏

Trace: `lib/md5.h:WORDS_BIGENDIAN`

### Requirement: UWORD32 32-bit word typedef
系统 MUST 在非 `PS2_IOP_PLATFORM` 且 `UWORD32_DEFINED` 尚未定义时将 `UWORD32` 定义为 `uint32_t`，并设置 `UWORD32_DEFINED` 防止重复定义。

#### Scenario: 默认平台公开 MD5 32 位字类型
- **GIVEN** 编译环境未定义 `PS2_IOP_PLATFORM` 且未预先定义 `UWORD32_DEFINED`
- **WHEN** 调用方包含 `lib/md5.h`
- **THEN** `UWORD32` 可作为 `uint32_t` 兼容的公开类型用于 MD5 状态和块参数

Trace: `lib/md5.h:UWORD32`

### Requirement: md5byte byte alias
系统 MUST 将 `md5byte` 预处理宏暴露为 `unsigned char`，使 MD5 输入缓冲区以字节粒度传递。

#### Scenario: 输入缓冲区使用 md5byte 类型
- **GIVEN** 调用方包含 `lib/md5.h`
- **WHEN** 调用方声明传给 `MD5Update` 的输入缓冲区
- **THEN** `md5byte` 展开为 `unsigned char` 并与函数声明保持一致

Trace: `lib/md5.h:md5byte`

### Requirement: MD5Context caller-owned digest state
系统 MUST 暴露包含 `buf[4]`、`bytes[2]` 和 `in[16]` 的 `struct MD5Context`，调用方 SHALL 在调用 `MD5Init`、`MD5Update` 和 `MD5Final` 时提供同一个上下文对象。

#### Scenario: 调用方分配可跨阶段传递的上下文
- **GIVEN** 调用方需要计算一段或多段输入的 MD5 摘要
- **WHEN** 调用方声明 `struct MD5Context` 并按生命周期传入 MD5 接口
- **THEN** 上下文提供状态字、字节计数和输入缓冲区用于实现累积摘要状态

Trace: `lib/md5.h:MD5Context`, `lib/md5.c:MD5Init`, `lib/md5.c:MD5Update`, `lib/md5.c:MD5Final`

### Requirement: MD5Init initialize digest context
系统 MUST 通过 `MD5Init` 将调用方提供的 `MD5Context` 初始化为 MD5 初始状态，并将累计字节计数清零。

#### Scenario: 初始化新摘要计算
- **GIVEN** 调用方提供一个可写的 `struct MD5Context *context`
- **WHEN** 调用方调用 `MD5Init(context)`
- **THEN** 上下文状态字被设置为 MD5 初始常量且 `bytes` 计数被清零

Trace: `lib/md5.h:MD5Init`, `lib/md5.c:MD5Init`

### Requirement: MD5Update append bytes to digest context
系统 MUST 通过 `MD5Update` 将 `len` 字节输入追加到上下文累计消息中，并对完整的 64 字节块执行 MD5 变换。

#### Scenario: 追加不足一个块的输入
- **GIVEN** 已调用 `MD5Init` 的上下文和长度小于当前块剩余容量的输入缓冲区
- **WHEN** 调用方调用 `MD5Update(context, buf, len)`
- **THEN** 上下文字节计数增加 `len` 且输入字节保留在内部块缓冲区等待后续输入或 final

Trace: `lib/md5.h:MD5Update`, `lib/md5.c:MD5Update`

#### Scenario: 追加包含完整块的输入
- **GIVEN** 已调用 `MD5Init` 的上下文和足以填满至少一个 64 字节块的输入缓冲区
- **WHEN** 调用方调用 `MD5Update(context, buf, len)`
- **THEN** 实现对每个完整 64 字节块调用 `MD5Transform`，并保留剩余字节用于后续处理

Trace: `lib/md5.h:MD5Update`, `lib/md5.c:MD5Update`, `lib/md5.c:MD5Transform`

### Requirement: MD5Final produce 16-byte digest and clear context
系统 MUST 通过 `MD5Final` 按 MD5 padding 和长度编码规则完成摘要，向调用方提供的 16 字节 `digest` 缓冲区写入结果，并清零上下文结构。

#### Scenario: 完成摘要计算
- **GIVEN** 已通过 `MD5Init` 初始化并通过零次或多次 `MD5Update` 累积输入的上下文
- **WHEN** 调用方调用 `MD5Final(digest, context)`
- **THEN** `digest` 包含 16 字节 MD5 摘要且上下文对象内容被置零

Trace: `lib/md5.h:MD5Final`, `lib/md5.c:MD5Final`

### Requirement: MD5Transform transform one MD5 block
系统 MUST 通过 `MD5Transform` 将 16 个 `UWORD32` 输入字作为一个 MD5 块混入四字状态缓冲区，并将结果累加回 `buf[4]`。

#### Scenario: 转换一个 512-bit 块
- **GIVEN** 调用方提供四字 MD5 状态缓冲区和 16 字输入块
- **WHEN** 调用方调用 `MD5Transform(buf, in)`
- **THEN** 实现执行四轮 MD5 step 运算并更新 `buf[0]` 到 `buf[3]`

Trace: `lib/md5.h:MD5Transform`, `lib/md5.c:MD5Transform`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `PS2_IOP_PLATFORM` 下 `UWORD32` 的来源和可用性是否由外部平台头保证？ | `UWORD32` | `lib/md5.h` 在该条件下跳过 typedef，但当前文件未显示替代定义来源。 |
| Q-002 | `MD5Final` 后是否允许调用方复用已清零的同一上下文而不重新调用 `MD5Init`？ | `MD5Final` | 实现清零上下文但未声明 final 后复用契约。 |
| Q-003 | 公开 `MD5Transform` 是否属于稳定外部 API，还是仅为实现文件和内部调用保留？ | `MD5Transform` | 头文件公开声明该函数，但源码注释将其描述为 MD5 核心内部转换。 |
