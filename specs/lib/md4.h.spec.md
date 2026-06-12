# lib/md4.h Specification

## Source Context

- Source: `lib/md4.h`
- Related Headers: `lib/md4c.c`
- Related Tests: `none`
- Related Dependencies: `lib/md4c.c`, `lib/ntlmssp.c`
- Build/Compile Context: C project via `CMakeLists.txt` and `configure.ac`; C standard unknown; declarations depend on `uint32_t` being visible before including `lib/md4.h`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| MD4_CTX | type | typedef struct { uint32_t state[4]; uint32_t count[2]; unsigned char buffer[64]; } MD4_CTX; | Include | 公开上下文结构承载 MD4 状态、位计数和缓冲区，调用方需按声明分配并传入 MD4 生命周期接口。 |
| MD4Init | function | void MD4Init(MD4_CTX *); | Include | 公开初始化入口，定义上下文从未初始化到可更新状态的生命周期起点。 |
| MD4Update | function | void MD4Update(MD4_CTX *, unsigned char *, unsigned int); | Include | 公开增量输入入口，更新上下文计数、缓冲和状态，供 NTLM 哈希路径跨文件调用。 |
| MD4Final | function | void MD4Final(unsigned char [16], MD4_CTX *); | Include | 公开终结入口，输出 16 字节摘要并清零上下文，影响资源和敏感数据生命周期。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| MD4_CTX | typedef | lib/md4.h:33 | MD4 调用方可见上下文，包含 4 个 32 位状态字、2 个 32 位 bit count 字和 64 字节输入缓冲区。 |

## ADDED Requirements

### Requirement: MD4_CTX expose MD4 context storage
系统 MUST 将 `MD4_CTX` 暴露为调用方可分配的 MD4 上下文，包含 `state[4]`、`count[2]` 和 `buffer[64]` 三个字段以承载摘要状态、累计 bit 数和未处理输入块。

#### Scenario: Context layout is visible to callers
- **GIVEN** 调用方包含 `lib/md4.h` 并需要执行 MD4 生命周期
- **WHEN** 调用方声明一个 `MD4_CTX` 对象
- **THEN** 该对象提供 4 个 `uint32_t` 状态字、2 个 `uint32_t` 计数字和 64 字节缓冲区供 `MD4Init`、`MD4Update` 与 `MD4Final` 操作

Trace: `lib/md4.h:MD4_CTX`, `lib/md4c.c:MD4Init`

### Requirement: MD4Init initialize MD4 context
系统 MUST 通过 `MD4Init` 将调用方提供的 `MD4_CTX` 初始化为 RFC1320 MD4 初始状态，并将累计 bit 计数清零。

#### Scenario: New context starts from MD4 constants
- **GIVEN** 调用方提供一个可写的 `MD4_CTX` 指针
- **WHEN** 调用方执行 `MD4Init(context)`
- **THEN** `context->count[0]` 和 `context->count[1]` 为 0，`context->state` 被设置为 MD4 初始常量 `0x67452301`、`0xefcdab89`、`0x98badcfe`、`0x10325476`

Trace: `lib/md4.h:MD4Init`, `lib/md4c.c:MD4Init`

### Requirement: MD4Update process incremental input
系统 MUST 通过 `MD4Update` 接收调用方提供的输入字节和长度，按 64 字节块更新 MD4 状态，并保留未满块输入以供后续更新或终结使用。

#### Scenario: Input updates count and buffered state
- **GIVEN** 调用方已使用 `MD4Init` 初始化 `MD4_CTX`，并提供 `input` 与 `inputLen`
- **WHEN** 调用方执行 `MD4Update(context, input, inputLen)`
- **THEN** 上下文累计 bit 计数按 `inputLen * 8` 更新，完整 64 字节块被转换进 `state`，剩余字节被保存在 `buffer` 中

Trace: `lib/md4.h:MD4Update`, `lib/md4c.c:MD4Update`, `lib/ntlmssp.c:NTOWFv1`

### Requirement: MD4Final emit digest and clear context
系统 MUST 通过 `MD4Final` 对当前上下文执行 MD4 padding、追加原始长度、写出 16 字节摘要，并在完成后清零 `MD4_CTX` 内容。

#### Scenario: Finalization writes digest and zeroizes context
- **GIVEN** 调用方已完成一个或多个 `MD4Update` 调用并提供 16 字节 digest 输出缓冲区
- **WHEN** 调用方执行 `MD4Final(digest, context)`
- **THEN** `digest` 接收 16 字节 MD4 摘要，`context` 在摘要写出后被置零以清除内部状态

Trace: `lib/md4.h:MD4Final`, `lib/md4c.c:MD4Final`, `lib/ntlmssp.c:NTOWFv1`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `lib/md4.h` 是否有意不包含 `<stdint.h>` 或 `compat.h`，而要求调用方或实现文件先提供 `uint32_t` 定义？ | MD4_CTX | 头文件直接使用 `uint32_t`，但仅 `lib/md4c.c` 在包含该头前按条件包含 `<stdint.h>` 并包含 `compat.h`。 |
| Q-002 | `MD4Update` 的 `input` 是否允许为 NULL 且 `inputLen == 0`，以及参数为空时是否属于未定义前置条件？ | MD4Update | 实现无空指针检查，源码仅显示按长度复制和转换，未发现测试覆盖空输入指针边界。 |
| Q-003 | GitNexus impact 是否应按声明符号还是实现符号归属 MD4 调用影响？ | MD4Init, MD4Update, MD4Final | `gitnexus impact` 对同名声明和实现返回 ambiguous，当前 CLI 未接受 `--uid` 或 `--file` 消歧选项。 |
