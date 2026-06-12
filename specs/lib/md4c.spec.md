# lib/md4c.c Specification

## Source Context

- Source: `lib/md4c.c`
- Related Headers: `lib/md4.h`, `lib/compat.h`
- Related Tests: `none`
- Related Dependencies: `MD4Init`, `MD4Update`, and `MD4Final` are called by `lib/ntlmssp.c:NTOWFv1`; `MD4Update` calls `MD4Transform` and `MD4_memcpy`; `MD4Final` calls `Encode`, `MD4Update`, and `MD4_memset`.
- Build/Compile Context: `CMakeLists.txt` and `configure.ac` build C sources; `HAVE_CONFIG_H` controls inclusion of `config.h`, and `HAVE_STDINT_H` controls inclusion of `<stdint.h>`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| MD4Init | function | void MD4Init(MD4_CTX *context) | Include | 公开 MD4 上下文初始化入口，被 NTLM 密码哈希流程调用并定义调用序列起点。 |
| MD4Update | function | void MD4Update(MD4_CTX *context, unsigned char *input, unsigned int inputLen) | Include | 公开 MD4 分块输入入口，维护 bit count、缓冲区和块转换状态，影响最终摘要。 |
| MD4Final | function | void MD4Final(unsigned char digest[16], MD4_CTX *context) | Include | 公开 MD4 完成入口，输出 16 字节摘要并清零上下文。 |
| MD4Transform | function | static void MD4Transform(uint32_t state[4], unsigned char block[64]) | Skip | 静态内部块压缩 helper，仅由本文件 `MD4Update` 调用，无独立外部契约。 |
| Encode | function | static void Encode(unsigned char *output, uint32_t *input, unsigned int len) | Skip | 静态内部 little-endian 编码 helper，仅支撑 `MD4Final`，无独立外部契约。 |
| Decode | function | static void Decode(uint32_t *output, unsigned char *input, unsigned int len) | Skip | 静态内部 little-endian 解码 helper，仅支撑 `MD4Transform`，无独立外部契约。 |
| MD4_memcpy | function | static void MD4_memcpy(unsigned char *output, unsigned char *input, unsigned int len) | Skip | 静态内部字节复制 helper，无独立外部契约。 |
| MD4_memset | function | static void MD4_memset(unsigned char *output, int value, unsigned int len) | Skip | 静态内部字节填充 helper，无独立外部契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| MD4_CTX | typedef | lib/md4.h:33 | 调用方可见的 MD4 上下文，包含 `state[4]`、`count[2]` 和 `buffer[64]`。 |
| S11 | macro | lib/md4c.c:40 | 内部轮函数移位常量，不作为公开宏契约。 |
| S12 | macro | lib/md4c.c:41 | 内部轮函数移位常量，不作为公开宏契约。 |
| S13 | macro | lib/md4c.c:42 | 内部轮函数移位常量，不作为公开宏契约。 |
| S14 | macro | lib/md4c.c:43 | 内部轮函数移位常量，不作为公开宏契约。 |
| S21 | macro | lib/md4c.c:44 | 内部轮函数移位常量，不作为公开宏契约。 |
| S22 | macro | lib/md4c.c:45 | 内部轮函数移位常量，不作为公开宏契约。 |
| S23 | macro | lib/md4c.c:46 | 内部轮函数移位常量，不作为公开宏契约。 |
| S24 | macro | lib/md4c.c:47 | 内部轮函数移位常量，不作为公开宏契约。 |
| S31 | macro | lib/md4c.c:48 | 内部轮函数移位常量，不作为公开宏契约。 |
| S32 | macro | lib/md4c.c:49 | 内部轮函数移位常量，不作为公开宏契约。 |
| S33 | macro | lib/md4c.c:50 | 内部轮函数移位常量，不作为公开宏契约。 |
| S34 | macro | lib/md4c.c:51 | 内部轮函数移位常量，不作为公开宏契约。 |
| PADDING | static data | lib/md4c.c:59 | 内部 finalization padding，以 `0x80` 开头并补零。 |
| F | macro | lib/md4c.c:67 | 内部 MD4 基本函数宏，不作为公开宏契约。 |
| G | macro | lib/md4c.c:68 | 内部 MD4 基本函数宏，不作为公开宏契约。 |
| H | macro | lib/md4c.c:69 | 内部 MD4 基本函数宏，不作为公开宏契约。 |
| ROTATE_LEFT | macro | lib/md4c.c:73 | 内部 32-bit 左旋宏，不作为公开宏契约。 |
| FF | macro | lib/md4c.c:78 | 内部 round 1 转换宏，不作为公开宏契约。 |
| GG | macro | lib/md4c.c:82 | 内部 round 2 转换宏，不作为公开宏契约。 |
| HH | macro | lib/md4c.c:86 | 内部 round 3 转换宏，不作为公开宏契约。 |

## ADDED Requirements

### Requirement: MD4Init initialize context state
系统 MUST 将调用方提供的 `MD4_CTX` 初始化为 RFC1320 MD4 初始状态，并将 bit count 清零。

#### Scenario: initialize fresh context
- **GIVEN** 调用方提供一个可写的 `MD4_CTX *context`
- **WHEN** 调用方执行 `MD4Init(context)`
- **THEN** `context->count[0]` 和 `context->count[1]` 均为 `0`，且 `state` 被设置为 `0x67452301`、`0xefcdab89`、`0x98badcfe`、`0x10325476`

Trace: `lib/md4c.c:MD4Init`

### Requirement: MD4Update absorb message bytes
系统 MUST 按 MD4 分块规则把 `inputLen` 字节输入合并进 `context`，更新 64-bit bit count，并对每个完整 64 字节块更新 digest state。

#### Scenario: update with partial block
- **GIVEN** 调用方已经通过 `MD4Init` 初始化 `context`，且输入长度不足以填满当前 64 字节块
- **WHEN** 调用方执行 `MD4Update(context, input, inputLen)`
- **THEN** 系统更新 `context->count` 的 bit 长度，并把剩余输入字节保存在 `context->buffer` 中供后续 update 或 final 使用

Trace: `lib/md4c.c:MD4Update`

#### Scenario: update with complete blocks
- **GIVEN** 调用方已经通过 `MD4Init` 初始化 `context`，且输入长度足以填满一个或多个 64 字节块
- **WHEN** 调用方执行 `MD4Update(context, input, inputLen)`
- **THEN** 系统对已满的 64 字节块执行 MD4 block transform，并只把未满 64 字节的尾部输入保存在 `context->buffer`

Trace: `lib/md4c.c:MD4Update`, `lib/md4c.c:MD4Transform`

### Requirement: MD4Final produce digest and clear context
系统 MUST 对当前 MD4 上下文追加 padding 和原始 bit length，输出 16 字节 little-endian digest，并清零 `MD4_CTX` 内容。

#### Scenario: finalize digest
- **GIVEN** 调用方已经通过 `MD4Init` 和零次或多次 `MD4Update` 准备 `context`，并提供可写的 `digest[16]`
- **WHEN** 调用方执行 `MD4Final(digest, context)`
- **THEN** 系统写入 16 字节摘要到 `digest`，并将 `context` 字节清零

Trace: `lib/md4c.c:MD4Final`, `lib/md4c.c:Encode`, `lib/md4c.c:MD4_memset`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `MD4Init`、`MD4Update` 和 `MD4Final` 对 NULL 指针、无效 buffer 或别名重叠输入是否要求调用方保证前置条件？ | MD4Init, MD4Update, MD4Final | 源码未做参数校验，头文件也未声明错误返回或约束文本。 |
| Q-002 | `MD4Update` 的 `inputLen` 为 `unsigned int`，超大输入跨多次调用时是否需要定义超过 2^64 bit 的截断或溢出行为？ | MD4Update | 源码按两个 `uint32_t` 计数累加并处理进位，但未说明超出 MD4 长度域后的契约。 |
| Q-003 | 当前项目是否有覆盖 RFC1320 MD4 known-answer vectors 或 NTLM hash 的测试归属？ | MD4Final | GitNexus 未定位到测试调用者，源码仅显示 `lib/ntlmssp.c:NTOWFv1` 运行时调用链。 |
