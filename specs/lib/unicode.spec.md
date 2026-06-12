# lib/unicode.c Specification

## Source Context

- Source: `lib/unicode.c`
- Related Headers: `include/smb2/libsmb2.h`, `include/portable-endian.h`, `include/libsmb2-private.h`, `lib/compat.h`
- Related Tests: `none`
- Related Dependencies: GitNexus `context` shows `smb2_utf8_to_utf16` is called by DCERPC, NTLMSSP, SMB2 create/query-directory/set-info/file-info/filesystem-info encoders and `libsmb2` share connect paths; `smb2_utf16_to_utf8` is called by DCERPC, NTLMSSP, SMB2 create/negotiate/query-directory/file-info/filesystem-info/reparse decoders and libsmb2 notify decode paths. Impact analysis by UID reports CRITICAL upstream risk for both public conversion functions.
- Build/Compile Context: C project; `HAVE_CONFIG_H`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `HAVE_TIME_H`, `HAVE_SYS_TIME_H`, and `STDC_HEADERS` control included headers; conversion uses little-endian helpers from `portable-endian.h`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| l1 | function | static int l1(char c) | Skip | 文件内 UTF-8 leading-bit helper，无独立对外契约。 |
| validate_utf8_cp | function | static int validate_utf8_cp(const char **utf8, uint16_t *ret) | Skip | 文件内 UTF-8 codepoint 校验和 UTF-16 单元写入 helper，行为归属到公开转换接口。 |
| validate_utf8_str | function | static int validate_utf8_str(const char *utf8) | Skip | 文件内 UTF-8 字符串校验和长度计算 helper，行为归属到 `smb2_utf8_to_utf16`。 |
| smb2_utf8_to_utf16 | function | struct smb2_utf16 *smb2_utf8_to_utf16(const char *utf8) | Include | 公开 header 声明的 UTF-8 到 SMB UTF-16LE 转换接口，调用方观察到分配、长度、字节序和错误语义。 |
| utf16_size | function | static int utf16_size(const uint16_t *utf16, size_t utf16_len) | Skip | 文件内 UTF-16LE 到 UTF-8 输出长度 helper，行为归属到 `smb2_utf16_to_utf8`。 |
| smb2_utf16_to_utf8 | function | const char *smb2_utf16_to_utf8(const uint16_t *str, size_t len) | Include | 公开 header 声明的 SMB UTF-16LE 到 UTF-8 转换接口，调用方观察到分配、NUL 终止、替换字符和错误语义。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| struct smb2_utf16 | struct | include/smb2/libsmb2.h:1283 | 公开转换结果容器；`len` 记录 UTF-16 code unit 数量，`val` 存储 little-endian UTF-16 单元。 |
| 0xef 0xbf 0xbd | macro | lib/unicode.c:278 | 源码内联写入 Unicode replacement character 的 UTF-8 字节序列，用于无法成对的 UTF-16 surrogate。 |

## ADDED Requirements

### Requirement: smb2_utf8_to_utf16 valid UTF-8 conversion
系统 MUST 将合法 UTF-8 输入转换为新分配的 SMB UTF-16LE 缓冲区，并在 `struct smb2_utf16.len` 中记录输出 UTF-16 code unit 数量。

#### Scenario: ASCII and multibyte conversion
- **GIVEN** 调用方提供以 NUL 结束且 UTF-8 编码合法的 `utf8` 字符串
- **WHEN** 调用 `smb2_utf8_to_utf16(const char *utf8)`
- **THEN** 返回值为新分配的 `struct smb2_utf16 *`，`len` 等于转换后 UTF-16 code unit 数量，`val` 中每个 code unit 以 little-endian 形式存储

Trace: `lib/unicode.c:smb2_utf8_to_utf16`, `include/smb2/libsmb2.h:smb2_utf8_to_utf16`

#### Scenario: Supplementary plane conversion
- **GIVEN** 调用方提供包含 UTF-8 四字节合法 codepoint 且 codepoint 小于 `0x110000` 的输入字符串
- **WHEN** 调用 `smb2_utf8_to_utf16(const char *utf8)`
- **THEN** 返回的 `val` MUST 使用两个 little-endian UTF-16 surrogate code units 表示该 codepoint，并将 `len` 增加两个 code units

Trace: `lib/unicode.c:smb2_utf8_to_utf16`, `include/smb2/libsmb2.h:smb2_utf8_to_utf16`

#### Scenario: Invalid UTF-8 rejection
- **GIVEN** 输入包含 continuation byte 作为起始字节、缺失 continuation byte、overlong sequence、surrogate range codepoint 或大于等于 `0x110000` 的 codepoint
- **WHEN** 调用 `smb2_utf8_to_utf16(const char *utf8)`
- **THEN** 函数 MUST 返回 `NULL`，且不会返回部分转换结果给调用方

Trace: `lib/unicode.c:smb2_utf8_to_utf16`, `lib/unicode.c:validate_utf8_cp`

#### Scenario: Allocation failure
- **GIVEN** UTF-8 输入校验成功但分配 `struct smb2_utf16` 结果缓冲区失败
- **WHEN** 调用 `smb2_utf8_to_utf16(const char *utf8)`
- **THEN** 函数 MUST 返回 `NULL`

Trace: `lib/unicode.c:smb2_utf8_to_utf16`, `include/smb2/libsmb2.h:smb2_utf8_to_utf16`

### Requirement: smb2_utf16_to_utf8 UTF-16LE conversion
系统 MUST 将给定长度的 SMB UTF-16LE code unit 序列转换为新分配且 NUL 终止的 UTF-8 字符串。

#### Scenario: BMP conversion
- **GIVEN** 调用方提供 `utf16_len` 个 little-endian UTF-16 code units，且每个 code unit 位于 ASCII、二字节 UTF-8 或三字节 UTF-8 可表示的 BMP 范围
- **WHEN** 调用 `smb2_utf16_to_utf8(const uint16_t *str, size_t len)`
- **THEN** 返回值为新分配的 UTF-8 字符串，内容按 code unit 值转换，且最后一个字节 MUST 为 NUL 终止符

Trace: `lib/unicode.c:smb2_utf16_to_utf8`, `include/smb2/libsmb2.h:smb2_utf16_to_utf8`

#### Scenario: Surrogate pair conversion
- **GIVEN** 输入包含 high surrogate 后紧跟合法 low surrogate 的 UTF-16LE pair
- **WHEN** 调用 `smb2_utf16_to_utf8(const uint16_t *str, size_t len)`
- **THEN** 函数 MUST 将 surrogate pair 合成为 codepoint，并输出对应的 UTF-8 四字节序列

Trace: `lib/unicode.c:smb2_utf16_to_utf8`, `lib/unicode.c:utf16_size`

#### Scenario: Invalid surrogate replacement
- **GIVEN** 输入以 high surrogate 结尾、high surrogate 后未跟合法 low surrogate，或输入包含孤立 low surrogate
- **WHEN** 调用 `smb2_utf16_to_utf8(const uint16_t *str, size_t len)`
- **THEN** 函数 MUST 在输出中写入 UTF-8 replacement character `0xef 0xbf 0xbd` 表示无效 surrogate 单元

Trace: `lib/unicode.c:smb2_utf16_to_utf8`, `lib/unicode.c:utf16_size`

#### Scenario: Allocation failure
- **GIVEN** UTF-16LE 输入长度完成输出大小计算但分配 UTF-8 字符串失败
- **WHEN** 调用 `smb2_utf16_to_utf8(const uint16_t *str, size_t len)`
- **THEN** 函数 MUST 返回 `NULL`

Trace: `lib/unicode.c:smb2_utf16_to_utf8`, `include/smb2/libsmb2.h:smb2_utf16_to_utf8`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_utf8_to_utf16` 是否要求 `utf8` 非 NULL 且以 NUL 结束需要由调用方保证？ | smb2_utf8_to_utf16 | 源码直接解引用并扫描输入，未发现空指针或最大长度保护。 |
| Q-002 | `smb2_utf8_to_utf16` 分配大小是否应包含 `struct smb2_utf16.val[1]` flexible-array 风格 ABI 的额外尾部终止单元？ | smb2_utf8_to_utf16 | 源码分配 `offsetof(struct smb2_utf16, val) + 2 * len`，header 注释未说明是否 NUL 终止 UTF-16。 |
| Q-003 | `smb2_utf16_to_utf8` 的返回类型为 `const char *` 但 header 注释要求调用方 `free()`，是否应视为调用方拥有的 mutable allocation？ | smb2_utf16_to_utf8 | 源码返回 `malloc` 分配的 `char *`，公开签名使用 `const char *`。 |
| Q-004 | `utf16_size` 和 `smb2_utf16_to_utf8` 使用 `int` 保存输出长度，超大 `utf16_len` 溢出时的行为是否定义？ | smb2_utf16_to_utf8 | 源码未发现 `int` 上限或 `size_t` 到 `int` 溢出检查。 |
