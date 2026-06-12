# include/asprintf.h Specification

## Source Context

- Source: `include/asprintf.h`
- Related Headers: `lib/compat.h`, `lib/compat.c`
- Related Tests: `tests/prog_ls.c`
- Related Dependencies: `asprintf` calls `vasprintf`; `vasprintf` calls `_vscprintf_so` on non-`_XBOX` builds and allocation helpers `malloc`/`free`; `_vscprintf_so` is only called by this header's `vasprintf` according to GitNexus context.
- Build/Compile Context: C header helper included by `lib/libsmb2.c`, `utils/smb2-ls.c`, `utils/smb2-cp.c`, and selected tests/examples; `_XBOX`, `__MINGW32__`, `__AROS__`, `__ps2sdk_iop__`, `vasprintf`, `asprintf`, and `_vscprintf` preprocessor conditions affect which inline compatibility APIs are emitted.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| _vscprintf_so | function | static inline int _vscprintf_so(const char * format, va_list pargs) | Include | 非 `_XBOX` 且非 `__MINGW32__` 构建中提供长度计算兼容函数，被本文件 `vasprintf` 调用并影响分配大小。 |
| vasprintf | function | static inline int vasprintf(char **strp, const char *fmt, va_list ap) | Include | 当平台未提供 `vasprintf` 宏/函数时提供可见 header-only 兼容实现，承担分配、格式化和错误返回契约。 |
| asprintf | function | static inline int asprintf(char *strp[], const char *fmt, ...) | Include | 当平台未提供 `asprintf` 宏/函数时提供可见 header-only varargs 包装，被库、工具和测试源码调用。 |
| inline | macro | #define inline __inline | Include | `_XBOX` 构建中将 C `inline` 拼写映射为 MSVC/Xbox 编译器可接受的 `__inline`。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| inline | macro | include/asprintf.h:12 | `_XBOX` 构建下定义为 `__inline`，用于保持本头文件静态内联函数可编译。 |

## ADDED Requirements

### Requirement: _vscprintf_so computes formatted output length
系统 MUST 在非 `_XBOX` 且非 `__MINGW32__` 构建中提供 `_vscprintf_so`，并返回 `vsnprintf(NULL, 0, format, copied_args)` 的结果，同时不消耗调用方传入的原始 `va_list`。

#### Scenario: non-Xbox length calculation uses a copied va_list
- **GIVEN** 编译条件未定义 `_XBOX` 和 `__MINGW32__`，且 `_vscprintf` 未预先定义
- **WHEN** 调用 `_vscprintf_so(format, pargs)` 计算格式化字符串长度
- **THEN** 函数基于 `va_copy` 创建的参数副本调用 `vsnprintf(NULL, 0, format, argcopy)`，结束副本并返回 `vsnprintf` 的返回值

Trace: `include/asprintf.h:_vscprintf_so`

### Requirement: vasprintf allocates and formats an owned buffer
系统 MUST 在未预定义 `vasprintf` 时提供 `vasprintf`，并在长度计算、内存分配或格式化失败时返回 `-1`；成功时 SHALL 将新分配的 NUL 结尾缓冲区写入 `*strp` 并返回格式化函数返回值。

#### Scenario: successful allocation and formatting
- **GIVEN** `vasprintf` 未预定义，长度计算返回非负值，且 `malloc((size_t)len + 1)` 成功
- **WHEN** 调用 `vasprintf(strp, fmt, ap)` 生成格式化字符串
- **THEN** 函数分配 `len + 1` 字节，调用平台对应的格式化函数写入缓冲区，将缓冲区地址赋给 `*strp`，并返回格式化结果 `r`

Trace: `include/asprintf.h:vasprintf`

#### Scenario: length calculation or allocation failure
- **GIVEN** `vasprintf` 未预定义，且长度计算返回 `-1` 或 `malloc` 返回 `NULL`
- **WHEN** 调用 `vasprintf(strp, fmt, ap)`
- **THEN** 函数返回 `-1`，且在 `malloc` 失败路径不会向 `*strp` 写入新缓冲区

Trace: `include/asprintf.h:vasprintf`

#### Scenario: formatting failure releases allocated storage
- **GIVEN** `vasprintf` 未预定义，长度计算和 `malloc` 成功，但最终格式化调用返回 `-1`
- **WHEN** 调用 `vasprintf(strp, fmt, ap)`
- **THEN** 函数释放已分配缓冲区并返回 `-1`

Trace: `include/asprintf.h:vasprintf`

### Requirement: asprintf wraps vasprintf with varargs lifecycle
系统 MUST 在未预定义 `asprintf` 时提供 `asprintf`，并 SHALL 使用 `va_start`/`va_end` 管理可变参数后返回底层 `vasprintf(strp, fmt, ap)` 的结果。

#### Scenario: varargs forwarding to vasprintf
- **GIVEN** `asprintf` 未预定义，调用方传入输出指针数组、格式字符串和可变参数
- **WHEN** 调用 `asprintf(strp, fmt, ...)`
- **THEN** 函数初始化 `va_list`，调用 `vasprintf(strp, fmt, ap)`，结束 `va_list`，并返回 `vasprintf` 的返回值

Trace: `include/asprintf.h:asprintf`, `tests/prog_ls.c:161`, `tests/prog_ls.c:166`

### Requirement: inline macro maps Xbox inline spelling
系统 MUST 在 `_XBOX` 构建中将 `inline` 定义为 `__inline`，使本头文件中的静态内联兼容函数使用 Xbox/MSVC 风格内联关键字。

#### Scenario: Xbox compile condition rewrites inline keyword
- **GIVEN** 编译条件定义 `_XBOX`
- **WHEN** 预处理 `include/asprintf.h`
- **THEN** 头文件定义 `inline` 为 `__inline`，后续 `static inline` 函数声明使用该映射

Trace: `include/asprintf.h:inline`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `vasprintf` 在最终格式化失败路径释放缓冲区但不重置 `*strp`，调用方是否依赖 `*strp` 保持原值或未定义状态？ | vasprintf | 源码仅显示 `return free(str), -1`，未提供调用方错误路径断言。 |
| Q-002 | `_XBOX` 路径使用 `_vscprintf` 和 `_vsnprintf`，这些函数在目标 SDK 中的返回语义是否完全等价于非 `_XBOX` 路径？ | vasprintf | 当前仓库源码只包含条件调用，未包含 Xbox SDK 实现或测试证据。 |
