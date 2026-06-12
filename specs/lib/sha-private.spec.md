# lib/sha-private.h Specification

## Source Context

- Source: `lib/sha-private.h`
- Related Headers: `lib/sha.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context located `SHA_Ch`, `SHA_Maj`, and `SHA_Parity` as macros in `lib/sha-private.h` with no indexed callers; source search shows `lib/sha384-512.c` defines separate local `SHA_Ch` and `SHA_Maj` macros rather than using this header's definitions.
- Build/Compile Context: The header is protected by `_SHA_PRIVATE__H`; `USE_MODIFIED_MACROS` selects alternate but equivalent definitions for `SHA_Ch` and `SHA_Maj`; `SHA_Parity` is always defined when the include guard admits the header.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| `SHA_Ch` | macro | `#define SHA_Ch(x,y,z)        (((x) & (y)) ^ ((~(x)) & (z)))` / `#define SHA_Ch(x, y, z)      (((x) & ((y) ^ (z))) ^ (z))` | Include | 该私有头文件暴露 SHA/FIPS 选择函数宏，`USE_MODIFIED_MACROS` 会切换等价公式，影响包含方的轮函数计算。 |
| `SHA_Maj` | macro | `#define SHA_Maj(x,y,z)       (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))` / `#define SHA_Maj(x, y, z)     (((x) & ((y) \| (z))) \| ((y) & (z)))` | Include | 该私有头文件暴露 SHA/FIPS 多数函数宏，`USE_MODIFIED_MACROS` 会切换等价公式，影响包含方的轮函数计算。 |
| `SHA_Parity` | macro | `#define SHA_Parity(x, y, z)  ((x) ^ (y) ^ (z))` | Include | 该私有头文件始终暴露 SHA parity 轮函数宏，供包含方按位组合三个输入字。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| `SHA_Ch` | macro | `lib/sha-private.h:14`, `lib/sha-private.h:22` | 根据 `USE_MODIFIED_MACROS` 在 FIPS 公式和等价优化公式之间选择。 |
| `SHA_Maj` | macro | `lib/sha-private.h:15`, `lib/sha-private.h:23` | 根据 `USE_MODIFIED_MACROS` 在 FIPS 公式和等价优化公式之间选择。 |
| `SHA_Parity` | macro | `lib/sha-private.h:26` | 不受 `USE_MODIFIED_MACROS` 影响，展开为三个输入的 XOR。 |

## ADDED Requirements

### Requirement: SHA_Ch choice function macro
系统 MUST 在未定义 `USE_MODIFIED_MACROS` 时将 `SHA_Ch(x,y,z)` 展开为 FIPS 180-2 choice 公式 `(((x) & (y)) ^ ((~(x)) & (z)))`，并在定义 `USE_MODIFIED_MACROS` 时展开为等价公式 `(((x) & ((y) ^ (z))) ^ (z))`。

#### Scenario: 默认 choice 公式展开
- **GIVEN** 编译包含 `lib/sha-private.h` 且未定义 `USE_MODIFIED_MACROS`
- **WHEN** 包含方使用 `SHA_Ch(x,y,z)` 组合三个输入字
- **THEN** 宏展开结果按 FIPS choice 公式选择 `x` 为 1 时的 `y` 位和 `x` 为 0 时的 `z` 位

Trace: `lib/sha-private.h:SHA_Ch`

#### Scenario: 修改宏 choice 公式展开
- **GIVEN** 编译包含 `lib/sha-private.h` 且定义了 `USE_MODIFIED_MACROS`
- **WHEN** 包含方使用 `SHA_Ch(x,y,z)` 组合三个输入字
- **THEN** 宏展开结果使用等价的 `((x) & ((y) ^ (z))) ^ (z)` 形式表达相同 choice 位语义

Trace: `lib/sha-private.h:SHA_Ch`

### Requirement: SHA_Maj majority function macro
系统 MUST 在未定义 `USE_MODIFIED_MACROS` 时将 `SHA_Maj(x,y,z)` 展开为 FIPS 180-2 majority 公式 `(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))`，并在定义 `USE_MODIFIED_MACROS` 时展开为等价公式 `(((x) & ((y) | (z))) | ((y) & (z)))`。

#### Scenario: 默认 majority 公式展开
- **GIVEN** 编译包含 `lib/sha-private.h` 且未定义 `USE_MODIFIED_MACROS`
- **WHEN** 包含方使用 `SHA_Maj(x,y,z)` 组合三个输入字
- **THEN** 宏展开结果按 FIPS majority 公式为每个位返回三个输入中的多数值

Trace: `lib/sha-private.h:SHA_Maj`

#### Scenario: 修改宏 majority 公式展开
- **GIVEN** 编译包含 `lib/sha-private.h` 且定义了 `USE_MODIFIED_MACROS`
- **WHEN** 包含方使用 `SHA_Maj(x,y,z)` 组合三个输入字
- **THEN** 宏展开结果使用等价的 `((x) & ((y) | (z))) | ((y) & (z))` 形式表达相同 majority 位语义

Trace: `lib/sha-private.h:SHA_Maj`

### Requirement: SHA_Parity parity function macro
系统 MUST 始终将 `SHA_Parity(x, y, z)` 展开为 `((x) ^ (y) ^ (z))`，不受 `USE_MODIFIED_MACROS` 条件影响。

#### Scenario: parity 公式展开
- **GIVEN** 编译包含 `lib/sha-private.h`
- **WHEN** 包含方使用 `SHA_Parity(x, y, z)` 组合三个输入字
- **THEN** 宏展开结果对三个输入执行逐位 XOR

Trace: `lib/sha-private.h:SHA_Parity`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `lib/sha-private.h` 中的 `SHA_Ch`、`SHA_Maj` 和 `SHA_Parity` 当前是否仍被 SHA-1 或 SHA-224/256 实现实际包含使用？ | `SHA_Ch`, `SHA_Maj`, `SHA_Parity` | GitNexus 未索引到直接调用者，当前源码搜索只确认 `lib/sha384-512.c` 有同名本地宏；实际预处理依赖可能受 SHA 编译开关影响。 |
