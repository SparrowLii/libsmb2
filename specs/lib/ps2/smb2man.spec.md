# lib/ps2/smb2man.c Specification

## Source Context

- Source: `lib/ps2/smb2man.c`
- Related Headers: `lib/ps2/smb2_fio.h`
- Related Tests: `none`
- Related Dependencies: `SMB2_initdev` from `lib/ps2/smb2_fio.c`; PS2SDK IOP services `CpuSuspendIntr`, `CpuResumeIntr`, `AllocSysMemory`, `FreeSysMemory`; GitNexus context found no test callers and no process flows for this file.
- Build/Compile Context: `lib/CMakeLists.txt` includes `ps2/smb2man.c` in the `IOP AND BUILD_IRX` source list and builds `smb2man.irx`; top-level CMake uses project `smb2man` version `2.3.0` when `NOT IOP AND BUILD_IRX`, while this source declares IRX module metadata `MODNAME` version `2.2`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| _start | function | int _start(int argc, char *argv[]) | Include | PS2 IRX 模块入口，调用方可观察到版本输出和设备注册返回码。 |
| malloc | function | void *malloc(int size) | Include | PS2 IOP 环境下替代标准分配入口，封装中断保护和系统内存分配，影响同文件 `calloc` 以及链接到 IRX 的分配调用。 |
| free | function | void free(void *ptr) | Include | PS2 IOP 环境下替代标准释放入口，封装中断保护和系统内存释放。 |
| calloc | function | void *calloc(size_t nmemb, size_t size) | Include | PS2 IOP 环境下替代标准清零分配入口，调用 `malloc` 并清零分配区域。 |
| MODNAME | macro | #define MODNAME   "smb2man" | Skip | 模块元数据宏由 `_start` 和 `IRX_ID` 入口行为覆盖，无独立调用方行为。 |
| VER_MAJOR | macro | #define VER_MAJOR 2 | Skip | 模块版本宏由 `_start` 和 `IRX_ID` 入口行为覆盖，无独立调用方行为。 |
| VER_MINOR | macro | #define VER_MINOR 2 | Skip | 模块版本宏由 `_start` 和 `IRX_ID` 入口行为覆盖，无独立调用方行为。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| MODNAME | macro | lib/ps2/smb2man.c:23 | 定义 IRX 模块名和 `_start` 日志前缀。 |
| VER_MAJOR | macro | lib/ps2/smb2man.c:24 | 定义 IRX 模块主版本并参与 `IRX_ID` 和 `_start` 输出。 |
| VER_MINOR | macro | lib/ps2/smb2man.c:25 | 定义 IRX 模块次版本并参与 `IRX_ID` 和 `_start` 输出。 |

## ADDED Requirements

### Requirement: _start register PS2 SMB device
系统 MUST 在 IRX 入口被调用时忽略 `argc` 和 `argv`，输出由 `MODNAME`、`VER_MAJOR` 和 `VER_MINOR` 组成的模块版本信息，并把 `SMB2_initdev()` 的返回值作为入口返回值传递给加载方。

#### Scenario: IRX entry delegates device registration
- **GIVEN** PS2 IOP 加载器调用 `lib/ps2/smb2man.c` 的 `_start` 入口
- **WHEN** `_start` 接收任意 `argc` 和 `argv` 参数
- **THEN** 入口输出 `smb2man` 版本信息并返回 `SMB2_initdev()` 的返回码

Trace: `lib/ps2/smb2man.c:_start`, `lib/ps2/smb2_fio.c:SMB2_initdev`

### Requirement: malloc allocate PS2 system memory with interrupts suspended
系统 MUST 在 `malloc` 被调用时先通过 `CpuSuspendIntr` 暂停中断，使用 `AllocSysMemory(ALLOC_FIRST, size, NULL)` 请求 PS2 IOP 系统内存，然后通过 `CpuResumeIntr` 恢复原中断状态并返回分配结果。

#### Scenario: protected system allocation
- **GIVEN** 调用方在 PS2 IOP IRX 环境中请求 `size` 字节内存
- **WHEN** 调用 `malloc(size)`
- **THEN** 分配过程在中断暂停区间内调用 `AllocSysMemory`，并把系统分配器返回的指针返回给调用方

Trace: `lib/ps2/smb2man.c:malloc`

### Requirement: free release PS2 system memory with interrupts suspended
系统 MUST 在 `free` 被调用时先通过 `CpuSuspendIntr` 暂停中断，使用 `FreeSysMemory(ptr)` 释放调用方提供的指针，然后通过 `CpuResumeIntr` 恢复原中断状态。

#### Scenario: protected system release
- **GIVEN** 调用方提供要释放的 PS2 IOP 系统内存指针
- **WHEN** 调用 `free(ptr)`
- **THEN** 释放过程在中断暂停区间内调用 `FreeSysMemory`，并在返回前恢复原中断状态

Trace: `lib/ps2/smb2man.c:free`

### Requirement: calloc allocate and zero PS2 system memory
系统 MUST 在 `calloc` 被调用时计算 `nmemb * size` 字节总长度，通过同文件 `malloc` 分配该长度的内存，并使用 `memset(ptr, 0, s)` 清零分配区域后返回该指针。

#### Scenario: zeroed allocation delegates to malloc
- **GIVEN** 调用方请求 `nmemb` 个元素且每个元素大小为 `size`
- **WHEN** 调用 `calloc(nmemb, size)`
- **THEN** 函数用乘积长度调用 `malloc`，对返回指针覆盖 `s` 字节零值，并返回该指针

Trace: `lib/ps2/smb2man.c:calloc`, `lib/ps2/smb2man.c:malloc`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `calloc` 在 `malloc` 返回 `NULL` 时仍调用 `memset(ptr, 0, s)`，该失败路径是否由 PS2SDK 分配器保证不会发生或应视为调用方前置条件？ | calloc | 源码未在清零前检查空指针，未发现测试覆盖。 |
| Q-002 | `nmemb * size` 乘法溢出是否需要作为稳定行为记录，还是由 PS2 IOP 调用方保证参数范围？ | calloc | 源码直接使用 `size_t` 乘法且无溢出检查，未发现外部契约说明。 |
| Q-003 | `free(NULL)` 的行为是否完全继承 `FreeSysMemory(NULL)`，以及是否允许空指针释放？ | free | 源码无空指针分支，PS2SDK 外部函数语义未在仓库内确认。 |
| Q-004 | `_start` 打印版本 `2.2` 与 top-level CMake `smb2man` project version `2.3.0` 的差异是否有发布语义？ | _start | 源码宏和构建元数据版本不一致，未发现说明文档解释差异。 |
