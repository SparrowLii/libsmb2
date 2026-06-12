# lib/ps2/smb2_fio.h Specification

## Source Context

- Source: `lib/ps2/smb2_fio.h`
- Related Headers: `lib/ps2/smb2man.c`, `lib/ps2/smb2_fio.c`
- Related Tests: `none`
- Related Dependencies: `SMB2_initdev` declaration context has no incoming/outgoing edges in GitNexus; implementation `Function:lib/ps2/smb2_fio.c:SMB2_initdev` is called by `lib/ps2/smb2man.c:_start`.
- Build/Compile Context: `lib/CMakeLists.txt` includes `ps2/smb2_fio.c` and `ps2/smb2man.c` only for `IOP AND BUILD_IRX`; top-level CMake adds PS2 IOP definitions including `__ps2sdk_iop__` for that build path.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| SMB2_initdev | function | int SMB2_initdev(void); | Include | PS2 IOP IRX 启动入口通过该声明注册 SMB2 文件系统设备，调用方可观察返回驻留状态。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| __SMB2_FIO_H__ | macro | lib/ps2/smb2_fio.h:10 | 头文件 include guard，防止声明重复展开。 |

## ADDED Requirements

### Requirement: SMB2_initdev PS2 device registration entry
系统 MUST 暴露 `int SMB2_initdev(void);` 作为 PS2 IOP IRX 启动代码可调用的设备初始化入口，并 SHALL 由实现完成 `smb` 文件系统驱动注册后返回 PS2 模块驻留状态。

#### Scenario: startup calls device initializer
- **GIVEN** `IOP AND BUILD_IRX` 构建包含 `lib/ps2/smb2man.c` 和 `lib/ps2/smb2_fio.c`
- **WHEN** PS2 IRX `_start` 调用 `SMB2_initdev()`
- **THEN** 调用 MUST 解析到无参数、返回 `int` 的初始化入口，并由实现根据 `AddDrv` 成功或失败返回 `MODULE_RESIDENT_END` 或 `MODULE_NO_RESIDENT_END`

Trace: `lib/ps2/smb2_fio.h:SMB2_initdev`, `lib/ps2/smb2_fio.c:SMB2_initdev`, `lib/ps2/smb2man.c:_start`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `SMB2_initdev` 是否需要在声明层公开 `extern "C"` 或 PS2SDK 特定 linkage 约束？ | SMB2_initdev | 当前头文件为 C 头文件且未包含 C++ linkage guard，未发现 C++ 调用证据。 |
