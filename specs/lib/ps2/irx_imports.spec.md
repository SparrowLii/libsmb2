# lib/ps2/irx_imports.h Specification

## Source Context

- Source: `lib/ps2/irx_imports.h`
- Related Headers: `<irx.h>`, `<intrman.h>`, `<ioman.h>`, `<ps2ip.h>`, `<sifman.h>`, `<stdio.h>`, `<sysclib.h>`, `<sysmem.h>`, `<thbase.h>`, `<thsemap.h>`
- Related Tests: `none`
- Related Dependencies: GitNexus context for `IOP_IRX_IMPORTS_H` found no incoming callers, outgoing symbols, or execution processes.
- Build/Compile Context: PS2 IOP import aggregation header; protected by `IOP_IRX_IMPORTS_H`; included headers are provided by the PS2SDK/IOP build environment.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| irx_imports.h include surface | header | `#include <irx.h>` and PS2SDK IOP import includes | Include | 该头文件为 PS2 IOP 构建集中暴露 IRX 导入依赖，调用方可观察行为是一次包含即可获得所列 PS2SDK 声明。 |
| IOP_IRX_IMPORTS_H | macro | #define IOP_IRX_IMPORTS_H | Skip | include guard 仅防止重复包含，无独立调用方可观察行为。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| IOP_IRX_IMPORTS_H | macro | lib/ps2/irx_imports.h:13 | 头文件 include guard，避免重复展开 PS2SDK IOP import includes。 |

## ADDED Requirements

### Requirement: irx_imports.h include surface exposes PS2 IOP imports
系统 MUST 在包含 `lib/ps2/irx_imports.h` 时向编译单元暴露该文件列出的 PS2SDK IOP import 头文件声明，并通过 `IOP_IRX_IMPORTS_H` 避免重复展开同一导入集合。

#### Scenario: include header once
- **GIVEN** PS2 IOP 编译环境提供 `irx.h`、`intrman.h`、`ioman.h`、`ps2ip.h`、`sifman.h`、`stdio.h`、`sysclib.h`、`sysmem.h`、`thbase.h` 和 `thsemap.h`
- **WHEN** 调用方包含 `lib/ps2/irx_imports.h`
- **THEN** 编译单元获得这些 PS2SDK import 头文件声明，且该头文件自身不定义额外函数、类型或资源生命周期行为

Trace: `lib/ps2/irx_imports.h:16`, `lib/ps2/irx_imports.h:18`, `lib/ps2/irx_imports.h:19`, `lib/ps2/irx_imports.h:20`, `lib/ps2/irx_imports.h:21`, `lib/ps2/irx_imports.h:22`, `lib/ps2/irx_imports.h:23`, `lib/ps2/irx_imports.h:24`, `lib/ps2/irx_imports.h:25`, `lib/ps2/irx_imports.h:26`

#### Scenario: include header repeatedly
- **GIVEN** 一个编译单元已展开过 `lib/ps2/irx_imports.h` 并定义 `IOP_IRX_IMPORTS_H`
- **WHEN** 同一编译单元再次包含 `lib/ps2/irx_imports.h`
- **THEN** 头文件主体不会重复展开 PS2SDK IOP import includes

Trace: `lib/ps2/irx_imports.h:13`, `lib/ps2/irx_imports.h:14`, `lib/ps2/irx_imports.h:28`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | PS2SDK 外部头文件在不同 IOP SDK 版本中的可用性和声明差异是否需要项目级兼容约束？ | irx_imports.h include surface | 当前仓库仅聚合包含这些外部头文件，未提供版本探测或替代实现。 |
