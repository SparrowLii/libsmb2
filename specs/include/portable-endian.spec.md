# include/portable-endian.h Specification

## Source Context

- Source: `include/portable-endian.h`
- Related Headers: `<machine/endian.h>`, `lwip/def.h`, `<endian.h>`, `<byteswap.h>`, `<sys/endian.h>`, `<libkern/OSByteOrder.h>`, `<xtl.h>`, `<windows.h>`, `<stdlib.h>`
- Related Tests: `none`
- Related Dependencies: GitNexus `context` located macro symbols `be16toh`, `htobe16`, `htole16`, `le16toh`, `be32toh`, `htobe32`, `htole32`, `le32toh`, `be64toh`, `htobe64`, `htole64`, and `le64toh`; direct source includes appear in `lib/aes128ccm.c`, `lib/dcerpc.c`, `lib/libsmb2.c`, `lib/ntlmssp.c`, `lib/pdu.c`, `lib/smb3-seal.c`, `lib/socket.c`, `lib/timestamps.c`, and `lib/unicode.c`.
- Build/Compile Context: C header selected by platform macros `__PS2__`, `PICO_PLATFORM`, `__DREAMCAST__`, `__linux__`, `__CYGWIN__`, `ESP_PLATFORM`, `__NetBSD__`, `__FreeBSD__`, `__DragonFly__`, `__OpenBSD__`, `__GNU__`, `__APPLE__`, `PS3_PPU_PLATFORM`, `__WIIU__`, `__wii__`, `__gamecube__`, `__SWITCH__`, `__N3DS__`, `__NDS__`, `__WINDOWS__`, `_XBOX`, `_MSC_VER`, `__GNUC__`, `__clang__`, `__amigaos4__`, `__AMIGA__`, `__NEWLIB__`, `__AROS__`, and `__vita__`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| be16toh | macro | #define be16toh(x) <platform conversion> | Include | 公开 16 位 big-endian 到 host-order 转换宏，被协议读写路径调用。 |
| htobe16 | macro | #define htobe16(x) <platform conversion> | Include | 公开 16 位 host-order 到 big-endian 转换宏，被协议序列化路径调用。 |
| htole16 | macro | #define htole16(x) <platform conversion> | Include | 公开 16 位 host-order 到 little-endian 转换宏，被 SMB/DCERPC/NTLM 编码路径调用。 |
| le16toh | macro | #define le16toh(x) <platform conversion> | Include | 公开 16 位 little-endian 到 host-order 转换宏，被解析路径调用。 |
| be32toh | macro | #define be32toh(x) <platform conversion> | Include | 公开 32 位 big-endian 到 host-order 转换宏，被 NetBIOS framing 和 DCERPC 解析路径调用。 |
| htobe32 | macro | #define htobe32(x) <platform conversion> | Include | 公开 32 位 host-order 到 big-endian 转换宏，被网络帧和密钥派生路径调用。 |
| htole32 | macro | #define htole32(x) <platform conversion> | Include | 公开 32 位 host-order 到 little-endian 转换宏，被 SMB/NTLM/DCERPC 编码路径调用。 |
| le32toh | macro | #define le32toh(x) <platform conversion> | Include | 公开 32 位 little-endian 到 host-order 转换宏，被 SMB/NTLM/DCERPC 解析路径调用。 |
| be64toh | macro | #define be64toh(x) <platform conversion> | Include | 公开 64 位 big-endian 到 host-order 转换宏，部分平台直接在本头定义。 |
| htobe64 | macro | #define htobe64(x) <platform conversion> | Include | 公开 64 位 host-order 到 big-endian 转换宏，被 DCERPC 和派生数据编码路径调用。 |
| htole64 | macro | #define htole64(x) <platform conversion> | Include | 公开 64 位 host-order 到 little-endian 转换宏，被 SMB/NTLM/DCERPC 编码路径调用。 |
| le64toh | macro | #define le64toh(x) <platform conversion> | Include | 公开 64 位 little-endian 到 host-order 转换宏，被 SMB/DCERPC 解析路径调用。 |
| PORTABLE_ENDIAN_H__ | macro | #define PORTABLE_ENDIAN_H__ | Skip | include guard，无独立调用方可观察 endian 转换语义。 |
| __WINDOWS__ | macro | #define __WINDOWS__ | Skip | 平台条件归一化宏，仅用于本头分支选择。 |
| _LITTLE_ENDIAN | macro | #define _LITTLE_ENDIAN LITTLE_ENDIAN | Skip | 平台常量兼容别名，无独立转换行为。 |
| __bswap16 | macro | #define __bswap16 <platform byteswap> | Skip | 内部 byteswap 兼容宏，只支撑公开 endian 转换宏。 |
| __bswap32 | macro | #define __bswap32 <platform byteswap> | Skip | 内部 byteswap 兼容宏，只支撑公开 endian 转换宏。 |
| __bswap64 | macro | #define __bswap64 <platform byteswap> | Skip | 内部 byteswap 兼容宏，只支撑公开 endian 转换宏。 |
| __BYTE_ORDER | macro | #define __BYTE_ORDER BYTE_ORDER | Skip | 平台字节序常量兼容别名，无独立转换行为。 |
| __BIG_ENDIAN | macro | #define __BIG_ENDIAN BIG_ENDIAN | Skip | 平台字节序常量兼容别名，无独立转换行为。 |
| __LITTLE_ENDIAN | macro | #define __LITTLE_ENDIAN LITTLE_ENDIAN | Skip | 平台字节序常量兼容别名，无独立转换行为。 |
| __PDP_ENDIAN | macro | #define __PDP_ENDIAN PDP_ENDIAN | Skip | 平台字节序常量兼容别名，无独立转换行为。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| PORTABLE_ENDIAN_H__ | macro | include/portable-endian.h:7 | 头文件 include guard，避免重复定义平台 endian 宏。 |
| __WINDOWS__ | macro | include/portable-endian.h:10 | 当 `_WIN16`、`_WIN32` 或 `_WIN64` 存在且非 `_XBOX` 时归一化 Windows 平台条件。 |
| _LITTLE_ENDIAN | macro | include/portable-endian.h:16`, `include/portable-endian.h:72 | 在部分 PS2/PICO/Linux/ESP 环境补齐 little-endian 常量别名。 |
| __bswap16 | macro | include/portable-endian.h:76`, `include/portable-endian.h:239`, `include/portable-endian.h:293`, `include/portable-endian.h:299 | 在平台头未提供时映射到系统或内建 byteswap 实现。 |
| __bswap32 | macro | include/portable-endian.h:80`, `include/portable-endian.h:243`, `include/portable-endian.h:294`, `include/portable-endian.h:301 | 在平台头未提供时映射到系统或内建 byteswap 实现。 |
| __bswap64 | macro | include/portable-endian.h:84`, `include/portable-endian.h:247`, `include/portable-endian.h:295`, `include/portable-endian.h:305 | 在平台头未提供时映射到系统或内建 byteswap 实现。 |
| __BYTE_ORDER | macro | include/portable-endian.h:131`, `include/portable-endian.h:197 | 在 Apple 和 MSVC 分支补齐字节序常量别名。 |
| __BIG_ENDIAN | macro | include/portable-endian.h:132`, `include/portable-endian.h:201 | 在 Apple 和 MSVC 分支补齐 big-endian 常量别名。 |
| __LITTLE_ENDIAN | macro | include/portable-endian.h:133`, `include/portable-endian.h:205 | 在 Apple 和 MSVC 分支补齐 little-endian 常量别名。 |
| __PDP_ENDIAN | macro | include/portable-endian.h:134`, `include/portable-endian.h:209 | 在 Apple 和 MSVC 分支补齐 PDP endian 常量别名。 |

## ADDED Requirements

### Requirement: be16toh converts 16-bit big-endian input to host order
系统 MUST 为支持的平台提供 `be16toh(x)` 宏，使调用方可将 16 位 big-endian 值转换为 host-order 值。

#### Scenario: supported platform converts big-endian 16-bit value
- **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
- **WHEN** 调用方使用 `be16toh(x)` 读取 16 位 big-endian 协议字段
- **THEN** 宏展开 MUST 使用该平台的网络序转换、byteswap 内建、系统 endian API 或恒等表达式返回 host-order 值

Trace: `include/portable-endian.h:26`, `include/portable-endian.h:44`, `include/portable-endian.h:88`, `include/portable-endian.h:118`, `include/portable-endian.h:140`, `include/portable-endian.h:158`, `include/portable-endian.h:184`, `include/portable-endian.h:217`, `include/portable-endian.h:253`, `include/portable-endian.h:270`, `include/portable-endian.h:320`, `include/portable-endian.h:337`, `include/portable-endian.h:360`

### Requirement: htobe16 converts 16-bit host input to big-endian order
系统 MUST 为支持的平台提供 `htobe16(x)` 宏，使调用方可将 16 位 host-order 值编码为 big-endian 值。

#### Scenario: supported platform writes big-endian 16-bit value
- **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
- **WHEN** 调用方使用 `htobe16(x)` 写入 16 位 big-endian 协议字段
- **THEN** 宏展开 MUST 使用该平台的网络序转换、byteswap 内建、系统 endian API 或恒等表达式生成 big-endian 值

Trace: `include/portable-endian.h:27`, `include/portable-endian.h:45`, `include/portable-endian.h:116`, `include/portable-endian.h:138`, `include/portable-endian.h:156`, `include/portable-endian.h:182`, `include/portable-endian.h:215`, `include/portable-endian.h:251`, `include/portable-endian.h:268`, `include/portable-endian.h:318`, `include/portable-endian.h:335`, `include/portable-endian.h:358`

### Requirement: htole16 converts 16-bit host input to little-endian order
系统 MUST 为支持的平台提供 `htole16(x)` 宏，使调用方可将 16 位 host-order 值编码为 little-endian 值。

#### Scenario: supported platform writes little-endian 16-bit value
- **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
- **WHEN** 调用方使用 `htole16(x)` 写入 SMB、DCERPC 或 NTLM little-endian 16 位字段
- **THEN** 宏展开 MUST 在 little-endian 平台保持值不变，或在 big-endian 平台执行 16 位 byteswap

Trace: `include/portable-endian.h:28`, `include/portable-endian.h:46`, `include/portable-endian.h:117`, `include/portable-endian.h:139`, `include/portable-endian.h:157`, `include/portable-endian.h:183`, `include/portable-endian.h:216`, `include/portable-endian.h:252`, `include/portable-endian.h:269`, `include/portable-endian.h:319`, `include/portable-endian.h:336`, `include/portable-endian.h:359`

### Requirement: le16toh converts 16-bit little-endian input to host order
系统 MUST 为支持的平台提供 `le16toh(x)` 宏，使调用方可将 16 位 little-endian 值转换为 host-order 值。

#### Scenario: supported platform reads little-endian 16-bit value
- **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
- **WHEN** 调用方使用 `le16toh(x)` 解析 SMB、DCERPC 或 NTLM little-endian 16 位字段
- **THEN** 宏展开 MUST 在 little-endian 平台保持值不变，或在 big-endian 平台执行 16 位 byteswap

Trace: `include/portable-endian.h:29`, `include/portable-endian.h:47`, `include/portable-endian.h:92`, `include/portable-endian.h:119`, `include/portable-endian.h:141`, `include/portable-endian.h:159`, `include/portable-endian.h:185`, `include/portable-endian.h:218`, `include/portable-endian.h:254`, `include/portable-endian.h:271`, `include/portable-endian.h:321`, `include/portable-endian.h:338`, `include/portable-endian.h:361`

### Requirement: be32toh converts 32-bit big-endian input to host order
系统 MUST 为支持的平台提供 `be32toh(x)` 宏，使调用方可将 32 位 big-endian 值转换为 host-order 值。

#### Scenario: supported platform reads big-endian 32-bit value
- **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
- **WHEN** 调用方使用 `be32toh(x)` 读取 32 位 big-endian 网络或协议字段
- **THEN** 宏展开 MUST 使用该平台的网络序转换、byteswap 内建、系统 endian API 或恒等表达式返回 host-order 值

Trace: `include/portable-endian.h:31`, `include/portable-endian.h:49`, `include/portable-endian.h:96`, `include/portable-endian.h:123`, `include/portable-endian.h:145`, `include/portable-endian.h:163`, `include/portable-endian.h:189`, `include/portable-endian.h:222`, `include/portable-endian.h:258`, `include/portable-endian.h:275`, `include/portable-endian.h:325`, `include/portable-endian.h:342`, `include/portable-endian.h:365`

### Requirement: htobe32 converts 32-bit host input to big-endian order
系统 MUST 为支持的平台提供 `htobe32(x)` 宏，使调用方可将 32 位 host-order 值编码为 big-endian 值。

#### Scenario: supported platform writes big-endian 32-bit value
- **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
- **WHEN** 调用方使用 `htobe32(x)` 写入 32 位 big-endian 网络或协议字段
- **THEN** 宏展开 MUST 使用该平台的网络序转换、byteswap 内建、系统 endian API 或恒等表达式生成 big-endian 值

Trace: `include/portable-endian.h:32`, `include/portable-endian.h:50`, `include/portable-endian.h:121`, `include/portable-endian.h:143`, `include/portable-endian.h:161`, `include/portable-endian.h:187`, `include/portable-endian.h:220`, `include/portable-endian.h:256`, `include/portable-endian.h:273`, `include/portable-endian.h:323`, `include/portable-endian.h:340`, `include/portable-endian.h:363`

### Requirement: htole32 converts 32-bit host input to little-endian order
系统 MUST 为支持的平台提供 `htole32(x)` 宏，使调用方可将 32 位 host-order 值编码为 little-endian 值。

#### Scenario: supported platform writes little-endian 32-bit value
- **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
- **WHEN** 调用方使用 `htole32(x)` 写入 SMB、DCERPC 或 NTLM little-endian 32 位字段
- **THEN** 宏展开 MUST 在 little-endian 平台保持值不变，或在 big-endian 平台执行 32 位 byteswap

Trace: `include/portable-endian.h:33`, `include/portable-endian.h:51`, `include/portable-endian.h:122`, `include/portable-endian.h:144`, `include/portable-endian.h:162`, `include/portable-endian.h:188`, `include/portable-endian.h:221`, `include/portable-endian.h:257`, `include/portable-endian.h:274`, `include/portable-endian.h:324`, `include/portable-endian.h:341`, `include/portable-endian.h:364`

### Requirement: le32toh converts 32-bit little-endian input to host order
系统 MUST 为支持的平台提供 `le32toh(x)` 宏，使调用方可将 32 位 little-endian 值转换为 host-order 值。

#### Scenario: supported platform reads little-endian 32-bit value
- **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
- **WHEN** 调用方使用 `le32toh(x)` 解析 SMB、DCERPC 或 NTLM little-endian 32 位字段
- **THEN** 宏展开 MUST 在 little-endian 平台保持值不变，或在 big-endian 平台执行 32 位 byteswap

Trace: `include/portable-endian.h:34`, `include/portable-endian.h:52`, `include/portable-endian.h:100`, `include/portable-endian.h:124`, `include/portable-endian.h:146`, `include/portable-endian.h:164`, `include/portable-endian.h:190`, `include/portable-endian.h:223`, `include/portable-endian.h:259`, `include/portable-endian.h:276`, `include/portable-endian.h:326`, `include/portable-endian.h:343`, `include/portable-endian.h:366`

### Requirement: be64toh converts 64-bit big-endian input to host order
系统 MUST 为支持的平台提供 `be64toh(x)` 宏，使调用方可将 64 位 big-endian 值转换为 host-order 值。

#### Scenario: supported platform reads big-endian 64-bit value
- **GIVEN** 编译目标命中 `include/portable-endian.h` 中定义 `be64toh(x)` 的平台分支，或系统头已提供该宏
- **WHEN** 调用方使用 `be64toh(x)` 读取 64 位 big-endian 协议字段
- **THEN** 宏展开 MUST 使用该平台的 64 位 byteswap、系统 endian API 或恒等表达式返回 host-order 值

Trace: `include/portable-endian.h:54`, `include/portable-endian.h:128`, `include/portable-endian.h:150`, `include/portable-endian.h:168`, `include/portable-endian.h:194`, `include/portable-endian.h:227`, `include/portable-endian.h:263`, `include/portable-endian.h:280`, `include/portable-endian.h:330`, `include/portable-endian.h:347`, `include/portable-endian.h:370`

### Requirement: htobe64 converts 64-bit host input to big-endian order
系统 MUST 为支持的平台提供 `htobe64(x)` 宏，使调用方可将 64 位 host-order 值编码为 big-endian 值。

#### Scenario: supported platform writes big-endian 64-bit value
- **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
- **WHEN** 调用方使用 `htobe64(x)` 写入 64 位 big-endian 协议字段
- **THEN** 宏展开 MUST 使用该平台的 64 位 byteswap、系统 endian API、`be64toh(x)` 代理或恒等表达式生成 big-endian 值

Trace: `include/portable-endian.h:36`, `include/portable-endian.h:55`, `include/portable-endian.h:126`, `include/portable-endian.h:148`, `include/portable-endian.h:166`, `include/portable-endian.h:192`, `include/portable-endian.h:225`, `include/portable-endian.h:261`, `include/portable-endian.h:278`, `include/portable-endian.h:328`, `include/portable-endian.h:345`, `include/portable-endian.h:368`

### Requirement: htole64 converts 64-bit host input to little-endian order
系统 MUST 为支持的平台提供 `htole64(x)` 宏，使调用方可将 64 位 host-order 值编码为 little-endian 值。

#### Scenario: supported platform writes little-endian 64-bit value
- **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
- **WHEN** 调用方使用 `htole64(x)` 写入 SMB、DCERPC 或 NTLM little-endian 64 位字段
- **THEN** 宏展开 MUST 在 little-endian 平台保持值不变，或在 big-endian 平台执行 64 位 byteswap

Trace: `include/portable-endian.h:37`, `include/portable-endian.h:56`, `include/portable-endian.h:127`, `include/portable-endian.h:149`, `include/portable-endian.h:167`, `include/portable-endian.h:193`, `include/portable-endian.h:226`, `include/portable-endian.h:262`, `include/portable-endian.h:279`, `include/portable-endian.h:329`, `include/portable-endian.h:346`, `include/portable-endian.h:369`

### Requirement: le64toh converts 64-bit little-endian input to host order
系统 MUST 为支持的平台提供 `le64toh(x)` 宏，使调用方可将 64 位 little-endian 值转换为 host-order 值。

#### Scenario: supported platform reads little-endian 64-bit value
- **GIVEN** 编译目标命中 `include/portable-endian.h` 中任一支持的平台分支
- **WHEN** 调用方使用 `le64toh(x)` 解析 SMB、DCERPC 或 NTLM little-endian 64 位字段
- **THEN** 宏展开 MUST 在 little-endian 平台保持值不变，或在 big-endian 平台执行 64 位 byteswap

Trace: `include/portable-endian.h:38`, `include/portable-endian.h:57`, `include/portable-endian.h:108`, `include/portable-endian.h:129`, `include/portable-endian.h:151`, `include/portable-endian.h:169`, `include/portable-endian.h:195`, `include/portable-endian.h:228`, `include/portable-endian.h:264`, `include/portable-endian.h:281`, `include/portable-endian.h:331`, `include/portable-endian.h:348`, `include/portable-endian.h:371`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | PS2/PICO 分支只在本头中显式定义 `htobe64`、`htole64` 和 `le64toh`，`be64toh` 依赖外部头或其他兼容层提供；需要确认所有 PS2/PICO 构建配置是否始终具备 `be64toh`。 | be64toh, htobe64 | 源码显示 `htobe64(x)` 代理到 `be64toh(x)`，但当前文件未在该分支定义 `be64toh`。 |
| Q-002 | Linux/BSD/GNU 分支只补齐 `be16toh`、`le16toh`、`be32toh`、`le32toh`、`be64toh` 和 `le64toh` 的缺失别名，未补齐 `htobe*`/`htole*`；需要确认目标系统头始终提供 host-to-endian 宏。 | htobe16, htole16, htobe32, htole32, htobe64, htole64 | 该分支依赖 `<endian.h>` 或 `<sys/endian.h>` 的平台定义，源码未提供 fallback。 |
| Q-003 | GitNexus `impact` 对关键 endian 宏返回 LOW 且 direct callers 为 0，但源码检索显示多个 C 文件包含本头并调用这些宏；需要确认 GitNexus 是否未建模宏调用者。 | file-level | GitNexus 宏上下文无 incoming/processes，源码 grep 存在直接使用。 |
