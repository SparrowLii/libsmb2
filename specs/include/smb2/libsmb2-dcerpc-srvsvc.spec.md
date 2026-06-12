# include/smb2/libsmb2-dcerpc-srvsvc.h Specification

## Source Context

- Source: `include/smb2/libsmb2-dcerpc-srvsvc.h`
- Related Headers: `include/smb2/libsmb2-dcerpc.h`, `include/smb2/libsmb2.h`, `include/smb2/libsmb2-raw.h`
- Related Tests: `examples/smb2-share-enum.c`, `examples/smb2-share-enum-sync.c`
- Related Dependencies: `lib/dcerpc-srvsvc.c`, `lib/smb2-share-enum.c`, `lib/sync.c`, `lib/libsmb2.syms`; GitNexus context found declarations but did not link header declarations to implementation callers; impact for implementation `smb2_share_enum_async` and `smb2_share_enum_sync` is LOW with direct example callers only.
- Build/Compile Context: C public header with `extern "C"` guards for C++ consumers; included by SRVSVC DCERPC implementation and share enumeration implementation; no source-level conditional declarations inside the header except the include guard and C++ linkage guard.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| SRVSVC_NETRSHAREENUM | macro | #define SRVSVC_NETRSHAREENUM      0x0f | Include | 对外暴露 SRVSVC NetrShareEnum DCERPC 操作号，调用方可观察。 |
| SRVSVC_NETRSHAREGETINFO | macro | #define SRVSVC_NETRSHAREGETINFO   0x10 | Include | 对外暴露 SRVSVC NetrShareGetInfo DCERPC 操作号，调用方可观察。 |
| SHARE_TYPE_DISKTREE | macro | #define SHARE_TYPE_DISKTREE  0 | Include | 对外暴露共享类型低位编码，影响 share info type 字段解释。 |
| SHARE_TYPE_PRINTQ | macro | #define SHARE_TYPE_PRINTQ    1 | Include | 对外暴露共享类型低位编码，影响 share info type 字段解释。 |
| SHARE_TYPE_DEVICE | macro | #define SHARE_TYPE_DEVICE    2 | Include | 对外暴露共享类型低位编码，影响 share info type 字段解释。 |
| SHARE_TYPE_IPC | macro | #define SHARE_TYPE_IPC       3 | Include | 对外暴露共享类型低位编码，影响 share info type 字段解释。 |
| SHARE_TYPE_TEMPORARY | macro | #define SHARE_TYPE_TEMPORARY 0x40000000 | Include | 对外暴露共享类型标志位，影响 share info type 字段解释。 |
| SHARE_TYPE_HIDDEN | macro | #define SHARE_TYPE_HIDDEN    0x80000000 | Include | 对外暴露共享类型标志位，影响 share info type 字段解释。 |
| SHARE_INFO_enum | type | enum SHARE_INFO_enum { SHARE_INFO_0 = 0, SHARE_INFO_1 = 1, }; | Include | 对外选择 share enum 响应级别，且被异步/同步 share enum API 使用。 |
| srvsvc_SHARE_INFO_0 | type | struct srvsvc_SHARE_INFO_0 { struct dcerpc_utf16 netname; }; | Include | 对外承载 level 0 share 枚举结果数据模型。 |
| srvsvc_SHARE_INFO_0_coder | function | int srvsvc_SHARE_INFO_0_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 对外导出编码器声明，承载 UTF-16 share 名称 DCERPC 编解码契约。 |
| srvsvc_SHARE_INFO_0_CONTAINER | type | struct srvsvc_SHARE_INFO_0_CONTAINER { uint32_t EntriesRead; struct srvsvc_SHARE_INFO_0 *share_info_0; }; | Include | 对外承载 level 0 share 数组及计数。 |
| srvsvc_SHARE_INFO_1 | type | struct srvsvc_SHARE_INFO_1 { struct dcerpc_utf16 netname; uint32_t type; struct dcerpc_utf16 remark; }; | Include | 对外承载 level 1 share 枚举结果数据模型。 |
| srvsvc_SHARE_INFO_1_coder | function | int srvsvc_SHARE_INFO_1_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 对外导出编码器声明，承载 level 1 share 名称、类型和备注 DCERPC 编解码契约。 |
| srvsvc_SHARE_INFO_1_CONTAINER | type | struct srvsvc_SHARE_INFO_1_CONTAINER { uint32_t EntriesRead; struct srvsvc_SHARE_INFO_1 *share_info_1; }; | Include | 对外承载 level 1 share 数组及计数。 |
| srvsvc_SHARE_INFO_1_CONTAINER_coder | function | int srvsvc_SHARE_INFO_1_CONTAINER_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 对外导出容器编码器声明，解码时负责 EntriesRead 驱动的数组分配。 |
| srvsvc_SHARE_ENUM_UNION | type | struct srvsvc_SHARE_ENUM_UNION { uint32_t Level; union { struct srvsvc_SHARE_INFO_0_CONTAINER Level0; struct srvsvc_SHARE_INFO_1_CONTAINER Level1; }; }; | Include | 对外承载 level 分派的 share enum union。 |
| srvsvc_SHARE_ENUM_STRUCT | type | struct srvsvc_SHARE_ENUM_STRUCT { uint32_t Level; struct srvsvc_SHARE_ENUM_UNION ShareInfo; }; | Include | 对外承载 NetrShareEnum 请求和响应中的 share enum 结构。 |
| srvsvc_NetrShareEnum_req | type | struct srvsvc_NetrShareEnum_req { struct dcerpc_utf16 ServerName; struct srvsvc_SHARE_ENUM_STRUCT ses; uint32_t PreferedMaximumLength; uint32_t ResumeHandle; }; | Include | 对外定义 NetrShareEnum 请求载荷。 |
| srvsvc_NetrShareEnum_rep | type | struct srvsvc_NetrShareEnum_rep { uint32_t status; struct srvsvc_SHARE_ENUM_STRUCT ses; uint32_t total_entries; uint32_t resume_handle; }; | Include | 对外定义 NetrShareEnum 响应载荷和状态。 |
| srvsvc_SHARE_INFO | type | struct srvsvc_SHARE_INFO { uint32_t level; union { struct srvsvc_SHARE_INFO_1 ShareInfo1; }; }; | Include | 对外承载 NetrShareGetInfo 响应的 level 分派 share 信息。 |
| srvsvc_NetrShareGetInfo_req | type | struct srvsvc_NetrShareGetInfo_req { struct dcerpc_utf16 ServerName; struct dcerpc_utf16 NetName; uint32_t Level; }; | Include | 对外定义 NetrShareGetInfo 请求载荷。 |
| srvsvc_NetrShareGetInfo_rep | type | struct srvsvc_NetrShareGetInfo_rep { uint32_t status; struct srvsvc_SHARE_INFO InfoStruct; }; | Include | 对外定义 NetrShareGetInfo 响应载荷和状态。 |
| srvsvc_rep | type | struct srvsvc_rep { uint32_t status; }; | Include | 对外定义通用 SRVSVC 状态响应。 |
| smb2_share_enum_async | function | int smb2_share_enum_async(struct smb2_context *smb2, enum SHARE_INFO_enum level, smb2_command_cb cb, void *cb_data); | Include | 对外异步 share 枚举 API，错误和回调语义在头文件注释中明确。 |
| smb2_share_enum_sync | function | struct srvsvc_NetrShareEnum_rep * smb2_share_enum_sync(struct smb2_context *smb2, enum SHARE_INFO_enum level); | Include | 对外同步 share 枚举 API，返回所有权在头文件注释中明确。 |
| srvsvc_NetrShareEnum_rep_coder | function | int srvsvc_NetrShareEnum_rep_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 对外导出 NetrShareEnum 响应编码器，供 DCERPC 调用路径使用。 |
| srvsvc_NetrShareEnum_req_coder | function | int srvsvc_NetrShareEnum_req_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 对外导出 NetrShareEnum 请求编码器，供 DCERPC 调用路径使用。 |
| srvsvc_NetrShareGetInfo_rep_coder | function | int srvsvc_NetrShareGetInfo_rep_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 对外导出 NetrShareGetInfo 响应编码器。 |
| srvsvc_NetrShareGetInfo_req_coder | function | int srvsvc_NetrShareGetInfo_req_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 对外导出 NetrShareGetInfo 请求编码器。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SRVSVC_NETRSHAREENUM | macro | include/smb2/libsmb2-dcerpc-srvsvc.h:28 | SRVSVC NetrShareEnum 操作号为 `0x0f`。 |
| SRVSVC_NETRSHAREGETINFO | macro | include/smb2/libsmb2-dcerpc-srvsvc.h:29 | SRVSVC NetrShareGetInfo 操作号为 `0x10`。 |
| SHARE_TYPE_DISKTREE | macro | include/smb2/libsmb2-dcerpc-srvsvc.h:36 | 共享类型低 2 位磁盘树编码。 |
| SHARE_TYPE_PRINTQ | macro | include/smb2/libsmb2-dcerpc-srvsvc.h:37 | 共享类型低 2 位打印队列编码。 |
| SHARE_TYPE_DEVICE | macro | include/smb2/libsmb2-dcerpc-srvsvc.h:38 | 共享类型低 2 位设备编码。 |
| SHARE_TYPE_IPC | macro | include/smb2/libsmb2-dcerpc-srvsvc.h:39 | 共享类型低 2 位 IPC 编码。 |
| SHARE_TYPE_TEMPORARY | macro | include/smb2/libsmb2-dcerpc-srvsvc.h:41 | 临时共享标志位。 |
| SHARE_TYPE_HIDDEN | macro | include/smb2/libsmb2-dcerpc-srvsvc.h:42 | 隐藏共享标志位。 |
| SHARE_INFO_enum | enum | include/smb2/libsmb2-dcerpc-srvsvc.h:44 | 仅声明 level 0 和 level 1。 |
| srvsvc_SHARE_INFO_0 | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:49 | 包含 `netname` UTF-16 字段。 |
| srvsvc_SHARE_INFO_0_CONTAINER | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:57 | 包含 `EntriesRead` 和 `share_info_0` 数组指针。 |
| srvsvc_SHARE_INFO_1 | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:62 | 包含 `netname`、`type` 和 `remark`。 |
| srvsvc_SHARE_INFO_1_CONTAINER | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:72 | 包含 `EntriesRead` 和 `share_info_1` 数组指针。 |
| srvsvc_SHARE_ENUM_UNION | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:82 | 通过 `Level` 选择 `Level0` 或 `Level1`。 |
| srvsvc_SHARE_ENUM_STRUCT | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:90 | 封装 share enum level 和 union。 |
| srvsvc_NetrShareEnum_req | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:95 | 请求包含 server、枚举结构、最大长度和 resume handle。 |
| srvsvc_NetrShareEnum_rep | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:102 | 响应包含 status、枚举结构、总数和 resume handle。 |
| srvsvc_SHARE_INFO | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:110 | 目前仅声明 `ShareInfo1` union 成员。 |
| srvsvc_NetrShareGetInfo_req | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:117 | 请求包含 server、share 名称和 level。 |
| srvsvc_NetrShareGetInfo_rep | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:123 | 响应包含 status 和 info struct。 |
| srvsvc_rep | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:129 | 通用 32 位 status 响应。 |

## ADDED Requirements

### Requirement: SRVSVC_NETRSHAREENUM operation number
系统 MUST 将 `SRVSVC_NETRSHAREENUM` 暴露为值 `0x0f`，用于发起 NetrShareEnum DCERPC 调用。

#### Scenario: NetrShareEnum opcode is stable
- **GIVEN** 调用方包含 `include/smb2/libsmb2-dcerpc-srvsvc.h`
- **WHEN** 调用方读取 `SRVSVC_NETRSHAREENUM`
- **THEN** 该宏展开结果为 `0x0f`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SRVSVC_NETRSHAREENUM`, `lib/smb2-share-enum.c:share_enum_bind_cb`

### Requirement: SRVSVC_NETRSHAREGETINFO operation number
系统 MUST 将 `SRVSVC_NETRSHAREGETINFO` 暴露为值 `0x10`，用于 NetrShareGetInfo DCERPC 调用。

#### Scenario: NetrShareGetInfo opcode is stable
- **GIVEN** 调用方包含 `include/smb2/libsmb2-dcerpc-srvsvc.h`
- **WHEN** 调用方读取 `SRVSVC_NETRSHAREGETINFO`
- **THEN** 该宏展开结果为 `0x10`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SRVSVC_NETRSHAREGETINFO`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_req_coder`

### Requirement: SHARE_TYPE_DISKTREE share type code
系统 MUST 将 `SHARE_TYPE_DISKTREE` 暴露为值 `0`，表示共享类型低 2 位中的磁盘树共享。

#### Scenario: Disk tree share type is encoded as zero
- **GIVEN** 调用方处理 `srvsvc_SHARE_INFO_1.type`
- **WHEN** 调用方比较 `SHARE_TYPE_DISKTREE`
- **THEN** 该宏值为 `0`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_TYPE_DISKTREE`

### Requirement: SHARE_TYPE_PRINTQ share type code
系统 MUST 将 `SHARE_TYPE_PRINTQ` 暴露为值 `1`，表示共享类型低 2 位中的打印队列共享。

#### Scenario: Print queue share type is encoded as one
- **GIVEN** 调用方处理 `srvsvc_SHARE_INFO_1.type`
- **WHEN** 调用方比较 `SHARE_TYPE_PRINTQ`
- **THEN** 该宏值为 `1`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_TYPE_PRINTQ`

### Requirement: SHARE_TYPE_DEVICE share type code
系统 MUST 将 `SHARE_TYPE_DEVICE` 暴露为值 `2`，表示共享类型低 2 位中的设备共享。

#### Scenario: Device share type is encoded as two
- **GIVEN** 调用方处理 `srvsvc_SHARE_INFO_1.type`
- **WHEN** 调用方比较 `SHARE_TYPE_DEVICE`
- **THEN** 该宏值为 `2`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_TYPE_DEVICE`

### Requirement: SHARE_TYPE_IPC share type code
系统 MUST 将 `SHARE_TYPE_IPC` 暴露为值 `3`，表示共享类型低 2 位中的 IPC 共享。

#### Scenario: IPC share type is encoded as three
- **GIVEN** 调用方处理 `srvsvc_SHARE_INFO_1.type`
- **WHEN** 调用方比较 `SHARE_TYPE_IPC`
- **THEN** 该宏值为 `3`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_TYPE_IPC`

### Requirement: SHARE_TYPE_TEMPORARY share type flag
系统 MUST 将 `SHARE_TYPE_TEMPORARY` 暴露为值 `0x40000000`，表示共享类型中的临时共享标志位。

#### Scenario: Temporary share flag is stable
- **GIVEN** 调用方处理 `srvsvc_SHARE_INFO_1.type`
- **WHEN** 调用方测试 `SHARE_TYPE_TEMPORARY`
- **THEN** 该宏值为 `0x40000000`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_TYPE_TEMPORARY`

### Requirement: SHARE_TYPE_HIDDEN share type flag
系统 MUST 将 `SHARE_TYPE_HIDDEN` 暴露为值 `0x80000000`，表示共享类型中的隐藏共享标志位。

#### Scenario: Hidden share flag is stable
- **GIVEN** 调用方处理 `srvsvc_SHARE_INFO_1.type`
- **WHEN** 调用方测试 `SHARE_TYPE_HIDDEN`
- **THEN** 该宏值为 `0x80000000`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_TYPE_HIDDEN`

### Requirement: SHARE_INFO_enum supported levels
系统 MUST 仅在该枚举中声明 `SHARE_INFO_0` 为 `0`、`SHARE_INFO_1` 为 `1`，并由 share enum API 使用该枚举选择响应结构级别。

#### Scenario: Share enum levels map to declared numeric values
- **GIVEN** 调用方调用 share enum API
- **WHEN** 调用方传入 `SHARE_INFO_0` 或 `SHARE_INFO_1`
- **THEN** `SHARE_INFO_0` 值为 `0` 且 `SHARE_INFO_1` 值为 `1`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:SHARE_INFO_enum`, `lib/smb2-share-enum.c:smb2_share_enum_async`

### Requirement: srvsvc_SHARE_INFO_0 level zero record layout
系统 MUST 将 `srvsvc_SHARE_INFO_0` 暴露为只包含 `struct dcerpc_utf16 netname` 的 level 0 share 记录。

#### Scenario: Level zero record carries share name
- **GIVEN** 调用方接收 `srvsvc_SHARE_INFO_0`
- **WHEN** 调用方读取该结构
- **THEN** 调用方可以通过 `netname` 获取 share 名称字段

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_INFO_0`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_0_coder`

### Requirement: srvsvc_SHARE_INFO_0_coder level zero coder
系统 MUST 通过 `srvsvc_SHARE_INFO_0_coder` 编解码 `srvsvc_SHARE_INFO_0.netname` 字段，并在底层 UTF-16 指针编码失败时返回 `-1`。

#### Scenario: Level zero coder propagates UTF-16 coder failure
- **GIVEN** `ptr` 指向 `srvsvc_SHARE_INFO_0` 且底层 `dcerpc_ptr_coder` 返回错误
- **WHEN** 调用方执行 `srvsvc_SHARE_INFO_0_coder`
- **THEN** 该函数返回 `-1`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_INFO_0_coder`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_0_coder`

### Requirement: srvsvc_SHARE_INFO_0_CONTAINER level zero container layout
系统 MUST 将 `srvsvc_SHARE_INFO_0_CONTAINER` 暴露为包含 `EntriesRead` 计数和 `share_info_0` 数组指针的 level 0 容器。

#### Scenario: Level zero container carries count and buffer
- **GIVEN** 调用方接收 level 0 share enum 响应
- **WHEN** 调用方读取 `srvsvc_SHARE_INFO_0_CONTAINER`
- **THEN** `EntriesRead` 表示条目数量且 `share_info_0` 指向对应记录数组

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_INFO_0_CONTAINER`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_0_CONTAINER_coder`

### Requirement: srvsvc_SHARE_INFO_1 level one record layout
系统 MUST 将 `srvsvc_SHARE_INFO_1` 暴露为包含 `netname`、`type` 和 `remark` 的 level 1 share 记录。

#### Scenario: Level one record carries name type and remark
- **GIVEN** 调用方接收 `srvsvc_SHARE_INFO_1`
- **WHEN** 调用方读取该结构
- **THEN** 调用方可以访问 share 名称、类型和备注字段

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_INFO_1`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_coder`

### Requirement: srvsvc_SHARE_INFO_1_coder level one coder
系统 MUST 通过 `srvsvc_SHARE_INFO_1_coder` 按 `netname`、`type`、`remark` 顺序编解码 level 1 share 记录，并在任一字段编解码失败时返回 `-1`。

#### Scenario: Level one coder propagates field coder failure
- **GIVEN** `ptr` 指向 `srvsvc_SHARE_INFO_1` 且任一底层字段 coder 返回错误
- **WHEN** 调用方执行 `srvsvc_SHARE_INFO_1_coder`
- **THEN** 该函数返回 `-1`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_INFO_1_coder`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_coder`

### Requirement: srvsvc_SHARE_INFO_1_CONTAINER level one container layout
系统 MUST 将 `srvsvc_SHARE_INFO_1_CONTAINER` 暴露为包含 `EntriesRead` 计数和 `share_info_1` 数组指针的 level 1 容器。

#### Scenario: Level one container carries count and buffer
- **GIVEN** 调用方接收 level 1 share enum 响应
- **WHEN** 调用方读取 `srvsvc_SHARE_INFO_1_CONTAINER`
- **THEN** `EntriesRead` 表示条目数量且 `share_info_1` 指向对应记录数组

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_INFO_1_CONTAINER`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_CONTAINER_coder`

### Requirement: srvsvc_SHARE_INFO_1_CONTAINER_coder level one container coder
系统 MUST 在解码且 `EntriesRead` 非零时使用 `EntriesRead * sizeof(struct srvsvc_SHARE_INFO_1)` 为缺失的 `share_info_1` 数组分配数据，并在分配或底层编码失败时返回 `-1`。

#### Scenario: Level one container decoder allocates missing array
- **GIVEN** DCERPC 方向为 decode、`EntriesRead` 非零且 `share_info_1` 为 `NULL`
- **WHEN** 调用方执行 `srvsvc_SHARE_INFO_1_CONTAINER_coder`
- **THEN** 该函数尝试分配 level 1 数组并在分配失败时返回 `-1`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_INFO_1_CONTAINER_coder`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_CONTAINER_coder`

### Requirement: srvsvc_SHARE_ENUM_UNION level selected union
系统 MUST 将 `srvsvc_SHARE_ENUM_UNION` 暴露为由 `Level` 选择 `Level0` 或 `Level1` 容器的 share enum union。

#### Scenario: Share enum union exposes level-specific containers
- **GIVEN** 调用方接收 `srvsvc_SHARE_ENUM_UNION`
- **WHEN** `Level` 为 `0` 或 `1`
- **THEN** 调用方可以分别通过 `Level0` 或 `Level1` 访问对应容器

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_ENUM_UNION`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_ENUM_UNION_coder`

### Requirement: srvsvc_SHARE_ENUM_STRUCT share enum wrapper
系统 MUST 将 `srvsvc_SHARE_ENUM_STRUCT` 暴露为包含顶层 `Level` 和 `ShareInfo` union 的 NetrShareEnum 结构。

#### Scenario: Share enum struct carries level and union
- **GIVEN** 调用方处理 NetrShareEnum 请求或响应
- **WHEN** 调用方读取 `srvsvc_SHARE_ENUM_STRUCT`
- **THEN** 调用方可以读取 `Level` 并通过 `ShareInfo` 访问 level 对应数据

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_ENUM_STRUCT`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_ENUM_STRUCT_coder`

### Requirement: srvsvc_NetrShareEnum_req request layout
系统 MUST 将 `srvsvc_NetrShareEnum_req` 暴露为包含 `ServerName`、`ses`、`PreferedMaximumLength` 和 `ResumeHandle` 的 NetrShareEnum 请求结构。

#### Scenario: NetrShareEnum request carries server and paging fields
- **GIVEN** 调用方准备 NetrShareEnum 请求
- **WHEN** 调用方填充 `srvsvc_NetrShareEnum_req`
- **THEN** 请求结构提供 server 名称、share enum 结构、最大长度和 resume handle 字段

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_NetrShareEnum_req`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_req_coder`

### Requirement: srvsvc_NetrShareEnum_rep response layout
系统 MUST 将 `srvsvc_NetrShareEnum_rep` 暴露为包含 `status`、`ses`、`total_entries` 和 `resume_handle` 的 NetrShareEnum 响应结构。

#### Scenario: NetrShareEnum response carries status and enumeration data
- **GIVEN** share enum 操作完成并返回响应
- **WHEN** 调用方读取 `srvsvc_NetrShareEnum_rep`
- **THEN** 调用方可以读取状态、share enum 数据、总条目数和 resume handle

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_NetrShareEnum_rep`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_rep_coder`

### Requirement: srvsvc_SHARE_INFO getinfo union layout
系统 MUST 将 `srvsvc_SHARE_INFO` 暴露为包含 `level` 和当前 `ShareInfo1` 成员的 NetrShareGetInfo 响应 union 结构。

#### Scenario: GetInfo share info carries level one data
- **GIVEN** 调用方接收 `srvsvc_SHARE_INFO`
- **WHEN** `level` 为 `1`
- **THEN** 调用方可以通过 `ShareInfo1` 访问 level 1 share 信息

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_SHARE_INFO`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_coder`

### Requirement: srvsvc_NetrShareGetInfo_req request layout
系统 MUST 将 `srvsvc_NetrShareGetInfo_req` 暴露为包含 `ServerName`、`NetName` 和 `Level` 的 NetrShareGetInfo 请求结构。

#### Scenario: NetrShareGetInfo request carries target share
- **GIVEN** 调用方准备 NetrShareGetInfo 请求
- **WHEN** 调用方填充 `srvsvc_NetrShareGetInfo_req`
- **THEN** 请求结构提供 server 名称、share 名称和请求 level 字段

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_NetrShareGetInfo_req`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_req_coder`

### Requirement: srvsvc_NetrShareGetInfo_rep response layout
系统 MUST 将 `srvsvc_NetrShareGetInfo_rep` 暴露为包含 `status` 和 `InfoStruct` 的 NetrShareGetInfo 响应结构。

#### Scenario: NetrShareGetInfo response carries status and info
- **GIVEN** NetrShareGetInfo 操作完成并返回响应
- **WHEN** 调用方读取 `srvsvc_NetrShareGetInfo_rep`
- **THEN** 调用方可以读取状态和 level 分派的 share 信息

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_NetrShareGetInfo_rep`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_rep_coder`

### Requirement: srvsvc_rep generic status response
系统 MUST 将 `srvsvc_rep` 暴露为只包含 32 位 `status` 字段的通用 SRVSVC 响应结构。

#### Scenario: Generic SRVSVC response carries status
- **GIVEN** 调用方接收通用 SRVSVC 响应
- **WHEN** 调用方读取 `srvsvc_rep`
- **THEN** 调用方可以通过 `status` 获取 32 位响应状态

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_rep`, `lib/smb2-share-enum.c:srvsvc_ioctl_cb`

### Requirement: smb2_share_enum_async asynchronous share enumeration
系统 MUST 在连接到 `IPC$` share 时通过 `smb2_share_enum_async` 发起异步 share enum 操作；成功发起时返回 `0` 并通过回调报告结果，发起失败时返回负 errno 且 SHALL NOT 调用回调。

#### Scenario: Async share enum starts and reports through callback
- **GIVEN** `smb2` 已连接到 `IPC$` share 且资源分配成功
- **WHEN** 调用方执行 `smb2_share_enum_async` 并传入 callback
- **THEN** 函数返回 `0`，操作结果随后通过 callback 的 `status` 和 `command_data` 报告

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_async`, `lib/smb2-share-enum.c:smb2_share_enum_async`, `examples/smb2-share-enum.c:main`

#### Scenario: Async share enum initiation failure suppresses callback
- **GIVEN** `dcerpc_create_context` 或后续资源分配失败
- **WHEN** 调用方执行 `smb2_share_enum_async`
- **THEN** 函数返回负 errno，且回调不会被调用

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_async`, `lib/smb2-share-enum.c:smb2_share_enum_async`

### Requirement: smb2_share_enum_sync synchronous share enumeration
系统 MUST 在连接到 `IPC$` share 时通过 `smb2_share_enum_sync` 同步返回 `struct srvsvc_NetrShareEnum_rep *`；失败时 MUST 返回 `NULL`，成功返回的指针 MUST 由调用方使用 `smb2_free_data()` 释放。

#### Scenario: Sync share enum returns response pointer on success
- **GIVEN** `smb2` 已连接且异步 share enum 与等待回复均成功
- **WHEN** 调用方执行 `smb2_share_enum_sync`
- **THEN** 函数返回非 `NULL` 的 `struct srvsvc_NetrShareEnum_rep *`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_sync`, `lib/sync.c:smb2_share_enum_sync`, `examples/smb2-share-enum-sync.c:main`

#### Scenario: Sync share enum fails before or during wait
- **GIVEN** `smb2` 未连接或异步发起/等待回复失败
- **WHEN** 调用方执行 `smb2_share_enum_sync`
- **THEN** 函数返回 `NULL`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_sync`, `lib/sync.c:smb2_share_enum_sync`

### Requirement: srvsvc_NetrShareEnum_rep_coder response coder
系统 MUST 通过 `srvsvc_NetrShareEnum_rep_coder` 按 `ses`、`total_entries`、`resume_handle`、`status` 顺序编解码 NetrShareEnum 响应，并在任一字段编解码失败时返回 `-1`。

#### Scenario: NetrShareEnum response coder propagates field failures
- **GIVEN** `ptr` 指向 `srvsvc_NetrShareEnum_rep` 且任一底层字段 coder 返回错误
- **WHEN** 调用方执行 `srvsvc_NetrShareEnum_rep_coder`
- **THEN** 该函数返回 `-1`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_NetrShareEnum_rep_coder`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_rep_coder`

### Requirement: srvsvc_NetrShareEnum_req_coder request coder
系统 MUST 通过 `srvsvc_NetrShareEnum_req_coder` 按 `ServerName`、`ses`、`PreferedMaximumLength`、`ResumeHandle` 顺序编解码 NetrShareEnum 请求，并在任一字段编解码失败时返回 `-1`。

#### Scenario: NetrShareEnum request coder propagates field failures
- **GIVEN** `ptr` 指向 `srvsvc_NetrShareEnum_req` 且任一底层字段 coder 返回错误
- **WHEN** 调用方执行 `srvsvc_NetrShareEnum_req_coder`
- **THEN** 该函数返回 `-1`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_NetrShareEnum_req_coder`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_req_coder`

### Requirement: srvsvc_NetrShareGetInfo_rep_coder response coder
系统 MUST 通过 `srvsvc_NetrShareGetInfo_rep_coder` 按 `InfoStruct`、`status` 顺序编解码 NetrShareGetInfo 响应，并在任一字段编解码失败时返回 `-1`。

#### Scenario: NetrShareGetInfo response coder propagates field failures
- **GIVEN** `ptr` 指向 `srvsvc_NetrShareGetInfo_rep` 且任一底层字段 coder 返回错误
- **WHEN** 调用方执行 `srvsvc_NetrShareGetInfo_rep_coder`
- **THEN** 该函数返回 `-1`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_NetrShareGetInfo_rep_coder`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_rep_coder`

### Requirement: srvsvc_NetrShareGetInfo_req_coder request coder
系统 MUST 通过 `srvsvc_NetrShareGetInfo_req_coder` 按 `ServerName`、`NetName`、`Level` 顺序编解码 NetrShareGetInfo 请求，并在任一字段编解码失败时返回 `-1`。

#### Scenario: NetrShareGetInfo request coder propagates field failures
- **GIVEN** `ptr` 指向 `srvsvc_NetrShareGetInfo_req` 且任一底层字段 coder 返回错误
- **WHEN** 调用方执行 `srvsvc_NetrShareGetInfo_req_coder`
- **THEN** 该函数返回 `-1`

Trace: `include/smb2/libsmb2-dcerpc-srvsvc.h:srvsvc_NetrShareGetInfo_req_coder`, `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_req_coder`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_share_enum_async` 对 `level` 非 `SHARE_INFO_0` 或 `SHARE_INFO_1` 时的请求结构初始化语义是否为受支持行为？ | smb2_share_enum_async | 源码 switch 没有 default 分支，头文件未声明非法 level 错误语义。 |
| Q-002 | `srvsvc_SHARE_INFO_0_CONTAINER_coder` 未在头文件声明但实现和 level 0 union coder 使用，是否应作为公开导出接口补入头文件或保持内部接口？ | srvsvc_SHARE_INFO_0_CONTAINER_coder | 实现存在非 static 函数，但 header 仅声明 level 1 container coder。 |
