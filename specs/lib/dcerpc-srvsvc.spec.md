# lib/dcerpc-srvsvc.c Specification

## Source Context

- Source: `lib/dcerpc-srvsvc.c`
- Related Headers: `include/smb2/libsmb2-dcerpc-srvsvc.h`, `include/smb2/libsmb2-dcerpc.h`, `include/smb2/libsmb2.h`, `include/smb2/libsmb2-raw.h`, `include/smb2/smb2.h`, `include/smb2/libsmb2-private.h`
- Related Tests: `tests/smb2-dcerpc-coder-test.c`
- Related Dependencies: GitNexus context shows SRVSVC coder functions calling `dcerpc_ptr_coder`, `dcerpc_uint32_coder`, `dcerpc_uint3264_coder`, `dcerpc_pdu_direction`, `dcerpc_set_size_is`, `dcerpc_get_size_is`, `dcerpc_carray_coder`, `dcerpc_utf16z_coder`, `smb2_alloc_data`, `dcerpc_get_smb2_context`, and `dcerpc_get_pdu_payload`; impact for `srvsvc_NetrShareEnum_req_coder` was ambiguous between header and implementation declarations.
- Build/Compile Context: C implementation compiled into the core `smb2` library; optional includes are controlled by `HAVE_CONFIG_H`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_SYS_TYPES_H`, `HAVE_SYS_STAT_H`, `HAVE_UNISTD_H`, and `HAVE_SYS_UNISTD_H`; the file defines `_GNU_SOURCE` when absent.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| SRVSVC_UUID | macro | #define SRVSVC_UUID    0x4b324fc8, 0x1670, 0x01d3, {0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88} | Include | 定义 SRVSVC 接口 UUID，影响对外 DCERPC 绑定语法标识。 |
| dcerpc_get_cr | function | int dcerpc_get_cr(struct dcerpc_pdu *pdu); | Skip | 外部函数前置声明，本文件未实现，行为归属到其实现文件。 |
| srvsvc_interface | variable | p_syntax_id_t srvsvc_interface = { {SRVSVC_UUID}, 3, 0 }; | Include | 对外提供 SRVSVC DCERPC syntax id，供绑定流程观察接口 UUID 和版本。 |
| srvsvc_SHARE_INFO_0_coder | function | int srvsvc_SHARE_INFO_0_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 非 static coder，编码/解码 level 0 share 名称并传播底层失败。 |
| srvsvc_SHARE_INFO_0_carray_coder | function | static int srvsvc_SHARE_INFO_0_carray_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Skip | 纯内部数组 helper，仅由本文件 level 0 container coder 调用。 |
| srvsvc_SHARE_INFO_0_CONTAINER_coder | function | int srvsvc_SHARE_INFO_0_CONTAINER_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 非 static coder，解码时按 `EntriesRead` 分配 level 0 数组并传播失败。 |
| srvsvc_SHARE_INFO_1_coder | function | int srvsvc_SHARE_INFO_1_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 非 static coder，编码/解码 level 1 share 名称、类型和备注；测试覆盖 NDR32。 |
| srvsvc_SHARE_INFO_1_carray_coder | function | static int srvsvc_SHARE_INFO_1_carray_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Skip | 纯内部数组 helper，仅由本文件 level 1 container coder 调用。 |
| srvsvc_SHARE_INFO_1_CONTAINER_coder | function | int srvsvc_SHARE_INFO_1_CONTAINER_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 非 static coder，解码时按 `EntriesRead` 分配 level 1 数组；测试覆盖 NDR32 和 NDR64。 |
| srvsvc_SHARE_ENUM_UNION_coder | function | static int srvsvc_SHARE_ENUM_UNION_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Skip | static level switch helper，无独立外部调用入口。 |
| srvsvc_SHARE_ENUM_STRUCT_coder | function | int srvsvc_SHARE_ENUM_STRUCT_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 非 static coder，编码/解码 NetrShareEnum 顶层 level 和 union。 |
| srvsvc_NetrShareEnum_req_coder | function | int srvsvc_NetrShareEnum_req_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 头文件声明的 NetrShareEnum 请求 coder，供 DCERPC ioctl 请求路径使用。 |
| srvsvc_NetrShareEnum_rep_coder | function | int srvsvc_NetrShareEnum_rep_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 头文件声明的 NetrShareEnum 响应 coder，供 DCERPC ioctl 响应路径使用。 |
| srvsvc_SHARE_INFO_coder | function | static int srvsvc_SHARE_INFO_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Skip | static NetrShareGetInfo union helper，仅由响应 coder 调用。 |
| srvsvc_NetrShareGetInfo_req_coder | function | int srvsvc_NetrShareGetInfo_req_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 头文件声明的 NetrShareGetInfo 请求 coder，编码 server、share 名称和 level。 |
| srvsvc_NetrShareGetInfo_rep_coder | function | int srvsvc_NetrShareGetInfo_rep_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 头文件声明的 NetrShareGetInfo 响应 coder，编码 info struct 和 status。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SRVSVC_UUID | macro | lib/dcerpc-srvsvc.c:70 | SRVSVC interface UUID initializer `4b324fc8-1670-01d3-1278-5a47bf6ee188`。 |
| srvsvc_interface | variable | lib/dcerpc-srvsvc.c:74 | 使用 `SRVSVC_UUID` 且版本为 `3.0` 的 `p_syntax_id_t`。 |
| srvsvc_SHARE_INFO_0 | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:49 | level 0 share record，字段由本文件 coder 编解码。 |
| srvsvc_SHARE_INFO_0_CONTAINER | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:57 | level 0 share 数组计数和指针容器。 |
| srvsvc_SHARE_INFO_1 | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:62 | level 1 share record，包含 name、type、remark。 |
| srvsvc_SHARE_INFO_1_CONTAINER | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:72 | level 1 share 数组计数和指针容器。 |
| srvsvc_SHARE_ENUM_UNION | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:82 | 使用 level 选择 level 0 或 level 1 容器。 |
| srvsvc_SHARE_ENUM_STRUCT | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:90 | NetrShareEnum 顶层 level 和 union 包装。 |
| srvsvc_NetrShareEnum_req | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:95 | NetrShareEnum 请求载荷。 |
| srvsvc_NetrShareEnum_rep | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:102 | NetrShareEnum 响应载荷。 |
| srvsvc_SHARE_INFO | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:110 | NetrShareGetInfo level 分派响应信息。 |
| srvsvc_NetrShareGetInfo_req | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:117 | NetrShareGetInfo 请求载荷。 |
| srvsvc_NetrShareGetInfo_rep | struct | include/smb2/libsmb2-dcerpc-srvsvc.h:123 | NetrShareGetInfo 响应载荷。 |

## ADDED Requirements

### Requirement: SRVSVC_UUID interface uuid initializer
系统 MUST 将 `SRVSVC_UUID` 定义为 SRVSVC DCERPC interface UUID initializer `0x4b324fc8, 0x1670, 0x01d3, {0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88}`。

#### Scenario: SRVSVC UUID feeds syntax id
- **GIVEN** 本文件初始化 `srvsvc_interface`
- **WHEN** 编译器展开 `SRVSVC_UUID`
- **THEN** `srvsvc_interface` 使用该 UUID initializer 作为 syntax id 的 UUID 字段

Trace: `lib/dcerpc-srvsvc.c:SRVSVC_UUID`, `lib/dcerpc-srvsvc.c:srvsvc_interface`

### Requirement: srvsvc_interface syntax identifier
系统 MUST 暴露 `srvsvc_interface` 为包含 SRVSVC UUID、major version `3` 和 minor version `0` 的 `p_syntax_id_t` 值。

#### Scenario: SRVSVC interface version remains stable
- **GIVEN** DCERPC 绑定路径引用 `srvsvc_interface`
- **WHEN** 调用方读取该 syntax id
- **THEN** UUID 来自 `SRVSVC_UUID` 且版本字段为 `3, 0`

Trace: `lib/dcerpc-srvsvc.c:srvsvc_interface`

### Requirement: srvsvc_SHARE_INFO_0_coder level zero record coder
系统 MUST 通过 `srvsvc_SHARE_INFO_0_coder` 使用 `PTR_UNIQUE` 和 `dcerpc_utf16z_coder` 编解码 `srvsvc_SHARE_INFO_0.netname`，并在底层指针 coder 失败时返回 `-1`。

#### Scenario: Level zero netname coder succeeds
- **GIVEN** `ptr` 指向有效的 `struct srvsvc_SHARE_INFO_0`
- **WHEN** `dcerpc_ptr_coder` 成功编解码 `netname`
- **THEN** `srvsvc_SHARE_INFO_0_coder` 返回 `0`

Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_0_coder`

#### Scenario: Level zero netname coder failure propagates
- **GIVEN** `ptr` 指向 `struct srvsvc_SHARE_INFO_0` 且底层 `dcerpc_ptr_coder` 返回错误
- **WHEN** 调用方执行 `srvsvc_SHARE_INFO_0_coder`
- **THEN** `srvsvc_SHARE_INFO_0_coder` 返回 `-1`

Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_0_coder`

### Requirement: srvsvc_SHARE_INFO_0_CONTAINER_coder level zero container coder
系统 MUST 通过 `srvsvc_SHARE_INFO_0_CONTAINER_coder` 先编解码 `EntriesRead`，在 decode 且 `EntriesRead` 非零时设置 DCERPC `size_is`，并在 `share_info_0` 为空时按 `EntriesRead * sizeof(struct srvsvc_SHARE_INFO_0)` 分配数组。

#### Scenario: Level zero decode allocates missing array
- **GIVEN** DCERPC PDU 方向为 decode、`EntriesRead` 非零且 `share_info_0` 为 `NULL`
- **WHEN** 调用方执行 `srvsvc_SHARE_INFO_0_CONTAINER_coder`
- **THEN** coder 设置 `size_is` 并尝试从 PDU payload 关联的数据区域分配 level 0 数组

Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_0_CONTAINER_coder`

#### Scenario: Level zero container failure propagates
- **GIVEN** `EntriesRead` coder、数组分配或后续 unique pointer coder 任一操作失败
- **WHEN** 调用方执行 `srvsvc_SHARE_INFO_0_CONTAINER_coder`
- **THEN** `srvsvc_SHARE_INFO_0_CONTAINER_coder` 返回 `-1`

Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_0_CONTAINER_coder`

### Requirement: srvsvc_SHARE_INFO_1_coder level one record coder
系统 MUST 通过 `srvsvc_SHARE_INFO_1_coder` 按 `netname`、`type`、`remark` 顺序编解码 level 1 share record，并在任一字段 coder 失败时返回 `-1`。

#### Scenario: Level one record encodes tested NDR32 data
- **GIVEN** `srvsvc_SHARE_INFO_1` 包含 `IPC$`、type `0x80000003` 和 remark `Remote IPC`
- **WHEN** 测试以 NDR32 little-endian 执行 `srvsvc_SHARE_INFO_1_coder`
- **THEN** 编解码结果保持 `netname`、`type` 和 `remark` 一致

Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_coder`, `tests/smb2-dcerpc-coder-test.c:test_SHARE_INFO_1_ndr32_le`

#### Scenario: Level one record failure propagates
- **GIVEN** `netname`、`type` 或 `remark` 的底层 coder 返回错误
- **WHEN** 调用方执行 `srvsvc_SHARE_INFO_1_coder`
- **THEN** `srvsvc_SHARE_INFO_1_coder` 返回 `-1`

Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_coder`

### Requirement: srvsvc_SHARE_INFO_1_CONTAINER_coder level one container coder
系统 MUST 通过 `srvsvc_SHARE_INFO_1_CONTAINER_coder` 先编解码 `EntriesRead`，在 decode 且 `EntriesRead` 非零时设置 DCERPC `size_is`，并在 `share_info_1` 为空时按 `EntriesRead * sizeof(struct srvsvc_SHARE_INFO_1)` 分配数组。

#### Scenario: Level one container encodes tested NDR32 data
- **GIVEN** `EntriesRead` 为 `10` 且 `share_info_1` 指向 10 条 level 1 share records
- **WHEN** 测试以 NDR32 little-endian 执行 `srvsvc_SHARE_INFO_1_CONTAINER_coder`
- **THEN** 编解码结果保持条目数和每条记录的 `netname`、`type`、`remark` 一致

Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_CONTAINER_coder`, `tests/smb2-dcerpc-coder-test.c:test_SHARE_INFO_1_CONTAINER_ndr32_le`

#### Scenario: Level one container encodes tested NDR64 data
- **GIVEN** `EntriesRead` 为 `10` 且 `share_info_1` 指向 10 条 level 1 share records
- **WHEN** 测试以 NDR64 little-endian 执行 `srvsvc_SHARE_INFO_1_CONTAINER_coder`
- **THEN** 编解码结果保持条目数和每条记录的 `netname`、`type`、`remark` 一致

Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_CONTAINER_coder`, `tests/smb2-dcerpc-coder-test.c:test_SHARE_INFO_1_CONTAINER_ndr64_le`

#### Scenario: Level one container failure propagates
- **GIVEN** `EntriesRead` coder、数组分配或后续 unique pointer coder 任一操作失败
- **WHEN** 调用方执行 `srvsvc_SHARE_INFO_1_CONTAINER_coder`
- **THEN** `srvsvc_SHARE_INFO_1_CONTAINER_coder` 返回 `-1`

Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_INFO_1_CONTAINER_coder`

### Requirement: srvsvc_SHARE_ENUM_STRUCT_coder share enum wrapper coder
系统 MUST 通过 `srvsvc_SHARE_ENUM_STRUCT_coder` 先编解码 `srvsvc_SHARE_ENUM_STRUCT.Level`，再编解码 `ShareInfo` union，并在任一阶段失败时返回 `-1`。

#### Scenario: Share enum struct dispatches level union
- **GIVEN** `ptr` 指向 `struct srvsvc_SHARE_ENUM_STRUCT`
- **WHEN** `Level` 编解码成功
- **THEN** coder 将 `ShareInfo` 交给 level 分派 union coder 处理

Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_ENUM_STRUCT_coder`, `lib/dcerpc-srvsvc.c:srvsvc_SHARE_ENUM_UNION_coder`

#### Scenario: Share enum struct failure propagates
- **GIVEN** `Level` coder 或 `ShareInfo` union coder 返回错误
- **WHEN** 调用方执行 `srvsvc_SHARE_ENUM_STRUCT_coder`
- **THEN** `srvsvc_SHARE_ENUM_STRUCT_coder` 返回 `-1`

Trace: `lib/dcerpc-srvsvc.c:srvsvc_SHARE_ENUM_STRUCT_coder`

### Requirement: srvsvc_NetrShareEnum_req_coder request coder
系统 MUST 通过 `srvsvc_NetrShareEnum_req_coder` 按 `ServerName`、`ses`、`PreferedMaximumLength`、`ResumeHandle` 顺序编解码 NetrShareEnum 请求，并使用 unique pointer 语义处理 `ServerName` 和 `ResumeHandle`、ref pointer 语义处理 `ses` 和 `PreferedMaximumLength`。

#### Scenario: NetrShareEnum request fields are encoded in declared order
- **GIVEN** `ptr` 指向 `struct srvsvc_NetrShareEnum_req`
- **WHEN** 调用方执行 `srvsvc_NetrShareEnum_req_coder`
- **THEN** coder 依次处理 server name、share enum struct、preferred maximum length 和 resume handle

Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_req_coder`, `lib/smb2-share-enum.c:smb2_share_enum_async`

#### Scenario: NetrShareEnum request failure propagates
- **GIVEN** 任一请求字段底层 coder 返回错误
- **WHEN** 调用方执行 `srvsvc_NetrShareEnum_req_coder`
- **THEN** `srvsvc_NetrShareEnum_req_coder` 返回 `-1`

Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_req_coder`

### Requirement: srvsvc_NetrShareEnum_rep_coder response coder
系统 MUST 通过 `srvsvc_NetrShareEnum_rep_coder` 按 `ses`、`total_entries`、`resume_handle`、`status` 顺序编解码 NetrShareEnum 响应，并在任一字段 coder 失败时返回 `-1`。

#### Scenario: NetrShareEnum response fields are encoded in declared order
- **GIVEN** `ptr` 指向 `struct srvsvc_NetrShareEnum_rep`
- **WHEN** 调用方执行 `srvsvc_NetrShareEnum_rep_coder`
- **THEN** coder 依次处理 share enum struct、total entries、resume handle 和 status

Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_rep_coder`, `lib/smb2-share-enum.c:smb2_share_enum_async`

#### Scenario: NetrShareEnum response failure propagates
- **GIVEN** 任一响应字段底层 coder 返回错误
- **WHEN** 调用方执行 `srvsvc_NetrShareEnum_rep_coder`
- **THEN** `srvsvc_NetrShareEnum_rep_coder` 返回 `-1`

Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareEnum_rep_coder`

### Requirement: srvsvc_NetrShareGetInfo_req_coder request coder
系统 MUST 通过 `srvsvc_NetrShareGetInfo_req_coder` 按 `ServerName`、`NetName`、`Level` 顺序编解码 NetrShareGetInfo 请求，并对 `NetName` 使用 ref pointer UTF-16 编解码。

#### Scenario: NetrShareGetInfo request fields are encoded in declared order
- **GIVEN** `ptr` 指向 `struct srvsvc_NetrShareGetInfo_req`
- **WHEN** 调用方执行 `srvsvc_NetrShareGetInfo_req_coder`
- **THEN** coder 依次处理 server name、share name 和 level

Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_req_coder`, `examples/smb2-share-info.c:main`

#### Scenario: NetrShareGetInfo request failure propagates
- **GIVEN** `ServerName`、`NetName` 或 `Level` 的底层 coder 返回错误
- **WHEN** 调用方执行 `srvsvc_NetrShareGetInfo_req_coder`
- **THEN** `srvsvc_NetrShareGetInfo_req_coder` 返回 `-1`

Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_req_coder`

### Requirement: srvsvc_NetrShareGetInfo_rep_coder response coder
系统 MUST 通过 `srvsvc_NetrShareGetInfo_rep_coder` 按 `InfoStruct`、`status` 顺序编解码 NetrShareGetInfo 响应，并在任一字段 coder 失败时返回 `-1`。

#### Scenario: NetrShareGetInfo response fields are encoded in declared order
- **GIVEN** `ptr` 指向 `struct srvsvc_NetrShareGetInfo_rep`
- **WHEN** 调用方执行 `srvsvc_NetrShareGetInfo_rep_coder`
- **THEN** coder 依次处理 level 分派 info struct 和 status

Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_rep_coder`, `examples/smb2-share-info.c:main`

#### Scenario: NetrShareGetInfo response failure propagates
- **GIVEN** `InfoStruct` 或 `status` 的底层 coder 返回错误
- **WHEN** 调用方执行 `srvsvc_NetrShareGetInfo_rep_coder`
- **THEN** `srvsvc_NetrShareGetInfo_rep_coder` 返回 `-1`

Trace: `lib/dcerpc-srvsvc.c:srvsvc_NetrShareGetInfo_rep_coder`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `srvsvc_SHARE_ENUM_UNION_coder` 对 `Level` 非 `0` 或 `1` 时是否应返回成功且不编码 union arm？ | srvsvc_SHARE_ENUM_STRUCT_coder | 源码 switch 仅处理 0 和 1 且无 default 错误分支；头文件只声明 enum level 0 和 1。 |
| Q-002 | `srvsvc_SHARE_INFO_coder` 对 `level` 非 `1` 时是否应返回成功且不编码具体 share info arm？ | srvsvc_NetrShareGetInfo_rep_coder | 源码 switch 仅处理 level 1 且无 default 错误分支，示例未覆盖非法 level。 |
| Q-003 | `srvsvc_SHARE_INFO_0_CONTAINER_coder` 是否应在 public header 中声明？ | srvsvc_SHARE_INFO_0_CONTAINER_coder | 函数为非 static 且被本文件 union coder 使用，但 `include/smb2/libsmb2-dcerpc-srvsvc.h` 未声明该 coder。 |
| Q-004 | `srvsvc_NetrShareEnum_req_coder` 的 GitNexus impact 应如何精确消歧实现定义与头文件声明？ | srvsvc_NetrShareEnum_req_coder | `gitnexus impact` 返回 header 和 implementation 两个候选，当前 CLI 未接受 `--uid` 或 `--file` 消歧选项。 |
