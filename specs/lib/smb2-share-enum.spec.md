# lib/smb2-share-enum.c Specification

## Source Context

- Source: `lib/smb2-share-enum.c`
- Related Headers: `include/smb2/libsmb2-dcerpc-srvsvc.h`, `include/smb2/libsmb2-dcerpc.h`, `include/smb2/libsmb2-raw.h`, `include/smb2/libsmb2.h`, `include/smb2/smb2.h`, `include/libsmb2-private.h`, `lib/compat.h`
- Related Tests: `examples/smb2-share-enum.c`; GitNexus did not report test callers for this file.
- Related Dependencies: GitNexus `context smb2_share_enum_async --file lib/smb2-share-enum.c` reports outgoing calls to `dcerpc_create_context`, `dcerpc_connect_context_async`, `dcerpc_destroy_context`, `smb2_set_error`, and `nse_free`; GitNexus downstream impact for `Function:lib/smb2-share-enum.c:smb2_share_enum_async` reports CRITICAL dependency reachability through DCERPC/PDU helper paths.
- Build/Compile Context: C source included in the core libsmb2 library; conditional includes depend on `HAVE_CONFIG_H`, `_GNU_SOURCE`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_SYS_TYPES_H`, `HAVE_SYS_STAT_H`, `HAVE_UNISTD_H`, and `HAVE_SYS_UNISTD_H`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| `smb2_share_enum_async` | function | `int smb2_share_enum_async(struct smb2_context *smb2, enum SHARE_INFO_enum level, smb2_command_cb cb, void *cb_data);` | Include | 公开异步 SRVSVC ShareEnum 入口，声明在 public DCERPC SRVSVC 头文件中，并由示例程序和同步包装层调用。 |
| `nse_free` | function | `static void nse_free(struct smb2nse *nse)` | Skip | 静态释放 helper，仅释放当前文件私有状态，无独立对外契约。 |
| `srvsvc_ioctl_cb` | function | `static void srvsvc_ioctl_cb(struct dcerpc_context *dce, int status, void *command_data, void *cb_data)` | Skip | 静态 DCERPC 调用回调，行为归属到 `smb2_share_enum_async` 的异步完成契约。 |
| `share_enum_bind_cb` | function | `static void share_enum_bind_cb(struct dcerpc_context *dce, int status, void *command_data, void *cb_data)` | Skip | 静态 bind 回调，行为归属到 `smb2_share_enum_async` 的连接与调用分派契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| `struct smb2nse` | struct | `lib/smb2-share-enum.c:70` | 当前文件私有异步状态，保存调用方 callback、callback 数据和 `srvsvc_NetrShareEnum_req` 请求体。 |
| `SRVSVC_NETRSHAREENUM` | macro | `include/smb2/libsmb2-dcerpc-srvsvc.h:28` | DCERPC SRVSVC ShareEnum 操作号，异步 bind 成功后传入 `dcerpc_call_async`。 |
| `enum SHARE_INFO_enum` | enum | `include/smb2/libsmb2-dcerpc-srvsvc.h:44` | 调用方可传入的 share info level，目前头文件定义 `SHARE_INFO_0` 和 `SHARE_INFO_1`。 |
| `struct srvsvc_NetrShareEnum_req` | struct | `include/smb2/libsmb2-dcerpc-srvsvc.h:95` | ShareEnum 请求体，当前实现填充服务器名、level、preferred maximum length 和 resume handle。 |
| `struct srvsvc_NetrShareEnum_rep` | struct | `include/smb2/libsmb2-dcerpc-srvsvc.h:102` | ShareEnum 成功响应体，public header 要求调用方使用 `smb2_free_data()` 释放。 |

## ADDED Requirements

### Requirement: smb2_share_enum_async starts SRVSVC ShareEnum asynchronously
系统 MUST 在成功启动时创建 DCERPC 上下文和私有异步状态，构造以 `\\` 加 `smb2->server` 为服务器名的 `srvsvc_NetrShareEnum_req`，并通过 `dcerpc_connect_context_async` 连接 `srvsvc` 接口后返回 `0`。

#### Scenario: 成功启动 ShareEnum 请求
- **GIVEN** 调用方提供已初始化的 `smb2_context`、支持的 `SHARE_INFO_0` 或 `SHARE_INFO_1` level、callback 和 callback 数据
- **WHEN** 调用方调用 `smb2_share_enum_async(smb2, level, cb, cb_data)` 且 DCERPC 上下文、私有状态和服务器名分配成功
- **THEN** 函数返回 `0`，请求使用 `SRVSVC_NETRSHAREENUM` 和 `srvsvc_NetrShareEnum_req_coder` 在 bind 成功后异步发送，完成结果通过调用方 callback 报告

Trace: `lib/smb2-share-enum.c:smb2_share_enum_async`, `lib/smb2-share-enum.c:share_enum_bind_cb`, `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_async`, `examples/smb2-share-enum.c:main`

#### Scenario: SHARE_INFO_0 初始化
- **GIVEN** 调用方传入 `SHARE_INFO_0`
- **WHEN** `smb2_share_enum_async` 构造 `srvsvc_NetrShareEnum_req`
- **THEN** 请求的 `ses.Level` 和 `ses.ShareInfo.Level` MUST 设置为 `SHARE_INFO_0`，`Level0.EntriesRead` MUST 初始化为 `0`，`Level0.share_info_0` MUST 初始化为 `NULL`

Trace: `lib/smb2-share-enum.c:smb2_share_enum_async`, `include/smb2/libsmb2-dcerpc-srvsvc.h:enum SHARE_INFO_enum`

#### Scenario: SHARE_INFO_1 初始化
- **GIVEN** 调用方传入 `SHARE_INFO_1`
- **WHEN** `smb2_share_enum_async` 构造 `srvsvc_NetrShareEnum_req`
- **THEN** 请求的 `ses.Level` 和 `ses.ShareInfo.Level` MUST 设置为 `SHARE_INFO_1`，`Level1.EntriesRead` MUST 初始化为 `0`，`Level1.share_info_1` MUST 初始化为 `NULL`

Trace: `lib/smb2-share-enum.c:smb2_share_enum_async`, `include/smb2/libsmb2-dcerpc-srvsvc.h:enum SHARE_INFO_enum`

#### Scenario: 启动前分配失败
- **GIVEN** 调用方调用 `smb2_share_enum_async` 时 DCERPC 上下文、私有状态或服务器名分配失败
- **WHEN** 函数无法完成异步请求启动
- **THEN** 函数 MUST 返回负 errno 风格错误码，MUST NOT 调用调用方 callback，并在私有状态或服务器名分配失败路径释放已创建的 DCERPC 上下文

Trace: `lib/smb2-share-enum.c:smb2_share_enum_async`, `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_async`

#### Scenario: bind 或 DCERPC 调用启动失败
- **GIVEN** `smb2_share_enum_async` 已创建私有状态并调用 `dcerpc_connect_context_async`
- **WHEN** `dcerpc_connect_context_async` 立即返回错误，或 bind 回调收到失败状态，或 bind 后 `dcerpc_call_async` 返回错误
- **THEN** 实现 MUST 释放私有状态和 DCERPC 上下文；对于 bind 回调或 call 启动失败，MUST 使用相同 status 调用调用方 callback 并传入 `NULL` command data

Trace: `lib/smb2-share-enum.c:smb2_share_enum_async`, `lib/smb2-share-enum.c:share_enum_bind_cb`

#### Scenario: DCERPC 完成回调
- **GIVEN** ShareEnum DCERPC 调用已启动并进入 `srvsvc_ioctl_cb`
- **WHEN** DCERPC 层返回非 `SMB2_STATUS_SUCCESS` status
- **THEN** callback MUST 以该 status、`NULL` command data 和原始 `cb_data` 调用，并在之后释放私有状态和销毁 DCERPC 上下文

Trace: `lib/smb2-share-enum.c:srvsvc_ioctl_cb`, `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_async`

#### Scenario: SRVSVC ShareEnum 响应完成
- **GIVEN** DCERPC 层以 `SMB2_STATUS_SUCCESS` 完成并提供 `struct srvsvc_rep` 响应数据
- **WHEN** `srvsvc_ioctl_cb` 调用用户 callback
- **THEN** callback MUST 接收 `rep->status` 作为 status、原始响应指针作为 command data 和原始 `cb_data`，响应数据生命周期 MUST 遵循 public header 中由调用方使用 `smb2_free_data()` 释放的约定

Trace: `lib/smb2-share-enum.c:srvsvc_ioctl_cb`, `include/smb2/libsmb2-dcerpc-srvsvc.h:smb2_share_enum_async`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `level` 既不是 `SHARE_INFO_0` 也不是 `SHARE_INFO_1` 时是否应立即失败，还是允许发送未完整初始化的 `ses` 字段？ | `smb2_share_enum_async` | 源码 switch 没有 default 分支，头文件只声明两个枚举值但未写非法 level 行为。 |
| Q-002 | `dcerpc_connect_context_async` 立即返回错误时是否应调用用户 callback？ | `smb2_share_enum_async` | public header 写明启动失败时 callback 不会被调用，源码立即失败路径也不调用 callback；bind 后 `dcerpc_call_async` 失败路径会调用 callback，两个阶段语义需要确认。 |
| Q-003 | 传入 `smb2 == NULL`、`cb == NULL` 或 `smb2->server == NULL` 的行为是否属于调用方前置条件？ | `smb2_share_enum_async` | 源码直接解引用 `smb2->server` 和 callback，未显式校验空指针。 |
