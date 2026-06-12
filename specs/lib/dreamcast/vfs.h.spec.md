# lib/dreamcast/vfs.h Specification

## Source Context

- Source: `lib/dreamcast/vfs.h`
- Related Headers: `lib/dreamcast/vfs.c`
- Related Tests: `none`
- Related Dependencies: `lib/dreamcast/vfs.c`, `lib/init.c:smb2_init_context`, `lib/init.c:smb2_parse_url`, `lib/init.c:smb2_destroy_url`, `lib/init.c:smb2_get_error`, `lib/sync.c:smb2_connect_share`, `lib/sync.c:smb2_disconnect_share`, `lib/libsmb2.c:smb2_close_context`
- Build/Compile Context: `Dreamcast/KallistiOS VFS header; implementation includes <kos.h>, <smb2/smb2.h>, <smb2/libsmb2.h>; C standard unknown`

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| kos_smb_init | function | int kos_smb_init(const char *url); | Include | 公开 Dreamcast/KallistiOS SMB VFS 初始化入口，建立 libsmb2 上下文、解析 URL、连接 share，并注册 `/smb` VFS handler。 |
| kos_smb_shutdown | function | void kos_smb_shutdown(void); | Include | 公开 Dreamcast/KallistiOS SMB VFS 清理入口，注销 `/smb` VFS handler 并释放初始化阶段保存的 SMB 资源。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| __KOS_SMB_VFS_H__ | macro | lib/dreamcast/vfs.h:8 | 头文件 include guard，防止重复声明。 |

## ADDED Requirements

### Requirement: kos_smb_init Dreamcast SMB VFS initialization
系统 MUST 通过 `kos_smb_init` 使用调用方提供的 SMB URL 初始化 Dreamcast/KallistiOS SMB VFS，并在成功连接 share 后注册 `/smb` VFS handler。

#### Scenario: 成功初始化并注册 VFS handler
- **GIVEN** 调用方提供可由 libsmb2 解析并连接的 SMB URL
- **WHEN** 调用方调用 `kos_smb_init(url)`
- **THEN** 函数返回 `0`，并完成 SMB context 初始化、URL 解析、share 连接和 `/smb` VFS handler 注册

Trace: `lib/dreamcast/vfs.h:kos_smb_init`, `lib/dreamcast/vfs.c:kos_smb_init`

#### Scenario: SMB context 初始化失败
- **GIVEN** libsmb2 context 初始化返回空指针
- **WHEN** 调用方调用 `kos_smb_init(url)`
- **THEN** 函数返回 `-EIO`，并且不会继续解析 URL、连接 share 或注册 VFS handler

Trace: `lib/dreamcast/vfs.h:kos_smb_init`, `lib/dreamcast/vfs.c:kos_smb_init`

#### Scenario: SMB URL 解析失败
- **GIVEN** libsmb2 context 已创建但 `url` 不能被 `smb2_parse_url` 解析
- **WHEN** 调用方调用 `kos_smb_init(url)`
- **THEN** 函数返回 `-EINVAL`，关闭已创建的 libsmb2 context，并且不会连接 share 或注册 VFS handler

Trace: `lib/dreamcast/vfs.h:kos_smb_init`, `lib/dreamcast/vfs.c:kos_smb_init`

#### Scenario: SMB share 连接失败
- **GIVEN** libsmb2 context 和 SMB URL 已创建但 `smb2_connect_share` 返回非零错误码
- **WHEN** 调用方调用 `kos_smb_init(url)`
- **THEN** 函数返回 `smb2_connect_share` 的错误码，销毁已解析 URL 并关闭 libsmb2 context，且不会注册 VFS handler

Trace: `lib/dreamcast/vfs.h:kos_smb_init`, `lib/dreamcast/vfs.c:kos_smb_init`

### Requirement: kos_smb_shutdown Dreamcast SMB VFS shutdown
系统 MUST 通过 `kos_smb_shutdown` 注销 Dreamcast/KallistiOS `/smb` VFS handler，并释放初始化阶段保存的 SMB share、URL 和 context 资源。

#### Scenario: 清理已初始化的 SMB VFS
- **GIVEN** `kos_smb_init` 已成功完成并保存 SMB context 与 URL
- **WHEN** 调用方调用 `kos_smb_shutdown()`
- **THEN** 函数注销 `/smb` VFS handler，断开 SMB share，销毁 SMB URL，并关闭 libsmb2 context

Trace: `lib/dreamcast/vfs.h:kos_smb_shutdown`, `lib/dreamcast/vfs.c:kos_smb_shutdown`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `kos_smb_shutdown` 在 `kos_smb_init` 未成功完成、重复调用或部分初始化失败后被调用时的空指针和幂等语义是否属于受支持行为？ | kos_smb_shutdown | 头文件未声明调用顺序约束，源码直接使用静态 `cxt` 和 `smb_url`，未见空指针防护或测试证据。 |
| Q-002 | `kos_smb_init` 成功后重复调用是否允许覆盖全局 SMB context、URL 和 VFS handler？ | kos_smb_init | 源码使用静态全局状态且未检查既有初始化状态，未见测试或文档说明重复初始化语义。 |
