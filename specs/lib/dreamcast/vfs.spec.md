# lib/dreamcast/vfs.c Specification

## Source Context

- Source: `lib/dreamcast/vfs.c`
- Related Headers: `lib/dreamcast/vfs.h`
- Related Tests: `none`
- Related Dependencies: `kos_smb_init` creates a libsmb2 context with `smb2_init_context`, parses the URL with `smb2_parse_url`, connects the share with `smb2_connect_share`, and registers a KallistiOS VFS handler with `nmmgr_handler_add`; `kos_smb_shutdown` removes the handler with `nmmgr_handler_remove`, disconnects via `smb2_disconnect_share`, destroys the parsed URL with `smb2_destroy_url`, and closes the context with `smb2_close_context`. The registered handler dispatches `/smb` VFS operations to libsmb2 file, directory, stat, seek, readlink, rename, unlink, mkdir, and rmdir APIs under a file-local mutex.
- Build/Compile Context: `lib/CMakeLists.txt` includes `lib/dreamcast/vfs.c` for Dreamcast/KallistiOS platform builds; the source includes `<kos.h>`, `<smb2/smb2.h>`, `<smb2/libsmb2.h>`, and `lib/dreamcast/vfs.h` without additional source-level `#if` conditions.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb_fd | type | struct smb_fd { bool is_dir; void *hdl; dirent_t dirent[]; }; | Skip | 文件内部句柄包装结构，仅通过 KallistiOS VFS 回调私有传递，不形成独立跨文件契约。 |
| smb_open | function | static void * smb_open(vfs_handler_t *vfs, const char *fn, int mode); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb_close | function | static int smb_close(void *hnd); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb_read | function | static ssize_t smb_read(void *hnd, void *buffer, size_t cnt); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb_write | function | static ssize_t smb_write(void *hnd, const void *buffer, size_t cnt); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb_readdir | function | static const dirent_t *smb_readdir(void *hnd); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb_rename | function | static int smb_rename(struct vfs_handler *vfs, const char *fn1, const char *fn2); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb_unlink | function | static int smb_unlink(struct vfs_handler *vfs, const char *path); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb2_stat_convert | function | static void smb2_stat_convert(struct stat *buf, const struct smb2_stat_64 *st); | Skip | 文件内部转换 helper，仅服务 `smb_stat` 与 `smb_fstat`，无独立公开入口。 |
| smb_stat | function | static int smb_stat(struct vfs_handler *vfs, const char *path, struct stat *buf, int flag); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb_mkdir | function | static int smb_mkdir(struct vfs_handler *vfs, const char *fn); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb_rmdir | function | static int smb_rmdir(struct vfs_handler *vfs, const char *fn); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb_seek64 | function | static _off64_t smb_seek64(void *hnd, _off64_t offset, int whence); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb_tell64 | function | static _off64_t smb_tell64(void *hnd); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb_readlink | function | static ssize_t smb_readlink(struct vfs_handler *vfs, const char *path, char *buf, size_t bufsize); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb_rewinddir | function | static int smb_rewinddir(void *hnd); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| smb_fstat | function | static int smb_fstat(void *hnd, struct stat *buf); | Skip | 静态 VFS 回调，由本文件注册表引用，行为归属到 `kos_smb_init` 注册后的 `/smb` VFS 契约。 |
| kos_smb_init | function | int kos_smb_init(const char *url); | Include | 头文件声明并由实现导出的 Dreamcast SMB VFS 初始化入口，负责建立连接和注册 `/smb` VFS。 |
| kos_smb_shutdown | function | void kos_smb_shutdown(void); | Include | 头文件声明并由实现导出的 Dreamcast SMB VFS 关闭入口，负责注销 `/smb` VFS 并释放全局 SMB 资源。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| smb_fd | struct | lib/dreamcast/vfs.c:20 | 文件内部 VFS 句柄，记录当前句柄是否为目录、libsmb2 句柄指针，并为目录读取保留一个 `dirent_t` 返回槽。 |
| lock | static object | lib/dreamcast/vfs.c:15 | 文件内部互斥锁，VFS 回调在调用全局 `cxt` 和 libsmb2 句柄前加锁。 |
| cxt | static object | lib/dreamcast/vfs.c:17 | 文件内部全局 libsmb2 context，由 `kos_smb_init` 设置并由 VFS 回调与 `kos_smb_shutdown` 使用。 |
| smb_url | static object | lib/dreamcast/vfs.c:18 | 文件内部全局 parsed SMB URL，由 `kos_smb_init` 设置并由 `kos_smb_shutdown` 释放。 |
| vh | static object | lib/dreamcast/vfs.c:252 | KallistiOS VFS handler，命名为 `/smb`，注册本文件的静态 SMB 文件系统回调。 |

## ADDED Requirements

### Requirement: kos_smb_init Dreamcast VFS initialization
系统 MUST 为给定 SMB URL 创建 libsmb2 上下文、解析 URL、连接目标 share，并仅在连接成功后注册名为 `/smb` 的 KallistiOS VFS handler。

#### Scenario: Successful share connection registers SMB VFS
- **GIVEN** 调用方提供可由 libsmb2 解析并连接的 SMB URL
- **WHEN** 调用方调用 `kos_smb_init(url)`
- **THEN** 实现 MUST 创建全局 `cxt`，保存解析后的 `smb_url`，调用 `smb2_connect_share(cxt, smb_url->server, smb_url->share, smb_url->user)`，并在返回 `0` 前调用 `nmmgr_handler_add(&vh.nmmgr)` 注册 `/smb` VFS

Trace: `lib/dreamcast/vfs.c:kos_smb_init`, `lib/dreamcast/vfs.h:kos_smb_init`

#### Scenario: Context allocation failure returns I/O error
- **GIVEN** `smb2_init_context()` 返回 `NULL`
- **WHEN** 调用方调用 `kos_smb_init(url)`
- **THEN** 实现 MUST 返回 `-EIO`，并且 SHALL NOT 尝试解析 URL、连接 share 或注册 `/smb` VFS

Trace: `lib/dreamcast/vfs.c:kos_smb_init`, `lib/dreamcast/vfs.h:kos_smb_init`

#### Scenario: URL parse failure closes context
- **GIVEN** `smb2_init_context()` 成功但 `smb2_parse_url(cxt, url)` 返回 `NULL`
- **WHEN** 调用方调用 `kos_smb_init(url)`
- **THEN** 实现 MUST 调用 `smb2_close_context(cxt)` 并返回 `-EINVAL`，并且 SHALL NOT 连接 share 或注册 `/smb` VFS

Trace: `lib/dreamcast/vfs.c:kos_smb_init`, `lib/dreamcast/vfs.h:kos_smb_init`

#### Scenario: Share connection failure releases parsed URL and context
- **GIVEN** context 创建和 URL 解析成功，但 `smb2_connect_share` 返回非零错误码
- **WHEN** 调用方调用 `kos_smb_init(url)`
- **THEN** 实现 MUST 调用 `smb2_destroy_url(smb_url)` 和 `smb2_close_context(cxt)`，返回 `smb2_connect_share` 的错误码，并且 SHALL NOT 注册 `/smb` VFS

Trace: `lib/dreamcast/vfs.c:kos_smb_init`, `lib/dreamcast/vfs.h:kos_smb_init`

#### Scenario: Registered VFS serializes SMB operations
- **GIVEN** `kos_smb_init(url)` 已成功注册 `/smb` VFS
- **WHEN** KallistiOS 通过 `vh` 调用本文件的 open、close、read、write、readdir、rename、unlink、stat、mkdir、rmdir、seek64、tell64、readlink、rewinddir 或 fstat 回调
- **THEN** 每个回调 MUST 在访问全局 `cxt` 或 libsmb2 句柄前持有文件级 `lock`，并把对应 VFS 操作转发到匹配的 libsmb2 同步 API

Trace: `lib/dreamcast/vfs.c:vh`, `lib/dreamcast/vfs.c:lock`, `lib/dreamcast/vfs.c:smb_open`, `lib/dreamcast/vfs.c:smb_close`, `lib/dreamcast/vfs.c:smb_read`, `lib/dreamcast/vfs.c:smb_write`, `lib/dreamcast/vfs.c:smb_readdir`, `lib/dreamcast/vfs.c:smb_stat`, `lib/dreamcast/vfs.c:smb_fstat`

### Requirement: kos_smb_shutdown Dreamcast VFS shutdown
系统 MUST 注销 Dreamcast `/smb` VFS handler，并按连接、URL、context 的资源层级释放由 `kos_smb_init` 保存的全局 SMB 资源。

#### Scenario: Shutdown removes VFS handler and releases SMB resources
- **GIVEN** `kos_smb_init(url)` 已成功初始化并注册 `/smb` VFS
- **WHEN** 调用方调用 `kos_smb_shutdown()`
- **THEN** 实现 MUST 调用 `nmmgr_handler_remove(&vh.nmmgr)`，随后调用 `smb2_disconnect_share(cxt)`、`smb2_destroy_url(smb_url)` 和 `smb2_close_context(cxt)` 释放全局连接资源

Trace: `lib/dreamcast/vfs.c:kos_smb_shutdown`, `lib/dreamcast/vfs.h:kos_smb_shutdown`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `kos_smb_init` 在 URL 解析失败或 share 连接失败后是否需要清空全局 `cxt` 和 `smb_url` 指针？ | kos_smb_init | 源码释放资源但未把静态全局指针置空；后续重复调用或错误后调用 shutdown 的契约未声明。 |
| Q-002 | `kos_smb_shutdown` 是否只允许在 `kos_smb_init` 成功后调用，且是否需要防御重复调用？ | kos_smb_shutdown | 源码无 NULL 检查或状态检查，直接使用全局 `cxt` 和 `smb_url`。 |
| Q-003 | Dreamcast VFS 回调的错误码是否应保持 libsmb2 原始返回值，还是需要映射到 KallistiOS errno 约定？ | kos_smb_init | 静态回调多数直接返回 libsmb2 返回值，open/read/write/stat 等失败仅记录日志；平台 VFS 错误映射契约未在源码中说明。 |
| Q-004 | `smb_readdir` 使用 `strncpy(fd->dirent[0].name, dir->name, NAME_MAX - 1)` 后是否需要显式 NUL 终止？ | kos_smb_init | 源码未写入结尾 NUL，目录名长度达到或超过 `NAME_MAX - 1` 时返回名称终止语义不明确。 |
| Q-005 | GitNexus `impact` 对 `kos_smb_init` 与 `kos_smb_shutdown` 因 `vfs.c` 实现和 `vfs.h` 声明同名而返回 ambiguous，CLI 未提供可用 UID 参数；直接上游影响范围需后续工具消歧确认。 | kos_smb_init, kos_smb_shutdown | `gitnexus context` 已定位实现符号；`gitnexus impact --include-tests` 返回两个候选，`--target-uid` 不是当前 CLI 支持选项。 |
