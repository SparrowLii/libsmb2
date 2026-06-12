# lib/ps2/smb2_fio.c Specification

## Source Context

- Source: `lib/ps2/smb2_fio.c`
- Related Headers: `lib/ps2/smb2_fio.h`, `lib/ps2/ps2smb2.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context links `SMB2_initdev` to `_start` in `lib/ps2/smb2man.c`; PS2 FIO callbacks call libsmb2 sync APIs such as `smb2_open`, `smb2_close`, `smb2_read`, `smb2_write`, `smb2_stat`, `smb2_mkdir`, `smb2_rmdir`, `smb2_unlink`, `smb2_rename`, `smb2_opendir`, `smb2_readdir`, and `smb2_lseek`.
- Build/Compile Context: PS2 IOP filesystem driver source using ps2sdk IOP headers and libsmb2; `DEBUG` enables optional SMB logging to a hard-coded SMB URL.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| `SMB2_initdev` | function | `int SMB2_initdev(void)` | Include | PS2 模块入口通过 `DelDrv`/`AddDrv` 注册 `smb` 文件系统设备。 |
| `SMB2_devctl` | function | `int SMB2_devctl(iop_file_t *f, const char *devname, int cmd, void *arg, unsigned int arglen, void *bufp, unsigned int buflen)` | Include | 公开设备控制入口处理 SMB2 共享连接命令。 |
| `SMB2_open` | function | `int SMB2_open(iop_file_t *f, const char *filename, int flags, int mode)` | Include | 文件打开回调建立 per-file SMB2 句柄并写入 `f->privdata`。 |
| `SMB2_close` | function | `int SMB2_close(iop_file_t *f)` | Include | 文件关闭回调释放 SMB2 文件句柄和私有数据。 |
| `SMB2_dopen` | function | `int SMB2_dopen(iop_file_t *f, const char *dirname)` | Include | 目录打开回调建立 per-directory SMB2 句柄或虚拟根目录迭代状态。 |
| `SMB2_dclose` | function | `int SMB2_dclose(iop_file_t *f)` | Include | 目录关闭回调释放目录句柄和私有数据。 |
| `SMB2_dread` | function | `int SMB2_dread(iop_file_t *f, iox_dirent_t *dirent)` | Include | 目录读取回调返回 SMB2 目录项或已连接共享列表项。 |
| `SMB2_getstat` | function | `int SMB2_getstat(iop_file_t *f, const char *filename, iox_stat_t *stat)` | Include | stat 回调把 libsmb2 64 位属性转换为 PS2 `iox_stat_t`。 |
| `SMB2_lseek64` | function | `s64 SMB2_lseek64(iop_file_t *f, s64 pos, int whence)` | Include | 64 位 seek 回调委托 libsmb2 文件偏移设置。 |
| `SMB2_lseek` | function | `int SMB2_lseek(iop_file_t *f, int pos, int where)` | Include | 32 位 seek 回调包装 `SMB2_lseek64` 并截断为 `int`。 |
| `SMB2_read` | function | `int SMB2_read(iop_file_t *f, void *buf, int size)` | Include | 读回调在有效文件句柄上委托 libsmb2 同步读取。 |
| `SMB2_write` | function | `int SMB2_write(iop_file_t *f, void *buf, int size)` | Include | 写回调在文件句柄上委托 libsmb2 同步写入。 |
| `SMB2_mkdir` | function | `int SMB2_mkdir(iop_file_t *f, const char *dirname, int mode)` | Include | mkdir 回调解析共享路径并委托 SMB2 创建目录。 |
| `SMB2_rmdir` | function | `int SMB2_rmdir(iop_file_t *f, const char *dirname)` | Include | rmdir 回调解析共享路径并委托 SMB2 删除目录。 |
| `SMB2_remove` | function | `int SMB2_remove(iop_file_t *f, const char *filename)` | Include | remove 回调解析共享路径并委托 SMB2 unlink。 |
| `SMB2_rename` | function | `int SMB2_rename(iop_file_t *f, const char *oldname, const char *newname)` | Include | rename 回调验证源和目标属于同一 SMB2 上下文后委托 SMB2 rename。 |
| `SMB2_dummy` | function | `int SMB2_dummy(void)` | Include | 未实现设备操作槽位返回固定 I/O 错误。 |
| `SMB2_chdir` | function | `int SMB2_chdir(iop_file_t *f, const char *dirname)` | Include | chdir 回调更新模块全局当前目录前缀。 |
| `SMB2_deinit` | function | `int SMB2_deinit(iop_device_t *dev)` | Include | 设备反初始化回调删除 I/O 互斥信号量。 |
| `SMB2_init` | function | `int SMB2_init(iop_device_t *dev)` | Include | 设备初始化回调创建 I/O 互斥信号量。 |
| `find_context` | function | `static struct smb2_context *find_context(char *path, char **remainder)` | Skip | 静态路径解析 helper，仅支撑本文件公开回调。 |
| `prepare_path` | function | `static char *prepare_path(const char *path)` | Skip | 静态路径规范化 helper，行为归属到调用它的公开回调。 |
| `smb2_Connect` | function | `static int smb2_Connect(smb2Connect_in_t *in, smb2Connect_out_t *out)` | Skip | 静态 devctl helper，连接契约归属到 `SMB2_devctl`。 |
| `FileTimeToDate` | function | `static void FileTimeToDate(u64 t, u8 *datetime)` | Skip | 静态时间转换 helper，stat 契约归属到 `SMB2_getstat`/`SMB2_dread`。 |
| `smb2_statFiller` | function | `static void smb2_statFiller(struct smb2_stat_64 *st, iox_stat_t *stat)` | Skip | 静态属性转换 helper，stat 契约归属到调用方。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| `struct smb2_share_list` | struct | `lib/ps2/smb2_fio.c:67` | 保存已连接共享名称、libsmb2 context 和链表 next 指针。 |
| `struct dir_fh` | struct | `lib/ps2/smb2_fio.c:245` | 目录私有句柄，区分 SMB2 目录和虚拟根共享列表迭代。 |
| `struct file_fh` | struct | `lib/ps2/smb2_fio.c:253` | 文件私有句柄，保存 libsmb2 context 和文件句柄。 |
| `smb2man_ops` | static object | `lib/ps2/smb2_fio.c:773` | PS2 IOP device operation table，把回调映射到 `smb` 文件系统设备。 |
| `smb2dev` | static object | `lib/ps2/smb2_fio.c:802` | PS2 IOP device descriptor，设备名为 `smb`。 |
| `smb2_io_lock` | macro | `lib/ps2/smb2_fio.c:75` | 包装 `WaitSema(smb2man_io_sema)` 保护 SMB2 I/O 操作。 |
| `smb2_io_unlock` | macro | `lib/ps2/smb2_fio.c:76` | 包装 `SignalSema(smb2man_io_sema)` 释放 SMB2 I/O 互斥。 |
| `SMB2_DEVCTL_CONNECT` | macro | `lib/ps2/ps2smb2.h:13` | devctl 连接命令常量。 |
| `smb2Connect_in_t` | typedef | `lib/ps2/ps2smb2.h:20` | 连接输入包含共享名、用户名、密码和 URL。 |
| `smb2Connect_out_t` | typedef | `lib/ps2/ps2smb2.h:27` | 连接输出携带创建的 SMB2 context 指针。 |

## ADDED Requirements

### Requirement: SMB2_initdev register PS2 SMB device
系统 MUST 在模块入口调用 `DelDrv` 删除既有同名设备后调用 `AddDrv` 注册 `smb` 文件系统设备，并 MUST 根据 `AddDrv` 结果返回 PS2 模块驻留状态。

#### Scenario: register succeeds
- **GIVEN** `SMB2_initdev` 被 PS2 模块 `_start` 调用
- **WHEN** `AddDrv((iop_device_t *)&smb2dev)` 返回 0
- **THEN** 函数返回 `MODULE_RESIDENT_END`

Trace: `lib/ps2/smb2_fio.c:SMB2_initdev`, `lib/ps2/smb2man.c:_start`

#### Scenario: register fails
- **GIVEN** `SMB2_initdev` 已尝试删除旧的 `smb` 设备
- **WHEN** `AddDrv((iop_device_t *)&smb2dev)` 返回非零
- **THEN** 函数返回 `MODULE_NO_RESIDENT_END`

Trace: `lib/ps2/smb2_fio.c:SMB2_initdev`

### Requirement: SMB2_devctl connect shares
系统 MUST 通过 `SMB2_DEVCTL_CONNECT` 命令创建 SMB2 共享连接，并 MUST 对未知 devctl 命令返回 `-EINVAL`。

#### Scenario: connect command succeeds
- **GIVEN** `cmd` 等于 `SMB2_DEVCTL_CONNECT` 且 `arg` 指向 `smb2Connect_in_t`
- **WHEN** `SMB2_devctl` 在 I/O 互斥锁内调用连接逻辑
- **THEN** 成功时返回 0，并在 `bufp` 非空时写入创建的 SMB2 context

Trace: `lib/ps2/smb2_fio.c:SMB2_devctl`

#### Scenario: unknown command rejected
- **GIVEN** `cmd` 不是 `SMB2_DEVCTL_CONNECT`
- **WHEN** `SMB2_devctl` 处理命令分发
- **THEN** 函数返回 `-EINVAL`

Trace: `lib/ps2/smb2_fio.c:SMB2_devctl`

### Requirement: SMB2_open open read-only files
系统 MUST 只允许只读打开 SMB2 文件，并 MUST 在成功打开时把分配的文件私有句柄写入 `f->privdata`。

#### Scenario: read-only file opens
- **GIVEN** `filename` 非空、`flags` 等于 `O_RDONLY` 且路径解析到已连接共享
- **WHEN** `SMB2_open` 成功调用 `smb2_open`
- **THEN** 函数返回 0，并把包含 SMB2 context 和文件句柄的 `struct file_fh` 保存到 `f->privdata`

Trace: `lib/ps2/smb2_fio.c:SMB2_open`

#### Scenario: write flags rejected
- **GIVEN** `flags` 不等于 `O_RDONLY`
- **WHEN** `SMB2_open` 被调用
- **THEN** 函数返回 `-EROFS`

Trace: `lib/ps2/smb2_fio.c:SMB2_open`

### Requirement: SMB2_close release file handles
系统 MUST 关闭有效文件私有句柄并释放其内存，并 MUST 在关闭后清空 `f->privdata`。

#### Scenario: valid file closes
- **GIVEN** `f->privdata` 指向 `struct file_fh`
- **WHEN** `SMB2_close` 被调用
- **THEN** 函数调用 `smb2_close`、释放私有句柄、设置 `f->privdata` 为 `NULL` 并返回 0

Trace: `lib/ps2/smb2_fio.c:SMB2_close`

#### Scenario: invalid file handle rejected
- **GIVEN** `f->privdata` 为 `NULL`
- **WHEN** `SMB2_close` 被调用
- **THEN** 函数返回 `-EBADF`

Trace: `lib/ps2/smb2_fio.c:SMB2_close`

### Requirement: SMB2_dopen open directories
系统 MUST 为有效目录路径创建目录私有句柄，并 MUST 对空目录名、路径分配失败或未知共享返回对应错误码。

#### Scenario: SMB2 directory opens
- **GIVEN** `dirname` 非空且路径解析到已连接共享内的非空 remainder
- **WHEN** `SMB2_dopen` 成功调用 `smb2_opendir`
- **THEN** 函数保存 `struct dir_fh` 到 `f->privdata` 并返回 0

Trace: `lib/ps2/smb2_fio.c:SMB2_dopen`

#### Scenario: missing directory name rejected
- **GIVEN** `dirname` 为 `NULL`
- **WHEN** `SMB2_dopen` 被调用
- **THEN** 函数返回 `-ENOENT`

Trace: `lib/ps2/smb2_fio.c:SMB2_dopen`

### Requirement: SMB2_dclose release directory handles
系统 MUST 释放目录私有句柄，并 MUST 仅对非虚拟根目录调用 `smb2_closedir`。

#### Scenario: valid directory closes
- **GIVEN** `f->privdata` 指向 `struct dir_fh`
- **WHEN** `SMB2_dclose` 被调用
- **THEN** 函数对非 root 目录关闭 SMB2 目录句柄、释放私有数据、清空 `f->privdata` 并返回 0

Trace: `lib/ps2/smb2_fio.c:SMB2_dclose`

#### Scenario: invalid directory handle rejected
- **GIVEN** `f->privdata` 为 `NULL`
- **WHEN** `SMB2_dclose` 被调用
- **THEN** 函数返回 `-EBADF`

Trace: `lib/ps2/smb2_fio.c:SMB2_dclose`

### Requirement: SMB2_dread return directory entries
系统 MUST 从有效目录私有句柄返回一个目录项计数语义，并 MUST 在没有更多条目时返回 0。

#### Scenario: SMB2 directory entry returned
- **GIVEN** `f->privdata` 指向非 root `struct dir_fh` 且 `smb2_readdir` 返回条目
- **WHEN** `SMB2_dread` 被调用
- **THEN** 函数复制条目名称、填充 stat 信息并返回 1

Trace: `lib/ps2/smb2_fio.c:SMB2_dread`

#### Scenario: virtual root share returned
- **GIVEN** `f->privdata` 指向 root `struct dir_fh` 且 `dfh->shares` 非空
- **WHEN** `SMB2_dread` 被调用
- **THEN** 函数把共享名作为目录名返回、设置目录模式并返回 1

Trace: `lib/ps2/smb2_fio.c:SMB2_dread`

### Requirement: SMB2_getstat fill PS2 stat
系统 MUST 对有效路径调用 SMB2 stat，并 MUST 在成功时把 SMB2 属性转换为 PS2 `iox_stat_t`。

#### Scenario: stat succeeds
- **GIVEN** `filename` 非空且路径解析到已连接共享
- **WHEN** `smb2_stat` 返回 0
- **THEN** `SMB2_getstat` 填充时间、大小和文件类型字段并返回 0

Trace: `lib/ps2/smb2_fio.c:SMB2_getstat`

#### Scenario: filename missing
- **GIVEN** `filename` 为 `NULL`
- **WHEN** `SMB2_getstat` 被调用
- **THEN** 函数返回 `-ENOENT`

Trace: `lib/ps2/smb2_fio.c:SMB2_getstat`

### Requirement: SMB2_lseek64 seek file offsets
系统 MUST 将 64 位 seek 请求委托给 libsmb2 `smb2_lseek` 并返回其结果值。

#### Scenario: seek delegates to libsmb2
- **GIVEN** `f->privdata` 指向有效 `struct file_fh`
- **WHEN** `SMB2_lseek64` 接收 `pos` 和 `whence`
- **THEN** 函数调用 `smb2_lseek(ffh->smb2, ffh->fh, pos, whence, NULL)` 并返回该调用结果

Trace: `lib/ps2/smb2_fio.c:SMB2_lseek64`

### Requirement: SMB2_lseek wrap 32-bit seek
系统 MUST 通过 `SMB2_lseek64` 执行 32 位 seek 请求，并 MUST 将返回值转换为 `int`。

#### Scenario: 32-bit seek delegates
- **GIVEN** 调用方提供 `pos` 和 `where`
- **WHEN** `SMB2_lseek` 被调用
- **THEN** 函数返回 `(int)SMB2_lseek64(f, pos, where)`

Trace: `lib/ps2/smb2_fio.c:SMB2_lseek`

### Requirement: SMB2_read read from file handles
系统 MUST 对有效文件私有句柄调用 libsmb2 读取，并 MUST 对空私有句柄返回 `-EBADF`。

#### Scenario: read succeeds or propagates libsmb2 result
- **GIVEN** `f->privdata` 指向有效 `struct file_fh`
- **WHEN** `SMB2_read` 被调用
- **THEN** 函数在 I/O 互斥锁内调用 `smb2_read` 并返回该调用结果

Trace: `lib/ps2/smb2_fio.c:SMB2_read`

#### Scenario: invalid read handle rejected
- **GIVEN** `f->privdata` 为 `NULL`
- **WHEN** `SMB2_read` 被调用
- **THEN** 函数返回 `-EBADF`

Trace: `lib/ps2/smb2_fio.c:SMB2_read`

### Requirement: SMB2_write write to file handles
系统 MUST 将写请求委托给 libsmb2 `smb2_write`，并 MUST 返回底层写调用结果。

#### Scenario: write delegates to libsmb2
- **GIVEN** `f->privdata` 指向 `struct file_fh`
- **WHEN** `SMB2_write` 接收 buffer 和 size
- **THEN** 函数在 I/O 互斥锁内调用 `smb2_write` 并返回该调用结果

Trace: `lib/ps2/smb2_fio.c:SMB2_write`

### Requirement: SMB2_mkdir create remote directories
系统 MUST 对有效目录路径调用 SMB2 mkdir，并 MUST 对空目录名、路径分配失败或未知共享返回对应错误码。

#### Scenario: mkdir delegates to libsmb2
- **GIVEN** `dirname` 非空且路径解析到已连接共享
- **WHEN** `SMB2_mkdir` 被调用
- **THEN** 函数在 I/O 互斥锁内调用 `smb2_mkdir` 并返回该调用结果

Trace: `lib/ps2/smb2_fio.c:SMB2_mkdir`

### Requirement: SMB2_rmdir remove remote directories
系统 MUST 对有效目录路径调用 SMB2 rmdir，并 MUST 对空目录名、路径分配失败或未知共享返回对应错误码。

#### Scenario: rmdir delegates to libsmb2
- **GIVEN** `dirname` 非空且路径解析到已连接共享
- **WHEN** `SMB2_rmdir` 被调用
- **THEN** 函数在 I/O 互斥锁内调用 `smb2_rmdir` 并返回该调用结果

Trace: `lib/ps2/smb2_fio.c:SMB2_rmdir`

### Requirement: SMB2_remove unlink remote files
系统 MUST 对有效文件路径调用 SMB2 unlink，并 MUST 对空文件名、路径分配失败或未知共享返回对应错误码。

#### Scenario: remove delegates to libsmb2
- **GIVEN** `filename` 非空且路径解析到已连接共享
- **WHEN** `SMB2_remove` 被调用
- **THEN** 函数在 I/O 互斥锁内调用 `smb2_unlink` 并返回该调用结果

Trace: `lib/ps2/smb2_fio.c:SMB2_remove`

### Requirement: SMB2_rename rename within one share
系统 MUST 仅在源路径和目标路径属于同一个 SMB2 context 时执行 rename，并 MUST 对跨共享 rename 返回 `-EINVAL`。

#### Scenario: same-share rename delegates
- **GIVEN** `oldname` 和 `newname` 均解析到同一个 SMB2 context
- **WHEN** `SMB2_rename` 被调用
- **THEN** 函数在 I/O 互斥锁内调用 `smb2_rename` 并返回该调用结果

Trace: `lib/ps2/smb2_fio.c:SMB2_rename`

#### Scenario: cross-share rename rejected
- **GIVEN** `oldname` 和 `newname` 解析到不同 SMB2 context
- **WHEN** `SMB2_rename` 被调用
- **THEN** 函数返回 `-EINVAL`

Trace: `lib/ps2/smb2_fio.c:SMB2_rename`

### Requirement: SMB2_dummy reject unsupported operations
系统 MUST 对映射到 dummy 槽位的未实现操作返回 `-EIO`。

#### Scenario: unsupported operation called
- **GIVEN** PS2 IOP 调用映射到 `SMB2_dummy` 的设备操作槽位
- **WHEN** `SMB2_dummy` 被执行
- **THEN** 函数返回 `-EIO`

Trace: `lib/ps2/smb2_fio.c:SMB2_dummy`

### Requirement: SMB2_chdir update current directory
系统 MUST 将有效目录路径保存为后续相对路径的当前目录前缀，并 MUST 释放旧的当前目录缓冲区。

#### Scenario: current directory changes
- **GIVEN** `dirname` 非空且 `prepare_path` 返回新路径缓冲区
- **WHEN** `SMB2_chdir` 被调用
- **THEN** 函数释放旧 `smb2_curdir`、保存新路径并返回 0

Trace: `lib/ps2/smb2_fio.c:SMB2_chdir`

#### Scenario: missing directory rejected
- **GIVEN** `dirname` 为 `NULL`
- **WHEN** `SMB2_chdir` 被调用
- **THEN** 函数返回 `-ENOENT`

Trace: `lib/ps2/smb2_fio.c:SMB2_chdir`

### Requirement: SMB2_deinit delete I/O semaphore
系统 MUST 在设备反初始化时删除 `smb2man_io_sema` 并返回成功。

#### Scenario: device deinitializes
- **GIVEN** `SMB2_deinit` 被 PS2 IOP 设备层调用
- **WHEN** 函数执行
- **THEN** 函数调用 `DeleteSema(smb2man_io_sema)` 并返回 0

Trace: `lib/ps2/smb2_fio.c:SMB2_deinit`

### Requirement: SMB2_init create I/O semaphore
系统 MUST 在设备初始化时创建未锁定 IOP mutex 并保存到 `smb2man_io_sema`。

#### Scenario: device initializes
- **GIVEN** `SMB2_init` 被 PS2 IOP 设备层调用
- **WHEN** 函数执行
- **THEN** 函数调用 `CreateMutex(IOP_MUTEX_UNLOCKED)`、保存返回值并返回 0

Trace: `lib/ps2/smb2_fio.c:SMB2_init`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `find_context` 使用 `strcmp(share->name, path)` 非零时返回 context，是否意图匹配相等共享名仍需确认。 | `SMB2_open`, `SMB2_dopen`, `SMB2_getstat`, `SMB2_mkdir`, `SMB2_rmdir`, `SMB2_remove`, `SMB2_rename` | 源码行为与注释“share name match”语义存在疑似冲突，未找到测试证据。 |
| Q-002 | `SMB2_dopen` 的虚拟 root 分支设置 `dfh->is_root = true` 后仍检查未初始化的 `dfh->fh == NULL`，root 目录是否实际可打开需确认。 | `SMB2_dopen`, `SMB2_dread` | 源码 TODO 提到虚拟 root 行为，未找到测试或平台文档确认预期。 |
| Q-003 | `SMB2_lseek64`、`SMB2_write` 未检查 `f->privdata == NULL`，调用方是否保证有效句柄需确认。 | `SMB2_lseek64`, `SMB2_write` | 与 `SMB2_read`/`SMB2_close` 的 `-EBADF` 处理不一致，未找到测试证据。 |
