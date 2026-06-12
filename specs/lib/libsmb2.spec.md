# lib/libsmb2.c Specification

## Source Context

- Source: `lib/libsmb2.c`
- Related Headers: `include/smb2/libsmb2.h`, `include/smb2/smb2.h`, `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/compat.h`, `include/slist.h`
- Related Tests: `tests/prog_cat.c`, `tests/prog_cat_cancel.c`, `tests/prog_ls.c`, `tests/prog_mkdir.c`, `tests/prog_rmdir.c`, `tests/metastat-0202-censored.c`
- Related Dependencies: GitNexus context shows `smb2_connect_share_async` calls `asprintf`, `strdup`, `smb2_set_error`, `smb2_set_user`, `free_c_data`, and `smb2_utf8_to_utf16`; `smb2_open_async` delegates to `_smb2_open_async_with_oplock_or_lease`; `smb2_pread_async` calls `smb2_cmd_read_async` and `smb2_queue_pdu`; `smb2_close_context` is called by connection, negotiation, session setup, Dreamcast VFS, and server paths.
- Build/Compile Context: C implementation compiled through CMake/Autotools core library; feature branches depend on `HAVE_CONFIG_H`, standard header probes, `_WIN32`, `_XBOX`, `__AROS__`, `ESP_PLATFORM`, `__PS2__`, `HAVE_LIBKRB5`, and `O_DIRECTORY`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_close_context | function | void smb2_close_context(struct smb2_context *smb2) | Include | 公开上下文关闭入口，释放 socket、重置会话状态和密钥。 |
| smb2_seekdir | function | void smb2_seekdir(struct smb2_context *smb2, struct smb2dir *dir, long loc) | Include | 公开目录游标定位入口，影响后续 `smb2_readdir` 结果。 |
| smb2_telldir | function | long smb2_telldir(struct smb2_context *smb2, struct smb2dir *dir) | Include | 公开目录游标查询入口，定义空目录句柄错误返回。 |
| smb2_rewinddir | function | void smb2_rewinddir(struct smb2_context *smb2, struct smb2dir *dir) | Include | 公开目录游标复位入口。 |
| smb2_readdir | function | struct smb2dirent *smb2_readdir(struct smb2_context *smb2, struct smb2dir *dir) | Include | 公开目录枚举入口，返回当前条目并推进游标。 |
| smb2_closedir | function | void smb2_closedir(struct smb2_context *smb2, struct smb2dir *dir) | Include | 公开目录资源释放入口。 |
| smb2_opendir_async_pdu | function | struct smb2_pdu *smb2_opendir_async_pdu(struct smb2_context *smb2, const char *path, smb2_command_cb cb, void *cb_data, void (*free_cb)(void *)) | Include | 公开异步目录打开 PDU 入口，调用者持有返回 PDU。 |
| smb2_opendir_async | function | int smb2_opendir_async(struct smb2_context *smb2, const char *path, smb2_command_cb cb, void *cb_data) | Include | 公开异步目录打开入口，返回启动状态。 |
| free_c_data | function | extern void free_c_data(struct smb2_context *smb2, struct connect_data *c_data) | Include | 跨文件连接数据释放符号，被连接失败和认证流程调用。 |
| smb2_derive_key | function | void smb2_derive_key(uint8_t *derivation_key, uint32_t derivation_key_len, const char *label, uint32_t label_len, const char *context, uint32_t context_len, uint8_t derived_key[SMB2_KEY_SIZE]) | Include | SMB3 签名和加密密钥派生入口，影响安全材料。 |
| smb2_connect_share_async | function | int smb2_connect_share_async(struct smb2_context *smb2, const char *server, const char *share, const char *user, smb2_command_cb cb, void *cb_data) | Include | 公开异步 share 连接入口，GitNexus impact 为 MEDIUM。 |
| smb2_open_async_pdu | function | struct smb2_pdu *smb2_open_async_pdu(struct smb2_context *smb2, const char *path, int flags, smb2_command_cb cb, void *cb_data, void (*free_cb)(void *)) | Include | 公开异步 open PDU 入口。 |
| smb2_open_async_with_oplock_or_lease | function | int smb2_open_async_with_oplock_or_lease(struct smb2_context *smb2, const char *path, int flags, uint8_t oplock_level, uint32_t lease_state, smb2_lease_key lease_key, smb2_command_cb cb, void *cb_data) | Include | 公开带 oplock/lease 的异步 open 入口。 |
| smb2_open_async | function | int smb2_open_async(struct smb2_context *smb2, const char *path, int flags, smb2_command_cb cb, void *cb_data) | Include | 公开异步 open 入口，被 examples/tests 调用。 |
| smb2_close_async | function | int smb2_close_async(struct smb2_context *smb2, struct smb2fh *fh, smb2_command_cb cb, void *cb_data) | Include | 公开异步 close 入口，负责关闭远端文件句柄。 |
| smb2_fsync_async | function | int smb2_fsync_async(struct smb2_context *smb2, struct smb2fh *fh, smb2_command_cb cb, void *cb_data) | Include | 公开异步 flush 入口。 |
| smb2_pread_async | function | int smb2_pread_async(struct smb2_context *smb2, struct smb2fh *fh, uint8_t *buf, uint32_t count, uint64_t offset, smb2_command_cb cb, void *cb_data) | Include | 公开异步定点读取入口，受最大读尺寸和 credits 限制。 |
| smb2_read_async | function | int smb2_read_async(struct smb2_context *smb2, struct smb2fh *fh, uint8_t *buf, uint32_t count, smb2_command_cb cb, void *cb_data) | Include | 公开基于当前文件偏移读取入口。 |
| smb2_pwrite_async | function | int smb2_pwrite_async(struct smb2_context *smb2, struct smb2fh *fh, const uint8_t *buf, uint32_t count, uint64_t offset, smb2_command_cb cb, void *cb_data) | Include | 公开异步定点写入入口，受最大写尺寸和 credits 限制。 |
| smb2_write_async | function | int smb2_write_async(struct smb2_context *smb2, struct smb2fh *fh, const uint8_t *buf, uint32_t count, smb2_command_cb cb, void *cb_data) | Include | 公开基于当前文件偏移写入入口。 |
| smb2_lseek | function | int64_t smb2_lseek(struct smb2_context *smb2, struct smb2fh *fh, int64_t offset, int whence, uint64_t *current_offset) | Include | 公开同步偏移调整入口。 |
| smb2_unlink_async | function | int smb2_unlink_async(struct smb2_context *smb2, const char *path, smb2_command_cb cb, void *cb_data) | Include | 公开异步文件删除入口。 |
| smb2_rmdir_async | function | int smb2_rmdir_async(struct smb2_context *smb2, const char *path, smb2_command_cb cb, void *cb_data) | Include | 公开异步目录删除入口。 |
| smb2_mkdir_async | function | int smb2_mkdir_async(struct smb2_context *smb2, const char *path, smb2_command_cb cb, void *cb_data) | Include | 公开异步目录创建入口。 |
| smb2_fstat_async | function | int smb2_fstat_async(struct smb2_context *smb2, struct smb2fh *fh, struct smb2_stat_64 *st, smb2_command_cb cb, void *cb_data) | Include | 公开文件句柄属性查询入口。 |
| smb2_stat_async | function | int smb2_stat_async(struct smb2_context *smb2, const char *path, struct smb2_stat_64 *st, smb2_command_cb cb, void *cb_data) | Include | 公开路径属性查询入口。 |
| smb2_statvfs_async | function | int smb2_statvfs_async(struct smb2_context *smb2, const char *path, struct smb2_statvfs *statvfs, smb2_command_cb cb, void *cb_data) | Include | 公开文件系统容量查询入口。 |
| smb2_truncate_async | function | int smb2_truncate_async(struct smb2_context *smb2, const char *path, uint64_t length, smb2_command_cb cb, void *cb_data) | Include | 公开路径截断入口。 |
| smb2_rename_async | function | int smb2_rename_async(struct smb2_context *smb2, const char *oldpath, const char *newpath, smb2_command_cb cb, void *cb_data) | Include | 公开路径重命名入口。 |
| smb2_ftruncate_async | function | int smb2_ftruncate_async(struct smb2_context *smb2, struct smb2fh *fh, uint64_t length, smb2_command_cb cb, void *cb_data) | Include | 公开文件句柄截断入口。 |
| smb2_readlink_async | function | int smb2_readlink_async(struct smb2_context *smb2, const char *path, smb2_command_cb cb, void *cb_data) | Include | 公开 reparse point/symlink 读取入口。 |
| smb2_disconnect_share_async | function | int smb2_disconnect_share_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data) | Include | 公开异步 share 断开入口。 |
| smb2_echo_async | function | int smb2_echo_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data) | Include | 公开 echo 探测入口。 |
| smb2_get_max_read_size | function | uint32_t smb2_get_max_read_size(struct smb2_context *smb2) | Include | 公开读取上限查询入口。 |
| smb2_get_max_write_size | function | uint32_t smb2_get_max_write_size(struct smb2_context *smb2) | Include | 公开写入上限查询入口。 |
| smb2_get_file_id | function | smb2_file_id *smb2_get_file_id(struct smb2fh *fh) | Include | 公开从文件句柄取得 file id 的入口。 |
| smb2_fh_from_file_id | function | struct smb2fh *smb2_fh_from_file_id(struct smb2_context *smb2, smb2_file_id *fileid) | Include | 公开从 file id 构造文件句柄入口。 |
| smb2_fd_event_callbacks | function | void smb2_fd_event_callbacks(struct smb2_context *smb2, smb2_change_fd_cb change_fd, smb2_change_events_cb change_events) | Include | 公开事件系统回调注册入口。 |
| smb2_oplock_break_notify | function | void smb2_oplock_break_notify(struct smb2_context *smb2, int status, void *command_data, void *cb_data) | Include | 公开 oplock/lease break 通知处理入口。 |
| smb2_decode_filenotifychangeinformation | function | int smb2_decode_filenotifychangeinformation(struct smb2_context *smb2, struct smb2_file_notify_change_information *fnc, struct smb2_iovec *vec, uint32_t next_entry_offset) | Include | 公开变更通知解码入口，构造链表结果。 |
| free_smb2_file_notify_change_information | function | void free_smb2_file_notify_change_information(struct smb2_context *smb2, struct smb2_file_notify_change_information *fnc) | Include | 公开变更通知链表释放入口。 |
| smb2_notify_change_filehandle_async | function | int smb2_notify_change_filehandle_async(struct smb2_context *smb2, struct smb2fh *smb2_dir_fh, uint16_t flags, uint32_t filter, int loop, smb2_command_cb cb, void *cb_data) | Include | 公开基于目录句柄的变更通知入口。 |
| smb2_notify_change_async | function | int smb2_notify_change_async(struct smb2_context *smb2, const char *path, uint16_t flags, uint32_t filter, int loop, smb2_command_cb cb, void *cb_data) | Include | 公开基于路径的变更通知入口。 |
| smb2_serve_port_async | function | int smb2_serve_port_async(const int fd, const int to_msecs, struct smb2_context **smb2) | Include | 公开服务端异步 accept 入口。 |
| smb2_serve_port | function | int smb2_serve_port(struct smb2_server *server, const int max_connections, smb2_client_connection cb, void *cb_data) | Include | 公开同步服务端循环入口。 |
| decode_dirents | function | static int decode_dirents(struct smb2_context *smb2, struct smb2dir *dir, struct smb2_iovec *vec) | Skip | 内部目录 reply 解码 helper，通过 opendir/readdir 契约体现。 |
| _smb2_opendir_async | function | static struct smb2_pdu *_smb2_opendir_async(struct smb2_context *smb2, const char *path, smb2_command_cb cb, void *cb_data, void (*free_cb)(void *), int caller_frees_pdu) | Skip | 内部转调 helper，外部契约由 `smb2_opendir_async_pdu` 和 `smb2_opendir_async` 覆盖。 |
| _smb2_open_async_with_oplock_or_lease | function | static struct smb2_pdu *_smb2_open_async_with_oplock_or_lease(struct smb2_context *smb2, const char *path, int flags, uint8_t oplock_level, uint32_t lease_state, smb2_lease_key lease_key, smb2_command_cb cb, void *cb_data, void (*free_cb)(void *), int caller_frees_pdu) | Skip | 内部 open 构造 helper，外部契约由公开 open 接口覆盖。 |
| smb2_getinfo_async | function | static int smb2_getinfo_async(struct smb2_context *smb2, const char *path, uint8_t info_type, uint8_t file_info_class, void *st, smb2_command_cb cb, void *cb_data) | Skip | 内部 stat/statvfs 共用 helper，外部契约由公开查询接口覆盖。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| DEFAULT_OUTPUT_BUFFER_LENGTH | macro | lib/libsmb2.c:114 | 平台相关默认输出缓冲区，ESP 为 512，PS2 为 4096，其他平台为 0xffff。 |
| compound_file_id | constant | lib/libsmb2.c:138 | 全 0xff compound file id，用于 compound 链后续 PDU 引用前序 create 结果。 |
| struct connect_data | struct | lib/libsmb2.c:143 | 连接、认证和 tree connect 异步链的私有状态。 |
| struct smb2fh | struct | lib/libsmb2.c:161 | 文件句柄内部状态，保存 file id、当前偏移和打开时 EOF。 |
| struct smb2dir | struct | include/libsmb2-private.h | 目录枚举内部状态，公开为不透明 `struct smb2dir`。 |
| struct smb2dirent | struct | include/smb2/libsmb2.h:107 | 目录枚举返回的名称和 stat 信息。 |
| struct smb2_stat_64 | struct | include/smb2/libsmb2.h:78 | stat/fstat/path 查询填充的公开属性模型。 |
| struct smb2_statvfs | struct | include/smb2/libsmb2.h:93 | statvfs 填充的公开文件系统容量模型。 |
| struct smb2_read_cb_data | struct | include/smb2/libsmb2.h:854 | read/pread 回调 command_data。 |
| struct smb2_write_cb_data | struct | include/smb2/libsmb2.h:861 | write/pwrite 回调 command_data。 |
| struct smb2_file_notify_change_information | struct | include/smb2/smb2.h:1079 | notify change 解码后的链表节点。 |

## ADDED Requirements

### Requirement: smb2_close_context reset connection state
系统 MUST 在输入为 `NULL` 时直接返回；在 socket 有效时关闭 fd、通知 `change_fd` 删除事件、重置 session/tree 标识、清空 signing key，并释放 `session_key`。

#### Scenario: close null context
- **GIVEN** 调用方传入 `NULL` 上下文
- **WHEN** 调用 `smb2_close_context`
- **THEN** 函数返回且不访问上下文字段

Trace: `lib/libsmb2.c:smb2_close_context`

#### Scenario: close active context
- **GIVEN** 上下文包含有效 socket 和非空 `session_key`
- **WHEN** 调用 `smb2_close_context`
- **THEN** socket 被关闭，`fd` 设为 `SMB2_INVALID_SOCKET`，session/tree 状态复位，`session_key` 被释放并置空

Trace: `lib/libsmb2.c:smb2_close_context`

### Requirement: smb2_seekdir move directory cursor
系统 MUST 在 `dir == NULL` 时直接返回；否则从目录头开始移动 `loc` 个条目并同步 `index`。

#### Scenario: seek directory cursor
- **GIVEN** 目录对象包含条目链表且 `loc` 为非负值
- **WHEN** 调用 `smb2_seekdir`
- **THEN** `current_entry` 指向从头跳过 `loc` 个节点后的位置，`index` 记录实际跳过数量

Trace: `lib/libsmb2.c:smb2_seekdir`

### Requirement: smb2_telldir report directory cursor
系统 MUST 在 `dir == NULL` 时返回 `-EINVAL`；否则返回目录对象当前 `index`。

#### Scenario: tell directory cursor
- **GIVEN** 目录对象当前 `index` 已由 seek/read/rewind 更新
- **WHEN** 调用 `smb2_telldir`
- **THEN** 返回值等于目录对象当前 `index`

Trace: `lib/libsmb2.c:smb2_telldir`

### Requirement: smb2_rewinddir reset directory cursor
系统 MUST 在 `dir == NULL` 时直接返回；否则把 `current_entry` 重置到条目链表头并把 `index` 设为 0。

#### Scenario: rewind directory cursor
- **GIVEN** 目录对象已被读取到非起始位置
- **WHEN** 调用 `smb2_rewinddir`
- **THEN** 下一次 `smb2_readdir` 从首个条目返回

Trace: `lib/libsmb2.c:smb2_rewinddir`

### Requirement: smb2_readdir return current entry and advance
系统 MUST 在目录为空或游标为空时返回 `NULL`；否则返回当前 `struct smb2dirent *` 并将游标推进到下一节点。

#### Scenario: read next directory entry
- **GIVEN** 目录对象的 `current_entry` 指向有效节点
- **WHEN** 调用 `smb2_readdir`
- **THEN** 返回该节点的 `dirent`，且目录 `index` 增加 1

Trace: `lib/libsmb2.c:smb2_readdir`

### Requirement: smb2_closedir release directory resources
系统 MUST 在 `smb2 == NULL` 或 `dir == NULL` 时直接返回；否则释放目录条目名称、条目节点、可选 cb_data 和目录对象。

#### Scenario: close populated directory
- **GIVEN** 目录对象包含内部条目链表和可选释放回调
- **WHEN** 调用 `smb2_closedir`
- **THEN** 目录关联内存被释放且不会发起网络请求

Trace: `lib/libsmb2.c:smb2_closedir`

### Requirement: smb2_opendir_async_pdu start cancellable directory open
系统 MUST 使用目录 create 请求打开 `path`，随后查询目录并在完成后通过回调返回 `struct smb2dir` 或负 errno。

#### Scenario: opendir pdu starts request
- **GIVEN** 有效上下文、路径和回调
- **WHEN** 调用 `smb2_opendir_async_pdu`
- **THEN** 返回排队后的 PDU，且 PDU 标记为调用方释放

Trace: `lib/libsmb2.c:smb2_opendir_async_pdu`

### Requirement: smb2_opendir_async start directory open
系统 MUST 通过内部 opendir 构造函数启动目录 open/query/close 链，并以 0 表示启动成功、以 -1 表示启动失败。

#### Scenario: opendir async starts request
- **GIVEN** 有效上下文和回调
- **WHEN** 调用 `smb2_opendir_async`
- **THEN** 函数返回 0 表示 PDU 已排队

Trace: `lib/libsmb2.c:smb2_opendir_async`

### Requirement: free_c_data release connection data
系统 MUST 释放认证上下文、UNC 缓冲区、server/share/user 副本和连接数据本体；若当前上下文指向该连接数据，则清空 `smb2->connect_data`。

#### Scenario: free active connect data
- **GIVEN** `smb2->connect_data` 指向待释放的 `connect_data`
- **WHEN** 调用 `free_c_data`
- **THEN** 认证和字符串资源被释放，且上下文不再保留悬挂指针

Trace: `lib/libsmb2.c:free_c_data`

### Requirement: smb2_derive_key produce SMB key material
系统 MUST 使用给定 derivation key、label、context 和 SMB2 key bit length 通过 HMAC-SHA256 派生 `SMB2_KEY_SIZE` 字节输出。

#### Scenario: derive fixed size key
- **GIVEN** 调用方提供 derivation key、label、context 和 `derived_key` 输出数组
- **WHEN** 调用 `smb2_derive_key`
- **THEN** `derived_key` 包含 HMAC-SHA256 digest 的前 `SMB2_KEY_SIZE` 字节

Trace: `lib/libsmb2.c:smb2_derive_key`

### Requirement: smb2_connect_share_async establish share connection
系统 MUST 校验上下文、server、share 和用户状态，保存 server/share/user 副本，构造 UTF-8/UTF-16 UNC，并启动 TCP connect 到 negotiate/session/tree connect 链。

#### Scenario: reject missing server or share
- **GIVEN** 有效上下文但 `server == NULL` 或 `share == NULL`
- **WHEN** 调用 `smb2_connect_share_async`
- **THEN** 函数设置错误字符串并返回 `-EINVAL`

Trace: `lib/libsmb2.c:smb2_connect_share_async`, `tests/prog_cat.c:main`

#### Scenario: start share connection
- **GIVEN** 有效上下文、server、share、用户和回调
- **WHEN** 调用 `smb2_connect_share_async`
- **THEN** 函数返回 0，后续连接结果通过回调报告

Trace: `lib/libsmb2.c:smb2_connect_share_async`, `tests/prog_cat_cancel.c:main`

### Requirement: smb2_open_async_pdu start cancellable file open
系统 MUST 将 POSIX flags 映射为 SMB2 create disposition、access 和 create options，并返回调用方释放的 PDU 或 `NULL`。

#### Scenario: open pdu maps flags
- **GIVEN** 调用方传入 `O_CREAT`、`O_EXCL`、访问模式和路径
- **WHEN** 调用 `smb2_open_async_pdu`
- **THEN** create 请求按 flags 选择 `SMB2_FILE_CREATE`/open 行为并排队

Trace: `lib/libsmb2.c:smb2_open_async_pdu`

### Requirement: smb2_open_async_with_oplock_or_lease request lease aware open
系统 MUST 使用调用方提供的 oplock level、lease state 和 lease key 构造 create 请求，并以 0/-1 报告启动结果。

#### Scenario: open with lease context
- **GIVEN** `lease_state` 非零且 `lease_key` 非空
- **WHEN** 调用 `smb2_open_async_with_oplock_or_lease`
- **THEN** create context 包含 lease key 和 lease state，且请求被排队

Trace: `lib/libsmb2.c:smb2_open_async_with_oplock_or_lease`

### Requirement: smb2_open_async start normal file open
系统 MUST 使用 `SMB2_OPLOCK_LEVEL_NONE` 且无 lease context 启动文件 open，并以 0/-1 报告启动结果。

#### Scenario: open async starts request
- **GIVEN** 有效上下文、路径、flags 和回调
- **WHEN** 调用 `smb2_open_async`
- **THEN** 函数委托内部 open 构造函数并返回启动状态

Trace: `lib/libsmb2.c:smb2_open_async`, `tests/prog_cat.c:cf_cb`

### Requirement: smb2_close_async close file handle
系统 MUST 拒绝空上下文或空文件句柄；否则使用句柄 file id 发送 close 请求并在回调中释放句柄。

#### Scenario: close valid handle
- **GIVEN** 有效上下文和文件句柄
- **WHEN** 调用 `smb2_close_async`
- **THEN** close PDU 被排队，回调收到 0 或负 errno，文件句柄随后释放

Trace: `lib/libsmb2.c:smb2_close_async`

### Requirement: smb2_fsync_async flush file handle
系统 MUST 拒绝空上下文或空文件句柄；否则发送 flush 请求并通过回调返回 0 或负 errno。

#### Scenario: flush valid handle
- **GIVEN** 有效上下文和文件句柄
- **WHEN** 调用 `smb2_fsync_async`
- **THEN** flush PDU 使用句柄 file id 排队

Trace: `lib/libsmb2.c:smb2_fsync_async`

### Requirement: smb2_pread_async read bounded data at offset
系统 MUST 拒绝空上下文或空文件句柄；否则按 `max_read_size`、dialect 和 credits 裁剪 count，并发送 read 请求。

#### Scenario: pread clamps request length
- **GIVEN** 请求 count 大于 server 最大读尺寸或当前 credits 支撑尺寸
- **WHEN** 调用 `smb2_pread_async`
- **THEN** SMB2 read 请求长度被裁剪到实现允许的最大值

Trace: `lib/libsmb2.c:smb2_pread_async`, `tests/prog_cat.c:pr_cb`

### Requirement: smb2_read_async read at current handle offset
系统 MUST 使用文件句柄当前 `offset` 调用 `smb2_pread_async`，并保留其返回语义。

#### Scenario: read delegates to pread
- **GIVEN** 文件句柄当前偏移为 N
- **WHEN** 调用 `smb2_read_async`
- **THEN** 读请求以 offset N 发起，成功回调后内部偏移按实际读取字节数更新

Trace: `lib/libsmb2.c:smb2_read_async`

### Requirement: smb2_pwrite_async write bounded data at offset
系统 MUST 拒绝空上下文或空文件句柄；否则按 `max_write_size`、dialect 和 credits 裁剪 count，并发送 write 请求。

#### Scenario: pwrite clamps request length
- **GIVEN** 请求 count 大于 server 最大写尺寸或当前 credits 支撑尺寸
- **WHEN** 调用 `smb2_pwrite_async`
- **THEN** SMB2 write 请求长度被裁剪到实现允许的最大值

Trace: `lib/libsmb2.c:smb2_pwrite_async`

### Requirement: smb2_write_async write at current handle offset
系统 MUST 使用文件句柄当前 `offset` 调用 `smb2_pwrite_async`，并保留其返回语义。

#### Scenario: write delegates to pwrite
- **GIVEN** 文件句柄当前偏移为 N
- **WHEN** 调用 `smb2_write_async`
- **THEN** 写请求以 offset N 发起，成功回调后内部偏移按实际写入字节数更新

Trace: `lib/libsmb2.c:smb2_write_async`

### Requirement: smb2_lseek update handle offset
系统 MUST 支持 `SEEK_SET`、`SEEK_CUR` 和 `SEEK_END`，拒绝负结果偏移和未知 whence，并在提供输出指针时写入当前偏移。

#### Scenario: reject negative lseek
- **GIVEN** 文件句柄当前偏移和输入 offset 组合产生负值
- **WHEN** 调用 `smb2_lseek`
- **THEN** 函数设置错误字符串并返回 `-EINVAL`

Trace: `lib/libsmb2.c:smb2_lseek`

### Requirement: smb2_unlink_async delete file by path
系统 MUST 通过 compound create/delete-on-close/close 链启动文件删除，并以 0 或负 errno 报告启动状态。

#### Scenario: unlink starts compound request
- **GIVEN** 有效上下文、路径和回调
- **WHEN** 调用 `smb2_unlink_async`
- **THEN** create 请求使用 `SMB2_FILE_DELETE_ON_CLOSE` 且非目录属性

Trace: `lib/libsmb2.c:smb2_unlink_async`

### Requirement: smb2_rmdir_async delete directory by path
系统 MUST 通过 compound create/delete-on-close/close 链启动目录删除，并以 0 或负 errno 报告启动状态。

#### Scenario: rmdir starts compound request
- **GIVEN** 有效上下文、路径和回调
- **WHEN** 调用 `smb2_rmdir_async`
- **THEN** create 请求使用目录属性和 `SMB2_FILE_DELETE_ON_CLOSE`

Trace: `lib/libsmb2.c:smb2_rmdir_async`

### Requirement: smb2_mkdir_async create directory by path
系统 MUST 通过 compound create/close 链创建目录，并在 close 回调中报告最终状态。

#### Scenario: mkdir starts compound request
- **GIVEN** 有效上下文、路径和回调
- **WHEN** 调用 `smb2_mkdir_async`
- **THEN** create 请求使用 `SMB2_FILE_CREATE` 和 `SMB2_FILE_DIRECTORY_FILE`

Trace: `lib/libsmb2.c:smb2_mkdir_async`

### Requirement: smb2_fstat_async query handle attributes
系统 MUST 使用文件句柄 file id 发送 `SMB2_FILE_ALL_INFORMATION` 查询，并把 reply 转换为 `struct smb2_stat_64`。

#### Scenario: fstat fills stat object
- **GIVEN** 有效上下文、文件句柄和 `struct smb2_stat_64` 输出
- **WHEN** 调用 `smb2_fstat_async`
- **THEN** 成功回调返回 status 0 且输出包含类型、大小、inode、link count 和时间字段

Trace: `lib/libsmb2.c:smb2_fstat_async`

### Requirement: smb2_stat_async query path attributes
系统 MUST 通过 compound create/query-info/close 链查询路径的 `SMB2_FILE_ALL_INFORMATION` 并填充 `struct smb2_stat_64`。

#### Scenario: stat path fills stat object
- **GIVEN** 有效上下文、路径和 stat 输出对象
- **WHEN** 调用 `smb2_stat_async`
- **THEN** 查询链被排队，最终回调带有 0 或负 errno

Trace: `lib/libsmb2.c:smb2_stat_async`

### Requirement: smb2_statvfs_async query filesystem capacity
系统 MUST 通过 compound create/query-info/close 链查询 `SMB2_FILE_FS_FULL_SIZE_INFORMATION` 并填充 `struct smb2_statvfs`。

#### Scenario: statvfs fills capacity fields
- **GIVEN** 有效上下文、路径和 statvfs 输出对象
- **WHEN** 调用 `smb2_statvfs_async`
- **THEN** 成功路径设置 block size、fragment size、total blocks、free blocks 和 available blocks

Trace: `lib/libsmb2.c:smb2_statvfs_async`

### Requirement: smb2_truncate_async set path EOF
系统 MUST 通过 compound create/set-info/close 链把路径 EOF 设置为调用方给定 length。

#### Scenario: truncate path starts set-info chain
- **GIVEN** 有效上下文、路径、length 和回调
- **WHEN** 调用 `smb2_truncate_async`
- **THEN** set-info 请求使用 `SMB2_FILE_END_OF_FILE_INFORMATION` 和给定 length

Trace: `lib/libsmb2.c:smb2_truncate_async`

### Requirement: smb2_rename_async rename path
系统 MUST 把新路径中的 `/` 转换为 `\`，通过 compound create/set-info/close 链提交 `SMB2_FILE_RENAME_INFORMATION`。

#### Scenario: rename normalizes new path separators
- **GIVEN** 新路径包含 `/`
- **WHEN** 调用 `smb2_rename_async`
- **THEN** set-info 请求中的 file_name 使用反斜杠分隔符

Trace: `lib/libsmb2.c:smb2_rename_async`

### Requirement: smb2_ftruncate_async set handle EOF
系统 MUST 使用文件句柄 file id 发送 `SMB2_FILE_END_OF_FILE_INFORMATION` set-info 请求。

#### Scenario: ftruncate handle starts set-info
- **GIVEN** 有效上下文、文件句柄和 length
- **WHEN** 调用 `smb2_ftruncate_async`
- **THEN** set-info PDU 被排队，回调返回转换后的 NT status

Trace: `lib/libsmb2.c:smb2_ftruncate_async`

### Requirement: smb2_readlink_async read reparse target
系统 MUST 打开 reparse point、发送 `SMB2_FSCTL_GET_REPARSE_POINT` ioctl、关闭句柄，并在回调中返回 symlink subname 或错误。

#### Scenario: readlink returns symlink target
- **GIVEN** 路径指向 symlink reparse point
- **WHEN** 调用 `smb2_readlink_async`
- **THEN** 成功回调的 command_data 指向 symlink subname

Trace: `lib/libsmb2.c:smb2_readlink_async`

### Requirement: smb2_disconnect_share_async disconnect tree and session
系统 MUST 拒绝空上下文和未连接 socket；否则发送 tree disconnect，再发送 logoff，最后关闭 socket 并通知 fd 删除。

#### Scenario: reject disconnected context
- **GIVEN** 上下文 fd 无效
- **WHEN** 调用 `smb2_disconnect_share_async`
- **THEN** 函数设置错误字符串并返回 `-EINVAL`

Trace: `lib/libsmb2.c:smb2_disconnect_share_async`

### Requirement: smb2_echo_async send echo request
系统 MUST 拒绝空上下文；否则分配 echo 回调状态、发送 echo PDU，并通过回调返回转换后的 NT status。

#### Scenario: echo starts request
- **GIVEN** 有效上下文和回调
- **WHEN** 调用 `smb2_echo_async`
- **THEN** echo PDU 被排队且函数返回 0

Trace: `lib/libsmb2.c:smb2_echo_async`

### Requirement: smb2_get_max_read_size return negotiated read size
系统 MUST 返回上下文中的 `max_read_size` 字段值。

#### Scenario: get max read size
- **GIVEN** 上下文已完成 negotiate 并记录 max read size
- **WHEN** 调用 `smb2_get_max_read_size`
- **THEN** 返回值等于 `smb2->max_read_size`

Trace: `lib/libsmb2.c:smb2_get_max_read_size`

### Requirement: smb2_get_max_write_size return negotiated write size
系统 MUST 返回上下文中的 `max_write_size` 字段值。

#### Scenario: get max write size
- **GIVEN** 上下文已完成 negotiate 并记录 max write size
- **WHEN** 调用 `smb2_get_max_write_size`
- **THEN** 返回值等于 `smb2->max_write_size`

Trace: `lib/libsmb2.c:smb2_get_max_write_size`

### Requirement: smb2_get_file_id expose handle file id
系统 MUST 返回文件句柄内部 `file_id` 数组地址。

#### Scenario: get file id pointer
- **GIVEN** 有效文件句柄
- **WHEN** 调用 `smb2_get_file_id`
- **THEN** 返回指针引用该句柄内部 file id

Trace: `lib/libsmb2.c:smb2_get_file_id`

### Requirement: smb2_fh_from_file_id create handle from file id
系统 MUST 分配新 `struct smb2fh`，复制调用方提供的 file id，并在分配失败时返回 `NULL`。

#### Scenario: create handle from file id
- **GIVEN** 有效 file id
- **WHEN** 调用 `smb2_fh_from_file_id`
- **THEN** 返回的新句柄包含相同 file id

Trace: `lib/libsmb2.c:smb2_fh_from_file_id`

### Requirement: smb2_fd_event_callbacks register event callbacks
系统 MUST 把调用方提供的 fd 变更和 events 变更回调保存到上下文。

#### Scenario: register callbacks
- **GIVEN** 有效上下文和两个回调函数指针
- **WHEN** 调用 `smb2_fd_event_callbacks`
- **THEN** 后续 fd/event 变化路径使用这些回调

Trace: `lib/libsmb2.c:smb2_fd_event_callbacks`

### Requirement: smb2_oplock_break_notify acknowledge breaks when not passthrough
系统 MUST 先调用应用 oplock/lease break 回调；在非 passthrough 且 status 为 0 时，根据 break 类型发送对应 acknowledgement PDU。

#### Scenario: acknowledge lease break notification
- **GIVEN** 非 passthrough 上下文收到 lease break notification
- **WHEN** 调用 `smb2_oplock_break_notify`
- **THEN** 使用应用返回的新 lease state 排队 lease break reply

Trace: `lib/libsmb2.c:smb2_oplock_break_notify`

### Requirement: smb2_decode_filenotifychangeinformation decode notify chain
系统 MUST 从 iovec 中读取 action/name，并在 `next_entry_offset` 指向后续记录时递归分配并解码 `next` 节点。

#### Scenario: decode chained notify entries
- **GIVEN** notify buffer 包含非零 next entry offset
- **WHEN** 调用 `smb2_decode_filenotifychangeinformation`
- **THEN** 当前节点被填充且 `next` 指向后续解码节点

Trace: `lib/libsmb2.c:smb2_decode_filenotifychangeinformation`

### Requirement: free_smb2_file_notify_change_information free notify chain
系统 MUST 递归释放 `next` 链、每个节点的 name 和节点本体。

#### Scenario: free notify chain
- **GIVEN** notify change 链包含多个节点
- **WHEN** 调用 `free_smb2_file_notify_change_information`
- **THEN** 所有节点和名称缓冲区被释放

Trace: `lib/libsmb2.c:free_smb2_file_notify_change_information`

### Requirement: smb2_notify_change_filehandle_async request change notification
系统 MUST 为目录文件句柄发送 change notify 请求，保存 flags、filter、loop 和回调状态，并在 loop 非零时继续提交下一次通知请求。

#### Scenario: notify filehandle starts request
- **GIVEN** 有效目录句柄、过滤器和回调
- **WHEN** 调用 `smb2_notify_change_filehandle_async`
- **THEN** change notify PDU 使用目录 file id 排队

Trace: `lib/libsmb2.c:smb2_notify_change_filehandle_async`

### Requirement: smb2_notify_change_async open path then notify
系统 MUST 先同步打开目录路径，再把得到的文件句柄交给 `smb2_notify_change_filehandle_async`。

#### Scenario: notify path opens directory
- **GIVEN** 有效上下文和路径
- **WHEN** 调用 `smb2_notify_change_async`
- **THEN** 打开成功后基于该句柄启动 change notify；打开失败时返回 -1 并设置错误字符串

Trace: `lib/libsmb2.c:smb2_notify_change_async`

### Requirement: smb2_serve_port_async accept one connection
系统 MUST 调用 `smb2_accept_connection_async`，并在 accept 回调中为新 fd 分配 `smb2_context`、设置 fd、写入输出指针。

#### Scenario: accept connection creates context
- **GIVEN** 监听 fd 和输出上下文指针
- **WHEN** 调用 `smb2_serve_port_async`
- **THEN** 成功 accept 后输出指针引用新上下文

Trace: `lib/libsmb2.c:smb2_serve_port_async`

### Requirement: smb2_serve_port run server event loop
系统 MUST 初始化服务端默认尺寸、GUID、hostname 和 domain，监听端口，处理客户端上下文事件，执行 server handlers，并在退出时关闭监听 fd 和销毁活动上下文。

#### Scenario: serve port handles accepted client
- **GIVEN** 服务端配置和连接回调
- **WHEN** `smb2_serve_port` 的 select 循环发现监听 fd 可读
- **THEN** 新客户端上下文被创建、分配初始 negotiate PDU，并调用连接回调

Trace: `lib/libsmb2.c:smb2_serve_port`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_pread_async` 和 `smb2_pwrite_async` 在 `count == 0` 时会计算 `(count - 1)`，零长度请求语义是否由调用方禁止？ | smb2_pread_async`, `smb2_pwrite_async | 头文件未声明零长度前置条件，源码存在无符号下溢风险。 |
| Q-002 | `smb2_notify_change_filehandle_async` 未显式校验 `smb2 == NULL` 或 `smb2_dir_fh == NULL`，该前置条件是否由 public API 文档承担？ | smb2_notify_change_filehandle_async | 源码直接访问上下文和文件句柄字段。 |
| Q-003 | `smb2_readlink_async` 在非 symlink reparse tag 成功路径返回字符串 `"<unknown reparse point type>"`，调用方是否依赖该固定文本？ | smb2_readlink_async | 源码定义固定字符串，但头文件只说明 link content。 |
| Q-004 | `smb2_serve_port` 的事件循环退出条件和错误码是否需要区分监听错误、客户端错误和 Kerberos renewal 错误？ | smb2_serve_port | 源码以单个 `err` 变量汇总多类退出原因。 |
