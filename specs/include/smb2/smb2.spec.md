# include/smb2/smb2.h Specification

## Source Context

- Source: `include/smb2/smb2.h`
- Related Headers: `include/smb2/smb2-errors.h`
- Related Tests: `examples/smb2-CMD-FIND.c` as example evidence for `smb2_decode_fileidfulldirectoryinformation`; no GitNexus test callers reported for header declarations.
- Related Dependencies: GitNexus `context -r libsmb2` found header declarations for `smb2_get_file_id`, `smb2_fh_from_file_id`, `smb2_decode_fileidfulldirectoryinformation`, and `smb2_decode_filenotifychangeinformation`; implementation evidence is in `lib/libsmb2.c` and `lib/smb2-cmd-query-directory.c`.
- Build/Compile Context: C public header guarded by `_SMB2_H_`, optionally includes `<stdint.h>` under `HAVE_STDINT_H` and `<time.h>` under `HAVE_TIME_H`, and exposes `extern "C"` linkage for C++ callers.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_get_file_id | function | smb2_file_id *smb2_get_file_id(struct smb2fh *fh); | Include | 公开文件句柄访问器，调用方可观察返回的 file id 指针。 |
| smb2_fh_from_file_id | function | struct smb2fh *smb2_fh_from_file_id(struct smb2_context *smb2, smb2_file_id *fileid); | Include | 公开文件句柄构造入口，涉及分配失败和 file id 复制语义。 |
| smb2_decode_fileidfulldirectoryinformation | function | int smb2_decode_fileidfulldirectoryinformation( struct smb2_context *smb2, struct smb2_fileidfulldirectoryinformation *fs, struct smb2_iovec *vec); | Include | 公开目录项解码入口，涉及输入缓冲区边界、时间戳转换和 UTF-16 名称转换。 |
| smb2_decode_filenotifychangeinformation | function | int smb2_decode_filenotifychangeinformation( struct smb2_context *smb2, struct smb2_file_notify_change_information *fnc, struct smb2_iovec *vec, uint32_t next_entry_offset); | Include | 公开变更通知解码入口，涉及链式记录递归解码和名称转换。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| smb2_timeval | struct | include/smb2/smb2.h:36 | 公开秒和微秒时间表示，用于目录项、文件信息和文件系统信息结构。 |
| smb2_guid | typedef | include/smb2/smb2.h:115 | `SMB2_GUID_SIZE` 为 16 字节，供协商和对象 ID 结构复用。 |
| smb2_file_id | typedef | include/smb2/smb2.h:345 | `SMB2_FD_SIZE` 为 16 字节，标识 SMB2 文件句柄。 |
| smb2_lease_key | typedef | include/smb2/smb2.h:348 | `SMB2_LEASE_KEY_SIZE` 为 16 字节，标识 lease break 关联键。 |
| smb2_command | enum | include/smb2/smb2.h:57 | 定义 SMB2/SMB1 命令编号，例如 NEGOTIATE、READ、WRITE 和 SMB1_NEGOTIATE。 |
| SMB2_FLAGS_* | macro | include/smb2/smb2.h:49 | SMB2 header flags，包括 server-to-redir、async、signed、DFS 和 replay 位。 |
| SMB2_*_REQUEST_SIZE / SMB2_*_REPLY_SIZE | macro | include/smb2/smb2.h:40 | 协议结构固定尺寸常量，覆盖 negotiate、session setup、tree connect、create、close、read、write、ioctl、notify、oplock/lease 等请求或响应。 |
| smb2_negotiate_request / smb2_negotiate_reply | struct | include/smb2/smb2.h:117 | SMB2 negotiate 请求和响应数据模型，包含 dialect、capabilities、GUID、上下文和安全缓冲区字段。 |
| smb2_session_setup_request / smb2_session_setup_reply | struct | include/smb2/smb2.h:158 | SMB2 session setup 请求和响应数据模型，包含 flags、security mode、capabilities、session id 和安全缓冲区字段。 |
| smb2_tree_connect_request / smb2_tree_connect_reply | struct | include/smb2/smb2.h:185 | SMB2 tree connect 请求和响应数据模型，包含路径、share type、share flags、capabilities 和 maximal access。 |
| smb2_create_request / smb2_create_reply | struct | include/smb2/smb2.h:324 | SMB2 create 请求和响应数据模型，包含 name、access masks、attributes、disposition、options、create context 和 file id。 |
| smb2_close_request / smb2_close_reply | struct | include/smb2/smb2.h:382 | SMB2 close 请求和响应数据模型，包含 file id、flags 和关闭后属性字段。 |
| smb2_fileidfulldirectoryinformation / smb2_fileidbothdirectoryinformation | struct | include/smb2/smb2.h:440 | 目录枚举项数据模型，包含时间戳、大小、属性、file id 和名称字段。 |
| smb2_read_request / smb2_read_reply | struct | include/smb2/smb2.h:511 | SMB2 read 请求和响应数据模型，包含 offset、length、file id、channel、buffer 和返回数据。 |
| smb2_query_info_request / smb2_query_info_reply | struct | include/smb2/smb2.h:672 | SMB2 query info 请求和响应数据模型，包含 info type、file info class、buffer、flags、file id 和输出缓冲区。 |
| smb2_file_*_info | struct | include/smb2/smb2.h:612 | 文件基础、标准、流、位置、名称、all、EOF、disposition、rename、network open 等信息数据模型。 |
| smb2_sid / smb2_ace / smb2_acl / smb2_security_descriptor | struct | include/smb2/smb2.h:744 | 安全描述符数据模型，包含 SID、ACE、ACL 和 security descriptor 字段及相关控制 flag。 |
| smb2_file_fs_*_info | struct | include/smb2/smb2.h:858 | 文件系统 volume、size、attribute、device、control、full size、object id 和 sector size 信息模型。 |
| smb2_ioctl_request / smb2_ioctl_reply | struct | include/smb2/smb2.h:1003 | SMB2 ioctl 请求和响应数据模型，包含 ctl code、file id、input/output offsets/counts、flags 和缓冲区指针。 |
| smb2_reparse_data_buffer / smb2_symlink_reparse_buffer | struct | include/smb2/smb2.h:985 | reparse point 和 symlink 数据模型，包含 tag、长度、flags、subname 和 printname。 |
| smb2_change_notify_request / smb2_change_notify_reply / smb2_file_notify_change_information | struct | include/smb2/smb2.h:1064 | change notify 请求、响应和链式通知项模型，包含过滤器、输出缓冲区、action、name 和 next。 |
| smb2_oplock_or_lease_break_request / smb2_oplock_or_lease_break_reply | struct | include/smb2/smb2.h:1164 | oplock 和 lease break request/reply 联合模型，携带 break type 和对应 lock 数据。 |
| smb2_write_request / smb2_write_reply | struct | include/smb2/smb2.h:1191 | SMB2 write 请求和响应数据模型，包含 data offset、length、offset、buffer、file id、channel 和 flags。 |
| smb2_lock_element / smb2_lock_request | struct | include/smb2/smb2.h:1214 | SMB2 lock 元素和请求数据模型，包含 offset、length、flags、sequence 和 file id。 |
| SMB2_* flags/constants | macro | include/smb2/smb2.h:84 | 协商、安全、share、create、file attribute、query info、ioctl、notify、oplock、lease、write、lock 等协议常量按头文件数值公开。 |

## ADDED Requirements

### Requirement: smb2_get_file_id expose handle file identifier
系统 MUST 将调用方提供的 `struct smb2fh *fh` 映射为该句柄内部 `smb2_file_id` 存储的地址，并将该指针返回给调用方。

#### Scenario: 返回句柄内部 file id 指针
- **GIVEN** 调用方持有一个有效的 `struct smb2fh *fh`
- **WHEN** 调用方调用 `smb2_get_file_id(fh)`
- **THEN** 返回值 MUST 指向该 `fh` 内部的 `file_id` 字段，而不是返回拷贝或新分配对象

Trace: `include/smb2/smb2.h:smb2_get_file_id`, `lib/libsmb2.c:smb2_get_file_id`

### Requirement: smb2_fh_from_file_id allocate handle from identifier
系统 MUST 为调用方提供从现有 `smb2_file_id` 构造 `struct smb2fh` 的入口；分配成功时 SHALL 复制 `SMB2_FD_SIZE` 字节 file id 到新句柄，分配失败时 MUST 返回 `NULL`。

#### Scenario: 成功复制 file id
- **GIVEN** 调用方提供一个 `smb2_file_id *fileid`
- **WHEN** `calloc(1, sizeof(struct smb2fh))` 成功并调用 `smb2_fh_from_file_id(smb2, fileid)`
- **THEN** 返回的 `struct smb2fh *` MUST 包含与输入 `fileid` 前 `SMB2_FD_SIZE` 字节相同的 file id 内容

Trace: `include/smb2/smb2.h:smb2_fh_from_file_id`, `lib/libsmb2.c:smb2_fh_from_file_id`

#### Scenario: 分配失败返回 NULL
- **GIVEN** 调用方提供 `smb2_file_id *fileid`
- **WHEN** `smb2_fh_from_file_id(smb2, fileid)` 内部分配句柄失败
- **THEN** 函数 MUST 返回 `NULL` 且不得返回部分初始化的句柄

Trace: `include/smb2/smb2.h:smb2_fh_from_file_id`, `lib/libsmb2.c:smb2_fh_from_file_id`

### Requirement: smb2_decode_fileidfulldirectoryinformation decode directory entry
系统 MUST 从 `struct smb2_iovec *vec` 解码 `SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION` 字段到 `struct smb2_fileidfulldirectoryinformation *fs`，并在名称越界时 SHALL 设置错误并返回 `-1`。

#### Scenario: 解码有效目录项
- **GIVEN** `vec` 包含至少 80 字节固定字段和 UTF-16 文件名数据
- **WHEN** 调用 `smb2_decode_fileidfulldirectoryinformation(smb2, fs, vec)`
- **THEN** 函数 MUST 填充 next entry offset、file index、file size、allocation size、attributes、EA size、file id、名称和四个时间戳字段，并返回 `0`

Trace: `include/smb2/smb2.h:smb2_decode_fileidfulldirectoryinformation`, `lib/smb2-cmd-query-directory.c:smb2_decode_fileidfulldirectoryinformation`, `examples/smb2-CMD-FIND.c`

#### Scenario: 拒绝越界名称
- **GIVEN** `vec` 中 offset 60 的名称长度会使 `80 + name_len` 超过 `vec->len`
- **WHEN** 调用 `smb2_decode_fileidfulldirectoryinformation(smb2, fs, vec)`
- **THEN** 函数 MUST 通过 `smb2_set_error` 报告 malformed name，并返回 `-1`

Trace: `include/smb2/smb2.h:smb2_decode_fileidfulldirectoryinformation`, `lib/smb2-cmd-query-directory.c:smb2_decode_fileidfulldirectoryinformation`

### Requirement: smb2_decode_filenotifychangeinformation decode notify chain
系统 MUST 从 change notify 输出缓冲区解码单个或链式 `smb2_file_notify_change_information` 记录，并在当前记录含后继 offset 时 SHALL 递归构造 `next` 记录。

#### Scenario: 解码单个通知记录
- **GIVEN** `vec` 中 `next_entry_offset + 12` 不超过 `vec->len` 且记录包含 action 和 UTF-16 名称长度
- **WHEN** 调用 `smb2_decode_filenotifychangeinformation(smb2, fnc, vec, next_entry_offset)`
- **THEN** 函数 MUST 填充 `fnc->action`，将 UTF-16 名称转换为 UTF-8 并赋给 `fnc->name`，然后返回 `0`

Trace: `include/smb2/smb2.h:smb2_decode_filenotifychangeinformation`, `lib/libsmb2.c:smb2_decode_filenotifychangeinformation`

#### Scenario: 解码链式通知记录
- **GIVEN** 当前通知记录起始处的 next-entry offset 非零
- **WHEN** 调用 `smb2_decode_filenotifychangeinformation(smb2, fnc, vec, next_entry_offset)`
- **THEN** 函数 MUST 为 `fnc->next` 分配后继节点，并递归解码位于累加 offset 的后继通知记录

Trace: `include/smb2/smb2.h:smb2_decode_filenotifychangeinformation`, `lib/libsmb2.c:smb2_decode_filenotifychangeinformation`

#### Scenario: 短缓冲区返回成功且不解码
- **GIVEN** `next_entry_offset + 12` 大于 `vec->len`
- **WHEN** 调用 `smb2_decode_filenotifychangeinformation(smb2, fnc, vec, next_entry_offset)`
- **THEN** 函数 MUST 返回 `0`，且不得读取当前记录的 action、name length 或 name payload

Trace: `include/smb2/smb2.h:smb2_decode_filenotifychangeinformation`, `lib/libsmb2.c:smb2_decode_filenotifychangeinformation`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_fh_from_file_id` 的 `struct smb2_context *smb2` 参数在当前实现中未使用，是否属于保留 ABI 参数需要确认。 | smb2_fh_from_file_id | 头文件声明包含该参数，但 `lib/libsmb2.c` 实现未引用。 |
| Q-002 | `smb2_decode_filenotifychangeinformation` 在后继节点 `calloc` 失败时仍递归调用的失败语义需要确认。 | smb2_decode_filenotifychangeinformation | 当前实现未检查 `calloc` 返回值，源码没有错误路径说明。 |
| Q-003 | `include/smb2/smb2.h` 中重复定义的宏名是否属于有意兼容公开 ABI 需要确认。 | file-level | 头文件重复出现如 `SMB2_GLOBAL_CAP_DFS`、`SMB2_FILE_DIRECTORY_INFORMATION`、`SMB2_OPLOCK_LEVEL_NONE`、`SMB2_ECHO_REQUEST_SIZE` 等宏。 |
