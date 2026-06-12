# lib/init.c Specification

## Source Context

- Source: `lib/init.c`
- Related Headers: `include/smb2/libsmb2.h`, `include/smb2/smb2.h`, `include/libsmb2-private.h`, `include/slist.h`, `lib/compat.h`
- Related Tests: `tests/metastat-0202-censored.c`, `tests/ntlmssp_generate_blob.c`, `tests/prog_cat.c`, `tests/prog_cat_cancel.c`, `tests/prog_ls.c`, `tests/prog_mkdir.c`, `tests/prog_rmdir.c`
- Related Dependencies: GitNexus context reports public callers from examples, tests, `lib/dreamcast/vfs.c`, `lib/ps2/smb2_fio.c`, and dependencies on `smb2_free_pdu`, `free_c_data`, `smb2_close_connecting_fds`, `SMB2_LIST_ADD`, `SMB2_LIST_REMOVE`, `strdup`, `free`, `getenv`, `fopen`, `random`, `srandom`, `time`, `getpid`, and optional `gss_release_cred`.
- Build/Compile Context: `lib/CMakeLists.txt` includes `init.c` in normal, ESP, PS2 IOP, and default library source lists; behavior is conditioned by `HAVE_CONFIG_H`, header availability macros, `_IOP`, `_XBOX`, `_MSC_UWP`, `HAVE_LIBKRB5`, Amiga platform macros, `NEED_RANDOM`, `NEED_SRANDOM`, `NEED_GETPID`, and `NEED_GETLOGIN_R` through `compat.h`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_parse_args | function | static int smb2_parse_args(struct smb2_context *smb2, const char *args) | Skip | 文件内部 URL 参数解析 helper，无独立公开声明；行为归属到 `smb2_parse_url`。 |
| smb2_parse_url | function | struct smb2_url *smb2_parse_url(struct smb2_context *smb2, const char *url); | Include | 公开 URL 解析入口，分配返回对象并设置 context 认证、版本、签名和错误状态。 |
| smb2_destroy_url | function | void smb2_destroy_url(struct smb2_url *url); | Include | 公开 URL 对象释放入口，定义 `smb2_parse_url` 返回对象的释放责任。 |
| smb2_init_context | function | struct smb2_context *smb2_init_context(void); | Include | 公开上下文生命周期入口，分配并初始化默认认证、版本、随机挑战和 active list 状态。 |
| smb2_destroy_context | function | void smb2_destroy_context(struct smb2_context *smb2); | Include | 公开上下文销毁入口，关闭 fd、取消队列、释放凭据和从 active list 移除。 |
| smb2_active_contexts | function | struct smb2_context *smb2_active_contexts(void); | Include | 公开服务器侧 active context 列表读取入口。 |
| smb2_context_active | function | int smb2_context_active(struct smb2_context *smb2); | Include | 公开 context 活跃性检测入口，供回调中判断 context 是否仍可引用。 |
| smb2_free_iovector | function | void smb2_free_iovector(struct smb2_context *smb2, struct smb2_io_vectors *v); | Include | 私有跨文件 I/O vector 资源释放入口，被 destroy 和 PDU 路径使用。 |
| smb2_add_iovector | function | struct smb2_iovec *smb2_add_iovector(struct smb2_context *smb2, struct smb2_io_vectors *v, uint8_t *buf, size_t len, void (*free)(void *)); | Include | 私有跨文件 I/O vector 追加入口，包含容量错误和 buffer 释放语义。 |
| smb2_set_error_string | function | static void smb2_set_error_string(struct smb2_context *smb2, const char * error_string, va_list args) | Skip | `_IOP` 以外的内部格式化 helper，无独立调用方契约；行为归属到 error setter。 |
| smb2_set_error | function | void smb2_set_error(struct smb2_context *smb2, const char *error_string, ...); | Include | 公开错误字符串设置入口，驱动 error callback 并清理 nterror。 |
| smb2_register_error_callback | function | void smb2_register_error_callback(struct smb2_context *smb, smb2_error_cb error_cb); | Include | 公开错误回调注册入口，影响后续 `smb2_set_error` 可观察行为。 |
| smb2_set_nterror | function | void smb2_set_nterror(struct smb2_context *smb2, int nterror, const char *error_string, ...); | Include | 私有跨文件 NT status 和错误字符串设置入口。 |
| smb2_get_error | function | const char *smb2_get_error(struct smb2_context *smb2); | Include | 公开最后错误字符串读取入口。 |
| smb2_get_nterror | function | int smb2_get_nterror(struct smb2_context *smb2); | Include | 公开最后 NT status 读取入口。 |
| smb2_set_client_guid | function | void smb2_set_client_guid(struct smb2_context *smb2, const uint8_t guid[SMB2_GUID_SIZE]); | Include | 公开 client GUID setter，复制固定长度 GUID 到 context。 |
| smb2_get_client_guid | function | const char *smb2_get_client_guid(struct smb2_context *smb2); | Include | 公开 client GUID getter，返回 context 内部 GUID 存储。 |
| smb2_get_dialect | function | uint16_t smb2_get_dialect(struct smb2_context *smb2); | Include | 公开协商 dialect getter。 |
| smb2_set_security_mode | function | void smb2_set_security_mode(struct smb2_context *smb2, uint16_t security_mode); | Include | 公开 security mode setter，影响 negotiate signing flags。 |
| smb2_set_password_from_file | function | void smb2_set_password_from_file(struct smb2_context *smb2); | Include | 公开 NTLM password file 装载入口，依赖环境变量和 user/domain/server 状态。 |
| smb2_set_user | function | void smb2_set_user(struct smb2_context *smb2, const char *user); | Include | 公开 user setter，释放旧值并触发 password file 重载。 |
| smb2_get_user | function | const char *smb2_get_user(struct smb2_context *smb2); | Include | 公开 user getter。 |
| smb2_get_workstation | function | const char *smb2_get_workstation(struct smb2_context *smb2); | Include | 公开 workstation getter。 |
| smb2_set_password | function | void smb2_set_password(struct smb2_context *smb2, const char *password); | Include | 公开 password setter，释放旧值并允许清空。 |
| smb2_set_domain | function | void smb2_set_domain(struct smb2_context *smb2, const char *domain); | Include | 公开 domain setter，释放旧值并触发 password file 重载。 |
| smb2_get_domain | function | const char *smb2_get_domain(struct smb2_context *smb2); | Include | 公开 domain getter。 |
| smb2_set_workstation | function | void smb2_set_workstation(struct smb2_context *smb2, const char *workstation); | Include | 公开 workstation setter，释放旧值并允许清空。 |
| smb2_set_opaque | function | void smb2_set_opaque(struct smb2_context *smb2, void *opaque); | Include | 公开 opaque pointer setter，供 async callback 附带调用方状态。 |
| smb2_get_opaque | function | void *smb2_get_opaque(struct smb2_context *smb2); | Include | 公开 opaque pointer getter。 |
| smb2_set_seal | function | void smb2_set_seal(struct smb2_context *smb2, int val); | Include | 公开 SMB3 encryption preference setter。 |
| smb2_set_sign | function | void smb2_set_sign(struct smb2_context *smb2, int val); | Include | 公开 SMB signing preference setter。 |
| smb2_set_authentication | function | void smb2_set_authentication(struct smb2_context *smb2, int val); | Include | 公开 authentication method setter。 |
| smb2_set_timeout | function | void smb2_set_timeout(struct smb2_context *smb2, int seconds); | Include | 公开 command timeout setter。 |
| smb2_set_version | function | void smb2_set_version(struct smb2_context *smb2, enum smb2_negotiate_version version); | Include | 公开 negotiate dialect preference setter。 |
| smb2_get_libsmb2Version | function | void smb2_get_libsmb2Version(struct smb2_libversion *smb2_ver); | Include | 公开库版本 getter，写入 `struct smb2_libversion`。 |
| smb2_set_passthrough | function | void smb2_set_passthrough(struct smb2_context *smb2, int passthrough); | Include | 公开 passthrough mode setter，影响复杂命令额外数据解析。 |
| smb2_get_passthrough | function | void smb2_get_passthrough(struct smb2_context *smb2, int *passthrough); | Include | 公开 passthrough mode getter，通过输出参数返回。 |
| smb2_set_oplock_or_lease_break_callback | function | void smb2_set_oplock_or_lease_break_callback(struct smb2_context *smb2, smb2_oplock_or_lease_break_cb cb); | Include | 公开 oplock/lease break callback 注册入口。 |
| smb2_delegate_credentials | function | int smb2_delegate_credentials(struct smb2_context *in, struct smb2_context *out); | Include | 公开 Kerberos credential delegation 入口，行为依赖 `HAVE_LIBKRB5`。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| MAX_URL_SIZE | macro | lib/init.c:78 | URL 主体临时缓冲区上限为 1024 字节；`smb2_parse_url` 拒绝 `smb://` 后长度大于等于该值的输入。 |
| active_contexts | static variable | lib/init.c:84 | 进程内 active context 单链表头，用于服务器枚举和活跃性检查；非公开存储但影响公开生命周期查询。 |
| struct smb2_url | struct | include/smb2/libsmb2.h:598 | URL 解析结果，字段为 `domain`、`user`、`server`、`share`、`path`，由 `smb2_destroy_url` 释放。 |
| struct smb2_context | struct | include/libsmb2-private.h:141 | 私有 context 状态容器，承载 fd、认证、队列、错误、加密、回调和 active list 链接。 |
| struct smb2_io_vectors | struct | include/libsmb2-private.h:58 | 私有 I/O vector 聚合，包含 `niov`、`total_size`、`num_done` 和固定数组。 |
| SMB2_MAX_VECTORS | macro | include/libsmb2-private.h:56 | `smb2_add_iovector` 可追加的最大 vector 数。 |

## ADDED Requirements

### Requirement: smb2_parse_url parses SMB URL components and options
系统 MUST 只接受以 `smb://` 开头且主机部分长度小于 `MAX_URL_SIZE` 的 URL，并在成功时返回由调用方通过 `smb2_destroy_url` 释放的 `struct smb2_url`。

#### Scenario: parse valid share URL
- **GIVEN** 一个有效 context 和 `smb://domain;user@server/share/path` 形式的 URL
- **WHEN** 调用 `smb2_parse_url`
- **THEN** 返回对象 MUST 保存 domain、user、server、share 和 path 字段，且不接管原始 URL 指针所有权

Trace: `lib/init.c:smb2_parse_url`, `include/smb2/libsmb2.h:smb2_parse_url`

#### Scenario: reject invalid URL prefix
- **GIVEN** 一个有效 context 和不以 `smb://` 开头的 URL
- **WHEN** 调用 `smb2_parse_url`
- **THEN** 返回值 MUST 为 `NULL`，并通过 `smb2_set_error` 设置 `URL does not start with 'smb://'`

Trace: `lib/init.c:smb2_parse_url`, `include/smb2/libsmb2.h:smb2_parse_url`

#### Scenario: apply URL query arguments
- **GIVEN** 一个带 `?seal&vers=3&sec=ntlmssp&timeout=5` 查询串的有效 URL
- **WHEN** 调用 `smb2_parse_url`
- **THEN** 解析 MUST 更新 context 的 seal、version、security method 和 timeout；未知参数或不兼容 seal/version 组合 MUST 使调用失败并设置错误字符串

Trace: `lib/init.c:smb2_parse_url`, `lib/init.c:smb2_parse_args`

### Requirement: smb2_destroy_url releases parsed URL ownership
系统 MUST 允许调用方用 `smb2_destroy_url` 释放 `smb2_parse_url` 返回的 URL 对象及其字符串字段。

#### Scenario: destroy parsed URL
- **GIVEN** 一个由 `smb2_parse_url` 返回的 URL 对象
- **WHEN** 调用 `smb2_destroy_url`
- **THEN** 函数 MUST 释放 domain、user、server、share、path 和 URL 对象本身

Trace: `lib/init.c:smb2_destroy_url`, `include/smb2/libsmb2.h:smb2_destroy_url`

#### Scenario: destroy null URL
- **GIVEN** URL 指针为 `NULL`
- **WHEN** 调用 `smb2_destroy_url`
- **THEN** 函数 MUST 直接返回且不访问任何字段

Trace: `lib/init.c:smb2_destroy_url`, `include/smb2/libsmb2.h:smb2_destroy_url`

### Requirement: smb2_init_context creates initialized active context
系统 MUST 在成功时分配零初始化 `struct smb2_context`，设置默认用户、fd、认证、版本、NDR、随机挑战、salt、client GUID，并把 context 加入 active list。

#### Scenario: initialize context defaults
- **GIVEN** 内存分配成功且平台提供或兼容实现 `getlogin_r`、`random`、`srandom`、`time` 和 `getpid`
- **WHEN** 调用 `smb2_init_context`
- **THEN** 返回 context MUST 具有 `SMB2_INVALID_SOCKET` fd、`SMB2_SEC_UNDEFINED` security、`SMB2_VERSION_ANY` version、NDR32 默认值和 active list 成员资格

Trace: `lib/init.c:smb2_init_context`, `include/smb2/libsmb2.h:smb2_init_context`, `tests/ntlmssp_generate_blob.c:main`

#### Scenario: initialize allocation failure
- **GIVEN** context 分配失败
- **WHEN** 调用 `smb2_init_context`
- **THEN** 返回值 MUST 为 `NULL` 且不得加入 active list

Trace: `lib/init.c:smb2_init_context`, `include/smb2/libsmb2.h:smb2_init_context`

### Requirement: smb2_destroy_context cancels and frees context resources
系统 MUST 允许调用方销毁非空 context，并释放 fd、连接中 fd、PDU 队列、输入 vectors、session key、字符串字段、加密缓冲区、可选 Kerberos credential、connect_data 和 context 本体。

#### Scenario: destroy active context
- **GIVEN** 一个通过 `smb2_init_context` 创建的 context
- **WHEN** 调用 `smb2_destroy_context`
- **THEN** 函数 MUST 从 active list 移除该 context，释放拥有的资源，并对未完成 PDU callback 报告 shutdown 或 cancelled 状态

Trace: `lib/init.c:smb2_destroy_context`, `include/smb2/libsmb2.h:smb2_destroy_context`, `tests/prog_cat.c:main`

#### Scenario: destroy null context
- **GIVEN** context 指针为 `NULL`
- **WHEN** 调用 `smb2_destroy_context`
- **THEN** 函数 MUST 直接返回且不释放任何资源

Trace: `lib/init.c:smb2_destroy_context`, `include/smb2/libsmb2.h:smb2_destroy_context`

### Requirement: smb2_active_contexts returns active context list head
系统 MUST 返回当前进程内 active context 单链表头，供服务器侧代码遍历已分配 context。

#### Scenario: read active context list
- **GIVEN** 一个或多个 context 已由 `smb2_init_context` 加入 active list
- **WHEN** 调用 `smb2_active_contexts`
- **THEN** 返回值 MUST 为当前 `active_contexts` 链表头

Trace: `lib/init.c:smb2_active_contexts`, `include/smb2/libsmb2.h:smb2_active_contexts`

### Requirement: smb2_context_active reports active list membership
系统 MUST 通过遍历 active list 判断给定 context 指针是否仍处于 active 状态。

#### Scenario: report active context
- **GIVEN** 一个仍在 active list 中的 context 指针
- **WHEN** 调用 `smb2_context_active`
- **THEN** 返回值 MUST 为 `1`

Trace: `lib/init.c:smb2_context_active`, `include/smb2/libsmb2.h:smb2_context_active`

#### Scenario: report inactive context
- **GIVEN** 一个不在 active list 中的 context 指针
- **WHEN** 调用 `smb2_context_active`
- **THEN** 返回值 MUST 为 `0`

Trace: `lib/init.c:smb2_context_active`, `include/smb2/libsmb2.h:smb2_context_active`

### Requirement: smb2_free_iovector releases vector-owned buffers
系统 MUST 对 `struct smb2_io_vectors` 中每个带 free callback 的 vector 调用对应释放函数，并重置计数状态。

#### Scenario: free populated iovector
- **GIVEN** 一个 `niov` 大于 0 且部分元素带 `free` callback 的 vector 集合
- **WHEN** 调用 `smb2_free_iovector`
- **THEN** 函数 MUST 对每个带 callback 的 buffer 调用 callback，并把 `niov`、`total_size` 和 `num_done` 重置为 0

Trace: `lib/init.c:smb2_free_iovector`, `include/libsmb2-private.h:smb2_free_iovector`

### Requirement: smb2_add_iovector appends bounded vectors
系统 MUST 在 `niov < SMB2_MAX_VECTORS` 时追加 buffer、length 和 free callback，并更新 vector 总大小和数量。

#### Scenario: append vector entry
- **GIVEN** 一个未满的 `struct smb2_io_vectors`
- **WHEN** 调用 `smb2_add_iovector`
- **THEN** 返回值 MUST 指向新追加的 `struct smb2_iovec`，且 `niov` 增加 1、`total_size` 增加 `len`

Trace: `lib/init.c:smb2_add_iovector`, `include/libsmb2-private.h:smb2_add_iovector`

#### Scenario: reject vector overflow
- **GIVEN** 一个 `niov >= SMB2_MAX_VECTORS` 的 vector 集合
- **WHEN** 调用 `smb2_add_iovector`
- **THEN** 函数 MUST 设置 `Too many I/O vectors` 错误，若提供了 `free_cb` 和 `buf` 则调用 `free_cb(buf)`，并返回 `NULL`

Trace: `lib/init.c:smb2_add_iovector`, `include/libsmb2-private.h:smb2_add_iovector`

### Requirement: smb2_set_error stores formatted error and invokes callback
系统 MUST 在非 `_IOP` 构建中格式化错误字符串、按需清零 NT status，并在注册了 error callback 时同步通知调用方。

#### Scenario: set formatted error
- **GIVEN** 一个非空 context 和非空格式字符串
- **WHEN** 调用 `smb2_set_error`
- **THEN** context 的 error string MUST 更新为格式化结果，且已注册 callback 时 MUST 以 `smb2_get_error` 的返回值调用 callback

Trace: `lib/init.c:smb2_set_error`, `include/smb2/libsmb2.h:smb2_set_error`

#### Scenario: clear nterror on empty error
- **GIVEN** 一个非空 context 和空错误字符串或 `NULL` 错误字符串
- **WHEN** 调用 `smb2_set_error`
- **THEN** context 的 `nterror` MUST 设置为 0

Trace: `lib/init.c:smb2_set_error`, `include/smb2/libsmb2.h:smb2_set_error`

### Requirement: smb2_register_error_callback stores error callback
系统 MUST 把调用方提供的 error callback 保存在 context 中，以便后续 `smb2_set_error` 通知。

#### Scenario: register error callback
- **GIVEN** 一个有效 context 和 callback 指针
- **WHEN** 调用 `smb2_register_error_callback`
- **THEN** 后续 `smb2_set_error` MUST 使用该 callback 报告当前错误字符串

Trace: `lib/init.c:smb2_register_error_callback`, `include/smb2/libsmb2.h:smb2_register_error_callback`

### Requirement: smb2_set_nterror stores NT status and optional error text
系统 MUST 为非空 context 设置 NT status，并在非 `_IOP` 构建中同步格式化错误字符串。

#### Scenario: set NT status
- **GIVEN** 一个非空 context、NT status 和错误格式字符串
- **WHEN** 调用 `smb2_set_nterror`
- **THEN** context 的 `nterror` MUST 等于传入状态，且非 `_IOP` 构建中 error string MUST 按格式字符串更新

Trace: `lib/init.c:smb2_set_nterror`, `include/libsmb2-private.h:smb2_set_nterror`

### Requirement: smb2_get_error returns last error string
系统 MUST 对非空 context 返回内部 error string，对空 context 返回空字符串。

#### Scenario: get error string
- **GIVEN** 一个 context 已设置错误字符串
- **WHEN** 调用 `smb2_get_error`
- **THEN** 返回值 MUST 指向该 context 的内部 error string

Trace: `lib/init.c:smb2_get_error`, `include/smb2/libsmb2.h:smb2_get_error`

#### Scenario: get error from null context
- **GIVEN** context 指针为 `NULL`
- **WHEN** 调用 `smb2_get_error`
- **THEN** 返回值 MUST 为 `""`

Trace: `lib/init.c:smb2_get_error`, `include/smb2/libsmb2.h:smb2_get_error`

### Requirement: smb2_get_nterror returns last NT status
系统 MUST 对非空 context 返回内部 NT status，对空 context 返回 0。

#### Scenario: get NT status
- **GIVEN** 一个 context 已设置 NT status
- **WHEN** 调用 `smb2_get_nterror`
- **THEN** 返回值 MUST 等于该 context 的 `nterror`

Trace: `lib/init.c:smb2_get_nterror`, `include/smb2/libsmb2.h:smb2_get_nterror`

### Requirement: smb2_set_client_guid copies fixed-size GUID
系统 MUST 将传入的 `SMB2_GUID_SIZE` 字节 GUID 复制到 context 的 `client_guid` 存储。

#### Scenario: set client GUID
- **GIVEN** 一个有效 context 和长度为 `SMB2_GUID_SIZE` 的 GUID 数组
- **WHEN** 调用 `smb2_set_client_guid`
- **THEN** context 的 client GUID MUST 与传入字节序列相同

Trace: `lib/init.c:smb2_set_client_guid`, `include/smb2/libsmb2.h:smb2_set_client_guid`

### Requirement: smb2_get_client_guid returns internal GUID storage
系统 MUST 返回 context 内部 `client_guid` 存储地址。

#### Scenario: get client GUID
- **GIVEN** 一个有效 context
- **WHEN** 调用 `smb2_get_client_guid`
- **THEN** 返回值 MUST 指向该 context 的 client GUID 存储

Trace: `lib/init.c:smb2_get_client_guid`, `include/smb2/libsmb2.h:smb2_get_client_guid`

### Requirement: smb2_get_dialect returns negotiated dialect
系统 MUST 返回 context 当前保存的 dialect 值。

#### Scenario: get dialect
- **GIVEN** 一个 context 的 dialect 字段已由 negotiate 路径设置
- **WHEN** 调用 `smb2_get_dialect`
- **THEN** 返回值 MUST 等于 context 的 `dialect`

Trace: `lib/init.c:smb2_get_dialect`, `include/smb2/libsmb2.h:smb2_get_dialect`

### Requirement: smb2_set_security_mode stores security mode flags
系统 MUST 把传入 security mode 写入 context，以供 negotiate 使用。

#### Scenario: set security mode
- **GIVEN** 一个有效 context 和 security mode 值
- **WHEN** 调用 `smb2_set_security_mode`
- **THEN** context 的 `security_mode` MUST 等于传入值

Trace: `lib/init.c:smb2_set_security_mode`, `include/smb2/libsmb2.h:smb2_set_security_mode`

### Requirement: smb2_set_password_from_file loads matching NTLM password
系统 MUST 在支持的平台上从 `NTLM_USER_FILE` 指向的文件读取 `domain:user:password` 行，并为匹配 domain、server 或 wildcard 的记录设置 password。

#### Scenario: load matching password
- **GIVEN** 非受排除平台、context 已有 user，且 `NTLM_USER_FILE` 指向包含匹配 domain 或 server 的文件
- **WHEN** 调用 `smb2_set_password_from_file`
- **THEN** context password MUST 更新为匹配记录中的 password，且文件句柄 MUST 被关闭

Trace: `lib/init.c:smb2_set_password_from_file`, `include/smb2/libsmb2.h:smb2_set_password_from_file`

#### Scenario: skip unsupported or missing password file
- **GIVEN** 平台命中 `_XBOX`、`_IOP`、Amiga 排除条件，或环境变量、user、文件打开失败任一条件不满足
- **WHEN** 调用 `smb2_set_password_from_file`
- **THEN** 函数 MUST 不设置新 password 并返回

Trace: `lib/init.c:smb2_set_password_from_file`, `include/smb2/libsmb2.h:smb2_set_password_from_file`

### Requirement: smb2_set_user stores user and reloads password file
系统 MUST 释放旧 user，允许通过 `NULL` 清空 user，并在设置非空 user 后尝试从 password file 更新 password。

#### Scenario: set non-null user
- **GIVEN** 一个有效 context 和非空 user 字符串
- **WHEN** 调用 `smb2_set_user`
- **THEN** context user MUST 保存为 `strdup` 副本，旧 user MUST 被释放，并 MUST 调用 `smb2_set_password_from_file`

Trace: `lib/init.c:smb2_set_user`, `include/smb2/libsmb2.h:smb2_set_user`

### Requirement: smb2_get_user returns configured user
系统 MUST 在 context 和 user 均非空时返回 user，否则返回 `NULL`。

#### Scenario: get configured user
- **GIVEN** 一个 context 已设置 user
- **WHEN** 调用 `smb2_get_user`
- **THEN** 返回值 MUST 指向 context 的 user 字符串

Trace: `lib/init.c:smb2_get_user`, `include/smb2/libsmb2.h:smb2_get_user`

### Requirement: smb2_get_workstation returns configured workstation
系统 MUST 在 context 和 workstation 均非空时返回 workstation，否则返回 `NULL`。

#### Scenario: get configured workstation
- **GIVEN** 一个 context 已设置 workstation
- **WHEN** 调用 `smb2_get_workstation`
- **THEN** 返回值 MUST 指向 context 的 workstation 字符串

Trace: `lib/init.c:smb2_get_workstation`, `include/smb2/libsmb2.h:smb2_get_workstation`

### Requirement: smb2_set_password stores password copy
系统 MUST 释放旧 password，允许通过 `NULL` 清空 password，并为非空输入保存 `strdup` 副本。

#### Scenario: set password
- **GIVEN** 一个有效 context 和非空 password 字符串
- **WHEN** 调用 `smb2_set_password`
- **THEN** context password MUST 指向新分配副本，旧 password MUST 被释放

Trace: `lib/init.c:smb2_set_password`, `include/smb2/libsmb2.h:smb2_set_password`

### Requirement: smb2_set_domain stores domain and reloads password file
系统 MUST 释放旧 domain，允许通过 `NULL` 清空 domain，并在设置非空 domain 后尝试从 password file 更新 password。

#### Scenario: set domain
- **GIVEN** 一个有效 context 和非空 domain 字符串
- **WHEN** 调用 `smb2_set_domain`
- **THEN** context domain MUST 保存为 `strdup` 副本，旧 domain MUST 被释放，并 MUST 调用 `smb2_set_password_from_file`

Trace: `lib/init.c:smb2_set_domain`, `include/smb2/libsmb2.h:smb2_set_domain`

### Requirement: smb2_get_domain returns configured domain
系统 MUST 在 context 和 domain 均非空时返回 domain，否则返回 `NULL`。

#### Scenario: get configured domain
- **GIVEN** 一个 context 已设置 domain
- **WHEN** 调用 `smb2_get_domain`
- **THEN** 返回值 MUST 指向 context 的 domain 字符串

Trace: `lib/init.c:smb2_get_domain`, `include/smb2/libsmb2.h:smb2_get_domain`

### Requirement: smb2_set_workstation stores workstation copy
系统 MUST 释放旧 workstation，允许通过 `NULL` 清空 workstation，并为非空输入保存 `strdup` 副本。

#### Scenario: set workstation
- **GIVEN** 一个有效 context 和非空 workstation 字符串
- **WHEN** 调用 `smb2_set_workstation`
- **THEN** context workstation MUST 指向新分配副本，旧 workstation MUST 被释放

Trace: `lib/init.c:smb2_set_workstation`, `include/smb2/libsmb2.h:smb2_set_workstation`

### Requirement: smb2_set_opaque stores caller opaque pointer
系统 MUST 将调用方提供的 opaque pointer 保存到 context 中，不获取其所有权。

#### Scenario: set opaque pointer
- **GIVEN** 一个有效 context 和任意 opaque 指针
- **WHEN** 调用 `smb2_set_opaque`
- **THEN** context 的 `opaque` 字段 MUST 等于传入指针

Trace: `lib/init.c:smb2_set_opaque`, `include/smb2/libsmb2.h:smb2_set_opaque`

### Requirement: smb2_get_opaque returns caller opaque pointer
系统 MUST 返回最近通过 `smb2_set_opaque` 保存的 opaque pointer。

#### Scenario: get opaque pointer
- **GIVEN** 一个 context 已设置 opaque pointer
- **WHEN** 调用 `smb2_get_opaque`
- **THEN** 返回值 MUST 等于 context 的 `opaque` 字段

Trace: `lib/init.c:smb2_get_opaque`, `include/smb2/libsmb2.h:smb2_get_opaque`

### Requirement: smb2_set_seal stores encryption preference
系统 MUST 将传入值保存到 context 的 seal 标志。

#### Scenario: set seal flag
- **GIVEN** 一个有效 context 和整数值
- **WHEN** 调用 `smb2_set_seal`
- **THEN** context 的 `seal` 标志 MUST 反映传入值

Trace: `lib/init.c:smb2_set_seal`, `include/smb2/libsmb2.h:smb2_set_seal`

### Requirement: smb2_set_sign stores signing preference
系统 MUST 将传入值保存到 context 的 sign 标志。

#### Scenario: set sign flag
- **GIVEN** 一个有效 context 和整数值
- **WHEN** 调用 `smb2_set_sign`
- **THEN** context 的 `sign` 标志 MUST 反映传入值

Trace: `lib/init.c:smb2_set_sign`, `include/smb2/libsmb2.h:smb2_set_sign`

### Requirement: smb2_set_authentication stores authentication method
系统 MUST 将传入整数转换为 `enum smb2_sec` 并保存到 context 的 authentication method 字段。

#### Scenario: set authentication method
- **GIVEN** 一个有效 context 和 authentication method 值
- **WHEN** 调用 `smb2_set_authentication`
- **THEN** context 的 `sec` 字段 MUST 等于传入值转换后的 `enum smb2_sec`

Trace: `lib/init.c:smb2_set_authentication`, `include/smb2/libsmb2.h:smb2_set_authentication`

### Requirement: smb2_set_timeout stores command timeout
系统 MUST 将传入秒数保存到 context 的 timeout 字段。

#### Scenario: set timeout
- **GIVEN** 一个有效 context 和 seconds 值
- **WHEN** 调用 `smb2_set_timeout`
- **THEN** context 的 `timeout` 字段 MUST 等于传入秒数

Trace: `lib/init.c:smb2_set_timeout`, `include/smb2/libsmb2.h:smb2_set_timeout`

### Requirement: smb2_set_version stores negotiation version preference
系统 MUST 将传入 `enum smb2_negotiate_version` 保存到 context 的 version 字段。

#### Scenario: set version
- **GIVEN** 一个有效 context 和 negotiate version
- **WHEN** 调用 `smb2_set_version`
- **THEN** context 的 `version` 字段 MUST 等于传入值

Trace: `lib/init.c:smb2_set_version`, `include/smb2/libsmb2.h:smb2_set_version`

### Requirement: smb2_get_libsmb2Version writes library version fields
系统 MUST 将编译期库版本宏写入调用方提供的 `struct smb2_libversion`。

#### Scenario: get library version
- **GIVEN** 一个有效 `struct smb2_libversion` 输出指针
- **WHEN** 调用 `smb2_get_libsmb2Version`
- **THEN** major 和 minor 字段 MUST 分别来自 `LIBSMB2_MAJOR_VERSION` 和 `LIBSMB2_MINOR_VERSION`

Trace: `lib/init.c:smb2_get_libsmb2Version`, `include/smb2/libsmb2.h:smb2_get_libsmb2Version`

### Requirement: smb2_set_passthrough stores passthrough mode
系统 MUST 将 passthrough 值保存到 context，以影响复杂命令额外数据是否透传。

#### Scenario: set passthrough
- **GIVEN** 一个有效 context 和 passthrough 值
- **WHEN** 调用 `smb2_set_passthrough`
- **THEN** context 的 `passthrough` 字段 MUST 等于传入值

Trace: `lib/init.c:smb2_set_passthrough`, `include/smb2/libsmb2.h:smb2_set_passthrough`

### Requirement: smb2_get_passthrough writes passthrough mode
系统 MUST 通过输出参数返回 context 当前 passthrough 值。

#### Scenario: get passthrough
- **GIVEN** 一个有效 context 和非空输出指针
- **WHEN** 调用 `smb2_get_passthrough`
- **THEN** 输出指针指向的值 MUST 等于 context 的 `passthrough`

Trace: `lib/init.c:smb2_get_passthrough`, `include/smb2/libsmb2.h:smb2_get_passthrough`

### Requirement: smb2_set_oplock_or_lease_break_callback stores break callback
系统 MUST 保存调用方提供的 oplock/lease break callback，以便后续 break 处理通知应用。

#### Scenario: register break callback
- **GIVEN** 一个有效 context 和 callback 指针
- **WHEN** 调用 `smb2_set_oplock_or_lease_break_callback`
- **THEN** context 的 `oplock_or_lease_break_cb` MUST 等于传入 callback

Trace: `lib/init.c:smb2_set_oplock_or_lease_break_callback`, `include/smb2/libsmb2.h:smb2_set_oplock_or_lease_break_callback`

### Requirement: smb2_delegate_credentials transfers Kerberos credential when available
系统 MUST 在 `HAVE_LIBKRB5` 构建且输入、输出 context 与输入 credential 均非空时把 credential handle 从输入 context 转移到输出 context。

#### Scenario: delegate credential with Kerberos support
- **GIVEN** `HAVE_LIBKRB5` 构建、非空 input/output context，且 input context 持有 credential handle
- **WHEN** 调用 `smb2_delegate_credentials`
- **THEN** 函数 MUST 返回 0，将 handle 写入 output context，并将 input context 的 handle 置为 `NULL`

Trace: `lib/init.c:smb2_delegate_credentials`, `include/smb2/libsmb2.h:smb2_delegate_credentials`

#### Scenario: delegate credential unavailable
- **GIVEN** 未启用 `HAVE_LIBKRB5`，或 input/output context 为空，或 input context 无 credential handle
- **WHEN** 调用 `smb2_delegate_credentials`
- **THEN** 函数 MUST 返回 -1

Trace: `lib/init.c:smb2_delegate_credentials`, `include/smb2/libsmb2.h:smb2_delegate_credentials`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_parse_url` 在已分配 `struct smb2_url` 后遇到 `Wrong URL format` 是否泄漏该对象？ | smb2_parse_url | 源码在 `calloc` 后对缺少 share slash 的路径直接返回 `NULL`，未看到释放 `u` 的证据。 |
| Q-002 | `smb2_get_libsmb2Version` 是否应把 patch 字段写为 `LIBSMB2_PATCH_VERSION`？ | smb2_get_libsmb2Version | 源码将 `patch_version` 设置为 `LIBSMB2_MAJOR_VERSION`，与 header 宏命名存在差异。 |
| Q-003 | `smb2_set_password_from_file` 的行尾裁剪循环在空字符串上访问 `buf[strlen(buf) - 1]` 是否有前置约束？ | smb2_set_password_from_file | 源码在 switch 前未先检查 `strlen(buf) == 0`，需要测试或平台输入约束确认。 |
| Q-004 | setter/getter 系列是否要求调用方保证 `smb2` 和输出参数非空？ | setter/getter interfaces | 多数 setter/getter 未做空指针检查，公开 header 未完整声明前置条件。 |
| Q-005 | active context list 是否需要外部同步？ | smb2_init_context`, `smb2_destroy_context`, `smb2_active_contexts`, `smb2_context_active | `active_contexts` 是静态全局链表，源码未显示锁或线程局部状态。 |
