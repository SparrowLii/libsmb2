# include/libsmb2-private.h Specification

## Source Context

- Source: `include/libsmb2-private.h`
- Related Headers: `include/smb2/libsmb2.h`, `include/smb2/libsmb2-raw.h`, `include/smb2/smb2.h`, `include/slist.h`, `lib/smb2-signing.h`, `lib/smb3-seal.h`, `lib/ntlmssp.h`, `lib/krb5-wrapper.h`, `lib/spnego-wrapper.h`
- Related Tests: `tests/ld_sockerr.c`
- Related Dependencies: GitNexus `context` confirmed `smb2_io_vectors`, `smb2_header`, `smb2_recv_state`, `smb2_context`, `smb2_pdu`, `smb2_tree_id`, and `smb2_is_server` in `include/libsmb2-private.h`; source search confirmed receive-state and queue users in `lib/socket.c`, PDU queue/tree-id users in `lib/pdu.c`, tree-id users in `lib/smb2-cmd-tree-connect.c` and `lib/libsmb2.c`, and server-mode users in `lib/ntlmssp.c` and `lib/libsmb2.c`.
- Build/Compile Context: C project; `HAVE_LIBKRB5` adds Kerberos/GSSAPI fields and headers; `__APPLE__` selects `<GSS/GSS.h>` instead of `<gssapi/gssapi.h>` and `<gssapi/gssapi_ext.h>`; `__cplusplus` wraps declarations in `extern "C"`; C standard unknown.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| MIN | macro | #define MIN(a,b) (((a)<(b))?(a):(b)) | Include | 通用最小值宏对包含方可见，表达参数比较契约。 |
| discard_const | macro | #define discard_const(ptr) ((void *)((intptr_t)(ptr))) | Include | 宏显式移除指针 const 限定并依赖整数指针转换，对调用方有可观察类型转换语义。 |
| MAX_ERROR_SIZE | macro | #define MAX_ERROR_SIZE 256 | Include | 约束 `smb2_context.error_string` 的固定容量。 |
| PAD_TO_32BIT | macro | #define PAD_TO_32BIT(len) ((len + 0x03) & 0xfffffffc) | Include | 宏对长度执行 32 位边界对齐，影响缓冲区和协议字段长度。 |
| PAD_TO_64BIT | macro | #define PAD_TO_64BIT(len) ((len + 0x07) & 0xfffffff8) | Include | 宏对长度执行 64 位边界对齐，影响缓冲区和协议字段长度。 |
| SMB2_SPL_SIZE | macro | #define SMB2_SPL_SIZE 4 | Include | 约束 SMB2 SPL 读取阶段的固定长度。 |
| SMB2_HEADER_SIZE | macro | #define SMB2_HEADER_SIZE 64 | Include | 约束 SMB2 header 缓冲区和 PDU header 大小。 |
| SMB2_SIGNATURE_SIZE | macro | #define SMB2_SIGNATURE_SIZE 16 | Include | 约束 SMB2 signature 字节数。 |
| SMB2_KEY_SIZE | macro | #define SMB2_KEY_SIZE 16 | Include | 约束签名和加密 key 字节数。 |
| SMB2_MAX_VECTORS | macro | #define SMB2_MAX_VECTORS 256 | Include | 约束 `smb2_io_vectors.iov` 的最大元素数量。 |
| smb2_io_vectors | type | struct smb2_io_vectors { size_t num_done; size_t total_size; int niov; struct smb2_iovec iov[SMB2_MAX_VECTORS]; }; | Include | I/O vector 集合是 PDU 输入输出缓冲区的共享数据模型。 |
| smb2_async | type | struct smb2_async { uint64_t async_id; }; | Include | SMB2 header union 的异步标识数据模型。 |
| smb2_sync | type | struct smb2_sync { uint32_t process_id; uint32_t tree_id; }; | Include | SMB2 header union 的同步进程和 tree 标识数据模型。 |
| smb2_header | type | struct smb2_header { uint8_t protocol_id[4]; uint16_t struct_size; uint16_t credit_charge; uint32_t status; uint16_t command; uint16_t credit_request_response; uint32_t flags; uint32_t next_command; uint64_t message_id; union { struct smb2_async async; struct smb2_sync sync; }; uint64_t session_id; uint8_t signature[16]; }; | Include | 内部 PDU header 模型被解码、编码、签名和队列处理共享。 |
| smb2_recv_state | type | enum smb2_recv_state { SMB2_RECV_SPL = 0, SMB2_RECV_HEADER, SMB2_RECV_FIXED, SMB2_RECV_VARIABLE, SMB2_RECV_PAD, SMB2_RECV_TRFM, SMB2_RECV_UNKNOWN, }; | Include | 接收状态机的枚举值驱动 `lib/socket.c` 的读取流程。 |
| SMB2_MAX_TREE_NESTING | macro | #define SMB2_MAX_TREE_NESTING 32 | Include | 约束 `smb2_context.tree_id` 栈容量。 |
| smb2_tree_id | macro | #define smb2_tree_id(smb2) (((smb2)->tree_id_cur >= 0)?smb2->tree_id[(smb2)->tree_id_cur]:0xdeadbeef) | Include | 宏返回当前 tree id 或哨兵值，被 PDU 编码和断开逻辑使用。 |
| MAX_CREDITS | macro | #define MAX_CREDITS 1024 | Include | 约束 SMB2 credit 上限。 |
| SMB2_SALT_SIZE | macro | #define SMB2_SALT_SIZE 32 | Include | 约束 SMB3 salt 字节数。 |
| sync_cb_data | type | struct sync_cb_data { int is_finished; int status; void *ptr; }; | Include | 同步回调状态数据模型承载完成标志、状态码和结果指针。 |
| smb2_context | type | struct smb2_context { ... }; | Include | 核心内部上下文保存连接、认证、队列、接收状态、加密、回调、错误和 server 链表状态。 |
| smb2_free_payload | type | typedef void (*smb2_free_payload)(struct smb2_context *smb2, void *payload); | Include | PDU payload 释放回调类型定义释放函数签名。 |
| SMB2_MAX_PDU_SIZE | macro | #define SMB2_MAX_PDU_SIZE 16*1024*1024 | Include | 约束单个 SMB2 PDU 的最大大小表达式。 |
| smb2_pdu | type | struct smb2_pdu { ... }; | Include | PDU 数据模型承载 header、compound 链、callback、payload、I/O vectors、加密和超时状态。 |
| smb2_dirent_internal | type | struct smb2_dirent_internal { struct smb2_dirent_internal *next; struct smb2dirent dirent; }; | Include | 目录项内部链表节点包装公开目录项数据。 |
| smb2dir | type | struct smb2dir { smb2_command_cb cb; void (*free_cb_data)(void *); void *cb_data; smb2_file_id file_id; struct smb2_dirent_internal *entries; struct smb2_dirent_internal *current_entry; int index; }; | Include | 目录遍历上下文承载回调、file id、目录项链表和当前位置。 |
| smb2_is_server | macro | #define smb2_is_server(ctx) ((ctx)->owning_server != NULL) | Include | 宏通过 `owning_server` 判断上下文 server/client 模式，被 socket、PDU、认证和连接逻辑使用。 |
| smb2_set_nterror | function | void smb2_set_nterror(struct smb2_context *smb2, int nterror, const char *error_string, ...); | Skip | 仅声明实现函数，行为归属到实现文件；本 header spec 记录数据模型和声明面。 |
| smb2_close_connecting_fds | function | void smb2_close_connecting_fds(struct smb2_context *smb2); | Skip | 仅声明实现函数，行为归属到实现文件。 |
| smb2_alloc_init | function | void *smb2_alloc_init(struct smb2_context *smb2, size_t size); | Skip | 仅声明实现函数，分配语义归属到 `lib/alloc.c`。 |
| smb2_alloc_data | function | void *smb2_alloc_data(struct smb2_context *smb2, void *memctx, size_t size); | Skip | 仅声明实现函数，分配语义归属到 `lib/alloc.c`。 |
| smb2_add_iovector | function | struct smb2_iovec *smb2_add_iovector(struct smb2_context *smb2, struct smb2_io_vectors *v, uint8_t *buf, size_t len, void (*free)(void *)); | Skip | 仅声明实现函数，I/O vector 变更行为归属到实现文件。 |
| smb2_pad_to_64bit | function | int smb2_pad_to_64bit(struct smb2_context *smb2, struct smb2_io_vectors *v); | Skip | 仅声明实现函数，padding 行为归属到实现文件。 |
| smb2_process_* | function family | int smb2_process_<command>_<part>(struct smb2_context *smb2, struct smb2_pdu *pdu); | Skip | 大量命令处理声明归属到各 `lib/smb2-cmd-*.c` 实现文件。 |
| smb2_decode_file_* | function family | int smb2_decode_file_<info>(struct smb2_context *smb2, void *memctx, struct smb2_file_* *fs, struct smb2_iovec *vec); | Skip | 文件信息解码声明归属到数据实现文件。 |
| smb2_encode_file_* | function family | int smb2_encode_file_<info>(struct smb2_context *smb2, struct smb2_file_* *fs, struct smb2_iovec *vec); | Skip | 文件信息编码声明归属到数据实现文件。 |
| dcerpc_set_uint8 | function | int dcerpc_set_uint8(struct dcerpc_context *ctx, struct smb2_iovec *iov, int *offset, uint8_t value); | Skip | DCERPC helper 声明归属到 DCERPC 实现文件。 |
| dcerpc_pdu_direction | function | int dcerpc_pdu_direction(struct dcerpc_pdu *pdu); | Skip | DCERPC helper 声明归属到 DCERPC 实现文件。 |
| dcerpc_align_3264 | function | int dcerpc_align_3264(struct dcerpc_context *ctx, int offset); | Skip | DCERPC helper 声明归属到 DCERPC 实现文件。 |
| free_c_data | function | void free_c_data(struct smb2_context*, struct connect_data*); | Skip | 注释明确 `defined in libsmb2.c`，行为归属到 `lib/libsmb2.c`。 |
| smb2_write_to_socket | function | int smb2_write_to_socket(struct smb2_context *smb2); | Skip | 仅声明实现函数，socket 写入行为归属到 `lib/socket.c`。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| MIN | macro | include/libsmb2-private.h:37 | 计算两个表达式中的较小值。 |
| discard_const | macro | include/libsmb2-private.h:41 | 通过 `intptr_t` 转换移除 const 限定并返回 `void *`。 |
| MAX_ERROR_SIZE | macro | include/libsmb2-private.h:45 | 固定错误字符串缓冲区大小为 256。 |
| PAD_TO_32BIT | macro | include/libsmb2-private.h:47 | 将长度向上对齐到 4 字节边界。 |
| PAD_TO_64BIT | macro | include/libsmb2-private.h:48 | 将长度向上对齐到 8 字节边界。 |
| SMB2_SPL_SIZE | macro | include/libsmb2-private.h:50 | SMB2 SPL 固定大小为 4。 |
| SMB2_HEADER_SIZE | macro | include/libsmb2-private.h:51 | SMB2 header 固定大小为 64。 |
| SMB2_SIGNATURE_SIZE | macro | include/libsmb2-private.h:53 | SMB2 signature 固定大小为 16。 |
| SMB2_KEY_SIZE | macro | include/libsmb2-private.h:54 | SMB2 key 固定大小为 16。 |
| SMB2_MAX_VECTORS | macro | include/libsmb2-private.h:56 | I/O vector 数组容量为 256。 |
| smb2_io_vectors | struct | include/libsmb2-private.h:58 | 保存已处理字节数、总大小、vector 数量和固定容量 vector 数组。 |
| smb2_async | struct | include/libsmb2-private.h:65 | 保存 SMB2 异步 id。 |
| smb2_sync | struct | include/libsmb2-private.h:69 | 保存 SMB2 process id 和 tree id。 |
| smb2_header | struct | include/libsmb2-private.h:74 | 保存 SMB2 header 字段、同步/异步 union、session id 和 signature。 |
| smb2_recv_state | enum | include/libsmb2-private.h:117 | 定义普通 SMB2、SMB3 transform 和 unknown/cancelled receive 状态。 |
| SMB2_MAX_TREE_NESTING | macro | include/libsmb2-private.h:129 | Tree id 栈容量为 32，注释说明索引 0 不使用。 |
| smb2_tree_id | macro | include/libsmb2-private.h:130 | 当前 tree id 有效时返回栈中值，否则返回 `0xdeadbeef`。 |
| MAX_CREDITS | macro | include/libsmb2-private.h:132 | Credit 上限为 1024。 |
| SMB2_SALT_SIZE | macro | include/libsmb2-private.h:133 | SMB3 salt 固定大小为 32。 |
| sync_cb_data | struct | include/libsmb2-private.h:135 | 保存同步 API 回调完成状态、状态码和结果指针。 |
| smb2_context | struct | include/libsmb2-private.h:141 | 核心上下文保存连接、认证、加密、队列、接收状态、回调、错误和 server 链表字段。 |
| smb2_free_payload | typedef | include/libsmb2-private.h:287 | PDU payload 释放回调类型。 |
| SMB2_MAX_PDU_SIZE | macro | include/libsmb2-private.h:290 | 最大 PDU 大小表达式为 `16*1024*1024`。 |
| smb2_pdu | struct | include/libsmb2-private.h:292 | 保存 PDU 链接、header、compound、callbacks、payload、I/O vectors、加密数据和 timeout。 |
| smb2_dirent_internal | struct | include/libsmb2-private.h:337 | 内部目录项链表节点。 |
| smb2dir | struct | include/libsmb2-private.h:342 | 目录遍历状态和目录项链表容器。 |
| smb2_is_server | macro | include/libsmb2-private.h:354 | 根据 `owning_server != NULL` 判断 server 模式。 |

## ADDED Requirements

### Requirement: MIN choose smaller expression value
系统 MUST 以 `<` 比较两个宏参数，并返回比较结果中较小一侧的表达式值。

#### Scenario: left expression is smaller
- **GIVEN** 调用方包含 `include/libsmb2-private.h` 且传入两个可比较表达式
- **WHEN** 调用 `MIN(a,b)` 且 `a < b` 为真
- **THEN** 宏展开 MUST 选择 `a` 表达式结果

Trace: `include/libsmb2-private.h:MIN`

### Requirement: discard_const convert pointer through intptr_t
系统 MUST 将输入指针先转换为 `intptr_t` 再转换为 `void *`，以便调用方获得移除 const 限定后的指针值。

#### Scenario: const pointer is discarded
- **GIVEN** 调用方传入一个指针表达式 `ptr`
- **WHEN** 调用 `discard_const(ptr)`
- **THEN** 宏展开 MUST 产生类型为 `void *` 的结果

Trace: `include/libsmb2-private.h:discard_const`

### Requirement: MAX_ERROR_SIZE fix error buffer capacity
系统 MUST 将内部错误字符串缓冲区容量定义为 256 字节，并使 `smb2_context.error_string` 使用该容量。

#### Scenario: context stores error string buffer
- **GIVEN** `smb2_context` 定义包含 `char error_string[MAX_ERROR_SIZE]`
- **WHEN** 编译包含该 header 的实现文件
- **THEN** `error_string` 数组大小 MUST 由 `MAX_ERROR_SIZE` 的 256 字节定义决定

Trace: `include/libsmb2-private.h:MAX_ERROR_SIZE`, `include/libsmb2-private.h:smb2_context`

### Requirement: PAD_TO_32BIT align length to four-byte boundary
系统 MUST 对输入长度加 `0x03` 后与 `0xfffffffc` 按位与，生成向上对齐到 4 字节边界的长度表达式。

#### Scenario: unaligned length is padded to 32-bit boundary
- **GIVEN** 调用方传入长度表达式 `len`
- **WHEN** 调用 `PAD_TO_32BIT(len)`
- **THEN** 结果 MUST 清除低两位并表示不小于原长度的 4 字节对齐长度

Trace: `include/libsmb2-private.h:PAD_TO_32BIT`

### Requirement: PAD_TO_64BIT align length to eight-byte boundary
系统 MUST 对输入长度加 `0x07` 后与 `0xfffffff8` 按位与，生成向上对齐到 8 字节边界的长度表达式。

#### Scenario: unaligned length is padded to 64-bit boundary
- **GIVEN** 调用方传入长度表达式 `len`
- **WHEN** 调用 `PAD_TO_64BIT(len)`
- **THEN** 结果 MUST 清除低三位并表示不小于原长度的 8 字节对齐长度

Trace: `include/libsmb2-private.h:PAD_TO_64BIT`

### Requirement: SMB2_SPL_SIZE define SPL read size
系统 MUST 将 SMB2 SPL 固定大小定义为 4 字节，供接收状态机读取 SPL 阶段使用。

#### Scenario: receive state starts with SPL
- **GIVEN** 接收状态机处于 `SMB2_RECV_SPL`
- **WHEN** 实现代码需要 SPL 字段大小
- **THEN** `SMB2_SPL_SIZE` MUST 提供值 `4`

Trace: `include/libsmb2-private.h:SMB2_SPL_SIZE`, `include/libsmb2-private.h:smb2_recv_state`

### Requirement: SMB2_HEADER_SIZE define fixed header size
系统 MUST 将 SMB2 header 固定大小定义为 64 字节，并用于 context/PDU header 缓冲区容量。

#### Scenario: context and PDU allocate inline header buffers
- **GIVEN** `smb2_context.header` 和 `smb2_pdu.hdr` 声明为 `uint8_t[SMB2_HEADER_SIZE]`
- **WHEN** 编译包含该 header 的实现文件
- **THEN** 这些 header 缓冲区容量 MUST 为 64 字节

Trace: `include/libsmb2-private.h:SMB2_HEADER_SIZE`, `include/libsmb2-private.h:smb2_context`, `include/libsmb2-private.h:smb2_pdu`

### Requirement: SMB2_SIGNATURE_SIZE define signature byte count
系统 MUST 将 SMB2 signature 固定大小定义为 16 字节，供签名相关逻辑使用。

#### Scenario: signature size is referenced by callers
- **GIVEN** 调用方需要 SMB2 signature 字节数
- **WHEN** 读取 `SMB2_SIGNATURE_SIZE`
- **THEN** 宏值 MUST 为 `16`

Trace: `include/libsmb2-private.h:SMB2_SIGNATURE_SIZE`

### Requirement: SMB2_KEY_SIZE define crypto key byte count
系统 MUST 将 SMB2 key 固定大小定义为 16 字节，并使 signing/server key 数组使用该容量。

#### Scenario: context stores signing and sealing keys
- **GIVEN** `smb2_context` 包含 `signing_key`、`serverin_key` 和 `serverout_key`
- **WHEN** 编译包含该 header 的实现文件
- **THEN** 每个 key 数组大小 MUST 由 `SMB2_KEY_SIZE` 的 16 字节定义决定

Trace: `include/libsmb2-private.h:SMB2_KEY_SIZE`, `include/libsmb2-private.h:smb2_context`

### Requirement: SMB2_MAX_VECTORS bound io vector array
系统 MUST 将 `smb2_io_vectors.iov` 的固定容量约束为 256 个 `struct smb2_iovec` 元素。

#### Scenario: io vector container is compiled
- **GIVEN** `struct smb2_io_vectors` 被包含方使用
- **WHEN** 编译 `iov[SMB2_MAX_VECTORS]` 字段
- **THEN** `iov` 数组容量 MUST 为 256 个元素

Trace: `include/libsmb2-private.h:SMB2_MAX_VECTORS`, `include/libsmb2-private.h:smb2_io_vectors`

### Requirement: smb2_io_vectors track vector progress and capacity
系统 MUST 在 `smb2_io_vectors` 中保存已完成字节数、总字节数、当前 vector 数量以及固定容量 vector 数组。

#### Scenario: PDU contains send and receive vectors
- **GIVEN** `smb2_pdu` 需要发送和接收缓冲区集合
- **WHEN** 使用 `out` 或 `in` 字段
- **THEN** 每个字段 MUST 提供 `num_done`、`total_size`、`niov` 和 `iov` 成员

Trace: `include/libsmb2-private.h:smb2_io_vectors`, `include/libsmb2-private.h:smb2_pdu`

### Requirement: smb2_async store asynchronous header id
系统 MUST 用 `smb2_async.async_id` 保存 SMB2 异步 header 标识。

#### Scenario: header uses async union member
- **GIVEN** `smb2_header` 的匿名 union 选择异步形式
- **WHEN** 访问 `async` 成员
- **THEN** 该成员 MUST 提供 `uint64_t async_id`

Trace: `include/libsmb2-private.h:smb2_async`, `include/libsmb2-private.h:smb2_header`

### Requirement: smb2_sync store process and tree identifiers
系统 MUST 用 `smb2_sync` 保存 SMB2 同步 header 的 `process_id` 和 `tree_id` 字段。

#### Scenario: header uses sync union member
- **GIVEN** `smb2_header` 的匿名 union 选择同步形式
- **WHEN** 访问 `sync` 成员
- **THEN** 该成员 MUST 提供 `uint32_t process_id` 和 `uint32_t tree_id`

Trace: `include/libsmb2-private.h:smb2_sync`, `include/libsmb2-private.h:smb2_header`

### Requirement: smb2_header preserve SMB2 wire header fields
系统 MUST 按声明顺序保存 SMB2 header 的 protocol id、size、credit、status、command、flags、message id、同步/异步 union、session id 和 16 字节 signature。

#### Scenario: header is decoded or encoded by PDU logic
- **GIVEN** PDU 处理逻辑持有 `struct smb2_header`
- **WHEN** 访问 header 字段
- **THEN** 结构体 MUST 提供声明中的固定字段和匿名同步/异步 union

Trace: `include/libsmb2-private.h:smb2_header`, `lib/pdu.c:smb2_tree_id`

### Requirement: smb2_recv_state enumerate receive state machine stages
系统 MUST 定义普通 SMB2/3、SMB3 transform 和 unknown PDU 接收路径所需的所有接收状态枚举值。

#### Scenario: socket receive loop dispatches state
- **GIVEN** `lib/socket.c` 按 `smb2->recv_state` 分派接收流程
- **WHEN** 状态机进入 SPL、header、fixed、variable、pad、transform 或 unknown 阶段
- **THEN** `smb2_recv_state` MUST 提供对应枚举值 `SMB2_RECV_SPL`、`SMB2_RECV_HEADER`、`SMB2_RECV_FIXED`、`SMB2_RECV_VARIABLE`、`SMB2_RECV_PAD`、`SMB2_RECV_TRFM` 和 `SMB2_RECV_UNKNOWN`

Trace: `include/libsmb2-private.h:smb2_recv_state`, `lib/socket.c:recv_state`

### Requirement: SMB2_MAX_TREE_NESTING bound tree id stack
系统 MUST 将 `smb2_context.tree_id` 的栈容量约束为 32 个 `uint32_t` 槽位。

#### Scenario: context stores nested tree ids
- **GIVEN** `smb2_context` 声明 `tree_id[SMB2_MAX_TREE_NESTING]`
- **WHEN** 编译包含该 header 的实现文件
- **THEN** tree id 栈容量 MUST 为 32 个槽位

Trace: `include/libsmb2-private.h:SMB2_MAX_TREE_NESTING`, `include/libsmb2-private.h:smb2_context`

### Requirement: smb2_tree_id return active tree id or sentinel
系统 MUST 在 `tree_id_cur >= 0` 时返回当前 tree id 栈元素，并在没有当前 tree id 时返回 `0xdeadbeef`。

#### Scenario: caller encodes a request header
- **GIVEN** `smb2_context.tree_id_cur` 表示当前 tree id 栈位置
- **WHEN** 调用 `smb2_tree_id(smb2)`
- **THEN** 宏 MUST 返回当前 tree id 或无当前项时的 `0xdeadbeef` 哨兵值

Trace: `include/libsmb2-private.h:smb2_tree_id`, `lib/pdu.c:smb2_tree_id`, `lib/smb2-cmd-tree-connect.c:smb2_tree_id`, `lib/libsmb2.c:smb2_tree_id`

### Requirement: MAX_CREDITS define credit ceiling
系统 MUST 将内部 SMB2 credit 上限定义为 1024。

#### Scenario: credit-related logic needs maximum value
- **GIVEN** 实现代码需要内部 credit 上限
- **WHEN** 读取 `MAX_CREDITS`
- **THEN** 宏值 MUST 为 `1024`

Trace: `include/libsmb2-private.h:MAX_CREDITS`

### Requirement: SMB2_SALT_SIZE define salt byte count
系统 MUST 将 SMB3 salt 固定大小定义为 32 字节，并使 `smb2_context.salt` 使用该容量。

#### Scenario: context stores SMB3 salt
- **GIVEN** `smb2_context` 声明 `uint8_t salt[SMB2_SALT_SIZE]`
- **WHEN** 编译包含该 header 的实现文件
- **THEN** salt 数组大小 MUST 为 32 字节

Trace: `include/libsmb2-private.h:SMB2_SALT_SIZE`, `include/libsmb2-private.h:smb2_context`

### Requirement: sync_cb_data store synchronous callback result
系统 MUST 用 `sync_cb_data` 保存同步调用是否完成、完成状态码和结果指针。

#### Scenario: context embeds connect callback data
- **GIVEN** `smb2_context` 声明 `struct sync_cb_data connect_cb_data`
- **WHEN** 同步连接流程需要记录回调结果
- **THEN** 数据结构 MUST 提供 `is_finished`、`status` 和 `ptr` 成员

Trace: `include/libsmb2-private.h:sync_cb_data`, `include/libsmb2-private.h:smb2_context`

### Requirement: smb2_context aggregate connection protocol and callback state
系统 MUST 在一个上下文结构中聚合 socket、连接候选、认证参数、credit、tree/session/message ids、加密密钥、PDU 队列、接收状态、callbacks、错误状态和 server 链表指针。

#### Scenario: socket and PDU code share a context
- **GIVEN** socket、PDU、认证和命令处理代码接收 `struct smb2_context *smb2`
- **WHEN** 这些实现访问连接、队列、状态机、加密或回调字段
- **THEN** `smb2_context` MUST 提供对应声明字段作为共享内部状态容器

Trace: `include/libsmb2-private.h:smb2_context`, `lib/socket.c:recv_state`, `lib/pdu.c:outqueue`, `lib/init.c:outqueue`

### Requirement: smb2_free_payload define payload cleanup callback shape
系统 MUST 将 PDU payload 释放回调定义为接收 `struct smb2_context *` 和 payload 指针且返回 `void` 的函数指针类型。

#### Scenario: PDU stores payload cleanup callback
- **GIVEN** `smb2_pdu` 包含 `smb2_free_payload free_payload`
- **WHEN** PDU 清理逻辑需要释放 payload 附加分配
- **THEN** 回调类型 MUST 匹配 `void (*)(struct smb2_context *smb2, void *payload)`

Trace: `include/libsmb2-private.h:smb2_free_payload`, `include/libsmb2-private.h:smb2_pdu`

### Requirement: SMB2_MAX_PDU_SIZE define maximum PDU expression
系统 MUST 将最大 PDU 大小定义为表达式 `16*1024*1024`。

#### Scenario: implementation checks or allocates PDU size
- **GIVEN** 实现代码需要内部最大 PDU 大小
- **WHEN** 读取 `SMB2_MAX_PDU_SIZE`
- **THEN** 宏表达式 MUST 为 `16*1024*1024`

Trace: `include/libsmb2-private.h:SMB2_MAX_PDU_SIZE`

### Requirement: smb2_pdu preserve request reply and buffer state
系统 MUST 在 PDU 结构中保存链表链接、header、compound 关联、callback、payload、释放回调、send/receive vectors、query-info 保留字段、加密缓冲区和 timeout。

#### Scenario: PDU queue and socket code process a PDU
- **GIVEN** PDU 被加入 `outqueue` 或 `waitqueue`
- **WHEN** socket/PDU 处理逻辑访问 header、payload、vectors、callback 或加密字段
- **THEN** `smb2_pdu` MUST 提供声明中的对应成员

Trace: `include/libsmb2-private.h:smb2_pdu`, `lib/socket.c:outqueue`, `lib/pdu.c:waitqueue`

### Requirement: smb2_dirent_internal link directory entries
系统 MUST 用 `smb2_dirent_internal` 将公开 `smb2dirent` 包装为单向链表节点。

#### Scenario: directory context stores decoded entries
- **GIVEN** 目录读取逻辑需要保存多个目录项
- **WHEN** 使用内部目录项节点
- **THEN** 节点 MUST 提供 `next` 指针和 `struct smb2dirent dirent` 成员

Trace: `include/libsmb2-private.h:smb2_dirent_internal`, `include/libsmb2-private.h:smb2dir`

### Requirement: smb2dir preserve directory traversal state
系统 MUST 在 `smb2dir` 中保存目录命令回调、回调释放函数、回调数据、file id、目录项链表、当前项和索引。

#### Scenario: directory API iterates decoded entries
- **GIVEN** 目录上下文包含已解码目录项
- **WHEN** 调用方或实现推进目录遍历
- **THEN** `smb2dir` MUST 提供 entries、current_entry 和 index 以保存遍历状态

Trace: `include/libsmb2-private.h:smb2dir`

### Requirement: smb2_is_server classify context mode
系统 MUST 通过检查 `ctx->owning_server != NULL` 判断上下文是否处于 server 模式。

#### Scenario: socket and PDU paths branch on mode
- **GIVEN** 一个 `struct smb2_context *ctx`
- **WHEN** 调用 `smb2_is_server(ctx)`
- **THEN** 宏 MUST 在 `owning_server` 非空时返回真值，在为空时返回假值

Trace: `include/libsmb2-private.h:smb2_is_server`, `lib/socket.c:smb2_is_server`, `lib/pdu.c:smb2_is_server`, `lib/ntlmssp.c:smb2_is_server`, `lib/libsmb2.c:smb2_is_server`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `SMB2_MAX_PDU_SIZE` 是否在所有构建路径中实际用于拒绝超大 PDU 需要实现文件逐项确认。 | SMB2_MAX_PDU_SIZE | 当前 header 只给出宏定义，GitNexus context 未返回调用关系。 |
| Q-002 | 各 `smb2_process_*`、`smb2_decode_file_*`、`smb2_encode_file_*` 声明的错误码和资源语义需要在对应实现文件 spec 中确认。 | function families | 当前任务只允许修改 `include/libsmb2-private.h` 对应 spec，不能替代实现文件规格。 |
