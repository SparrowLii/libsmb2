# include/smb2/libsmb2-dcerpc.h Specification

## Source Context

- Source: `include/smb2/libsmb2-dcerpc.h`
- Related Headers: `include/smb2/libsmb2.h`, `include/smb2/libsmb2-raw.h`, `include/smb2/smb2.h`
- Related Tests: `tests/smb2-dcerpc-coder-test.c`
- Related Dependencies: GitNexus `context` confirmed declarations in `include/smb2/libsmb2-dcerpc.h`; implementation context for `dcerpc_call_async`, `dcerpc_utf16_coder`, and `dcerpc_allocate_pdu` is in `lib/dcerpc.c`; callers include `lib/smb2-share-enum.c` and example DCERPC clients.
- Build/Compile Context: C library build from CMake/Autotools; public declarations are wrapped in `extern "C"` when `__cplusplus` is defined; no per-header compile-time feature gate was found.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| DCERPC_DR_BIG_ENDIAN | macro | #define DCERPC_DR_BIG_ENDIAN                    0x00 | Include | 公开数据表示常量，调用方和编码器可观察。 |
| DCERPC_DR_LITTLE_ENDIAN | macro | #define DCERPC_DR_LITTLE_ENDIAN                 0x10 | Include | 公开数据表示常量，影响 PDU 字节序选择。 |
| DCERPC_DR_ASCII | macro | #define DCERPC_DR_ASCII                         0x00 | Include | 公开字符表示常量，属于 DCERPC packed data representation。 |
| DCERPC_DR_EBCDIC | macro | #define DCERPC_DR_EBCDIC                        0x01 | Include | 公开字符表示常量，属于 DCERPC packed data representation。 |
| dcerpc_coder | type | typedef int (*dcerpc_coder)(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开回调类型，所有 NDR 编解码接口依赖该签名。 |
| ptr_type | type | enum ptr_type { PTR_REF = 0, PTR_UNIQUE = 1, PTR_FULL = 2 }; | Include | 公开指针编码类型，影响 `dcerpc_ptr_coder` 行为。 |
| dcerpc_uuid_t | type | typedef struct dcerpc_uuid { uint32_t v1; uint16_t v2; uint16_t v3; uint8_t v4[8]; } dcerpc_uuid_t; | Include | 公开 UUID 数据模型，被接口语法和 coder 使用。 |
| p_syntax_id_t | type | typedef struct p_syntax_id { dcerpc_uuid_t uuid; uint16_t vers; uint16_t vers_minor; } p_syntax_id_t; | Include | 公开 DCERPC presentation syntax 数据模型，被连接接口使用。 |
| ndr_transfer_syntax | type | struct ndr_transfer_syntax { dcerpc_uuid_t uuid; uint16_t vers; }; | Include | 公开 NDR transfer syntax 数据模型。 |
| ndr_context_handle | type | struct ndr_context_handle { uint32_t context_handle_attributes; dcerpc_uuid_t context_handle_uuid; }; | Include | 公开上下文句柄数据模型，存在对应 coder。 |
| dcerpc_utf16 | type | struct dcerpc_utf16 { uint32_t max_count; uint32_t offset; uint32_t actual_count; struct smb2_utf16 *utf16; const char *utf8; }; | Include | 公开 UTF-16 字符串桥接数据模型，测试覆盖 NDR32/NDR64 编解码。 |
| dcerpc_carray | type | struct dcerpc_carray { uint32_t max_count; uint8_t *data; }; | Include | 公开 conformant array 数据模型，SRVSVC 数据结构使用。 |
| lsa_interface | variable | extern p_syntax_id_t lsa_interface; | Include | 公开 LSA presentation syntax 入口，连接接口可使用。 |
| srvsvc_interface | variable | extern p_syntax_id_t srvsvc_interface; | Include | 公开 SRVSVC presentation syntax 入口，连接接口可使用。 |
| dcerpc_cb | type | typedef void (*dcerpc_cb)(struct dcerpc_context *dce, int status, void *command_data, void *cb_data); | Include | 公开异步回调类型，连接、打开和调用接口依赖该签名。 |
| dcerpc_create_context | function | struct dcerpc_context *dcerpc_create_context(struct smb2_context *smb2); | Include | 公开生命周期入口，分配 DCERPC 上下文并绑定 SMB2 上下文。 |
| dcerpc_free_data | function | void dcerpc_free_data(struct dcerpc_context *dce, void *data); | Include | 公开数据释放入口，释放 DCERPC 响应 payload 关联数据。 |
| dcerpc_get_error | function | const char *dcerpc_get_error(struct dcerpc_context *dce); | Include | 公开错误读取入口，返回底层 SMB2 错误字符串。 |
| dcerpc_connect_context_async | function | int dcerpc_connect_context_async(struct dcerpc_context *dce, const char *path, p_syntax_id_t *syntax, dcerpc_cb cb, void *cb_data); | Include | 公开异步连接入口，设置 pipe path 和 syntax 后打开并 bind。 |
| dcerpc_destroy_context | function | void dcerpc_destroy_context(struct dcerpc_context *dce); | Include | 公开生命周期清理入口，允许 NULL 输入。 |
| dcerpc_get_smb2_context | function | struct smb2_context *dcerpc_get_smb2_context(struct dcerpc_context *dce); | Include | 公开上下文访问入口，数据释放和 coder 路径依赖。 |
| dcerpc_get_pdu_payload | function | void *dcerpc_get_pdu_payload(struct dcerpc_pdu *pdu); | Include | 公开 PDU payload 访问入口，响应解码数据分配依赖。 |
| dcerpc_open_async | function | int dcerpc_open_async(struct dcerpc_context *dce, dcerpc_cb cb, void *cb_data); | Include | 公开异步打开 named pipe 入口，连接流程调用。 |
| dcerpc_call_async | function | int dcerpc_call_async(struct dcerpc_context *dce, int opnum, dcerpc_coder req_coder, void *req, dcerpc_coder rep_coder, int decode_size, dcerpc_cb cb, void *cb_data); | Include | 公开 DCERPC request 发送入口，SRVSVC/LSA 调用依赖。 |
| dcerpc_do_coder | function | int dcerpc_do_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr, dcerpc_coder coder); | Include | 公开两阶段 coder 驱动入口，指针和测试路径依赖。 |
| dcerpc_ptr_coder | function | int dcerpc_ptr_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr, enum ptr_type type, dcerpc_coder coder); | Include | 公开 NDR 指针编解码入口，测试覆盖 REF/UNIQUE 路径。 |
| dcerpc_carray_coder | function | int dcerpc_carray_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, int num, void *ptr, int elem_size, dcerpc_coder coder); | Include | 公开 conformant array 编解码入口，SRVSVC 容器 coder 使用。 |
| dcerpc_uint8_coder | function | int dcerpc_uint8_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开 8-bit 标量 coder。 |
| dcerpc_uint16_coder | function | int dcerpc_uint16_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开 16-bit 标量 coder。 |
| dcerpc_uint32_coder | function | int dcerpc_uint32_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开 32-bit 标量 coder。 |
| dcerpc_uint3264_coder | function | int dcerpc_uint3264_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开 NDR32/NDR64 可变宽标量 coder。 |
| dcerpc_conformance_coder | function | int dcerpc_conformance_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开 conformant 字段 coder，数组和字符串 coder 依赖。 |
| dcerpc_utf16_coder | function | int dcerpc_utf16_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开非 NUL 终止 UTF-16 coder。 |
| dcerpc_utf16z_coder | function | int dcerpc_utf16z_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开 NUL 终止 UTF-16 coder，测试覆盖。 |
| dcerpc_context_handle_coder | function | int dcerpc_context_handle_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr); | Include | 公开上下文句柄 coder。 |
| dcerpc_uuid_coder | function | int dcerpc_uuid_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, dcerpc_uuid_t *uuid); | Include | 公开 UUID coder。 |
| DCERPC_DECODE | macro | #define DCERPC_DECODE 0 | Include | 公开 PDU 方向常量。 |
| DCERPC_ENCODE | macro | #define DCERPC_ENCODE 1 | Include | 公开 PDU 方向常量。 |
| dcerpc_allocate_pdu | function | struct dcerpc_pdu *dcerpc_allocate_pdu(struct dcerpc_context *dce, int direction, int payload_size); | Include | 公开 PDU 分配入口，测试和异步调用路径依赖。 |
| dcerpc_free_pdu | function | void dcerpc_free_pdu(struct dcerpc_context *dce, struct dcerpc_pdu *pdu); | Include | 公开 PDU 释放入口，允许 NULL PDU。 |
| dcerpc_set_size_is | function | void dcerpc_set_size_is(struct dcerpc_pdu *pdu, int size_is); | Include | 公开 conformant array size 状态设置入口。 |
| dcerpc_get_size_is | function | int dcerpc_get_size_is(struct dcerpc_pdu *pdu); | Include | 公开 conformant array size 状态读取入口。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| DCERPC_DR_BIG_ENDIAN | macro | include/smb2/libsmb2-dcerpc.h:28 | 数据表示整数字节序位，值为 `0x00`。 |
| DCERPC_DR_LITTLE_ENDIAN | macro | include/smb2/libsmb2-dcerpc.h:29 | 数据表示整数字节序位，值为 `0x10`。 |
| DCERPC_DR_ASCII | macro | include/smb2/libsmb2-dcerpc.h:31 | 数据表示字符集位，值为 `0x00`。 |
| DCERPC_DR_EBCDIC | macro | include/smb2/libsmb2-dcerpc.h:32 | 数据表示字符集位，值为 `0x01`。 |
| dcerpc_coder | typedef | include/smb2/libsmb2-dcerpc.h:38 | coder 回调接收 DCERPC 上下文、PDU、iov、offset 和 caller 数据指针。 |
| ptr_type | enum | include/smb2/libsmb2-dcerpc.h:42 | 定义 `PTR_REF`、`PTR_UNIQUE`、`PTR_FULL` 三种 NDR 指针类型。 |
| dcerpc_uuid_t | typedef | include/smb2/libsmb2-dcerpc.h:48 | UUID 由 32-bit、两个 16-bit 和 8 字节尾部字段组成。 |
| p_syntax_id_t | typedef | include/smb2/libsmb2-dcerpc.h:55 | presentation syntax 由 UUID、major version 和 minor version 组成。 |
| ndr_transfer_syntax | struct | include/smb2/libsmb2-dcerpc.h:61 | transfer syntax 由 UUID 和 version 组成。 |
| ndr_context_handle | struct | include/smb2/libsmb2-dcerpc.h:66 | context handle 包含 attributes 和 UUID。 |
| dcerpc_utf16 | struct | include/smb2/libsmb2-dcerpc.h:71 | 编解码时维护 NDR conformant string 元数据、内部 UTF-16 缓冲和公开 UTF-8 指针。 |
| dcerpc_carray | struct | include/smb2/libsmb2-dcerpc.h:81 | conformant array 包含 max_count 和字节数据指针。 |
| DCERPC_DECODE | macro | include/smb2/libsmb2-dcerpc.h:145 | PDU decode 方向值为 `0`。 |
| DCERPC_ENCODE | macro | include/smb2/libsmb2-dcerpc.h:146 | PDU encode 方向值为 `1`。 |

## ADDED Requirements

### Requirement: DCERPC_DR_BIG_ENDIAN data representation constant
系统 MUST 将 `DCERPC_DR_BIG_ENDIAN` 暴露为整数数据表示的大端标志值 `0x00`。

#### Scenario: Header exposes big endian flag
- **GIVEN** 调用方包含 `include/smb2/libsmb2-dcerpc.h`
- **WHEN** 调用方读取 `DCERPC_DR_BIG_ENDIAN`
- **THEN** 该宏值为 `0x00`

Trace: `include/smb2/libsmb2-dcerpc.h:28`

### Requirement: DCERPC_DR_LITTLE_ENDIAN data representation constant
系统 MUST 将 `DCERPC_DR_LITTLE_ENDIAN` 暴露为整数数据表示的小端标志值 `0x10`。

#### Scenario: Header exposes little endian flag
- **GIVEN** 调用方包含 `include/smb2/libsmb2-dcerpc.h`
- **WHEN** 调用方读取 `DCERPC_DR_LITTLE_ENDIAN`
- **THEN** 该宏值为 `0x10`，并可被实现写入 packed data representation 字节

Trace: `include/smb2/libsmb2-dcerpc.h:29`, `lib/dcerpc.c:460`

### Requirement: DCERPC_DR_ASCII character representation constant
系统 MUST 将 `DCERPC_DR_ASCII` 暴露为字符数据表示的 ASCII 标志值 `0x00`。

#### Scenario: Header exposes ASCII flag
- **GIVEN** 调用方包含 `include/smb2/libsmb2-dcerpc.h`
- **WHEN** 调用方读取 `DCERPC_DR_ASCII`
- **THEN** 该宏值为 `0x00`

Trace: `include/smb2/libsmb2-dcerpc.h:31`, `lib/dcerpc.c:477`

### Requirement: DCERPC_DR_EBCDIC character representation constant
系统 MUST 将 `DCERPC_DR_EBCDIC` 暴露为字符数据表示的 EBCDIC 标志值 `0x01`。

#### Scenario: Header exposes EBCDIC flag
- **GIVEN** 调用方包含 `include/smb2/libsmb2-dcerpc.h`
- **WHEN** 调用方读取 `DCERPC_DR_EBCDIC`
- **THEN** 该宏值为 `0x01`

Trace: `include/smb2/libsmb2-dcerpc.h:32`

### Requirement: dcerpc_coder callback signature
系统 MUST 使用 `dcerpc_coder` 作为 DCERPC 对象编解码回调类型，并保持 `dce`、`pdu`、`iov`、`offset` 和 `ptr` 参数顺序稳定。

#### Scenario: Coder callback receives shared encoding state
- **GIVEN** 调用方实现一个 `dcerpc_coder` 回调
- **WHEN** 该回调传入 `dcerpc_do_coder` 或 `dcerpc_call_async`
- **THEN** 实现以声明中的参数顺序调用回调并根据非零返回值判定失败

Trace: `include/smb2/libsmb2-dcerpc.h:38`, `lib/dcerpc.c:555`, `lib/dcerpc.c:1611`

### Requirement: ptr_type pointer type values
系统 MUST 将 `PTR_REF`、`PTR_UNIQUE` 和 `PTR_FULL` 分别暴露为 `0`、`1` 和 `2`，供指针 coder 选择 NDR 指针语义。

#### Scenario: Pointer coder receives declared pointer type
- **GIVEN** 调用方传入 `PTR_REF`、`PTR_UNIQUE` 或 `PTR_FULL`
- **WHEN** `dcerpc_ptr_coder` 分派到 encode 或 decode 路径
- **THEN** 实现按照该枚举值选择对应分支处理引用、唯一或完整指针

Trace: `include/smb2/libsmb2-dcerpc.h:42`, `lib/dcerpc.c:744`, `lib/dcerpc.c:848`, `tests/smb2-dcerpc-coder-test.c:73`

### Requirement: dcerpc_uuid_t UUID layout
系统 MUST 以 `uint32_t v1`、`uint16_t v2`、`uint16_t v3` 和 `uint8_t v4[8]` 的公开字段布局表示 DCERPC UUID。

#### Scenario: UUID coder consumes public layout
- **GIVEN** 调用方持有 `dcerpc_uuid_t` 值
- **WHEN** 调用 `dcerpc_uuid_coder`
- **THEN** 实现按 `v1`、`v2`、`v3` 和 `v4[0..7]` 顺序编解码字段

Trace: `include/smb2/libsmb2-dcerpc.h:48`, `lib/dcerpc.c:1155`

### Requirement: p_syntax_id_t presentation syntax layout
系统 MUST 以 `uuid`、`vers` 和 `vers_minor` 公开字段表示 DCERPC presentation syntax。

#### Scenario: Connect context stores presentation syntax pointer
- **GIVEN** 调用方提供一个 `p_syntax_id_t *syntax`
- **WHEN** 调用 `dcerpc_connect_context_async`
- **THEN** 实现保存该 syntax 指针用于后续 bind 请求

Trace: `include/smb2/libsmb2-dcerpc.h:55`, `lib/dcerpc.c:476`, `lib/dcerpc.c:1766`

### Requirement: ndr_transfer_syntax transfer syntax layout
系统 MUST 以 `uuid` 和 `vers` 公开字段表示 NDR transfer syntax。

#### Scenario: Bind coder emits transfer syntax identity
- **GIVEN** 实现选择一个 transfer syntax
- **WHEN** bind PDU 被编码
- **THEN** 实现按 UUID 和版本字段写入 transfer syntax 条目

Trace: `include/smb2/libsmb2-dcerpc.h:61`, `lib/dcerpc.c:1249`

### Requirement: ndr_context_handle handle layout
系统 MUST 以 `context_handle_attributes` 和 `context_handle_uuid` 公开字段表示 NDR context handle。

#### Scenario: Context handle coder serializes attributes and UUID
- **GIVEN** 调用方提供 `struct ndr_context_handle`
- **WHEN** 调用 `dcerpc_context_handle_coder`
- **THEN** 实现先编解码 attributes，再编解码 UUID

Trace: `include/smb2/libsmb2-dcerpc.h:66`, `lib/dcerpc.c:1185`, `tests/smb2-dcerpc-coder-test.c:621`

### Requirement: dcerpc_utf16 UTF-8 bridge model
系统 MUST 使用 `struct dcerpc_utf16` 同时承载 NDR 字符串计数字段、内部 UTF-16 缓冲和调用方可见的 UTF-8 字符串指针。

#### Scenario: UTF-16 coder round-trips UTF-8 text
- **GIVEN** `struct dcerpc_utf16` 的 `utf8` 字段指向调用方字符串
- **WHEN** 测试通过 UTF-16 coder 编码并解码该结构
- **THEN** 解码结果的 `utf8` 字符串与原始字符串相同

Trace: `include/smb2/libsmb2-dcerpc.h:71`, `lib/dcerpc.c:951`, `lib/dcerpc.c:1051`, `tests/smb2-dcerpc-coder-test.c:138`

### Requirement: dcerpc_carray conformant array model
系统 MUST 使用 `struct dcerpc_carray` 的 `max_count` 和 `data` 字段表示公开 conformant array 容器。

#### Scenario: Array coder uses caller-provided count and data pointer
- **GIVEN** 调用方提供 array 元素数量、元素大小和数据指针
- **WHEN** 调用 `dcerpc_carray_coder`
- **THEN** 实现先处理 conformance count，再按元素大小逐个调用元素 coder

Trace: `include/smb2/libsmb2-dcerpc.h:81`, `lib/dcerpc.c:908`, `tests/smb2-dcerpc-coder-test.c:293`

### Requirement: lsa_interface presentation syntax symbol
系统 MUST 暴露 `lsa_interface` 作为 LSA DCERPC presentation syntax 的外部符号。

#### Scenario: LSA client passes interface to connect
- **GIVEN** 调用方包含 DCERPC LSA 相关头文件
- **WHEN** 调用方将 `&lsa_interface` 传给 `dcerpc_connect_context_async`
- **THEN** 连接流程接收该 presentation syntax 指针

Trace: `include/smb2/libsmb2-dcerpc.h:86`, `lib/dcerpc.c:465`

### Requirement: srvsvc_interface presentation syntax symbol
系统 MUST 暴露 `srvsvc_interface` 作为 SRVSVC DCERPC presentation syntax 的外部符号。

#### Scenario: SRVSVC share enumeration passes interface to connect
- **GIVEN** 调用方执行 share enumeration bind 流程
- **WHEN** 调用方将 `&srvsvc_interface` 传给 `dcerpc_connect_context_async`
- **THEN** 连接流程接收该 presentation syntax 指针

Trace: `include/smb2/libsmb2-dcerpc.h:87`, `lib/smb2-share-enum.c:185`

### Requirement: dcerpc_cb async callback signature
系统 MUST 使用 `dcerpc_cb` 作为 DCERPC 异步 completion 回调类型，并传递 DCERPC 上下文、状态码、命令数据和调用方私有数据。

#### Scenario: Async operation completes through callback
- **GIVEN** 调用方提供 `dcerpc_cb` 和 `cb_data`
- **WHEN** DCERPC open、bind 或 call 路径完成
- **THEN** 实现调用回调并传回原始 `cb_data`

Trace: `include/smb2/libsmb2-dcerpc.h:89`, `lib/dcerpc.c:1511`, `lib/dcerpc.c:1657`

### Requirement: dcerpc_create_context context allocation
系统 MUST 为给定 SMB2 上下文分配 DCERPC 上下文，保存 SMB2 指针，并默认启用 little-endian 数据表示；分配失败时 MUST 返回 `NULL` 并设置 SMB2 错误。

#### Scenario: Context allocation succeeds
- **GIVEN** 调用方提供有效的 `struct smb2_context *smb2`
- **WHEN** 调用 `dcerpc_create_context(smb2)`
- **THEN** 返回的 DCERPC 上下文关联该 SMB2 上下文，并设置 little-endian packed data representation

Trace: `include/smb2/libsmb2-dcerpc.h:92`, `lib/dcerpc.c:449`, `tests/smb2-dcerpc-coder-test.c:614`

### Requirement: dcerpc_free_data payload data release
系统 MUST 通过关联的 SMB2 上下文释放 DCERPC 响应数据。

#### Scenario: Caller releases command data
- **GIVEN** 调用方从 DCERPC callback 收到需要释放的数据指针
- **WHEN** 调用 `dcerpc_free_data(dce, data)`
- **THEN** 实现转发到底层 SMB2 数据释放函数

Trace: `include/smb2/libsmb2-dcerpc.h:93`, `lib/dcerpc.c:1903`

### Requirement: dcerpc_get_error error forwarding
系统 MUST 从 DCERPC 上下文关联的 SMB2 上下文返回错误字符串。

#### Scenario: Caller reads last DCERPC error
- **GIVEN** DCERPC 操作失败且底层 SMB2 上下文保存错误文本
- **WHEN** 调用 `dcerpc_get_error(dce)`
- **THEN** 返回 `smb2_get_error(dcerpc_get_smb2_context(dce))` 的结果

Trace: `include/smb2/libsmb2-dcerpc.h:94`, `lib/dcerpc.c:1897`

### Requirement: dcerpc_connect_context_async connect and bind setup
系统 MUST 在异步连接上下文时初始化 call id、复制 pipe path、保存 syntax 指针、设置数据表示，并调用 open/bind 流程；path 分配失败时 MUST 返回 `-ENOMEM`。

#### Scenario: Connect context starts async open
- **GIVEN** 调用方提供 DCERPC 上下文、pipe path、syntax、回调和私有数据
- **WHEN** 调用 `dcerpc_connect_context_async`
- **THEN** 实现保存连接状态并调用 `dcerpc_open_async` 启动 named pipe open

Trace: `include/smb2/libsmb2-dcerpc.h:95`, `lib/dcerpc.c:465`, `lib/dcerpc.c:482`

### Requirement: dcerpc_destroy_context context cleanup
系统 MUST 允许销毁 `NULL` DCERPC 上下文，并在非 `NULL` 时释放复制的 path 和上下文本身。

#### Scenario: Destroy context after coder tests
- **GIVEN** 调用方完成 DCERPC 上下文使用
- **WHEN** 调用 `dcerpc_destroy_context(dce)`
- **THEN** 实现释放 path 和上下文内存

Trace: `include/smb2/libsmb2-dcerpc.h:98`, `lib/dcerpc.c:490`, `tests/smb2-dcerpc-coder-test.c:631`

### Requirement: dcerpc_get_smb2_context associated SMB2 access
系统 MUST 返回 DCERPC 上下文保存的 SMB2 上下文指针。

#### Scenario: Helper retrieves SMB2 context
- **GIVEN** DCERPC 上下文包含 `smb2` 字段
- **WHEN** 调用 `dcerpc_get_smb2_context(dce)`
- **THEN** 返回该字段指向的 SMB2 上下文

Trace: `include/smb2/libsmb2-dcerpc.h:100`, `lib/dcerpc.c:436`

### Requirement: dcerpc_get_pdu_payload payload access
系统 MUST 返回给定 DCERPC PDU 的 payload 指针。

#### Scenario: Decoder allocates data from PDU payload
- **GIVEN** 调用方或 coder 持有 `struct dcerpc_pdu *pdu`
- **WHEN** 调用 `dcerpc_get_pdu_payload(pdu)`
- **THEN** 返回 `pdu->payload`

Trace: `include/smb2/libsmb2-dcerpc.h:101`, `lib/dcerpc.c:442`, `lib/dcerpc-srvsvc.c:138`

### Requirement: dcerpc_open_async named pipe open
系统 MUST 构造 SMB2 create request 打开 DCERPC pipe，并在分配 callback data 或创建 SMB2 PDU 失败时返回 `-ENOMEM`。

#### Scenario: Open async queues SMB2 create request
- **GIVEN** DCERPC 上下文已设置 pipe path
- **WHEN** 调用 `dcerpc_open_async(dce, cb, cb_data)`
- **THEN** 实现构造 create request、注册回调并 queue SMB2 PDU

Trace: `include/smb2/libsmb2-dcerpc.h:103`, `lib/dcerpc.c:1849`

### Requirement: dcerpc_call_async request transceive
系统 MUST 为 DCERPC operation 分配 encode PDU、编码 request header 和 payload、修正 fragment length/allocation hint，并通过 SMB2 IOCTL pipe transceive queue 异步请求。

#### Scenario: Async call queues IOCTL transceive
- **GIVEN** 调用方提供 opnum、request coder、response coder、decode size 和 callback
- **WHEN** 调用 `dcerpc_call_async`
- **THEN** 实现编码 DCERPC request 并 queue `SMB2_FSCTL_PIPE_TRANSCEIVE` IOCTL PDU

Trace: `include/smb2/libsmb2-dcerpc.h:104`, `lib/dcerpc.c:1567`, `lib/smb2-share-enum.c:119`

### Requirement: dcerpc_do_coder two-pass coding
系统 MUST 对给定 coder 执行 conformance/alignment pass 和 data pass，并在任一 pass 返回非零时返回 `-1`。

#### Scenario: Pointer coder delegates object encoding
- **GIVEN** 指针 coder 需要编码或解码被引用对象
- **WHEN** `dcerpc_do_coder` 被调用
- **THEN** 实现先更新 alignment 并对齐 offset，再执行实际 coder pass

Trace: `include/smb2/libsmb2-dcerpc.h:110`, `lib/dcerpc.c:548`, `lib/dcerpc.c:748`

### Requirement: dcerpc_ptr_coder NDR pointer dispatch
系统 MUST 根据 PDU direction 在 encode 和 decode 指针路径之间分派，并遵循 `ptr_type` 的 REF、UNIQUE 和 FULL 指针语义。

#### Scenario: Test encodes and decodes reference pointer
- **GIVEN** 测试创建 encode/decode PDU 并传入 `PTR_REF`
- **WHEN** 调用 `dcerpc_ptr_coder`
- **THEN** 对象被编码到 buffer 并可按相同期望 offset 解码回来

Trace: `include/smb2/libsmb2-dcerpc.h:114`, `lib/dcerpc.c:928`, `tests/smb2-dcerpc-coder-test.c:73`, `tests/smb2-dcerpc-coder-test.c:122`

### Requirement: dcerpc_carray_coder conformant array coding
系统 MUST 先编解码 conformant array count，并且只有 wire count 与调用方 `num` 一致时才逐元素调用元素 coder。

#### Scenario: Array count mismatch fails
- **GIVEN** PDU 中 conformant count 与调用方 `num` 不一致
- **WHEN** 调用 `dcerpc_carray_coder`
- **THEN** 实现返回 `-1` 而不继续逐元素处理

Trace: `include/smb2/libsmb2-dcerpc.h:117`, `lib/dcerpc.c:899`, `lib/dcerpc.c:913`

### Requirement: dcerpc_uint8_coder 8-bit scalar coding
系统 MUST 在 conformance pass 更新 1 字节 alignment，并在 decode/encode pass 分别读取或写入 8-bit 值。

#### Scenario: Scalar coder follows PDU direction
- **GIVEN** PDU direction 为 decode 或 encode
- **WHEN** 调用 `dcerpc_uint8_coder`
- **THEN** 实现分别调用 8-bit get 或 set 路径

Trace: `include/smb2/libsmb2-dcerpc.h:121`, `lib/dcerpc.c:621`

### Requirement: dcerpc_uint16_coder 16-bit scalar coding
系统 MUST 在 conformance pass 更新至少 2 字节 alignment，并在 decode/encode pass 分别读取或写入 16-bit 值。

#### Scenario: Scalar coder follows PDU direction
- **GIVEN** PDU direction 为 decode 或 encode
- **WHEN** 调用 `dcerpc_uint16_coder`
- **THEN** 实现分别调用 16-bit get 或 set 路径

Trace: `include/smb2/libsmb2-dcerpc.h:123`, `lib/dcerpc.c:603`

### Requirement: dcerpc_uint32_coder 32-bit scalar coding
系统 MUST 在 conformance pass 更新至少 4 字节 alignment，并在 decode/encode pass 分别读取或写入 32-bit 值。

#### Scenario: Scalar coder follows PDU direction
- **GIVEN** PDU direction 为 decode 或 encode
- **WHEN** 调用 `dcerpc_uint32_coder`
- **THEN** 实现分别调用 32-bit get 或 set 路径

Trace: `include/smb2/libsmb2-dcerpc.h:125`, `lib/dcerpc.c:586`

### Requirement: dcerpc_uint3264_coder transfer-syntax scalar coding
系统 MUST 按当前 transfer syntax 在 NDR64 时处理 64-bit 表示，在 NDR32 时处理 32-bit 表示并映射到调用方 64-bit 存储。

#### Scenario: NDR32 encodes lower 32-bit value
- **GIVEN** DCERPC context 使用 NDR32 transfer context
- **WHEN** 调用 `dcerpc_uint3264_coder`
- **THEN** 实现以 32-bit wire value 编解码调用方数值

Trace: `include/smb2/libsmb2-dcerpc.h:127`, `lib/dcerpc.c:641`

### Requirement: dcerpc_conformance_coder conformance-only processing
系统 MUST 仅在 conformance pass 处理 conformant 字段，在 data pass 返回成功且不消费数据。

#### Scenario: Data pass skips conformance field
- **GIVEN** PDU 不处于 conformance run
- **WHEN** 调用 `dcerpc_conformance_coder`
- **THEN** 实现返回 `0` 且不读取或写入 conformance value

Trace: `include/smb2/libsmb2-dcerpc.h:129`, `lib/dcerpc.c:684`

### Requirement: dcerpc_utf16_coder nonterminated UTF-16 coding
系统 MUST 使用非 NUL 终止模式编解码 `struct dcerpc_utf16`，并按 PDU direction 分派到 UTF-16 encode 或 decode 实现。

#### Scenario: Nonterminated coder dispatches by direction
- **GIVEN** 调用方传入 `struct dcerpc_utf16`
- **WHEN** 调用 `dcerpc_utf16_coder`
- **THEN** 实现以 `nult` 为 `0` 调用内部 UTF-16 编码或解码路径

Trace: `include/smb2/libsmb2-dcerpc.h:131`, `lib/dcerpc.c:1083`

### Requirement: dcerpc_utf16z_coder NUL-terminated UTF-16 coding
系统 MUST 使用 NUL 终止模式编解码 `struct dcerpc_utf16`，并在编码时包含结尾 UTF-16 NUL。

#### Scenario: Test round-trips NUL-terminated UTF-16 text
- **GIVEN** 测试输入 `\\win16-1` UTF-8 字符串
- **WHEN** 调用 `dcerpc_utf16z_coder` 编码并解码
- **THEN** 结果匹配测试期望字节序列和原始字符串

Trace: `include/smb2/libsmb2-dcerpc.h:133`, `lib/dcerpc.c:1069`, `tests/smb2-dcerpc-coder-test.c:150`

### Requirement: dcerpc_context_handle_coder context handle coding
系统 MUST 按 attributes 后 UUID 的顺序编解码 `struct ndr_context_handle`。

#### Scenario: Context handle fields are serialized in declaration order
- **GIVEN** 调用方提供 `struct ndr_context_handle`
- **WHEN** 调用 `dcerpc_context_handle_coder`
- **THEN** 实现先调用 32-bit coder 处理 attributes，再调用 UUID coder 处理 UUID

Trace: `include/smb2/libsmb2-dcerpc.h:135`, `lib/dcerpc.c:1180`

### Requirement: dcerpc_uuid_coder UUID field coding
系统 MUST 按 `dcerpc_uuid_t` 字段顺序编解码 UUID，并逐字节处理 `v4` 数组。

#### Scenario: UUID coder walks v4 bytes
- **GIVEN** 调用方提供 `dcerpc_uuid_t *uuid`
- **WHEN** 调用 `dcerpc_uuid_coder`
- **THEN** 实现编解码 `v1`、`v2`、`v3` 后遍历 8 个 `v4` 字节

Trace: `include/smb2/libsmb2-dcerpc.h:139`, `lib/dcerpc.c:1148`

### Requirement: DCERPC_DECODE direction constant
系统 MUST 将 `DCERPC_DECODE` 暴露为 PDU decode direction 值 `0`。

#### Scenario: Test allocates decode PDU
- **GIVEN** 调用方需要创建 decode PDU
- **WHEN** 调用 `dcerpc_allocate_pdu(dce, DCERPC_DECODE, size)`
- **THEN** PDU direction 使用值 `0`

Trace: `include/smb2/libsmb2-dcerpc.h:145`, `tests/smb2-dcerpc-coder-test.c:119`

### Requirement: DCERPC_ENCODE direction constant
系统 MUST 将 `DCERPC_ENCODE` 暴露为 PDU encode direction 值 `1`。

#### Scenario: Test allocates encode PDU
- **GIVEN** 调用方需要创建 encode PDU
- **WHEN** 调用 `dcerpc_allocate_pdu(dce, DCERPC_ENCODE, size)`
- **THEN** PDU direction 使用值 `1`

Trace: `include/smb2/libsmb2-dcerpc.h:146`, `tests/smb2-dcerpc-coder-test.c:67`

### Requirement: dcerpc_allocate_pdu PDU allocation
系统 MUST 分配 DCERPC PDU、设置 call id、direction、top-level 标志和 payload；PDU 或 payload 分配失败时 MUST 设置 SMB2 错误并返回 `NULL`。

#### Scenario: Test allocates PDU for coder round-trip
- **GIVEN** 调用方提供 DCERPC 上下文、direction 和 payload size
- **WHEN** 调用 `dcerpc_allocate_pdu`
- **THEN** 返回的 PDU 可用于后续 coder 测试并由 `dcerpc_free_pdu` 释放

Trace: `include/smb2/libsmb2-dcerpc.h:147`, `lib/dcerpc.c:513`, `tests/smb2-dcerpc-coder-test.c:67`

### Requirement: dcerpc_free_pdu PDU cleanup
系统 MUST 允许释放 `NULL` PDU，并在非 `NULL` 时释放 payload 后释放 PDU 本身。

#### Scenario: Test frees encoded and decoded PDU
- **GIVEN** coder 测试完成两个 PDU 的使用
- **WHEN** 调用 `dcerpc_free_pdu(dce, pdu)`
- **THEN** 实现释放 payload 关联数据和 PDU 内存

Trace: `include/smb2/libsmb2-dcerpc.h:149`, `lib/dcerpc.c:500`, `tests/smb2-dcerpc-coder-test.c:133`

### Requirement: dcerpc_set_size_is conformant size state
系统 MUST 将给定 size 写入 PDU 的 conformant array `size_is` 状态。

#### Scenario: Container coder stores decoded entry count
- **GIVEN** 解码容器读取到 EntriesRead
- **WHEN** 调用 `dcerpc_set_size_is(pdu, EntriesRead)`
- **THEN** 后续 carray coder 可读取该 count

Trace: `include/smb2/libsmb2-dcerpc.h:151`, `lib/dcerpc.c:1950`, `lib/dcerpc-srvsvc.c:135`

### Requirement: dcerpc_get_size_is conformant size state
系统 MUST 返回 PDU 当前保存的 conformant array `size_is` 状态。

#### Scenario: Carray coder reads stored entry count
- **GIVEN** 前序 coder 已设置 PDU `size_is`
- **WHEN** 调用 `dcerpc_get_size_is(pdu)`
- **THEN** 返回该值供 conformant array 编解码使用

Trace: `include/smb2/libsmb2-dcerpc.h:152`, `lib/dcerpc.c:1955`, `lib/dcerpc-srvsvc.c:113`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `dcerpc_connect_context_async` 在 `dcerpc_open_async` 失败后是否应释放已复制的 `path`？ | dcerpc_connect_context_async | 源码显示失败时直接返回 `-1`，未确认调用方是否总是随后销毁 context。 |
| Q-002 | `PTR_FULL` decode 分支当前注释为 `not implemented yet`，调用方是否依赖该类型的完整 decode 语义？ | dcerpc_ptr_coder | 头文件公开 `PTR_FULL`，但实现 decode 分支未处理非空 full pointer 内容。 |
| Q-003 | `dcerpc_uint8_coder` 在头文件中声明两次是否为兼容性保留？ | dcerpc_uint8_coder | 源码声明重复，未发现说明其原因。 |
