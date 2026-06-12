# lib/dcerpc.c Specification

## Source Context

- Source: `lib/dcerpc.c`
- Related Headers: `include/smb2/libsmb2-dcerpc.h`, `include/smb2/libsmb2.h`, `include/smb2/libsmb2-raw.h`, `include/smb2/smb2.h`, `include/libsmb2-private.h`
- Related Tests: `tests/smb2-dcerpc-coder-test.c`
- Related Dependencies: GitNexus `context` for `dcerpc_create_context` reports callers in `lib/smb2-share-enum.c`, `tests/smb2-dcerpc-coder-test.c`, and DCERPC examples; source review confirms SRVSVC/LSA coders call scalar, pointer, array, context, payload, and async request helpers from this file.
- Build/Compile Context: C library build from CMake/Autotools; compile-time includes depend on `HAVE_CONFIG_H`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_SYS_TYPES_H`, `HAVE_SYS_STAT_H`, `HAVE_UNISTD_H`, and `HAVE_SYS_UNISTD_H`; `_GNU_SOURCE` is defined when absent.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| ndr32_syntax | variable | p_syntax_id_t ndr32_syntax = { {NDR32_UUID}, 2, 0 }; | Include | 传输语法全局对象被 bind 流程发送给远端，影响协商结果。 |
| ndr64_syntax | variable | p_syntax_id_t ndr64_syntax = { {NDR64_UUID}, 1, 0 }; | Include | 传输语法全局对象被 bind 流程发送给远端，影响 NDR64 协商结果。 |
| dcerpc_set_uint8 | function | int dcerpc_set_uint8(struct dcerpc_context *ctx, struct smb2_iovec *iov, int *offset, uint8_t value) | Include | 非 static 基础写入 helper，标量 coder 路径依赖其边界检查。 |
| dcerpc_uint64_coder | function | int dcerpc_uint64_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 非 static 64-bit 标量 coder，具有对齐、大小端和方向语义。 |
| dcerpc_get_smb2_context | function | struct smb2_context *dcerpc_get_smb2_context(struct dcerpc_context *dce) | Include | 公开上下文访问入口，被 SRVSVC 和释放路径使用。 |
| dcerpc_get_pdu_payload | function | void *dcerpc_get_pdu_payload(struct dcerpc_pdu *pdu) | Include | 公开 payload 访问入口，被解码分配路径使用。 |
| dcerpc_create_context | function | struct dcerpc_context *dcerpc_create_context(struct smb2_context *smb2) | Include | 公开生命周期入口，分配并初始化 DCERPC 上下文。 |
| dcerpc_connect_context_async | function | int dcerpc_connect_context_async(struct dcerpc_context *dce, const char *path, p_syntax_id_t *syntax, dcerpc_cb cb, void *cb_data) | Include | 公开异步连接入口，配置 path、syntax、数据表示并启动 open/bind。 |
| dcerpc_destroy_context | function | void dcerpc_destroy_context(struct dcerpc_context *dce) | Include | 公开生命周期清理入口，具有 NULL 输入语义。 |
| dcerpc_free_pdu | function | void dcerpc_free_pdu(struct dcerpc_context *dce, struct dcerpc_pdu *pdu) | Include | 公开 PDU 释放入口，释放 payload 关联数据和 PDU。 |
| dcerpc_allocate_pdu | function | struct dcerpc_pdu *dcerpc_allocate_pdu(struct dcerpc_context *dce, int direction, int payload_size) | Include | 公开 PDU 分配入口，被测试和异步调用路径使用。 |
| dcerpc_do_coder | function | int dcerpc_do_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr, dcerpc_coder coder) | Include | 公开两阶段 coder 驱动入口，指针 coder 依赖。 |
| dcerpc_uint32_coder | function | int dcerpc_uint32_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 32-bit 标量 coder，多个 PDU 和 IDL coder 依赖。 |
| dcerpc_uint16_coder | function | int dcerpc_uint16_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 16-bit 标量 coder，多个 PDU 和 IDL coder 依赖。 |
| dcerpc_uint8_coder | function | int dcerpc_uint8_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 8-bit 标量 coder，多个 PDU 和 IDL coder 依赖。 |
| dcerpc_uint3264_coder | function | int dcerpc_uint3264_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 NDR32/NDR64 可变宽标量 coder，指针和 union switch 值依赖。 |
| dcerpc_conformance_coder | function | int dcerpc_conformance_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 conformant 字段 coder，数组和字符串 coder 依赖。 |
| dcerpc_carray_coder | function | int dcerpc_carray_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, int num, void *ptr, int elem_size, dcerpc_coder coder) | Include | 公开 conformant array coder，SRVSVC 容器 coder 和测试路径依赖。 |
| dcerpc_ptr_coder | function | int dcerpc_ptr_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr, enum ptr_type type, dcerpc_coder coder) | Include | 公开 NDR 指针 coder，测试覆盖 REF/UNIQUE 路径。 |
| dcerpc_utf16z_coder | function | int dcerpc_utf16z_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 NUL 终止 UTF-16 coder，测试覆盖 NDR32/NDR64。 |
| dcerpc_utf16_coder | function | int dcerpc_utf16_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开非 NUL 终止 UTF-16 coder。 |
| dcerpc_header_coder | function | int dcerpc_header_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, struct dcerpc_header *hdr) | Include | 非 static DCERPC header coder，被 PDU 编解码和 unfragment 路径依赖。 |
| dcerpc_uuid_coder | function | int dcerpc_uuid_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, dcerpc_uuid_t *uuid) | Include | 公开 UUID coder，被 context handle 和 bind coder 使用。 |
| dcerpc_context_handle_coder | function | int dcerpc_context_handle_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, void *ptr) | Include | 公开 NDR context handle coder。 |
| dcerpc_call_async | function | int dcerpc_call_async(struct dcerpc_context *dce, int opnum, dcerpc_coder req_coder, void *req, dcerpc_coder rep_coder, int decode_size, dcerpc_cb cb, void *cb_data) | Include | 公开异步 DCERPC request 发送入口，SRVSVC/LSA 调用依赖。 |
| dcerpc_open_async | function | int dcerpc_open_async(struct dcerpc_context *dce, dcerpc_cb cb, void *cb_data) | Include | 公开 named pipe open 入口，连接流程调用。 |
| dcerpc_get_error | function | const char *dcerpc_get_error(struct dcerpc_context *dce) | Include | 公开错误读取入口，转发底层 SMB2 错误。 |
| dcerpc_free_data | function | void dcerpc_free_data(struct dcerpc_context *dce, void *data) | Include | 公开响应数据释放入口，转发底层 SMB2 数据释放。 |
| dcerpc_pdu_direction | function | int dcerpc_pdu_direction(struct dcerpc_pdu *pdu) | Include | 非 static 方向读取 helper，被 IDL coder 决定 decode 分配路径。 |
| dcerpc_align_3264 | function | int dcerpc_align_3264(struct dcerpc_context *ctx, int offset) | Include | 非 static NDR32/NDR64 对齐 helper，具有负 offset 保留语义。 |
| dcerpc_set_tctx | function | void dcerpc_set_tctx(struct dcerpc_context *ctx, int tctx) | Include | 非 static 测试辅助入口，测试强制 transfer syntax。 |
| dcerpc_set_endian | function | void dcerpc_set_endian(struct dcerpc_pdu *pdu, int little_endian) | Include | 非 static 测试辅助入口，测试强制 packed data representation。 |
| dcerpc_get_cr | function | int dcerpc_get_cr(struct dcerpc_pdu *pdu) | Include | 非 static conformance-run 读取 helper，被其他 DCERPC coder 文件前置声明。 |
| dcerpc_set_size_is | function | void dcerpc_set_size_is(struct dcerpc_pdu *pdu, int size_is) | Include | 公开 conformant array size 状态设置入口。 |
| dcerpc_get_size_is | function | int dcerpc_get_size_is(struct dcerpc_pdu *pdu) | Include | 公开 conformant array size 状态读取入口。 |
| dcerpc_set_uint16 | function | static int dcerpc_set_uint16(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, uint16_t value) | Skip | static 基础 helper，行为归属到公开标量 coder。 |
| dcerpc_set_uint32 | function | static int dcerpc_set_uint32(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, uint32_t value) | Skip | static 基础 helper，行为归属到公开标量 coder。 |
| dcerpc_set_uint64 | function | static int dcerpc_set_uint64(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, uint64_t value) | Skip | static 基础 helper，行为归属到公开标量 coder。 |
| dcerpc_get_uint8 | function | static int dcerpc_get_uint8(struct dcerpc_context *ctx, struct smb2_iovec *iov, int *offset, uint8_t *value) | Skip | static 基础 helper，行为归属到公开标量 coder。 |
| dcerpc_get_uint16 | function | static int dcerpc_get_uint16(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, uint16_t *value) | Skip | static 基础 helper，行为归属到公开标量 coder。 |
| dcerpc_get_uint32 | function | static int dcerpc_get_uint32(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, uint32_t *value) | Skip | static 基础 helper，行为归属到公开标量 coder。 |
| dcerpc_get_uint64 | function | static int dcerpc_get_uint64(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu, struct smb2_iovec *iov, int *offset, uint64_t *value) | Skip | static 基础 helper，行为归属到公开标量 coder。 |
| dcerpc_bind_async | function | static int dcerpc_bind_async(struct dcerpc_context *dce, dcerpc_cb cb, void *cb_data) | Skip | static bind helper，调用方可观察语义归属到 `dcerpc_connect_context_async` 和 `dcerpc_open_async`。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| dcerpc_deferred_pointer | struct | lib/dcerpc.c:74 | 保存延迟指针 coder 和对象指针。 |
| MAX_DEFERRED_PTR | macro | lib/dcerpc.c:79 | 延迟指针数组容量为 `1024`。 |
| NDR32_UUID | macro | lib/dcerpc.c:81 | NDR32 transfer syntax UUID 常量。 |
| NDR64_UUID | macro | lib/dcerpc.c:82 | NDR64 transfer syntax UUID 常量。 |
| dcerpc_context | struct | lib/dcerpc.c:96 | 保存 SMB2 上下文、pipe path、syntax、file id、transfer context、data representation 和 call id。 |
| dcerpc_header | struct | lib/dcerpc.c:107 | DCERPC common header 字段布局。 |
| p_cont_elem_t | struct | lib/dcerpc.c:118 | bind presentation context element。 |
| dcerpc_bind_pdu | struct | lib/dcerpc.c:126 | bind PDU body。 |
| ACK_RESULT_ACCEPTANCE | macro | lib/dcerpc.c:140 | bind ack acceptance result 值。 |
| ACK_RESULT_USER_REJECTION | macro | lib/dcerpc.c:141 | bind ack user rejection result 值。 |
| ACK_RESULT_PROVIDER_REJECTION | macro | lib/dcerpc.c:142 | bind ack provider rejection result 值。 |
| dcerpc_bind_context_results | struct | lib/dcerpc.c:149 | bind ack context result。 |
| MAX_ACK_RESULTS | macro | lib/dcerpc.c:156 | bind ack result 数组容量为 `4`。 |
| dcerpc_bind_ack_pdu | struct | lib/dcerpc.c:157 | bind ack PDU body。 |
| dcerpc_request_pdu | struct | lib/dcerpc.c:167 | request PDU body。 |
| dcerpc_response_pdu | struct | lib/dcerpc.c:182 | response PDU body。 |
| PDU_TYPE_REQUEST | macro | lib/dcerpc.c:194 | request PDU type 值。 |
| PDU_TYPE_RESPONSE | macro | lib/dcerpc.c:196 | response PDU type 值。 |
| PDU_TYPE_BIND | macro | lib/dcerpc.c:205 | bind PDU type 值。 |
| PDU_TYPE_BIND_ACK | macro | lib/dcerpc.c:206 | bind ack PDU type 值。 |
| PFC_FIRST_FRAG | macro | lib/dcerpc.c:216 | first fragment flag。 |
| PFC_LAST_FRAG | macro | lib/dcerpc.c:217 | last fragment flag。 |
| NSE_BUF_SIZE | macro | lib/dcerpc.c:225 | DCERPC request/bind encode buffer 大小为 `128*1024`。 |
| dcerpc_cb_data | struct | lib/dcerpc.c:227 | 异步 open/bind callback state。 |
| dcerpc_pdu | struct | lib/dcerpc.c:233 | 保存 header、PDU body、callback、payload、coder、指针队列、方向、alignment 和 size state。 |

## ADDED Requirements

### Requirement: ndr32_syntax transfer syntax identity
系统 MUST 将 `ndr32_syntax` 初始化为 NDR32 UUID、major version `2` 和 minor version `0`。

#### Scenario: Bind proposes NDR32 syntax
- **GIVEN** SMB2 上下文允许 NDR32 协商
- **WHEN** bind PDU presentation context 被构造
- **THEN** 实现将 `&ndr32_syntax` 放入 transfer syntax 列表

Trace: `lib/dcerpc.c:88`, `lib/dcerpc.c:1775`

### Requirement: ndr64_syntax transfer syntax identity
系统 MUST 将 `ndr64_syntax` 初始化为 NDR64 UUID、major version `1` 和 minor version `0`。

#### Scenario: Bind proposes NDR64 syntax
- **GIVEN** SMB2 上下文允许 NDR64 协商
- **WHEN** bind PDU presentation context 被构造
- **THEN** 实现将 `&ndr64_syntax` 放入 transfer syntax 列表

Trace: `lib/dcerpc.c:92`, `lib/dcerpc.c:1790`

### Requirement: dcerpc_set_uint8 bounded byte write
系统 MUST 在写入 8-bit 值前检查 `offset + sizeof(uint8_t)` 未超过 iov 长度，成功后 MUST 写入值并递增 offset。

#### Scenario: Byte write rejects short buffer
- **GIVEN** `*offset + 1` 大于 `iov->len`
- **WHEN** 调用 `dcerpc_set_uint8`
- **THEN** 返回 `-1` 且不递增 offset

Trace: `lib/dcerpc.c:275`

### Requirement: dcerpc_uint64_coder 64-bit scalar coding
系统 MUST 在 conformance pass 记录 8 字节 alignment，在 data pass 按 PDU direction 编解码 64-bit 标量并遵循 packed data representation 字节序。

#### Scenario: NDR scalar coder dispatches by direction
- **GIVEN** PDU direction 为 decode 或 encode
- **WHEN** 调用 `dcerpc_uint64_coder`
- **THEN** 实现分别调用 64-bit get 或 set 路径，失败时返回 `-1`

Trace: `lib/dcerpc.c:419`

### Requirement: dcerpc_get_smb2_context associated SMB2 access
系统 MUST 返回 DCERPC 上下文保存的 SMB2 上下文指针。

#### Scenario: Caller retrieves backing SMB2 context
- **GIVEN** DCERPC 上下文包含 `smb2` 字段
- **WHEN** 调用 `dcerpc_get_smb2_context(dce)`
- **THEN** 返回 `dce->smb2`

Trace: `lib/dcerpc.c:436`, `lib/smb2-share-enum.c:91`

### Requirement: dcerpc_get_pdu_payload payload access
系统 MUST 返回给定 DCERPC PDU 的 payload 指针。

#### Scenario: Decoder allocates data from PDU payload
- **GIVEN** coder 持有 `struct dcerpc_pdu *pdu`
- **WHEN** 调用 `dcerpc_get_pdu_payload(pdu)`
- **THEN** 返回 `pdu->payload`

Trace: `lib/dcerpc.c:442`, `lib/dcerpc-srvsvc.c:138`

### Requirement: dcerpc_create_context context allocation
系统 MUST 为给定 SMB2 上下文分配零初始化 DCERPC 上下文，保存 SMB2 指针，并默认设置 little-endian 数据表示；分配失败时 MUST 返回 `NULL` 并设置 SMB2 错误。

#### Scenario: Context allocation succeeds
- **GIVEN** 调用方提供有效 `struct smb2_context *smb2`
- **WHEN** 调用 `dcerpc_create_context(smb2)`
- **THEN** 返回的上下文保存该 SMB2 指针且 `packed_drep[0]` 包含 `DCERPC_DR_LITTLE_ENDIAN`

Trace: `lib/dcerpc.c:449`, `tests/smb2-dcerpc-coder-test.c:614`

### Requirement: dcerpc_connect_context_async connect and bind setup
系统 MUST 初始化 call id、复制 pipe path、保存 presentation syntax、设置 data representation，并调用 `dcerpc_open_async` 启动 open/bind 流程；path 分配失败时 MUST 返回 `-ENOMEM`。

#### Scenario: Async connect starts named pipe open
- **GIVEN** 调用方提供 DCERPC 上下文、path、syntax、回调和私有数据
- **WHEN** 调用 `dcerpc_connect_context_async`
- **THEN** 实现保存连接状态并调用 `dcerpc_open_async`

Trace: `lib/dcerpc.c:465`, `lib/smb2-share-enum.c:185`

### Requirement: dcerpc_destroy_context context cleanup
系统 MUST 允许 `NULL` DCERPC 上下文输入，并在非 `NULL` 时释放复制的 path 和上下文本身。

#### Scenario: Context cleanup after coder tests
- **GIVEN** 调用方完成 DCERPC 上下文使用
- **WHEN** 调用 `dcerpc_destroy_context(dce)`
- **THEN** 实现释放 `dce->path` 和 `dce`

Trace: `lib/dcerpc.c:490`, `tests/smb2-dcerpc-coder-test.c:631`

### Requirement: dcerpc_free_pdu PDU cleanup
系统 MUST 允许 `NULL` PDU 输入，并在非 `NULL` 时释放 payload 关联数据后释放 PDU 内存。

#### Scenario: Test frees encoded and decoded PDUs
- **GIVEN** coder round-trip 创建 encode 和 decode PDU
- **WHEN** 调用 `dcerpc_free_pdu(dce, pdu)`
- **THEN** 实现释放 payload 关联数据和 PDU 对象

Trace: `lib/dcerpc.c:500`, `tests/smb2-dcerpc-coder-test.c:133`

### Requirement: dcerpc_allocate_pdu PDU allocation
系统 MUST 分配零初始化 DCERPC PDU、设置 call id、direction、top-level 标志和 payload；PDU 或 payload 分配失败时 MUST 设置 SMB2 错误并返回 `NULL`。

#### Scenario: PDU allocation prepares coder state
- **GIVEN** 调用方提供 DCERPC 上下文、direction 和 payload size
- **WHEN** 调用 `dcerpc_allocate_pdu`
- **THEN** 返回的 PDU 包含递增后的 call id、指定 direction、top-level 标志和 payload

Trace: `lib/dcerpc.c:513`, `tests/smb2-dcerpc-coder-test.c:67`

### Requirement: dcerpc_do_coder two-pass coding
系统 MUST 对给定 coder 执行 conformance/alignment pass 和 data pass，并在任一 pass 返回非零时 MUST 返回 `-1`。

#### Scenario: Pointer coder delegates object coding
- **GIVEN** 指针 coder 需要处理被引用对象
- **WHEN** `dcerpc_do_coder` 被调用
- **THEN** 实现先更新最大 alignment 并对齐 offset，再执行实际 coder pass

Trace: `lib/dcerpc.c:548`, `lib/dcerpc.c:748`

### Requirement: dcerpc_uint32_coder 32-bit scalar coding
系统 MUST 在 conformance pass 记录至少 4 字节 alignment，并在 data pass 根据 PDU direction 读取或写入 32-bit 值。

#### Scenario: 32-bit coder follows PDU direction
- **GIVEN** PDU direction 为 decode 或 encode
- **WHEN** 调用 `dcerpc_uint32_coder`
- **THEN** 实现分别调用 32-bit get 或 set 路径

Trace: `lib/dcerpc.c:586`, `lib/dcerpc-srvsvc.c:119`

### Requirement: dcerpc_uint16_coder 16-bit scalar coding
系统 MUST 在 conformance pass 记录至少 2 字节 alignment，并在 data pass 根据 PDU direction 读取或写入 16-bit 值。

#### Scenario: 16-bit coder follows PDU direction
- **GIVEN** PDU direction 为 decode 或 encode
- **WHEN** 调用 `dcerpc_uint16_coder`
- **THEN** 实现分别调用 16-bit get 或 set 路径

Trace: `lib/dcerpc.c:603`, `lib/dcerpc.c:1131`

### Requirement: dcerpc_uint8_coder 8-bit scalar coding
系统 MUST 在 conformance pass 记录至少 1 字节 alignment，并在 data pass 根据 PDU direction 读取或写入 8-bit 值。

#### Scenario: 8-bit coder follows PDU direction
- **GIVEN** PDU direction 为 decode 或 encode
- **WHEN** 调用 `dcerpc_uint8_coder`
- **THEN** 实现分别调用 8-bit get 或 set 路径

Trace: `lib/dcerpc.c:621`, `lib/dcerpc.c:1100`

### Requirement: dcerpc_uint3264_coder transfer-syntax scalar coding
系统 MUST 按当前 transfer context 在 NDR64 下处理 64-bit 表示，在 NDR32 下处理 32-bit 表示并映射到调用方 64-bit 存储。

#### Scenario: NDR32 decodes into 64-bit storage
- **GIVEN** DCERPC 上下文使用 NDR32 transfer context
- **WHEN** 调用 `dcerpc_uint3264_coder` decode 路径
- **THEN** 实现读取 32-bit wire value 并写入调用方 64-bit 存储

Trace: `lib/dcerpc.c:641`, `lib/dcerpc.c:665`

### Requirement: dcerpc_conformance_coder conformance-only processing
系统 MUST 仅在 conformance pass 编解码 conformant 字段，在 data pass 返回成功且不消费数据。

#### Scenario: Data pass skips conformance field
- **GIVEN** PDU 不处于 conformance run
- **WHEN** 调用 `dcerpc_conformance_coder`
- **THEN** 实现返回 `0`

Trace: `lib/dcerpc.c:684`, `lib/dcerpc.c:691`

### Requirement: dcerpc_carray_coder conformant array coding
系统 MUST 先处理 conformant array count，并且只有 wire count 与调用方 `num` 一致时才逐元素调用元素 coder。

#### Scenario: Array count mismatch fails
- **GIVEN** PDU 中 conformant count 与调用方 `num` 不一致
- **WHEN** 调用 `dcerpc_carray_coder`
- **THEN** 实现返回 `-1`

Trace: `lib/dcerpc.c:899`, `lib/dcerpc.c:913`

### Requirement: dcerpc_ptr_coder NDR pointer dispatch
系统 MUST 根据 PDU direction 分派到 encode 或 decode 指针路径，并按 `ptr_type` 处理 REF、UNIQUE 和 FULL 指针。

#### Scenario: Test round-trips reference pointer
- **GIVEN** 测试创建 encode/decode PDU 并传入 `PTR_REF`
- **WHEN** 调用 `dcerpc_ptr_coder`
- **THEN** 对象被编码到 buffer 并按相同期望 offset 解码回来

Trace: `lib/dcerpc.c:928`, `tests/smb2-dcerpc-coder-test.c:73`, `tests/smb2-dcerpc-coder-test.c:122`

### Requirement: dcerpc_utf16z_coder NUL-terminated UTF-16 coding
系统 MUST 使用 NUL 终止模式编解码 `struct dcerpc_utf16`，并在编码时包含结尾 UTF-16 NUL。

#### Scenario: Test round-trips NUL-terminated UTF-16 text
- **GIVEN** 测试输入 `\\win16-1` UTF-8 字符串
- **WHEN** 调用 `dcerpc_utf16z_coder` 编码并解码
- **THEN** 结果匹配测试期望字节序列和原始字符串

Trace: `lib/dcerpc.c:1069`, `tests/smb2-dcerpc-coder-test.c:150`

### Requirement: dcerpc_utf16_coder nonterminated UTF-16 coding
系统 MUST 使用非 NUL 终止模式编解码 `struct dcerpc_utf16`，并按 PDU direction 分派到内部 UTF-16 encode 或 decode 路径。

#### Scenario: Nonterminated UTF-16 coder dispatches by direction
- **GIVEN** 调用方传入 `struct dcerpc_utf16`
- **WHEN** 调用 `dcerpc_utf16_coder`
- **THEN** 实现以 `nult` 为 `0` 调用内部 UTF-16 编码或解码路径

Trace: `lib/dcerpc.c:1083`

### Requirement: dcerpc_header_coder common header coding
系统 MUST 按 DCERPC common header 字段顺序编解码 version、packet type、flags、data representation、fragment length、auth length 和 call id。

#### Scenario: PDU coder processes header before body
- **GIVEN** PDU 需要编码或解码
- **WHEN** `dcerpc_pdu_coder` 调用 `dcerpc_header_coder`
- **THEN** common header 在 PDU body 之前完成处理

Trace: `lib/dcerpc.c:1095`, `lib/dcerpc.c:1413`

### Requirement: dcerpc_uuid_coder UUID field coding
系统 MUST 按 `dcerpc_uuid_t` 字段顺序编解码 UUID，并逐字节处理 `v4` 数组。

#### Scenario: UUID coder walks v4 bytes
- **GIVEN** 调用方提供 `dcerpc_uuid_t *uuid`
- **WHEN** 调用 `dcerpc_uuid_coder`
- **THEN** 实现编解码 `v1`、`v2`、`v3` 后处理 8 个 `v4` 字节

Trace: `lib/dcerpc.c:1148`, `lib/dcerpc.c:1164`

### Requirement: dcerpc_context_handle_coder context handle coding
系统 MUST 按 attributes 后 UUID 的顺序编解码 `struct ndr_context_handle`。

#### Scenario: Context handle fields are serialized in declaration order
- **GIVEN** 调用方提供 `struct ndr_context_handle`
- **WHEN** 调用 `dcerpc_context_handle_coder`
- **THEN** 实现先处理 attributes，再处理 UUID

Trace: `lib/dcerpc.c:1180`, `tests/smb2-dcerpc-coder-test.c:621`

### Requirement: dcerpc_call_async request transceive
系统 MUST 分配 encode PDU、编码 request header 和 payload、修正 fragment length/allocation hint，并通过 SMB2 IOCTL pipe transceive queue 异步请求。

#### Scenario: Async call queues IOCTL transceive
- **GIVEN** 调用方提供 opnum、request coder、response coder、decode size 和 callback
- **WHEN** 调用 `dcerpc_call_async`
- **THEN** 实现编码 DCERPC request 并 queue `SMB2_FSCTL_PIPE_TRANSCEIVE` IOCTL PDU

Trace: `lib/dcerpc.c:1567`, `lib/smb2-share-enum.c:119`

### Requirement: dcerpc_open_async named pipe open
系统 MUST 构造 SMB2 create request 打开 DCERPC pipe，并在分配 callback data 或创建 SMB2 PDU 失败时返回 `-ENOMEM`。

#### Scenario: Open async queues SMB2 create request
- **GIVEN** DCERPC 上下文已设置 pipe path
- **WHEN** 调用 `dcerpc_open_async(dce, cb, cb_data)`
- **THEN** 实现构造 create request、注册回调并 queue SMB2 PDU

Trace: `lib/dcerpc.c:1849`, `lib/dcerpc.c:1887`

### Requirement: dcerpc_get_error error forwarding
系统 MUST 从 DCERPC 上下文关联的 SMB2 上下文返回错误字符串。

#### Scenario: Caller reads last DCERPC error
- **GIVEN** DCERPC 操作失败且底层 SMB2 上下文保存错误文本
- **WHEN** 调用 `dcerpc_get_error(dce)`
- **THEN** 返回底层 `smb2_get_error` 的结果

Trace: `lib/dcerpc.c:1897`

### Requirement: dcerpc_free_data payload data release
系统 MUST 通过关联的 SMB2 上下文释放 DCERPC 响应数据。

#### Scenario: Caller releases command data
- **GIVEN** 调用方从 DCERPC callback 收到需要释放的数据指针
- **WHEN** 调用 `dcerpc_free_data(dce, data)`
- **THEN** 实现转发到底层 SMB2 数据释放函数

Trace: `lib/dcerpc.c:1903`

### Requirement: dcerpc_pdu_direction direction access
系统 MUST 返回 PDU 当前保存的 direction 值。

#### Scenario: IDL coder branches on decode direction
- **GIVEN** IDL coder 需要判断当前 PDU 方向
- **WHEN** 调用 `dcerpc_pdu_direction(pdu)`
- **THEN** 返回 `pdu->direction`

Trace: `lib/dcerpc.c:1909`, `lib/dcerpc-srvsvc.c:134`

### Requirement: dcerpc_align_3264 transfer-syntax alignment
系统 MUST 对非负 offset 按当前 transfer context 执行 NDR64 8 字节或 NDR32 4 字节对齐；负 offset MUST 原样返回。

#### Scenario: Negative offset is preserved
- **GIVEN** offset 小于 `0`
- **WHEN** 调用 `dcerpc_align_3264(ctx, offset)`
- **THEN** 返回原始负值

Trace: `lib/dcerpc.c:1915`

### Requirement: dcerpc_set_tctx test transfer syntax override
系统 MUST 将给定 transfer context id 写入 DCERPC 上下文。

#### Scenario: Test forces NDR64
- **GIVEN** 测试需要使用 NDR64 编码期望字节序列
- **WHEN** 调用 `dcerpc_set_tctx(dce, 1)`
- **THEN** 后续可变宽 coder 使用 NDR64 对齐和宽度

Trace: `lib/dcerpc.c:1931`, `tests/smb2-dcerpc-coder-test.c:199`

### Requirement: dcerpc_set_endian test endian override
系统 MUST 根据 `little_endian` 参数设置或清除 PDU packed data representation 的 little-endian 位。

#### Scenario: Test forces big endian
- **GIVEN** 测试传入 `little_endian` 为 `0`
- **WHEN** 调用 `dcerpc_set_endian(pdu, 0)`
- **THEN** 实现清除 `DCERPC_DR_LITTLE_ENDIAN` 位

Trace: `lib/dcerpc.c:1937`, `tests/smb2-dcerpc-coder-test.c:72`

### Requirement: dcerpc_get_cr conformance-run access
系统 MUST 返回 PDU 当前 `is_conformance_run` 状态。

#### Scenario: External coder checks conformance pass
- **GIVEN** 其他 DCERPC coder 文件需要检查当前 pass
- **WHEN** 调用 `dcerpc_get_cr(pdu)`
- **THEN** 返回 `pdu->is_conformance_run`

Trace: `lib/dcerpc.c:1945`, `lib/dcerpc-srvsvc.c:68`

### Requirement: dcerpc_set_size_is conformant size state
系统 MUST 将给定 size 写入 PDU 的 conformant array `size_is` 状态。

#### Scenario: Container coder stores decoded entry count
- **GIVEN** 解码容器读取到 EntriesRead
- **WHEN** 调用 `dcerpc_set_size_is(pdu, EntriesRead)`
- **THEN** 后续 carray coder 读取该 count

Trace: `lib/dcerpc.c:1950`, `lib/dcerpc-srvsvc.c:135`

### Requirement: dcerpc_get_size_is conformant size state
系统 MUST 返回 PDU 当前保存的 conformant array `size_is` 状态。

#### Scenario: Carray coder reads stored entry count
- **GIVEN** 前序 coder 已设置 PDU `size_is`
- **WHEN** 调用 `dcerpc_get_size_is(pdu)`
- **THEN** 返回该值供 conformant array 编解码使用

Trace: `lib/dcerpc.c:1955`, `lib/dcerpc-srvsvc.c:113`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `dcerpc_connect_context_async` 在 `dcerpc_open_async` 失败后是否应释放已复制的 `path`？ | dcerpc_connect_context_async | 源码显示失败时直接返回 `-1`，未确认调用方是否总是随后销毁 context。 |
| Q-002 | `dcerpc_uint64_coder` encode 路径当前从 `ptr` 按 `uint32_t *` 取值是否为有意截断？ | dcerpc_uint64_coder | 源码在 64-bit set 路径使用 `*(uint32_t *)ptr`，未发现测试覆盖该函数。 |
| Q-003 | `PTR_FULL` decode 分支当前注释为 `not implemented yet`，调用方是否依赖完整指针 decode 语义？ | dcerpc_ptr_coder | 头文件公开 `PTR_FULL`，但实现 decode 分支未处理非空 full pointer 内容。 |
| Q-004 | `smb2_bind_cb` 在 bind ack `num_results` 大于 `MAX_ACK_RESULTS` 时是否依赖上层长度保证？ | dcerpc_connect_context_async | `dcerpc_bind_ack_pdu` 固定 results 容量为 4，但 decode loop 使用 wire `num_results`。 |
