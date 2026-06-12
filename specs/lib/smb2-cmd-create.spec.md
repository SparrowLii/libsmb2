# lib/smb2-cmd-create.c Specification

## Source Context

- Source: `lib/smb2-cmd-create.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context reports `smb2_cmd_create_async` is called by `lib/libsmb2.c` create/open/stat/mkdir/rename/truncate/readlink paths and `lib/dcerpc.c:dcerpc_open_async`; `smb2_cmd_create_reply_async` is called by `lib/libsmb2.c:smb2_create_request_cb`; fixed/variable create parsers are called by `lib/pdu.c` reply/request payload processing; implementation depends on PDU allocation/free/padding, integer get/set helpers, SMB2 allocation, UTF-8/UTF-16 conversion, and error reporting.
- Build/Compile Context: C source compiled into the core `smb2` library; source includes optional `HAVE_CONFIG_H`, `_GNU_SOURCE`, standard header feature probes, `compat.h`, `smb2.h`, `libsmb2.h`, and `libsmb2-private.h`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_create_request | function | `static int smb2_encode_create_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_create_request *req)` | Skip | 静态 helper，仅服务 `smb2_cmd_create_async` 的请求编码，错误和资源语义归属到公开入口。 |
| smb2_cmd_create_async | function | `struct smb2_pdu *smb2_cmd_create_async(struct smb2_context *smb2, struct smb2_create_request *req, smb2_command_cb cb, void *cb_data)` | Include | RAW create 公开构造入口，跨模块调用并决定 PDU 生命周期、路径编码和失败返回。 |
| smb2_encode_create_reply | function | `static int smb2_encode_create_reply(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_create_reply *rep)` | Skip | 静态 helper，仅服务 `smb2_cmd_create_reply_async` 的回复编码，行为归属到公开 reply builder。 |
| smb2_cmd_create_reply_async | function | `struct smb2_pdu *smb2_cmd_create_reply_async(struct smb2_context *smb2, struct smb2_create_reply *rep, smb2_command_cb cb, void *cb_data)` | Include | SMB2 server-side create reply PDU 构造入口，被请求回调路径跨文件调用。 |
| smb2_process_create_fixed | function | `int smb2_process_create_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有但跨文件声明的 reply fixed parser，影响 PDU payload、长度校验和后续 variable 读取。 |
| smb2_process_create_variable | function | `int smb2_process_create_variable(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有但跨文件声明的 reply variable parser，决定 create context 指针暴露语义。 |
| smb2_process_create_request_fixed | function | `int smb2_process_create_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有但跨文件声明的 request fixed parser，影响 server-side 请求 payload、name/context 边界校验和剩余长度。 |
| smb2_process_create_request_variable | function | `int smb2_process_create_request_variable(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 私有但跨文件声明的 request variable parser，执行 UTF-16 名称转换、SMB2 内存归属和 create context 指针绑定。 |
| CCX_OFFSET | macro | `#define CCX_OFFSET() PAD_TO_64BIT(SMB2_HEADER_SIZE + (SMB2_CREATE_REQUEST_SIZE & 0xfffe) + (req->name_length ? req->name_length : 1));` | Skip | 文件内未使用宏，无当前调用方可观察行为。 |
| IOV_OFFSET_CREATE | macro | `#define IOV_OFFSET_CREATE (rep->create_context_offset - SMB2_HEADER_SIZE - (SMB2_CREATE_REPLY_SIZE & 0xfffe))` | Skip | 文件内 offset helper，仅支持 included parser 的场景描述。 |
| IOVREQ_OFFSET_CREATE | macro | `#define IOVREQ_OFFSET_CREATE (req->name_offset - SMB2_HEADER_SIZE - (SMB2_CREATE_REQUEST_SIZE & 0xfffe))` | Skip | 文件内 offset helper，仅支持 included request parser 的场景描述。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| struct smb2_create_request | struct | `include/smb2/smb2.h:324` | Create 请求模型包含安全标志、oplock、访问掩码、共享模式、创建处置、名称 offset/length、UTF-8 name 和 create context 指针/长度。 |
| struct smb2_create_reply | struct | `include/smb2/smb2.h:361` | Create 回复模型包含 oplock、action、时间戳、大小、属性、file_id 和 create context 指针/offset/length。 |
| SMB2_CREATE_REQUEST_SIZE | macro | `include/smb2/smb2.h` | 请求 fixed structure size，由编码和解析路径用于结构长度校验。 |
| SMB2_CREATE_REPLY_SIZE | macro | `include/smb2/smb2.h:342` | 回复 fixed structure size 为 89，编码和解析以低 bit 清除后的长度作为 iovec fixed 长度。 |
| SMB2_FD_SIZE | macro | `include/smb2/smb2.h:344` | file_id 复制长度为 16 字节。 |

## ADDED Requirements

### Requirement: smb2_cmd_create_async create request PDU construction
系统 MUST 为有效的 create request 构造 SMB2_CREATE PDU，并在本地分配、请求编码或最终 64-bit padding 失败时返回 `NULL` 且释放已分配 PDU。

#### Scenario: encode create request with name and context
- **GIVEN** 调用方提供包含 UTF-8 `req->name`、可选 `req->create_context` 和 create 字段的 `struct smb2_create_request`
- **WHEN** 调用 `smb2_cmd_create_async(smb2, req, cb, cb_data)` 构造 RAW create 请求
- **THEN** 返回的 PDU MUST 使用 SMB2_CREATE command，fixed request 写入安全标志、oplock、访问掩码、共享模式、处置和选项，非空名称 MUST 转为 UTF-16 并将 `/` 替换为 `\`，name 和 create context MUST 按 64-bit 边界 padding 后追加到输出 iovec

Trace: `lib/smb2-cmd-create.c:smb2_cmd_create_async`, `lib/smb2-cmd-create.c:smb2_encode_create_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_create_async`

#### Scenario: fail without invoking callback on local setup error
- **GIVEN** PDU allocation、request buffer allocation、UTF-16 conversion、iovector append 或 final padding 任一步失败
- **WHEN** 调用 `smb2_cmd_create_async(smb2, req, cb, cb_data)`
- **THEN** 函数 MUST 返回 `NULL`，本地已分配的 PDU MUST 释放，且 header 注释承诺 callback 不会被调用

Trace: `lib/smb2-cmd-create.c:smb2_cmd_create_async`, `lib/smb2-cmd-create.c:smb2_encode_create_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_create_async`

### Requirement: smb2_cmd_create_reply_async create reply PDU construction
系统 MUST 为 server-side create reply 构造 SMB2_CREATE PDU，并将 fixed reply、file id 和可选 create context 按 SMB2 wire layout 写入输出 iovec。

#### Scenario: encode create reply with file id and optional context
- **GIVEN** 调用方提供包含 oplock、flags、create_action、时间戳、大小、属性、`file_id` 和可选 create context 的 `struct smb2_create_reply`
- **WHEN** 调用 `smb2_cmd_create_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 返回的 PDU MUST 写入 SMB2_CREATE reply fixed fields，MUST 复制 `SMB2_FD_SIZE` 字节 file id，MUST 将 `create_context_offset` 设为 fixed reply 后的 64-bit aligned offset，并在存在 create context 时追加 padded context buffer

Trace: `lib/smb2-cmd-create.c:smb2_cmd_create_reply_async`, `lib/smb2-cmd-create.c:smb2_encode_create_reply`, `include/smb2/libsmb2-raw.h:smb2_cmd_create_reply_async`

#### Scenario: release PDU on reply encoding failure
- **GIVEN** reply PDU allocation 后，fixed reply buffer、context buffer、iovector append 或 final padding 失败
- **WHEN** 调用 `smb2_cmd_create_reply_async(smb2, rep, cb, cb_data)`
- **THEN** 函数 MUST 释放已分配 PDU 并返回 `NULL`

Trace: `lib/smb2-cmd-create.c:smb2_cmd_create_reply_async`, `lib/smb2-cmd-create.c:smb2_encode_create_reply`

### Requirement: smb2_process_create_fixed parse create reply fixed payload
系统 MUST 校验 create reply fixed payload 的结构大小，并在成功时分配 `struct smb2_create_reply` 作为 `pdu->payload`。

#### Scenario: reject invalid create reply fixed size
- **GIVEN** 当前输入 iovec 的 structure size 不等于 `SMB2_CREATE_REPLY_SIZE` 或 masked structure size 不等于 iovec 长度
- **WHEN** 调用 `smb2_process_create_fixed(smb2, pdu)`
- **THEN** 函数 MUST 设置错误并返回 `-1`，且不得向调用方暴露成功解析的 reply payload

Trace: `lib/smb2-cmd-create.c:smb2_process_create_fixed`, `include/libsmb2-private.h:smb2_process_create_fixed`

#### Scenario: parse reply fixed fields and return variable byte count
- **GIVEN** create reply fixed payload 长度有效且包含非零 create context length
- **WHEN** 调用 `smb2_process_create_fixed(smb2, pdu)`
- **THEN** 函数 MUST 读取 oplock、flags、create_action、时间戳、大小、属性、file_id、context offset 和 length；当 context offset 不覆盖 fixed header 时 MUST 返回 context 前 padding 加 context length 的字节数

Trace: `lib/smb2-cmd-create.c:smb2_process_create_fixed`, `include/libsmb2-private.h:smb2_process_create_fixed`

### Requirement: smb2_process_create_variable expose create reply context
系统 MUST 在 create reply variable 解析阶段仅通过 `rep->create_context` 暴露已接收 buffer 内的 create context 指针，不复制 context 内容。

#### Scenario: bind reply context pointer when length is present
- **GIVEN** `pdu->payload` 是已解析的 `struct smb2_create_reply` 且 `rep->create_context_length` 非零
- **WHEN** 调用 `smb2_process_create_variable(smb2, pdu)`
- **THEN** 函数 MUST 将 `rep->create_context` 设置为当前输入 iovec 中由 `rep->create_context_offset` 推导出的位置，并返回 `0`

Trace: `lib/smb2-cmd-create.c:smb2_process_create_variable`, `include/libsmb2-private.h:smb2_process_create_variable`

#### Scenario: clear reply context pointer when length is absent
- **GIVEN** `pdu->payload` 是已解析的 `struct smb2_create_reply` 且 `rep->create_context_length` 为 0
- **WHEN** 调用 `smb2_process_create_variable(smb2, pdu)`
- **THEN** 函数 MUST 将 `rep->create_context` 保持为 `NULL` 并返回 `0`

Trace: `lib/smb2-cmd-create.c:smb2_process_create_variable`

### Requirement: smb2_process_create_request_fixed parse create request fixed payload
系统 MUST 校验 create request fixed payload 的结构大小和 variable 区域边界，并在成功时分配 `struct smb2_create_request` 作为 `pdu->payload`。

#### Scenario: reject invalid request fixed size or overlapping variable offsets
- **GIVEN** 当前输入 iovec 的 structure size 无效，或非零 name/create context offset 指向 SMB2 header 加 fixed request 区域之前
- **WHEN** 调用 `smb2_process_create_request_fixed(smb2, pdu)`
- **THEN** 函数 MUST 设置错误并返回 `-1`；对于 offset overlap 失败，函数 MUST 清除 `pdu->payload` 并释放已分配 request

Trace: `lib/smb2-cmd-create.c:smb2_process_create_request_fixed`, `include/libsmb2-private.h:smb2_process_create_request_fixed`

#### Scenario: parse request fixed fields and compute variable byte count
- **GIVEN** create request fixed payload 长度有效，name 或 create context length 非零且 offsets 未覆盖 header
- **WHEN** 调用 `smb2_process_create_request_fixed(smb2, pdu)`
- **THEN** 函数 MUST 读取 request fixed fields，MUST 初始设置 `req->name` 为 `NULL`，并返回 name 区域、padding 和 create context length 所需的 remaining 字节数

Trace: `lib/smb2-cmd-create.c:smb2_process_create_request_fixed`, `include/libsmb2-private.h:smb2_process_create_request_fixed`

### Requirement: smb2_process_create_request_variable decode request name and context
系统 MUST 在 create request variable 解析阶段把非空 UTF-16 name 转换为 SMB2 上下文分配的 UTF-8 字符串，并将 create context 指向输入 buffer 中的对应位置。

#### Scenario: convert request name into SMB2-owned UTF-8 buffer
- **GIVEN** `pdu->payload` 是已解析的 `struct smb2_create_request` 且 `req->name_length` 非零
- **WHEN** 调用 `smb2_process_create_request_variable(smb2, pdu)`
- **THEN** 函数 MUST 将 UTF-16 name 转为 UTF-8，MUST 使用 `smb2_alloc_init` 分配 SMB2-owned name buffer 并复制包含 NUL 结尾的字符串，转换或分配失败时 MUST 设置错误并返回 `-1`

Trace: `lib/smb2-cmd-create.c:smb2_process_create_request_variable`, `include/libsmb2-private.h:smb2_process_create_request_variable`

#### Scenario: attach request create context without parsing it
- **GIVEN** `req->create_context_length` 和 `req->create_context_offset` 均非零
- **WHEN** 调用 `smb2_process_create_request_variable(smb2, pdu)`
- **THEN** 函数 MUST 将 `req->create_context` 设置为当前输入 iovec 中 offset 指向的位置，且 MUST NOT 解析 create context 内容

Trace: `lib/smb2-cmd-create.c:smb2_process_create_request_variable`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_process_create_variable` 未检查 `IOV_OFFSET_CREATE` 是否超过当前 iovec 长度；调用方是否已保证 Step fixed 返回的 variable 长度完成边界保护？ | smb2_process_create_variable | 源码只计算指针和长度，GitNexus context 只显示由 `lib/pdu.c` variable payload dispatcher 调用，未回读 dispatcher 的完整边界契约。 |
| Q-002 | `smb2_process_create_request_variable` 转换 name 时从 variable iovec 起始地址读取，而不是显式加 `IOVREQ_OFFSET_CREATE`；调用方传入的 variable iovec 是否已裁剪到 name 起点？ | smb2_process_create_request_variable | 当前文件无法单独确认 `lib/pdu.c` 对 request variable buffer 的切片语义。 |
| Q-003 | `CCX_OFFSET` 宏在当前文件未使用，是否为历史遗留或供未来 create context offset 计算使用？ | CCX_OFFSET | 源码未引用，GitNexus 未提供宏使用关系证据。 |
| Q-004 | GitNexus UID impact 对关键接口返回 LOW 但 `partial: true`，并报告 read-only traversal warning；完整上游影响范围是否应以 `context` incoming calls 为准？ | file-level | impact traversal 未完整写入深度遍历结果，context 已显示多条跨模块调用。 |
