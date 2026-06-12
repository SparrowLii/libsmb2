# lib/smb2-cmd-read.c Specification

## Source Context

- Source: `lib/smb2-cmd-read.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`, `include/smb2/libsmb2.h`, `include/libsmb2-private.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context reports callers from `lib/libsmb2.c:smb2_pread_async`, `lib/libsmb2.c:smb2_read_request_cb`, `lib/pdu.c:smb2_process_reply_payload_fixed`, `lib/pdu.c:smb2_process_reply_payload_variable`, `lib/pdu.c:smb2_process_request_payload_fixed`, and `lib/pdu.c:smb2_process_request_payload_variable`; callees include PDU allocation, iovector, padding, integer codec, and error helpers from `lib/pdu.c` and `lib/init.c`.
- Build/Compile Context: C source compiled as part of the core `smb2` library; optional `HAVE_CONFIG_H`, standard header availability macros, and `_GNU_SOURCE` affect included headers only.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_cmd_read_async | function | struct smb2_pdu *smb2_cmd_read_async(struct smb2_context *smb2, struct smb2_read_request *req, smb2_command_cb cb, void *cb_data); | Include | 公开 RAW read 请求构造入口，调用方可观察 PDU 创建、错误返回、输入缓冲区和 credit charge 行为。 |
| smb2_cmd_read_reply_async | function | struct smb2_pdu *smb2_cmd_read_reply_async(struct smb2_context *smb2, struct smb2_read_reply *rep, smb2_command_cb cb, void *cb_data); | Include | 公开 RAW read reply 构造入口，用于服务端/回调路径生成 READ 响应 PDU。 |
| smb2_process_read_fixed | function | int smb2_process_read_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 私有 PDU dispatch 入口解析 READ reply fixed 部分，影响异步 read 回调 payload 和 variable 长度。 |
| smb2_process_read_variable | function | int smb2_process_read_variable(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 私有 PDU dispatch 入口绑定或复制 READ reply variable 数据，影响 payload 数据生命周期。 |
| smb2_process_read_request_fixed | function | int smb2_process_read_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 私有服务端请求解析入口，校验 request fixed 字段、最大读取长度和 channel info 边界。 |
| smb2_process_read_request_variable | function | int smb2_process_read_request_variable(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 私有服务端请求解析入口，绑定 READ request channel info variable 数据。 |
| smb2_encode_read_request | function | static int smb2_encode_read_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_read_request *req) | Skip | 静态 helper，仅支撑 `smb2_cmd_read_async` 的请求编码，无独立跨文件接口。 |
| smb2_encode_read_reply | function | static int smb2_encode_read_reply(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_read_reply *rep) | Skip | 静态 helper，仅支撑 `smb2_cmd_read_reply_async` 的响应编码，无独立跨文件接口。 |
| free_read_reply | function | static void free_read_reply(struct smb2_context *smb2, void * payload) | Skip | 静态释放回调，仅作为 `smb2_process_read_variable` 的 payload 生命周期细节。 |
| IOVREQ_OFFSET_READ | macro | #define IOVREQ_OFFSET_READ ((req->read_channel_info_offset)?(req->read_channel_info_offset - SMB2_HEADER_SIZE - (SMB2_READ_REQUEST_SIZE & 0xfffe)):0) | Skip | 文件内偏移计算宏，仅用于 `smb2_process_read_request_fixed` 的返回长度。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| IOVREQ_OFFSET_READ | macro | lib/smb2-cmd-read.c:321 | 根据 request channel info offset 计算 variable payload 需要读取的相对偏移；仅文件内部使用。 |

## ADDED Requirements

### Requirement: smb2_cmd_read_async read request PDU construction
系统 MUST 为有效的 READ 请求构造 `SMB2_READ` PDU，并在任何分配、编码、输入缓冲区或 padding 失败时返回 `NULL` 且不保留未释放的 PDU。

#### Scenario: 构造普通 READ 请求
- **GIVEN** 调用方提供 `smb2_context`、`smb2_read_request`、回调和回调数据，且请求编码、输入 iovector 和 padding 均成功
- **WHEN** 调用 `smb2_cmd_read_async`
- **THEN** 返回的 PDU 使用 `SMB2_READ` 命令并包含 encoded read request；当 `req->length` 非零时，PDU input vector MUST 指向调用方提供的 `req->buf`

Trace: `lib/smb2-cmd-read.c:smb2_cmd_read_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_read_async`, `lib/libsmb2.c:smb2_pread_async`

#### Scenario: 非 multi-credit 大读取被截断
- **GIVEN** `smb2->supports_multi_credit` 为 false 且 `req->length` 大于 64 KiB
- **WHEN** 调用 `smb2_cmd_read_async`
- **THEN** 请求编码 MUST 将 `req->length` 截断为 64 KiB，并将 `req->minimum_count` 置为 0 后写入请求 PDU

Trace: `lib/smb2-cmd-read.c:smb2_cmd_read_async`, `lib/smb2-cmd-read.c:smb2_encode_read_request`

#### Scenario: 缺少读取数据缓冲区
- **GIVEN** `req->length` 非零且 `req->buf` 为 `NULL`
- **WHEN** 调用 `smb2_cmd_read_async`
- **THEN** 函数 MUST 设置错误 `No buffer for read reply data`、释放已分配 PDU 并返回 `NULL`

Trace: `lib/smb2-cmd-read.c:smb2_cmd_read_async`

#### Scenario: multi-credit credit charge
- **GIVEN** `smb2->supports_multi_credit` 为 true 且 PDU 构造成功
- **WHEN** 调用 `smb2_cmd_read_async`
- **THEN** 返回 PDU 的 `header.credit_charge` MUST 设置为 `(req->length - 1) / 65536 + 1`

Trace: `lib/smb2-cmd-read.c:smb2_cmd_read_async`

### Requirement: smb2_cmd_read_reply_async read reply PDU construction
系统 MUST 为 READ reply 构造 `SMB2_READ` PDU，并在响应编码或 padding 失败时释放 PDU 后返回 `NULL`。

#### Scenario: 构造 READ 响应
- **GIVEN** 调用方提供 `smb2_read_reply`，且 PDU 分配、fixed reply 编码和 padding 均成功
- **WHEN** 调用 `smb2_cmd_read_reply_async`
- **THEN** 返回的 PDU MUST 包含 READ reply fixed 区域；当 `rep->data_length` 非零且 `rep->data` 非空时，PDU output vector MUST 附加 `rep->data` 并使用 `free` 作为释放回调

Trace: `lib/smb2-cmd-read.c:smb2_cmd_read_reply_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_read_reply_async`, `lib/libsmb2.c:smb2_read_request_cb`

#### Scenario: 空 READ 响应数据
- **GIVEN** `rep->data_length` 为 0 或 `rep->data` 为 `NULL`
- **WHEN** 调用 `smb2_cmd_read_reply_async`
- **THEN** 响应 fixed 区域 MUST 将 `data_offset` 编码为 0，且 MUST NOT 附加 data output vector

Trace: `lib/smb2-cmd-read.c:smb2_cmd_read_reply_async`, `lib/smb2-cmd-read.c:smb2_encode_read_reply`

### Requirement: smb2_process_read_fixed read reply fixed parser
系统 MUST 解析 READ reply fixed 部分，分配 `smb2_read_reply` payload，并根据 `data_length` 返回后续 variable 数据长度或错误。

#### Scenario: 无 READ 数据的响应
- **GIVEN** 输入 iovector 的 structure size 不大于 `SMB2_READ_REPLY_SIZE`，且 encoded `data_length` 为 0
- **WHEN** 调用 `smb2_process_read_fixed`
- **THEN** 函数 MUST 分配 reply payload、填充 `data_offset`、`data_length` 和 `data_remaining`，将 `rep->data` 置为 `NULL`，并返回 0

Trace: `lib/smb2-cmd-read.c:smb2_process_read_fixed`, `include/libsmb2-private.h:smb2_process_read_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

#### Scenario: 有 READ 数据的响应
- **GIVEN** encoded `data_length` 非零且 `data_offset` 等于 `SMB2_HEADER_SIZE + 16`
- **WHEN** 调用 `smb2_process_read_fixed`
- **THEN** 函数 MUST 返回 `rep->data_length`，用于请求后续 variable payload 读取

Trace: `lib/smb2-cmd-read.c:smb2_process_read_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

#### Scenario: READ 响应 fixed 字段非法
- **GIVEN** structure size 大于 `SMB2_READ_REPLY_SIZE`，或有数据响应的 `data_offset` 不等于 `SMB2_HEADER_SIZE + 16`
- **WHEN** 调用 `smb2_process_read_fixed`
- **THEN** 函数 MUST 设置错误并返回 -1；若已分配 payload，MUST 清空 `pdu->payload` 并释放该 payload

Trace: `lib/smb2-cmd-read.c:smb2_process_read_fixed`

### Requirement: smb2_process_read_variable read reply variable parser
系统 MUST 将 READ reply variable 数据交付给 reply payload，并按是否已有目标缓冲区决定复制或零拷贝绑定。

#### Scenario: 复制到调用方缓冲区
- **GIVEN** fixed parser 已设置 `pdu->payload` 为 `smb2_read_reply`，且 `rep->data` 已指向调用方缓冲区
- **WHEN** 调用 `smb2_process_read_variable`
- **THEN** 函数 MUST 设置 `pdu->free_payload` 为释放回调，并将输入 iovector 中的 `rep->data_length` 字节复制到 `rep->data`

Trace: `lib/smb2-cmd-read.c:smb2_process_read_variable`, `include/libsmb2-private.h:smb2_process_read_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`

#### Scenario: 零拷贝绑定输入缓冲区
- **GIVEN** fixed parser 已设置 reply payload，且 `rep->data` 为 `NULL`
- **WHEN** 调用 `smb2_process_read_variable`
- **THEN** 函数 MUST 将 `rep->data` 指向当前输入 iovector buffer，并返回 0

Trace: `lib/smb2-cmd-read.c:smb2_process_read_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`

### Requirement: smb2_process_read_request_fixed read request fixed parser
系统 MUST 解析 READ request fixed 部分，校验请求大小、读取长度和 channel info 偏移，并返回后续 variable payload 需求。

#### Scenario: 无 channel info 的 READ 请求
- **GIVEN** 输入 iovector 的 structure size 不大于 `SMB2_READ_REQUEST_SIZE`，请求长度不超过 `smb2->max_read_size`，且 `read_channel_info_length` 为 0
- **WHEN** 调用 `smb2_process_read_request_fixed`
- **THEN** 函数 MUST 分配 request payload、解码 flags、length、offset、file_id、minimum_count、channel 和 remaining_bytes，并返回 0

Trace: `lib/smb2-cmd-read.c:smb2_process_read_request_fixed`, `include/libsmb2-private.h:smb2_process_read_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

#### Scenario: 有 channel info 的 READ 请求
- **GIVEN** `read_channel_info_length` 非零，读取长度不超过 `smb2->max_read_size`，且 channel info offset 不早于 SMB2 header 加 read request fixed 区域
- **WHEN** 调用 `smb2_process_read_request_fixed`
- **THEN** 函数 MUST 返回 `IOVREQ_OFFSET_READ + req->read_channel_info_length`，用于请求后续 variable payload 读取

Trace: `lib/smb2-cmd-read.c:smb2_process_read_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

#### Scenario: READ 请求 fixed 字段非法
- **GIVEN** structure size 大于 `SMB2_READ_REQUEST_SIZE`，或 `req->length` 大于 `smb2->max_read_size`，或 channel info offset 与 fixed request 区域重叠
- **WHEN** 调用 `smb2_process_read_request_fixed`
- **THEN** 函数 MUST 设置错误并返回 -1；若已分配 request payload，MUST 清空 `pdu->payload` 并释放该 payload

Trace: `lib/smb2-cmd-read.c:smb2_process_read_request_fixed`

### Requirement: smb2_process_read_request_variable read request variable parser
系统 MUST 将 READ request variable payload 绑定为 request 的 channel info 数据。

#### Scenario: 绑定 channel info 数据
- **GIVEN** fixed parser 已设置 `pdu->payload` 为 `smb2_read_request`，且当前输入 iovector 包含 channel info bytes
- **WHEN** 调用 `smb2_process_read_request_variable`
- **THEN** 函数 MUST 将 `req->read_channel_info` 指向当前输入 iovector buffer，并返回 0

Trace: `lib/smb2-cmd-read.c:smb2_process_read_request_variable`, `include/libsmb2-private.h:smb2_process_read_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_process_read_request_fixed` 在读取 offset 44 前检查了未初始化的 `req->read_channel_info_length`；实际是否依赖 `calloc` 使该分支永远不执行，从而忽略 wire 中的 channel info offset？ | smb2_process_read_request_fixed | 源码先判断 `req->read_channel_info_length` 再在后续读取该字段，行为可能与协议意图不一致。 |
| Q-002 | `smb2_cmd_read_async` 在 `supports_multi_credit` 为 true 且 `req->length` 为 0 时是否允许 credit_charge 按无符号下溢计算？ | smb2_cmd_read_async | 公式 `(req->length - 1) / 65536 + 1` 对 0 长度请求的预期语义未由测试确认。 |
| Q-003 | GitNexus impact CLI 对同名声明和定义返回 ambiguous，无法用当前 CLI UID 参数消歧；风险等级和测试影响范围需在支持 UID impact 后复核。 | file-level | `gitnexus impact` 不接受 `--uid` 或 `--target-uid`，只能记录 context caller 证据。 |
