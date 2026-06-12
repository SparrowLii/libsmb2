# lib/smb2-cmd-query-directory.c Specification

## Source Context

- Source: `lib/smb2-cmd-query-directory.c`
- Related Headers: `include/smb2/smb2.h`, `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/libsmb2.h`
- Related Tests: `none`
- Related Dependencies: `smb2_set_error`, `smb2_get_uint8`, `smb2_get_uint16`, `smb2_get_uint32`, `smb2_get_uint64`, `smb2_set_uint8`, `smb2_set_uint16`, `smb2_set_uint32`, `smb2_set_uint64`, `smb2_add_iovector`, `smb2_allocate_pdu`, `smb2_free_pdu`, `smb2_pad_to_64bit`, `smb2_utf8_to_utf16`, `smb2_utf16_to_utf8`, `smb2_win_to_timeval`, `smb2_timeval_to_win`, `smb2_alloc_init`
- Build/Compile Context: `CMakeLists.txt` and `configure.ac` build the project as C; source includes `config.h` under `HAVE_CONFIG_H`, defines `_GNU_SOURCE` if absent, and conditionally includes standard headers via `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_decode_fileidfulldirectoryinformation | function | int smb2_decode_fileidfulldirectoryinformation(struct smb2_context *smb2, struct smb2_fileidfulldirectoryinformation *fs, struct smb2_iovec *vec); | Include | 公开声明于 `include/smb2/smb2.h`，解析调用方可见的目录项结构并承担错误语义。 |
| smb2_encode_query_directory_request | function | static int smb2_encode_query_directory_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_query_directory_request *req) | Skip | 文件内静态编码 helper，由公开异步入口封装，无独立外部接口。 |
| smb2_cmd_query_directory_async | function | struct smb2_pdu *smb2_cmd_query_directory_async(struct smb2_context *smb2, struct smb2_query_directory_request *req, smb2_command_cb cb, void *cb_data); | Include | 公开声明于 `include/smb2/libsmb2-raw.h`，创建客户端 Query Directory PDU 并定义失败返回语义。 |
| smb2_encode_query_directory_reply | function | static int smb2_encode_query_directory_reply(struct smb2_context *smb2, uint8_t info_class, uint8_t flags, uint32_t room, struct smb2_pdu *pdu, struct smb2_query_directory_reply *rep) | Skip | 文件内静态服务端回复编码 helper，由公开回复异步入口封装。 |
| smb2_cmd_query_directory_reply_async | function | struct smb2_pdu *smb2_cmd_query_directory_reply_async(struct smb2_context *smb2, struct smb2_query_directory_request *req, struct smb2_query_directory_reply *rep, smb2_command_cb cb, void *cb_data); | Include | 公开声明于 `include/smb2/libsmb2-raw.h`，创建服务端 Query Directory reply PDU。 |
| IOV_OFFSET_DIRECTORY | macro | #define IOV_OFFSET_DIRECTORY (rep->output_buffer_offset - SMB2_HEADER_SIZE - (SMB2_QUERY_DIRECTORY_REPLY_SIZE & 0xfffe)) | Skip | 文件内偏移计算宏，只服务解析实现细节。 |
| smb2_process_query_directory_fixed | function | int smb2_process_query_directory_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 私有头文件声明并由通用 PDU reply 固定部分解析流程调用，影响接收端错误和长度语义。 |
| smb2_process_query_directory_variable | function | int smb2_process_query_directory_variable(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 私有头文件声明并由通用 PDU reply 可变部分解析流程调用，绑定输出缓冲区视图。 |
| IOVREQ_OFFSET_DIRECTORY | macro | #define IOVREQ_OFFSET_DIRECTORY (req->file_name_offset - SMB2_HEADER_SIZE - (SMB2_QUERY_DIRECTORY_REQUEST_SIZE & 0xfffe)) | Skip | 文件内偏移计算宏，只服务请求解析实现细节。 |
| smb2_process_query_directory_request_fixed | function | int smb2_process_query_directory_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 私有头文件声明并由通用 PDU request 固定部分解析流程调用，影响服务端请求校验语义。 |
| smb2_process_query_directory_request_variable | function | int smb2_process_query_directory_request_variable(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 私有头文件声明并由通用 PDU request 可变部分解析流程调用，负责 UTF-16 名称转换和上下文分配。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE | macro | include/smb2/smb2.h:435 | FileIdFullDirectoryInformation 固定字段大小，解码和回复编码使用 80 字节基线。 |
| struct smb2_fileidfulldirectoryinformation | struct | include/smb2/smb2.h:440 | 目录项输出模型，包含时间戳、大小、属性、EA、file_id 和 UTF-8 名称。 |
| SMB2_FILEID_BOTH_DIRECTORY_INFORMATION_SIZE | macro | include/smb2/smb2.h:456 | FileIdBothDirectoryInformation 固定字段大小，回复编码使用 104 字节基线。 |
| struct smb2_fileidbothdirectoryinformation | struct | include/smb2/smb2.h:460 | 服务端回复编码输入模型，包含 full directory 字段以及 short name 字段。 |
| struct smb2_query_directory_request | struct | include/smb2/smb2.h:484 | Query Directory 请求模型，包含信息类别、flags、file index、file id、输出长度和 UTF-8 名称。 |
| SMB2_QUERY_DIRECTORY_REPLY_SIZE | macro | include/smb2/smb2.h:495 | Query Directory reply 固定结构大小，固定部分解析和编码均使用该值。 |
| struct smb2_query_directory_reply | struct | include/smb2/smb2.h:497 | Query Directory reply 模型，携带输出缓冲区偏移、长度和指针。 |

## ADDED Requirements

### Requirement: smb2_decode_fileidfulldirectoryinformation decode directory entry
系统 MUST 在输入向量包含完整 FileIdFullDirectoryInformation 记录时解析固定字段、转换 Windows 时间戳、并把 UTF-16 文件名转换为 UTF-8 名称。

#### Scenario: decode well-formed entry
- **GIVEN** `vec` 至少包含 80 字节固定字段以及 `name_len` 指示的 UTF-16 名称数据
- **WHEN** 调用 `smb2_decode_fileidfulldirectoryinformation` 解码目录项
- **THEN** 函数返回 `0`，填充 `fs` 的索引、大小、属性、EA、file_id、时间字段和 `name`

Trace: `lib/smb2-cmd-query-directory.c:smb2_decode_fileidfulldirectoryinformation`, `include/smb2/smb2.h:smb2_fileidfulldirectoryinformation`

#### Scenario: reject malformed name span
- **GIVEN** `name_len` 溢出 `80 + name_len` 或者名称范围超过 `vec->len`
- **WHEN** 调用 `smb2_decode_fileidfulldirectoryinformation` 解码目录项
- **THEN** 函数 MUST 设置 SMB2 错误并返回 `-1`

Trace: `lib/smb2-cmd-query-directory.c:smb2_decode_fileidfulldirectoryinformation`

### Requirement: smb2_cmd_query_directory_async build request PDU
系统 MUST 为 Query Directory 请求分配 SMB2_QUERY_DIRECTORY PDU，编码固定请求字段和可选名称，并在任一编码、分配或填充步骤失败时释放 PDU 后返回 `NULL`。

#### Scenario: build request with optional name
- **GIVEN** 调用方提供 `smb2_context`、`smb2_query_directory_request`、回调和回调数据
- **WHEN** 调用 `smb2_cmd_query_directory_async` 创建请求 PDU
- **THEN** 函数返回已填充并 64-bit 对齐的 PDU，且在请求名称非空时把 UTF-8 名称编码为 UTF-16 附加 iovec

Trace: `lib/smb2-cmd-query-directory.c:smb2_cmd_query_directory_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_query_directory_async`

#### Scenario: adjust multi-credit charge
- **GIVEN** `smb2->supports_multi_credit` 为真且请求指定 `output_buffer_length`
- **WHEN** `smb2_cmd_query_directory_async` 成功创建 PDU
- **THEN** 函数 MUST 将 `pdu->header.credit_charge` 设置为 `(output_buffer_length - 1) / 65536 + 1`

Trace: `lib/smb2-cmd-query-directory.c:smb2_cmd_query_directory_async`

### Requirement: smb2_cmd_query_directory_reply_async build reply PDU
系统 MUST 为服务端 Query Directory 回复分配 SMB2_QUERY_DIRECTORY PDU，按照请求信息类别编码回复，并在编码或填充失败时释放 PDU 后返回 `NULL`。

#### Scenario: build reply PDU
- **GIVEN** 调用方提供请求、回复、回调和回调数据
- **WHEN** 调用 `smb2_cmd_query_directory_reply_async` 创建回复 PDU
- **THEN** 函数返回已编码并 64-bit 对齐的 PDU，回复固定头包含输出缓冲区偏移和长度

Trace: `lib/smb2-cmd-query-directory.c:smb2_cmd_query_directory_reply_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_query_directory_reply_async`

#### Scenario: encode passthrough or structured output
- **GIVEN** `rep->output_buffer_length` 非零且 `rep->output_buffer` 可用
- **WHEN** 回复编码 helper 被 `smb2_cmd_query_directory_reply_async` 调用
- **THEN** 系统 MUST 在 passthrough 模式复制原始输出缓冲区，否则按 FileIdFull 或 FileIdBoth 格式重新编码目录项并维护 next-entry offset

Trace: `lib/smb2-cmd-query-directory.c:smb2_cmd_query_directory_reply_async`, `lib/smb2-cmd-query-directory.c:smb2_encode_query_directory_reply`

### Requirement: smb2_process_query_directory_fixed validate reply fixed part
系统 MUST 校验 Query Directory reply 固定结构大小、输出缓冲区边界和输出缓冲区偏移，并在有效回复中把 `struct smb2_query_directory_reply` 安装到 `pdu->payload`。

#### Scenario: accept valid reply fixed part
- **GIVEN** 输入 iovec 的结构大小等于 `SMB2_QUERY_DIRECTORY_REPLY_SIZE` 且输出缓冲区范围在 `smb2->spl` 内
- **WHEN** 调用 `smb2_process_query_directory_fixed` 解析 reply 固定部分
- **THEN** 函数返回 `0` 或包含 padding 的输出缓冲区长度，并设置 `pdu->payload`

Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_fixed`, `include/libsmb2-private.h:smb2_process_query_directory_fixed`

#### Scenario: reject invalid reply bounds
- **GIVEN** 固定结构大小不匹配、输出缓冲区越过 PDU 末尾、或者非空输出缓冲区偏移重叠固定头
- **WHEN** 调用 `smb2_process_query_directory_fixed`
- **THEN** 函数 MUST 设置 SMB2 错误、释放已分配 reply 结构并返回 `-1`

Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_fixed`

### Requirement: smb2_process_query_directory_variable bind reply output buffer
系统 MUST 将 Query Directory reply 的 `output_buffer` 指向当前输入 iovec 中固定部分校验确认的可变缓冲区位置。

#### Scenario: bind variable reply buffer
- **GIVEN** `pdu->payload` 已包含 `smb2_query_directory_reply` 且固定部分解析已计算输出偏移
- **WHEN** 调用 `smb2_process_query_directory_variable` 解析 reply 可变部分
- **THEN** 函数返回 `0`，并把 `rep->output_buffer` 设为 `iov->buf[IOV_OFFSET_DIRECTORY]`

Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_variable`, `include/libsmb2-private.h:smb2_process_query_directory_variable`

### Requirement: smb2_process_query_directory_request_fixed validate request fixed part
系统 MUST 校验 Query Directory request 固定结构大小、复制请求字段、校验名称缓冲区边界，并在有效请求中把 `struct smb2_query_directory_request` 安装到 `pdu->payload`。

#### Scenario: accept valid request fixed part
- **GIVEN** 输入 iovec 的结构大小等于 `SMB2_QUERY_DIRECTORY_REQUEST_SIZE` 且名称范围在 PDU 内
- **WHEN** 调用 `smb2_process_query_directory_request_fixed` 解析 request 固定部分
- **THEN** 函数返回 `0` 或包含 padding 的名称缓冲区长度，并填充请求信息类别、flags、file index、file id、名称偏移、名称长度和输出长度

Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_request_fixed`, `include/libsmb2-private.h:smb2_process_query_directory_request_fixed`

#### Scenario: reject invalid request bounds
- **GIVEN** 固定结构大小不匹配、名称范围越过 PDU 末尾、或者非空名称偏移重叠请求固定头
- **WHEN** 调用 `smb2_process_query_directory_request_fixed`
- **THEN** 函数 MUST 设置 SMB2 错误、释放已分配 request 结构并返回 `-1`

Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_request_fixed`

### Requirement: smb2_process_query_directory_request_variable convert request name
系统 MUST 在请求名称长度非零时把 UTF-16 名称转换为 UTF-8，并把复制后的名称存入 SMB2 上下文管理的分配区。

#### Scenario: convert request name
- **GIVEN** `pdu->payload` 已包含 request 且 `file_name_length` 大于 `0`
- **WHEN** 调用 `smb2_process_query_directory_request_variable` 解析 request 可变部分
- **THEN** 函数返回 `0`，并将 `req->name` 指向通过 `smb2_alloc_init` 分配并复制的 UTF-8 字符串

Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_request_variable`, `include/libsmb2-private.h:smb2_process_query_directory_request_variable`

#### Scenario: reject name conversion or allocation failure
- **GIVEN** UTF-16 到 UTF-8 转换失败，或者上下文分配复制缓冲区失败
- **WHEN** 调用 `smb2_process_query_directory_request_variable`
- **THEN** 函数 MUST 设置 SMB2 错误并返回 `-1`

Trace: `lib/smb2-cmd-query-directory.c:smb2_process_query_directory_request_variable`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_encode_query_directory_reply` 参数 `room` 和 `flags` 当前未被使用，是否应作为协议约束记录或视为保留参数？ | smb2_cmd_query_directory_reply_async | 源码未体现这两个参数的调用方可观察行为。 |
| Q-002 | `smb2_decode_fileidfulldirectoryinformation` 未检查 `smb2_utf16_to_utf8` 返回值是否为空，调用方应如何处理名称转换失败？ | smb2_decode_fileidfulldirectoryinformation | 源码只赋值并返回成功，缺少错误路径证据。 |
