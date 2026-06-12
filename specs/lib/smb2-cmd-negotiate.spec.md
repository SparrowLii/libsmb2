# lib/smb2-cmd-negotiate.c Specification

## Source Context

- Source: `lib/smb2-cmd-negotiate.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: GitNexus context shows `smb2_cmd_negotiate_async` is called by `lib/libsmb2.c:connect_cb`; `smb2_cmd_negotiate_reply_async` is called by `lib/libsmb2.c:smb2_negotiate_request_cb`; negotiate fixed/variable processors are called by `lib/pdu.c` reply/request payload processors and depend on PDU integer accessors plus `smb2_set_error`.
- Build/Compile Context: C source compiled through `lib/CMakeLists.txt` core library source list; source conditionally includes `config.h`, standard integer, stdlib, string, time, sys/time, and stddef headers based on configure/CMake probes.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_cmd_negotiate_async | function | struct smb2_pdu *smb2_cmd_negotiate_async(struct smb2_context *smb2, struct smb2_negotiate_request *req, smb2_command_cb cb, void *cb_data); | Include | 公开 RAW SMB2 Negotiate 异步入口，构造请求 PDU 并决定错误时是否返回 NULL。 |
| smb2_cmd_negotiate_reply_async | function | struct smb2_pdu *smb2_cmd_negotiate_reply_async(struct smb2_context *smb2, struct smb2_negotiate_reply *rep, smb2_command_cb cb, void *cb_data); | Include | 公开/服务端使用的 Negotiate reply PDU 构造入口，影响服务器 negotiate 回调响应。 |
| smb2_process_negotiate_fixed | function | int smb2_process_negotiate_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 内部跨文件 reply fixed parser，被 PDU 分发层调用并建立 negotiate reply payload。 |
| smb2_process_negotiate_variable | function | int smb2_process_negotiate_variable(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 内部跨文件 reply variable parser，解析 security buffer 与 SMB 3.1.1 negotiate contexts。 |
| smb2_process_negotiate_request_fixed | function | int smb2_process_negotiate_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 内部跨文件 request fixed parser，被服务端请求分发层调用并建立 negotiate request payload。 |
| smb2_process_negotiate_request_variable | function | int smb2_process_negotiate_request_variable(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 内部跨文件 request variable parser，填充 dialect 数组并按 SMB 3.1.1 条件解析 contexts。 |
| smb2_encode_preauth_context | function | static int smb2_encode_preauth_context(struct smb2_context *smb2, struct smb2_pdu *pdu) | Skip | 静态 helper，仅为本文件请求/回复编码追加 preauth context，无独立跨文件接口。 |
| smb2_encode_encryption_context | function | static int smb2_encode_encryption_context(struct smb2_context *smb2, struct smb2_pdu *pdu) | Skip | 静态 helper，仅为本文件请求/回复编码追加 encryption context，无独立跨文件接口。 |
| smb2_encode_negotiate_request | function | static int smb2_encode_negotiate_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_negotiate_request *req) | Skip | 静态编码 helper，其行为归属 `smb2_cmd_negotiate_async`。 |
| smb2_encode_negotiate_reply | function | static int smb2_encode_negotiate_reply(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_negotiate_reply *rep) | Skip | 静态编码 helper，其行为归属 `smb2_cmd_negotiate_reply_async`。 |
| smb2_parse_encryption_context | function | static int smb2_parse_encryption_context(struct smb2_context *smb2, struct smb2_negotiate_reply *rep, struct smb2_iovec *iov, int offset) | Skip | 静态 parser helper，仅写入 reply cypher，行为归属 variable reply parser。 |
| smb2_parse_negotiate_contexts | function | static int smb2_parse_negotiate_contexts(struct smb2_context *smb2, struct smb2_negotiate_reply *rep, struct smb2_iovec *iov, int offset, int count) | Skip | 静态 parser helper，错误语义归属 `smb2_process_negotiate_variable`。 |
| smb2_parse_encryption_request_context | function | static int smb2_parse_encryption_request_context(struct smb2_context *smb2, struct smb2_negotiate_request *req, struct smb2_iovec *iov, int offset, int len) | Skip | 静态空实现 helper，无调用方可观察独立状态变化。 |
| smb2_parse_netname_request_context | function | static int smb2_parse_netname_request_context(struct smb2_context *smb2, struct smb2_negotiate_request *req, struct smb2_iovec *iov, int offset, int len) | Skip | 静态 helper 转换并释放 netname，行为归属 request context parser。 |
| smb2_parse_negotiate_request_contexts | function | static int smb2_parse_negotiate_request_contexts(struct smb2_context *smb2, struct smb2_negotiate_request *req, struct smb2_iovec *iov, int offset, int count) | Skip | 静态 parser helper，错误语义归属 `smb2_process_negotiate_request_variable`。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| struct smb2_negotiate_request | struct | include/smb2/smb2.h:117 | 请求字段包括 dialect count/security mode/capabilities/client GUID/context offset/context count 与最多 `SMB2_NEGOTIATE_MAX_DIALECTS` 个 dialect。 |
| struct smb2_negotiate_reply | struct | include/smb2/smb2.h:129 | 回复字段包括 security mode/dialect/cypher/server GUID/capabilities/大小限制/时间/security buffer 与 negotiate context 元数据。 |
| SMB2_NEGOTIATE_REQUEST_SIZE | macro | include/smb2/smb2.h:112 | 固定请求结构大小为 36，用于编码和 fixed parser 校验。 |
| SMB2_NEGOTIATE_REPLY_SIZE | macro | include/smb2/smb2.h:127 | 固定回复结构大小为 65，代码按 `& 0xfffe` 处理 wire fixed iovec 长度。 |
| SMB2_PREAUTH_INTEGRITY_CAP | macro | include/smb2/smb2.h:95 | SMB 3.1.1 negotiate context 类型，编码 SHA-512 preauth capability 并在 parser 中被接受。 |
| SMB2_ENCRYPTION_CAP | macro | include/smb2/smb2.h:96 | negotiate context 类型，编码 AES-128-CCM 能力并在 reply parser 中读取 cypher。 |
| IOV_OFFSET_NEGOTIATE | macro | lib/smb2-cmd-negotiate.c:320 | 根据 reply security buffer offset 计算 variable iovec 内 security buffer 起点。 |
| IOVREQ_OFFSET_NEGOTIATE | macro | lib/smb2-cmd-negotiate.c:481 | request security buffer 偏移宏在当前文件未被使用，保留为实现细节。 |

## ADDED Requirements

### Requirement: smb2_cmd_negotiate_async builds negotiate request PDU
系统 MUST 为客户端 negotiate 请求分配 `SMB2_NEGOTIATE` PDU，编码 fixed request、dialect 列表以及 SMB 3.1.1/ANY 版本所需的 negotiate contexts，并在任一分配、编码或 64-bit padding 步骤失败时释放 PDU 且返回 `NULL`。

#### Scenario: request PDU construction succeeds
- **GIVEN** 调用方提供 `smb2_context`、`smb2_negotiate_request`、回调和回调数据，且 PDU、请求缓冲区、context iovector 与最终 padding 均可成功建立
- **WHEN** 调用 `smb2_cmd_negotiate_async`
- **THEN** 返回的 PDU 使用 `SMB2_NEGOTIATE` command，输出缓冲区包含 request fixed fields、client GUID、dialects，并根据版本条件包含 preauth 与 encryption negotiate contexts

Trace: `lib/smb2-cmd-negotiate.c:smb2_cmd_negotiate_async`, `lib/smb2-cmd-negotiate.c:smb2_encode_negotiate_request`

#### Scenario: request PDU construction fails
- **GIVEN** PDU 分配成功但 request 编码或 64-bit padding 返回失败
- **WHEN** 调用 `smb2_cmd_negotiate_async`
- **THEN** 系统 MUST 释放已分配 PDU 并返回 `NULL`，且不会向调用方返回部分构造的 PDU

Trace: `lib/smb2-cmd-negotiate.c:smb2_cmd_negotiate_async`

### Requirement: smb2_cmd_negotiate_reply_async builds negotiate reply PDU
系统 MUST 为 negotiate reply 分配 `SMB2_NEGOTIATE` PDU，编码 fixed reply、可选 security buffer、SMB 3.1.1/ANY dialect contexts，并在编码或 padding 失败时释放 PDU 且返回 `NULL`。

#### Scenario: reply PDU construction succeeds
- **GIVEN** 调用方提供 reply 数据，且 fixed reply、可选 security buffer、negotiate contexts 与 64-bit padding 都可成功编码
- **WHEN** 调用 `smb2_cmd_negotiate_reply_async`
- **THEN** 返回的 PDU 包含 reply fixed fields、server GUID、capabilities、大小限制、时间字段、security buffer offset/length，并在 dialect 条件匹配时追加 preauth 与 encryption contexts

Trace: `lib/smb2-cmd-negotiate.c:smb2_cmd_negotiate_reply_async`, `lib/smb2-cmd-negotiate.c:smb2_encode_negotiate_reply`

#### Scenario: reply PDU construction fails
- **GIVEN** PDU 分配成功但 reply 编码或 64-bit padding 返回失败
- **WHEN** 调用 `smb2_cmd_negotiate_reply_async`
- **THEN** 系统 MUST 释放已分配 PDU 并返回 `NULL`

Trace: `lib/smb2-cmd-negotiate.c:smb2_cmd_negotiate_reply_async`

### Requirement: smb2_process_negotiate_fixed parses negotiate reply fixed payload
系统 MUST 验证 negotiate reply fixed structure size，分配 `struct smb2_negotiate_reply` payload，填充 fixed reply 字段，并返回后续 variable payload 需要读取的字节数或错误码。

#### Scenario: fixed reply payload is valid
- **GIVEN** 输入 iovec 的 structure size 等于 `SMB2_NEGOTIATE_REPLY_SIZE` 且 wire fixed 长度匹配，并且 reply payload 分配成功
- **WHEN** 调用 `smb2_process_negotiate_fixed`
- **THEN** 系统 MUST 将 `pdu->payload` 设置为新分配的 reply，填充 security mode、dialect、server GUID、capabilities、大小限制、时间和 security buffer 元数据，并按 security buffer 与 SMB 3.1.1 条件返回 variable 字节数

Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_fixed`

#### Scenario: fixed reply rejects invalid size or buffer range
- **GIVEN** fixed reply size 不匹配、security buffer 超出 PDU 长度，或 security buffer 与 reply header 重叠
- **WHEN** 调用 `smb2_process_negotiate_fixed`
- **THEN** 系统 MUST 设置错误信息并返回 `-1`；若已分配 reply payload，系统 MUST 清空 `pdu->payload` 并释放该 payload

Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_fixed`

### Requirement: smb2_process_negotiate_variable parses negotiate reply variable payload
系统 MUST 将 reply security buffer 指向 variable iovec 中的 negotiated security blob，并且仅在 SMB 3.1.1 或更高 dialect 且 context count 非零时解析 negotiate contexts。

#### Scenario: reply variable parsing without contexts
- **GIVEN** reply payload 已由 fixed parser 建立，且 dialect 小于 `SMB2_VERSION_0311` 或 `negotiate_context_count` 为 0
- **WHEN** 调用 `smb2_process_negotiate_variable`
- **THEN** 系统 MUST 设置 `rep->security_buffer` 指向 variable iovec 的 security buffer 位置并返回 `0`，不解析 negotiate contexts

Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_variable`

#### Scenario: reply variable context parsing validates offset and type
- **GIVEN** reply dialect 至少为 `SMB2_VERSION_0311` 且 `negotiate_context_count` 非零
- **WHEN** 调用 `smb2_process_negotiate_variable`
- **THEN** 系统 MUST 校验 context offset 位于 variable iovec 范围内，解析已知 context 类型，在 encryption context 中填充 `rep->cypher`，并对未知 context 类型或越界 context 返回 `-1`

Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_variable`, `lib/smb2-cmd-negotiate.c:smb2_parse_negotiate_contexts`

### Requirement: smb2_process_negotiate_request_fixed parses negotiate request fixed payload
系统 MUST 验证 negotiate request fixed structure size，分配 `struct smb2_negotiate_request` payload，填充 fixed request 字段，并返回 dialect 列表或 SMB 3.1.1 context 尾部所需的 variable 字节数。

#### Scenario: fixed request payload is valid
- **GIVEN** 输入 iovec 的 structure size 等于 `SMB2_NEGOTIATE_REQUEST_SIZE` 且 wire fixed 长度匹配，并且 request payload 分配成功
- **WHEN** 调用 `smb2_process_negotiate_request_fixed`
- **THEN** 系统 MUST 将 `pdu->payload` 设置为 request，填充 dialect count、security mode、capabilities、client GUID、negotiate context offset/count，并在 context count 非零时返回 fixed part 后剩余字节数，否则返回 dialect 列表字节数

Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_request_fixed`

#### Scenario: fixed request rejects invalid size
- **GIVEN** fixed request structure size 或 iovec fixed 长度不匹配，或 request payload 分配失败
- **WHEN** 调用 `smb2_process_negotiate_request_fixed`
- **THEN** 系统 MUST 设置错误信息并返回 `-1`，且不会设置有效 request payload

Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_request_fixed`

### Requirement: smb2_process_negotiate_request_variable parses dialects and SMB 3.1.1 request contexts
系统 MUST 从 variable iovec 读取最多 `SMB2_NEGOTIATE_MAX_DIALECTS` 个 dialect，并且只有当 dialect 列表包含 `0x0311` 且 context count 非零时才解释 negotiate request contexts。

#### Scenario: request variable parsing without SMB 3.1.1 contexts
- **GIVEN** request payload 已由 fixed parser 建立，但 context count 为 0 或读取到的 dialect 列表不包含 `0x0311`
- **WHEN** 调用 `smb2_process_negotiate_request_variable`
- **THEN** 系统 MUST 填充可容纳范围内的 dialect entries 并返回 `0`，不解释 negotiate contexts

Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_request_variable`

#### Scenario: request variable context parsing validates offset and type
- **GIVEN** request payload 声明 context count 非零且 dialect 列表包含 `0x0311`
- **WHEN** 调用 `smb2_process_negotiate_request_variable`
- **THEN** 系统 MUST 校验 context offset 位于 variable iovec 范围内，接受已知 request context 类型和 Samba reserved context，并对未知 context 类型或越界 context 返回 `-1`

Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_request_variable`, `lib/smb2-cmd-negotiate.c:smb2_parse_negotiate_request_contexts`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_encode_negotiate_reply` 中 `seclen` 在 `security_buffer_length == 0` 路径是否存在未初始化参与 `negotiate_context_offset` 计算的行为？ | smb2_cmd_negotiate_reply_async | 源码声明 `int len, seclen;`，仅在 security buffer 分支内赋值，但后续无条件使用 `len + seclen + SMB2_HEADER_SIZE`。 |
| Q-002 | `smb2_encode_negotiate_reply` 对 security buffer padding 使用 `PAD_TO_64BIT(len)` 而不是 security buffer length 是否为有意协议行为？ | smb2_cmd_negotiate_reply_async | 源码中 `seclen = rep->security_buffer_length; seclen = PAD_TO_64BIT(len);`，无法仅从当前文件确认意图。 |
| Q-003 | request context parser 对 `offset > iov->len` 的检查发生在读取 type/len 之后，是否允许越界读取风险？ | smb2_process_negotiate_request_variable | 源码先调用 `smb2_get_uint16` 读取 context header，再检查 offset 上界。 |
| Q-004 | 当前文件是否有专门测试覆盖 negotiate context 解析错误路径？ | file-level | GitNexus context/impact 未返回 test callers，未发现直接测试证据。 |
