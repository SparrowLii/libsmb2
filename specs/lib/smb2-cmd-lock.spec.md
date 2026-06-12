# lib/smb2-cmd-lock.c Specification

## Source Context

- Source: `lib/smb2-cmd-lock.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `none`
- Related Dependencies: GitNexus `context` shows `smb2_cmd_lock_reply_async` is called by `lib/libsmb2.c:smb2_lock_request_cb`; `smb2_process_lock_fixed` is called by `lib/pdu.c:smb2_process_reply_payload_fixed`; `smb2_process_lock_request_fixed` is called by `lib/pdu.c:smb2_process_request_payload_fixed`; `smb2_process_lock_request_variable` is called by `lib/pdu.c:smb2_process_request_payload_variable`. Source review also confirms lock request dispatch in `lib/libsmb2.c:smb2_lock_request_cb` and fixed-size routing in `lib/pdu.c`.
- Build/Compile Context: C source compiled through core library build; optional `HAVE_CONFIG_H`, `_GNU_SOURCE`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H` include paths affect headers only.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_lock_request | function | static int smb2_encode_lock_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_lock_request *req) | Skip | 静态编码 helper，仅由本文件 `smb2_cmd_lock_async` 调用，行为归属到公开 lock PDU 构造接口。 |
| smb2_cmd_lock_async | function | struct smb2_pdu *smb2_cmd_lock_async(struct smb2_context *smb2, struct smb2_lock_request *req, smb2_command_cb cb, void *cb_data); | Include | RAW SMB2 Lock 请求构造入口，声明在公开 raw header 中并返回可排队 PDU。 |
| smb2_encode_lock_reply | function | static int smb2_encode_lock_reply(struct smb2_context *smb2, struct smb2_pdu *pdu) | Skip | 静态编码 helper，仅由本文件 `smb2_cmd_lock_reply_async` 调用，行为归属到服务端 lock reply 构造接口。 |
| smb2_cmd_lock_reply_async | function | struct smb2_pdu *smb2_cmd_lock_reply_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data); | Include | SMB2 Lock 成功回复 PDU 构造入口，被服务端 lock request callback 调用。 |
| smb2_process_lock_fixed | function | int smb2_process_lock_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 客户端接收 SMB2 Lock reply 固定区解析入口，声明在私有 header 并由 PDU 分发调用。 |
| smb2_parse_locks | function | static int smb2_parse_locks(struct smb2_context *smb2, struct smb2_iovec *iov, uint32_t offset, int count, void *locks) | Skip | 静态 lock element 解析 helper，空指针和循环读取行为归属到 request fixed/variable 解析接口。 |
| smb2_process_lock_request_fixed | function | int smb2_process_lock_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 服务端接收 SMB2 Lock request 固定区解析入口，负责 payload 分配、基础字段解析和变量区长度返回。 |
| smb2_process_lock_request_variable | function | int smb2_process_lock_request_variable(struct smb2_context *smb2, struct smb2_pdu *pdu); | Include | 服务端接收 SMB2 Lock request 变量区解析入口，补充解析剩余 lock elements。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_LOCK_ELEMENT_SIZE | macro | include/smb2/smb2.h:1212 | Lock element wire size is 24 bytes and is used for fixed and variable element offsets. |
| smb2_lock_element | struct | include/smb2/smb2.h:1214 | Lock element carries `offset`, `length`, `flags`, and `reserved`; this file serializes/deserializes the first three fields. |
| SMB2_LOCK_REQUEST_SIZE | macro | include/smb2/smb2.h:1222 | Lock request fixed size is 48 bytes and includes one lock element. |
| smb2_lock_request | struct | include/smb2/smb2.h:1224 | Request model carries lock count, sequence fields, file id, and allocated lock element array. |
| SMB2_LOCK_REPLY_SIZE | macro | include/smb2/smb2.h:1232 | Lock reply fixed size is 4 bytes. |

## ADDED Requirements

### Requirement: smb2_cmd_lock_async build lock request PDU
系统 MUST construct an SMB2_LOCK request PDU whose fixed request body contains the lock structure size, lock count, combined sequence number/index field, file id, and available lock elements from the supplied `smb2_lock_request`.

#### Scenario: construct single-lock request
- **GIVEN** a context, callback, callback data, and a lock request with `lock_count` set to one and `locks` pointing to at least one element
- **WHEN** `smb2_cmd_lock_async` is called
- **THEN** the returned PDU contains an SMB2_LOCK command with a 48-byte fixed body, the first lock encoded in the fixed body, and output padding aligned to 64 bits

Trace: `lib/smb2-cmd-lock.c:smb2_cmd_lock_async`, `lib/smb2-cmd-lock.c:smb2_encode_lock_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_lock_async`

#### Scenario: construct multi-lock request
- **GIVEN** a lock request with `lock_count` greater than one and `locks` pointing to an array with all requested elements
- **WHEN** `smb2_cmd_lock_async` is called
- **THEN** the first lock is encoded in the fixed body and each additional lock is encoded in a padded variable iovector using 24-byte element slots

Trace: `lib/smb2-cmd-lock.c:smb2_cmd_lock_async`, `lib/smb2-cmd-lock.c:smb2_encode_lock_request`, `include/smb2/smb2.h:SMB2_LOCK_ELEMENT_SIZE`

#### Scenario: fail request allocation or padding
- **GIVEN** PDU allocation, request body allocation, iovector attachment, lock element allocation, or 64-bit padding fails
- **WHEN** `smb2_cmd_lock_async` attempts to build the request PDU
- **THEN** the function returns `NULL`, frees any allocated PDU after encode or padding failure, and records an error for encode allocation or iovector failures

Trace: `lib/smb2-cmd-lock.c:smb2_cmd_lock_async`, `lib/smb2-cmd-lock.c:smb2_encode_lock_request`

### Requirement: smb2_cmd_lock_reply_async build lock reply PDU
系统 MUST construct an SMB2_LOCK reply PDU with the lock reply structure size and 64-bit output padding when a server handler accepts a lock request.

#### Scenario: construct successful lock reply
- **GIVEN** a context, callback, and callback data for a successful server-side lock command
- **WHEN** `smb2_cmd_lock_reply_async` is called
- **THEN** the returned PDU uses command SMB2_LOCK, contains a 4-byte lock reply structure, and has its output padded to a 64-bit boundary

Trace: `lib/smb2-cmd-lock.c:smb2_cmd_lock_reply_async`, `lib/smb2-cmd-lock.c:smb2_encode_lock_reply`, `lib/libsmb2.c:smb2_lock_request_cb`

#### Scenario: fail reply allocation or padding
- **GIVEN** PDU allocation, reply buffer allocation, iovector attachment, or 64-bit padding fails
- **WHEN** `smb2_cmd_lock_reply_async` attempts to build the reply PDU
- **THEN** the function returns `NULL`, frees any allocated PDU after encode or padding failure, and records an error for encode allocation or iovector failures

Trace: `lib/smb2-cmd-lock.c:smb2_cmd_lock_reply_async`, `lib/smb2-cmd-lock.c:smb2_encode_lock_reply`

### Requirement: smb2_process_lock_fixed validate lock reply fixed body
系统 MUST accept only SMB2 Lock replies whose fixed body reports `SMB2_LOCK_REPLY_SIZE` and whose even-size masked structure size matches the received iovector length.

#### Scenario: accept valid lock reply size
- **GIVEN** the current input iovector contains a lock reply with structure size `SMB2_LOCK_REPLY_SIZE` and matching received length
- **WHEN** `smb2_process_lock_fixed` parses the fixed reply payload
- **THEN** the function returns `0` without allocating command data

Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

#### Scenario: reject invalid lock reply size
- **GIVEN** the current input iovector contains a lock reply whose structure size is not `SMB2_LOCK_REPLY_SIZE` or whose masked size does not match the iovector length
- **WHEN** `smb2_process_lock_fixed` parses the fixed reply payload
- **THEN** the function records an unexpected-size error and returns `-1`

Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_fixed`, `include/smb2/smb2.h:SMB2_LOCK_REPLY_SIZE`

### Requirement: smb2_process_lock_request_fixed parse lock request fixed body
系统 MUST validate the SMB2 Lock request fixed body, allocate a `smb2_lock_request` payload, decode sequence and file-id fields, require at least one lock, parse the first lock element, and return the remaining variable-byte count.

#### Scenario: parse valid lock request fixed body
- **GIVEN** the current input iovector contains a lock request with structure size `SMB2_LOCK_REQUEST_SIZE`, matching received length, and `lock_count` of at least one
- **WHEN** `smb2_process_lock_request_fixed` parses the fixed request payload
- **THEN** the function stores a newly allocated `smb2_lock_request` in `pdu->payload`, decodes the sequence number from the high 4 bits, decodes the sequence index from the low 28 bits, copies the file id, parses the first lock element, and returns `SMB2_LOCK_ELEMENT_SIZE * (lock_count - 1)`

Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`, `include/smb2/smb2.h:smb2_lock_request`

#### Scenario: reject malformed or empty lock request
- **GIVEN** the fixed request iovector has an unexpected structure size, mismatched masked length, or a decoded `lock_count` less than one
- **WHEN** `smb2_process_lock_request_fixed` parses the fixed request payload
- **THEN** the function records an error, returns `-1`, and clears/frees the partially allocated payload when rejection happens after payload allocation

Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_request_fixed`, `include/smb2/smb2.h:SMB2_LOCK_REQUEST_SIZE`

#### Scenario: fail lock request allocation
- **GIVEN** allocation of the request payload or lock element array fails
- **WHEN** `smb2_process_lock_request_fixed` parses the fixed request payload
- **THEN** the function records an allocation error, returns `-1`, and clears/frees the request payload when the element array allocation fails

Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_request_fixed`, `lib/alloc.c:smb2_alloc_init`

### Requirement: smb2_process_lock_request_variable parse remaining lock elements
系统 MUST parse the remaining SMB2 Lock request elements from the variable input iovector into the already allocated request lock array after the first fixed-body element.

#### Scenario: parse additional lock elements
- **GIVEN** `pdu->payload` is a lock request previously populated by `smb2_process_lock_request_fixed` with `lock_count` greater than one
- **WHEN** `smb2_process_lock_request_variable` is called for the variable payload
- **THEN** the function parses `lock_count - 1` additional lock elements from offset zero into `req->locks + 1` and returns `0` on success

Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_request_variable`, `lib/smb2-cmd-lock.c:smb2_parse_locks`, `lib/pdu.c:smb2_process_request_payload_variable`

#### Scenario: reject missing variable parse targets
- **GIVEN** the variable parse helper receives a missing iovector or missing lock output pointer
- **WHEN** lock element parsing is requested
- **THEN** the helper returns `-1` and `smb2_process_lock_request_variable` propagates that failure

Trace: `lib/smb2-cmd-lock.c:smb2_process_lock_request_variable`, `lib/smb2-cmd-lock.c:smb2_parse_locks`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_cmd_lock_async` 在 `lock_count > 0` 但 `req->locks == NULL` 时仍可生成不含 lock element 的请求；该输入是否为调用方未定义前置条件？ | smb2_cmd_lock_async | 源码只在 `req->lock_count && req->locks` 时写入元素，没有显式拒绝空 lock 数组。 |
| Q-002 | `smb2_process_lock_request_fixed` 为解析第一个 lock 构造的临时 iovector从 `iov->buf + SMB2_LOCK_ELEMENT_SIZE` 开始，而 lock 元素在请求编码侧写入偏移 24；该偏移是否依赖固定头长度和 element size 相等的协议假设？ | smb2_process_lock_request_fixed | 源码可确认当前偏移值相等，但未发现注释说明该关系是否为稳定契约。 |
| Q-003 | GitNexus `impact` 对 lock 接口名称返回声明/定义歧义，未能用当前 CLI 选项消歧；实际风险级别需主 Agent 或后续批次用可用 UID 语法复核。 | file-level | `gitnexus impact` 输出 ambiguous，`--target-uid` 在当前 CLI 中不可用。 |
