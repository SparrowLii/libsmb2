# lib/smb2-cmd-query-info.c Specification

## Source Context

- Source: `lib/smb2-cmd-query-info.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `tests/metastat-0202-censored.c` via GitNexus impact on `smb2_cmd_query_info_async`; no direct query-info unit test found.
- Related Dependencies: GitNexus context shows `smb2_cmd_query_info_async` is called by `lib/libsmb2.c:smb2_fstat_async`, `lib/libsmb2.c:smb2_getinfo_async`, and raw stat/fsstat/getsd examples; `smb2_cmd_query_info_reply_async` is called by `lib/libsmb2.c:smb2_query_info_request_cb`; fixed and variable parsers are dispatched from `lib/pdu.c`; reply variable parsing delegates file, filesystem, and security descriptor decoding to data modules.
- Build/Compile Context: C source compiled into the core `smb2` library; source includes optional `HAVE_CONFIG_H`, `_GNU_SOURCE`, standard header feature probes, `compat.h`, `smb2.h`, `libsmb2.h`, and `libsmb2-private.h`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_query_info_request | function | int smb2_encode_query_info_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_query_info_request *req) | Skip | 请求编码 helper 未在头文件声明，行为归属到公开 RAW 构造入口 `smb2_cmd_query_info_async`。 |
| smb2_cmd_query_info_async | function | struct smb2_pdu *smb2_cmd_query_info_async(struct smb2_context *smb2, struct smb2_query_info_request *req, smb2_command_cb cb, void *cb_data) | Include | RAW SMB2 Query Info 公开构造入口，跨模块用于 stat/getinfo 和示例流程，GitNexus impact 为 HIGH。 |
| smb2_encode_query_info_reply | function | static int smb2_encode_query_info_reply(struct smb2_context *smb2, struct smb2_query_info_request *req, struct smb2_pdu *pdu, struct smb2_query_info_reply *rep) | Skip | 静态 reply 编码 helper，仅由 reply 构造入口调用，行为归属到 `smb2_cmd_query_info_reply_async`。 |
| smb2_cmd_query_info_reply_async | function | struct smb2_pdu *smb2_cmd_query_info_reply_async(struct smb2_context *smb2, struct smb2_query_info_request *req, struct smb2_query_info_reply *rep, smb2_command_cb cb, void *cb_data) | Include | server-side Query Info reply PDU 构造入口，被 `smb2_query_info_request_cb` 跨文件调用。 |
| IOV_OFFSET_QUERY | macro | #define IOV_OFFSET_QUERY (rep->output_buffer_offset - SMB2_HEADER_SIZE - (SMB2_QUERY_INFO_REPLY_SIZE & 0xfffe)) | Skip | 文件内 reply output offset helper，调用方不可直接使用，行为归属到 reply parser。 |
| smb2_process_query_info_fixed | function | int smb2_process_query_info_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | Query Info reply fixed payload parser，由 `lib/pdu.c` 分派并决定 payload、边界和 variable 长度。 |
| smb2_process_query_info_variable | function | int smb2_process_query_info_variable(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | Query Info reply variable payload parser，负责按 info type/class 解码或 passthrough 输出。 |
| IOVREQ_OFFSET_QUERY | macro | #define IOVREQ_OFFSET_QUERY (req->input_buffer_offset - SMB2_HEADER_SIZE - (SMB2_QUERY_INFO_REQUEST_SIZE & 0xfffe)) | Skip | 文件内 request input offset helper，调用方不可直接使用，行为归属到 request parser。 |
| smb2_process_query_info_request_fixed | function | int smb2_process_query_info_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | server-side Query Info request fixed payload parser，由 `lib/pdu.c` 分派并填充 request 字段。 |
| smb2_process_query_info_request_variable | function | int smb2_process_query_info_request_variable(struct smb2_context *smb2, struct smb2_pdu *pdu) | Include | server-side Query Info request variable payload parser，暴露 input buffer 指针。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_QUERY_INFO_REQUEST_SIZE | macro | include/smb2/smb2.h:534 | Query Info request fixed structure size is encoded as 41 and masked to even wire length for iovector sizing. |
| struct smb2_query_info_request | struct | include/smb2/smb2.h:672 | request carries info type, class, output/input lengths, input offset, additional information, flags, file id, and input pointer. |
| SMB2_QUERY_INFO_REPLY_SIZE | macro | include/smb2/smb2.h:953 | Query Info reply fixed structure size is encoded as 9 and masked to even wire length for fixed payload parsing. |
| struct smb2_query_info_reply | struct | include/smb2/smb2.h:955 | reply carries output buffer offset, output buffer length, and decoded or passthrough output pointer. |
| IOV_OFFSET_QUERY | macro | lib/smb2-cmd-query-info.c:362 | internal reply output offset calculation relative to SMB2 header and fixed Query Info reply body. |
| IOVREQ_OFFSET_QUERY | macro | lib/smb2-cmd-query-info.c:688 | internal request input offset calculation relative to SMB2 header and fixed Query Info request body. |

## ADDED Requirements

### Requirement: smb2_cmd_query_info_async build Query Info request PDU
系统 MUST allocate an `SMB2_QUERY_INFO` PDU, reject nonzero input buffers, encode the fixed Query Info request body, remember requested info type/class on the PDU, align the outgoing vector to 64 bits, and return `NULL` without invoking the callback when local construction fails.

#### Scenario: encode request without input buffer
- **GIVEN** a `struct smb2_query_info_request` with `input_buffer_length` equal to zero and valid info type, file info class, output length, additional information, flags, and file id
- **WHEN** `smb2_cmd_query_info_async` is called with a context, request, callback, and callback data
- **THEN** the returned PDU MUST use command `SMB2_QUERY_INFO`, encode `SMB2_QUERY_INFO_REQUEST_SIZE`, copy the fixed request fields and `SMB2_FD_SIZE` bytes of file id, set `input_buffer_offset` to the fixed request end, and store `req->info_type` and `req->file_info_class` in the PDU for reply unmarshalling

Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_async`, `lib/smb2-cmd-query-info.c:smb2_encode_query_info_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_query_info_async`

#### Scenario: reject unsupported request input buffer
- **GIVEN** a Query Info request whose `input_buffer_length` is greater than zero
- **WHEN** `smb2_cmd_query_info_async` attempts to encode the request
- **THEN** it MUST set an error for unsupported input buffers, free the allocated PDU through the caller path, and return `NULL`

Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_async`, `lib/smb2-cmd-query-info.c:smb2_encode_query_info_request`

#### Scenario: request construction failure
- **GIVEN** PDU allocation, fixed request allocation, iovector append, or final padding fails
- **WHEN** `smb2_cmd_query_info_async` constructs the request PDU
- **THEN** the function MUST return `NULL`, free an allocated PDU on encode or padding failure, and preserve the header contract that the callback is not invoked on local setup error

Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_async`, `include/smb2/libsmb2-raw.h:smb2_cmd_query_info_async`

### Requirement: smb2_cmd_query_info_reply_async build Query Info reply PDU
系统 MUST allocate an `SMB2_QUERY_INFO` reply PDU, encode the fixed reply body, encode supported output payload classes, honor passthrough for unhandled output classes, set overflow status when encoded output exceeds the requested length, and return `NULL` on construction failure.

#### Scenario: encode supported file and filesystem output
- **GIVEN** a reply with nonzero `output_buffer_length`, a non-null `output_buffer`, and request info type/class matching a supported file or filesystem encoder
- **WHEN** `smb2_cmd_query_info_reply_async` builds the reply PDU
- **THEN** the output payload MUST be encoded using the matching file, filesystem, or name/stream encoder, the fixed reply MUST report the resulting output length, and the variable iovector length MUST be padded to an 8-byte boundary

Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_reply_async`, `lib/smb2-cmd-query-info.c:smb2_encode_query_info_reply`, `lib/libsmb2.c:smb2_query_info_request_cb`

#### Scenario: truncate oversized encoded output
- **GIVEN** a supported encoder produces more bytes than `req->output_buffer_length`
- **WHEN** `smb2_cmd_query_info_reply_async` finalizes the encoded reply
- **THEN** it MUST limit `rep->output_buffer_length` to the requested output length, set the PDU status to `SMB2_STATUS_BUFFER_OVERFLOW`, and keep the variable iovector padded to the truncated length

Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_reply_async`, `lib/smb2-cmd-query-info.c:smb2_encode_query_info_reply`

#### Scenario: passthrough reply output
- **GIVEN** a reply with nonzero output length for an unhandled info type/class and `smb2->passthrough` enabled
- **WHEN** `smb2_cmd_query_info_reply_async` builds the reply PDU
- **THEN** it MUST copy the output buffer bytes into the reply, zero the padding up to 8-byte alignment, and report the original output buffer length in the fixed reply

Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_reply_async`, `lib/smb2-cmd-query-info.c:smb2_encode_query_info_reply`

#### Scenario: unsupported non-passthrough reply output
- **GIVEN** a reply with nonzero output length for an unhandled info type/class and `smb2->passthrough` disabled
- **WHEN** `smb2_cmd_query_info_reply_async` attempts to encode the output payload
- **THEN** it MUST set an error for the unhandled info type/class and return `NULL` through the caller path

Trace: `lib/smb2-cmd-query-info.c:smb2_cmd_query_info_reply_async`, `lib/smb2-cmd-query-info.c:smb2_encode_query_info_reply`

### Requirement: smb2_process_query_info_fixed parse Query Info reply fixed body
系统 MUST validate Query Info reply fixed size, allocate `struct smb2_query_info_reply` into `pdu->payload`, populate output offset and length, reject wrapped or out-of-bounds output ranges, and return the required variable payload length when output exists.

#### Scenario: fixed reply without output
- **GIVEN** an incoming Query Info reply fixed body with structure size `SMB2_QUERY_INFO_REPLY_SIZE`, matching even wire length, and `output_buffer_length` equal to zero
- **WHEN** `smb2_process_query_info_fixed` parses the fixed payload
- **THEN** it MUST allocate the reply payload, assign it to `pdu->payload`, set `rep->output_buffer` to `NULL`, and return `0`

Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

#### Scenario: fixed reply with output buffer
- **GIVEN** an incoming Query Info reply fixed body with nonzero output length, non-wrapping offset plus length, and an output offset at or after the end of the fixed reply body
- **WHEN** `smb2_process_query_info_fixed` parses the fixed payload
- **THEN** it MUST verify the output does not extend past the current PDU or into the next chained PDU, then return `IOV_OFFSET_QUERY + rep->output_buffer_length` so the caller reads the variable payload

Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

#### Scenario: malformed fixed reply
- **GIVEN** an incoming fixed reply with unexpected structure size, mismatched fixed length, allocation failure, wrapped output range, output beyond the current PDU, output into the next chained PDU, or output offset overlapping the fixed header
- **WHEN** `smb2_process_query_info_fixed` validates the fixed payload
- **THEN** it MUST return `-1`, set an error where implemented, and clear/free `pdu->payload` for failures detected after allocation

Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

### Requirement: smb2_process_query_info_variable parse Query Info reply variable body
系统 MUST decode supported Query Info reply outputs into SMB2-owned data according to `pdu->info_type` and `pdu->file_info_class`, use passthrough copying for unsupported classes only when enabled, and assign the resulting pointer to `rep->output_buffer`.

#### Scenario: decode supported file information output
- **GIVEN** `pdu->payload` is a Query Info reply and `pdu->info_type` is `SMB2_0_INFO_FILE` with a supported file information class
- **WHEN** `smb2_process_query_info_variable` parses the variable payload
- **THEN** it MUST allocate an appropriate SMB2-owned structure, decode the output using the matching file-info decoder, assign the decoded pointer to `rep->output_buffer`, and return `0` when decoding succeeds

Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_variable`, `lib/smb2-data-file-info.c:smb2_decode_file_basic_info`, `lib/pdu.c:smb2_process_reply_payload_variable`

#### Scenario: decode supported filesystem information output
- **GIVEN** `pdu->payload` is a Query Info reply and `pdu->info_type` is `SMB2_0_INFO_FILESYSTEM` with a supported filesystem information class
- **WHEN** `smb2_process_query_info_variable` parses the variable payload
- **THEN** it MUST allocate an appropriate SMB2-owned filesystem structure, decode the output using the matching filesystem decoder, assign the decoded pointer to `rep->output_buffer`, and return `0` when decoding succeeds

Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_variable`, `lib/smb2-data-filesystem-info.c:smb2_decode_file_fs_volume_info`, `lib/pdu.c:smb2_process_reply_payload_variable`

#### Scenario: decode security descriptor output
- **GIVEN** `pdu->payload` is a Query Info reply, `pdu->info_type` is `SMB2_0_INFO_SECURITY`, and `smb2->passthrough` is disabled
- **WHEN** `smb2_process_query_info_variable` parses the variable payload
- **THEN** it MUST allocate `struct smb2_security_descriptor`, decode the security descriptor, assign it to `rep->output_buffer`, and return `0` when decoding succeeds

Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_variable`, `lib/smb2-data-security-descriptor.c:smb2_decode_security_descriptor`, `lib/pdu.c:smb2_process_reply_payload_variable`

#### Scenario: unsupported output class handling
- **GIVEN** the reply info type/class does not produce a decoder result
- **WHEN** `smb2_process_query_info_variable` reaches the fallback path
- **THEN** it MUST copy the raw output bytes into SMB2-owned memory when `smb2->passthrough` is enabled, and MUST return `-1` with an error when passthrough is disabled

Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`

### Requirement: smb2_process_query_info_request_fixed parse Query Info request fixed body
系统 MUST validate Query Info request fixed size, allocate `struct smb2_query_info_request` into `pdu->payload`, populate request fields, and return the required input payload length when input exists.

#### Scenario: fixed request without input
- **GIVEN** an incoming Query Info request fixed body with structure size `SMB2_QUERY_INFO_REQUEST_SIZE`, matching even wire length, and `input_buffer_length` equal to zero
- **WHEN** `smb2_process_query_info_request_fixed` parses the fixed payload
- **THEN** it MUST allocate the request payload, populate info type, file info class, output length, input offset and length, additional information, flags, and file id, store it in `pdu->payload`, and return `0`

Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

#### Scenario: fixed request with input buffer
- **GIVEN** an incoming Query Info request fixed body with nonzero input length and an input offset at or after the end of the fixed request body
- **WHEN** `smb2_process_query_info_request_fixed` parses the fixed payload
- **THEN** it MUST return `IOVREQ_OFFSET_QUERY + req->input_buffer_length` so the caller reads the complete input variable payload

Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

#### Scenario: malformed fixed request
- **GIVEN** an incoming fixed request with unexpected structure size, mismatched fixed length, allocation failure, or input offset overlapping the fixed header
- **WHEN** `smb2_process_query_info_request_fixed` validates the fixed payload
- **THEN** it MUST return `-1`, set an error where implemented, and clear/free `pdu->payload` when overlap is detected after allocation

Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

### Requirement: smb2_process_query_info_request_variable expose Query Info request input
系统 MUST expose the request input variable bytes by assigning `req->input` to the computed input buffer inside the current incoming iovector and returning success.

#### Scenario: bind request input pointer
- **GIVEN** `pdu->payload` is a parsed `struct smb2_query_info_request` with nonzero input length and the variable payload iovector contains the requested bytes
- **WHEN** `smb2_process_query_info_request_variable` parses the variable payload
- **THEN** it MUST compute `IOVREQ_OFFSET_QUERY`, assign `req->input` to that location in the current incoming iovector, and return `0` without copying the input bytes

Trace: `lib/smb2-cmd-query-info.c:smb2_process_query_info_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_encode_query_info_request` is non-static in the implementation but not declared in the reviewed headers; whether it is intended as an internal-only helper or an omitted private declaration is not confirmed. | smb2_encode_query_info_request | Source and header evidence differ on visibility; GitNexus query returned it as a file-local candidate only. |
| Q-002 | `smb2_process_query_info_variable` allocates `sizeof(struct smb2_file_all_info)` before decoding `SMB2_FILE_NETWORK_OPEN_INFORMATION`; whether this larger allocation is intentional compatibility space or a bug is not confirmed. | smb2_process_query_info_variable | Source shows the allocation/decoder mismatch and no direct test coverage was found. |
| Q-003 | Fallback passthrough copy in `smb2_process_query_info_variable` copies `vec.len` bytes into an allocation sized as `rep->output_buffer_length`; whether fixed parsing always constrains `vec.len` to that length plus no padding is not fully confirmed. | smb2_process_query_info_variable | Current file constructs `vec` from the remaining iovec length and lacks an explicit copy-size check. |
| Q-004 | `smb2_process_query_info_request_variable` does not validate `IOVREQ_OFFSET_QUERY` against the current iovec length; whether `lib/pdu.c` always slices or fetches enough bytes based on the fixed parser return value is not confirmed. | smb2_process_query_info_request_variable | Current file relies on dispatcher behavior and no direct boundary test was found. |
