# lib/smb2-cmd-ioctl.c Specification

## Source Context

- Source: `lib/smb2-cmd-ioctl.c`
- Related Headers: `include/smb2/libsmb2-raw.h`, `include/libsmb2-private.h`, `include/smb2/smb2.h`
- Related Tests: `tests/prog_ls.c` via GitNexus impact for readlink caller; no direct ioctl unit test found.
- Related Dependencies: GitNexus context shows `smb2_cmd_ioctl_async` is called by `dcerpc_call_async`, `dcerpc_bind_async`, and `smb2_readlink_async`; `smb2_cmd_ioctl_reply_async` is called by `smb2_ioctl_request_cb`; fixed and variable ioctl processors are dispatched from `lib/pdu.c` payload processing.
- Build/Compile Context: C source compiled in core `smb2` library; compile conditions include `HAVE_CONFIG_H`, `_GNU_SOURCE`, `HAVE_STDINT_H`, `HAVE_STDLIB_H`, `HAVE_STRING_H`, `STDC_HEADERS`, `HAVE_TIME_H`, and `HAVE_SYS_TIME_H`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| smb2_encode_ioctl_request | function | `static int smb2_encode_ioctl_request(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_ioctl_request *req)` | Skip | 静态编码 helper，仅由本文件公开构造入口调用，行为归属到 `smb2_cmd_ioctl_async`。 |
| smb2_cmd_ioctl_async | function | `struct smb2_pdu *smb2_cmd_ioctl_async(struct smb2_context *smb2, struct smb2_ioctl_request *req, smb2_command_cb cb, void *cb_data)` | Include | RAW SMB2 ioctl 公开构造入口，被 DCERPC 和 readlink 流程跨文件调用。 |
| smb2_encode_ioctl_reply | function | `static int smb2_encode_ioctl_reply(struct smb2_context *smb2, struct smb2_pdu *pdu, struct smb2_ioctl_reply *rep)` | Skip | 静态编码 helper，仅由本文件 reply 构造入口调用，行为归属到 `smb2_cmd_ioctl_reply_async`。 |
| smb2_cmd_ioctl_reply_async | function | `struct smb2_pdu *smb2_cmd_ioctl_reply_async(struct smb2_context *smb2, struct smb2_ioctl_reply *rep, smb2_command_cb cb, void *cb_data)` | Include | 服务器端 ioctl reply PDU 构造入口，被 `smb2_ioctl_request_cb` 跨文件调用。 |
| IOV_OFFSET_IOCTL | macro | `#define IOV_OFFSET_IOCTL (rep->output_offset - SMB2_HEADER_SIZE - (SMB2_IOCTL_REPLY_SIZE & 0xfffe))` | Skip | 本文件内部偏移计算宏，调用方不可直接使用，行为归属到 reply variable 解析。 |
| smb2_process_ioctl_fixed | function | `int smb2_process_ioctl_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | PDU reply fixed payload 解析入口，由 `lib/pdu.c` 分派并影响 ioctl reply 解码状态。 |
| smb2_process_ioctl_variable | function | `int smb2_process_ioctl_variable(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | PDU reply variable payload 解析入口，负责 ioctl 输出缓冲区解码和分配。 |
| IOVREQ_OFFSET_IOCTL | macro | `#define IOVREQ_OFFSET_IOCTL (req->input_offset - SMB2_HEADER_SIZE - (SMB2_IOCTL_REQUEST_SIZE & 0xfffe))` | Skip | 本文件内部偏移计算宏，调用方不可直接使用，行为归属到 request variable 解析。 |
| smb2_process_ioctl_request_fixed | function | `int smb2_process_ioctl_request_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 服务器端 request fixed payload 解析入口，由 `lib/pdu.c` 分派并填充 ioctl request。 |
| smb2_process_ioctl_request_variable | function | `int smb2_process_ioctl_request_variable(struct smb2_context *smb2, struct smb2_pdu *pdu)` | Include | 服务器端 request variable payload 解析入口，负责 validate negotiate 和 passthrough 输入处理。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| SMB2_IOCTL_REQUEST_SIZE | macro | `include/smb2/smb2.h:961` | ioctl request fixed structure size is encoded as 57 and masked to even wire length by this implementation. |
| SMB2_IOCTL_REPLY_SIZE | macro | `include/smb2/smb2.h:1016` | ioctl reply fixed structure size is encoded as 49 and masked to even wire length by this implementation. |
| struct smb2_ioctl_request | struct | `include/smb2/smb2.h:1003` | request carries ctl code, file id, input/output offsets and counts, response limits, flags, and input pointer. |
| struct smb2_ioctl_reply | struct | `include/smb2/smb2.h:1018` | reply carries ctl code, file id, input/output offsets and counts, flags, and output pointer. |
| SMB2_IOCTL_VALIDIATE_NEGOTIATE_INFO_SIZE | macro | `include/smb2/smb2.h:1029` | validate-negotiate ioctl output is encoded as 24 bytes. |
| struct smb2_ioctl_validate_negotiate_info | struct | `include/smb2/smb2.h:1031` | validate-negotiate payload contains capabilities, GUID, security mode, and dialect. |
| IOV_OFFSET_IOCTL | macro | `lib/smb2-cmd-ioctl.c:247` | internal reply output offset calculation relative to SMB2 header and fixed reply body. |
| IOVREQ_OFFSET_IOCTL | macro | `lib/smb2-cmd-ioctl.c:344` | internal request input offset calculation relative to SMB2 header and fixed request body. |

## ADDED Requirements

### Requirement: smb2_cmd_ioctl_async build ioctl request PDU
系统 MUST allocate an `SMB2_IOCTL` PDU, encode the fixed ioctl request body, append request input bytes when `req->input_count` is nonzero, align the outgoing vector to 64 bits, and return `NULL` without invoking the callback when allocation, encoding, or padding fails.

#### Scenario: request with optional input buffer
- **GIVEN** a valid `struct smb2_ioctl_request` whose `ctl_code`, `file_id`, `input_count`, `input`, and `flags` describe an ioctl request
- **WHEN** `smb2_cmd_ioctl_async` is called with a context, request, callback, and callback data
- **THEN** the returned PDU MUST use command `SMB2_IOCTL`, encode `SMB2_IOCTL_REQUEST_SIZE`, `ctl_code`, `file_id`, input offset, input count, max input response `0`, max output response `65535`, and flags, and append the input buffer only when `input_count` is nonzero

Trace: `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_async`, `lib/smb2-cmd-ioctl.c:smb2_encode_ioctl_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_ioctl_async`

#### Scenario: request construction failure
- **GIVEN** PDU allocation, ioctl fixed-buffer allocation, iovector append, or final padding fails
- **WHEN** `smb2_cmd_ioctl_async` attempts to construct the ioctl request PDU
- **THEN** the function MUST return `NULL`, free an allocated PDU on encode or padding failure, and preserve the documented no-callback-on-error contract

Trace: `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_async`, `lib/smb2-cmd-ioctl.c:smb2_encode_ioctl_request`, `include/smb2/libsmb2-raw.h:smb2_cmd_ioctl_async`

### Requirement: smb2_cmd_ioctl_reply_async build ioctl reply PDU
系统 MUST allocate an `SMB2_IOCTL` reply PDU, encode the fixed reply body, encode supported output payloads, honor passthrough for unhandled output codes, align the outgoing vector to 64 bits, and return `NULL` on construction failure.

#### Scenario: validate negotiate reply encoding
- **GIVEN** a reply with `ctl_code` equal to `SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO` and an output pointer to `struct smb2_ioctl_validate_negotiate_info`
- **WHEN** `smb2_cmd_ioctl_reply_async` builds the reply PDU
- **THEN** the output payload MUST be encoded as capabilities, 16-byte GUID, security mode, and dialect, and the fixed reply MUST report output count `SMB2_IOCTL_VALIDIATE_NEGOTIATE_INFO_SIZE`

Trace: `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_reply_async`, `lib/smb2-cmd-ioctl.c:smb2_encode_ioctl_reply`, `lib/libsmb2.c:smb2_ioctl_request_cb`

#### Scenario: passthrough reply encoding
- **GIVEN** a reply with nonzero `output_count` and a control code not handled locally
- **WHEN** `smb2_cmd_ioctl_reply_async` builds the reply while `smb2->passthrough` is enabled
- **THEN** the output payload MUST be copied byte-for-byte from `rep->output`, the iovector length MUST match `rep->output_count`, and the fixed reply MUST include the original flags and file id

Trace: `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_reply_async`, `lib/smb2-cmd-ioctl.c:smb2_encode_ioctl_reply`, `lib/libsmb2.c:smb2_ioctl_request_cb`

#### Scenario: unsupported non-passthrough reply output
- **GIVEN** a reply with nonzero `output_count`, an unhandled control code, and `smb2->passthrough` disabled
- **WHEN** `smb2_cmd_ioctl_reply_async` attempts to encode the output payload
- **THEN** the function MUST set an error for the unhandled code, free the allocated PDU through the caller path, and return `NULL`

Trace: `lib/smb2-cmd-ioctl.c:smb2_cmd_ioctl_reply_async`, `lib/smb2-cmd-ioctl.c:smb2_encode_ioctl_reply`

### Requirement: smb2_process_ioctl_fixed parse ioctl reply fixed body
系统 MUST validate the ioctl reply fixed body size, allocate `struct smb2_ioctl_reply` into `pdu->payload`, populate fixed fields from the incoming iovector, reject overlapping output offsets, and return the required variable payload length when output exists.

#### Scenario: fixed reply without output
- **GIVEN** an incoming SMB2 ioctl reply fixed body with structure size `SMB2_IOCTL_REPLY_SIZE`, matching even wire length, and `output_count` equal to zero
- **WHEN** `smb2_process_ioctl_fixed` parses the payload
- **THEN** it MUST allocate the reply payload, populate `ctl_code`, `file_id`, offsets, counts, and flags, store it in `pdu->payload`, and return `0`

Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

#### Scenario: fixed reply with output buffer
- **GIVEN** an incoming SMB2 ioctl reply fixed body with nonzero `output_count` and an `output_offset` at or after the end of the fixed ioctl reply body
- **WHEN** `smb2_process_ioctl_fixed` parses the payload
- **THEN** it MUST return `IOV_OFFSET_IOCTL + PAD_TO_64BIT(rep->input_count) + rep->output_count` so the caller reads the complete variable payload including passthrough input padding

Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

#### Scenario: malformed fixed reply
- **GIVEN** an incoming fixed reply with an unexpected structure size, mismatched fixed body length, allocation failure, or output offset overlapping the fixed header
- **WHEN** `smb2_process_ioctl_fixed` validates the fixed body
- **THEN** it MUST return `-1`, set an error for size, allocation, or overlap failures where implemented, and clear/free `pdu->payload` when overlap is detected after allocation

Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_fixed`, `lib/pdu.c:smb2_process_reply_payload_fixed`

### Requirement: smb2_process_ioctl_variable parse ioctl reply variable body
系统 MUST validate that the output payload fits the incoming iovector, decode reparse-point replies into library-owned data, copy default replies into allocated data, and store the decoded output pointer in `rep->output`.

#### Scenario: reparse-point output decoding
- **GIVEN** `pdu->payload` is an ioctl reply whose `ctl_code` is `SMB2_FSCTL_GET_REPARSE_POINT` and whose variable payload fits the iovector
- **WHEN** `smb2_process_ioctl_variable` parses the variable payload
- **THEN** it MUST allocate a `struct smb2_reparse_data_buffer`, decode the reparse data buffer from the computed output vector, assign it to `rep->output`, and return `0` when decoding succeeds

Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_variable`, `lib/smb2-data-reparse-point.c:smb2_decode_reparse_data_buffer`, `lib/pdu.c:smb2_process_reply_payload_variable`

#### Scenario: default output copy
- **GIVEN** `pdu->payload` is an ioctl reply with an unhandled control code and the output payload fits the iovector
- **WHEN** `smb2_process_ioctl_variable` parses the variable payload
- **THEN** it MUST allocate `rep->output_count` bytes from the SMB2 memory context, copy bytes from the computed output offset, assign the allocation to `rep->output`, and return `0`

Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`

#### Scenario: invalid reply variable length
- **GIVEN** `rep->output_count` is greater than the bytes available after `IOV_OFFSET_IOCTL`
- **WHEN** `smb2_process_ioctl_variable` validates the variable payload
- **THEN** it MUST return `-EINVAL` without assigning a decoded output pointer

Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_variable`, `lib/pdu.c:smb2_process_reply_payload_variable`

### Requirement: smb2_process_ioctl_request_fixed parse ioctl request fixed body
系统 MUST validate the ioctl request fixed body size, allocate `struct smb2_ioctl_request` into `pdu->payload`, populate fixed request fields from the incoming iovector, reject overlapping input offsets, and return the required input payload length when input exists.

#### Scenario: fixed request without input
- **GIVEN** an incoming SMB2 ioctl request fixed body with structure size `SMB2_IOCTL_REQUEST_SIZE`, matching even wire length, and `input_count` equal to zero
- **WHEN** `smb2_process_ioctl_request_fixed` parses the payload
- **THEN** it MUST allocate the request payload, populate `ctl_code`, `file_id`, offsets, counts, response limits, and flags, store it in `pdu->payload`, and return `0`

Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

#### Scenario: fixed request with input buffer
- **GIVEN** an incoming SMB2 ioctl request fixed body with nonzero `input_count` and an `input_offset` at or after the end of the fixed ioctl request body
- **WHEN** `smb2_process_ioctl_request_fixed` parses the payload
- **THEN** it MUST return `IOVREQ_OFFSET_IOCTL + req->input_count` so the caller reads the complete input variable payload

Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

#### Scenario: malformed fixed request
- **GIVEN** an incoming fixed request with an unexpected structure size, mismatched fixed body length, allocation failure, or input offset overlapping the fixed header
- **WHEN** `smb2_process_ioctl_request_fixed` validates the fixed body
- **THEN** it MUST return `-1`, set an error for size, allocation, or overlap failures where implemented, and clear/free `pdu->payload` when overlap is detected after allocation

Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_fixed`, `lib/pdu.c:smb2_process_request_payload_fixed`

### Requirement: smb2_process_ioctl_request_variable parse ioctl request variable body
系统 MUST validate that the request input payload fits the incoming iovector, decode validate-negotiate requests into library-owned data, expose unknown passthrough inputs directly when passthrough is enabled, and assign the resulting input pointer to `req->input`.

#### Scenario: validate negotiate request decoding
- **GIVEN** `pdu->payload` is an ioctl request whose `ctl_code` is `SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO` and whose input payload fits the iovector
- **WHEN** `smb2_process_ioctl_request_variable` parses the variable payload
- **THEN** it MUST allocate a `struct smb2_ioctl_validate_negotiate_info`, decode capabilities, GUID, security mode, and dialect from the input vector, set `req->input_count` to the structure size, assign the allocation to `req->input`, and return `0`

Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_variable`, `lib/libsmb2.c:smb2_ioctl_request_cb`, `lib/pdu.c:smb2_process_request_payload_variable`

#### Scenario: unknown passthrough request input
- **GIVEN** `pdu->payload` is an ioctl request with an unhandled control code, the input payload fits the iovector, and `smb2->passthrough` is enabled
- **WHEN** `smb2_process_ioctl_request_variable` parses the variable payload
- **THEN** it MUST set `req->input` to the incoming vector buffer, set `req->input_count` to the available vector length, and return `0` so the server handler can decode the bytes

Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_variable`, `lib/libsmb2.c:smb2_ioctl_request_cb`, `lib/pdu.c:smb2_process_request_payload_variable`

#### Scenario: unsupported non-passthrough request input
- **GIVEN** `pdu->payload` is an ioctl request with an unhandled control code and `smb2->passthrough` disabled
- **WHEN** `smb2_process_ioctl_request_variable` parses the variable payload
- **THEN** it MUST set an error for the unhandled ioctl request, leave `req->input` as `NULL`, and return `0`

Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`

#### Scenario: invalid request variable length
- **GIVEN** `req->input_count` is greater than the bytes available after `IOVREQ_OFFSET_IOCTL`
- **WHEN** `smb2_process_ioctl_request_variable` validates the variable payload
- **THEN** it MUST return `-EINVAL` without assigning a decoded input pointer

Trace: `lib/smb2-cmd-ioctl.c:smb2_process_ioctl_request_variable`, `lib/pdu.c:smb2_process_request_payload_variable`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_encode_ioctl_reply` allocates `PAD_TO_64BIT(len)` bytes but clears `rep->output_count` bytes; whether callers can provide `output_count` greater than encoded `len` for `SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO` is not confirmed. | smb2_cmd_ioctl_reply_async | Source shows different size variables and no direct test coverage was found. |
| Q-002 | `smb2_process_ioctl_variable` allocates `rep->output_count` bytes for default replies but copies `iov->len - IOV_OFFSET_IOCTL` bytes; whether fixed parsing always constrains those values to the same size is not fully confirmed. | smb2_process_ioctl_variable | Source evidence indicates possible padded/available length difference; no direct test coverage was found. |
| Q-003 | `smb2_process_ioctl_request_variable` does not check allocation failure before writing validate-negotiate fields; the expected behavior under allocation failure is not confirmed. | smb2_process_ioctl_request_variable | Source lacks a null check and no direct test coverage was found. |
