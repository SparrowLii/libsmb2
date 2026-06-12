# lib/ntlmssp.h Specification

## Source Context

- Source: `lib/ntlmssp.h`
- Related Headers: `lib/ntlmssp.c`, `include/smb2/smb2.h`, `include/smb2/libsmb2.h`
- Related Tests: `tests/ntlmssp_generate_blob.c`
- Related Dependencies: `lib/ntlmssp.c`, `lib/libsmb2.c`, SPNEGO wrapper helpers, SMB2 context/server authentication state, timestamp conversion helpers
- Build/Compile Context: C library header guarded by `_GSSAPI_WRAPPER_H_`; includes `config.h` when `HAVE_CONFIG_H` is defined, defines `_GNU_SOURCE` when absent, and exposes declarations inside `extern "C"` for C++ callers.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| `NEGOTIATE_MESSAGE` | macro | `#define NEGOTIATE_MESSAGE      0x00000001` | Include | NTLMSSP negotiate message type constant is externally observable through message parsing and generation. |
| `CHALLENGE_MESSAGE` | macro | `#define CHALLENGE_MESSAGE      0x00000002` | Include | NTLMSSP challenge message type constant is externally observable through client challenge handling. |
| `AUTHENTICATION_MESSAGE` | macro | `#define AUTHENTICATION_MESSAGE 0x00000003` | Include | NTLMSSP authenticate message type constant is externally observable through server authentication handling. |
| `struct auth_data` | type | `struct auth_data;` | Include | Opaque authentication context type is the shared handle for all declared NTLMSSP operations. |
| `ntlmssp_init_context` | function | `struct auth_data * ntlmssp_init_context(const char *user, const char *password, const char *domain, const char *workstation, const char *client_challenge);` | Include | Creates the opaque authentication context used by all NTLMSSP message and state APIs. |
| `ntlmssp_destroy_context` | function | `void ntlmssp_destroy_context(struct auth_data *auth);` | Include | Releases authentication context allocations and terminates context lifetime. |
| `ntlmssp_set_spnego_wrapping` | function | `void ntlmssp_set_spnego_wrapping(struct auth_data *auth, int wrap);` | Include | Configures whether generated NTLMSSP blobs are wrapped in SPNEGO. |
| `ntlmssp_get_spnego_wrapping` | function | `int ntlmssp_get_spnego_wrapping(struct auth_data *auth);` | Include | Returns the context SPNEGO wrapping flag used by callers and blob generation. |
| `ntlmssp_get_message_type` | function | `int ntlmssp_get_message_type(struct smb2_context *smb2, uint8_t *ntlmssp_buffer, int len, int suppress_errors, uint32_t *message_type, uint8_t **ntlmssp_ptr, int *ntlmssp_len, int *is_wrapped);` | Include | Parses raw or SPNEGO-wrapped NTLMSSP data and reports type, payload pointer, payload length, and wrapping state. |
| `ntlmssp_generate_blob` | function | `int ntlmssp_generate_blob(struct smb2_server *server, struct smb2_context *smb2, time_t t, struct auth_data *auth_data, unsigned char *input_buf, int input_len, unsigned char **output_buf, uint16_t *output_len);` | Include | Drives NTLMSSP negotiate/challenge/authenticate blob generation for client and server authentication flows. |
| `ntlmssp_authenticate_blob` | function | `int ntlmssp_authenticate_blob(struct smb2_server *server, struct smb2_context *smb2, struct auth_data *auth_data, unsigned char *input_buf, int input_len);` | Include | Validates an NTLMSSP authentication message and updates SMB2 server credential/session state. |
| `ntlmssp_get_authenticated` | function | `int ntlmssp_get_authenticated(struct auth_data *auth);` | Include | Exposes whether server-side authentication has succeeded for the context. |
| `ntlmssp_get_session_key` | function | `int ntlmssp_get_session_key(struct auth_data *auth, uint8_t **key, uint8_t *key_size);` | Include | Copies the exported session key for downstream signing or sealing setup. |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| `NEGOTIATE_MESSAGE` | macro | `lib/ntlmssp.h:33` | NTLMSSP negotiate message type value `0x00000001`. |
| `CHALLENGE_MESSAGE` | macro | `lib/ntlmssp.h:34` | NTLMSSP challenge message type value `0x00000002`. |
| `AUTHENTICATION_MESSAGE` | macro | `lib/ntlmssp.h:35` | NTLMSSP authenticate message type value `0x00000003`. |
| `struct auth_data` | struct | `lib/ntlmssp.h:37` | Opaque context declaration; concrete fields are private to `lib/ntlmssp.c`. |

## ADDED Requirements

### Requirement: NEGOTIATE_MESSAGE NTLMSSP type value
系统 MUST expose `NEGOTIATE_MESSAGE` as the NTLMSSP negotiate message type value `0x00000001`.

#### Scenario: Negotiate constant is available to callers
- **GIVEN** a caller includes `lib/ntlmssp.h`
- **WHEN** the caller compares an NTLMSSP message type with `NEGOTIATE_MESSAGE`
- **THEN** the comparison uses the stable value `0x00000001`

Trace: `lib/ntlmssp.h:NEGOTIATE_MESSAGE`, `lib/ntlmssp.c:ntlmssp_generate_blob`

### Requirement: CHALLENGE_MESSAGE NTLMSSP type value
系统 MUST expose `CHALLENGE_MESSAGE` as the NTLMSSP challenge message type value `0x00000002`.

#### Scenario: Challenge constant is available to callers
- **GIVEN** a caller includes `lib/ntlmssp.h`
- **WHEN** the caller compares an NTLMSSP message type with `CHALLENGE_MESSAGE`
- **THEN** the comparison uses the stable value `0x00000002`

Trace: `lib/ntlmssp.h:CHALLENGE_MESSAGE`, `lib/ntlmssp.c:ntlmssp_generate_blob`, `tests/ntlmssp_generate_blob.c:main`

### Requirement: AUTHENTICATION_MESSAGE NTLMSSP type value
系统 MUST expose `AUTHENTICATION_MESSAGE` as the NTLMSSP authenticate message type value `0x00000003`.

#### Scenario: Authenticate constant is available to callers
- **GIVEN** a caller includes `lib/ntlmssp.h`
- **WHEN** the caller compares an NTLMSSP message type with `AUTHENTICATION_MESSAGE`
- **THEN** the comparison uses the stable value `0x00000003`

Trace: `lib/ntlmssp.h:AUTHENTICATION_MESSAGE`, `lib/ntlmssp.c:ntlmssp_generate_blob`, `lib/ntlmssp.c:ntlmssp_authenticate_blob`

### Requirement: struct auth_data opaque context
系统 MUST expose `struct auth_data` only as an opaque authentication context handle through this header.

#### Scenario: Callers pass opaque authentication state
- **GIVEN** a caller has a `struct auth_data *` returned by `ntlmssp_init_context`
- **WHEN** the caller passes that pointer to another NTLMSSP API declared in this header
- **THEN** the caller relies on the pointer identity and SHALL NOT require field access from `lib/ntlmssp.h`

Trace: `lib/ntlmssp.h:struct auth_data`, `lib/ntlmssp.c:struct auth_data`

### Requirement: ntlmssp_init_context context allocation
系统 MUST return a newly allocated `struct auth_data *` initialized from caller credentials and an 8-byte client challenge, or return `NULL` if allocation or duplication fails.

#### Scenario: Context initializes for valid credentials
- **GIVEN** non-NULL credential strings and an 8-byte `client_challenge`
- **WHEN** `ntlmssp_init_context` is called
- **THEN** the returned context stores duplicated credential state, initializes authentication as not authenticated, initializes the exported session key to zeros, and captures a Windows timestamp

Trace: `lib/ntlmssp.h:ntlmssp_init_context`, `lib/ntlmssp.c:ntlmssp_init_context`, `tests/ntlmssp_generate_blob.c:main`

#### Scenario: Allocation failure reports no context
- **GIVEN** memory allocation or string duplication fails while creating context state
- **WHEN** `ntlmssp_init_context` is called
- **THEN** the function MUST release allocations it created for the failed context and return `NULL`

Trace: `lib/ntlmssp.h:ntlmssp_init_context`, `lib/ntlmssp.c:ntlmssp_init_context`

### Requirement: ntlmssp_destroy_context context release
系统 MUST release all heap-owned fields in the NTLMSSP authentication context and then release the context object.

#### Scenario: Context destruction frees owned buffers
- **GIVEN** a context created by `ntlmssp_init_context`
- **WHEN** `ntlmssp_destroy_context` is called with that context
- **THEN** the function releases NTLM buffers, credential strings, target data, challenge data, and the context allocation

Trace: `lib/ntlmssp.h:ntlmssp_destroy_context`, `lib/ntlmssp.c:ntlmssp_destroy_context`

### Requirement: ntlmssp_set_spnego_wrapping wrapping flag update
系统 MUST store the caller-provided SPNEGO wrapping flag in the NTLMSSP authentication context.

#### Scenario: Wrapping flag is set
- **GIVEN** a valid authentication context and a wrapping flag value
- **WHEN** `ntlmssp_set_spnego_wrapping` is called
- **THEN** subsequent reads through `ntlmssp_get_spnego_wrapping` observe that stored value

Trace: `lib/ntlmssp.h:ntlmssp_set_spnego_wrapping`, `lib/ntlmssp.c:ntlmssp_set_spnego_wrapping`, `lib/ntlmssp.c:ntlmssp_get_spnego_wrapping`

### Requirement: ntlmssp_get_spnego_wrapping wrapping flag read
系统 MUST return the SPNEGO wrapping flag stored in the NTLMSSP authentication context.

#### Scenario: Wrapping flag is read
- **GIVEN** a valid authentication context whose wrapping flag was initialized or updated
- **WHEN** `ntlmssp_get_spnego_wrapping` is called
- **THEN** the function returns the context's current wrapping flag value

Trace: `lib/ntlmssp.h:ntlmssp_get_spnego_wrapping`, `lib/ntlmssp.c:ntlmssp_get_spnego_wrapping`

### Requirement: ntlmssp_get_message_type NTLMSSP parsing
系统 MUST unwrap supported SPNEGO NTLMSSP blobs, validate the `NTLMSSP` signature, and report the decoded message type and optional output fields when parsing succeeds.

#### Scenario: NTLMSSP message type is decoded
- **GIVEN** a raw or SPNEGO-wrapped buffer containing a valid NTLMSSP signature and at least 12 bytes of payload
- **WHEN** `ntlmssp_get_message_type` is called with output pointers
- **THEN** the function returns `0`, writes the little-endian message type, writes the NTLMSSP payload pointer and length when requested, and writes whether SPNEGO unwrapping changed the payload pointer when requested

Trace: `lib/ntlmssp.h:ntlmssp_get_message_type`, `lib/ntlmssp.c:ntlmssp_get_message_type`, `lib/ntlmssp.c:ntlmssp_generate_blob`

#### Scenario: Invalid NTLMSSP data is rejected
- **GIVEN** a NULL buffer, a length shorter than 12 bytes, an unwrap failure, or a payload without the NTLMSSP signature
- **WHEN** `ntlmssp_get_message_type` is called
- **THEN** the function MUST return `-1` after initializing provided output pointers to failure defaults

Trace: `lib/ntlmssp.h:ntlmssp_get_message_type`, `lib/ntlmssp.c:ntlmssp_get_message_type`

### Requirement: ntlmssp_generate_blob authentication blob generation
系统 MUST generate the next NTLMSSP blob for client or server state based on the input message, context wrapping flag, and SMB2 role.

#### Scenario: Client challenge produces authentication blob
- **GIVEN** a client SMB2 context, initialized auth data, a timestamp, and a valid NTLMSSP challenge message
- **WHEN** `ntlmssp_generate_blob` is called with the challenge as `input_buf`
- **THEN** the function returns `0`, writes `*output_buf` to the generated authentication blob, and writes `*output_len` to the generated length

Trace: `lib/ntlmssp.h:ntlmssp_generate_blob`, `lib/ntlmssp.c:ntlmssp_generate_blob`, `tests/ntlmssp_generate_blob.c:main`

#### Scenario: Initial client negotiate blob is generated
- **GIVEN** a client SMB2 context, initialized auth data, and `input_buf == NULL`
- **WHEN** `ntlmssp_generate_blob` is called
- **THEN** the function MUST generate a negotiate message, optionally wrap it when SPNEGO wrapping is enabled, and expose the generated buffer and length through output parameters

Trace: `lib/ntlmssp.h:ntlmssp_generate_blob`, `lib/ntlmssp.c:ntlmssp_generate_blob`

#### Scenario: Unsupported input message fails
- **GIVEN** input data that cannot be parsed as a valid or expected NTLMSSP message for the current SMB2 role
- **WHEN** `ntlmssp_generate_blob` is called
- **THEN** the function MUST return `-1` and set an SMB2 error for confirmed parse or role errors where the implementation provides one

Trace: `lib/ntlmssp.h:ntlmssp_generate_blob`, `lib/ntlmssp.c:ntlmssp_generate_blob`

### Requirement: ntlmssp_authenticate_blob server authentication
系统 MUST validate an NTLMSSP authenticate message, update SMB2 user/domain/workstation state from decoded UTF-16 fields, and return `0` only when authentication succeeds.

#### Scenario: Server authenticate message succeeds
- **GIVEN** a server SMB2 context, auth data with a server challenge, and an NTLMSSP authenticate message with valid proof data or allowed anonymous credentials
- **WHEN** `ntlmssp_authenticate_blob` is called
- **THEN** the function returns `0`, updates SMB2 identity fields, and stores the exported session key for non-anonymous proof validation

Trace: `lib/ntlmssp.h:ntlmssp_authenticate_blob`, `lib/ntlmssp.c:ntlmssp_authenticate_blob`, `lib/ntlmssp.c:ntlmssp_generate_blob`

#### Scenario: Invalid authenticate message fails
- **GIVEN** NULL input, an undersized buffer, a non-NTLMSSP signature, a non-authenticate message type, missing NT response fields, denied server authorization, or proof mismatch
- **WHEN** `ntlmssp_authenticate_blob` is called
- **THEN** the function MUST return `-1` and preserve failure as unauthenticated state for callers that consume `ntlmssp_generate_blob`

Trace: `lib/ntlmssp.h:ntlmssp_authenticate_blob`, `lib/ntlmssp.c:ntlmssp_authenticate_blob`

### Requirement: ntlmssp_get_authenticated authentication state read
系统 MUST return the context authentication flag for a non-NULL context and return `0` for a NULL context.

#### Scenario: Authentication flag is queried
- **GIVEN** a context that may or may not have completed server authentication
- **WHEN** `ntlmssp_get_authenticated` is called
- **THEN** the function returns the context's `is_authenticated` value, or `0` when the context pointer is NULL

Trace: `lib/ntlmssp.h:ntlmssp_get_authenticated`, `lib/ntlmssp.c:ntlmssp_get_authenticated`, `lib/libsmb2.c:ntlmssp_get_authenticated`

### Requirement: ntlmssp_get_session_key exported key copy
系统 MUST allocate and return a copy of the exported session key and its size when all output parameters are valid.

#### Scenario: Session key copy succeeds
- **GIVEN** a valid authentication context and non-NULL `key` and `key_size` output pointers
- **WHEN** `ntlmssp_get_session_key` is called
- **THEN** the function returns `0`, allocates a `SMB2_KEY_SIZE` byte key copy, writes the allocated pointer to `*key`, and writes `SMB2_KEY_SIZE` to `*key_size`

Trace: `lib/ntlmssp.h:ntlmssp_get_session_key`, `lib/ntlmssp.c:ntlmssp_get_session_key`, `lib/libsmb2.c:ntlmssp_get_session_key`

#### Scenario: Session key copy fails for invalid parameters or allocation failure
- **GIVEN** a NULL context, NULL output pointer, or failed key allocation
- **WHEN** `ntlmssp_get_session_key` is called
- **THEN** the function MUST return `-1` without reporting a usable key copy

Trace: `lib/ntlmssp.h:ntlmssp_get_session_key`, `lib/ntlmssp.c:ntlmssp_get_session_key`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `ntlmssp_init_context` 对 `client_challenge == NULL` 的前置条件是否由调用方保证？ | `ntlmssp_init_context` | 实现无 NULL 检查且直接复制 8 字节；头文件未声明该约束。 |
| Q-002 | `ntlmssp_destroy_context` 是否允许传入 NULL 指针？ | `ntlmssp_destroy_context` | 实现直接解引用 `auth` 字段后释放，头文件未声明调用方责任。 |
| Q-003 | SPNEGO 包装失败、输出缓冲区所有权和 `output_buf` 生命周期是否需要公开为调用方契约？ | `ntlmssp_generate_blob` | 实现返回内部 `auth_data->buf`，所有权与后续调用释放关系需要与调用方文档确认。 |
| Q-004 | `ntlmssp_authenticate_blob` 在 `server == NULL` 且缺少用户或密码时是否可能解引用 NULL server？ | `ntlmssp_authenticate_blob` | 实现匿名分支访问 `server->allow_anonymous`，头文件未声明 server 参数前置条件。 |
