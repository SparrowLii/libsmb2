# lib/spnego-wrapper.h Specification

## Source Context

- Source: `lib/spnego-wrapper.h`
- Related Headers: `lib/spnego-wrapper.c`, `lib/asn1-ber.h`, `include/smb2/smb2.h`, `include/smb2/libsmb2.h`, `include/libsmb2-private.h`
- Related Tests: `none`
- Related Dependencies: `lib/spnego-wrapper.c` implements the declared SPNEGO wrapper and unwrap helpers; callers observed in source include `lib/ntlmssp.c` and `lib/libsmb2.c`; ASN.1 BER helpers encode and decode SPNEGO structures.
- Build/Compile Context: C project; `HAVE_CONFIG_H` includes `config.h`; `_GNU_SOURCE` is defined when absent; declarations are exposed with `extern "C"` under `__cplusplus`; implementation conditionally includes Kerberos mechanism OID when `HAVE_LIBKRB5` is defined.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| SPNEGO_MECHANISM_KRB5 | macro | #define SPNEGO_MECHANISM_KRB5       (0x0001) | Include | 调用方通过该机制标志识别解析出的 Kerberos SPNEGO mechanism。 |
| SPNEGO_MECHANISM_NTLMSSP | macro | #define SPNEGO_MECHANISM_NTLMSSP    (0x0002) | Include | 调用方通过该机制标志识别解析出的 NTLMSSP SPNEGO mechanism。 |
| smb2_spnego_create_negotiate_reply_blob | function | int smb2_spnego_create_negotiate_reply_blob(struct smb2_context *smb2, int allow_ntlmssp, void **neg_init_token); | Include | SMB 服务端 negotiate reply 使用该接口生成 SPNEGO negTokenInit blob 并返回分配缓冲区。 |
| smb2_spnego_wrap_gssapi | function | int smb2_spnego_wrap_gssapi(struct smb2_context *smb2, const uint8_t *ntlmssp_token, const int token_len, void **blob); | Include | NTLMSSP 客户端认证路径使用该接口把可选 NTLMSSP token 包装成 GSS-API SPNEGO blob。 |
| smb2_spnego_wrap_ntlmssp_challenge | function | int smb2_spnego_wrap_ntlmssp_challenge(struct smb2_context *smb2, const uint8_t *ntlmssp_token, const int token_len, void **neg_targ_token); | Include | 服务端 NTLMSSP challenge 路径使用该接口生成 accept-incomplete negTokenTarg。 |
| smb2_spnego_wrap_ntlmssp_auth | function | int smb2_spnego_wrap_ntlmssp_auth(struct smb2_context *smb2, const uint8_t *ntlmssp_token, const int token_len, void **neg_targ_token); | Include | NTLMSSP authentication token 路径使用该接口生成含 response token 的 negTokenTarg。 |
| smb2_spnego_wrap_authenticate_result | function | int smb2_spnego_wrap_authenticate_result(struct smb2_context *smb2, const int authorized_ok, void **blob); | Include | 服务端认证完成路径使用该接口编码 accept-completed 或 accept-fail 结果。 |
| smb2_spnego_unwrap_gssapi | function | int smb2_spnego_unwrap_gssapi(struct smb2_context *smb2, const uint8_t *spnego, const int spnego_len, const int suppress_errors, uint8_t **token, uint32_t *mechanisms); | Include | SMB session setup 路径使用该接口解析 GSS-API SPNEGO blob、机制集合和可选 token。 |
| smb2_spnego_unwrap_blob | function | int smb2_spnego_unwrap_blob(struct smb2_context *smb2, const uint8_t *spnego, const int spnego_len, const int suppress_errors, uint8_t **response_token, uint32_t *mechanisms); | Include | NTLMSSP 路径使用该接口统一处理 raw NTLMSSP、GSS-API SPNEGO 和 raw negTokenTarg 输入。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| HAVE_CONFIG_H | macro | lib/spnego-wrapper.h:22 | 启用配置头包含，影响可见类型和平台条件。 |
| _GNU_SOURCE | macro | lib/spnego-wrapper.h:26 | 未定义时由头文件定义，以启用 GNU 扩展声明。 |
| SPNEGO_MECHANISM_KRB5 | macro | lib/spnego-wrapper.h:34 | Kerberos mechanism bit，值为 `0x0001`。 |
| SPNEGO_MECHANISM_NTLMSSP | macro | lib/spnego-wrapper.h:35 | NTLMSSP mechanism bit，值为 `0x0002`。 |

## ADDED Requirements

### Requirement: SPNEGO_MECHANISM_KRB5 Kerberos mechanism flag
系统 MUST expose `SPNEGO_MECHANISM_KRB5` as the stable bit value for Kerberos SPNEGO mechanism detection.

#### Scenario: caller observes Kerberos mechanism flag
- **GIVEN** SPNEGO mechanism parsing identifies either the standard Kerberos OID or Microsoft Kerberos OID
- **WHEN** the parser records supported mechanisms
- **THEN** the Kerberos mechanism bit MUST use value `0x0001`

Trace: `lib/spnego-wrapper.h:SPNEGO_MECHANISM_KRB5`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`

### Requirement: SPNEGO_MECHANISM_NTLMSSP NTLMSSP mechanism flag
系统 MUST expose `SPNEGO_MECHANISM_NTLMSSP` as the stable bit value for NTLMSSP SPNEGO mechanism detection.

#### Scenario: caller observes NTLMSSP mechanism flag
- **GIVEN** SPNEGO mechanism parsing identifies the NTLMSSP OID
- **WHEN** the parser records supported mechanisms
- **THEN** the NTLMSSP mechanism bit MUST use value `0x0002`

Trace: `lib/spnego-wrapper.h:SPNEGO_MECHANISM_NTLMSSP`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`

### Requirement: smb2_spnego_create_negotiate_reply_blob creates negotiate init blob
系统 MUST create an allocated SPNEGO negotiate-init blob and report its encoded length through the return value.

#### Scenario: negotiate reply blob is created
- **GIVEN** a valid SMB context and writable `neg_init_token` output pointer
- **WHEN** `smb2_spnego_create_negotiate_reply_blob(smb2, allow_ntlmssp, neg_init_token)` is called
- **THEN** the function MUST allocate a zeroed output buffer, encode the SPNEGO top-level OID and mechanism list, store the buffer in `*neg_init_token`, and return the encoded byte length

Trace: `lib/spnego-wrapper.h:smb2_spnego_create_negotiate_reply_blob`, `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`

#### Scenario: negotiate reply allocation fails
- **GIVEN** output buffer allocation fails
- **WHEN** `smb2_spnego_create_negotiate_reply_blob` attempts to create the negotiate token
- **THEN** the function MUST set an SMB error and return `0`

Trace: `lib/spnego-wrapper.h:smb2_spnego_create_negotiate_reply_blob`, `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`

### Requirement: smb2_spnego_wrap_gssapi wraps NTLMSSP token in GSS-API SPNEGO
系统 MUST encode a GSS-API SPNEGO negTokenInit wrapper that advertises NTLMSSP and optionally carries the supplied NTLMSSP token.

#### Scenario: wrapper includes optional NTLMSSP token
- **GIVEN** `ntlmssp_token` is non-NULL and `token_len` is non-zero
- **WHEN** `smb2_spnego_wrap_gssapi(smb2, ntlmssp_token, token_len, blob)` is called
- **THEN** the function MUST allocate a wrapper blob, encode the SPNEGO and NTLMSSP mechanism OIDs, copy the NTLMSSP bytes into an octet string, store the buffer in `*blob`, and return the encoded byte length

Trace: `lib/spnego-wrapper.h:smb2_spnego_wrap_gssapi`, `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`

#### Scenario: wrapper omits missing NTLMSSP token
- **GIVEN** `ntlmssp_token` is NULL or `token_len` is zero
- **WHEN** `smb2_spnego_wrap_gssapi` is called
- **THEN** the function MUST still encode the mechanism list and return a valid wrapper without a mech-token octet string

Trace: `lib/spnego-wrapper.h:smb2_spnego_wrap_gssapi`, `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`

### Requirement: smb2_spnego_wrap_ntlmssp_challenge creates accept-incomplete target
系统 MUST encode an NTLMSSP challenge as a SPNEGO negTokenTarg with accept-incomplete status and NTLMSSP supported mechanism.

#### Scenario: challenge wrapper is created
- **GIVEN** a valid NTLMSSP challenge token and writable `neg_targ_token` output pointer
- **WHEN** `smb2_spnego_wrap_ntlmssp_challenge(smb2, ntlmssp_token, token_len, neg_targ_token)` is called
- **THEN** the function MUST encode negResult `accept-incomplete`, encode the NTLMSSP mechanism OID, copy the challenge token into an octet string, store the allocated buffer, and return its encoded byte length

Trace: `lib/spnego-wrapper.h:smb2_spnego_wrap_ntlmssp_challenge`, `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_challenge`

### Requirement: smb2_spnego_wrap_ntlmssp_auth creates response target
系统 MUST encode an NTLMSSP authentication response token as a SPNEGO negTokenTarg response-token field.

#### Scenario: auth wrapper is created
- **GIVEN** a valid NTLMSSP authentication token and writable `neg_targ_token` output pointer
- **WHEN** `smb2_spnego_wrap_ntlmssp_auth(smb2, ntlmssp_token, token_len, neg_targ_token)` is called
- **THEN** the function MUST allocate a negTokenTarg buffer, copy the token into the context-2 octet string, store the buffer in `*neg_targ_token`, and return the encoded byte length

Trace: `lib/spnego-wrapper.h:smb2_spnego_wrap_ntlmssp_auth`, `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_auth`

### Requirement: smb2_spnego_wrap_authenticate_result encodes authentication outcome
系统 MUST encode a SPNEGO negTokenTarg result code that represents authentication success or failure.

#### Scenario: authentication result is encoded
- **GIVEN** a writable `blob` output pointer
- **WHEN** `smb2_spnego_wrap_authenticate_result(smb2, authorized_ok, blob)` is called
- **THEN** the function MUST encode result code `0` when `authorized_ok` is non-zero and result code `3` when `authorized_ok` is zero

Trace: `lib/spnego-wrapper.h:smb2_spnego_wrap_authenticate_result`, `lib/spnego-wrapper.c:smb2_spnego_wrap_authenticate_result`

#### Scenario: authentication result allocation fails
- **GIVEN** output buffer allocation fails
- **WHEN** `smb2_spnego_wrap_authenticate_result` attempts to create the result blob
- **THEN** the function MUST set an SMB error and return `-ENOMEM`

Trace: `lib/spnego-wrapper.h:smb2_spnego_wrap_authenticate_result`, `lib/spnego-wrapper.c:smb2_spnego_wrap_authenticate_result`

### Requirement: smb2_spnego_unwrap_gssapi parses GSS-API SPNEGO blob
系统 MUST validate the GSS-API SPNEGO envelope, detect supported mechanisms, and optionally return the embedded NTLMSSP token pointer.

#### Scenario: GSS-API wrapper is parsed
- **GIVEN** a well-formed GSS-API SPNEGO blob with mechanism OIDs and optional mech token
- **WHEN** `smb2_spnego_unwrap_gssapi(smb2, spnego, spnego_len, suppress_errors, token, mechanisms)` is called
- **THEN** the function MUST set mechanism bits for recognized Kerberos and NTLMSSP OIDs, set `*token` to NULL before optional token parsing, and return the embedded token length when a token is present

Trace: `lib/spnego-wrapper.h:smb2_spnego_unwrap_gssapi`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`

#### Scenario: malformed GSS-API wrapper is rejected
- **GIVEN** the SPNEGO envelope, OID, sequence, mechanism list, or mech-token encoding fails validation
- **WHEN** `smb2_spnego_unwrap_gssapi` parses the blob
- **THEN** the function MUST return `-EINVAL` and MUST set an SMB error unless `suppress_errors` is non-zero

Trace: `lib/spnego-wrapper.h:smb2_spnego_unwrap_gssapi`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`

### Requirement: smb2_spnego_unwrap_blob dispatches SPNEGO input formats
系统 MUST normalize supported security-buffer encodings into an NTLMSSP token pointer and token length.

#### Scenario: raw NTLMSSP token is returned unchanged
- **GIVEN** `spnego` points to a buffer longer than seven bytes beginning with `NTLMSSP`
- **WHEN** `smb2_spnego_unwrap_blob(smb2, spnego, spnego_len, suppress_errors, response_token, mechanisms)` is called
- **THEN** the function MUST set `*response_token` to the input buffer and return `spnego_len`

Trace: `lib/spnego-wrapper.h:smb2_spnego_unwrap_blob`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`

#### Scenario: wrapped SPNEGO input is dispatched by first byte
- **GIVEN** `spnego` is a valid GSS-API wrapper or raw SPNEGO target blob
- **WHEN** `smb2_spnego_unwrap_blob` inspects the first byte
- **THEN** the function MUST call `smb2_spnego_unwrap_gssapi` for application-constructor input and MUST call target unwrapping for context-specific input

Trace: `lib/spnego-wrapper.h:smb2_spnego_unwrap_blob`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`

#### Scenario: invalid unwrap input is rejected
- **GIVEN** `spnego` is NULL, `response_token` is NULL, `spnego_len` is less than seven, or the first byte is unsupported
- **WHEN** `smb2_spnego_unwrap_blob` validates the input
- **THEN** the function MUST return `-EINVAL`

Trace: `lib/spnego-wrapper.h:smb2_spnego_unwrap_blob`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_spnego_wrap_ntlmssp_challenge` and `smb2_spnego_wrap_ntlmssp_auth` 对 NULL token 或负 `token_len` 的前置条件是否应由调用方保证？ | smb2_spnego_wrap_ntlmssp_challenge`, `smb2_spnego_wrap_ntlmssp_auth | 实现直接按 `token_len` 分配并 `memcpy`，源码未显式校验边界。 |
| Q-002 | `smb2_spnego_unwrap_gssapi` 在 `token == NULL` 时是否仍应向 `mechanisms` 返回机制集合作为稳定契约？ | smb2_spnego_unwrap_gssapi | 实现支持该路径并返回 `0`，但未发现测试或公开文档确认调用方依赖。 |
| Q-003 | GitNexus impact 对同名声明和实现返回歧义，具体上游风险需在实现文件 spec 中按 UID 或工具能力补充确认。 | file-level | 当前 `gitnexus impact` CLI 仅接受 symbol name，无法用 `--file` 或 `--target-uid` 消歧。 |
