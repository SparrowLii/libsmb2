# lib/spnego-wrapper.c Specification

## Source Context

- Source: `lib/spnego-wrapper.c`
- Related Headers: `lib/spnego-wrapper.h`, `lib/asn1-ber.h`, `include/smb2/libsmb2.h`, `include/smb2/libsmb2-raw.h`, `include/smb2/smb2.h`
- Related Tests: `tests/ntlmssp_generate_blob.c`
- Related Dependencies: GitNexus context shows callers from `lib/libsmb2.c` negotiate/session setup and `lib/ntlmssp.c` NTLMSSP blob generation; outgoing dependencies include `lib/asn1-ber.c` BER encode/decode helpers and `lib/init.c:smb2_set_error`.
- Build/Compile Context: C project via CMake/Autotools; `HAVE_CONFIG_H`, `_GNU_SOURCE`, platform header probes, `HAVE_LIBKRB5`, and standard header probes affect compilation and offered mechanisms.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| `smb2_spnego_create_negotiate_reply_blob` | function | `int smb2_spnego_create_negotiate_reply_blob(struct smb2_context *smb2, int allow_ntlmssp, void **neg_init_token);` | Include | 生成 SMB2 negotiate reply 的 GSS-SPNEGO 机制列表，服务端协商路径直接调用。 |
| `smb2_spnego_wrap_gssapi` | function | `int smb2_spnego_wrap_gssapi(struct smb2_context *smb2, const uint8_t *ntlmssp_token, const int token_len, void **blob);` | Include | 将 NTLMSSP negotiate/auth token 包装为 GSS-API/SPNEGO NegTokenInit，NTLMSSP 握手路径直接依赖。 |
| `smb2_spnego_wrap_ntlmssp_challenge` | function | `int smb2_spnego_wrap_ntlmssp_challenge(struct smb2_context *smb2, const uint8_t *ntlmssp_token, const int token_len, void **neg_targ_token);` | Include | 将服务端 NTLMSSP challenge 包装为 accept-incomplete NegTokenTarg。 |
| `smb2_spnego_wrap_ntlmssp_auth` | function | `int smb2_spnego_wrap_ntlmssp_auth(struct smb2_context *smb2, const uint8_t *ntlmssp_token, const int token_len, void **neg_targ_token);` | Include | 将客户端 NTLMSSP authenticate token 包装为 NegTokenTarg response token。 |
| `smb2_spnego_wrap_authenticate_result` | function | `int smb2_spnego_wrap_authenticate_result(struct smb2_context *smb2, const int authorized_ok, void **blob);` | Include | 将服务端认证结果编码为 SPNEGO negResult。 |
| `smb2_spnego_unwrap_targ` | function | `int smb2_spnego_unwrap_targ(struct smb2_context *smb2, const uint8_t *spnego, const int spnego_len, uint8_t **token, uint32_t *mechanisms);` | Include | 解析 raw NegTokenTarg 并提取 response token 或机制结果，虽未在头文件声明但由本文件公开分派入口调用。 |
| `smb2_spnego_unwrap_gssapi` | function | `int smb2_spnego_unwrap_gssapi(struct smb2_context *smb2, const uint8_t *spnego, const int spnego_len, const int suppress_errors, uint8_t **token, uint32_t *mechanisms);` | Include | 解析 GSS-API/SPNEGO NegTokenInit，协商路径用其发现 KRB5/NTLMSSP 机制并可提取 mech token。 |
| `smb2_spnego_unwrap_blob` | function | `int smb2_spnego_unwrap_blob(struct smb2_context *smb2, const uint8_t *spnego, const int spnego_len, const int suppress_errors, uint8_t **response_token, uint32_t *mechanisms);` | Include | NTLMSSP 入口的通用 unwrap 分派，识别 raw NTLMSSP、GSS-API 和 raw SPNEGO blob。 |
| `oid_compare` | function | `static int oid_compare(const struct asn1ber_oid_value *a, const struct asn1ber_oid_value *b);` | Skip | `static` OID 比较 helper，无独立跨文件接口；行为归属到 unwrap 机制识别 Requirement。 |
| `require_typecode` | macro | `#define require_typecode(ctx, expected, label)` | Skip | 文件内部解析控制宏，错误跳转行为归属到 unwrap Requirement。 |
| `require_typeandlen` | macro | `#define require_typeandlen(ctx, expected, minimum, label)` | Skip | 文件内部解析控制宏，错误跳转行为归属到 unwrap Requirement。 |
| `require_noerr` | macro | `#define require_noerr(errcode, label)` | Skip | 文件内部错误检查宏，错误跳转行为归属到 unwrap Requirement。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| `SPNEGO_MECHANISM_KRB5` | macro | `lib/spnego-wrapper.h:34` | unwrap GSS-API 时识别 KRB5 或 Microsoft KRB5 OID 后设置的机制标志。 |
| `SPNEGO_MECHANISM_NTLMSSP` | macro | `lib/spnego-wrapper.h:35` | unwrap GSS-API 时识别 NTLMSSP OID 后设置的机制标志。 |
| `oid_gss_mech_spnego` | static data | `lib/spnego-wrapper.c:73` | GSS-SPNEGO top-level OID，编码和解码都使用。 |
| `oid_spnego_mech_krb5` | static data | `lib/spnego-wrapper.c:77` | Kerberos V5 mechanism OID；`HAVE_LIBKRB5` 编码路径和 decode 机制识别使用。 |
| `oid_spnego_mech_ms_krb5` | static data | `lib/spnego-wrapper.c:82` | Microsoft legacy KRB5 OID，decode 时映射到 `SPNEGO_MECHANISM_KRB5`。 |
| `oid_spnego_mech_ntlmssp` | static data | `lib/spnego-wrapper.c:86` | NTLMSSP mechanism OID，所有 NTLMSSP SPNEGO 包装路径使用。 |

## ADDED Requirements

### Requirement: smb2_spnego_create_negotiate_reply_blob builds negotiate reply token
系统 MUST 为 SMB2 negotiate reply 生成 GSS-SPNEGO application blob，并在成功时把新分配的缓冲区写入 `neg_init_token`，返回已编码长度。

#### Scenario: mechanism list includes configured mechanisms
- **GIVEN** 调用方提供有效 `smb2` 上下文、`neg_init_token` 输出指针，并传入 `allow_ntlmssp` 标志
- **WHEN** 调用 `smb2_spnego_create_negotiate_reply_blob`
- **THEN** 返回值 MUST 是 ASN.1 BER 编码长度，blob MUST 包含 GSS-SPNEGO OID，并在 `HAVE_LIBKRB5` 启用时包含 KRB5 OID，在 `allow_ntlmssp` 非零时包含 NTLMSSP OID

Trace: `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`, `lib/libsmb2.c:smb2_negotiate_request_cb`

#### Scenario: allocation failure reports context error
- **GIVEN** 底层分配返回 `NULL`
- **WHEN** 调用 `smb2_spnego_create_negotiate_reply_blob`
- **THEN** 函数 MUST 通过 `smb2_set_error` 记录分配失败并返回 `0`

Trace: `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`

### Requirement: smb2_spnego_wrap_gssapi wraps NTLMSSP token as NegTokenInit
系统 MUST 将输入 NTLMSSP token 编码为 GSS-API SPNEGO NegTokenInit blob，并在机制列表中声明 NTLMSSP。

#### Scenario: token is present
- **GIVEN** 调用方提供 `ntlmssp_token`、非零 `token_len` 和 `blob` 输出指针
- **WHEN** 调用 `smb2_spnego_wrap_gssapi`
- **THEN** 输出 blob MUST 包含 GSS-SPNEGO OID、NTLMSSP mechanism OID 和 context 2 OCTET STRING 形式的原始 token，返回值 MUST 是编码长度

Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`, `lib/ntlmssp.c:ntlmssp_generate_blob`, `tests/ntlmssp_generate_blob.c:main`

#### Scenario: token is absent
- **GIVEN** `ntlmssp_token` 为 `NULL` 或 `token_len` 为 `0`
- **WHEN** 调用 `smb2_spnego_wrap_gssapi`
- **THEN** 输出 blob MUST 仍包含 GSS-SPNEGO OID 和 NTLMSSP mechanism OID，并 MUST NOT 写入 mech token OCTET STRING

Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`, `lib/ntlmssp.c:ntlmssp_generate_blob`

### Requirement: smb2_spnego_wrap_ntlmssp_challenge wraps server challenge
系统 MUST 将服务端 NTLMSSP challenge 编码为 SPNEGO NegTokenTarg，并声明协商结果为 accept-incomplete。

#### Scenario: challenge token is wrapped
- **GIVEN** 调用方提供 NTLMSSP challenge token、长度和 `neg_targ_token` 输出指针
- **WHEN** 调用 `smb2_spnego_wrap_ntlmssp_challenge`
- **THEN** 输出 blob MUST 包含 context 1 NegTokenTarg、negResult 枚举值 `1`、NTLMSSP supportedMech OID 和 context 2 OCTET STRING token，返回值 MUST 是编码长度

Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_challenge`, `lib/ntlmssp.c:ntlmssp_generate_blob`

### Requirement: smb2_spnego_wrap_ntlmssp_auth wraps client auth token
系统 MUST 将客户端 NTLMSSP authenticate token 编码为 SPNEGO NegTokenTarg response token。

#### Scenario: authenticate token is wrapped
- **GIVEN** 调用方提供 NTLMSSP authenticate token、长度和 `neg_targ_token` 输出指针
- **WHEN** 调用 `smb2_spnego_wrap_ntlmssp_auth`
- **THEN** 输出 blob MUST 包含 context 1 NegTokenTarg、sequence 和 context 2 OCTET STRING token，返回值 MUST 是编码长度

Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_auth`, `lib/ntlmssp.c:ntlmssp_generate_blob`, `tests/ntlmssp_generate_blob.c:main`

### Requirement: smb2_spnego_wrap_authenticate_result encodes auth result
系统 MUST 将服务端认证布尔结果编码为 SPNEGO NegTokenTarg negResult。

#### Scenario: authentication accepted
- **GIVEN** `authorized_ok` 非零且 `blob` 输出指针有效
- **WHEN** 调用 `smb2_spnego_wrap_authenticate_result`
- **THEN** 输出 blob MUST 包含 negResult 枚举值 `0` 表示 accept-completed，返回值 MUST 是编码长度

Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_authenticate_result`, `lib/ntlmssp.c:ntlmssp_generate_blob`

#### Scenario: authentication rejected
- **GIVEN** `authorized_ok` 为 `0` 且 `blob` 输出指针有效
- **WHEN** 调用 `smb2_spnego_wrap_authenticate_result`
- **THEN** 输出 blob MUST 包含 negResult 枚举值 `3` 表示 accept-fail，返回值 MUST 是编码长度

Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_authenticate_result`, `lib/ntlmssp.c:ntlmssp_generate_blob`

#### Scenario: allocation failure uses errno style return
- **GIVEN** 底层分配返回 `NULL`
- **WHEN** 调用 `smb2_spnego_wrap_authenticate_result`
- **THEN** 函数 MUST 通过 `smb2_set_error` 记录分配失败并返回 `-ENOMEM`

Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_authenticate_result`

### Requirement: smb2_spnego_unwrap_targ extracts raw NegTokenTarg response token
系统 MUST 从 raw SPNEGO NegTokenTarg 中解析 sequence 元素并返回 response token 长度或错误码。

#### Scenario: response token is present
- **GIVEN** 输入 blob 以 context 1 NegTokenTarg 和 sequence 开始，并包含 context 2 OCTET STRING token
- **WHEN** 调用 `smb2_spnego_unwrap_targ`
- **THEN** 函数 MUST 将 `token` 指向输入缓冲区内的 OCTET STRING 内容，并返回该 token 长度

Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_targ`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`

#### Scenario: raw target is malformed
- **GIVEN** 输入 blob 缺少 required type、length 或子对象解析失败
- **WHEN** 调用 `smb2_spnego_unwrap_targ`
- **THEN** 函数 MUST 通过 `smb2_set_error` 记录坏 SPNEGO 偏移并返回 `-EINVAL`

Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_targ`

### Requirement: smb2_spnego_unwrap_gssapi decodes GSS-API SPNEGO mechanisms
系统 MUST 验证 GSS-SPNEGO top-level OID，解析 mechanism OID 列表，并按已知 OID 设置机制位。

#### Scenario: mechanism list is decoded
- **GIVEN** 输入 blob 是 GSS-API application SPNEGO NegTokenInit，并包含 KRB5、Microsoft KRB5 或 NTLMSSP mechanism OID
- **WHEN** 调用 `smb2_spnego_unwrap_gssapi` 且 `mechanisms` 非空
- **THEN** 函数 MUST 对 KRB5 或 Microsoft KRB5 设置 `SPNEGO_MECHANISM_KRB5`，对 NTLMSSP 设置 `SPNEGO_MECHANISM_NTLMSSP`

Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`, `lib/libsmb2.c:negotiate_cb`

#### Scenario: optional mech token is decoded
- **GIVEN** GSS-API SPNEGO blob 在 mechanism list 后包含 context 2 OCTET STRING，且 `token` 输出指针非空
- **WHEN** 调用 `smb2_spnego_unwrap_gssapi`
- **THEN** 函数 MUST 将 `token` 指向输入缓冲区内的 OCTET STRING 内容并返回该 token length

Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`

#### Scenario: malformed GSS-API blob respects suppress_errors
- **GIVEN** 输入 blob 结构、OID 或长度校验失败
- **WHEN** 调用 `smb2_spnego_unwrap_gssapi`
- **THEN** 函数 MUST 返回 `-EINVAL`，并且只有 `suppress_errors` 为 `0` 时才通过 `smb2_set_error` 记录坏 SPNEGO 偏移

Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`

### Requirement: smb2_spnego_unwrap_blob dispatches supported token formats
系统 MUST 将 raw NTLMSSP、GSS-API SPNEGO 和 raw SPNEGO target blob 统一分派为 NTLMSSP response token 输出。

#### Scenario: raw NTLMSSP token is returned directly
- **GIVEN** 输入非空、`token` 输出指针非空、长度大于 `7` 且前 8 字节为 `NTLMSSP`
- **WHEN** 调用 `smb2_spnego_unwrap_blob`
- **THEN** 函数 MUST 将 `token` 指向原始输入并返回原始输入长度

Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`, `lib/ntlmssp.c:ntlmssp_get_message_type`

#### Scenario: wrapped token is dispatched by first type byte
- **GIVEN** 输入首字节为 GSS-API application type 或 ASN.1 context type `0`、`1`、`2`
- **WHEN** 调用 `smb2_spnego_unwrap_blob`
- **THEN** 函数 MUST 分别调用 GSS-API unwrap 或 raw target unwrap，并返回对应解析结果

Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_targ`

#### Scenario: invalid input is rejected
- **GIVEN** `spnego` 为 `NULL`、`token` 为 `NULL`、长度小于 `7` 或首字节不是支持的 ASN.1 type
- **WHEN** 调用 `smb2_spnego_unwrap_blob`
- **THEN** 函数 MUST 返回 `-EINVAL`，且在 `token` 非空时 MUST 先将 `*token` 置为 `NULL`

Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_spnego_wrap_gssapi`、`smb2_spnego_wrap_ntlmssp_challenge` 和 `smb2_spnego_wrap_ntlmssp_auth` 在分配失败时返回 `0`，但调用方只检查 `< 0`；`0` 是否应视为合法空 blob 或失败？ | `smb2_spnego_wrap_gssapi`, `smb2_spnego_wrap_ntlmssp_challenge`, `smb2_spnego_wrap_ntlmssp_auth` | 源码记录错误后返回 `0`，`ntlmssp_generate_blob` 的错误检查与该返回约定不完全一致。 |
| Q-002 | 包装函数是否要求 `token_len >= 0` 且输出指针非空？ | `smb2_spnego_wrap_gssapi`, `smb2_spnego_wrap_ntlmssp_challenge`, `smb2_spnego_wrap_ntlmssp_auth` | 源码未显式校验负长度或空输出指针，分配长度表达式可能受输入影响。 |
| Q-003 | `smb2_spnego_unwrap_targ` 对 context 0 调用 `asn1ber_uint32_from_ber(&asn_decoder, mechanisms)` 时是否允许 `mechanisms == NULL`？ | `smb2_spnego_unwrap_targ` | 公开分派入口允许 `mechanisms` 透传，源码未在 raw target 分支保护空指针。 |
| Q-004 | `smb2_spnego_unwrap_gssapi` 中 `fail_line` 未初始化时错误消息行号是否被视为稳定诊断契约？ | `smb2_spnego_unwrap_gssapi` | 源码声明 `int fail_line;` 且错误宏依赖 `fail_line`，部分失败路径可能未设置。 |
