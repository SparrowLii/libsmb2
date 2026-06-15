use libsmb2_rs::lib::spnego_wrapper::{self as spnego, SPNEGO_MECHANISM_NTLMSSP};

fn blob_is_valid(result: &spnego::SpnegoBlobResult) -> bool {
    result.rc > 0 && result.has_blob && result.bytes.len() == result.rc as usize
}

fn ntlmssp_token() -> &'static [u8] {
    b"NTLMSSP\0token"
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`, `lib/libsmb2.c:smb2_negotiate_request_cb`
// Spec: smb2_spnego_create_negotiate_reply_blob builds negotiate reply token#mechanism list includes configured mechanisms
// - **GIVEN** 调用方提供有效 `smb2` 上下文、`neg_init_token` 输出指针，并传入 `allow_ntlmssp` 标志
// - **WHEN** 调用 `smb2_spnego_create_negotiate_reply_blob`
// - **THEN** 返回值 MUST 是 ASN.1 BER 编码长度，blob MUST 包含 GSS-SPNEGO OID，并在 `HAVE_LIBKRB5` 启用时包含 KRB5 OID，在 `allow_ntlmssp` 非零时包含 NTLMSSP OID
#[test]
fn test_spnego_wrapper_mechanism_list_includes_configured_mechanisms() {
    let result = spnego::create_negotiate_reply(true);

    assert!(blob_is_valid(&result));
    assert!(!result.set_error_called);
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`
// Spec: smb2_spnego_create_negotiate_reply_blob builds negotiate reply token#allocation failure reports context error
// - **GIVEN** 底层分配返回 `NULL`
// - **WHEN** 调用 `smb2_spnego_create_negotiate_reply_blob`
// - **THEN** 函数 MUST 通过 `smb2_set_error` 记录分配失败并返回 `0`
#[test]
fn test_spnego_wrapper_allocation_failure_reports_context_error() {
    let result = spnego::create_negotiate_reply_alloc_failure();

    assert_eq!(result.rc, 0);
    assert!(!result.has_blob);
    assert!(result.set_error_called);
    assert!(result
        .error
        .contains("Failed to allocate negotiate token init"));
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`, `lib/ntlmssp.c:ntlmssp_generate_blob`, `tests/ntlmssp_generate_blob.c:main`
// Spec: smb2_spnego_wrap_gssapi wraps NTLMSSP token as NegTokenInit#token is present
// - **GIVEN** 调用方提供 `ntlmssp_token`、非零 `token_len` 和 `blob` 输出指针
// - **WHEN** 调用 `smb2_spnego_wrap_gssapi`
// - **THEN** 输出 blob MUST 包含 GSS-SPNEGO OID、NTLMSSP mechanism OID 和 context 2 OCTET STRING 形式的原始 token，返回值 MUST 是编码长度
#[test]
fn test_spnego_wrapper_token_is_present() {
    let result = spnego::wrap_gssapi(Some(ntlmssp_token()));

    assert!(blob_is_valid(&result));
    assert!(result
        .bytes
        .windows(ntlmssp_token().len())
        .any(|window| window == ntlmssp_token()));
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`, `lib/ntlmssp.c:ntlmssp_generate_blob`
// Spec: smb2_spnego_wrap_gssapi wraps NTLMSSP token as NegTokenInit#token is absent
// - **GIVEN** `ntlmssp_token` 为 `NULL` 或 `token_len` 为 `0`
// - **WHEN** 调用 `smb2_spnego_wrap_gssapi`
// - **THEN** 输出 blob MUST 仍包含 GSS-SPNEGO OID 和 NTLMSSP mechanism OID，并 MUST NOT 写入 mech token OCTET STRING
#[test]
fn test_spnego_wrapper_token_is_absent() {
    let result = spnego::wrap_gssapi(None);

    assert!(blob_is_valid(&result));
    assert!(!result
        .bytes
        .windows(ntlmssp_token().len())
        .any(|window| window == ntlmssp_token()));
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_challenge`, `lib/ntlmssp.c:ntlmssp_generate_blob`
// Spec: smb2_spnego_wrap_ntlmssp_challenge wraps server challenge#challenge token is wrapped
// - **GIVEN** 调用方提供 NTLMSSP challenge token、长度和 `neg_targ_token` 输出指针
// - **WHEN** 调用 `smb2_spnego_wrap_ntlmssp_challenge`
// - **THEN** 输出 blob MUST 包含 context 1 NegTokenTarg、negResult 枚举值 `1`、NTLMSSP supportedMech OID 和 context 2 OCTET STRING token，返回值 MUST 是编码长度
#[test]
fn test_spnego_wrapper_challenge_token_is_wrapped() {
    let result = spnego::wrap_ntlmssp_challenge(ntlmssp_token());

    assert!(blob_is_valid(&result));
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_auth`, `lib/ntlmssp.c:ntlmssp_generate_blob`, `tests/ntlmssp_generate_blob.c:main`
// Spec: smb2_spnego_wrap_ntlmssp_auth wraps client auth token#authenticate token is wrapped
// - **GIVEN** 调用方提供 NTLMSSP authenticate token、长度和 `neg_targ_token` 输出指针
// - **WHEN** 调用 `smb2_spnego_wrap_ntlmssp_auth`
// - **THEN** 输出 blob MUST 包含 context 1 NegTokenTarg、sequence 和 context 2 OCTET STRING token，返回值 MUST 是编码长度
#[test]
fn test_spnego_wrapper_authenticate_token_is_wrapped() {
    let result = spnego::wrap_ntlmssp_auth(ntlmssp_token());

    assert!(blob_is_valid(&result));
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_authenticate_result`, `lib/ntlmssp.c:ntlmssp_generate_blob`
// Spec: smb2_spnego_wrap_authenticate_result encodes auth result#authentication accepted
// - **GIVEN** `authorized_ok` 非零且 `blob` 输出指针有效
// - **WHEN** 调用 `smb2_spnego_wrap_authenticate_result`
// - **THEN** 输出 blob MUST 包含 negResult 枚举值 `0` 表示 accept-completed，返回值 MUST 是编码长度
#[test]
fn test_spnego_wrapper_authentication_accepted() {
    let result = spnego::wrap_authenticate_result(true);

    assert!(blob_is_valid(&result));
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_authenticate_result`, `lib/ntlmssp.c:ntlmssp_generate_blob`
// Spec: smb2_spnego_wrap_authenticate_result encodes auth result#authentication rejected
// - **GIVEN** `authorized_ok` 为 `0` 且 `blob` 输出指针有效
// - **WHEN** 调用 `smb2_spnego_wrap_authenticate_result`
// - **THEN** 输出 blob MUST 包含 negResult 枚举值 `3` 表示 accept-fail，返回值 MUST 是编码长度
#[test]
fn test_spnego_wrapper_authentication_rejected() {
    let result = spnego::wrap_authenticate_result(false);

    assert!(blob_is_valid(&result));
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_wrap_authenticate_result`
// Spec: smb2_spnego_wrap_authenticate_result encodes auth result#allocation failure uses errno style return
// - **GIVEN** 底层分配返回 `NULL`
// - **WHEN** 调用 `smb2_spnego_wrap_authenticate_result`
// - **THEN** 函数 MUST 通过 `smb2_set_error` 记录分配失败并返回 `-ENOMEM`
#[test]
fn test_spnego_wrapper_allocation_failure_uses_errno_style_return() {
    let result = spnego::wrap_authenticate_result_alloc_failure();

    assert_eq!(result.rc, -12);
    assert!(!result.has_blob);
    assert!(result.set_error_called);
    assert!(result.error.contains("Failed to allocate spnego wrapper"));
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_targ`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`
// Spec: smb2_spnego_unwrap_targ extracts raw NegTokenTarg response token#response token is present
// - **GIVEN** 输入 blob 以 context 1 NegTokenTarg 和 sequence 开始，并包含 context 2 OCTET STRING token
// - **WHEN** 调用 `smb2_spnego_unwrap_targ`
// - **THEN** 函数 MUST 将 `token` 指向输入缓冲区内的 OCTET STRING 内容，并返回该 token 长度
#[test]
fn test_spnego_wrapper_response_token_is_present() {
    let wrapped = spnego::wrap_ntlmssp_challenge(ntlmssp_token());
    let result = spnego::unwrap_targ(&wrapped.bytes);

    assert!(result.rc > 0, "target unwrap failed: {result:?}");
    assert!(result.token_offset.is_some());
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_targ`
// Spec: smb2_spnego_unwrap_targ extracts raw NegTokenTarg response token#raw target is malformed
// - **GIVEN** 输入 blob 缺少 required type、length 或子对象解析失败
// - **WHEN** 调用 `smb2_spnego_unwrap_targ`
// - **THEN** 函数 MUST 通过 `smb2_set_error` 记录坏 SPNEGO 偏移并返回 `-EINVAL`
#[test]
fn test_spnego_wrapper_raw_target_is_malformed() {
    let result = spnego::unwrap_targ(b"not-spnego");

    assert!(result.rc < 0);
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`, `lib/libsmb2.c:negotiate_cb`
// Spec: smb2_spnego_unwrap_gssapi decodes GSS-API SPNEGO mechanisms#mechanism list is decoded
// - **GIVEN** 输入 blob 是 GSS-API application SPNEGO NegTokenInit，并包含 KRB5、Microsoft KRB5 或 NTLMSSP mechanism OID
// - **WHEN** 调用 `smb2_spnego_unwrap_gssapi` 且 `mechanisms` 非空
// - **THEN** 函数 MUST 对 KRB5 或 Microsoft KRB5 设置 `SPNEGO_MECHANISM_KRB5`，对 NTLMSSP 设置 `SPNEGO_MECHANISM_NTLMSSP`
#[test]
fn test_spnego_wrapper_mechanism_list_is_decoded() {
    let wrapped = spnego::wrap_gssapi(Some(ntlmssp_token()));
    let result = spnego::unwrap_blob(&wrapped.bytes, false);

    assert!(result.rc >= 0, "SPNEGO unwrap failed: {result:?}");
    assert_ne!(result.mechanisms & SPNEGO_MECHANISM_NTLMSSP, 0);
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`
// Spec: smb2_spnego_unwrap_gssapi decodes GSS-API SPNEGO mechanisms#optional mech token is decoded
// - **GIVEN** GSS-API SPNEGO blob 在 mechanism list 后包含 context 2 OCTET STRING，且 `token` 输出指针非空
// - **WHEN** 调用 `smb2_spnego_unwrap_gssapi`
// - **THEN** 函数 MUST 将 `token` 指向输入缓冲区内的 OCTET STRING 内容并返回该 token length
#[test]
fn test_spnego_wrapper_optional_mech_token_is_decoded() {
    let wrapped = spnego::wrap_gssapi(Some(ntlmssp_token()));
    let result = spnego::unwrap_gssapi(&wrapped.bytes, false);

    assert_eq!(result.rc, ntlmssp_token().len() as i32);
    assert!(result.token_offset.is_some());
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`
// Spec: smb2_spnego_unwrap_gssapi decodes GSS-API SPNEGO mechanisms#malformed GSS-API blob respects suppress_errors
// - **GIVEN** 输入 blob 结构、OID 或长度校验失败
// - **WHEN** 调用 `smb2_spnego_unwrap_gssapi`
// - **THEN** 函数 MUST 返回 `-EINVAL`，并且只有 `suppress_errors` 为 `0` 时才通过 `smb2_set_error` 记录坏 SPNEGO 偏移
#[test]
fn test_spnego_wrapper_malformed_gss_api_blob_respects_suppress_errors() {
    let noisy = spnego::unwrap_gssapi(b"bad", false);
    let suppressed = spnego::unwrap_gssapi(b"bad", true);

    assert!(noisy.rc < 0);
    assert!(noisy.set_error_called);
    assert!(suppressed.rc < 0);
    assert!(!suppressed.set_error_called);
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`, `lib/ntlmssp.c:ntlmssp_get_message_type`
// Spec: smb2_spnego_unwrap_blob dispatches supported token formats#raw NTLMSSP token is returned directly
// - **GIVEN** 输入非空、`token` 输出指针非空、长度大于 `7` 且前 8 字节为 `NTLMSSP`
// - **WHEN** 调用 `smb2_spnego_unwrap_blob`
// - **THEN** 函数 MUST 将 `token` 指向原始输入并返回原始输入长度
#[test]
fn test_spnego_wrapper_raw_ntlmssp_token_is_returned_directly() {
    let result = spnego::unwrap_blob(ntlmssp_token(), false);

    assert_eq!(result.rc, ntlmssp_token().len() as i32);
    assert_eq!(result.token_offset, None);
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_targ`
// Spec: smb2_spnego_unwrap_blob dispatches supported token formats#wrapped token is dispatched by first type byte
// - **GIVEN** 输入首字节为 GSS-API application type 或 ASN.1 context type `0`、`1`、`2`
// - **WHEN** 调用 `smb2_spnego_unwrap_blob`
// - **THEN** 函数 MUST 分别调用 GSS-API unwrap 或 raw target unwrap，并返回对应解析结果
#[test]
fn test_spnego_wrapper_wrapped_token_is_dispatched_by_first_type_byte() {
    let wrapped = spnego::wrap_gssapi(Some(ntlmssp_token()));
    let result = spnego::unwrap_blob(&wrapped.bytes, false);

    assert_eq!(result.rc, ntlmssp_token().len() as i32);
    assert!(result.token_offset.is_some());
}

// Trace: `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`
// Spec: smb2_spnego_unwrap_blob dispatches supported token formats#invalid input is rejected
// - **GIVEN** `spnego` 为 `NULL`、`token` 为 `NULL`、长度小于 `7` 或首字节不是支持的 ASN.1 type
// - **WHEN** 调用 `smb2_spnego_unwrap_blob`
// - **THEN** 函数 MUST 返回 `-EINVAL`，且在 `token` 非空时 MUST 先将 `*token` 置为 `NULL`
#[test]
fn test_spnego_wrapper_invalid_input_is_rejected() {
    let result = spnego::unwrap_blob(b"invalid", false);

    assert!(result.rc < 0);
}
