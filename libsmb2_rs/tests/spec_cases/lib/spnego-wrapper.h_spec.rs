use libsmb2_rs::lib::spnego_wrapper::{
    self as spnego, SPNEGO_MECHANISM_KRB5, SPNEGO_MECHANISM_NTLMSSP,
};

fn blob_is_positive(result: &spnego::SpnegoBlobResult) -> bool {
    result.rc > 0 && result.has_blob
}

fn ntlmssp_token() -> &'static [u8] {
    b"NTLMSSP\0header"
}

// Trace: `lib/spnego-wrapper.h:SPNEGO_MECHANISM_KRB5`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`
// Spec: SPNEGO_MECHANISM_KRB5 Kerberos mechanism flag#caller observes Kerberos mechanism flag
// - **GIVEN** SPNEGO mechanism parsing identifies either the standard Kerberos OID or Microsoft Kerberos OID
// - **WHEN** the parser records supported mechanisms
// - **THEN** the Kerberos mechanism bit MUST use value `0x0001`
#[test]
fn test_spnego_wrapper_h_caller_observes_kerberos_mechanism_flag() {
    assert_eq!(SPNEGO_MECHANISM_KRB5, 0x0001);
}

// Trace: `lib/spnego-wrapper.h:SPNEGO_MECHANISM_NTLMSSP`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`
// Spec: SPNEGO_MECHANISM_NTLMSSP NTLMSSP mechanism flag#caller observes NTLMSSP mechanism flag
// - **GIVEN** SPNEGO mechanism parsing identifies the NTLMSSP OID
// - **WHEN** the parser records supported mechanisms
// - **THEN** the NTLMSSP mechanism bit MUST use value `0x0002`
#[test]
fn test_spnego_wrapper_h_caller_observes_ntlmssp_mechanism_flag() {
    assert_eq!(SPNEGO_MECHANISM_NTLMSSP, 0x0002);
}

// Trace: `lib/spnego-wrapper.h:smb2_spnego_create_negotiate_reply_blob`, `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`
// Spec: smb2_spnego_create_negotiate_reply_blob creates negotiate init blob#negotiate reply blob is created
// - **GIVEN** a valid SMB context and writable `neg_init_token` output pointer
// - **WHEN** `smb2_spnego_create_negotiate_reply_blob(smb2, allow_ntlmssp, neg_init_token)` is called
// - **THEN** the function MUST allocate a zeroed output buffer, encode the SPNEGO top-level OID and mechanism list, store the buffer in `*neg_init_token`, and return the encoded byte length
#[test]
fn test_spnego_wrapper_h_negotiate_reply_blob_is_created() {
    let result = spnego::create_negotiate_reply(true);

    assert!(blob_is_positive(&result), "expected positive blob length, got {result:?}");
}

// Trace: `lib/spnego-wrapper.h:smb2_spnego_create_negotiate_reply_blob`, `lib/spnego-wrapper.c:smb2_spnego_create_negotiate_reply_blob`
// Spec: smb2_spnego_create_negotiate_reply_blob creates negotiate init blob#negotiate reply allocation fails
// - **GIVEN** output buffer allocation fails
// - **WHEN** `smb2_spnego_create_negotiate_reply_blob` attempts to create the negotiate token
// - **THEN** the function MUST set an SMB error and return `0`
#[test]
fn test_spnego_wrapper_h_negotiate_reply_allocation_fails() {
    let result = spnego::create_negotiate_reply_alloc_failure();

    assert_eq!(result.rc, 0);
    assert!(!result.has_blob);
    assert!(result.set_error_called);
    assert!(result
        .error
        .contains("Failed to allocate negotiate token init"));
}

// Trace: `lib/spnego-wrapper.h:smb2_spnego_wrap_gssapi`, `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`
// Spec: smb2_spnego_wrap_gssapi wraps NTLMSSP token in GSS-API SPNEGO#wrapper includes optional NTLMSSP token
// - **GIVEN** `ntlmssp_token` is non-NULL and `token_len` is non-zero
// - **WHEN** `smb2_spnego_wrap_gssapi(smb2, ntlmssp_token, token_len, blob)` is called
// - **THEN** the function MUST allocate a wrapper blob, encode the SPNEGO and NTLMSSP mechanism OIDs, copy the NTLMSSP bytes into an octet string, store the buffer in `*blob`, and return the encoded byte length
#[test]
fn test_spnego_wrapper_h_wrapper_includes_optional_ntlmssp_token() {
    let result = spnego::wrap_gssapi(Some(ntlmssp_token()));

    assert!(blob_is_positive(&result), "expected positive blob length, got {result:?}");
    assert!(result
        .bytes
        .windows(ntlmssp_token().len())
        .any(|window| window == ntlmssp_token()));
}

// Trace: `lib/spnego-wrapper.h:smb2_spnego_wrap_gssapi`, `lib/spnego-wrapper.c:smb2_spnego_wrap_gssapi`
// Spec: smb2_spnego_wrap_gssapi wraps NTLMSSP token in GSS-API SPNEGO#wrapper omits missing NTLMSSP token
// - **GIVEN** `ntlmssp_token` is NULL or `token_len` is zero
// - **WHEN** `smb2_spnego_wrap_gssapi` is called
// - **THEN** the function MUST still encode the mechanism list and return a valid wrapper without a mech-token octet string
#[test]
fn test_spnego_wrapper_h_wrapper_omits_missing_ntlmssp_token() {
    let result = spnego::wrap_gssapi(None);

    assert!(blob_is_positive(&result), "expected positive blob length, got {result:?}");
    assert!(!result
        .bytes
        .windows(ntlmssp_token().len())
        .any(|window| window == ntlmssp_token()));
}

// Trace: `lib/spnego-wrapper.h:smb2_spnego_wrap_ntlmssp_challenge`, `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_challenge`
// Spec: smb2_spnego_wrap_ntlmssp_challenge creates accept-incomplete target#challenge wrapper is created
// - **GIVEN** a valid NTLMSSP challenge token and writable `neg_targ_token` output pointer
// - **WHEN** `smb2_spnego_wrap_ntlmssp_challenge(smb2, ntlmssp_token, token_len, neg_targ_token)` is called
// - **THEN** the function MUST encode negResult `accept-incomplete`, encode the NTLMSSP mechanism OID, copy the challenge token into an octet string, store the allocated buffer, and return its encoded byte length
#[test]
fn test_spnego_wrapper_h_challenge_wrapper_is_created() {
    let result = spnego::wrap_ntlmssp_challenge(ntlmssp_token());

    assert!(blob_is_positive(&result), "expected positive blob length, got {result:?}");
}

// Trace: `lib/spnego-wrapper.h:smb2_spnego_wrap_ntlmssp_auth`, `lib/spnego-wrapper.c:smb2_spnego_wrap_ntlmssp_auth`
// Spec: smb2_spnego_wrap_ntlmssp_auth creates response target#auth wrapper is created
// - **GIVEN** a valid NTLMSSP authentication token and writable `neg_targ_token` output pointer
// - **WHEN** `smb2_spnego_wrap_ntlmssp_auth(smb2, ntlmssp_token, token_len, neg_targ_token)` is called
// - **THEN** the function MUST allocate a negTokenTarg buffer, copy the token into the context-2 octet string, store the buffer in `*neg_targ_token`, and return the encoded byte length
#[test]
fn test_spnego_wrapper_h_auth_wrapper_is_created() {
    let result = spnego::wrap_ntlmssp_auth(ntlmssp_token());

    assert!(blob_is_positive(&result), "expected positive blob length, got {result:?}");
}

// Trace: `lib/spnego-wrapper.h:smb2_spnego_wrap_authenticate_result`, `lib/spnego-wrapper.c:smb2_spnego_wrap_authenticate_result`
// Spec: smb2_spnego_wrap_authenticate_result encodes authentication outcome#authentication result is encoded
// - **GIVEN** a writable `blob` output pointer
// - **WHEN** `smb2_spnego_wrap_authenticate_result(smb2, authorized_ok, blob)` is called
// - **THEN** the function MUST encode result code `0` when `authorized_ok` is non-zero and result code `3` when `authorized_ok` is zero
#[test]
fn test_spnego_wrapper_h_authentication_result_is_encoded() {
    let authorized = spnego::wrap_authenticate_result(true);
    let rejected = spnego::wrap_authenticate_result(false);

    assert!(blob_is_positive(&authorized), "expected positive blob length, got {authorized:?}");
    assert!(blob_is_positive(&rejected), "expected positive blob length, got {rejected:?}");
}

// Trace: `lib/spnego-wrapper.h:smb2_spnego_wrap_authenticate_result`, `lib/spnego-wrapper.c:smb2_spnego_wrap_authenticate_result`
// Spec: smb2_spnego_wrap_authenticate_result encodes authentication outcome#authentication result allocation fails
// - **GIVEN** output buffer allocation fails
// - **WHEN** `smb2_spnego_wrap_authenticate_result` attempts to create the result blob
// - **THEN** the function MUST set an SMB error and return `-ENOMEM`
#[test]
fn test_spnego_wrapper_h_authentication_result_allocation_fails() {
    let result = spnego::wrap_authenticate_result_alloc_failure();

    assert_eq!(result.rc, -12);
    assert!(!result.has_blob);
    assert!(result.set_error_called);
    assert!(result.error.contains("Failed to allocate spnego wrapper"));
}

// Trace: `lib/spnego-wrapper.h:smb2_spnego_unwrap_gssapi`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`
// Spec: smb2_spnego_unwrap_gssapi parses GSS-API SPNEGO blob#GSS-API wrapper is parsed
// - **GIVEN** a well-formed GSS-API SPNEGO blob with mechanism OIDs and optional mech token
// - **WHEN** `smb2_spnego_unwrap_gssapi(smb2, spnego, spnego_len, suppress_errors, token, mechanisms)` is called
// - **THEN** the function MUST set mechanism bits for recognized Kerberos and NTLMSSP OIDs, set `*token` to NULL before optional token parsing, and return the embedded token length when a token is present
#[test]
fn test_spnego_wrapper_h_gss_api_wrapper_is_parsed() {
    let wrapped = spnego::wrap_gssapi(Some(ntlmssp_token()));
    let result = spnego::unwrap_gssapi(&wrapped.bytes, false);

    assert_eq!(result.rc, ntlmssp_token().len() as i32);
    assert_ne!(result.mechanisms & SPNEGO_MECHANISM_NTLMSSP, 0);
}

// Trace: `lib/spnego-wrapper.h:smb2_spnego_unwrap_gssapi`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_gssapi`
// Spec: smb2_spnego_unwrap_gssapi parses GSS-API SPNEGO blob#malformed GSS-API wrapper is rejected
// - **GIVEN** the SPNEGO envelope, OID, sequence, mechanism list, or mech-token encoding fails validation
// - **WHEN** `smb2_spnego_unwrap_gssapi` parses the blob
// - **THEN** the function MUST return `-EINVAL` and MUST set an SMB error unless `suppress_errors` is non-zero
#[test]
fn test_spnego_wrapper_h_malformed_gss_api_wrapper_is_rejected() {
    let result = spnego::unwrap_gssapi(b"bad", false);

    assert!(result.rc < 0);
}

// Trace: `lib/spnego-wrapper.h:smb2_spnego_unwrap_blob`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`
// Spec: smb2_spnego_unwrap_blob dispatches SPNEGO input formats#raw NTLMSSP token is returned unchanged
// - **GIVEN** `spnego` points to a buffer longer than seven bytes beginning with `NTLMSSP`
// - **WHEN** `smb2_spnego_unwrap_blob(smb2, spnego, spnego_len, suppress_errors, response_token, mechanisms)` is called
// - **THEN** the function MUST set `*response_token` to the input buffer and return `spnego_len`
#[test]
fn test_spnego_wrapper_h_raw_ntlmssp_token_is_returned_unchanged() {
    let result = spnego::unwrap_blob(ntlmssp_token(), false);

    assert_eq!(result.rc, ntlmssp_token().len() as i32);
    assert_eq!(result.token_offset, None);
}

// Trace: `lib/spnego-wrapper.h:smb2_spnego_unwrap_blob`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`
// Spec: smb2_spnego_unwrap_blob dispatches SPNEGO input formats#wrapped SPNEGO input is dispatched by first byte
// - **GIVEN** `spnego` is a valid GSS-API wrapper or raw SPNEGO target blob
// - **WHEN** `smb2_spnego_unwrap_blob` inspects the first byte
// - **THEN** the function MUST call `smb2_spnego_unwrap_gssapi` for application-constructor input and MUST call target unwrapping for context-specific input
#[test]
fn test_spnego_wrapper_h_wrapped_spnego_input_is_dispatched_by_first_byte() {
    let wrapped = spnego::wrap_gssapi(Some(ntlmssp_token()));
    let result = spnego::unwrap_blob(&wrapped.bytes, false);

    assert_eq!(result.rc, ntlmssp_token().len() as i32);
}

// Trace: `lib/spnego-wrapper.h:smb2_spnego_unwrap_blob`, `lib/spnego-wrapper.c:smb2_spnego_unwrap_blob`
// Spec: smb2_spnego_unwrap_blob dispatches SPNEGO input formats#invalid unwrap input is rejected
// - **GIVEN** `spnego` is NULL, `response_token` is NULL, `spnego_len` is less than seven, or the first byte is unsupported
// - **WHEN** `smb2_spnego_unwrap_blob` validates the input
// - **THEN** the function MUST return `-EINVAL`
#[test]
fn test_spnego_wrapper_h_invalid_unwrap_input_is_rejected() {
    let result = spnego::unwrap_blob(b"invalid", false);

    assert!(result.rc < 0);
}
