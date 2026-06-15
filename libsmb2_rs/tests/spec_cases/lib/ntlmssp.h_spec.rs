use libsmb2_rs::lib::ntlmssp::{
    self, AuthContext, AUTHENTICATION_MESSAGE, CHALLENGE_MESSAGE, NEGOTIATE_MESSAGE, SMB2_KEY_SIZE,
};

// Trace: `lib/ntlmssp.h:NEGOTIATE_MESSAGE`, `lib/ntlmssp.c:ntlmssp_generate_blob`
// Spec: NEGOTIATE_MESSAGE NTLMSSP type value#Negotiate constant is available to callers
// - **GIVEN** a caller includes `lib/ntlmssp.h`
// - **WHEN** the caller compares an NTLMSSP message type with `NEGOTIATE_MESSAGE`
// - **THEN** the comparison uses the stable value `0x00000001`
#[test]
fn test_ntlmssp_h_negotiate_constant_is_available_to_callers() {
    assert_eq!(NEGOTIATE_MESSAGE, 0x0000_0001);
}

// Trace: `lib/ntlmssp.h:CHALLENGE_MESSAGE`, `lib/ntlmssp.c:ntlmssp_generate_blob`, `tests/ntlmssp_generate_blob.c:main`
// Spec: CHALLENGE_MESSAGE NTLMSSP type value#Challenge constant is available to callers
// - **GIVEN** a caller includes `lib/ntlmssp.h`
// - **WHEN** the caller compares an NTLMSSP message type with `CHALLENGE_MESSAGE`
// - **THEN** the comparison uses the stable value `0x00000002`
#[test]
fn test_ntlmssp_h_challenge_constant_is_available_to_callers() {
    assert_eq!(CHALLENGE_MESSAGE, 0x0000_0002);
}

// Trace: `lib/ntlmssp.h:AUTHENTICATION_MESSAGE`, `lib/ntlmssp.c:ntlmssp_generate_blob`, `lib/ntlmssp.c:ntlmssp_authenticate_blob`
// Spec: AUTHENTICATION_MESSAGE NTLMSSP type value#Authenticate constant is available to callers
// - **GIVEN** a caller includes `lib/ntlmssp.h`
// - **WHEN** the caller compares an NTLMSSP message type with `AUTHENTICATION_MESSAGE`
// - **THEN** the comparison uses the stable value `0x00000003`
#[test]
fn test_ntlmssp_h_authenticate_constant_is_available_to_callers() {
    assert_eq!(AUTHENTICATION_MESSAGE, 0x0000_0003);
}

// Trace: `lib/ntlmssp.h:struct auth_data`, `lib/ntlmssp.c:struct auth_data`
// Spec: struct auth_data opaque context#Callers pass opaque authentication state
// - **GIVEN** a caller has a `struct auth_data *` returned by `ntlmssp_init_context`
// - **WHEN** the caller passes that pointer to another NTLMSSP API declared in this header
// - **THEN** the caller relies on the pointer identity and SHALL NOT require field access from `lib/ntlmssp.h`
#[test]
fn test_ntlmssp_h_callers_pass_opaque_authentication_state() {
    let mut auth = AuthContext::new_default().expect("auth context should allocate");

    auth.set_spnego_wrapping(5);

    assert_eq!(auth.spnego_wrapping(), 5);
    assert_eq!(auth.authenticated(), 0);
}

// Trace: `lib/ntlmssp.h:ntlmssp_init_context`, `lib/ntlmssp.c:ntlmssp_init_context`, `tests/ntlmssp_generate_blob.c:main`
// Spec: ntlmssp_init_context context allocation#Context initializes for valid credentials
// - **GIVEN** non-NULL credential strings and an 8-byte `client_challenge`
// - **WHEN** `ntlmssp_init_context` is called
// - **THEN** the returned context stores duplicated credential state, initializes authentication as not authenticated, initializes the exported session key to zeros, and captures a Windows timestamp
#[test]
fn test_ntlmssp_h_context_initializes_for_valid_credentials() {
    let snapshot = ntlmssp::context_success();

    assert!(snapshot.created);
    assert_eq!(snapshot.authenticated, 0);
    assert_eq!(snapshot.key_rc, 0);
    assert_eq!(snapshot.key_size as usize, SMB2_KEY_SIZE);
    assert_eq!(snapshot.key, [0; SMB2_KEY_SIZE]);
}

// Trace: `lib/ntlmssp.h:ntlmssp_init_context`, `lib/ntlmssp.c:ntlmssp_init_context`
// Spec: ntlmssp_init_context context allocation#Allocation failure reports no context
// - **GIVEN** memory allocation or string duplication fails while creating context state
// - **WHEN** `ntlmssp_init_context` is called
// - **THEN** the function MUST release allocations it created for the failed context and return `NULL`
#[test]
fn test_ntlmssp_h_allocation_failure_reports_no_context() {
    assert!(ntlmssp::context_allocation_failure());
}

// Trace: `lib/ntlmssp.h:ntlmssp_destroy_context`, `lib/ntlmssp.c:ntlmssp_destroy_context`
// Spec: ntlmssp_destroy_context context release#Context destruction frees owned buffers
// - **GIVEN** a context created by `ntlmssp_init_context`
// - **WHEN** `ntlmssp_destroy_context` is called with that context
// - **THEN** the function releases NTLM buffers, credential strings, target data, challenge data, and the context allocation
#[test]
fn test_ntlmssp_h_context_destruction_frees_owned_buffers() {
    assert!(ntlmssp::destroy_populated_context_free_count() >= 6);
}

// Trace: `lib/ntlmssp.h:ntlmssp_set_spnego_wrapping`, `lib/ntlmssp.c:ntlmssp_set_spnego_wrapping`, `lib/ntlmssp.c:ntlmssp_get_spnego_wrapping`
// Spec: ntlmssp_set_spnego_wrapping wrapping flag update#Wrapping flag is set
// - **GIVEN** a valid authentication context and a wrapping flag value
// - **WHEN** `ntlmssp_set_spnego_wrapping` is called
// - **THEN** subsequent reads through `ntlmssp_get_spnego_wrapping` observe that stored value
#[test]
fn test_ntlmssp_h_wrapping_flag_is_set() {
    assert_eq!(ntlmssp::wrapping_roundtrip(7), 7);
}

// Trace: `lib/ntlmssp.h:ntlmssp_get_spnego_wrapping`, `lib/ntlmssp.c:ntlmssp_get_spnego_wrapping`
// Spec: ntlmssp_get_spnego_wrapping wrapping flag read#Wrapping flag is read
// - **GIVEN** a valid authentication context whose wrapping flag was initialized or updated
// - **WHEN** `ntlmssp_get_spnego_wrapping` is called
// - **THEN** the function returns the context's current wrapping flag value
#[test]
fn test_ntlmssp_h_wrapping_flag_is_read() {
    let snapshot = ntlmssp::context_success();

    assert_eq!(snapshot.spnego_initial, 0);
    assert_eq!(snapshot.spnego_after_set, 7);
}

// Trace: `lib/ntlmssp.h:ntlmssp_get_message_type`, `lib/ntlmssp.c:ntlmssp_get_message_type`, `lib/ntlmssp.c:ntlmssp_generate_blob`
// Spec: ntlmssp_get_message_type NTLMSSP parsing#NTLMSSP message type is decoded
// - **GIVEN** a raw or SPNEGO-wrapped buffer containing a valid NTLMSSP signature and at least 12 bytes of payload
// - **WHEN** `ntlmssp_get_message_type` is called with output pointers
// - **THEN** the function returns `0`, writes the little-endian message type, writes the NTLMSSP payload pointer and length when requested, and writes whether SPNEGO unwrapping changed the payload pointer when requested
#[test]
fn test_ntlmssp_h_ntlmssp_message_type_is_decoded() {
    let result = ntlmssp::message_type_raw(NEGOTIATE_MESSAGE);

    assert_eq!(result.rc, 0);
    assert_eq!(result.message_type, NEGOTIATE_MESSAGE);
    assert_eq!(result.ptr_offset, Some(0));
    assert_eq!(result.len, 16);
    assert_eq!(result.is_wrapped, 0);
}

// Trace: `lib/ntlmssp.h:ntlmssp_get_message_type`, `lib/ntlmssp.c:ntlmssp_get_message_type`
// Spec: ntlmssp_get_message_type NTLMSSP parsing#Invalid NTLMSSP data is rejected
// - **GIVEN** a NULL buffer, a length shorter than 12 bytes, an unwrap failure, or a payload without the NTLMSSP signature
// - **WHEN** `ntlmssp_get_message_type` is called
// - **THEN** the function MUST return `-1` after initializing provided output pointers to failure defaults
#[test]
fn test_ntlmssp_h_invalid_ntlmssp_data_is_rejected() {
    let result = ntlmssp::message_type_invalid_short();

    assert_eq!(result.rc, -1);
    assert_eq!(result.message_type, 0xffff_ffff);
    assert_eq!(result.ptr_offset, None);
    assert_eq!(result.len, 0);
}

// Trace: `lib/ntlmssp.h:ntlmssp_generate_blob`, `lib/ntlmssp.c:ntlmssp_generate_blob`
// Spec: ntlmssp_generate_blob authentication blob generation#Initial client negotiate blob is generated
// - **GIVEN** a client SMB2 context, initialized auth data, and `input_buf == NULL`
// - **WHEN** `ntlmssp_generate_blob` is called
// - **THEN** the function MUST generate a negotiate message, optionally wrap it when SPNEGO wrapping is enabled, and expose the generated buffer and length through output parameters
#[test]
fn test_ntlmssp_h_initial_client_negotiate_blob_is_generated() {
    let result = ntlmssp::generate_initial_client_negotiate();

    assert_eq!(result.rc, 0, "unexpected error: {}", result.error);
    assert!(result.output_len > 12);
    assert_eq!(result.message_type, NEGOTIATE_MESSAGE);
    assert_eq!(result.is_wrapped, 0);
    assert!(result.bytes.starts_with(b"NTLMSSP\0"));
}

// Trace: `lib/ntlmssp.h:ntlmssp_generate_blob`, `lib/ntlmssp.c:ntlmssp_generate_blob`
// Spec: ntlmssp_generate_blob authentication blob generation#Unsupported input message fails
// - **GIVEN** input data that cannot be parsed as a valid or expected NTLMSSP message for the current SMB2 role
// - **WHEN** `ntlmssp_generate_blob` is called
// - **THEN** the function MUST return `-1` and set an SMB2 error for confirmed parse or role errors where the implementation provides one
#[test]
fn test_ntlmssp_h_unsupported_input_message_fails() {
    let result = ntlmssp::generate_invalid_client_blob();

    assert_eq!(result.rc, -1);
    assert!(result.set_error_called);
    assert!(result.error.contains("no message type"));
}

// Trace: `lib/ntlmssp.h:ntlmssp_authenticate_blob`, `lib/ntlmssp.c:ntlmssp_authenticate_blob`
// Spec: ntlmssp_authenticate_blob server authentication#Invalid authenticate message fails
// - **GIVEN** NULL input, an undersized buffer, a non-NTLMSSP signature, a non-authenticate message type, missing NT response fields, denied server authorization, or proof mismatch
// - **WHEN** `ntlmssp_authenticate_blob` is called
// - **THEN** the function MUST return `-1` and preserve failure as unauthenticated state for callers that consume `ntlmssp_generate_blob`
#[test]
fn test_ntlmssp_h_invalid_authenticate_message_fails() {
    assert_eq!(ntlmssp::authenticate_invalid_input(), -1);
}

// Trace: `lib/ntlmssp.h:ntlmssp_get_authenticated`, `lib/ntlmssp.c:ntlmssp_get_authenticated`, `lib/libsmb2.c:ntlmssp_get_authenticated`
// Spec: ntlmssp_get_authenticated authentication state read#Authentication flag is queried
// - **GIVEN** a context that may or may not have completed server authentication
// - **WHEN** `ntlmssp_get_authenticated` is called
// - **THEN** the function returns the context's `is_authenticated` value, or `0` when the context pointer is NULL
#[test]
fn test_ntlmssp_h_authentication_flag_is_queried() {
    let auth = AuthContext::new_default().expect("auth context should allocate");

    assert_eq!(auth.authenticated(), 0);
    assert_eq!(ntlmssp::authenticated_null(), 0);
}

// Trace: `lib/ntlmssp.h:ntlmssp_get_session_key`, `lib/ntlmssp.c:ntlmssp_get_session_key`, `lib/libsmb2.c:ntlmssp_get_session_key`
// Spec: ntlmssp_get_session_key exported key copy#Session key copy succeeds
// - **GIVEN** a valid authentication context and non-NULL `key` and `key_size` output pointers
// - **WHEN** `ntlmssp_get_session_key` is called
// - **THEN** the function returns `0`, allocates a `SMB2_KEY_SIZE` byte key copy, writes the allocated pointer to `*key`, and writes `SMB2_KEY_SIZE` to `*key_size`
#[test]
fn test_ntlmssp_h_session_key_copy_succeeds() {
    let result = ntlmssp::session_key_copy();

    assert_eq!(result.rc, 0);
    assert_eq!(result.key_size as usize, SMB2_KEY_SIZE);
    assert_eq!(result.key, [0; SMB2_KEY_SIZE]);
}

// Trace: `lib/ntlmssp.h:ntlmssp_get_session_key`, `lib/ntlmssp.c:ntlmssp_get_session_key`
// Spec: ntlmssp_get_session_key exported key copy#Session key copy fails for invalid parameters or allocation failure
// - **GIVEN** a NULL context, NULL output pointer, or failed key allocation
// - **WHEN** `ntlmssp_get_session_key` is called
// - **THEN** the function MUST return `-1` without reporting a usable key copy
#[test]
fn test_ntlmssp_h_session_key_copy_fails_for_invalid_parameters_or_allocation_failure() {
    let result = ntlmssp::session_key_invalid_arguments();

    assert_eq!(result.rc, -1);
    assert_eq!(result.key_size, 0);
}
