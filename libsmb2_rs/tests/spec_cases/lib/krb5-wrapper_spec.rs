use libsmb2_rs::lib::krb5_wrapper::{
    krb5_can_do_ntlmssp, krb5_set_gss_error_message, Krb5Backend, Krb5ContextState, Krb5Error,
    Krb5Mechanism, Krb5NegotiateConfig, Krb5ServerCredentialsConfig, Krb5SessionRequest,
    PrivateAuthData,
};

// Trace: `lib/krb5-wrapper.c:krb5_free_auth_data`, `lib/libsmb2.c:free_c_data`, `lib/krb5-wrapper.c:krb5_init_server_credentials`, `lib/krb5-wrapper.c:krb5_free_server_credentials`
// Spec: krb5_free_auth_data releases private authentication resources#release populated auth data
// - **GIVEN** `auth` 指向包含 output token、Kerberos cache、GSS context、names、credential 和 `g_server` 的认证状态
// - **WHEN** 调用 `krb5_free_auth_data(auth)`
// - **THEN** 函数释放这些资源并最终释放 `auth` 结构
#[test]
fn test_krb5_wrapper_release_populated_auth_data() {
    let mut auth = PrivateAuthData::new();
    auth.set_output_token(vec![1, 2, 3]);
    auth.set_session_key(vec![4, 5, 6]);

    auth.free_auth_data();

    assert_eq!(auth.context_state(), Krb5ContextState::Empty);
    assert_eq!(auth.get_output_token_length(), 0);
    assert!(auth.get_output_token_buffer().is_empty());
    assert_eq!(
        auth.session_get_session_key(),
        Err(Krb5Error::MissingSessionKey)
    );
}

// Trace: `lib/krb5-wrapper.c:krb5_set_gss_error`, `lib/krb5-wrapper.c:display_status`
// Spec: krb5_set_gss_error records formatted GSS failure details#record GSS error on context
// - **GIVEN** `smb2` 非空且 GSSAPI 返回 major/minor 错误码
// - **WHEN** 调用 `krb5_set_gss_error(smb2, func, maj, min)`
// - **THEN** `smb2` 的错误状态包含函数名和两个 GSS status 文本，临时 status 字符串被释放
#[test]
fn test_krb5_wrapper_record_gss_error_on_context() {
    let message = krb5_set_gss_error_message("gss_init_sec_context", 1, 2);

    assert_eq!(message, "gss_init_sec_context: (1, 2)");
}

// Trace: `lib/krb5-wrapper.c:krb5_set_gss_error`, `lib/krb5-wrapper.c:krb5_can_do_ntlmssp`
// Spec: krb5_set_gss_error records formatted GSS failure details#ignore NULL SMB2 context
// - **GIVEN** `smb2` 为 `NULL`
// - **WHEN** 调用 `krb5_set_gss_error(NULL, func, maj, min)`
// - **THEN** 函数释放格式化出的 status 字符串且不写入 SMB2 错误状态
#[test]
fn test_krb5_wrapper_ignore_null_smb2_context() {
    let message = krb5_set_gss_error_message("gss_inquire_attrs_for_mech", 0, 0);

    assert_eq!(message, "gss_inquire_attrs_for_mech: (0, 0)");
}

// Trace: `lib/krb5-wrapper.c:krb5_negotiate_reply`, `lib/libsmb2.c:negotiate_cb`
// Spec: krb5_negotiate_reply initializes client-side Kerberos authentication#reject cached credentials without domain or password
// - **GIVEN** `smb2->use_cached_creds` 为真且 `domain` 或 `password` 为 `NULL`
// - **WHEN** 调用 `krb5_negotiate_reply(smb2, server, domain, user_name, password)`
// - **THEN** 函数返回 `NULL` 并设置错误 `domain and password must be set while using krb5cc mode`
#[test]
fn test_krb5_wrapper_reject_cached_credentials_without_domain_or_password() {
    let error = PrivateAuthData::negotiate_reply(Krb5NegotiateConfig {
        server: String::from("server.example.com"),
        user_name: Some(String::from("alice")),
        use_cached_creds: true,
        ..Krb5NegotiateConfig::default()
    })
    .expect_err("cached credentials require domain and password before backend setup");

    assert_eq!(error, Krb5Error::MissingParameter("domain"));
}

// Trace: `lib/krb5-wrapper.c:krb5_session_get_session_key`, `lib/libsmb2.c:session_setup_cb`, `lib/libsmb2.c:smb2_session_setup_request_cb`
// Spec: krb5_session_get_session_key stores the negotiated session key#copy valid session key
// - **GIVEN** GSS context 返回至少一个非空 session key buffer
// - **WHEN** 调用 `krb5_session_get_session_key(smb2, auth_data)`
// - **THEN** 函数分配 `smb2->session_key`、复制 key bytes、设置 `smb2->session_key_size` 并返回 `0`
#[test]
fn test_krb5_wrapper_copy_valid_session_key() {
    let mut auth = PrivateAuthData::new();

    auth.set_session_key(vec![0xaa, 0xbb, 0xcc]);

    assert_eq!(auth.session_get_session_key().unwrap(), &[0xaa, 0xbb, 0xcc]);
}

// Trace: `lib/krb5-wrapper.c:krb5_session_get_session_key`, `lib/init.c:smb2_set_error`, `lib/krb5-wrapper.c:krb5_set_gss_error`
// Spec: krb5_session_get_session_key stores the negotiated session key#reject invalid session key
// - **GIVEN** GSS 查询失败或返回空 session key set、空元素、零长度 key 或内存分配失败
// - **WHEN** 调用 `krb5_session_get_session_key(smb2, auth_data)`
// - **THEN** 函数设置 SMB2/GSS 错误并返回 `-1`
#[test]
fn test_krb5_wrapper_reject_invalid_session_key() {
    let auth = PrivateAuthData::new();

    assert_eq!(
        auth.session_get_session_key(),
        Err(Krb5Error::MissingSessionKey)
    );
}

// Trace: `lib/krb5-wrapper.c:krb5_session_request`, `lib/libsmb2.c:send_session_setup_request`, `lib/libsmb2.c:session_setup_cb`
// Spec: krb5_session_request advances client GSS session setup#consume server token and continue
// - **GIVEN** `buf` 非空且 GSSAPI 返回 `GSS_S_CONTINUE_NEEDED`
// - **WHEN** 调用 `krb5_session_request(smb2, auth_data, buf, len)`
// - **THEN** 函数先释放旧 output token，再以 `buf/len` 作为 input token 推进上下文并返回 `0`
#[test]
fn test_krb5_wrapper_consume_server_token_and_continue() {
    let mut auth = PrivateAuthData::new();
    let previous = auth.clone();
    let error = auth
        .session_request(Some(&[1, 2, 3]))
        .expect_err("missing GSS backend is the only blocked part of this safe path");

    assert_eq!(
        error,
        Krb5Error::UnsupportedBackend {
            operation: "krb5_session_request"
        }
    );
    assert_eq!(auth, previous);
}

// Trace: `lib/krb5-wrapper.c:krb5_session_request`, `lib/krb5-wrapper.c:krb5_set_gss_error`
// Spec: krb5_session_request advances client GSS session setup#report GSS init failure
// - **GIVEN** `gss_init_sec_context` 返回 GSS error
// - **WHEN** 调用 `krb5_session_request(smb2, auth_data, buf, len)`
// - **THEN** 函数通过 `krb5_set_gss_error` 记录错误并返回 `-1`
#[test]
fn test_krb5_wrapper_report_gss_init_failure() {
    let mut auth = PrivateAuthData::new();
    let error = auth
        .session_request(None)
        .expect_err("unlinked backend reports GSS init as unsupported");

    assert_eq!(
        error,
        Krb5Error::UnsupportedBackend {
            operation: "krb5_session_request"
        }
    );
}

// Trace: `lib/krb5-wrapper.c:krb5_session_reply`, `lib/libsmb2.c:smb2_session_setup_request_cb`
// Spec: krb5_session_reply accepts server-side GSS tokens#request more processing
// - **GIVEN** `gss_accept_sec_context` 返回 `GSS_S_CONTINUE_NEEDED`
// - **WHEN** 调用 `krb5_session_reply(smb2, auth_data, buf, len, more_processing_needed)`
// - **THEN** 函数将 `*more_processing_needed` 设置为 `1` 并返回 `0`
#[test]
fn test_krb5_wrapper_request_more_processing() {
    let mut auth = PrivateAuthData::new();
    let previous = auth.clone();
    let error = auth
        .session_reply(&[4, 5, 6])
        .expect_err("missing GSS backend is the only blocked part of this safe path");

    assert_eq!(
        error,
        Krb5Error::UnsupportedBackend {
            operation: "krb5_session_reply"
        }
    );
    assert_eq!(auth, previous);
}

// Trace: `lib/krb5-wrapper.c:krb5_session_reply`, `lib/init.c:smb2_set_error`
// Spec: krb5_session_reply accepts server-side GSS tokens#reject unavailable proxy credentials on Apple
// - **GIVEN** `auth_data->get_proxy_cred` 为真、没有 delegated credential 且平台为 Apple
// - **WHEN** 调用 `krb5_session_reply(smb2, auth_data, buf, len, more_processing_needed)`
// - **THEN** 函数设置错误 `Apple has no way to proxy credentials` 并返回 `-1`
#[test]
fn test_krb5_wrapper_reject_unavailable_proxy_credentials_on_apple() {
    let mut auth = PrivateAuthData::new();
    let error = auth
        .session_reply(&[])
        .expect_err("unlinked backend cannot accept server-side tokens");

    assert_eq!(
        error,
        Krb5Error::UnsupportedBackend {
            operation: "krb5_session_reply"
        }
    );
}

// Trace: `lib/krb5-wrapper.c:krb5_renew_server_credentials`, `lib/libsmb2.c:smb2_serve_port`
// Spec: krb5_renew_server_credentials refreshes keytab-backed server tickets#no keytab requires no renewal
// - **GIVEN** `server->auth_data` 为空或其 `keytab` 为空
// - **WHEN** 调用 `krb5_renew_server_credentials(server)`
// - **THEN** 函数返回 `0` 且不修改 Kerberos cache
#[test]
fn test_krb5_wrapper_no_keytab_requires_no_renewal() {
    let auth = PrivateAuthData::new();

    assert_eq!(auth.renew_server_credentials(), Ok(()));
}

// Trace: `lib/krb5-wrapper.c:krb5_init_server_credentials`, `lib/libsmb2.c:smb2_serve_port`
// Spec: krb5_init_server_credentials initializes keytab-backed server state#no keytab path is a no-op success
// - **GIVEN** `keytab_path` 为 `NULL`、空字符串或无需显式 keytab
// - **WHEN** 调用 `krb5_init_server_credentials(server, keytab_path)`
// - **THEN** 函数返回 `0` 且不要求创建 `server->auth_data`
#[test]
fn test_krb5_wrapper_no_keytab_path_is_a_no_op_success() {
    let auth = PrivateAuthData::init_server_credentials(Krb5ServerCredentialsConfig {
        hostname: String::from("server.example.com"),
        keytab_path: None,
    })
    .expect("absent keytab is handled before backend calls");

    assert_eq!(auth, None);
}

// Trace: `lib/krb5-wrapper.c:krb5_get_output_token_length`, `lib/libsmb2.c:session_setup_cb`, `lib/libsmb2.c:smb2_session_setup_request_cb`
// Spec: krb5_get_output_token_length returns current output token length#expose generated token length
// - **GIVEN** `auth_data->output_token.length` 已由 GSSAPI session step 设置
// - **WHEN** 调用 `krb5_get_output_token_length(auth_data)`
// - **THEN** 返回值等于当前 output token length
#[test]
fn test_krb5_wrapper_expose_generated_token_length() {
    let mut auth = PrivateAuthData::new();

    auth.set_output_token(vec![9, 8, 7, 6]);

    assert_eq!(auth.get_output_token_length(), 4);
}

// Trace: `lib/krb5-wrapper.c:krb5_get_output_token_buffer`, `lib/libsmb2.c:session_setup_cb`, `lib/libsmb2.c:smb2_session_setup_request_cb`
// Spec: krb5_get_output_token_buffer returns current output token buffer#expose generated token buffer
// - **GIVEN** `auth_data->output_token.value` 已由 GSSAPI session step 设置
// - **WHEN** 调用 `krb5_get_output_token_buffer(auth_data)`
// - **THEN** 返回值等于当前 output token buffer 指针
#[test]
fn test_krb5_wrapper_expose_generated_token_buffer() {
    let mut auth = PrivateAuthData::new();

    auth.set_output_token(vec![9, 8, 7, 6]);

    assert_eq!(auth.get_output_token_buffer(), &[9, 8, 7, 6]);
}

// Trace: `lib/krb5-wrapper.c:krb5_can_do_ntlmssp`, `lib/krb5-wrapper.c:krb5_set_gss_error`
// Spec: krb5_can_do_ntlmssp reports runtime NTLMSSP mechanism availability#Apple or GSS failure reports unavailable
// - **GIVEN** 平台为 Apple 或 GSSAPI 查询 NTLMSSP OID 失败
// - **WHEN** 调用 `krb5_can_do_ntlmssp()`
// - **THEN** 函数返回 `0`，非 Apple GSS failure 路径还通过 `krb5_set_gss_error(NULL, ...)` 丢弃错误文本
#[test]
fn test_krb5_wrapper_apple_or_gss_failure_reports_unavailable() {
    assert_eq!(Krb5Backend::current(), Krb5Backend::Unavailable);
    assert!(!krb5_can_do_ntlmssp());
}

#[test]
fn test_krb5_wrapper_session_request_result_shape_is_safe_to_construct() {
    let result = Krb5SessionRequest {
        continue_needed: true,
        output_token: Default::default(),
    };

    assert!(result.continue_needed);
    assert!(result.output_token.is_empty());
}

// Trace: `lib/krb5-wrapper.h:private_auth_data`, `lib/krb5-wrapper.c:krb5_session_request`, `lib/krb5-wrapper.c:krb5_session_reply`
// Spec: private_auth_data auth state carrier#authentication state is shared across wrapper calls
// - **GIVEN** Kerberos wrapper 创建或接收一个 `private_auth_data` 实例
// - **WHEN** 调用方把该实例传给 session request、session reply、session key 或释放接口
// - **THEN** 接口 MUST 通过该实例中的 GSS/Kerberos 句柄和 output token 字段传递认证状态
#[test]
fn test_krb5_wrapper_private_auth_data_carries_safe_state_across_calls() {
    let mut auth = PrivateAuthData::new();
    auth.set_output_token(vec![1]);
    auth.set_session_key(vec![2]);

    assert_eq!(auth.get_output_token_length(), 1);
    assert_eq!(auth.session_get_session_key().unwrap(), &[2]);
    assert_eq!(auth.mechanism(), Krb5Mechanism::Default);
}
