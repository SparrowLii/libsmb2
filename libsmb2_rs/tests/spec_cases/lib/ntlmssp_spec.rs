use libsmb2_rs::lib::ntlmssp::{self, AuthContext, NEGOTIATE_MESSAGE, SMB2_KEY_SIZE};

// Trace: `lib/ntlmssp.c:ntlmssp_init_context`, `tests/ntlmssp_generate_blob.c:main`
// Spec: ntlmssp_init_context initializes NTLMSSP state#successful initialization
// - **GIVEN** 调用方提供 user、password、domain、workstation 和至少 8 字节 client challenge
// - **WHEN** 调用方调用 `ntlmssp_init_context`
// - **THEN** 返回值为非空上下文，后续握手使用复制后的凭据、challenge、未认证状态和清零的导出会话密钥
#[test]
fn test_ntlmssp_successful_initialization() {
    let snapshot = ntlmssp::context_success();

    assert!(snapshot.created);
    assert_eq!(snapshot.authenticated, 0);
    assert_eq!(snapshot.key_rc, 0);
    assert_eq!(snapshot.key, [0; SMB2_KEY_SIZE]);
}

// Trace: `lib/ntlmssp.c:ntlmssp_init_context`
// Spec: ntlmssp_init_context initializes NTLMSSP state#allocation failure
// - **GIVEN** 上下文、凭据字段或 client challenge 分配失败
// - **WHEN** 调用方调用 `ntlmssp_init_context`
// - **THEN** 函数 MUST 释放已分配的字段并返回 `NULL`
#[test]
fn test_ntlmssp_allocation_failure() {
    assert!(ntlmssp::context_allocation_failure());
}

// Trace: `lib/ntlmssp.c:ntlmssp_destroy_context`
// Spec: ntlmssp_destroy_context releases NTLMSSP state#destroy populated context
// - **GIVEN** 调用方持有由 `ntlmssp_init_context` 返回且可能已执行握手的上下文
// - **WHEN** 调用方调用 `ntlmssp_destroy_context`
// - **THEN** 上下文拥有的动态内存被释放，调用方不再使用该上下文指针
#[test]
fn test_ntlmssp_destroy_populated_context() {
    assert!(ntlmssp::destroy_populated_context_free_count() >= 6);
}

// Trace: `lib/ntlmssp.c:ntlmssp_set_spnego_wrapping`
// Spec: ntlmssp_set_spnego_wrapping stores wrapping flag#enable wrapping
// - **GIVEN** 调用方持有有效 `struct auth_data` 上下文
// - **WHEN** 调用方调用 `ntlmssp_set_spnego_wrapping(auth, wrap)`
// - **THEN** 上下文保存 `wrap` 值供后续 `ntlmssp_generate_blob` 使用
#[test]
fn test_ntlmssp_enable_wrapping() {
    assert_eq!(ntlmssp::wrapping_roundtrip(1), 1);
}

// Trace: `lib/ntlmssp.c:ntlmssp_get_spnego_wrapping`
// Spec: ntlmssp_get_spnego_wrapping returns wrapping flag#read wrapping state
// - **GIVEN** 调用方持有有效 `struct auth_data` 上下文
// - **WHEN** 调用方调用 `ntlmssp_get_spnego_wrapping`
// - **THEN** 返回值等于上下文中保存的 `spnego_wrap` 字段
#[test]
fn test_ntlmssp_read_wrapping_state() {
    let mut auth = AuthContext::new_default().expect("auth context should allocate");

    auth.set_spnego_wrapping(9);

    assert_eq!(auth.spnego_wrapping(), 9);
}

// Trace: `lib/ntlmssp.c:ntlmssp_get_message_type`
// Spec: ntlmssp_get_message_type unwraps and reports NTLMSSP type#valid raw or wrapped NTLMSSP message
// - **GIVEN** 调用方提供 raw NTLMSSP buffer 或可由 SPNEGO unwrap 得到 NTLMSSP payload 的 buffer
// - **WHEN** 调用方调用 `ntlmssp_get_message_type`
// - **THEN** 函数返回 `0`，`message_type` 写入 little-endian message type，`ntlmssp_ptr` 和 `ntlmssp_len` 指向有效 payload，`is_wrapped` 表示 payload 是否不同于输入 buffer
#[test]
fn test_ntlmssp_valid_raw_or_wrapped_ntlmssp_message() {
    let result = ntlmssp::message_type_raw(NEGOTIATE_MESSAGE);

    assert_eq!(result.rc, 0);
    assert_eq!(result.message_type, NEGOTIATE_MESSAGE);
    assert_eq!(result.ptr_offset, Some(0));
    assert_eq!(result.len, 16);
    assert_eq!(result.is_wrapped, 0);
}

// Trace: `lib/ntlmssp.c:ntlmssp_get_message_type`
// Spec: ntlmssp_get_message_type unwraps and reports NTLMSSP type#invalid or too-short message
// - **GIVEN** 输入 buffer 为空、长度小于 12、unwrap 失败或 payload 不含 `NTLMSSP` 签名
// - **WHEN** 调用方调用 `ntlmssp_get_message_type`
// - **THEN** 函数 MUST 返回 `-1`，并在提供输出参数时保持初始化后的失败默认值
#[test]
fn test_ntlmssp_invalid_or_too_short_message() {
    let result = ntlmssp::message_type_invalid_short();

    assert_eq!(result.rc, -1);
    assert_eq!(result.message_type, 0xffff_ffff);
    assert_eq!(result.ptr_offset, None);
    assert_eq!(result.len, 0);
}

// Trace: `lib/ntlmssp.c:ntlmssp_generate_blob`
// Spec: ntlmssp_generate_blob drives NTLMSSP handshakes#client starts negotiation
// - **GIVEN** SMB2 context 处于客户端模式且 `input_buf` 为 `NULL`
// - **WHEN** 调用方调用 `ntlmssp_generate_blob`
// - **THEN** 函数生成 NTLMSSP NEGOTIATE_MESSAGE；如果 SPNEGO wrapping 已启用，输出 MUST 为 GSSAPI 包装后的 negotiate blob
#[test]
fn test_ntlmssp_client_starts_negotiation() {
    let result = ntlmssp::generate_initial_client_negotiate();

    assert_eq!(result.rc, 0, "unexpected error: {}", result.error);
    assert_eq!(result.message_type, NEGOTIATE_MESSAGE);
    assert!(result.bytes.starts_with(b"NTLMSSP\0"));
}

// Trace: `lib/ntlmssp.c:ntlmssp_generate_blob`
// Spec: ntlmssp_generate_blob drives NTLMSSP handshakes#invalid handshake input
// - **GIVEN** 输入消息缺少 NTLMSSP message type、服务端收到非 negotiate/authenticate 消息，或客户端收到非 challenge 消息
// - **WHEN** 调用方调用 `ntlmssp_generate_blob`
// - **THEN** 函数 MUST 返回 `-1`，并在可定位错误的路径上通过 `smb2_set_error` 记录错误文本
#[test]
fn test_ntlmssp_invalid_handshake_input() {
    let result = ntlmssp::generate_invalid_client_blob();

    assert_eq!(result.rc, -1);
    assert!(result.set_error_called);
    assert!(result.error.contains("no message type"));
}

// Trace: `lib/ntlmssp.c:ntlmssp_authenticate_blob`
// Spec: ntlmssp_authenticate_blob validates AUTHENTICATION_MESSAGE#invalid proof or authorization
// - **GIVEN** 输入签名或 type 无效、授权处理器拒绝用户、缺少 password 且匿名未启用、challenge 长度不足，或 NT proof 与响应不匹配
// - **WHEN** 服务端调用 `ntlmssp_authenticate_blob`
// - **THEN** 函数 MUST 返回 `-1`，并在已设置错误文本的路径上保留认证失败原因
#[test]
fn test_ntlmssp_invalid_proof_or_authorization() {
    assert_eq!(ntlmssp::authenticate_invalid_input(), -1);
}

// Trace: `lib/ntlmssp.c:ntlmssp_get_authenticated`
// Spec: ntlmssp_get_authenticated reports authentication state#query authentication state
// - **GIVEN** 调用方需要检查服务端认证结果
// - **WHEN** 调用方调用 `ntlmssp_get_authenticated`
// - **THEN** 非空上下文返回内部认证状态，空上下文返回 `0`
#[test]
fn test_ntlmssp_query_authentication_state() {
    let auth = AuthContext::new_default().expect("auth context should allocate");

    assert_eq!(auth.authenticated(), 0);
    assert_eq!(ntlmssp::authenticated_null(), 0);
}

// Trace: `lib/ntlmssp.c:ntlmssp_get_session_key`
// Spec: ntlmssp_get_session_key copies exported key#successful key export
// - **GIVEN** 调用方提供非空 auth、key 和 key_size 指针
// - **WHEN** 调用方调用 `ntlmssp_get_session_key`
// - **THEN** 函数返回 `0`，`*key` 指向调用方需释放的 `SMB2_KEY_SIZE` 字节副本，`*key_size` 等于 `SMB2_KEY_SIZE`
#[test]
fn test_ntlmssp_successful_key_export() {
    let result = ntlmssp::session_key_copy();

    assert_eq!(result.rc, 0);
    assert_eq!(result.key_size as usize, SMB2_KEY_SIZE);
    assert_eq!(result.key, [0; SMB2_KEY_SIZE]);
}

// Trace: `lib/ntlmssp.c:ntlmssp_get_session_key`
// Spec: ntlmssp_get_session_key copies exported key#invalid arguments or allocation failure
// - **GIVEN** auth、key 或 key_size 为空，或 key 缓冲区分配失败
// - **WHEN** 调用方调用 `ntlmssp_get_session_key`
// - **THEN** 函数 MUST 返回 `-1` 且不返回有效 key 副本
#[test]
fn test_ntlmssp_invalid_arguments_or_allocation_failure() {
    let result = ntlmssp::session_key_invalid_arguments();

    assert_eq!(result.rc, -1);
    assert_eq!(result.key_size, 0);
}
