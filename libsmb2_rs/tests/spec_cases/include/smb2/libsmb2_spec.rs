use libsmb2_sys::legacy::unicode;

use libsmb2_rs::include::smb2::libsmb2::{
    AuthenticationMethod, NegotiateVersion, Smb2Client, Smb2ClientState,
};
use libsmb2_sys::smb2::smb2_errors::SMB2_STATUS_INVALID_PARAMETER;

// Trace: `include/smb2/libsmb2.h:smb2_context_lifecycle_api`, `lib/init.c:smb2_init_context`
// Spec: smb2_context_lifecycle_api manage context lifetime#创建默认 context
// - **GIVEN** 调用方准备开始 SMB2 client 或 server 会话
// - **WHEN** 调用方调用 `smb2_init_context()`
// - **THEN** 成功时返回非空 context，失败时 MUST 返回 `NULL`
#[test]
fn test_libsmb2_context_create_default() {
    let mut client = Smb2Client::new();

    assert!(client.is_active());
    assert_eq!(client.state(), Smb2ClientState::Active);
    assert_eq!(client.last_request_message_id(), 0);

    client.destroy_context();
    assert_eq!(client.state(), Smb2ClientState::Destroyed);
    assert!(!client.is_active());
}

// Trace: `include/smb2/libsmb2.h:smb2_configuration_api`, `lib/init.c:smb2_set_error`
// Spec: smb2_configuration_api configure context behavior#设置并读取 context 属性
// - **GIVEN** 调用方持有一个有效 context
// - **WHEN** 调用方调用 setter 配置用户、domain、workstation、opaque、passthrough、version 或 security 选项
// - **THEN** 对应 getter 或后续连接流程 MUST 使用该 context 中保存的最新配置值
#[test]
fn test_libsmb2_configuration_set_read() {
    let mut client = Smb2Client::new();
    let opaque = 0x1234usize;
    let guid = [0x42; 16];

    client.set_passthrough(true);
    client.set_version(NegotiateVersion::V0311);
    client.set_security_mode(1);
    client.set_seal(true);
    client.set_sign(true);
    client.set_authentication(AuthenticationMethod::NtlmSsp);
    client.set_user("alice");
    client.set_domain("DOMAIN");
    client.set_workstation("WORKSTATION");
    client.set_opaque(Some(opaque));
    client.set_client_guid(guid);

    assert!(client.passthrough());
    assert_eq!(client.version(), NegotiateVersion::V0311);
    assert_eq!(client.security_mode(), 1);
    assert!(client.seal());
    assert!(client.sign());
    assert_eq!(client.authentication(), AuthenticationMethod::NtlmSsp);
    assert_eq!(client.user(), Some("alice"));
    assert_eq!(client.domain(), Some("DOMAIN"));
    assert_eq!(client.workstation(), Some("WORKSTATION"));
    assert_eq!(client.opaque(), Some(opaque));
    assert_eq!(client.client_guid(), Some(guid));
}

// Trace: `include/smb2/libsmb2.h:smb2_url_error_api`, `lib/init.c:smb2_parse_url`, `lib/init.c:smb2_destroy_url`
// Spec: smb2_url_error_api expose URL and error helpers#解析并释放 SMB2 URL
// - **GIVEN** 调用方提供形如 `smb2://[domain;][user@]server/share/path` 的 URL 字符串
// - **WHEN** 调用方调用 `smb2_parse_url(smb2, url)` 后使用返回的 `struct smb2_url *`
// - **THEN** 成功时 MUST 填充 domain、user、server、share 和 path 字段，调用方 MUST 使用 `smb2_destroy_url()` 释放返回结构
#[test]
fn test_libsmb2_url_parse_free() {
    let mut client = Smb2Client::new();
    let parsed = client
        .parse_url("smb://DOMAIN;alice@example/share/path/to/file")
        .unwrap();

    assert_eq!(parsed.domain.as_deref(), Some("DOMAIN"));
    assert_eq!(parsed.user.as_deref(), Some("alice"));
    assert_eq!(parsed.server, "example");
    assert_eq!(parsed.share, "share");
    assert_eq!(parsed.path.as_deref(), Some("path/to/file"));
}

// Trace: `include/smb2/libsmb2.h:smb2_url_error_api`, `lib/init.c:smb2_parse_url`, `lib/errors.c:nterror_to_errno`
// Spec: smb2_url_error_api expose URL and error helpers#error/status helpers
// - **GIVEN** context 记录最近错误或调用方提供 NTSTATUS
// - **WHEN** 调用方读取 `smb2_get_error()`、`smb2_get_nterror()` 或转换 NTSTATUS
// - **THEN** safe API MUST 暴露稳定错误字符串和 errno/status 映射
#[test]
fn test_libsmb2_error_status_helpers() {
    let mut client = Smb2Client::new();

    assert!(client.parse_url("http://example/share").is_err());
    assert_eq!(client.error(), Some("URL does not start with 'smb://'"));
    assert_eq!(client.nterror(), -22);
    assert_eq!(libsmb2_rs::lib::errors::nterror_to_str(0), "STATUS_SUCCESS");
    assert_eq!(
        libsmb2_rs::lib::errors::nterror_to_errno(SMB2_STATUS_INVALID_PARAMETER),
        22
    );
}

// Trace: `include/smb2/libsmb2.h:smb2_unicode_api`, `lib/unicode.c:smb2_utf8_to_utf16`
// Spec: smb2_unicode_api convert UTF encodings#UTF-8 转 UTF-16LE
// - **GIVEN** 调用方提供有效 UTF-8 字符串
// - **WHEN** 调用方调用 `smb2_utf8_to_utf16(utf8)`
// - **THEN** 成功时 MUST 返回包含 UTF-16 code unit 长度和 little-endian code units 的 `struct smb2_utf16 *`，失败时 MUST 返回 `NULL`
#[test]
fn test_libsmb2_utf8_to_utf16le() {
    assert_eq!(
        unicode::utf8_to_utf16_units("Aé你"),
        Some(vec![0x0041, 0x00e9, 0x4f60])
    );
}

// Trace: `include/smb2/libsmb2.h:smb2_unicode_api`, `lib/unicode.c:smb2_utf16_to_utf8`
// Spec: smb2_unicode_api convert UTF encodings#UTF-16LE 转 UTF-8
// - **GIVEN** 调用方提供 UTF-16LE code unit 指针和长度
// - **WHEN** 调用方调用 `smb2_utf16_to_utf8(str, len)`
// - **THEN** 成功时 MUST 返回可由 `free()` 释放的 UTF-8 字符串
#[test]
fn test_libsmb2_utf16le_to_utf8() {
    assert_eq!(
        unicode::utf16_units_to_utf8(&[0x0041, 0x00e9, 0x4f60]),
        Some(String::from("Aé你"))
    );
}
