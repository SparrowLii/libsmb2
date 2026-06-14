use libsmb2_rs::lib::krb5_wrapper::{
    GSS_MECH_SPNEGO_OID, SPNEGO_MECH_KRB5_OID, SPNEGO_MECH_NTLMSSP_OID,
};

// Trace: `lib/krb5-wrapper.h:gss_mech_spnego`, `lib/krb5-wrapper.c:krb5_negotiate_reply`
// Spec: gss_mech_spnego non-Apple SPNEGO OID#non-Apple SPNEGO mechanism is available
// - **GIVEN** 构建平台未定义 `__APPLE__`
// - **WHEN** 代码包含 `lib/krb5-wrapper.h`
// - **THEN** 头文件 MUST 定义长度为 6、值为 `2b 06 01 05 05 02` 的 `gss_mech_spnego`
#[test]
fn test_krb5_wrapper_h_non_apple_spnego_mechanism_is_available() {
    assert_eq!(GSS_MECH_SPNEGO_OID, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);
}

// Trace: `lib/krb5-wrapper.h:spnego_mech_krb5`, `lib/krb5-wrapper.c:krb5_negotiate_reply`
// Spec: spnego_mech_krb5 Kerberos OID#Kerberos mechanism restriction uses declared OID
// - **GIVEN** 调用方选择 Kerberos security mechanism
// - **WHEN** wrapper 需要限制 GSS negotiation mechanism
// - **THEN** 代码 MUST 能使用长度为 9、值为 `2a 86 48 86 f7 12 01 02 02` 的 `spnego_mech_krb5`
#[test]
fn test_krb5_wrapper_h_kerberos_mechanism_restriction_uses_declared_oid() {
    assert_eq!(
        SPNEGO_MECH_KRB5_OID,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]
    );
}

// Trace: `lib/krb5-wrapper.h:spnego_mech_ntlmssp`, `lib/krb5-wrapper.c:krb5_can_do_ntlmssp`
// Spec: spnego_mech_ntlmssp NTLMSSP OID#NTLMSSP mechanism selection uses declared OID
// - **GIVEN** 调用方选择 NTLMSSP security mechanism or requests NTLMSSP capability detection
// - **WHEN** wrapper restricts negotiation or probes GSSAPI attributes
// - **THEN** 代码 MUST use length 10 OID bytes `2b 06 01 04 01 82 37 02 02 0a` from `spnego_mech_ntlmssp`
#[test]
fn test_krb5_wrapper_h_ntlmssp_mechanism_selection_uses_declared_oid() {
    assert_eq!(
        SPNEGO_MECH_NTLMSSP_OID,
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]
    );
}
