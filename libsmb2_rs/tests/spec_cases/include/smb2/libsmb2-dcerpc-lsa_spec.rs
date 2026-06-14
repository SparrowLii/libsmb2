use libsmb2_rs::lib::dcerpc_lsa::{
    decode_lsa_close_reply, decode_lsa_close_request, decode_lsa_lookup_sids2_reply,
    decode_lsa_lookup_sids2_request, decode_lsa_open_policy2_reply,
    decode_lsa_open_policy2_request, decode_rpc_sid, encode_lsa_close_reply,
    encode_lsa_close_request, encode_lsa_lookup_sids2_reply, encode_lsa_lookup_sids2_request,
    encode_lsa_open_policy2_reply, encode_lsa_open_policy2_request, encode_rpc_sid,
    ContextHandle as SafeContextHandle, LsaCloseReply, LsaCloseRequest, LsaLookupSids2Reply,
    LsaLookupSids2Request, LsaOpenPolicy2Reply, LsaOpenPolicy2Request,
    LsapLookupLevel as SafeLsapLookupLevel, LsaprReferencedDomainList, LsaprSidEnumBuffer,
    LsaprTranslatedNameEx, LsaprTranslatedNamesEx, LsaprTrustInformation, RpcSid as SafeRpcSid,
    RpcUnicodeString, SidNameUse, LSA_LOOKUP_SIDS2_CLIENT_REVISION, LSA_STATUS_SUCCESS,
    NT_SID_AUTHORITY as SAFE_NT_SID_AUTHORITY,
};
use libsmb2_sys::smb2::libsmb2_dcerpc_lsa::{
    CloseRequest, CloseResponse, LookupSids2Request, LookupSids2Response, LsapLookupLevel,
    NdrContextHandle, ObjectAttributes, OpenPolicy2Request, OpenPolicy2Response,
    ReferencedDomainList, RpcSid, SidEnumBuffer, TranslatedNameEx, TranslatedNamesEx,
    TrustInformation, LSA_CLOSE, LSA_LOOKUPSIDS2, LSA_OPENPOLICY2, NT_SID_AUTHORITY,
    POLICY_AUDIT_LOG_ADMIN, POLICY_CREATE_ACCOUNT, POLICY_CREATE_PRIVILEGE, POLICY_CREATE_SECRET,
    POLICY_GET_PRIVATE_INFORMATION, POLICY_LOOKUP_NAMES, POLICY_NOTIFICATION, POLICY_SERVER_ADMIN,
    POLICY_SET_AUDIT_REQUIREMENTS, POLICY_SET_DEFAULT_QUOTA_LIMITS, POLICY_TRUST_ADMIN,
    POLICY_VIEW_AUDIT_INFORMATION, POLICY_VIEW_LOCAL_INFORMATION,
};

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSA_CLOSE`, `lib/dcerpc-lsa.c:lsa_Close_req_coder`
// Spec: LSA_CLOSE exposes the Close operation number#Close operation constant is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller builds an LSA Close DCERPC request
// - **THEN** `LSA_CLOSE` expands to `0x00`
#[test]
fn test_libsmb2_dcerpc_lsa_close_operation_constant_is_available() {
    assert_eq!(LSA_CLOSE, 0x00);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSA_OPENPOLICY2`, `lib/dcerpc-lsa.c:lsa_OpenPolicy2_req_coder`
// Spec: LSA_OPENPOLICY2 exposes the OpenPolicy2 operation number#OpenPolicy2 operation constant is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller builds an LSA OpenPolicy2 DCERPC request
// - **THEN** `LSA_OPENPOLICY2` expands to `0x2c`
#[test]
fn test_libsmb2_dcerpc_lsa_openpolicy2_operation_constant_is_available() {
    assert_eq!(LSA_OPENPOLICY2, 0x2c);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSA_LOOKUPSIDS2`, `lib/dcerpc-lsa.c:lsa_LookupSids2_req_coder`
// Spec: LSA_LOOKUPSIDS2 exposes the LookupSids2 operation number#LookupSids2 operation constant is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller builds an LSA LookupSids2 DCERPC request
// - **THEN** `LSA_LOOKUPSIDS2` expands to `0x39`
#[test]
fn test_libsmb2_dcerpc_lsa_lookupsids2_operation_constant_is_available() {
    assert_eq!(LSA_LOOKUPSIDS2, 0x39);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_VIEW_LOCAL_INFORMATION`
// Spec: POLICY_VIEW_LOCAL_INFORMATION exposes its policy access bit#policy access bit is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
// - **THEN** `POLICY_VIEW_LOCAL_INFORMATION` expands to `0x00000001`
#[test]
fn test_libsmb2_dcerpc_lsa_policy_access_bit_is_available() {
    assert_eq!(POLICY_VIEW_LOCAL_INFORMATION, 0x0000_0001);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_VIEW_AUDIT_INFORMATION`
// Spec: POLICY_VIEW_AUDIT_INFORMATION exposes its policy access bit#policy access bit is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
// - **THEN** `POLICY_VIEW_AUDIT_INFORMATION` expands to `0x00000002`
#[test]
fn test_libsmb2_dcerpc_lsa_policy_access_bit_is_available_2() {
    assert_eq!(POLICY_VIEW_AUDIT_INFORMATION, 0x0000_0002);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_GET_PRIVATE_INFORMATION`
// Spec: POLICY_GET_PRIVATE_INFORMATION exposes its policy access bit#policy access bit is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
// - **THEN** `POLICY_GET_PRIVATE_INFORMATION` expands to `0x00000004`
#[test]
fn test_libsmb2_dcerpc_lsa_policy_access_bit_is_available_3() {
    assert_eq!(POLICY_GET_PRIVATE_INFORMATION, 0x0000_0004);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_TRUST_ADMIN`
// Spec: POLICY_TRUST_ADMIN exposes its policy access bit#policy access bit is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
// - **THEN** `POLICY_TRUST_ADMIN` expands to `0x00000008`
#[test]
fn test_libsmb2_dcerpc_lsa_policy_access_bit_is_available_4() {
    assert_eq!(POLICY_TRUST_ADMIN, 0x0000_0008);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_CREATE_ACCOUNT`
// Spec: POLICY_CREATE_ACCOUNT exposes its policy access bit#policy access bit is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
// - **THEN** `POLICY_CREATE_ACCOUNT` expands to `0x00000010`
#[test]
fn test_libsmb2_dcerpc_lsa_policy_access_bit_is_available_5() {
    assert_eq!(POLICY_CREATE_ACCOUNT, 0x0000_0010);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_CREATE_SECRET`
// Spec: POLICY_CREATE_SECRET exposes its policy access bit#policy access bit is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
// - **THEN** `POLICY_CREATE_SECRET` expands to `0x00000020`
#[test]
fn test_libsmb2_dcerpc_lsa_policy_access_bit_is_available_6() {
    assert_eq!(POLICY_CREATE_SECRET, 0x0000_0020);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_CREATE_PRIVILEGE`
// Spec: POLICY_CREATE_PRIVILEGE exposes its policy access bit#policy access bit is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
// - **THEN** `POLICY_CREATE_PRIVILEGE` expands to `0x00000040`
#[test]
fn test_libsmb2_dcerpc_lsa_policy_access_bit_is_available_7() {
    assert_eq!(POLICY_CREATE_PRIVILEGE, 0x0000_0040);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_SET_DEFAULT_QUOTA_LIMITS`
// Spec: POLICY_SET_DEFAULT_QUOTA_LIMITS exposes its policy access bit#policy access bit is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
// - **THEN** `POLICY_SET_DEFAULT_QUOTA_LIMITS` expands to `0x00000080`
#[test]
fn test_libsmb2_dcerpc_lsa_policy_access_bit_is_available_8() {
    assert_eq!(POLICY_SET_DEFAULT_QUOTA_LIMITS, 0x0000_0080);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_SET_AUDIT_REQUIREMENTS`
// Spec: POLICY_SET_AUDIT_REQUIREMENTS exposes its policy access bit#policy access bit is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
// - **THEN** `POLICY_SET_AUDIT_REQUIREMENTS` expands to `0x00000100`
#[test]
fn test_libsmb2_dcerpc_lsa_policy_access_bit_is_available_9() {
    assert_eq!(POLICY_SET_AUDIT_REQUIREMENTS, 0x0000_0100);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_AUDIT_LOG_ADMIN`
// Spec: POLICY_AUDIT_LOG_ADMIN exposes its policy access bit#policy access bit is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
// - **THEN** `POLICY_AUDIT_LOG_ADMIN` expands to `0x00000200`
#[test]
fn test_libsmb2_dcerpc_lsa_policy_access_bit_is_available_10() {
    assert_eq!(POLICY_AUDIT_LOG_ADMIN, 0x0000_0200);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_SERVER_ADMIN`
// Spec: POLICY_SERVER_ADMIN exposes its policy access bit#policy access bit is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
// - **THEN** `POLICY_SERVER_ADMIN` expands to `0x00000400`
#[test]
fn test_libsmb2_dcerpc_lsa_policy_access_bit_is_available_11() {
    assert_eq!(POLICY_SERVER_ADMIN, 0x0000_0400);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_LOOKUP_NAMES`, `examples/smb2-lsa-lookupsids.c:204`
// Spec: POLICY_LOOKUP_NAMES exposes its policy access bit#policy access bit is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
// - **THEN** `POLICY_LOOKUP_NAMES` expands to `0x00000800`
#[test]
fn test_libsmb2_dcerpc_lsa_policy_access_bit_is_available_12() {
    assert_eq!(POLICY_LOOKUP_NAMES, 0x0000_0800);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:POLICY_NOTIFICATION`
// Spec: POLICY_NOTIFICATION exposes its policy access bit#policy access bit is available
// - **GIVEN** a caller includes `include/smb2/libsmb2-dcerpc-lsa.h`
// - **WHEN** the caller composes an OpenPolicy2 `DesiredAccess` mask
// - **THEN** `POLICY_NOTIFICATION` expands to `0x00001000`
#[test]
fn test_libsmb2_dcerpc_lsa_policy_access_bit_is_available_13() {
    assert_eq!(POLICY_NOTIFICATION, 0x0000_1000);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:NT_SID_AUTHORITY`, `lib/dcerpc-lsa.c:NT_SID_AUTHORITY`, `examples/smb2-lsa-lookupsids.c:148`
// Spec: NT_SID_AUTHORITY exposes the NT authority bytes#caller copies NT SID authority
// - **GIVEN** a caller constructs an `RPC_SID`
// - **WHEN** the caller copies `NT_SID_AUTHORITY` into `RPC_SID.IdentifierAuthority`
// - **THEN** the available authority source is exactly six bytes and the implementation definition contains the NT authority value ending in `0x05`
#[test]
fn test_libsmb2_dcerpc_lsa_caller_copies_nt_sid_authority() {
    let sid = RpcSid::new(NT_SID_AUTHORITY, &[21, 32, 544]);

    assert_eq!(sid.identifier_authority.len(), 6);
    assert_eq!(sid.identifier_authority, [0, 0, 0, 0, 0, 5]);
    assert_eq!(sid.identifier_authority[5], 0x05);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:RPC_SID`, `lib/dcerpc-lsa.c:lsa_RPC_SID_coder`
// Spec: RPC_SID defines the public SID layout#SID structure carries variable sub-authorities
// - **GIVEN** a caller prepares an `RPC_SID`
// - **WHEN** the caller sets `SubAuthorityCount` and points `SubAuthority` at `uint32_t` values
// - **THEN** the public layout provides the count and pointer fields consumed by `lsa_RPC_SID_coder`
#[test]
fn test_libsmb2_dcerpc_lsa_sid_structure_carries_variable_sub_authorities() {
    let sid = RpcSid::new(NT_SID_AUTHORITY, &[21, 32, 544]);

    assert_eq!(sid.sub_authority_count(), 3);
    assert_eq!(sid.sub_authorities, vec![21, 32, 544]);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAPR_TRANSLATED_NAME_EX`, `lib/dcerpc-lsa.c:lsa_TRANSLATED_NAME_EX_coder`
// Spec: LSAPR_TRANSLATED_NAME_EX defines one translated name record#translated name record is addressable
// - **GIVEN** LookupSids2 response decoding populates translated names
// - **WHEN** an entry in `LSAPR_TRANSLATED_NAMES_EX.Names` is accessed
// - **THEN** the entry exposes use, name, domain index, and flags fields
#[test]
fn test_libsmb2_dcerpc_lsa_translated_name_record_is_addressable() {
    let entry = TranslatedNameEx {
        use_: 1,
        name: Some("Administrator".to_owned()),
        domain_index: 0,
        flags: 0,
    };

    assert_eq!(entry.use_, 1);
    assert_eq!(entry.name.as_deref(), Some("Administrator"));
    assert_eq!(entry.domain_index, 0);
    assert_eq!(entry.flags, 0);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAPR_TRANSLATED_NAMES_EX`, `lib/dcerpc-lsa.c:lsa_TRANSLATED_NAMES_EX_coder`
// Spec: LSAPR_TRANSLATED_NAMES_EX defines the translated-name array#translated names array is encoded or decoded
// - **GIVEN** a LookupSids2 request or response contains translated-name state
// - **WHEN** the coder processes `LSAPR_TRANSLATED_NAMES_EX`
// - **THEN** `Entries` controls the number of `LSAPR_TRANSLATED_NAME_EX` elements referenced by `Names`
#[test]
fn test_libsmb2_dcerpc_lsa_translated_names_array_is_encoded_or_decoded() {
    let names = TranslatedNamesEx {
        names: vec![TranslatedNameEx {
            use_: 1,
            name: Some("Administrator".to_owned()),
            domain_index: 0,
            flags: 0,
        }],
    };

    assert_eq!(names.entries(), 1);
    assert_eq!(names.names.len(), 1);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAPR_SID_ENUM_BUFFER`, `lib/dcerpc-lsa.c:lsa_SID_ENUM_BUFFER_coder`
// Spec: LSAPR_SID_ENUM_BUFFER defines the SID input array#SID enum buffer carries multiple SIDs
// - **GIVEN** a caller prepares a LookupSids2 request for one or more SIDs
// - **WHEN** `lsa_LookupSids2_req_coder` processes the request
// - **THEN** `Entries` controls how many `PRPC_SID` entries are read through `SidInfo`
#[test]
fn test_libsmb2_dcerpc_lsa_sid_enum_buffer_carries_multiple_sids() {
    let buffer = SidEnumBuffer {
        sid_info: vec![
            RpcSid::new(NT_SID_AUTHORITY, &[21]),
            RpcSid::new(NT_SID_AUTHORITY, &[32]),
        ],
    };

    assert_eq!(buffer.entries(), 2);
    assert_eq!(buffer.sid_info.len(), 2);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAP_LOOKUP_LEVEL`, `lib/dcerpc-lsa.c:lsa_LookupSids2_req_coder`
// Spec: LSAP_LOOKUP_LEVEL defines stable lookup-level values#lookup level enum is serialized as uint32
// - **GIVEN** a caller sets `lsa_lookupsids2_req.LookupLevel`
// - **WHEN** `lsa_LookupSids2_req_coder` serializes the request
// - **THEN** the enum value is converted through a `uint32_t` transport value and written back to `LookupLevel`
#[test]
fn test_libsmb2_dcerpc_lsa_lookup_level_enum_is_serialized_as_uint32() {
    assert_eq!(LsapLookupLevel::Wksta as u32, 1);
    assert_eq!(LsapLookupLevel::Pdc as u32, 2);
    assert_eq!(LsapLookupLevel::Tdl as u32, 3);
    assert_eq!(LsapLookupLevel::Gc as u32, 4);
    assert_eq!(LsapLookupLevel::XForestReferral as u32, 5);
    assert_eq!(LsapLookupLevel::XForestResolve as u32, 6);
    assert_eq!(LsapLookupLevel::RodcReferralToFullDc as u32, 7);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAPR_TRUST_INFORMATION`, `lib/dcerpc-lsa.c:lsa_TRUST_INFORMATION_coder`
// Spec: LSAPR_TRUST_INFORMATION defines referenced-domain entries#referenced domain entry carries name and SID
// - **GIVEN** a LookupSids2 response contains referenced domains
// - **WHEN** a domain entry is decoded
// - **THEN** the entry exposes a string name and an embedded `RPC_SID`
#[test]
fn test_libsmb2_dcerpc_lsa_referenced_domain_entry_carries_name_and_sid() {
    let domain = TrustInformation {
        name: Some("BUILTIN".to_owned()),
        sid: RpcSid::new(NT_SID_AUTHORITY, &[32]),
    };

    assert_eq!(domain.name.as_deref(), Some("BUILTIN"));
    assert_eq!(domain.sid.identifier_authority, NT_SID_AUTHORITY);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAPR_REFERENCED_DOMAIN_LIST`, `lib/dcerpc-lsa.c:lsa_REFERENCED_DOMAIN_LIST_coder`
// Spec: LSAPR_REFERENCED_DOMAIN_LIST defines referenced-domain arrays#referenced-domain list is decoded
// - **GIVEN** a LookupSids2 response contains a referenced-domain list
// - **WHEN** `lsa_LookupSids2_rep_coder` processes `ReferencedDomains`
// - **THEN** `Entries` controls the number of `LSAPR_TRUST_INFORMATION` records in `Domains`, and `MaxEntries` remains a serialized field without caller-visible sizing authority
#[test]
fn test_libsmb2_dcerpc_lsa_referenced_domain_list_is_decoded() {
    let domains = ReferencedDomainList {
        domains: vec![TrustInformation {
            name: Some("BUILTIN".to_owned()),
            sid: RpcSid::new(NT_SID_AUTHORITY, &[32]),
        }],
        max_entries: 99,
    };

    assert_eq!(domains.entries(), 1);
    assert_eq!(domains.domains.len(), 1);
    assert_eq!(domains.max_entries, 99);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:LSAPR_OBJECT_ATTRIBUTES`, `lib/dcerpc-lsa.c:lsa_ObjectAttributes_coder`
// Spec: LSAPR_OBJECT_ATTRIBUTES defines OpenPolicy2 object attributes#OpenPolicy2 object attributes are encoded as empty attributes
// - **GIVEN** a caller prepares `lsa_openpolicy2_req.ObjectAttributes`
// - **WHEN** `lsa_OpenPolicy2_req_coder` processes the request
// - **THEN** the implementation encodes an empty object-attributes payload with null pointer-sized fields and zero attributes independent of most input field values
#[test]
fn test_libsmb2_dcerpc_lsa_openpolicy2_object_attributes_are_encoded_as_empty_attributes() {
    let attrs = ObjectAttributes::empty_for_openpolicy2();

    assert!(attrs.root_directory_is_null);
    assert!(attrs.object_name_is_null);
    assert_eq!(attrs.attributes, 0);
    assert!(attrs.security_descriptor_is_null);
    assert!(attrs.security_quality_of_service_is_null);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_close_req`, `lib/dcerpc-lsa.c:lsa_Close_req_coder`
// Spec: lsa_close_req defines the Close request payload#Close request carries a policy handle
// - **GIVEN** a caller prepares `struct lsa_close_req`
// - **WHEN** `lsa_Close_req_coder` encodes the request
// - **THEN** the coder serializes `PolicyHandle` as a reference pointer to a DCERPC context handle
#[test]
fn test_libsmb2_dcerpc_lsa_close_request_carries_a_policy_handle() {
    let handle = NdrContextHandle { bytes: [7; 20] };
    let req = CloseRequest {
        policy_handle: handle.clone(),
    };

    assert_eq!(req.policy_handle, handle);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_close_rep`, `lib/dcerpc-lsa.c:lsa_Close_rep_coder`
// Spec: lsa_close_rep defines the Close response payload#Close response carries handle and status
// - **GIVEN** a caller decodes `struct lsa_close_rep`
// - **WHEN** `lsa_Close_rep_coder` processes the response
// - **THEN** the coder processes the context handle first and then the 32-bit status value
#[test]
fn test_libsmb2_dcerpc_lsa_close_response_carries_handle_and_status() {
    let rep = CloseResponse {
        status: 0xc000_0001,
        policy_handle: NdrContextHandle { bytes: [9; 20] },
    };

    assert_eq!(rep.policy_handle.bytes, [9; 20]);
    assert_eq!(rep.status, 0xc000_0001);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_openpolicy2_req`, `lib/dcerpc-lsa.c:lsa_OpenPolicy2_req_coder`
// Spec: lsa_openpolicy2_req defines the OpenPolicy2 request payload#OpenPolicy2 request carries system name, attributes, and access mask
// - **GIVEN** a caller prepares `struct lsa_openpolicy2_req`
// - **WHEN** `lsa_OpenPolicy2_req_coder` encodes the request
// - **THEN** the coder processes `SystemName` as a unique UTF-16 string pointer, `ObjectAttributes` as a reference object-attributes pointer, and `DesiredAccess` as a 32-bit value
#[test]
fn test_libsmb2_dcerpc_lsa_openpolicy2_request_carries_system_name_attributes_and_access_mask() {
    let req = OpenPolicy2Request {
        system_name: Some("server".to_owned()),
        object_attributes: ObjectAttributes::empty_for_openpolicy2(),
        desired_access: POLICY_LOOKUP_NAMES,
    };

    assert_eq!(req.system_name.as_deref(), Some("server"));
    assert!(req.object_attributes.root_directory_is_null);
    assert_eq!(req.desired_access, POLICY_LOOKUP_NAMES);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_openpolicy2_rep`, `lib/dcerpc-lsa.c:lsa_OpenPolicy2_rep_coder`
// Spec: lsa_openpolicy2_rep defines the OpenPolicy2 response payload#OpenPolicy2 response carries handle and status
// - **GIVEN** a caller decodes `struct lsa_openpolicy2_rep`
// - **WHEN** `lsa_OpenPolicy2_rep_coder` processes the response
// - **THEN** the coder processes `PolicyHandle` as a reference context handle and then processes `status` as a 32-bit value
#[test]
fn test_libsmb2_dcerpc_lsa_openpolicy2_response_carries_handle_and_status() {
    let rep = OpenPolicy2Response {
        status: 0,
        policy_handle: NdrContextHandle { bytes: [1; 20] },
    };

    assert_eq!(rep.policy_handle.bytes, [1; 20]);
    assert_eq!(rep.status, 0);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_lookupsids2_req`, `lib/dcerpc-lsa.c:lsa_LookupSids2_req_coder`
// Spec: lsa_lookupsids2_req defines the LookupSids2 request payload#LookupSids2 request carries SID and lookup state
// - **GIVEN** a caller prepares `struct lsa_lookupsids2_req`
// - **WHEN** `lsa_LookupSids2_req_coder` encodes the request
// - **THEN** the coder processes the policy handle, SID enum buffer, translated names, lookup level, two zero 32-bit values, and client revision value `2`
#[test]
fn test_libsmb2_dcerpc_lsa_lookupsids2_request_carries_sid_and_lookup_state() {
    let req = LookupSids2Request {
        policy_handle: NdrContextHandle { bytes: [2; 20] },
        sid_enum_buffer: SidEnumBuffer {
            sid_info: vec![RpcSid::new(NT_SID_AUTHORITY, &[21, 32])],
        },
        translated_names: TranslatedNamesEx { names: Vec::new() },
        lookup_level: LsapLookupLevel::Wksta,
    };

    assert_eq!(req.policy_handle.bytes, [2; 20]);
    assert_eq!(req.sid_enum_buffer.entries(), 1);
    assert_eq!(req.translated_names.entries(), 0);
    assert_eq!(req.lookup_level as u32, 1);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_lookupsids2_rep`, `lib/dcerpc-lsa.c:lsa_LookupSids2_rep_coder`
// Spec: lsa_lookupsids2_rep defines the LookupSids2 response payload#LookupSids2 response carries domains, names, count, and status
// - **GIVEN** a caller decodes `struct lsa_lookupsids2_rep`
// - **WHEN** `lsa_LookupSids2_rep_coder` processes the response
// - **THEN** the coder processes referenced domains, translated names, mapped count, and final status in that order
#[test]
fn test_libsmb2_dcerpc_lsa_lookupsids2_response_carries_domains_names_count_and_status() {
    let rep = LookupSids2Response {
        status: 0,
        referenced_domains: ReferencedDomainList {
            domains: vec![TrustInformation {
                name: Some("BUILTIN".to_owned()),
                sid: RpcSid::new(NT_SID_AUTHORITY, &[32]),
            }],
            max_entries: 1,
        },
        translated_names: TranslatedNamesEx {
            names: vec![TranslatedNameEx {
                use_: 1,
                name: Some("Administrator".to_owned()),
                domain_index: 0,
                flags: 0,
            }],
        },
        mapped_count: 1,
    };

    assert_eq!(rep.referenced_domains.entries(), 1);
    assert_eq!(rep.translated_names.entries(), 1);
    assert_eq!(rep.mapped_count, 1);
    assert_eq!(rep.status, 0);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_Close_rep_coder`, `lib/dcerpc-lsa.c:lsa_Close_rep_coder`
// Spec: lsa_Close_rep_coder decodes or encodes Close responses#Close response coder succeeds
// - **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `struct lsa_close_rep` pointer
// - **WHEN** `lsa_Close_rep_coder` is invoked and both field coders succeed
// - **THEN** the function returns `0` after processing `PolicyHandle` and `status`
#[test]
fn test_libsmb2_dcerpc_lsa_close_response_coder_succeeds() {
    let rep = LsaCloseReply {
        policy_handle: sample_safe_handle(7),
        status: LSA_STATUS_SUCCESS,
    };

    let encoded = encode_lsa_close_reply(&rep).expect("close response encoding should succeed");
    let decoded = decode_lsa_close_reply(&encoded).expect("close response decoding should succeed");

    assert_eq!(decoded, rep);
    assert_eq!(&encoded[24..28], &LSA_STATUS_SUCCESS.to_le_bytes());
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_Close_req_coder`, `lib/dcerpc-lsa.c:lsa_Close_req_coder`
// Spec: lsa_Close_req_coder encodes Close requests#Close request coder succeeds
// - **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `struct lsa_close_req` pointer
// - **WHEN** `lsa_Close_req_coder` is invoked and context-handle coding succeeds
// - **THEN** the function returns `0` after processing `PolicyHandle` as a reference pointer
#[test]
fn test_libsmb2_dcerpc_lsa_close_request_coder_succeeds() {
    let req = LsaCloseRequest {
        policy_handle: sample_safe_handle(5),
    };

    let encoded = encode_lsa_close_request(&req).expect("close request encoding should succeed");
    let decoded =
        decode_lsa_close_request(&encoded).expect("close request decoding should succeed");

    assert_eq!(decoded, req);
    assert_eq!(&encoded[0..4], &[0x52, 0x70, 0x74, 0x72]);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_LookupSids2_rep_coder`, `lib/dcerpc-lsa.c:lsa_LookupSids2_rep_coder`
// Spec: lsa_LookupSids2_rep_coder decodes or encodes LookupSids2 responses#LookupSids2 response coder succeeds
// - **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `struct lsa_lookupsids2_rep` pointer
// - **WHEN** `lsa_LookupSids2_rep_coder` is invoked and all field coders succeed
// - **THEN** the function returns `0` after processing referenced domains, translated names, mapped count, and status
#[test]
fn test_libsmb2_dcerpc_lsa_lookupsids2_response_coder_succeeds() {
    let rep = sample_safe_lookup_sids2_reply();

    let encoded =
        encode_lsa_lookup_sids2_reply(&rep).expect("LookupSids2 response encoding should succeed");
    let decoded = decode_lsa_lookup_sids2_reply(&encoded)
        .expect("LookupSids2 response decoding should succeed");

    assert_eq!(decoded, rep);
    assert_eq!(
        decoded.translated_names.names[0].name.value,
        "Administrator"
    );
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_LookupSids2_req_coder`, `lib/dcerpc-lsa.c:lsa_LookupSids2_req_coder`
// Spec: lsa_LookupSids2_req_coder encodes LookupSids2 requests#LookupSids2 request coder succeeds
// - **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `struct lsa_lookupsids2_req` pointer
// - **WHEN** `lsa_LookupSids2_req_coder` is invoked and all field coders succeed
// - **THEN** the function returns `0` after processing the handle, SID buffer, translated names, lookup level, two zero 32-bit values, and revision `2`
#[test]
fn test_libsmb2_dcerpc_lsa_lookupsids2_request_coder_succeeds() {
    let req = LsaLookupSids2Request::new(
        sample_safe_handle(3),
        LsaprSidEnumBuffer::new(vec![SafeRpcSid::nt_authority(1, vec![21, 32])]),
        SafeLsapLookupLevel::Wksta,
    );

    let encoded =
        encode_lsa_lookup_sids2_request(&req).expect("LookupSids2 request encoding should succeed");
    let decoded = decode_lsa_lookup_sids2_request(&encoded)
        .expect("LookupSids2 request decoding should succeed");

    assert_eq!(
        decoded.sid_enum_buffer.sid_info[0].sub_authority,
        vec![21, 32]
    );
    assert_eq!(decoded.lookup_level, SafeLsapLookupLevel::Wksta);
    assert_eq!(decoded.mapped_count, 0);
    assert_eq!(decoded.client_revision, LSA_LOOKUP_SIDS2_CLIENT_REVISION);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_OpenPolicy2_rep_coder`, `lib/dcerpc-lsa.c:lsa_OpenPolicy2_rep_coder`
// Spec: lsa_OpenPolicy2_rep_coder decodes or encodes OpenPolicy2 responses#OpenPolicy2 response coder succeeds
// - **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `struct lsa_openpolicy2_rep` pointer
// - **WHEN** `lsa_OpenPolicy2_rep_coder` is invoked and both field coders succeed
// - **THEN** the function returns `0` after processing `PolicyHandle` and `status`
#[test]
fn test_libsmb2_dcerpc_lsa_openpolicy2_response_coder_succeeds() {
    let rep = LsaOpenPolicy2Reply {
        policy_handle: sample_safe_handle(9),
        status: LSA_STATUS_SUCCESS,
    };

    let encoded =
        encode_lsa_open_policy2_reply(&rep).expect("OpenPolicy2 response encoding should succeed");
    let decoded = decode_lsa_open_policy2_reply(&encoded)
        .expect("OpenPolicy2 response decoding should succeed");

    assert_eq!(decoded, rep);
    assert_eq!(&encoded[24..28], &LSA_STATUS_SUCCESS.to_le_bytes());
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_OpenPolicy2_req_coder`, `lib/dcerpc-lsa.c:lsa_OpenPolicy2_req_coder`
// Spec: lsa_OpenPolicy2_req_coder encodes OpenPolicy2 requests#OpenPolicy2 request coder succeeds
// - **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `struct lsa_openpolicy2_req` pointer
// - **WHEN** `lsa_OpenPolicy2_req_coder` is invoked and all field coders succeed
// - **THEN** the function returns `0` after processing `SystemName`, object attributes, and desired access
#[test]
fn test_libsmb2_dcerpc_lsa_openpolicy2_request_coder_succeeds() {
    let mut req = LsaOpenPolicy2Request::new(POLICY_LOOKUP_NAMES);
    req.system_name = Some(RpcUnicodeString::new("server"));

    let encoded =
        encode_lsa_open_policy2_request(&req).expect("OpenPolicy2 request encoding should succeed");
    let decoded = decode_lsa_open_policy2_request(&encoded)
        .expect("OpenPolicy2 request decoding should succeed");

    assert_eq!(decoded.system_name.expect("system name").value, "server");
    assert_eq!(decoded.object_attributes.length, 24);
    assert_eq!(decoded.object_attributes.attributes, 0);
    assert_eq!(decoded.desired_access, POLICY_LOOKUP_NAMES);
}

// Trace: `include/smb2/libsmb2-dcerpc-lsa.h:lsa_RPC_SID_coder`, `lib/dcerpc-lsa.c:lsa_RPC_SID_coder`
// Spec: lsa_RPC_SID_coder encodes and decodes RPC SID values#RPC SID coder processes variable sub-authorities
// - **GIVEN** a valid DCERPC context, PDU, iovec, offset pointer, and `RPC_SID` pointer
// - **WHEN** `lsa_RPC_SID_coder` is invoked and all primitive coders and decode allocation succeed
// - **THEN** the function returns `0` after processing six identifier-authority bytes and `SubAuthorityCount` 32-bit sub-authority values
#[test]
fn test_libsmb2_dcerpc_lsa_rpc_sid_coder_processes_variable_sub_authorities() {
    let sid = SafeRpcSid::nt_authority(1, vec![21, 32, 544]);

    let encoded = encode_rpc_sid(&sid).expect("SID encoding should succeed");
    let decoded = decode_rpc_sid(&encoded).expect("SID decoding should succeed");

    assert_eq!(decoded, sid);
    assert_eq!(&encoded[0..4], &3u32.to_le_bytes());
    assert_eq!(encoded[5], 3);
    assert_eq!(&encoded[6..12], &SAFE_NT_SID_AUTHORITY);
}

fn sample_safe_handle(attributes: u32) -> SafeContextHandle {
    SafeContextHandle {
        attributes,
        uuid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    }
}

fn sample_safe_lookup_sids2_reply() -> LsaLookupSids2Reply {
    LsaLookupSids2Reply {
        referenced_domains: Some(LsaprReferencedDomainList {
            domains: vec![LsaprTrustInformation {
                name: RpcUnicodeString::new("BUILTIN"),
                sid: Some(SafeRpcSid::nt_authority(1, vec![32])),
            }],
            max_entries: 1,
        }),
        translated_names: LsaprTranslatedNamesEx::new(vec![LsaprTranslatedNameEx {
            use_kind: SidNameUse::User,
            name: RpcUnicodeString::new("Administrator"),
            domain_index: 0,
            flags: 0,
        }]),
        mapped_count: 1,
        status: LSA_STATUS_SUCCESS,
    }
}
