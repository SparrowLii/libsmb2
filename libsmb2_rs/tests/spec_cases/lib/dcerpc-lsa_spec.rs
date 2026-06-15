use libsmb2_rs::lib::dcerpc::DceRpcError;
use libsmb2_rs::lib::dcerpc_lsa::{
    decode_lsa_close_reply, decode_lsa_close_request, decode_lsa_lookup_sids2_reply,
    decode_lsa_lookup_sids2_request, decode_lsa_open_policy2_reply,
    decode_lsa_open_policy2_request, decode_rpc_sid, decode_rpc_unicode_string,
    encode_lsa_close_reply, encode_lsa_close_request, encode_lsa_lookup_sids2_reply,
    encode_lsa_lookup_sids2_request, encode_lsa_open_policy2_reply,
    encode_lsa_open_policy2_request, encode_rpc_sid, encode_rpc_unicode_string, ContextHandle,
    LsaCloseReply, LsaCloseRequest, LsaLookupSids2Reply, LsaLookupSids2Request,
    LsaOpenPolicy2Reply, LsaOpenPolicy2Request, LsapLookupLevel, LsaprReferencedDomainList,
    LsaprSidEnumBuffer, LsaprTranslatedNameEx, LsaprTranslatedNamesEx, LsaprTrustInformation,
    RpcSid, RpcUnicodeString, SidNameUse, LSA_LOOKUP_SIDS2_CLIENT_REVISION,
    LSA_LOOKUP_SIDS2_LOOKUP_OPTIONS, LSA_STATUS_SUCCESS, NT_SID_AUTHORITY as SAFE_NT_SID_AUTHORITY,
};
use libsmb2_rs::include::smb2::dcerpc_coder::LSA_INTERFACE;
use libsmb2_rs::include::smb2::dcerpc_coder_lsa::{LSA_UUID_PARTS, NT_SID_AUTHORITY};

// Trace: `lib/dcerpc-lsa.c:LSA_UUID`, `lib/dcerpc-lsa.c:lsa_interface`
// Spec: LSA_UUID defines the LSA transfer syntax UUID#LSA UUID initializes syntax identifier
// - **GIVEN** the LSA DCERPC implementation is compiled
// - **WHEN** `lsa_interface` is initialized
// - **THEN** the syntax identifier uses the byte sequence from `LSA_UUID`
#[test]
fn test_dcerpc_lsa_lsa_uuid_initializes_syntax_identifier() {
    assert_eq!(LSA_UUID_PARTS.0, 0x1234_5778);
    assert_eq!(LSA_UUID_PARTS.1, 0x1234);
    assert_eq!(LSA_UUID_PARTS.2, 0xabcd);
    assert_eq!(
        LSA_UUID_PARTS.3,
        [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab]
    );
    assert_eq!(LSA_INTERFACE.uuid.v1, LSA_UUID_PARTS.0);
    assert_eq!(LSA_INTERFACE.uuid.v2, LSA_UUID_PARTS.1);
    assert_eq!(LSA_INTERFACE.uuid.v3, LSA_UUID_PARTS.2);
    assert_eq!(LSA_INTERFACE.uuid.v4, LSA_UUID_PARTS.3);
}

// Trace: `lib/dcerpc-lsa.c:lsa_interface`, `examples/smb2-lsa-lookupsids.c:261`
// Spec: lsa_interface exposes the LSA syntax identifier#caller binds to LSA interface
// - **GIVEN** a caller needs to connect a DCERPC context to the LSA endpoint
// - **WHEN** the caller passes `lsa_interface` to the DCERPC connect path
// - **THEN** the object supplies the LSA UUID with both version fields set to zero
#[test]
fn test_dcerpc_lsa_caller_binds_to_lsa_interface() {
    assert_eq!(LSA_INTERFACE.uuid.v1, LSA_UUID_PARTS.0);
    assert_eq!(LSA_INTERFACE.uuid.v2, LSA_UUID_PARTS.1);
    assert_eq!(LSA_INTERFACE.uuid.v3, LSA_UUID_PARTS.2);
    assert_eq!(LSA_INTERFACE.uuid.v4, LSA_UUID_PARTS.3);
    assert_eq!(LSA_INTERFACE.vers, 0);
    assert_eq!(LSA_INTERFACE.vers_minor, 0);
}

// Trace: `lib/dcerpc-lsa.c:NT_SID_AUTHORITY`, `include/smb2/libsmb2-dcerpc-lsa.h:NT_SID_AUTHORITY`, `examples/smb2-lsa-lookupsids.c:148`
// Spec: NT_SID_AUTHORITY defines NT SID authority bytes#caller constructs NT authority SID
// - **GIVEN** a caller prepares an `RPC_SID.IdentifierAuthority` buffer
// - **WHEN** the caller copies `NT_SID_AUTHORITY`
// - **THEN** the available byte sequence is exactly six bytes ending with authority byte `0x05`
#[test]
fn test_dcerpc_lsa_caller_constructs_nt_authority_sid() {
    assert_eq!(NT_SID_AUTHORITY.len(), 6);
    assert_eq!(NT_SID_AUTHORITY, [0, 0, 0, 0, 0, 5]);
    assert_eq!(NT_SID_AUTHORITY[5], 0x05);
}

// Trace: `lib/dcerpc-lsa.c:lsa_RPC_SID_coder`
// Spec: lsa_RPC_SID_coder encodes and decodes RPC SID values#RPC SID coder succeeds
// - **GIVEN** a valid `RPC_SID`, DCERPC context, PDU, iovec, and offset pointer
// - **WHEN** `lsa_RPC_SID_coder` runs and all primitive coders plus decode allocation succeed
// - **THEN** the function returns `0` after processing the count, fixed authority bytes, and `SubAuthorityCount` sub-authority values
#[test]
fn test_dcerpc_lsa_rpc_sid_coder_succeeds() {
    let sid = RpcSid::nt_authority(1, vec![21, 32, 544]);

    let encoded = encode_rpc_sid(&sid).expect("SID encoding should succeed");
    let decoded = decode_rpc_sid(&encoded).expect("SID decoding should succeed");

    assert_eq!(decoded, sid);
    assert_eq!(&encoded[0..4], &3u32.to_le_bytes());
    assert_eq!(encoded[4], 1);
    assert_eq!(encoded[5], 3);
    assert_eq!(&encoded[6..12], &SAFE_NT_SID_AUTHORITY);
    assert_eq!(&encoded[12..16], &21u32.to_le_bytes());
}

// Trace: `lib/dcerpc-lsa.c:lsa_RPC_SID_coder`
// Spec: lsa_RPC_SID_coder encodes and decodes RPC SID values#RPC SID coder fails on primitive or allocation error
// - **GIVEN** `lsa_RPC_SID_coder` is processing an `RPC_SID`
// - **WHEN** any nested coder returns an error or decode allocation for `SubAuthority` returns `NULL`
// - **THEN** the function returns `-1`
#[test]
fn test_dcerpc_lsa_rpc_sid_coder_fails_on_primitive_or_allocation_error() {
    let err = decode_rpc_sid(&[3, 0, 0, 0, 1, 3, 0, 0]).expect_err("truncated SID must fail");

    assert!(matches!(err, DceRpcError::BufferTooSmall { .. }));
}

// Trace: `lib/dcerpc-lsa.c:lsa_RPC_UNICODE_STRING_coder`
// Spec: lsa_RPC_UNICODE_STRING_coder encodes and decodes RPC unicode strings#unicode string coder encodes string length
// - **GIVEN** `dcerpc_pdu_direction(pdu)` is `DCERPC_ENCODE` and `ptr` addresses a `char *`
// - **WHEN** `lsa_RPC_UNICODE_STRING_coder` processes the value
// - **THEN** `Length` is derived from `strlen(*(char **)ptr) * 2`, `MaximumLength` is derived from that length, and the UTF-16 buffer is coded as a unique pointer
#[test]
fn test_dcerpc_lsa_unicode_string_coder_encodes_string_length() {
    let value = RpcUnicodeString::new("AB");

    let encoded =
        encode_rpc_unicode_string(&value).expect("unicode string encoding should succeed");
    let decoded =
        decode_rpc_unicode_string(&encoded).expect("unicode string decoding should succeed");

    assert_eq!(decoded.value, "AB");
    assert_eq!(&encoded[0..2], &4u16.to_le_bytes());
    assert_eq!(&encoded[2..4], &4u16.to_le_bytes());
    assert_eq!(&encoded[4..8], &[0x55, 0x70, 0x74, 0x72]);
}

// Trace: `lib/dcerpc-lsa.c:lsa_RPC_UNICODE_STRING_coder`
// Spec: lsa_RPC_UNICODE_STRING_coder encodes and decodes RPC unicode strings#unicode string coder fails on nested coder error
// - **GIVEN** `lsa_RPC_UNICODE_STRING_coder` is processing a string value
// - **WHEN** a 16-bit field coder or `dcerpc_ptr_coder` fails
// - **THEN** the function returns `-1`
#[test]
fn test_dcerpc_lsa_unicode_string_coder_fails_on_nested_coder_error() {
    let err = decode_rpc_unicode_string(&[4, 0, 4, 0, 0x55, 0x70, 0x74, 0x72, 2, 0, 0, 0])
        .expect_err("truncated nested UTF-16 payload must fail");

    assert!(matches!(err, DceRpcError::BufferTooSmall { .. }));
}

// Trace: `lib/dcerpc-lsa.c:lsa_Close_req_coder`
// Spec: lsa_Close_req_coder encodes Close requests#Close request coder processes policy handle
// - **GIVEN** a valid `struct lsa_close_req` pointer
// - **WHEN** `lsa_Close_req_coder` is invoked
// - **THEN** the function codes `PolicyHandle` with pointer kind `PTR_REF` and returns `0` when the nested coder succeeds
#[test]
fn test_dcerpc_lsa_close_request_coder_processes_policy_handle() {
    let req = LsaCloseRequest {
        policy_handle: sample_handle(0x1122_3344),
    };

    let encoded = encode_lsa_close_request(&req).expect("close request encoding should succeed");
    let decoded =
        decode_lsa_close_request(&encoded).expect("close request decoding should succeed");

    assert_eq!(decoded, req);
    assert_eq!(&encoded[0..4], &[0x52, 0x70, 0x74, 0x72]);
    assert_eq!(&encoded[4..8], &0x1122_3344u32.to_le_bytes());
}

// Trace: `lib/dcerpc-lsa.c:lsa_Close_rep_coder`
// Spec: lsa_Close_rep_coder encodes and decodes Close responses#Close response coder processes handle and status
// - **GIVEN** a valid `struct lsa_close_rep` pointer
// - **WHEN** `lsa_Close_rep_coder` is invoked and nested coders succeed
// - **THEN** the function returns `0` after coding `PolicyHandle` and `status` in that order
#[test]
fn test_dcerpc_lsa_close_response_coder_processes_handle_and_status() {
    let rep = LsaCloseReply {
        policy_handle: sample_handle(7),
        status: LSA_STATUS_SUCCESS,
    };

    let encoded = encode_lsa_close_reply(&rep).expect("close response encoding should succeed");
    let decoded = decode_lsa_close_reply(&encoded).expect("close response decoding should succeed");

    assert_eq!(decoded, rep);
    assert_eq!(&encoded[24..28], &LSA_STATUS_SUCCESS.to_le_bytes());
}

// Trace: `lib/dcerpc-lsa.c:lsa_OpenPolicy2_req_coder`, `lib/dcerpc-lsa.c:lsa_ObjectAttributes_coder`
// Spec: lsa_OpenPolicy2_req_coder encodes OpenPolicy2 requests#OpenPolicy2 request coder processes request fields
// - **GIVEN** a valid `struct lsa_openpolicy2_req` pointer
// - **WHEN** `lsa_OpenPolicy2_req_coder` is invoked and nested coders succeed
// - **THEN** the function returns `0` after coding `SystemName`, `ObjectAttributes`, and `DesiredAccess` in order
#[test]
fn test_dcerpc_lsa_openpolicy2_request_coder_processes_request_fields() {
    let mut req = LsaOpenPolicy2Request::new(0x0000_0800);
    req.system_name = Some(RpcUnicodeString::new("server"));

    let encoded =
        encode_lsa_open_policy2_request(&req).expect("OpenPolicy2 request encoding should succeed");
    let decoded = decode_lsa_open_policy2_request(&encoded)
        .expect("OpenPolicy2 request decoding should succeed");

    assert_eq!(decoded.system_name.expect("system name").value, "server");
    assert_eq!(decoded.object_attributes.length, 24);
    assert_eq!(decoded.object_attributes.attributes, 0);
    assert_eq!(decoded.desired_access, 0x0000_0800);
}

// Trace: `lib/dcerpc-lsa.c:lsa_ObjectAttributes_coder`
// Spec: lsa_OpenPolicy2_req_coder encodes OpenPolicy2 requests#OpenPolicy2 object attributes are encoded as empty attributes
// - **GIVEN** `lsa_OpenPolicy2_req_coder` delegates to `lsa_ObjectAttributes_coder`
// - **WHEN** object attributes are serialized
// - **THEN** the helper emits length `24`, null pointer-sized fields, zero attributes, and no caller-provided object-name or security fields
#[test]
fn test_dcerpc_lsa_openpolicy2_object_attributes_are_encoded_as_empty_attributes() {
    let req = LsaOpenPolicy2Request::new(0x0000_0800);

    let encoded =
        encode_lsa_open_policy2_request(&req).expect("OpenPolicy2 request encoding should succeed");
    let tail = 8;

    assert_eq!(&encoded[tail..tail + 4], &24u32.to_le_bytes());
    assert_eq!(&encoded[tail + 4..tail + 8], &0u32.to_le_bytes());
    assert_eq!(&encoded[tail + 8..tail + 12], &0u32.to_le_bytes());
    assert_eq!(&encoded[tail + 12..tail + 16], &0u32.to_le_bytes());
}

// Trace: `lib/dcerpc-lsa.c:lsa_OpenPolicy2_rep_coder`
// Spec: lsa_OpenPolicy2_rep_coder encodes and decodes OpenPolicy2 responses#OpenPolicy2 response coder processes handle and status
// - **GIVEN** a valid `struct lsa_openpolicy2_rep` pointer
// - **WHEN** `lsa_OpenPolicy2_rep_coder` is invoked and nested coders succeed
// - **THEN** the function returns `0` after coding `PolicyHandle` and `status` in order
#[test]
fn test_dcerpc_lsa_openpolicy2_response_coder_processes_handle_and_status() {
    let rep = LsaOpenPolicy2Reply {
        policy_handle: sample_handle(9),
        status: LSA_STATUS_SUCCESS,
    };

    let encoded =
        encode_lsa_open_policy2_reply(&rep).expect("OpenPolicy2 response encoding should succeed");
    let decoded = decode_lsa_open_policy2_reply(&encoded)
        .expect("OpenPolicy2 response decoding should succeed");

    assert_eq!(decoded, rep);
    assert_eq!(&encoded[24..28], &LSA_STATUS_SUCCESS.to_le_bytes());
}

// Trace: `lib/dcerpc-lsa.c:lsa_LookupSids2_req_coder`, `lib/dcerpc-lsa.c:lsa_SID_ENUM_BUFFER_coder`, `lib/dcerpc-lsa.c:lsa_TRANSLATED_NAMES_EX_coder`
// Spec: lsa_LookupSids2_req_coder encodes LookupSids2 requests#LookupSids2 request coder processes request fields
// - **GIVEN** a valid `struct lsa_lookupsids2_req` pointer
// - **WHEN** `lsa_LookupSids2_req_coder` is invoked and nested coders succeed
// - **THEN** the function returns `0` after coding the policy handle, SID enum buffer, translated names, lookup level, two zero values, and revision value `2`
#[test]
fn test_dcerpc_lsa_lookupsids2_request_coder_processes_request_fields() {
    let mut req = LsaLookupSids2Request::new(
        sample_handle(3),
        LsaprSidEnumBuffer::new(vec![RpcSid::nt_authority(1, vec![21, 32])]),
        LsapLookupLevel::Wksta,
    );
    req.mapped_count = 99;
    req.lookup_options = 99;
    req.client_revision = 99;

    let encoded =
        encode_lsa_lookup_sids2_request(&req).expect("LookupSids2 request encoding should succeed");
    let decoded = decode_lsa_lookup_sids2_request(&encoded)
        .expect("LookupSids2 request decoding should succeed");

    assert_eq!(decoded.policy_handle, sample_handle(3));
    assert_eq!(
        decoded.sid_enum_buffer.sid_info[0].sub_authority,
        vec![21, 32]
    );
    assert_eq!(decoded.lookup_level, LsapLookupLevel::Wksta);
    assert_eq!(decoded.mapped_count, 0);
    assert_eq!(decoded.lookup_options, LSA_LOOKUP_SIDS2_LOOKUP_OPTIONS);
    assert_eq!(decoded.client_revision, LSA_LOOKUP_SIDS2_CLIENT_REVISION);
}

// Trace: `lib/dcerpc-lsa.c:lsa_LookupSids2_req_coder`
// Spec: lsa_LookupSids2_req_coder encodes LookupSids2 requests#LookupSids2 request coder fails on nested coder error
// - **GIVEN** `lsa_LookupSids2_req_coder` is processing a request
// - **WHEN** any pointer coder or 32-bit field coder fails
// - **THEN** the function returns `-1`
#[test]
fn test_dcerpc_lsa_lookupsids2_request_coder_fails_on_nested_coder_error() {
    let req = LsaLookupSids2Request::new(
        sample_handle(3),
        LsaprSidEnumBuffer::new(vec![RpcSid::nt_authority(1, vec![0; 256])]),
        LsapLookupLevel::Wksta,
    );

    let err = encode_lsa_lookup_sids2_request(&req)
        .expect_err("oversized SID sub-authority count must fail");

    assert!(matches!(err, DceRpcError::CountOutOfRange { count: 256 }));
}

// Trace: `lib/dcerpc-lsa.c:lsa_LookupSids2_rep_coder`, `lib/dcerpc-lsa.c:lsa_REFERENCED_DOMAIN_LIST_coder`, `lib/dcerpc-lsa.c:lsa_TRANSLATED_NAMES_EX_coder`
// Spec: lsa_LookupSids2_rep_coder encodes and decodes LookupSids2 responses#LookupSids2 response coder processes response fields
// - **GIVEN** a valid `struct lsa_lookupsids2_rep` pointer
// - **WHEN** `lsa_LookupSids2_rep_coder` is invoked and nested coders succeed
// - **THEN** the function returns `0` after coding referenced domains, translated names, mapped count, and status in order
#[test]
fn test_dcerpc_lsa_lookupsids2_response_coder_processes_response_fields() {
    let rep = sample_lookup_sids2_reply();

    let encoded =
        encode_lsa_lookup_sids2_reply(&rep).expect("LookupSids2 response encoding should succeed");
    let decoded = decode_lsa_lookup_sids2_reply(&encoded)
        .expect("LookupSids2 response decoding should succeed");

    assert_eq!(decoded, rep);
    assert_eq!(decoded.mapped_count, 1);
    assert_eq!(decoded.status, LSA_STATUS_SUCCESS);
}

// Trace: `lib/dcerpc-lsa.c:RDL_DOMAINS_array_coder`, `lib/dcerpc-lsa.c:TN_array_coder`, `lib/dcerpc-lsa.c:lsa_PRPC_SID_array_coder`
// Spec: lsa_LookupSids2_rep_coder encodes and decodes LookupSids2 responses#LookupSids2 response decode allocates nested arrays
// - **GIVEN** a LookupSids2 response is being decoded
// - **WHEN** referenced domains, translated names, or SID arrays contain nonzero counts
// - **THEN** the implementation allocates payload-owned arrays through `smb2_alloc_data` before coding each nested element
#[test]
fn test_dcerpc_lsa_lookupsids2_response_decode_allocates_nested_arrays() {
    let encoded = encode_lsa_lookup_sids2_reply(&sample_lookup_sids2_reply())
        .expect("LookupSids2 response encoding should succeed");

    let decoded = decode_lsa_lookup_sids2_reply(&encoded)
        .expect("LookupSids2 response decoding should succeed");

    let domains = decoded.referenced_domains.expect("referenced domains");
    assert_eq!(domains.domains.len(), 1);
    assert_eq!(
        domains.domains[0]
            .sid
            .as_ref()
            .expect("domain SID")
            .sub_authority,
        vec![32]
    );
    assert_eq!(decoded.translated_names.names.len(), 1);
    assert_eq!(
        decoded.translated_names.names[0].name.value,
        "Administrator"
    );
}

fn sample_handle(attributes: u32) -> ContextHandle {
    ContextHandle {
        attributes,
        uuid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    }
}

fn sample_lookup_sids2_reply() -> LsaLookupSids2Reply {
    LsaLookupSids2Reply {
        referenced_domains: Some(LsaprReferencedDomainList {
            domains: vec![LsaprTrustInformation {
                name: RpcUnicodeString::new("BUILTIN"),
                sid: Some(RpcSid::nt_authority(1, vec![32])),
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
