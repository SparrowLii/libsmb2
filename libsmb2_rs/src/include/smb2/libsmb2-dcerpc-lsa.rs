//! LSA DCERPC public surface from `include/smb2/libsmb2-dcerpc-lsa.h`.

use crate::lib::dcerpc_lsa as lib_lsa;

/// LSA `Close` operation number.
pub const LSA_CLOSE: u16 = 0x00;

/// LSA `OpenPolicy2` operation number.
pub const LSA_OPENPOLICY2: u16 = 0x2c;

/// LSA `LookupSids2` operation number.
pub const LSA_LOOKUPSIDS2: u16 = 0x39;

/// Allows viewing local policy information.
pub const POLICY_VIEW_LOCAL_INFORMATION: u32 = 0x0000_0001;

/// Allows viewing audit policy information.
pub const POLICY_VIEW_AUDIT_INFORMATION: u32 = 0x0000_0002;

/// Allows retrieving private policy information.
pub const POLICY_GET_PRIVATE_INFORMATION: u32 = 0x0000_0004;

/// Allows administering trusted domains.
pub const POLICY_TRUST_ADMIN: u32 = 0x0000_0008;

/// Allows creating accounts.
pub const POLICY_CREATE_ACCOUNT: u32 = 0x0000_0010;

/// Allows creating secrets.
pub const POLICY_CREATE_SECRET: u32 = 0x0000_0020;

/// Allows creating privileges.
pub const POLICY_CREATE_PRIVILEGE: u32 = 0x0000_0040;

/// Allows setting default quota limits.
pub const POLICY_SET_DEFAULT_QUOTA_LIMITS: u32 = 0x0000_0080;

/// Allows setting audit requirements.
pub const POLICY_SET_AUDIT_REQUIREMENTS: u32 = 0x0000_0100;

/// Allows administering the audit log.
pub const POLICY_AUDIT_LOG_ADMIN: u32 = 0x0000_0200;

/// Allows administering the policy server.
pub const POLICY_SERVER_ADMIN: u32 = 0x0000_0400;

/// Allows looking up names and SIDs.
pub const POLICY_LOOKUP_NAMES: u32 = 0x0000_0800;

/// Allows receiving policy notifications.
pub const POLICY_NOTIFICATION: u32 = 0x0000_1000;

/// NT SID identifier authority value exported by the C API.
pub const NT_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

/// LSA status value used when a staged encoder or decoder has no protocol logic yet.
pub const LSA_STATUS_NOT_IMPLEMENTED: u32 = 0xc000_0002;

/// NTSTATUS value used for malformed local coder input or truncated wire data.
pub const LSA_STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;

/// Opaque NDR context handle used by LSA policy operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NdrContextHandle {
    /// Raw context handle bytes as carried by DCERPC/NDR.
    pub bytes: [u8; 20],
}

/// Security identifier in the shape of the C `RPC_SID` structure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RpcSid {
    /// SID revision.
    pub revision: u8,
    /// Identifier authority bytes.
    pub identifier_authority: [u8; 6],
    /// SID sub-authorities.
    pub sub_authority: Vec<u32>,
}

/// Backwards-compatible public SID name used by earlier staged bindings.
pub type Sid = RpcSid;

/// Translated account name returned by `LookupSids2`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsaprTranslatedNameEx {
    /// SID name-use discriminator.
    pub use_: u32,
    /// Translated name, when present.
    pub name: Option<String>,
    /// Index into the referenced domain list.
    pub domain_index: u32,
    /// Name flags returned by the server.
    pub flags: u32,
}

/// Collection of translated names returned by LSA lookup calls.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsaprTranslatedNamesEx {
    /// Translated name entries.
    pub names: Vec<LsaprTranslatedNameEx>,
}

/// SID enumeration buffer supplied to `LookupSids2`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsaprSidEnumBuffer {
    /// SIDs to look up.
    pub sid_info: Vec<RpcSid>,
}

/// Lookup level used by LSA SID and name translation operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum LsapLookupLevel {
    /// Workstation lookup.
    #[default]
    Wksta = 1,
    /// Primary domain controller lookup.
    Pdc = 2,
    /// Trusted domain list lookup.
    Tdl = 3,
    /// Global catalog lookup.
    Gc = 4,
    /// Cross-forest referral lookup.
    XForestReferral = 5,
    /// Cross-forest resolve lookup.
    XForestResolve = 6,
    /// Read-only domain controller referral to a full domain controller.
    RodcReferralToFullDc = 7,
}

/// Trust information entry in an LSA referenced domain list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsaprTrustInformation {
    /// Referenced domain name, when present.
    pub name: Option<String>,
    /// Referenced domain SID.
    pub sid: RpcSid,
}

/// Referenced domains returned by LSA lookup calls.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsaprReferencedDomainList {
    /// Domain entries referenced by translated names.
    pub domains: Vec<LsaprTrustInformation>,
    /// Server-provided maximum entry count; consumers should ignore this value.
    pub max_entries: u32,
}

/// Object attributes supplied to `OpenPolicy2`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsaprObjectAttributes {
    /// Structure length from the wire representation.
    pub length: u32,
    /// Root directory handle bytes; `OpenPolicy2` requires this to be absent.
    pub root_directory: Option<Vec<u8>>,
    /// Opaque object name bytes retained until protocol support is implemented.
    pub object_name: Option<Vec<u8>>,
    /// Object attribute flags.
    pub attributes: u32,
    /// Opaque security descriptor bytes retained until protocol support is implemented.
    pub security_descriptor: Option<Vec<u8>>,
    /// Opaque security quality-of-service bytes retained until protocol support is implemented.
    pub security_quality_of_service: Option<Vec<u8>>,
}

/// Request body for LSA `Close`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsaCloseReq {
    /// Policy handle to close.
    pub policy_handle: NdrContextHandle,
}

/// Response body for LSA `Close`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsaCloseRep {
    /// NTSTATUS result.
    pub status: u32,
    /// Policy handle returned by the server.
    pub policy_handle: NdrContextHandle,
}

/// Request body for LSA `OpenPolicy2`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsaOpenPolicy2Req {
    /// Optional target system name.
    pub system_name: Option<String>,
    /// Object attributes for the policy object.
    pub object_attributes: LsaprObjectAttributes,
    /// Desired policy access mask.
    pub desired_access: u32,
}

/// Response body for LSA `OpenPolicy2`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsaOpenPolicy2Rep {
    /// NTSTATUS result.
    pub status: u32,
    /// Opened policy handle.
    pub policy_handle: NdrContextHandle,
}

/// Request body for LSA `LookupSids2`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsaLookupSids2Req {
    /// Policy handle used for lookup.
    pub policy_handle: NdrContextHandle,
    /// SID enumeration buffer.
    pub sid_enum_buffer: LsaprSidEnumBuffer,
    /// Client-provided translated-name buffer.
    pub translated_names: LsaprTranslatedNamesEx,
    /// Lookup level requested by the caller.
    pub lookup_level: LsapLookupLevel,
}

/// Response body for LSA `LookupSids2`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsaLookupSids2Rep {
    /// NTSTATUS result.
    pub status: u32,
    /// Referenced domain list returned by the server.
    pub referenced_domains: LsaprReferencedDomainList,
    /// Translated names returned by the server.
    pub translated_names: LsaprTranslatedNamesEx,
    /// Number of successfully mapped SIDs.
    pub mapped_count: u32,
}

/// Placeholder DCERPC context for LSA coder skeletons.
#[derive(Debug, Default)]
pub struct DceRpcContext;

/// Minimal DCERPC PDU payload carrier for LSA public coders.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DceRpcPdu {
    /// `0` decodes from `payload`; non-zero encodes into `payload`.
    pub direction: i32,
    /// Encoded or decoded LSA stub bytes.
    pub payload: Vec<u8>,
}

/// Minimal SMB2 iovec payload carrier for LSA public coders.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2Iovec {
    /// Encoded or decoded LSA stub bytes.
    pub buf: Vec<u8>,
}

/// Error returned by staged LSA coder skeletons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsaCoderError {
    /// NTSTATUS-style status associated with the failed operation.
    pub status: u32,
}

impl LsaCoderError {
    /// Creates an error indicating that protocol encoding or decoding is not implemented yet.
    pub const fn not_implemented() -> Self {
        Self {
            status: LSA_STATUS_NOT_IMPLEMENTED,
        }
    }

    /// Creates an error indicating invalid input or malformed/truncated NDR data.
    pub const fn invalid_parameter() -> Self {
        Self {
            status: LSA_STATUS_INVALID_PARAMETER,
        }
    }
}

/// Result type returned by LSA coder skeletons.
pub type LsaCoderResult = Result<(), LsaCoderError>;

/// Decoder skeleton for an LSA `Close` response.
pub fn lsa_close_rep_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    rep: &mut LsaCloseRep,
) -> LsaCoderResult {
    let decoded = lib_lsa::decode_lsa_close_reply(decode_bytes(pdu, iov, *offset))
        .map_err(map_dcerpc_error)?;
    *rep = from_lib_close_reply(decoded);
    *offset = input_len(pdu, iov);
    Ok(())
}

/// Encoder skeleton for an LSA `Close` request.
pub fn lsa_close_req_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    req: &LsaCloseReq,
) -> LsaCoderResult {
    let bytes =
        lib_lsa::encode_lsa_close_request(&to_lib_close_request(req)).map_err(map_dcerpc_error)?;
    store_bytes(pdu, iov, offset, bytes);
    Ok(())
}

/// Decoder skeleton for an LSA `LookupSids2` response.
pub fn lsa_lookup_sids2_rep_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    rep: &mut LsaLookupSids2Rep,
) -> LsaCoderResult {
    let decoded = lib_lsa::decode_lsa_lookup_sids2_reply(decode_bytes(pdu, iov, *offset))
        .map_err(map_dcerpc_error)?;
    *rep = from_lib_lookup_sids2_reply(decoded);
    *offset = input_len(pdu, iov);
    Ok(())
}

/// Encoder skeleton for an LSA `LookupSids2` request.
pub fn lsa_lookup_sids2_req_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    req: &LsaLookupSids2Req,
) -> LsaCoderResult {
    let bytes = lib_lsa::encode_lsa_lookup_sids2_request(&to_lib_lookup_sids2_request(req))
        .map_err(map_dcerpc_error)?;
    store_bytes(pdu, iov, offset, bytes);
    Ok(())
}

/// Decoder skeleton for an LSA `OpenPolicy2` response.
pub fn lsa_open_policy2_rep_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    rep: &mut LsaOpenPolicy2Rep,
) -> LsaCoderResult {
    let decoded = lib_lsa::decode_lsa_open_policy2_reply(decode_bytes(pdu, iov, *offset))
        .map_err(map_dcerpc_error)?;
    *rep = from_lib_open_policy2_reply(decoded);
    *offset = input_len(pdu, iov);
    Ok(())
}

/// Encoder skeleton for an LSA `OpenPolicy2` request.
pub fn lsa_open_policy2_req_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    req: &LsaOpenPolicy2Req,
) -> LsaCoderResult {
    let bytes = lib_lsa::encode_lsa_open_policy2_request(&to_lib_open_policy2_request(req))
        .map_err(map_dcerpc_error)?;
    store_bytes(pdu, iov, offset, bytes);
    Ok(())
}

/// Encoder/decoder skeleton for an `RPC_SID` value.
pub fn lsa_rpc_sid_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    sid: &mut RpcSid,
) -> LsaCoderResult {
    if pdu.direction == 0 {
        let decoded =
            lib_lsa::decode_rpc_sid(decode_bytes(pdu, iov, *offset)).map_err(map_dcerpc_error)?;
        *sid = from_lib_sid(decoded);
        *offset = input_len(pdu, iov);
    } else {
        let bytes = lib_lsa::encode_rpc_sid(&to_lib_sid(sid)).map_err(map_dcerpc_error)?;
        store_bytes(pdu, iov, offset, bytes);
    }
    Ok(())
}

fn decode_bytes<'a>(pdu: &'a DceRpcPdu, iov: &'a Smb2Iovec, offset: usize) -> &'a [u8] {
    let bytes = if pdu.payload.is_empty() {
        &iov.buf
    } else {
        &pdu.payload
    };
    if offset >= bytes.len() {
        &[]
    } else {
        &bytes[offset..]
    }
}

fn input_len(pdu: &DceRpcPdu, iov: &Smb2Iovec) -> usize {
    if pdu.payload.is_empty() {
        iov.buf.len()
    } else {
        pdu.payload.len()
    }
}

fn store_bytes(pdu: &mut DceRpcPdu, iov: &mut Smb2Iovec, offset: &mut usize, bytes: Vec<u8>) {
    *offset = bytes.len();
    pdu.payload = bytes.clone();
    iov.buf = bytes;
}

fn to_lib_handle(handle: &NdrContextHandle) -> lib_lsa::ContextHandle {
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&handle.bytes[4..20]);
    lib_lsa::ContextHandle {
        attributes: u32::from_le_bytes([
            handle.bytes[0],
            handle.bytes[1],
            handle.bytes[2],
            handle.bytes[3],
        ]),
        uuid,
    }
}

fn from_lib_handle(handle: lib_lsa::ContextHandle) -> NdrContextHandle {
    let mut bytes = [0u8; 20];
    bytes[0..4].copy_from_slice(&handle.attributes.to_le_bytes());
    bytes[4..20].copy_from_slice(&handle.uuid);
    NdrContextHandle { bytes }
}

fn to_lib_sid(sid: &RpcSid) -> lib_lsa::RpcSid {
    lib_lsa::RpcSid::new(
        sid.revision,
        sid.identifier_authority,
        sid.sub_authority.clone(),
    )
}

fn from_lib_sid(sid: lib_lsa::RpcSid) -> RpcSid {
    RpcSid {
        revision: sid.revision,
        identifier_authority: sid.identifier_authority,
        sub_authority: sid.sub_authority,
    }
}

fn to_lib_close_request(req: &LsaCloseReq) -> lib_lsa::LsaCloseRequest {
    lib_lsa::LsaCloseRequest {
        policy_handle: to_lib_handle(&req.policy_handle),
    }
}

fn from_lib_close_reply(rep: lib_lsa::LsaCloseReply) -> LsaCloseRep {
    LsaCloseRep {
        status: rep.status,
        policy_handle: from_lib_handle(rep.policy_handle),
    }
}

fn to_lib_open_policy2_request(req: &LsaOpenPolicy2Req) -> lib_lsa::LsaOpenPolicy2Request {
    lib_lsa::LsaOpenPolicy2Request {
        system_name: req.system_name.clone().map(lib_lsa::RpcUnicodeString::new),
        object_attributes: lib_lsa::LsaprObjectAttributes {
            length: req.object_attributes.length,
            attributes: req.object_attributes.attributes,
        },
        desired_access: req.desired_access,
    }
}

fn from_lib_open_policy2_reply(rep: lib_lsa::LsaOpenPolicy2Reply) -> LsaOpenPolicy2Rep {
    LsaOpenPolicy2Rep {
        status: rep.status,
        policy_handle: from_lib_handle(rep.policy_handle),
    }
}

fn to_lib_lookup_sids2_request(req: &LsaLookupSids2Req) -> lib_lsa::LsaLookupSids2Request {
    let mut request = lib_lsa::LsaLookupSids2Request::new(
        to_lib_handle(&req.policy_handle),
        lib_lsa::LsaprSidEnumBuffer::new(
            req.sid_enum_buffer
                .sid_info
                .iter()
                .map(to_lib_sid)
                .collect(),
        ),
        to_lib_lookup_level(req.lookup_level),
    );
    request.translated_names = to_lib_translated_names(&req.translated_names);
    request
}

fn from_lib_lookup_sids2_reply(rep: lib_lsa::LsaLookupSids2Reply) -> LsaLookupSids2Rep {
    LsaLookupSids2Rep {
        status: rep.status,
        referenced_domains: rep
            .referenced_domains
            .map(from_lib_referenced_domains)
            .map_or_else(LsaprReferencedDomainList::default, core::convert::identity),
        translated_names: from_lib_translated_names(rep.translated_names),
        mapped_count: rep.mapped_count,
    }
}

fn from_lib_referenced_domains(
    value: lib_lsa::LsaprReferencedDomainList,
) -> LsaprReferencedDomainList {
    LsaprReferencedDomainList {
        domains: value
            .domains
            .into_iter()
            .map(|domain| LsaprTrustInformation {
                name: if domain.name.value.is_empty() {
                    None
                } else {
                    Some(domain.name.value)
                },
                sid: domain
                    .sid
                    .map(from_lib_sid)
                    .map_or_else(RpcSid::default, core::convert::identity),
            })
            .collect(),
        max_entries: value.max_entries,
    }
}

fn to_lib_translated_names(value: &LsaprTranslatedNamesEx) -> lib_lsa::LsaprTranslatedNamesEx {
    lib_lsa::LsaprTranslatedNamesEx::new(
        value
            .names
            .iter()
            .map(|name| lib_lsa::LsaprTranslatedNameEx {
                use_kind: lib_lsa::SidNameUse::from_raw(name.use_),
                name: lib_lsa::RpcUnicodeString::new(name.name.clone().unwrap_or_default()),
                domain_index: name.domain_index,
                flags: name.flags,
            })
            .collect(),
    )
}

fn from_lib_translated_names(value: lib_lsa::LsaprTranslatedNamesEx) -> LsaprTranslatedNamesEx {
    LsaprTranslatedNamesEx {
        names: value
            .names
            .into_iter()
            .map(|name| LsaprTranslatedNameEx {
                use_: name.use_kind.as_raw(),
                name: if name.name.value.is_empty() {
                    None
                } else {
                    Some(name.name.value)
                },
                domain_index: name.domain_index,
                flags: name.flags,
            })
            .collect(),
    }
}

fn to_lib_lookup_level(level: LsapLookupLevel) -> lib_lsa::LsapLookupLevel {
    match level {
        LsapLookupLevel::Pdc => lib_lsa::LsapLookupLevel::Pdc,
        LsapLookupLevel::Tdl => lib_lsa::LsapLookupLevel::Tdl,
        LsapLookupLevel::Gc => lib_lsa::LsapLookupLevel::Gc,
        LsapLookupLevel::XForestReferral => lib_lsa::LsapLookupLevel::XForestReferral,
        LsapLookupLevel::XForestResolve => lib_lsa::LsapLookupLevel::XForestResolve,
        LsapLookupLevel::RodcReferralToFullDc => lib_lsa::LsapLookupLevel::RodcReferral,
        LsapLookupLevel::Wksta => lib_lsa::LsapLookupLevel::Wksta,
    }
}

fn map_dcerpc_error(error: crate::lib::dcerpc::DceRpcError) -> LsaCoderError {
    match error {
        crate::lib::dcerpc::DceRpcError::ProtocolNotImplemented(_)
        | crate::lib::dcerpc::DceRpcError::UnsupportedPduBody { .. } => {
            LsaCoderError::not_implemented()
        }
        crate::lib::dcerpc::DceRpcError::InvalidPduType { .. }
        | crate::lib::dcerpc::DceRpcError::InvalidAuthVerifier { .. }
        | crate::lib::dcerpc::DceRpcError::BufferTooSmall { .. }
        | crate::lib::dcerpc::DceRpcError::TooManyDeferredPointers { .. }
        | crate::lib::dcerpc::DceRpcError::AllocHintOutOfRange { .. }
        | crate::lib::dcerpc::DceRpcError::CountOutOfRange { .. }
        | crate::lib::dcerpc::DceRpcError::InvalidUtf16
        | crate::lib::dcerpc::DceRpcError::NullPointer => LsaCoderError::invalid_parameter(),
    }
}
