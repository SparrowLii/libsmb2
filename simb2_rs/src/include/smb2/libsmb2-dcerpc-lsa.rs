//! LSA DCERPC skeleton from `include/smb2/libsmb2-dcerpc-lsa.h`.

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LsapLookupLevel {
    /// Workstation lookup.
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

impl Default for LsapLookupLevel {
    fn default() -> Self {
        Self::Wksta
    }
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

/// Placeholder DCERPC PDU for LSA coder skeletons.
#[derive(Debug, Default)]
pub struct DceRpcPdu;

/// Placeholder SMB2 iovec for LSA coder skeletons.
#[derive(Debug, Default)]
pub struct Smb2Iovec;

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
}

/// Result type returned by LSA coder skeletons.
pub type LsaCoderResult = Result<(), LsaCoderError>;

/// Decoder skeleton for an LSA `Close` response.
pub fn lsa_close_rep_coder(
    _dce: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _rep: &mut LsaCloseRep,
) -> LsaCoderResult {
    Err(LsaCoderError::not_implemented())
}

/// Encoder skeleton for an LSA `Close` request.
pub fn lsa_close_req_coder(
    _dce: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _req: &LsaCloseReq,
) -> LsaCoderResult {
    Err(LsaCoderError::not_implemented())
}

/// Decoder skeleton for an LSA `LookupSids2` response.
pub fn lsa_lookup_sids2_rep_coder(
    _dce: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _rep: &mut LsaLookupSids2Rep,
) -> LsaCoderResult {
    Err(LsaCoderError::not_implemented())
}

/// Encoder skeleton for an LSA `LookupSids2` request.
pub fn lsa_lookup_sids2_req_coder(
    _dce: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _req: &LsaLookupSids2Req,
) -> LsaCoderResult {
    Err(LsaCoderError::not_implemented())
}

/// Decoder skeleton for an LSA `OpenPolicy2` response.
pub fn lsa_open_policy2_rep_coder(
    _dce: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _rep: &mut LsaOpenPolicy2Rep,
) -> LsaCoderResult {
    Err(LsaCoderError::not_implemented())
}

/// Encoder skeleton for an LSA `OpenPolicy2` request.
pub fn lsa_open_policy2_req_coder(
    _dce: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _req: &LsaOpenPolicy2Req,
) -> LsaCoderResult {
    Err(LsaCoderError::not_implemented())
}

/// Encoder/decoder skeleton for an `RPC_SID` value.
pub fn lsa_rpc_sid_coder(
    _dce: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _sid: &mut RpcSid,
) -> LsaCoderResult {
    Err(LsaCoderError::not_implemented())
}
