pub const LSA_CLOSE: u32 = 0x00;
pub const LSA_OPENPOLICY2: u32 = 0x2c;
pub const LSA_LOOKUPSIDS2: u32 = 0x39;

pub const POLICY_VIEW_LOCAL_INFORMATION: u32 = 0x0000_0001;
pub const POLICY_VIEW_AUDIT_INFORMATION: u32 = 0x0000_0002;
pub const POLICY_GET_PRIVATE_INFORMATION: u32 = 0x0000_0004;
pub const POLICY_TRUST_ADMIN: u32 = 0x0000_0008;
pub const POLICY_CREATE_ACCOUNT: u32 = 0x0000_0010;
pub const POLICY_CREATE_SECRET: u32 = 0x0000_0020;
pub const POLICY_CREATE_PRIVILEGE: u32 = 0x0000_0040;
pub const POLICY_SET_DEFAULT_QUOTA_LIMITS: u32 = 0x0000_0080;
pub const POLICY_SET_AUDIT_REQUIREMENTS: u32 = 0x0000_0100;
pub const POLICY_AUDIT_LOG_ADMIN: u32 = 0x0000_0200;
pub const POLICY_SERVER_ADMIN: u32 = 0x0000_0400;
pub const POLICY_LOOKUP_NAMES: u32 = 0x0000_0800;
pub const POLICY_NOTIFICATION: u32 = 0x0000_1000;

pub const NT_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LsapLookupLevel {
    Wksta = 1,
    Pdc = 2,
    Tdl = 3,
    Gc = 4,
    XForestReferral = 5,
    XForestResolve = 6,
    RodcReferralToFullDc = 7,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcSid {
    pub revision: u8,
    pub identifier_authority: [u8; 6],
    pub sub_authorities: Vec<u32>,
}

impl RpcSid {
    pub fn new(identifier_authority: [u8; 6], sub_authorities: &[u32]) -> Self {
        Self {
            revision: 1,
            identifier_authority,
            sub_authorities: sub_authorities.to_vec(),
        }
    }

    pub fn sub_authority_count(&self) -> u8 {
        self.sub_authorities.len().try_into().unwrap_or(u8::MAX)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslatedNameEx {
    pub use_: u32,
    pub name: Option<String>,
    pub domain_index: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslatedNamesEx {
    pub names: Vec<TranslatedNameEx>,
}

impl TranslatedNamesEx {
    pub fn entries(&self) -> u32 {
        self.names.len().try_into().unwrap_or(u32::MAX)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidEnumBuffer {
    pub sid_info: Vec<RpcSid>,
}

impl SidEnumBuffer {
    pub fn entries(&self) -> u32 {
        self.sid_info.len().try_into().unwrap_or(u32::MAX)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustInformation {
    pub name: Option<String>,
    pub sid: RpcSid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferencedDomainList {
    pub domains: Vec<TrustInformation>,
    pub max_entries: u32,
}

impl ReferencedDomainList {
    pub fn entries(&self) -> u32 {
        self.domains.len().try_into().unwrap_or(u32::MAX)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory_is_null: bool,
    pub attributes: u32,
    pub object_name_is_null: bool,
    pub security_descriptor_is_null: bool,
    pub security_quality_of_service_is_null: bool,
}

impl ObjectAttributes {
    pub fn empty_for_openpolicy2() -> Self {
        Self {
            length: 0,
            root_directory_is_null: true,
            attributes: 0,
            object_name_is_null: true,
            security_descriptor_is_null: true,
            security_quality_of_service_is_null: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdrContextHandle {
    pub bytes: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseRequest {
    pub policy_handle: NdrContextHandle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseResponse {
    pub status: u32,
    pub policy_handle: NdrContextHandle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPolicy2Request {
    pub system_name: Option<String>,
    pub object_attributes: ObjectAttributes,
    pub desired_access: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPolicy2Response {
    pub status: u32,
    pub policy_handle: NdrContextHandle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupSids2Request {
    pub policy_handle: NdrContextHandle,
    pub sid_enum_buffer: SidEnumBuffer,
    pub translated_names: TranslatedNamesEx,
    pub lookup_level: LsapLookupLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupSids2Response {
    pub status: u32,
    pub referenced_domains: ReferencedDomainList,
    pub translated_names: TranslatedNamesEx,
    pub mapped_count: u32,
}
