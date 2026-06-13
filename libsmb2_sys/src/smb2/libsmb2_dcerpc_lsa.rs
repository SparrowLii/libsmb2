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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory_is_null: bool,
    pub attributes: u32,
}

impl ObjectAttributes {
    pub fn empty_for_openpolicy2() -> Self {
        Self {
            length: 0,
            root_directory_is_null: true,
            attributes: 0,
        }
    }
}
