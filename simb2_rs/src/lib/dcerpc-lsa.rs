//! LSA DCERPC command helpers migrated from `lib/dcerpc-lsa.c`.
//!
//! This module intentionally models the legacy LSA request, reply, and nested
//! NDR structures without implementing the full DCERPC/NDR protocol encoder.

/// LSA interface UUID from `LSA_UUID` in the C source.
pub const LSA_UUID: Uuid = Uuid {
    time_low: 0x1234_5778,
    time_mid: 0x1234,
    time_hi_and_version: 0xabcd,
    clock_seq_and_node: [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab],
};

/// LSA DCERPC interface syntax id.
pub const LSA_INTERFACE: SyntaxId = SyntaxId {
    uuid: LSA_UUID,
    version_major: 0,
    version_minor: 0,
};

/// Identifier authority bytes used by NT SIDs.
pub const NT_SID_AUTHORITY: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x05];

/// LSA `Close` operation number.
pub const LSA_OPNUM_CLOSE: u16 = 0x00;
/// LSA `OpenPolicy2` operation number.
pub const LSA_OPNUM_OPEN_POLICY2: u16 = 0x2c;
/// LSA `LookupSids2` operation number.
pub const LSA_OPNUM_LOOKUP_SIDS2: u16 = 0x39;

/// Default client revision emitted by the legacy `LookupSids2` request coder.
pub const LSA_LOOKUP_SIDS2_CLIENT_REVISION: u32 = 2;
/// Default lookup options emitted by the legacy `LookupSids2` request coder.
pub const LSA_LOOKUP_SIDS2_LOOKUP_OPTIONS: u32 = 0;

/// Maximum count used by LSA SID and translated-name arrays in the IDL comments.
pub const LSA_MAX_ENUM_ENTRIES: u32 = 20_480;

/// Minimal UUID representation used by DCERPC syntax identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid {
    /// First 32 bits of the UUID.
    pub time_low: u32,
    /// Middle 16 bits of the UUID.
    pub time_mid: u16,
    /// Versioned high 16 bits of the UUID.
    pub time_hi_and_version: u16,
    /// Remaining clock sequence and node bytes.
    pub clock_seq_and_node: [u8; 8],
}

/// DCERPC presentation syntax identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxId {
    /// Interface UUID.
    pub uuid: Uuid,
    /// Major interface version.
    pub version_major: u16,
    /// Minor interface version.
    pub version_minor: u16,
}

/// NDR context handle placeholder used by LSA calls.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContextHandle {
    /// Handle attributes field.
    pub attributes: u32,
    /// Opaque handle UUID bytes.
    pub uuid: [u8; 16],
}

/// Rust-owned counterpart of `RPC_SID`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcSid {
    /// SID revision.
    pub revision: u8,
    /// Six-byte identifier authority.
    pub identifier_authority: [u8; 6],
    /// Variable sub-authority list.
    pub sub_authority: Vec<u32>,
}

impl RpcSid {
    /// Creates an SID skeleton with the supplied revision and sub-authorities.
    #[must_use]
    pub fn new(revision: u8, identifier_authority: [u8; 6], sub_authority: Vec<u32>) -> Self {
        Self {
            revision,
            identifier_authority,
            sub_authority,
        }
    }

    /// Creates an NT-authority SID skeleton.
    #[must_use]
    pub fn nt_authority(revision: u8, sub_authority: Vec<u32>) -> Self {
        Self::new(revision, NT_SID_AUTHORITY, sub_authority)
    }

    /// Returns the `SubAuthorityCount` value represented by this SID.
    #[must_use]
    pub fn sub_authority_count(&self) -> u8 {
        len_to_u8_saturating(self.sub_authority.len())
    }

    /// Returns a side-effect-free coder plan matching `lsa_RPC_SID_coder` field order.
    #[must_use]
    pub fn coder_plan(&self) -> CoderPlan {
        CoderPlan::new(CoderName::RpcSid)
            .with_step(CoderStep::Uint3264Count(self.sub_authority.len() as u64))
            .with_step(CoderStep::Uint8("Revision"))
            .with_step(CoderStep::Uint8("SubAuthorityCount"))
            .with_step(CoderStep::FixedBytes("IdentifierAuthority", 6))
            .with_step(CoderStep::Uint32Array(
                "SubAuthority",
                self.sub_authority.len(),
            ))
    }
}

/// Rust-owned counterpart of `RPC_UNICODE_STRING`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RpcUnicodeString {
    /// UTF-8 text retained until UTF-16 NDR encoding is implemented.
    pub value: String,
}

impl RpcUnicodeString {
    /// Creates a Unicode-string skeleton from UTF-8 text.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Returns the C `Length` value in bytes after UTF-16 expansion, saturating at `u16::MAX`.
    #[must_use]
    pub fn length_bytes(&self) -> u16 {
        utf16_len_bytes_saturating(&self.value)
    }

    /// Returns the C `MaximumLength` value used by the legacy coder.
    #[must_use]
    pub fn maximum_length_bytes(&self) -> u16 {
        let len = self.length_bytes();
        if len & 0x02 != 0 {
            len.saturating_add(2)
        } else {
            len
        }
    }

    /// Returns a side-effect-free coder plan matching `lsa_RPC_UNICODE_STRING_coder`.
    #[must_use]
    pub fn coder_plan(&self) -> CoderPlan {
        CoderPlan::new(CoderName::RpcUnicodeString)
            .with_step(CoderStep::Align3264)
            .with_step(CoderStep::Uint16("Length"))
            .with_step(CoderStep::Uint16("MaximumLength"))
            .with_step(CoderStep::Pointer {
                field: "Buffer",
                kind: PointerKind::Unique,
                coder: CoderName::Utf16,
            })
    }
}

/// Rust-owned counterpart of `LSAPR_SID_ENUM_BUFFER`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LsaprSidEnumBuffer {
    /// SID pointers to include in the request.
    pub sid_info: Vec<RpcSid>,
}

impl LsaprSidEnumBuffer {
    /// Creates a SID enum buffer skeleton.
    #[must_use]
    pub fn new(sid_info: Vec<RpcSid>) -> Self {
        Self { sid_info }
    }

    /// Returns the `Entries` value represented by this buffer.
    #[must_use]
    pub fn entries(&self) -> u32 {
        len_to_u32_saturating(self.sid_info.len())
    }

    /// Returns a side-effect-free coder plan matching `lsa_SID_ENUM_BUFFER_coder`.
    #[must_use]
    pub fn coder_plan(&self) -> CoderPlan {
        CoderPlan::new(CoderName::SidEnumBuffer)
            .with_step(CoderStep::Uint32("Entries"))
            .with_step(CoderStep::Pointer {
                field: "SidInfo",
                kind: PointerKind::Unique,
                coder: CoderName::PrpcSidArray,
            })
    }
}

/// SID name-use values carried by `LSAPR_TRANSLATED_NAME_EX`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum SidNameUse {
    /// User SID.
    User,
    /// Group SID.
    Group,
    /// Domain SID.
    Domain,
    /// Alias SID.
    Alias,
    /// Well-known group SID.
    WellKnownGroup,
    /// Deleted account SID.
    DeletedAccount,
    /// Invalid SID.
    Invalid,
    /// Unknown SID type.
    #[default]
    Unknown,
    /// Computer SID.
    Computer,
    /// Label SID.
    Label,
    /// Numeric value not modeled by this skeleton.
    Other(u32),
}

impl SidNameUse {
    /// Converts a wire numeric value into a skeleton enum.
    #[must_use]
    pub const fn from_raw(value: u32) -> Self {
        match value {
            1 => Self::User,
            2 => Self::Group,
            3 => Self::Domain,
            4 => Self::Alias,
            5 => Self::WellKnownGroup,
            6 => Self::DeletedAccount,
            7 => Self::Invalid,
            8 => Self::Unknown,
            9 => Self::Computer,
            10 => Self::Label,
            other => Self::Other(other),
        }
    }

    /// Converts this skeleton enum into the corresponding wire numeric value.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::User => 1,
            Self::Group => 2,
            Self::Domain => 3,
            Self::Alias => 4,
            Self::WellKnownGroup => 5,
            Self::DeletedAccount => 6,
            Self::Invalid => 7,
            Self::Unknown => 8,
            Self::Computer => 9,
            Self::Label => 10,
            Self::Other(other) => other,
        }
    }
}

/// Rust-owned counterpart of `LSAPR_TRANSLATED_NAME_EX`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LsaprTranslatedNameEx {
    /// SID name-use classification.
    pub use_kind: SidNameUse,
    /// Translated account name.
    pub name: RpcUnicodeString,
    /// Referenced domain index.
    pub domain_index: u32,
    /// Translation flags.
    pub flags: u32,
}

impl LsaprTranslatedNameEx {
    /// Returns a side-effect-free coder plan matching `lsa_TRANSLATED_NAME_EX_coder`.
    #[must_use]
    pub fn coder_plan(&self) -> CoderPlan {
        CoderPlan::new(CoderName::TranslatedNameEx)
            .with_step(CoderStep::Uint32("Use"))
            .with_step(CoderStep::Nested(CoderName::RpcUnicodeString))
            .with_step(CoderStep::Uint32("DomainIndex"))
            .with_step(CoderStep::Uint32("Flags"))
    }
}

/// Rust-owned counterpart of `LSAPR_TRANSLATED_NAMES_EX`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LsaprTranslatedNamesEx {
    /// Translated-name array.
    pub names: Vec<LsaprTranslatedNameEx>,
}

impl LsaprTranslatedNamesEx {
    /// Creates a translated-names skeleton.
    #[must_use]
    pub fn new(names: Vec<LsaprTranslatedNameEx>) -> Self {
        Self { names }
    }

    /// Returns the `Entries` value represented by this buffer.
    #[must_use]
    pub fn entries(&self) -> u32 {
        len_to_u32_saturating(self.names.len())
    }

    /// Returns a side-effect-free coder plan matching `lsa_TRANSLATED_NAMES_EX_coder`.
    #[must_use]
    pub fn coder_plan(&self) -> CoderPlan {
        CoderPlan::new(CoderName::TranslatedNamesEx)
            .with_step(CoderStep::Uint32("Entries"))
            .with_step(CoderStep::Pointer {
                field: "Names",
                kind: PointerKind::Unique,
                coder: CoderName::TranslatedNameArray,
            })
    }
}

/// Rust-owned counterpart of the empty `LSAPR_OBJECT_ATTRIBUTES` sent by `OpenPolicy2`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LsaprObjectAttributes {
    /// Object attribute length; the legacy coder emits `24`.
    pub length: u32,
    /// Attribute bitset; the legacy `OpenPolicy2` path emits `0`.
    pub attributes: u32,
}

impl LsaprObjectAttributes {
    /// Creates the fake empty object attributes used by the C `OpenPolicy2` request coder.
    #[must_use]
    pub const fn empty_for_open_policy2() -> Self {
        Self {
            length: 24,
            attributes: 0,
        }
    }

    /// Returns a side-effect-free coder plan matching `lsa_ObjectAttributes_coder`.
    #[must_use]
    pub fn coder_plan(&self) -> CoderPlan {
        CoderPlan::new(CoderName::ObjectAttributes)
            .with_step(CoderStep::Uint32("Length"))
            .with_step(CoderStep::Uint3264("RootDirectory"))
            .with_step(CoderStep::Uint3264("ObjectName"))
            .with_step(CoderStep::Uint32("Attributes"))
            .with_step(CoderStep::Uint3264("SecurityDescriptor"))
            .with_step(CoderStep::Uint3264("SecurityQualityOfService"))
    }
}

/// Rust-owned counterpart of `struct lsa_close_req`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LsaCloseRequest {
    /// Policy context handle to close.
    pub policy_handle: ContextHandle,
}

/// Rust-owned counterpart of `struct lsa_close_rep`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LsaCloseReply {
    /// Returned policy context handle.
    pub policy_handle: ContextHandle,
    /// NTSTATUS result.
    pub status: u32,
}

/// Rust-owned counterpart of `struct lsa_openpolicy2_req`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaOpenPolicy2Request {
    /// Optional remote system name.
    pub system_name: Option<RpcUnicodeString>,
    /// Object attributes passed by reference.
    pub object_attributes: LsaprObjectAttributes,
    /// Desired policy access mask.
    pub desired_access: u32,
}

impl LsaOpenPolicy2Request {
    /// Creates an `OpenPolicy2` request skeleton.
    #[must_use]
    pub const fn new(desired_access: u32) -> Self {
        Self {
            system_name: None,
            object_attributes: LsaprObjectAttributes::empty_for_open_policy2(),
            desired_access,
        }
    }

    /// Returns a side-effect-free coder plan matching `lsa_OpenPolicy2_req_coder`.
    #[must_use]
    pub fn coder_plan(&self) -> CoderPlan {
        CoderPlan::new(CoderName::OpenPolicy2Request)
            .with_step(CoderStep::Pointer {
                field: "SystemName",
                kind: PointerKind::Unique,
                coder: CoderName::Utf16z,
            })
            .with_step(CoderStep::Pointer {
                field: "ObjectAttributes",
                kind: PointerKind::Ref,
                coder: CoderName::ObjectAttributes,
            })
            .with_step(CoderStep::Uint32("DesiredAccess"))
    }
}

/// Rust-owned counterpart of `struct lsa_openpolicy2_rep`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LsaOpenPolicy2Reply {
    /// Returned policy context handle.
    pub policy_handle: ContextHandle,
    /// NTSTATUS result.
    pub status: u32,
}

/// Rust-owned counterpart of `LSAPR_TRUST_INFORMATION`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LsaprTrustInformation {
    /// Domain name.
    pub name: RpcUnicodeString,
    /// Optional domain SID.
    pub sid: Option<RpcSid>,
}

/// Rust-owned counterpart of `LSAPR_REFERENCED_DOMAIN_LIST`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LsaprReferencedDomainList {
    /// Referenced domains.
    pub domains: Vec<LsaprTrustInformation>,
    /// Maximum entries field retained for reply modeling; the C coder ignores it semantically.
    pub max_entries: u32,
}

impl LsaprReferencedDomainList {
    /// Returns the `Entries` value represented by this list.
    #[must_use]
    pub fn entries(&self) -> u32 {
        len_to_u32_saturating(self.domains.len())
    }

    /// Returns a side-effect-free coder plan matching `lsa_REFERENCED_DOMAIN_LIST_coder`.
    #[must_use]
    pub fn coder_plan(&self) -> CoderPlan {
        CoderPlan::new(CoderName::ReferencedDomainList)
            .with_step(CoderStep::Uint32("Entries"))
            .with_step(CoderStep::Pointer {
                field: "Domains",
                kind: PointerKind::Unique,
                coder: CoderName::ReferencedDomainArray,
            })
            .with_step(CoderStep::Uint32("MaxEntries"))
    }
}

/// Lookup-level values accepted by `LsarLookupSids2`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum LsapLookupLevel {
    /// Translate isolated names.
    #[default]
    Wksta = 1,
    /// Translate names from a primary domain context.
    Pdc = 2,
    /// Translate names from a trusted-domain context.
    Tdl = 3,
    /// Translate names with garbage-collection semantics.
    Gc = 4,
    /// Translate names from an XForest referral context.
    XForestReferral = 5,
    /// Translate names from an XForest resolve context.
    XForestResolve = 6,
    /// Translate names from an RODC referral context.
    RodcReferral = 7,
}

/// Rust-owned counterpart of `struct lsa_lookupsids2_req`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LsaLookupSids2Request {
    /// Policy context handle.
    pub policy_handle: ContextHandle,
    /// SID enum buffer passed by reference.
    pub sid_enum_buffer: LsaprSidEnumBuffer,
    /// Translated names passed in/out by reference.
    pub translated_names: LsaprTranslatedNamesEx,
    /// Lookup level.
    pub lookup_level: LsapLookupLevel,
    /// Mapped-count input value.
    pub mapped_count: u32,
    /// Lookup options; the legacy request coder emits zero.
    pub lookup_options: u32,
    /// Client revision; the legacy request coder emits two.
    pub client_revision: u32,
}

impl LsaLookupSids2Request {
    /// Creates a `LookupSids2` request skeleton with legacy default options.
    #[must_use]
    pub fn new(
        policy_handle: ContextHandle,
        sid_enum_buffer: LsaprSidEnumBuffer,
        lookup_level: LsapLookupLevel,
    ) -> Self {
        Self {
            policy_handle,
            sid_enum_buffer,
            lookup_level,
            lookup_options: LSA_LOOKUP_SIDS2_LOOKUP_OPTIONS,
            client_revision: LSA_LOOKUP_SIDS2_CLIENT_REVISION,
            ..Self::default()
        }
    }

    /// Returns a side-effect-free coder plan matching `lsa_LookupSids2_req_coder`.
    #[must_use]
    pub fn coder_plan(&self) -> CoderPlan {
        CoderPlan::new(CoderName::LookupSids2Request)
            .with_step(CoderStep::Pointer {
                field: "PolicyHandle",
                kind: PointerKind::Ref,
                coder: CoderName::ContextHandle,
            })
            .with_step(CoderStep::Pointer {
                field: "SidEnumBuffer",
                kind: PointerKind::Ref,
                coder: CoderName::SidEnumBuffer,
            })
            .with_step(CoderStep::Pointer {
                field: "TranslatedNames",
                kind: PointerKind::Ref,
                coder: CoderName::TranslatedNamesEx,
            })
            .with_step(CoderStep::Uint32("LookupLevel"))
            .with_step(CoderStep::Uint32("MappedCount"))
            .with_step(CoderStep::Uint32("LookupOptions"))
            .with_step(CoderStep::Uint32("ClientRevision"))
    }
}

/// Rust-owned counterpart of `struct lsa_lookupsids2_rep`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LsaLookupSids2Reply {
    /// Optional referenced-domain list.
    pub referenced_domains: Option<LsaprReferencedDomainList>,
    /// Translated names returned by reference.
    pub translated_names: LsaprTranslatedNamesEx,
    /// Mapped SID count.
    pub mapped_count: u32,
    /// NTSTATUS result.
    pub status: u32,
}

impl LsaLookupSids2Reply {
    /// Returns a side-effect-free coder plan matching `lsa_LookupSids2_rep_coder`.
    #[must_use]
    pub fn coder_plan(&self) -> CoderPlan {
        CoderPlan::new(CoderName::LookupSids2Reply)
            .with_step(CoderStep::Pointer {
                field: "ReferencedDomains",
                kind: PointerKind::Unique,
                coder: CoderName::ReferencedDomainList,
            })
            .with_step(CoderStep::Pointer {
                field: "TranslatedNames",
                kind: PointerKind::Ref,
                coder: CoderName::TranslatedNamesEx,
            })
            .with_step(CoderStep::Uint32("MappedCount"))
            .with_step(CoderStep::Uint32("Status"))
    }
}

/// DCERPC pointer flavor used by the legacy coders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerKind {
    /// Non-null reference pointer.
    Ref,
    /// Nullable unique pointer.
    Unique,
}

/// Legacy coder names referenced by plan steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoderName {
    /// `dcerpc_context_handle_coder`.
    ContextHandle,
    /// `dcerpc_utf16_coder`.
    Utf16,
    /// `dcerpc_utf16z_coder`.
    Utf16z,
    /// `lsa_RPC_SID_coder`.
    RpcSid,
    /// `lsa_PRPC_SID_array_coder`.
    PrpcSidArray,
    /// `lsa_SID_ENUM_BUFFER_coder`.
    SidEnumBuffer,
    /// `lsa_RPC_UNICODE_STRING_coder`.
    RpcUnicodeString,
    /// `lsa_TRANSLATED_NAME_EX_coder`.
    TranslatedNameEx,
    /// `TN_array_coder`.
    TranslatedNameArray,
    /// `lsa_TRANSLATED_NAMES_EX_coder`.
    TranslatedNamesEx,
    /// `lsa_ObjectAttributes_coder`.
    ObjectAttributes,
    /// `lsa_OpenPolicy2_req_coder`.
    OpenPolicy2Request,
    /// `lsa_TRUST_INFORMATION_coder`.
    TrustInformation,
    /// `RDL_DOMAINS_array_coder`.
    ReferencedDomainArray,
    /// `lsa_REFERENCED_DOMAIN_LIST_coder`.
    ReferencedDomainList,
    /// `lsa_LookupSids2_req_coder`.
    LookupSids2Request,
    /// `lsa_LookupSids2_rep_coder`.
    LookupSids2Reply,
}

/// One field-level action in a future NDR coder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoderStep {
    /// Align to the legacy 32/64-bit boundary.
    Align3264,
    /// Encode or decode an unsigned 8-bit field.
    Uint8(&'static str),
    /// Encode or decode an unsigned 16-bit field.
    Uint16(&'static str),
    /// Encode or decode an unsigned 32-bit field.
    Uint32(&'static str),
    /// Encode or decode an unsigned pointer-sized scalar field.
    Uint3264(&'static str),
    /// Encode or decode a conformance count.
    Uint3264Count(u64),
    /// Encode or decode fixed-size bytes.
    FixedBytes(&'static str, usize),
    /// Encode or decode an array of `u32` values.
    Uint32Array(&'static str, usize),
    /// Delegate to another coder without pointer wrapping.
    Nested(CoderName),
    /// Delegate to another coder through a DCERPC pointer wrapper.
    Pointer {
        /// Field being wrapped.
        field: &'static str,
        /// Pointer flavor.
        kind: PointerKind,
        /// Delegate coder.
        coder: CoderName,
    },
}

/// Side-effect-free description of a legacy C coder's field order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoderPlan {
    /// Legacy coder represented by this plan.
    pub coder: CoderName,
    /// Ordered field-level actions.
    pub steps: Vec<CoderStep>,
}

impl CoderPlan {
    /// Creates an empty coder plan.
    #[must_use]
    pub fn new(coder: CoderName) -> Self {
        Self {
            coder,
            steps: Vec::new(),
        }
    }

    /// Appends a field-level action and returns the updated plan.
    #[must_use]
    pub fn with_step(mut self, step: CoderStep) -> Self {
        self.steps.push(step);
        self
    }
}

/// Returns a side-effect-free coder plan matching `lsa_Close_req_coder`.
#[must_use]
pub fn lsa_close_req_coder_plan() -> CoderPlan {
    CoderPlan::new(CoderName::ContextHandle).with_step(CoderStep::Pointer {
        field: "PolicyHandle",
        kind: PointerKind::Ref,
        coder: CoderName::ContextHandle,
    })
}

/// Returns a side-effect-free coder plan matching `lsa_Close_rep_coder`.
#[must_use]
pub fn lsa_close_rep_coder_plan() -> CoderPlan {
    lsa_close_req_coder_plan().with_step(CoderStep::Uint32("Status"))
}

fn len_to_u8_saturating(len: usize) -> u8 {
    if len > u8::MAX as usize {
        u8::MAX
    } else {
        len as u8
    }
}

fn len_to_u32_saturating(len: usize) -> u32 {
    if len > u32::MAX as usize {
        u32::MAX
    } else {
        len as u32
    }
}

fn utf16_len_bytes_saturating(value: &str) -> u16 {
    let units = value.encode_utf16().count();
    let bytes = units.saturating_mul(2);
    if bytes > u16::MAX as usize {
        u16::MAX
    } else {
        bytes as u16
    }
}
