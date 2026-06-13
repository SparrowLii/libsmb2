//! LSA DCERPC command helpers migrated from `lib/dcerpc-lsa.c`.
//!
//! This module intentionally models the legacy LSA request, reply, and nested
//! NDR structures without implementing the full DCERPC/NDR protocol encoder.

use super::dcerpc::{DceRpcError, DceRpcResult, DceRpcUtf16, Direction, NdrCodec};

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

/// Maximum count used by LSA SID, referenced-domain, and translated-name arrays in the IDL.
pub const LSA_MAX_ENUM_ENTRIES: u32 = 20_480;

/// NTSTATUS success.
pub const LSA_STATUS_SUCCESS: u32 = 0x0000_0000;

/// NTSTATUS warning returned when only part of a SID/name lookup mapped.
pub const LSA_STATUS_SOME_NOT_MAPPED: u32 = 0x0000_0107;

/// NTSTATUS returned when no SID/name lookup entries mapped.
pub const LSA_STATUS_NONE_MAPPED: u32 = 0xc000_0073;

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

    /// Counts names with a concrete mapping, matching LookupSids2 mapped-count semantics.
    #[must_use]
    pub fn mapped_count(&self) -> u32 {
        len_to_u32_saturating(self.names.iter().filter(|name| name.is_mapped()).count())
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

impl LsaprTranslatedNameEx {
    /// Returns true when this entry represents a successful SID/name mapping.
    #[must_use]
    pub fn is_mapped(&self) -> bool {
        !matches!(
            self.use_kind,
            SidNameUse::Unknown | SidNameUse::Invalid | SidNameUse::Other(0)
        ) && !self.name.value.is_empty()
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

    /// Returns true when `index` points at a decoded referenced-domain entry.
    #[must_use]
    pub fn contains_domain_index(&self, index: u32) -> bool {
        usize::try_from(index).is_ok_and(|index| index < self.domains.len())
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
    /// Normalizes mapped-count and status from translated names using LSA lookup semantics.
    pub fn normalize_lookup_result(&mut self) {
        self.mapped_count = self.translated_names.mapped_count();
        self.status = lookup_status_for_counts(self.mapped_count, self.translated_names.entries());
    }

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

/// Encodes an LSA `Close` request body.
pub fn encode_lsa_close_request(req: &LsaCloseRequest) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_lsa_close_request(&mut codec, &mut req.clone())?;
    Ok(codec.into_bytes())
}

/// Decodes an LSA `OpenPolicy2` request body.
pub fn decode_lsa_open_policy2_request(bytes: &[u8]) -> DceRpcResult<LsaOpenPolicy2Request> {
    let mut req = LsaOpenPolicy2Request::new(0);
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_open_policy2_request(&mut codec, &mut req)?;
    Ok(req)
}

/// Encodes an LSA `OpenPolicy2` response body.
pub fn encode_lsa_open_policy2_reply(rep: &LsaOpenPolicy2Reply) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_open_policy2_reply(&mut codec, &mut rep.clone())?;
    Ok(codec.into_bytes())
}

/// Decodes an LSA `Close` request body.
pub fn decode_lsa_close_request(bytes: &[u8]) -> DceRpcResult<LsaCloseRequest> {
    let mut req = LsaCloseRequest::default();
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_lsa_close_request(&mut codec, &mut req)?;
    Ok(req)
}

/// Encodes an LSA `Close` response body.
pub fn encode_lsa_close_reply(rep: &LsaCloseReply) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_lsa_close_reply(&mut codec, &mut rep.clone())?;
    Ok(codec.into_bytes())
}

/// Decodes an LSA `Close` response body.
pub fn decode_lsa_close_reply(bytes: &[u8]) -> DceRpcResult<LsaCloseReply> {
    let mut rep = LsaCloseReply::default();
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_lsa_close_reply(&mut codec, &mut rep)?;
    Ok(rep)
}

/// Encodes an LSA `OpenPolicy2` request body.
pub fn encode_lsa_open_policy2_request(req: &LsaOpenPolicy2Request) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_open_policy2_request(&mut codec, &mut req.clone())?;
    Ok(codec.into_bytes())
}

/// Decodes an LSA `OpenPolicy2` response body.
pub fn decode_lsa_open_policy2_reply(bytes: &[u8]) -> DceRpcResult<LsaOpenPolicy2Reply> {
    let mut rep = LsaOpenPolicy2Reply::default();
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_open_policy2_reply(&mut codec, &mut rep)?;
    Ok(rep)
}

/// Encodes an LSA `LookupSids2` request body.
pub fn encode_lsa_lookup_sids2_request(req: &LsaLookupSids2Request) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_lookup_sids2_request(&mut codec, &mut req.clone())?;
    Ok(codec.into_bytes())
}

/// Decodes an LSA `LookupSids2` request body.
pub fn decode_lsa_lookup_sids2_request(bytes: &[u8]) -> DceRpcResult<LsaLookupSids2Request> {
    let mut req = LsaLookupSids2Request::default();
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_lookup_sids2_request(&mut codec, &mut req)?;
    Ok(req)
}

/// Encodes an LSA `LookupSids2` response body.
pub fn encode_lsa_lookup_sids2_reply(rep: &LsaLookupSids2Reply) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_lookup_sids2_reply(&mut codec, &mut rep.clone())?;
    Ok(codec.into_bytes())
}

/// Decodes an LSA `LookupSids2` response body.
pub fn decode_lsa_lookup_sids2_reply(bytes: &[u8]) -> DceRpcResult<LsaLookupSids2Reply> {
    let mut rep = LsaLookupSids2Reply::default();
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_lookup_sids2_reply(&mut codec, &mut rep)?;
    Ok(rep)
}

/// Encodes a standalone LSA `RPC_SID` value.
pub fn encode_rpc_sid(sid: &RpcSid) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_rpc_sid(&mut codec, &mut sid.clone())?;
    Ok(codec.into_bytes())
}

/// Decodes a standalone LSA `RPC_SID` value.
pub fn decode_rpc_sid(bytes: &[u8]) -> DceRpcResult<RpcSid> {
    let mut sid = RpcSid::nt_authority(1, Vec::new());
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_rpc_sid(&mut codec, &mut sid)?;
    Ok(sid)
}

fn code_lsa_close_request(codec: &mut NdrCodec, req: &mut LsaCloseRequest) -> DceRpcResult<()> {
    codec.code_ref_pointer()?;
    let mut h = to_ndr_handle(&req.policy_handle);
    codec.code_context_handle(&mut h)?;
    req.policy_handle = from_ndr_handle(h);
    Ok(())
}

fn code_lsa_close_reply(codec: &mut NdrCodec, rep: &mut LsaCloseReply) -> DceRpcResult<()> {
    codec.code_ref_pointer()?;
    let mut h = to_ndr_handle(&rep.policy_handle);
    codec.code_context_handle(&mut h)?;
    rep.policy_handle = from_ndr_handle(h);
    codec.code_u32(&mut rep.status)
}

fn code_open_policy2_request(
    codec: &mut NdrCodec,
    req: &mut LsaOpenPolicy2Request,
) -> DceRpcResult<()> {
    code_optional_utf16(codec, &mut req.system_name, true)?;
    codec.code_ref_pointer()?;
    code_object_attributes(codec, &mut req.object_attributes)?;
    codec.code_u32(&mut req.desired_access)
}

fn code_open_policy2_reply(
    codec: &mut NdrCodec,
    rep: &mut LsaOpenPolicy2Reply,
) -> DceRpcResult<()> {
    codec.code_ref_pointer()?;
    let mut h = to_ndr_handle(&rep.policy_handle);
    codec.code_context_handle(&mut h)?;
    rep.policy_handle = from_ndr_handle(h);
    codec.code_u32(&mut rep.status)
}

fn code_lookup_sids2_request(
    codec: &mut NdrCodec,
    req: &mut LsaLookupSids2Request,
) -> DceRpcResult<()> {
    codec.code_ref_pointer()?;
    let mut h = to_ndr_handle(&req.policy_handle);
    codec.code_context_handle(&mut h)?;
    req.policy_handle = from_ndr_handle(h);
    codec.code_ref_pointer()?;
    code_sid_enum_buffer(codec, &mut req.sid_enum_buffer)?;
    codec.code_ref_pointer()?;
    code_translated_names(codec, &mut req.translated_names)?;
    let mut level = req.lookup_level as u32;
    codec.code_u32(&mut level)?;
    req.lookup_level = lookup_level_from_u32(level);
    codec.code_u32(&mut req.mapped_count)?;
    codec.code_u32(&mut req.lookup_options)?;
    codec.code_u32(&mut req.client_revision)
}

fn code_lookup_sids2_reply(
    codec: &mut NdrCodec,
    rep: &mut LsaLookupSids2Reply,
) -> DceRpcResult<()> {
    let present = codec.code_unique_pointer_present(rep.referenced_domains.is_some())?;
    if present {
        let mut rdl = rep
            .referenced_domains
            .take()
            .map_or_else(LsaprReferencedDomainList::default, core::convert::identity);
        code_referenced_domain_list(codec, &mut rdl)?;
        rep.referenced_domains = Some(rdl);
    } else {
        rep.referenced_domains = None;
    }
    codec.code_ref_pointer()?;
    code_translated_names(codec, &mut rep.translated_names)?;
    codec.code_u32(&mut rep.mapped_count)?;
    codec.code_u32(&mut rep.status)
}

fn code_object_attributes(
    codec: &mut NdrCodec,
    attrs: &mut LsaprObjectAttributes,
) -> DceRpcResult<()> {
    codec.code_u32(&mut attrs.length)?;
    let mut zero = 0u64;
    codec.code_u3264(&mut zero)?;
    codec.code_u3264(&mut zero)?;
    codec.code_u32(&mut attrs.attributes)?;
    codec.code_u3264(&mut zero)?;
    codec.code_u3264(&mut zero)
}

fn code_sid_enum_buffer(codec: &mut NdrCodec, buffer: &mut LsaprSidEnumBuffer) -> DceRpcResult<()> {
    validate_encode_count(codec.direction(), buffer.sid_info.len())?;
    let mut entries = buffer.entries();
    codec.code_u32(&mut entries)?;
    validate_wire_count(entries)?;
    let present = codec.code_unique_pointer_present(entries != 0)?;
    if !present {
        buffer.sid_info.clear();
        return Ok(());
    }
    let count = checked_u32_to_usize(entries)?;
    resize_sids(&mut buffer.sid_info, count);
    let mut conformant = u64::from(entries);
    codec.code_u3264(&mut conformant)?;
    for sid in &mut buffer.sid_info {
        let sid_present = codec.code_unique_pointer_present(true)?;
        if !sid_present {
            return Err(DceRpcError::NullPointer);
        }
        code_rpc_sid(codec, sid)?;
    }
    Ok(())
}

fn code_rpc_sid(codec: &mut NdrCodec, sid: &mut RpcSid) -> DceRpcResult<()> {
    if matches!(codec.direction(), Direction::Encode | Direction::Request) {
        u8::try_from(sid.sub_authority.len()).map_err(|_| DceRpcError::CountOutOfRange {
            count: sid.sub_authority.len(),
        })?;
    }
    let mut count = u64::from(sid.sub_authority_count());
    codec.code_u3264(&mut count)?;
    if count > u64::from(u8::MAX) {
        return Err(DceRpcError::CountOutOfRange { count: usize::MAX });
    }
    codec.code_u8(&mut sid.revision)?;
    let mut sub_count = sid.sub_authority_count();
    codec.code_u8(&mut sub_count)?;
    if matches!(codec.direction(), Direction::Decode | Direction::Response) {
        sid.sub_authority.resize(usize::from(sub_count), 0);
    }
    for byte in &mut sid.identifier_authority {
        codec.code_u8(byte)?;
    }
    for authority in &mut sid.sub_authority {
        codec.code_u32(authority)?;
    }
    Ok(())
}

fn code_translated_names(
    codec: &mut NdrCodec,
    names: &mut LsaprTranslatedNamesEx,
) -> DceRpcResult<()> {
    validate_encode_count(codec.direction(), names.names.len())?;
    let mut entries = names.entries();
    codec.code_u32(&mut entries)?;
    validate_wire_count(entries)?;
    let present = codec.code_unique_pointer_present(entries != 0)?;
    if !present {
        names.names.clear();
        return Ok(());
    }
    let count = checked_u32_to_usize(entries)?;
    names
        .names
        .resize_with(count, LsaprTranslatedNameEx::default);
    let mut conformant = u64::from(entries);
    codec.code_u3264(&mut conformant)?;
    for name in &mut names.names {
        let mut raw_use = name.use_kind.as_raw();
        codec.code_u32(&mut raw_use)?;
        name.use_kind = SidNameUse::from_raw(raw_use);
        code_unicode_string(codec, &mut name.name)?;
        codec.code_u32(&mut name.domain_index)?;
        codec.code_u32(&mut name.flags)?;
    }
    Ok(())
}

fn code_referenced_domain_list(
    codec: &mut NdrCodec,
    rdl: &mut LsaprReferencedDomainList,
) -> DceRpcResult<()> {
    validate_encode_count(codec.direction(), rdl.domains.len())?;
    let mut entries = rdl.entries();
    codec.code_u32(&mut entries)?;
    validate_wire_count(entries)?;
    let present = codec.code_unique_pointer_present(entries != 0)?;
    if present {
        let count = checked_u32_to_usize(entries)?;
        rdl.domains
            .resize_with(count, LsaprTrustInformation::default);
        let mut conformant = u64::from(entries);
        codec.code_u3264(&mut conformant)?;
        for domain in &mut rdl.domains {
            code_unicode_string(codec, &mut domain.name)?;
            let sid_present = codec.code_unique_pointer_present(domain.sid.is_some())?;
            if sid_present {
                let mut sid = match domain.sid.take() {
                    Some(sid) => sid,
                    None => RpcSid::nt_authority(1, Vec::new()),
                };
                code_rpc_sid(codec, &mut sid)?;
                domain.sid = Some(sid);
            } else {
                domain.sid = None;
            }
        }
    } else {
        rdl.domains.clear();
    }
    codec.code_u32(&mut rdl.max_entries)
}

fn code_unicode_string(codec: &mut NdrCodec, value: &mut RpcUnicodeString) -> DceRpcResult<()> {
    codec.align_3264();
    let mut len = value.length_bytes();
    let mut max_len = value.maximum_length_bytes();
    codec.code_u16(&mut len)?;
    codec.code_u16(&mut max_len)?;
    let mut utf = DceRpcUtf16 {
        utf8: Some(value.value.clone()),
        ..DceRpcUtf16::default()
    };
    let present = codec.code_unique_pointer_present(!value.value.is_empty())?;
    if present {
        codec.code_utf16(&mut utf, false)?;
        if let Some(decoded) = utf.utf8 {
            value.value = decoded;
        }
    } else if matches!(codec.direction(), Direction::Decode | Direction::Response) {
        value.value.clear();
    }
    Ok(())
}

fn code_optional_utf16(
    codec: &mut NdrCodec,
    value: &mut Option<RpcUnicodeString>,
    nul: bool,
) -> DceRpcResult<()> {
    let present = codec.code_unique_pointer_present(value.is_some())?;
    if present {
        let mut utf = DceRpcUtf16 {
            utf8: value.as_ref().map(|v| v.value.clone()),
            ..DceRpcUtf16::default()
        };
        codec.code_utf16(&mut utf, nul)?;
        let decoded = utf.utf8.map_or_else(String::new, core::convert::identity);
        value.replace(RpcUnicodeString::new(decoded));
    } else {
        *value = None;
    }
    Ok(())
}

fn to_ndr_handle(handle: &ContextHandle) -> super::dcerpc::NdrContextHandle {
    let mut uuid = super::dcerpc::DceRpcUuid::default();
    uuid.v1 = u32::from_le_bytes([
        handle.uuid[0],
        handle.uuid[1],
        handle.uuid[2],
        handle.uuid[3],
    ]);
    uuid.v2 = u16::from_le_bytes([handle.uuid[4], handle.uuid[5]]);
    uuid.v3 = u16::from_le_bytes([handle.uuid[6], handle.uuid[7]]);
    uuid.v4.copy_from_slice(&handle.uuid[8..16]);
    super::dcerpc::NdrContextHandle {
        context_handle_attributes: handle.attributes,
        context_handle_uuid: uuid,
    }
}

fn from_ndr_handle(handle: super::dcerpc::NdrContextHandle) -> ContextHandle {
    let mut uuid = [0u8; 16];
    uuid[0..4].copy_from_slice(&handle.context_handle_uuid.v1.to_le_bytes());
    uuid[4..6].copy_from_slice(&handle.context_handle_uuid.v2.to_le_bytes());
    uuid[6..8].copy_from_slice(&handle.context_handle_uuid.v3.to_le_bytes());
    uuid[8..16].copy_from_slice(&handle.context_handle_uuid.v4);
    ContextHandle {
        attributes: handle.context_handle_attributes,
        uuid,
    }
}

fn resize_sids(sids: &mut Vec<RpcSid>, count: usize) {
    sids.resize_with(count, || RpcSid::nt_authority(1, Vec::new()));
}

fn checked_u32_to_usize(value: u32) -> DceRpcResult<usize> {
    usize::try_from(value).map_err(|_| DceRpcError::CountOutOfRange { count: usize::MAX })
}

fn validate_encode_count(direction: Direction, len: usize) -> DceRpcResult<()> {
    if matches!(direction, Direction::Encode | Direction::Request) {
        let max = usize::try_from(LSA_MAX_ENUM_ENTRIES)
            .map_err(|_| DceRpcError::CountOutOfRange { count: usize::MAX })?;
        if len > max {
            return Err(DceRpcError::CountOutOfRange { count: len });
        }
    }
    Ok(())
}

fn validate_wire_count(entries: u32) -> DceRpcResult<()> {
    if entries > LSA_MAX_ENUM_ENTRIES {
        Err(DceRpcError::CountOutOfRange {
            count: usize::try_from(entries).unwrap_or(usize::MAX),
        })
    } else {
        Ok(())
    }
}

fn lookup_status_for_counts(mapped_count: u32, total_count: u32) -> u32 {
    match (mapped_count, total_count) {
        (0, 0) => LSA_STATUS_SUCCESS,
        (0, _) => LSA_STATUS_NONE_MAPPED,
        (mapped, total) if mapped < total => LSA_STATUS_SOME_NOT_MAPPED,
        _ => LSA_STATUS_SUCCESS,
    }
}

fn lookup_level_from_u32(value: u32) -> LsapLookupLevel {
    match value {
        2 => LsapLookupLevel::Pdc,
        3 => LsapLookupLevel::Tdl,
        4 => LsapLookupLevel::Gc,
        5 => LsapLookupLevel::XForestReferral,
        6 => LsapLookupLevel::XForestResolve,
        7 => LsapLookupLevel::RodcReferral,
        _ => LsapLookupLevel::Wksta,
    }
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
