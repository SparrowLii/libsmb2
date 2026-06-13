//! SRVSVC DCERPC command helpers migrated from `lib/dcerpc-srvsvc.c`.

use core::fmt;

/// SRVSVC interface UUID from the legacy `SRVSVC_UUID` definition.
pub const SRVSVC_UUID: [u8; 16] = [
    0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
];

/// SRVSVC interface major version.
pub const SRVSVC_INTERFACE_VERSION_MAJOR: u16 = 3;

/// SRVSVC interface minor version.
pub const SRVSVC_INTERFACE_VERSION_MINOR: u16 = 0;

/// Operation number for `NetrShareEnum`.
pub const SRVSVC_NETR_SHARE_ENUM: u16 = 0x0f;

/// Operation number for `NetrShareGetInfo`.
pub const SRVSVC_NETR_SHARE_GET_INFO: u16 = 0x10;

/// Share type for disk-tree shares.
pub const SHARE_TYPE_DISKTREE: u32 = 0;

/// Share type for print queues.
pub const SHARE_TYPE_PRINTQ: u32 = 1;

/// Share type for device shares.
pub const SHARE_TYPE_DEVICE: u32 = 2;

/// Share type for IPC shares.
pub const SHARE_TYPE_IPC: u32 = 3;

/// Share type flag for temporary shares.
pub const SHARE_TYPE_TEMPORARY: u32 = 0x4000_0000;

/// Share type flag for hidden shares.
pub const SHARE_TYPE_HIDDEN: u32 = 0x8000_0000;

/// Result type used by SRVSVC codec skeleton functions.
pub type SrvsvcResult<T> = core::result::Result<T, SrvsvcCodecError>;

/// Error returned by SRVSVC codec skeletons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrvsvcCodecError {
    /// Full NDR/DCERPC protocol encoding or decoding has not been ported yet.
    ProtocolLogicNotImplemented,
    /// The requested SRVSVC information level is not represented by this skeleton.
    UnsupportedShareInfoLevel(u32),
}

impl fmt::Display for SrvsvcCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolLogicNotImplemented => {
                f.write_str("SRVSVC protocol encoding is not implemented")
            }
            Self::UnsupportedShareInfoLevel(level) => {
                write!(f, "unsupported SRVSVC share information level {level}")
            }
        }
    }
}

impl std::error::Error for SrvsvcCodecError {}

/// Packet direction used by SRVSVC coder skeleton functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrvsvcCoderDirection {
    /// Encode a request or response into a DCERPC payload.
    Encode,
    /// Decode a request or response from a DCERPC payload.
    Decode,
}

/// Share information levels represented by the legacy SRVSVC migration skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareInfoLevel {
    /// `SHARE_INFO_0` contains only the share net name.
    Level0,
    /// `SHARE_INFO_1` contains the share net name, type, and remark.
    Level1,
}

impl ShareInfoLevel {
    /// Returns the numeric DCERPC level discriminator.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Level0 => 0,
            Self::Level1 => 1,
        }
    }

    /// Converts a numeric DCERPC level discriminator into a share info level.
    ///
    /// # Errors
    ///
    /// Returns [`SrvsvcCodecError::UnsupportedShareInfoLevel`] when `level` is not
    /// represented by this migration skeleton.
    pub const fn try_from_u32(level: u32) -> SrvsvcResult<Self> {
        match level {
            0 => Ok(Self::Level0),
            1 => Ok(Self::Level1),
            other => Err(SrvsvcCodecError::UnsupportedShareInfoLevel(other)),
        }
    }
}

/// Rust representation of the C `srvsvc_SHARE_INFO_0` structure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo0 {
    /// Share net name.
    pub netname: Option<String>,
}

impl SrvsvcShareInfo0 {
    /// Creates a level 0 share information value.
    #[must_use]
    pub fn new(netname: impl Into<String>) -> Self {
        Self {
            netname: Some(netname.into()),
        }
    }
}

/// Rust representation of the C `srvsvc_SHARE_INFO_1` structure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo1 {
    /// Share net name.
    pub netname: Option<String>,
    /// Share type and share type flags.
    pub share_type: u32,
    /// Optional share remark.
    pub remark: Option<String>,
}

impl SrvsvcShareInfo1 {
    /// Creates a level 1 share information value.
    #[must_use]
    pub fn new(netname: impl Into<String>, share_type: u32, remark: Option<String>) -> Self {
        Self {
            netname: Some(netname.into()),
            share_type,
            remark,
        }
    }
}

/// Container for `[size_is(EntriesRead)] SHARE_INFO_0` arrays.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo0Container {
    /// Number of entries read by the server.
    pub entries_read: u32,
    /// Level 0 share entries.
    pub share_info_0: Vec<SrvsvcShareInfo0>,
}

impl SrvsvcShareInfo0Container {
    /// Creates a level 0 share information container.
    #[must_use]
    pub fn new(share_info_0: Vec<SrvsvcShareInfo0>) -> Self {
        Self {
            entries_read: share_info_0.len() as u32,
            share_info_0,
        }
    }
}

/// Container for `[size_is(EntriesRead)] SHARE_INFO_1` arrays.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo1Container {
    /// Number of entries read by the server.
    pub entries_read: u32,
    /// Level 1 share entries.
    pub share_info_1: Vec<SrvsvcShareInfo1>,
}

impl SrvsvcShareInfo1Container {
    /// Creates a level 1 share information container.
    #[must_use]
    pub fn new(share_info_1: Vec<SrvsvcShareInfo1>) -> Self {
        Self {
            entries_read: share_info_1.len() as u32,
            share_info_1,
        }
    }
}

/// Rust representation of the C `srvsvc_SHARE_ENUM_UNION` switch union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrvsvcShareEnumUnion {
    /// Level 0 share enumeration container.
    Level0(SrvsvcShareInfo0Container),
    /// Level 1 share enumeration container.
    Level1(SrvsvcShareInfo1Container),
}

impl SrvsvcShareEnumUnion {
    /// Returns the numeric switch level for this union arm.
    #[must_use]
    pub const fn level(&self) -> ShareInfoLevel {
        match self {
            Self::Level0(_) => ShareInfoLevel::Level0,
            Self::Level1(_) => ShareInfoLevel::Level1,
        }
    }
}

impl Default for SrvsvcShareEnumUnion {
    fn default() -> Self {
        Self::Level1(SrvsvcShareInfo1Container::default())
    }
}

/// Rust representation of the C `srvsvc_SHARE_ENUM_STRUCT` structure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareEnumStruct {
    /// Share information switch union.
    pub share_info: SrvsvcShareEnumUnion,
}

impl SrvsvcShareEnumStruct {
    /// Creates a share enumeration structure for the requested level.
    #[must_use]
    pub fn for_level(level: ShareInfoLevel) -> Self {
        let share_info = match level {
            ShareInfoLevel::Level0 => {
                SrvsvcShareEnumUnion::Level0(SrvsvcShareInfo0Container::default())
            }
            ShareInfoLevel::Level1 => {
                SrvsvcShareEnumUnion::Level1(SrvsvcShareInfo1Container::default())
            }
        };

        Self { share_info }
    }

    /// Returns the numeric level associated with the share enumeration structure.
    #[must_use]
    pub const fn level(&self) -> ShareInfoLevel {
        self.share_info.level()
    }
}

/// Request payload for the SRVSVC `NetrShareEnum` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvsvcNetrShareEnumReq {
    /// Optional target server name.
    pub server_name: Option<String>,
    /// Requested share information structure.
    pub share_enum: SrvsvcShareEnumStruct,
    /// Preferred maximum response length. This maps to the C field
    /// `PreferedMaximumLength`.
    pub preferred_maximum_length: u32,
    /// Optional resume handle.
    pub resume_handle: Option<u32>,
}

impl SrvsvcNetrShareEnumReq {
    /// Creates a `NetrShareEnum` request for a share information level.
    #[must_use]
    pub fn new(level: ShareInfoLevel) -> Self {
        Self {
            server_name: None,
            share_enum: SrvsvcShareEnumStruct::for_level(level),
            preferred_maximum_length: u32::MAX,
            resume_handle: None,
        }
    }
}

/// Response payload for the SRVSVC `NetrShareEnum` operation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcNetrShareEnumRep {
    /// Share enumeration data returned by the server.
    pub share_enum: SrvsvcShareEnumStruct,
    /// Total number of entries available on the server.
    pub total_entries: u32,
    /// Optional resume handle returned by the server.
    pub resume_handle: Option<u32>,
    /// NET_API_STATUS value returned by the server.
    pub status: u32,
}

impl SrvsvcNetrShareEnumRep {
    /// Returns whether the response status is success.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status == 0
    }
}

/// Rust representation of the C `srvsvc_SHARE_INFO` switch union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrvsvcShareInfo {
    /// Level 1 share information.
    Level1(SrvsvcShareInfo1),
}

impl SrvsvcShareInfo {
    /// Returns the numeric switch level for this union arm.
    #[must_use]
    pub const fn level(&self) -> ShareInfoLevel {
        match self {
            Self::Level1(_) => ShareInfoLevel::Level1,
        }
    }
}

impl Default for SrvsvcShareInfo {
    fn default() -> Self {
        Self::Level1(SrvsvcShareInfo1::default())
    }
}

/// Request payload for the SRVSVC `NetrShareGetInfo` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvsvcNetrShareGetInfoReq {
    /// Optional target server name.
    pub server_name: Option<String>,
    /// Share name to query.
    pub net_name: String,
    /// Requested share information level.
    pub level: ShareInfoLevel,
}

impl SrvsvcNetrShareGetInfoReq {
    /// Creates a `NetrShareGetInfo` request.
    #[must_use]
    pub fn new(net_name: impl Into<String>, level: ShareInfoLevel) -> Self {
        Self {
            server_name: None,
            net_name: net_name.into(),
            level,
        }
    }
}

/// Response payload for the SRVSVC `NetrShareGetInfo` operation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcNetrShareGetInfoRep {
    /// Share information returned by the server.
    pub info_struct: SrvsvcShareInfo,
    /// NET_API_STATUS value returned by the server.
    pub status: u32,
}

impl SrvsvcNetrShareGetInfoRep {
    /// Returns whether the response status is success.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status == 0
    }
}

/// Generic SRVSVC response status wrapper matching the C `srvsvc_rep` helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SrvsvcRep {
    /// NET_API_STATUS value returned by the server.
    pub status: u32,
}

impl SrvsvcRep {
    /// Returns whether the response status is success.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.status == 0
    }
}

/// Skeleton corresponding to `srvsvc_SHARE_INFO_0_coder` in the C source.
///
/// # Errors
///
/// Always returns [`SrvsvcCodecError::ProtocolLogicNotImplemented`] until the
/// DCERPC/NDR codec is ported.
pub fn srvsvc_share_info_0_coder(
    _direction: SrvsvcCoderDirection,
    _value: &mut SrvsvcShareInfo0,
) -> SrvsvcResult<()> {
    Err(SrvsvcCodecError::ProtocolLogicNotImplemented)
}

/// Skeleton corresponding to `srvsvc_SHARE_INFO_0_CONTAINER_coder` in the C source.
///
/// # Errors
///
/// Always returns [`SrvsvcCodecError::ProtocolLogicNotImplemented`] until the
/// DCERPC/NDR codec is ported.
pub fn srvsvc_share_info_0_container_coder(
    _direction: SrvsvcCoderDirection,
    _value: &mut SrvsvcShareInfo0Container,
) -> SrvsvcResult<()> {
    Err(SrvsvcCodecError::ProtocolLogicNotImplemented)
}

/// Skeleton corresponding to `srvsvc_SHARE_INFO_1_coder` in the C source.
///
/// # Errors
///
/// Always returns [`SrvsvcCodecError::ProtocolLogicNotImplemented`] until the
/// DCERPC/NDR codec is ported.
pub fn srvsvc_share_info_1_coder(
    _direction: SrvsvcCoderDirection,
    _value: &mut SrvsvcShareInfo1,
) -> SrvsvcResult<()> {
    Err(SrvsvcCodecError::ProtocolLogicNotImplemented)
}

/// Skeleton corresponding to `srvsvc_SHARE_INFO_1_CONTAINER_coder` in the C source.
///
/// # Errors
///
/// Always returns [`SrvsvcCodecError::ProtocolLogicNotImplemented`] until the
/// DCERPC/NDR codec is ported.
pub fn srvsvc_share_info_1_container_coder(
    _direction: SrvsvcCoderDirection,
    _value: &mut SrvsvcShareInfo1Container,
) -> SrvsvcResult<()> {
    Err(SrvsvcCodecError::ProtocolLogicNotImplemented)
}

/// Skeleton corresponding to `srvsvc_SHARE_ENUM_UNION_coder` in the C source.
///
/// # Errors
///
/// Always returns [`SrvsvcCodecError::ProtocolLogicNotImplemented`] until the
/// DCERPC/NDR codec is ported.
pub fn srvsvc_share_enum_union_coder(
    _direction: SrvsvcCoderDirection,
    _value: &mut SrvsvcShareEnumUnion,
) -> SrvsvcResult<()> {
    Err(SrvsvcCodecError::ProtocolLogicNotImplemented)
}

/// Skeleton corresponding to `srvsvc_SHARE_ENUM_STRUCT_coder` in the C source.
///
/// # Errors
///
/// Always returns [`SrvsvcCodecError::ProtocolLogicNotImplemented`] until the
/// DCERPC/NDR codec is ported.
pub fn srvsvc_share_enum_struct_coder(
    _direction: SrvsvcCoderDirection,
    _value: &mut SrvsvcShareEnumStruct,
) -> SrvsvcResult<()> {
    Err(SrvsvcCodecError::ProtocolLogicNotImplemented)
}

/// Skeleton corresponding to `srvsvc_NetrShareEnum_req_coder` in the C source.
///
/// # Errors
///
/// Always returns [`SrvsvcCodecError::ProtocolLogicNotImplemented`] until the
/// DCERPC/NDR codec is ported.
pub fn srvsvc_netr_share_enum_req_coder(
    _direction: SrvsvcCoderDirection,
    _value: &mut SrvsvcNetrShareEnumReq,
) -> SrvsvcResult<()> {
    Err(SrvsvcCodecError::ProtocolLogicNotImplemented)
}

/// Skeleton corresponding to `srvsvc_NetrShareEnum_rep_coder` in the C source.
///
/// # Errors
///
/// Always returns [`SrvsvcCodecError::ProtocolLogicNotImplemented`] until the
/// DCERPC/NDR codec is ported.
pub fn srvsvc_netr_share_enum_rep_coder(
    _direction: SrvsvcCoderDirection,
    _value: &mut SrvsvcNetrShareEnumRep,
) -> SrvsvcResult<()> {
    Err(SrvsvcCodecError::ProtocolLogicNotImplemented)
}

/// Skeleton corresponding to `srvsvc_SHARE_INFO_coder` in the C source.
///
/// # Errors
///
/// Always returns [`SrvsvcCodecError::ProtocolLogicNotImplemented`] until the
/// DCERPC/NDR codec is ported.
pub fn srvsvc_share_info_coder(
    _direction: SrvsvcCoderDirection,
    _value: &mut SrvsvcShareInfo,
) -> SrvsvcResult<()> {
    Err(SrvsvcCodecError::ProtocolLogicNotImplemented)
}

/// Skeleton corresponding to `srvsvc_NetrShareGetInfo_req_coder` in the C source.
///
/// # Errors
///
/// Always returns [`SrvsvcCodecError::ProtocolLogicNotImplemented`] until the
/// DCERPC/NDR codec is ported.
pub fn srvsvc_netr_share_get_info_req_coder(
    _direction: SrvsvcCoderDirection,
    _value: &mut SrvsvcNetrShareGetInfoReq,
) -> SrvsvcResult<()> {
    Err(SrvsvcCodecError::ProtocolLogicNotImplemented)
}

/// Skeleton corresponding to `srvsvc_NetrShareGetInfo_rep_coder` in the C source.
///
/// # Errors
///
/// Always returns [`SrvsvcCodecError::ProtocolLogicNotImplemented`] until the
/// DCERPC/NDR codec is ported.
pub fn srvsvc_netr_share_get_info_rep_coder(
    _direction: SrvsvcCoderDirection,
    _value: &mut SrvsvcNetrShareGetInfoRep,
) -> SrvsvcResult<()> {
    Err(SrvsvcCodecError::ProtocolLogicNotImplemented)
}
