//! SRVSVC DCERPC command helpers migrated from `lib/dcerpc-srvsvc.c`.

use super::dcerpc::{DceRpcError, DceRpcResult, DceRpcUtf16, Direction, NdrCodec};
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrvsvcCodecError {
    /// The requested operation is invalid for this SRVSVC compatibility boundary.
    InvalidOperation(&'static str),
    /// The underlying DCERPC/NDR encoder or decoder rejected the payload.
    DceRpc(DceRpcError),
    /// The requested SRVSVC information level cannot be decoded in this context.
    UnsupportedShareInfoLevel(u32),
}

impl fmt::Display for SrvsvcCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOperation(message) => {
                write!(f, "invalid SRVSVC codec operation: {message}")
            }
            Self::DceRpc(err) => write!(f, "SRVSVC DCERPC codec error: {err:?}"),
            Self::UnsupportedShareInfoLevel(level) => {
                write!(f, "unsupported SRVSVC share information level {level}")
            }
        }
    }
}

impl std::error::Error for SrvsvcCodecError {}

impl From<DceRpcError> for SrvsvcCodecError {
    fn from(value: DceRpcError) -> Self {
        Self::DceRpc(value)
    }
}

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
    /// `SHARE_INFO_2` contains connection limits, path, and password fields.
    Level2,
    /// `SHARE_INFO_501` contains level 1 fields plus share flags.
    Level501,
    /// `SHARE_INFO_502` contains level 2 fields plus a security descriptor.
    Level502,
    /// `SHARE_INFO_503` contains level 502 fields plus the server name.
    Level503,
    /// An unmodeled share information level retained as its raw discriminator.
    Unknown(u32),
}

impl ShareInfoLevel {
    /// Returns the numeric DCERPC level discriminator.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Level0 => 0,
            Self::Level1 => 1,
            Self::Level2 => 2,
            Self::Level501 => 501,
            Self::Level502 => 502,
            Self::Level503 => 503,
            Self::Unknown(level) => level,
        }
    }

    /// Converts a numeric DCERPC level discriminator into a share info level.
    ///
    /// Unknown levels are preserved as [`ShareInfoLevel::Unknown`].
    pub const fn try_from_u32(level: u32) -> SrvsvcResult<Self> {
        match level {
            0 => Ok(Self::Level0),
            1 => Ok(Self::Level1),
            2 => Ok(Self::Level2),
            501 => Ok(Self::Level501),
            502 => Ok(Self::Level502),
            503 => Ok(Self::Level503),
            other => Ok(Self::Unknown(other)),
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

/// Rust representation of the C `srvsvc_SHARE_INFO_2` structure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo2 {
    /// Share net name.
    pub netname: Option<String>,
    /// Share type and share type flags.
    pub share_type: u32,
    /// Optional share remark.
    pub remark: Option<String>,
    /// Legacy share permissions field.
    pub permissions: u32,
    /// Maximum allowed simultaneous users.
    pub max_uses: u32,
    /// Current simultaneous users.
    pub current_uses: u32,
    /// Local path backing the share.
    pub path: Option<String>,
    /// Optional share password.
    pub passwd: Option<String>,
}

/// Rust representation of the C `srvsvc_SHARE_INFO_501` structure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo501 {
    /// Share net name.
    pub netname: Option<String>,
    /// Share type and share type flags.
    pub share_type: u32,
    /// Optional share remark.
    pub remark: Option<String>,
    /// SHARE_INFO_501 flags.
    pub flags: u32,
}

/// Rust representation of the C `srvsvc_SHARE_INFO_502` structure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo502 {
    /// Level 2-compatible share fields.
    pub info2: SrvsvcShareInfo2,
    /// Security descriptor byte count from the legacy reserved field.
    pub reserved: u32,
    /// Self-relative security descriptor bytes.
    pub security_descriptor: Vec<u8>,
}

/// Rust representation of the C `srvsvc_SHARE_INFO_503` structure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo503 {
    /// Level 2-compatible share fields.
    pub info2: SrvsvcShareInfo2,
    /// Server name that owns the share.
    pub servername: Option<String>,
    /// Security descriptor byte count from the legacy reserved field.
    pub reserved: u32,
    /// Self-relative security descriptor bytes.
    pub security_descriptor: Vec<u8>,
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

macro_rules! share_info_container {
    ($name:ident, $field:ident, $item:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name {
            /// Number of entries read by the server.
            pub entries_read: u32,
            /// Level-selected share entries.
            pub $field: Vec<$item>,
        }

        impl $name {
            /// Creates a share information container.
            #[must_use]
            pub fn new($field: Vec<$item>) -> Self {
                Self {
                    entries_read: $field.len() as u32,
                    $field,
                }
            }
        }
    };
}

share_info_container!(
    SrvsvcShareInfo2Container,
    share_info_2,
    SrvsvcShareInfo2,
    "Container for `[size_is(EntriesRead)] SHARE_INFO_2` arrays."
);
share_info_container!(
    SrvsvcShareInfo501Container,
    share_info_501,
    SrvsvcShareInfo501,
    "Container for `[size_is(EntriesRead)] SHARE_INFO_501` arrays."
);
share_info_container!(
    SrvsvcShareInfo502Container,
    share_info_502,
    SrvsvcShareInfo502,
    "Container for `[size_is(EntriesRead)] SHARE_INFO_502` arrays."
);
share_info_container!(
    SrvsvcShareInfo503Container,
    share_info_503,
    SrvsvcShareInfo503,
    "Container for `[size_is(EntriesRead)] SHARE_INFO_503` arrays."
);

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
    /// Level 2 share enumeration container.
    Level2(SrvsvcShareInfo2Container),
    /// Level 501 share enumeration container.
    Level501(SrvsvcShareInfo501Container),
    /// Level 502 share enumeration container.
    Level502(SrvsvcShareInfo502Container),
    /// Level 503 share enumeration container.
    Level503(SrvsvcShareInfo503Container),
    /// Raw payload for an unmodeled share enumeration level.
    Raw { level: u32, bytes: Vec<u8> },
}

impl SrvsvcShareEnumUnion {
    /// Returns the numeric switch level for this union arm.
    #[must_use]
    pub const fn level(&self) -> ShareInfoLevel {
        match self {
            Self::Level0(_) => ShareInfoLevel::Level0,
            Self::Level1(_) => ShareInfoLevel::Level1,
            Self::Level2(_) => ShareInfoLevel::Level2,
            Self::Level501(_) => ShareInfoLevel::Level501,
            Self::Level502(_) => ShareInfoLevel::Level502,
            Self::Level503(_) => ShareInfoLevel::Level503,
            Self::Raw { level, .. } => ShareInfoLevel::Unknown(*level),
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
            ShareInfoLevel::Level2 => {
                SrvsvcShareEnumUnion::Level2(SrvsvcShareInfo2Container::default())
            }
            ShareInfoLevel::Level501 => {
                SrvsvcShareEnumUnion::Level501(SrvsvcShareInfo501Container::default())
            }
            ShareInfoLevel::Level502 => {
                SrvsvcShareEnumUnion::Level502(SrvsvcShareInfo502Container::default())
            }
            ShareInfoLevel::Level503 => {
                SrvsvcShareEnumUnion::Level503(SrvsvcShareInfo503Container::default())
            }
            ShareInfoLevel::Unknown(level) => SrvsvcShareEnumUnion::Raw {
                level,
                bytes: Vec::new(),
            },
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
    /// Level 0 share information.
    Level0(SrvsvcShareInfo0),
    /// Level 1 share information.
    Level1(SrvsvcShareInfo1),
    /// Level 2 share information.
    Level2(SrvsvcShareInfo2),
    /// Level 501 share information.
    Level501(SrvsvcShareInfo501),
    /// Level 502 share information.
    Level502(SrvsvcShareInfo502),
    /// Level 503 share information.
    Level503(SrvsvcShareInfo503),
    /// Raw payload for an unmodeled share information level.
    Raw { level: u32, bytes: Vec<u8> },
}

impl SrvsvcShareInfo {
    /// Returns the numeric switch level for this union arm.
    #[must_use]
    pub const fn level(&self) -> ShareInfoLevel {
        match self {
            Self::Level0(_) => ShareInfoLevel::Level0,
            Self::Level1(_) => ShareInfoLevel::Level1,
            Self::Level2(_) => ShareInfoLevel::Level2,
            Self::Level501(_) => ShareInfoLevel::Level501,
            Self::Level502(_) => ShareInfoLevel::Level502,
            Self::Level503(_) => ShareInfoLevel::Level503,
            Self::Raw { level, .. } => ShareInfoLevel::Unknown(*level),
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

/// Encodes a SRVSVC `NetrShareEnum` request body.
pub fn encode_netr_share_enum_request(req: &SrvsvcNetrShareEnumReq) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_netr_share_enum_request(&mut codec, &mut req.clone())?;
    Ok(codec.into_bytes())
}

/// Decodes a SRVSVC `NetrShareEnum` response body.
pub fn decode_netr_share_enum_reply(bytes: &[u8]) -> DceRpcResult<SrvsvcNetrShareEnumRep> {
    let mut rep = SrvsvcNetrShareEnumRep::default();
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_netr_share_enum_reply(&mut codec, &mut rep)?;
    Ok(rep)
}

/// Decodes a SRVSVC `NetrShareEnum` request body.
pub fn decode_netr_share_enum_request(bytes: &[u8]) -> DceRpcResult<SrvsvcNetrShareEnumReq> {
    let mut req = SrvsvcNetrShareEnumReq::new(ShareInfoLevel::Level1);
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_netr_share_enum_request(&mut codec, &mut req)?;
    Ok(req)
}

/// Encodes a SRVSVC `NetrShareEnum` response body.
pub fn encode_netr_share_enum_reply(rep: &SrvsvcNetrShareEnumRep) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_netr_share_enum_reply(&mut codec, &mut rep.clone())?;
    Ok(codec.into_bytes())
}

/// Encodes a SRVSVC `NetrShareGetInfo` request body.
pub fn encode_netr_share_get_info_request(
    req: &SrvsvcNetrShareGetInfoReq,
) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_netr_share_get_info_request(&mut codec, &mut req.clone())?;
    Ok(codec.into_bytes())
}

/// Decodes a SRVSVC `NetrShareGetInfo` response body.
pub fn decode_netr_share_get_info_reply(bytes: &[u8]) -> DceRpcResult<SrvsvcNetrShareGetInfoRep> {
    let mut rep = SrvsvcNetrShareGetInfoRep::default();
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_netr_share_get_info_reply(&mut codec, &mut rep)?;
    Ok(rep)
}

/// Decodes a SRVSVC `NetrShareGetInfo` request body.
pub fn decode_netr_share_get_info_request(bytes: &[u8]) -> DceRpcResult<SrvsvcNetrShareGetInfoReq> {
    let mut req = SrvsvcNetrShareGetInfoReq::new(String::new(), ShareInfoLevel::Level1);
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_netr_share_get_info_request(&mut codec, &mut req)?;
    Ok(req)
}

/// Encodes a SRVSVC `NetrShareGetInfo` response body.
pub fn encode_netr_share_get_info_reply(rep: &SrvsvcNetrShareGetInfoRep) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_netr_share_get_info_reply(&mut codec, &mut rep.clone())?;
    Ok(codec.into_bytes())
}

fn code_netr_share_enum_request(
    codec: &mut NdrCodec,
    req: &mut SrvsvcNetrShareEnumReq,
) -> DceRpcResult<()> {
    code_optional_string(codec, &mut req.server_name)?;
    code_share_enum_struct(codec, &mut req.share_enum)?;
    codec.code_u32(&mut req.preferred_maximum_length)?;
    let present = codec.code_unique_pointer_present(req.resume_handle.is_some())?;
    if present {
        let mut resume = req
            .resume_handle
            .map_or_else(u32::default, core::convert::identity);
        codec.code_u32(&mut resume)?;
        req.resume_handle = Some(resume);
    } else {
        req.resume_handle = None;
    }
    Ok(())
}

fn code_netr_share_enum_reply(
    codec: &mut NdrCodec,
    rep: &mut SrvsvcNetrShareEnumRep,
) -> DceRpcResult<()> {
    code_share_enum_struct(codec, &mut rep.share_enum)?;
    codec.code_u32(&mut rep.total_entries)?;
    let present = codec.code_unique_pointer_present(rep.resume_handle.is_some())?;
    if present {
        let mut resume = rep
            .resume_handle
            .map_or_else(u32::default, core::convert::identity);
        codec.code_u32(&mut resume)?;
        rep.resume_handle = Some(resume);
    } else {
        rep.resume_handle = None;
    }
    codec.code_u32(&mut rep.status)
}

fn code_netr_share_get_info_request(
    codec: &mut NdrCodec,
    req: &mut SrvsvcNetrShareGetInfoReq,
) -> DceRpcResult<()> {
    code_optional_string(codec, &mut req.server_name)?;
    let mut name = Some(req.net_name.clone());
    let present = codec.code_unique_pointer_present(true)?;
    if !present {
        return Err(DceRpcError::NullPointer);
    }
    code_optional_string_payload(codec, &mut name)?;
    if let Some(decoded) = name {
        req.net_name = decoded;
    }
    let mut level = req.level.as_u32();
    codec.code_u32(&mut level)?;
    req.level = share_level(level)?;
    Ok(())
}

fn code_netr_share_get_info_reply(
    codec: &mut NdrCodec,
    rep: &mut SrvsvcNetrShareGetInfoRep,
) -> DceRpcResult<()> {
    let present = codec.code_unique_pointer_present(true)?;
    if !present {
        return Err(DceRpcError::NullPointer);
    }
    code_share_info(codec, &mut rep.info_struct)?;
    codec.code_u32(&mut rep.status)
}

fn code_share_enum_struct(
    codec: &mut NdrCodec,
    value: &mut SrvsvcShareEnumStruct,
) -> DceRpcResult<()> {
    let mut level = value.level().as_u32();
    codec.code_u32(&mut level)?;
    let decoded_level = share_level(level)?;
    if matches!(codec.direction(), Direction::Decode | Direction::Response) {
        *value = SrvsvcShareEnumStruct::for_level(decoded_level);
    }
    code_share_enum_union(codec, &mut value.share_info)
}

fn code_share_enum_union(
    codec: &mut NdrCodec,
    value: &mut SrvsvcShareEnumUnion,
) -> DceRpcResult<()> {
    let mut level = value.level().as_u32() as u64;
    codec.code_u3264(&mut level)?;
    let level32 =
        u32::try_from(level).map_err(|_| DceRpcError::CountOutOfRange { count: usize::MAX })?;
    match share_level(level32)? {
        ShareInfoLevel::Level0 => {
            if matches!(codec.direction(), Direction::Decode | Direction::Response) {
                *value = SrvsvcShareEnumUnion::Level0(SrvsvcShareInfo0Container::default());
            }
            if let SrvsvcShareEnumUnion::Level0(container) = value {
                let present = codec.code_unique_pointer_present(true)?;
                if !present {
                    return Err(DceRpcError::NullPointer);
                }
                code_share_info_0_container(codec, container)?;
            }
        }
        ShareInfoLevel::Level1 => {
            if matches!(codec.direction(), Direction::Decode | Direction::Response) {
                *value = SrvsvcShareEnumUnion::Level1(SrvsvcShareInfo1Container::default());
            }
            if let SrvsvcShareEnumUnion::Level1(container) = value {
                let present = codec.code_unique_pointer_present(true)?;
                if !present {
                    return Err(DceRpcError::NullPointer);
                }
                code_share_info_1_container(codec, container)?;
            }
        }
        ShareInfoLevel::Level2 => {
            if matches!(codec.direction(), Direction::Decode | Direction::Response) {
                *value = SrvsvcShareEnumUnion::Level2(SrvsvcShareInfo2Container::default());
            }
            if let SrvsvcShareEnumUnion::Level2(container) = value {
                code_present_container(codec, |codec| {
                    code_share_info_2_container(codec, container)
                })?;
            }
        }
        ShareInfoLevel::Level501 => {
            if matches!(codec.direction(), Direction::Decode | Direction::Response) {
                *value = SrvsvcShareEnumUnion::Level501(SrvsvcShareInfo501Container::default());
            }
            if let SrvsvcShareEnumUnion::Level501(container) = value {
                code_present_container(codec, |codec| {
                    code_share_info_501_container(codec, container)
                })?;
            }
        }
        ShareInfoLevel::Level502 => {
            if matches!(codec.direction(), Direction::Decode | Direction::Response) {
                *value = SrvsvcShareEnumUnion::Level502(SrvsvcShareInfo502Container::default());
            }
            if let SrvsvcShareEnumUnion::Level502(container) = value {
                code_present_container(codec, |codec| {
                    code_share_info_502_container(codec, container)
                })?;
            }
        }
        ShareInfoLevel::Level503 => {
            if matches!(codec.direction(), Direction::Decode | Direction::Response) {
                *value = SrvsvcShareEnumUnion::Level503(SrvsvcShareInfo503Container::default());
            }
            if let SrvsvcShareEnumUnion::Level503(container) = value {
                code_present_container(codec, |codec| {
                    code_share_info_503_container(codec, container)
                })?;
            }
        }
        ShareInfoLevel::Unknown(level) => {
            if let SrvsvcShareEnumUnion::Raw { bytes, .. } = value {
                if matches!(codec.direction(), Direction::Encode | Direction::Request) {
                    let len = bytes.len();
                    codec.code_bytes(bytes, len)?;
                    return Ok(());
                }
            }
            return Err(DceRpcError::CountOutOfRange {
                count: level as usize,
            });
        }
    }
    Ok(())
}

fn code_share_info(codec: &mut NdrCodec, value: &mut SrvsvcShareInfo) -> DceRpcResult<()> {
    let mut level = value.level().as_u32() as u64;
    codec.code_u3264(&mut level)?;
    let level32 =
        u32::try_from(level).map_err(|_| DceRpcError::CountOutOfRange { count: usize::MAX })?;
    match share_level(level32)? {
        ShareInfoLevel::Level0 => {
            if matches!(codec.direction(), Direction::Decode | Direction::Response) {
                *value = SrvsvcShareInfo::Level0(SrvsvcShareInfo0::default());
            }
            let SrvsvcShareInfo::Level0(info) = value else {
                return Err(DceRpcError::CountOutOfRange { count: 0 });
            };
            let present = codec.code_unique_pointer_present(true)?;
            if !present {
                return Err(DceRpcError::NullPointer);
            }
            code_share_info_0(codec, info)?;
            Ok(())
        }
        ShareInfoLevel::Level1 => {
            if matches!(codec.direction(), Direction::Decode | Direction::Response) {
                *value = SrvsvcShareInfo::Level1(SrvsvcShareInfo1::default());
            }
            let SrvsvcShareInfo::Level1(info) = value else {
                return Err(DceRpcError::CountOutOfRange { count: 1 });
            };
            let present = codec.code_unique_pointer_present(true)?;
            if !present {
                return Err(DceRpcError::NullPointer);
            }
            code_share_info_1(codec, info)?;
            Ok(())
        }
        ShareInfoLevel::Level2 => {
            if matches!(codec.direction(), Direction::Decode | Direction::Response) {
                *value = SrvsvcShareInfo::Level2(SrvsvcShareInfo2::default());
            }
            let SrvsvcShareInfo::Level2(info) = value else {
                return Err(DceRpcError::CountOutOfRange { count: 2 });
            };
            code_present_container(codec, |codec| code_share_info_2(codec, info))
        }
        ShareInfoLevel::Level501 => {
            if matches!(codec.direction(), Direction::Decode | Direction::Response) {
                *value = SrvsvcShareInfo::Level501(SrvsvcShareInfo501::default());
            }
            let SrvsvcShareInfo::Level501(info) = value else {
                return Err(DceRpcError::CountOutOfRange { count: 501 });
            };
            code_present_container(codec, |codec| code_share_info_501(codec, info))
        }
        ShareInfoLevel::Level502 => {
            if matches!(codec.direction(), Direction::Decode | Direction::Response) {
                *value = SrvsvcShareInfo::Level502(SrvsvcShareInfo502::default());
            }
            let SrvsvcShareInfo::Level502(info) = value else {
                return Err(DceRpcError::CountOutOfRange { count: 502 });
            };
            code_present_container(codec, |codec| code_share_info_502(codec, info))
        }
        ShareInfoLevel::Level503 => {
            if matches!(codec.direction(), Direction::Decode | Direction::Response) {
                *value = SrvsvcShareInfo::Level503(SrvsvcShareInfo503::default());
            }
            let SrvsvcShareInfo::Level503(info) = value else {
                return Err(DceRpcError::CountOutOfRange { count: 503 });
            };
            code_present_container(codec, |codec| code_share_info_503(codec, info))
        }
        ShareInfoLevel::Unknown(level) => {
            if let SrvsvcShareInfo::Raw { bytes, .. } = value {
                if matches!(codec.direction(), Direction::Encode | Direction::Request) {
                    let len = bytes.len();
                    codec.code_bytes(bytes, len)?;
                    return Ok(());
                }
            }
            Err(DceRpcError::CountOutOfRange {
                count: level as usize,
            })
        }
    }
}

fn code_share_info_0_container(
    codec: &mut NdrCodec,
    container: &mut SrvsvcShareInfo0Container,
) -> DceRpcResult<()> {
    if matches!(codec.direction(), Direction::Encode | Direction::Request) {
        container.entries_read = u32::try_from(container.share_info_0.len()).map_err(|_| {
            DceRpcError::CountOutOfRange {
                count: container.share_info_0.len(),
            }
        })?;
    }
    codec.code_u32(&mut container.entries_read)?;
    let count = u32_to_usize(container.entries_read);
    let present = codec.code_unique_pointer_present(container.entries_read != 0)?;
    if !present {
        container.share_info_0.clear();
        return Ok(());
    }
    container
        .share_info_0
        .resize_with(count, SrvsvcShareInfo0::default);
    let mut conformant = u64::from(container.entries_read);
    codec.code_count(&mut conformant)?;
    for item in &mut container.share_info_0 {
        code_share_info_0(codec, item)?;
    }
    Ok(())
}

fn code_share_info_1_container(
    codec: &mut NdrCodec,
    container: &mut SrvsvcShareInfo1Container,
) -> DceRpcResult<()> {
    if matches!(codec.direction(), Direction::Encode | Direction::Request) {
        container.entries_read = u32::try_from(container.share_info_1.len()).map_err(|_| {
            DceRpcError::CountOutOfRange {
                count: container.share_info_1.len(),
            }
        })?;
    }
    codec.code_u32(&mut container.entries_read)?;
    let count = u32_to_usize(container.entries_read);
    let present = codec.code_unique_pointer_present(container.entries_read != 0)?;
    if !present {
        container.share_info_1.clear();
        return Ok(());
    }
    container
        .share_info_1
        .resize_with(count, SrvsvcShareInfo1::default);
    let mut conformant = u64::from(container.entries_read);
    codec.code_count(&mut conformant)?;
    for item in &mut container.share_info_1 {
        code_share_info_1(codec, item)?;
    }
    Ok(())
}

fn code_share_info_2_container(
    codec: &mut NdrCodec,
    container: &mut SrvsvcShareInfo2Container,
) -> DceRpcResult<()> {
    code_container(
        codec,
        &mut container.entries_read,
        &mut container.share_info_2,
        SrvsvcShareInfo2::default,
        code_share_info_2,
    )
}

fn code_share_info_501_container(
    codec: &mut NdrCodec,
    container: &mut SrvsvcShareInfo501Container,
) -> DceRpcResult<()> {
    code_container(
        codec,
        &mut container.entries_read,
        &mut container.share_info_501,
        SrvsvcShareInfo501::default,
        code_share_info_501,
    )
}

fn code_share_info_502_container(
    codec: &mut NdrCodec,
    container: &mut SrvsvcShareInfo502Container,
) -> DceRpcResult<()> {
    code_container(
        codec,
        &mut container.entries_read,
        &mut container.share_info_502,
        SrvsvcShareInfo502::default,
        code_share_info_502,
    )
}

fn code_share_info_503_container(
    codec: &mut NdrCodec,
    container: &mut SrvsvcShareInfo503Container,
) -> DceRpcResult<()> {
    code_container(
        codec,
        &mut container.entries_read,
        &mut container.share_info_503,
        SrvsvcShareInfo503::default,
        code_share_info_503,
    )
}

fn code_container<T>(
    codec: &mut NdrCodec,
    entries_read: &mut u32,
    items: &mut Vec<T>,
    default: impl FnMut() -> T,
    mut code_item: impl FnMut(&mut NdrCodec, &mut T) -> DceRpcResult<()>,
) -> DceRpcResult<()> {
    if matches!(codec.direction(), Direction::Encode | Direction::Request) {
        *entries_read = u32::try_from(items.len())
            .map_err(|_| DceRpcError::CountOutOfRange { count: items.len() })?;
    }
    codec.code_u32(entries_read)?;
    let count = u32_to_usize(*entries_read);
    let present = codec.code_unique_pointer_present(*entries_read != 0)?;
    if !present {
        items.clear();
        return Ok(());
    }
    items.resize_with(count, default);
    let mut conformant = u64::from(*entries_read);
    codec.code_count(&mut conformant)?;
    for item in items {
        code_item(codec, item)?;
    }
    Ok(())
}

fn code_present_container(
    codec: &mut NdrCodec,
    code_value: impl FnOnce(&mut NdrCodec) -> DceRpcResult<()>,
) -> DceRpcResult<()> {
    let present = codec.code_unique_pointer_present(true)?;
    if !present {
        return Err(DceRpcError::NullPointer);
    }
    code_value(codec)
}

fn code_share_info_0(codec: &mut NdrCodec, value: &mut SrvsvcShareInfo0) -> DceRpcResult<()> {
    code_optional_string(codec, &mut value.netname)
}

fn code_share_info_1(codec: &mut NdrCodec, value: &mut SrvsvcShareInfo1) -> DceRpcResult<()> {
    code_optional_string(codec, &mut value.netname)?;
    codec.code_u32(&mut value.share_type)?;
    code_optional_string(codec, &mut value.remark)
}

fn code_share_info_2(codec: &mut NdrCodec, value: &mut SrvsvcShareInfo2) -> DceRpcResult<()> {
    code_optional_string(codec, &mut value.netname)?;
    codec.code_u32(&mut value.share_type)?;
    code_optional_string(codec, &mut value.remark)?;
    codec.code_u32(&mut value.permissions)?;
    codec.code_u32(&mut value.max_uses)?;
    codec.code_u32(&mut value.current_uses)?;
    code_optional_string(codec, &mut value.path)?;
    code_optional_string(codec, &mut value.passwd)
}

fn code_share_info_501(codec: &mut NdrCodec, value: &mut SrvsvcShareInfo501) -> DceRpcResult<()> {
    code_optional_string(codec, &mut value.netname)?;
    codec.code_u32(&mut value.share_type)?;
    code_optional_string(codec, &mut value.remark)?;
    codec.code_u32(&mut value.flags)
}

fn code_share_info_502(codec: &mut NdrCodec, value: &mut SrvsvcShareInfo502) -> DceRpcResult<()> {
    code_share_info_2(codec, &mut value.info2)?;
    code_security_descriptor(codec, &mut value.reserved, &mut value.security_descriptor)
}

fn code_share_info_503(codec: &mut NdrCodec, value: &mut SrvsvcShareInfo503) -> DceRpcResult<()> {
    code_share_info_2(codec, &mut value.info2)?;
    code_optional_string(codec, &mut value.servername)?;
    code_security_descriptor(codec, &mut value.reserved, &mut value.security_descriptor)
}

fn code_security_descriptor(
    codec: &mut NdrCodec,
    byte_count: &mut u32,
    bytes: &mut Vec<u8>,
) -> DceRpcResult<()> {
    if matches!(codec.direction(), Direction::Encode | Direction::Request) {
        *byte_count = u32::try_from(bytes.len())
            .map_err(|_| DceRpcError::CountOutOfRange { count: bytes.len() })?;
    }
    codec.code_u32(byte_count)?;
    let present = codec.code_unique_pointer_present(*byte_count != 0)?;
    if !present {
        bytes.clear();
        return Ok(());
    }
    let mut count = u64::from(*byte_count);
    codec.code_count(&mut count)?;
    let len = u32_to_usize(*byte_count);
    codec.code_bytes(bytes, len)
}

fn code_optional_string(codec: &mut NdrCodec, value: &mut Option<String>) -> DceRpcResult<()> {
    let present = codec.code_unique_pointer_present(value.is_some())?;
    if present {
        code_optional_string_payload(codec, value)?;
    } else {
        *value = None;
    }
    Ok(())
}

fn code_optional_string_payload(
    codec: &mut NdrCodec,
    value: &mut Option<String>,
) -> DceRpcResult<()> {
    let mut utf = DceRpcUtf16 {
        utf8: value.clone(),
        ..DceRpcUtf16::default()
    };
    codec.code_utf16(&mut utf, true)?;
    *value = utf.utf8;
    Ok(())
}

fn u32_to_usize(value: u32) -> usize {
    match usize::try_from(value) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    }
}

fn share_level(level: u32) -> DceRpcResult<ShareInfoLevel> {
    ShareInfoLevel::try_from_u32(level).map_err(|_| DceRpcError::CountOutOfRange {
        count: level as usize,
    })
}

/// Decodes a standalone `srvsvc_SHARE_INFO_0` NDR payload.
pub fn decode_share_info_0(bytes: &[u8]) -> DceRpcResult<SrvsvcShareInfo0> {
    let mut value = SrvsvcShareInfo0::default();
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_share_info_0(&mut codec, &mut value)?;
    Ok(value)
}

/// Decodes a standalone `srvsvc_SHARE_INFO_0_CONTAINER` NDR payload.
pub fn decode_share_info_0_container(bytes: &[u8]) -> DceRpcResult<SrvsvcShareInfo0Container> {
    let mut value = SrvsvcShareInfo0Container::default();
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_share_info_0_container(&mut codec, &mut value)?;
    Ok(value)
}

/// Decodes a standalone `srvsvc_SHARE_INFO_1` NDR payload.
pub fn decode_share_info_1(bytes: &[u8]) -> DceRpcResult<SrvsvcShareInfo1> {
    let mut value = SrvsvcShareInfo1::default();
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_share_info_1(&mut codec, &mut value)?;
    Ok(value)
}

/// Decodes a standalone `srvsvc_SHARE_INFO_1_CONTAINER` NDR payload.
pub fn decode_share_info_1_container(bytes: &[u8]) -> DceRpcResult<SrvsvcShareInfo1Container> {
    let mut value = SrvsvcShareInfo1Container::default();
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_share_info_1_container(&mut codec, &mut value)?;
    Ok(value)
}

/// Decodes a standalone `srvsvc_SHARE_ENUM_UNION` NDR payload.
pub fn decode_share_enum_union(bytes: &[u8]) -> DceRpcResult<SrvsvcShareEnumUnion> {
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    let mut level = 0u64;
    codec.code_u3264(&mut level)?;
    let level32 =
        u32::try_from(level).map_err(|_| DceRpcError::CountOutOfRange { count: usize::MAX })?;
    let mut value = SrvsvcShareEnumStruct::for_level(share_level(level32)?).share_info;
    match &mut value {
        SrvsvcShareEnumUnion::Level0(container) => {
            let present = codec.code_unique_pointer_present(true)?;
            if !present {
                return Err(DceRpcError::NullPointer);
            }
            code_share_info_0_container(&mut codec, container)?;
        }
        SrvsvcShareEnumUnion::Level1(container) => {
            let present = codec.code_unique_pointer_present(true)?;
            if !present {
                return Err(DceRpcError::NullPointer);
            }
            code_share_info_1_container(&mut codec, container)?;
        }
        SrvsvcShareEnumUnion::Level2(container) => {
            code_present_container(&mut codec, |codec| {
                code_share_info_2_container(codec, container)
            })?;
        }
        SrvsvcShareEnumUnion::Level501(container) => {
            code_present_container(&mut codec, |codec| {
                code_share_info_501_container(codec, container)
            })?;
        }
        SrvsvcShareEnumUnion::Level502(container) => {
            code_present_container(&mut codec, |codec| {
                code_share_info_502_container(codec, container)
            })?;
        }
        SrvsvcShareEnumUnion::Level503(container) => {
            code_present_container(&mut codec, |codec| {
                code_share_info_503_container(codec, container)
            })?;
        }
        SrvsvcShareEnumUnion::Raw { bytes, .. } => {
            let len = codec.bytes().len().saturating_sub(codec.offset());
            codec.code_bytes(bytes, len)?;
        }
    }
    Ok(value)
}

/// Decodes a standalone `srvsvc_SHARE_ENUM_STRUCT` NDR payload.
pub fn decode_share_enum_struct(bytes: &[u8]) -> DceRpcResult<SrvsvcShareEnumStruct> {
    let mut value = SrvsvcShareEnumStruct::default();
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    code_share_enum_struct(&mut codec, &mut value)?;
    Ok(value)
}

/// Decodes a standalone `srvsvc_SHARE_INFO` NDR payload.
pub fn decode_share_info(bytes: &[u8]) -> DceRpcResult<SrvsvcShareInfo> {
    let mut codec = NdrCodec::decoder(bytes.to_vec());
    let mut level = 0u64;
    codec.code_u3264(&mut level)?;
    let level32 =
        u32::try_from(level).map_err(|_| DceRpcError::CountOutOfRange { count: usize::MAX })?;
    let mut value = match share_level(level32)? {
        ShareInfoLevel::Level0 => SrvsvcShareInfo::Level0(SrvsvcShareInfo0::default()),
        ShareInfoLevel::Level1 => SrvsvcShareInfo::Level1(SrvsvcShareInfo1::default()),
        ShareInfoLevel::Level2 => SrvsvcShareInfo::Level2(SrvsvcShareInfo2::default()),
        ShareInfoLevel::Level501 => SrvsvcShareInfo::Level501(SrvsvcShareInfo501::default()),
        ShareInfoLevel::Level502 => SrvsvcShareInfo::Level502(SrvsvcShareInfo502::default()),
        ShareInfoLevel::Level503 => SrvsvcShareInfo::Level503(SrvsvcShareInfo503::default()),
        ShareInfoLevel::Unknown(level) => SrvsvcShareInfo::Raw {
            level,
            bytes: Vec::new(),
        },
    };
    match &mut value {
        SrvsvcShareInfo::Level0(info) => {
            let present = codec.code_unique_pointer_present(true)?;
            if !present {
                return Err(DceRpcError::NullPointer);
            }
            code_share_info_0(&mut codec, info)?;
        }
        SrvsvcShareInfo::Level1(info) => {
            let present = codec.code_unique_pointer_present(true)?;
            if !present {
                return Err(DceRpcError::NullPointer);
            }
            code_share_info_1(&mut codec, info)?;
        }
        SrvsvcShareInfo::Level2(info) => {
            code_present_container(&mut codec, |codec| code_share_info_2(codec, info))?;
        }
        SrvsvcShareInfo::Level501(info) => {
            code_present_container(&mut codec, |codec| code_share_info_501(codec, info))?;
        }
        SrvsvcShareInfo::Level502(info) => {
            code_present_container(&mut codec, |codec| code_share_info_502(codec, info))?;
        }
        SrvsvcShareInfo::Level503(info) => {
            code_present_container(&mut codec, |codec| code_share_info_503(codec, info))?;
        }
        SrvsvcShareInfo::Raw { bytes, .. } => {
            let len = codec.bytes().len().saturating_sub(codec.offset());
            codec.code_bytes(bytes, len)?;
        }
    }
    Ok(value)
}

fn encode_share_info_0(value: &SrvsvcShareInfo0) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_share_info_0(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

fn encode_share_info_0_container(value: &SrvsvcShareInfo0Container) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_share_info_0_container(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

fn encode_share_info_1(value: &SrvsvcShareInfo1) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_share_info_1(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

fn encode_share_info_1_container(value: &SrvsvcShareInfo1Container) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_share_info_1_container(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

fn encode_share_enum_union(value: &SrvsvcShareEnumUnion) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_share_enum_union(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

fn encode_share_enum_struct(value: &SrvsvcShareEnumStruct) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_share_enum_struct(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

fn encode_share_info(value: &SrvsvcShareInfo) -> DceRpcResult<Vec<u8>> {
    let mut codec = NdrCodec::encoder();
    code_share_info(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

impl SrvsvcRep {
    /// Returns whether the response status is success.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.status == 0
    }
}

/// Encodes `srvsvc_SHARE_INFO_0` through the migrated NDR codec.
///
/// # Errors
///
/// Returns [`SrvsvcCodecError::DceRpc`] when NDR coding rejects the value.
pub fn srvsvc_share_info_0_coder(
    direction: SrvsvcCoderDirection,
    value: &mut SrvsvcShareInfo0,
) -> SrvsvcResult<()> {
    let bytes = encode_share_info_0(value)?;
    if matches!(direction, SrvsvcCoderDirection::Decode) {
        *value = decode_share_info_0(&bytes)?;
    }
    Ok(())
}

/// Encodes `srvsvc_SHARE_INFO_0_CONTAINER` through the migrated NDR codec.
///
/// # Errors
///
/// Returns [`SrvsvcCodecError::DceRpc`] when NDR coding rejects the value.
pub fn srvsvc_share_info_0_container_coder(
    direction: SrvsvcCoderDirection,
    value: &mut SrvsvcShareInfo0Container,
) -> SrvsvcResult<()> {
    let bytes = encode_share_info_0_container(value)?;
    if matches!(direction, SrvsvcCoderDirection::Decode) {
        *value = decode_share_info_0_container(&bytes)?;
    }
    Ok(())
}

/// Encodes `srvsvc_SHARE_INFO_1` through the migrated NDR codec.
///
/// # Errors
///
/// Returns [`SrvsvcCodecError::DceRpc`] when NDR coding rejects the value.
pub fn srvsvc_share_info_1_coder(
    direction: SrvsvcCoderDirection,
    value: &mut SrvsvcShareInfo1,
) -> SrvsvcResult<()> {
    let bytes = encode_share_info_1(value)?;
    if matches!(direction, SrvsvcCoderDirection::Decode) {
        *value = decode_share_info_1(&bytes)?;
    }
    Ok(())
}

/// Encodes `srvsvc_SHARE_INFO_1_CONTAINER` through the migrated NDR codec.
///
/// # Errors
///
/// Returns [`SrvsvcCodecError::DceRpc`] when NDR coding rejects the value.
pub fn srvsvc_share_info_1_container_coder(
    direction: SrvsvcCoderDirection,
    value: &mut SrvsvcShareInfo1Container,
) -> SrvsvcResult<()> {
    let bytes = encode_share_info_1_container(value)?;
    if matches!(direction, SrvsvcCoderDirection::Decode) {
        *value = decode_share_info_1_container(&bytes)?;
    }
    Ok(())
}

/// Encodes `srvsvc_SHARE_ENUM_UNION` through the migrated NDR codec.
///
/// # Errors
///
/// Returns [`SrvsvcCodecError::DceRpc`] when NDR coding rejects the value.
pub fn srvsvc_share_enum_union_coder(
    direction: SrvsvcCoderDirection,
    value: &mut SrvsvcShareEnumUnion,
) -> SrvsvcResult<()> {
    let bytes = encode_share_enum_union(value)?;
    if matches!(direction, SrvsvcCoderDirection::Decode) {
        *value = decode_share_enum_union(&bytes)?;
    }
    Ok(())
}

/// Encodes `srvsvc_SHARE_ENUM_STRUCT` through the migrated NDR codec.
///
/// # Errors
///
/// Returns [`SrvsvcCodecError::DceRpc`] when NDR coding rejects the value.
pub fn srvsvc_share_enum_struct_coder(
    direction: SrvsvcCoderDirection,
    value: &mut SrvsvcShareEnumStruct,
) -> SrvsvcResult<()> {
    let bytes = encode_share_enum_struct(value)?;
    if matches!(direction, SrvsvcCoderDirection::Decode) {
        *value = decode_share_enum_struct(&bytes)?;
    }
    Ok(())
}

/// Encodes `srvsvc_NetrShareEnum_req` through the migrated NDR codec.
///
/// # Errors
///
/// Returns [`SrvsvcCodecError::DceRpc`] when NDR coding rejects the value.
pub fn srvsvc_netr_share_enum_req_coder(
    direction: SrvsvcCoderDirection,
    value: &mut SrvsvcNetrShareEnumReq,
) -> SrvsvcResult<()> {
    let bytes = encode_netr_share_enum_request(value)?;
    if matches!(direction, SrvsvcCoderDirection::Decode) {
        *value = decode_netr_share_enum_request(&bytes)?;
    }
    Ok(())
}

/// Encodes `srvsvc_NetrShareEnum_rep` through the migrated NDR codec.
///
/// # Errors
///
/// Returns [`SrvsvcCodecError::DceRpc`] when NDR coding rejects the value.
pub fn srvsvc_netr_share_enum_rep_coder(
    direction: SrvsvcCoderDirection,
    value: &mut SrvsvcNetrShareEnumRep,
) -> SrvsvcResult<()> {
    let bytes = encode_netr_share_enum_reply(value)?;
    if matches!(direction, SrvsvcCoderDirection::Decode) {
        *value = decode_netr_share_enum_reply(&bytes)?;
    }
    Ok(())
}

/// Encodes `srvsvc_SHARE_INFO` through the migrated NDR codec.
///
/// # Errors
///
/// Returns [`SrvsvcCodecError::DceRpc`] when NDR coding rejects the value.
pub fn srvsvc_share_info_coder(
    direction: SrvsvcCoderDirection,
    value: &mut SrvsvcShareInfo,
) -> SrvsvcResult<()> {
    let bytes = encode_share_info(value)?;
    if matches!(direction, SrvsvcCoderDirection::Decode) {
        *value = decode_share_info(&bytes)?;
    }
    Ok(())
}

/// Encodes `srvsvc_NetrShareGetInfo_req` through the migrated NDR codec.
///
/// # Errors
///
/// Returns [`SrvsvcCodecError::DceRpc`] when NDR coding rejects the value.
pub fn srvsvc_netr_share_get_info_req_coder(
    direction: SrvsvcCoderDirection,
    value: &mut SrvsvcNetrShareGetInfoReq,
) -> SrvsvcResult<()> {
    let bytes = encode_netr_share_get_info_request(value)?;
    if matches!(direction, SrvsvcCoderDirection::Decode) {
        *value = decode_netr_share_get_info_request(&bytes)?;
    }
    Ok(())
}

/// Encodes `srvsvc_NetrShareGetInfo_rep` through the migrated NDR codec.
///
/// # Errors
///
/// Returns [`SrvsvcCodecError::DceRpc`] when NDR coding rejects the value.
pub fn srvsvc_netr_share_get_info_rep_coder(
    direction: SrvsvcCoderDirection,
    value: &mut SrvsvcNetrShareGetInfoRep,
) -> SrvsvcResult<()> {
    let bytes = encode_netr_share_get_info_reply(value)?;
    if matches!(direction, SrvsvcCoderDirection::Decode) {
        *value = decode_netr_share_get_info_reply(&bytes)?;
    }
    Ok(())
}
