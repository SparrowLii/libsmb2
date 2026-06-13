//! SRVSVC DCERPC public surface from `include/smb2/libsmb2-dcerpc-srvsvc.h`.

use super::libsmb2::{ErrorCode, Result, Smb2Client};
use crate::lib::dcerpc_srvsvc as lib_srvsvc;

/// SRVSVC operation number for `NetrShareEnum`.
pub const SRVSVC_NETR_SHARE_ENUM: u16 = 0x0f;

/// SRVSVC operation number for `NetrShareGetInfo`.
pub const SRVSVC_NETR_SHARE_GET_INFO: u16 = 0x10;

/// Low-bit share type value for a disk tree share.
pub const SHARE_TYPE_DISK_TREE: u32 = 0;

/// Low-bit share type value for a print queue share.
pub const SHARE_TYPE_PRINT_QUEUE: u32 = 1;

/// Low-bit share type value for a communication device share.
pub const SHARE_TYPE_DEVICE: u32 = 2;

/// Low-bit share type value for the IPC share.
pub const SHARE_TYPE_IPC: u32 = 3;

/// Share type flag for a temporary share.
pub const SHARE_TYPE_TEMPORARY: u32 = 0x4000_0000;

/// Share type flag for a hidden administrative share.
pub const SHARE_TYPE_HIDDEN: u32 = 0x8000_0000;

const ERROR_FUNCTION_NOT_IMPLEMENTED: i32 = -38;

/// Share information detail level used by SRVSVC share APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShareInfoLevel {
    /// Level 0 contains only the share network name.
    Level0,
    /// Level 1 contains the share network name, type, and remark.
    #[default]
    Level1,
    /// A level value not modeled by this migration skeleton.
    Unknown(u32),
}

impl From<u32> for ShareInfoLevel {
    fn from(level: u32) -> Self {
        match level {
            0 => Self::Level0,
            1 => Self::Level1,
            value => Self::Unknown(value),
        }
    }
}

impl From<ShareInfoLevel> for u32 {
    fn from(level: ShareInfoLevel) -> Self {
        match level {
            ShareInfoLevel::Level0 => 0,
            ShareInfoLevel::Level1 => 1,
            ShareInfoLevel::Unknown(value) => value,
        }
    }
}

/// SRVSVC share kind encoded in the low two bits of the legacy share type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShareKind {
    /// Disk tree share.
    #[default]
    DiskTree,
    /// Print queue share.
    PrintQueue,
    /// Communication device share.
    Device,
    /// IPC share.
    Ipc,
}

/// Decoded SRVSVC share type and flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShareType {
    /// Share kind encoded by the low two bits.
    pub kind: ShareKind,
    /// Whether the temporary share flag is set.
    pub temporary: bool,
    /// Whether the hidden administrative share flag is set.
    pub hidden: bool,
    /// Bits not modeled by this skeleton.
    pub raw_flags: u32,
}

impl ShareType {
    /// Creates a decoded share type from the raw SRVSVC bit field.
    #[must_use]
    pub fn from_bits(bits: u32) -> Self {
        let kind = match bits & 0x3 {
            SHARE_TYPE_PRINT_QUEUE => ShareKind::PrintQueue,
            SHARE_TYPE_DEVICE => ShareKind::Device,
            SHARE_TYPE_IPC => ShareKind::Ipc,
            _ => ShareKind::DiskTree,
        };

        Self {
            kind,
            temporary: bits & SHARE_TYPE_TEMPORARY != 0,
            hidden: bits & SHARE_TYPE_HIDDEN != 0,
            raw_flags: bits & !(0x3 | SHARE_TYPE_TEMPORARY | SHARE_TYPE_HIDDEN),
        }
    }

    /// Encodes this share type into the legacy SRVSVC bit field.
    #[must_use]
    pub fn to_bits(self) -> u32 {
        let kind = match self.kind {
            ShareKind::DiskTree => SHARE_TYPE_DISK_TREE,
            ShareKind::PrintQueue => SHARE_TYPE_PRINT_QUEUE,
            ShareKind::Device => SHARE_TYPE_DEVICE,
            ShareKind::Ipc => SHARE_TYPE_IPC,
        };

        let temporary = if self.temporary {
            SHARE_TYPE_TEMPORARY
        } else {
            0
        };
        let hidden = if self.hidden { SHARE_TYPE_HIDDEN } else { 0 };

        kind | temporary | hidden | self.raw_flags
    }
}

/// Share information returned by SRVSVC enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShareInfo {
    /// Share name.
    pub name: String,
    /// Raw SRVSVC share type value, if returned by the selected info level.
    pub share_type: Option<ShareType>,
    /// Optional share comment.
    pub comment: Option<String>,
}

/// Rust representation of `struct srvsvc_SHARE_INFO_0`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo0 {
    /// Share network name.
    pub netname: String,
}

/// Rust representation of `struct srvsvc_SHARE_INFO_0_CONTAINER`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo0Container {
    /// Number of level 0 entries returned by the server.
    pub entries_read: u32,
    /// Level 0 share entries.
    pub shares: Vec<SrvsvcShareInfo0>,
}

/// Rust representation of `struct srvsvc_SHARE_INFO_1`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo1 {
    /// Share network name.
    pub netname: String,
    /// Raw SRVSVC share type bit field.
    pub share_type: u32,
    /// Optional share remark.
    pub remark: String,
}

/// Rust representation of `struct srvsvc_SHARE_INFO_1_CONTAINER`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo1Container {
    /// Number of level 1 entries returned by the server.
    pub entries_read: u32,
    /// Level 1 share entries.
    pub shares: Vec<SrvsvcShareInfo1>,
}

/// Union-like SRVSVC share enumeration payload selected by level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrvsvcShareEnumUnion {
    /// Level 0 share enumeration container.
    Level0(SrvsvcShareInfo0Container),
    /// Level 1 share enumeration container.
    Level1(SrvsvcShareInfo1Container),
    /// Unsupported level placeholder retained for forward compatibility.
    ///
    /// Known raw levels are safely converted to empty modeled containers when
    /// this value crosses the migrated SRVSVC NDR boundary.
    Unsupported { level: u32 },
}

impl Default for SrvsvcShareEnumUnion {
    fn default() -> Self {
        Self::Level1(SrvsvcShareInfo1Container::default())
    }
}

/// Rust representation of `struct srvsvc_SHARE_ENUM_STRUCT`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareEnumStruct {
    /// Requested or returned share information level.
    pub level: ShareInfoLevel,
    /// Level-selected share information payload.
    pub share_info: SrvsvcShareEnumUnion,
}

/// Rust representation of `struct srvsvc_NetrShareEnum_req`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetrShareEnumRequest {
    /// Target server name.
    pub server_name: String,
    /// Share enumeration selector and container.
    pub share_enum: SrvsvcShareEnumStruct,
    /// Preferred maximum response length in bytes.
    pub preferred_maximum_length: u32,
    /// Resume handle for paged enumeration.
    pub resume_handle: u32,
}

impl Default for NetrShareEnumRequest {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            share_enum: SrvsvcShareEnumStruct::default(),
            preferred_maximum_length: u32::MAX,
            resume_handle: 0,
        }
    }
}

/// Rust representation of `struct srvsvc_NetrShareEnum_rep`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetrShareEnumResponse {
    /// Legacy SRVSVC status code.
    pub status: u32,
    /// Returned share enumeration selector and container.
    pub share_enum: SrvsvcShareEnumStruct,
    /// Total number of entries available on the server.
    pub total_entries: u32,
    /// Resume handle for a subsequent enumeration call.
    pub resume_handle: u32,
}

/// Union-like SRVSVC share information payload selected by level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrvsvcShareInfoUnion {
    /// Level 0 share information.
    Level0(SrvsvcShareInfo0),
    /// Level 1 share information.
    Level1(SrvsvcShareInfo1),
    /// Unsupported level placeholder retained for forward compatibility.
    Unsupported { level: u32 },
}

impl Default for SrvsvcShareInfoUnion {
    fn default() -> Self {
        Self::Level1(SrvsvcShareInfo1::default())
    }
}

/// Rust representation of `struct srvsvc_SHARE_INFO`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo {
    /// Requested or returned share information level.
    pub level: ShareInfoLevel,
    /// Level-selected share information payload.
    pub info: SrvsvcShareInfoUnion,
}

/// Rust representation of `struct srvsvc_NetrShareGetInfo_req`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetrShareGetInfoRequest {
    /// Target server name.
    pub server_name: String,
    /// Share name to query.
    pub netname: String,
    /// Requested share information level.
    pub level: ShareInfoLevel,
}

impl Default for NetrShareGetInfoRequest {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            netname: String::new(),
            level: ShareInfoLevel::Level1,
        }
    }
}

/// Rust representation of `struct srvsvc_NetrShareGetInfo_rep`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetrShareGetInfoResponse {
    /// Legacy SRVSVC status code.
    pub status: u32,
    /// Returned share information payload.
    pub info: SrvsvcShareInfo,
}

/// Minimal SRVSVC response containing only a legacy status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SrvsvcResponse {
    /// Legacy SRVSVC status code.
    pub status: u32,
}

/// Completion callback shape for typed SRVSVC asynchronous operations.
pub type SrvsvcCommandCallback<T> = Box<dyn FnOnce(&mut Smb2Client, Result<T>) + Send + 'static>;

/// Encodes or decodes a level 0 share information structure.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until SRVSVC NDR coding is implemented.
pub fn srvsvc_share_info_0_coder(value: &mut SrvsvcShareInfo0) -> Result<()> {
    let mut req = lib_srvsvc::SrvsvcNetrShareEnumReq::new(lib_srvsvc::ShareInfoLevel::Level0);
    req.share_enum.share_info =
        lib_srvsvc::SrvsvcShareEnumUnion::Level0(lib_srvsvc::SrvsvcShareInfo0Container::new(vec![
            lib_srvsvc::SrvsvcShareInfo0 {
                netname: non_empty_option(value.netname.clone()),
            },
        ]));
    lib_srvsvc::encode_netr_share_enum_request(&req).map_err(map_dcerpc_error)?;
    Ok(())
}

/// Encodes or decodes a level 1 share information structure.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until SRVSVC NDR coding is implemented.
pub fn srvsvc_share_info_1_coder(value: &mut SrvsvcShareInfo1) -> Result<()> {
    let req = lib_srvsvc::SrvsvcNetrShareGetInfoReq::new(
        value.netname.clone(),
        lib_srvsvc::ShareInfoLevel::Level1,
    );
    lib_srvsvc::encode_netr_share_get_info_request(&req).map_err(map_dcerpc_error)?;
    Ok(())
}

/// Encodes or decodes a level 1 share information container.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until SRVSVC NDR coding is implemented.
pub fn srvsvc_share_info_1_container_coder(value: &mut SrvsvcShareInfo1Container) -> Result<()> {
    let mut req = lib_srvsvc::SrvsvcNetrShareEnumReq::new(lib_srvsvc::ShareInfoLevel::Level1);
    req.share_enum.share_info =
        lib_srvsvc::SrvsvcShareEnumUnion::Level1(lib_srvsvc::SrvsvcShareInfo1Container::new(
            value.shares.iter().map(to_lib_share_info_1).collect(),
        ));
    lib_srvsvc::encode_netr_share_enum_request(&req).map_err(map_dcerpc_error)?;
    Ok(())
}

/// Encodes or decodes a `NetrShareEnum` response.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until SRVSVC NDR coding is implemented.
pub fn srvsvc_netr_share_enum_response_coder(value: &mut NetrShareEnumResponse) -> Result<()> {
    let rep = to_lib_share_enum_reply(value)?;
    let bytes = lib_srvsvc::encode_netr_share_enum_reply(&rep).map_err(map_dcerpc_error)?;
    let decoded = lib_srvsvc::decode_netr_share_enum_reply(&bytes).map_err(map_dcerpc_error)?;
    *value = from_lib_share_enum_reply(decoded);
    Ok(())
}

/// Encodes or decodes a `NetrShareEnum` request.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until SRVSVC NDR coding is implemented.
pub fn srvsvc_netr_share_enum_request_coder(value: &mut NetrShareEnumRequest) -> Result<()> {
    let req = to_lib_share_enum_request(value)?;
    lib_srvsvc::encode_netr_share_enum_request(&req).map_err(map_dcerpc_error)?;
    Ok(())
}

/// Encodes or decodes a `NetrShareGetInfo` response.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until SRVSVC NDR coding is implemented.
pub fn srvsvc_netr_share_get_info_response_coder(
    value: &mut NetrShareGetInfoResponse,
) -> Result<()> {
    let rep = to_lib_share_get_info_reply(value)?;
    let bytes = lib_srvsvc::encode_netr_share_get_info_reply(&rep).map_err(map_dcerpc_error)?;
    let decoded = lib_srvsvc::decode_netr_share_get_info_reply(&bytes).map_err(map_dcerpc_error)?;
    *value = from_lib_share_get_info_reply(decoded);
    Ok(())
}

/// Encodes or decodes a `NetrShareGetInfo` request.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until SRVSVC NDR coding is implemented.
pub fn srvsvc_netr_share_get_info_request_coder(value: &mut NetrShareGetInfoRequest) -> Result<()> {
    let req = to_lib_share_get_info_request(value)?;
    lib_srvsvc::encode_netr_share_get_info_request(&req).map_err(map_dcerpc_error)?;
    Ok(())
}

impl Smb2Client {
    /// Starts an asynchronous SRVSVC share enumeration request.
    ///
    /// This skeleton mirrors `smb2_share_enum_async` and is intended for IPC$ connections.
    ///
    /// # Errors
    ///
    /// Always returns `ErrorCode(-38)` until SRVSVC transport binding and NDR coding are
    /// implemented. The callback is not invoked when this error is returned.
    pub fn share_enum_async(
        &mut self,
        _level: ShareInfoLevel,
        _callback: SrvsvcCommandCallback<NetrShareEnumResponse>,
    ) -> Result<()> {
        Err(not_implemented())
    }

    /// Performs a synchronous SRVSVC share enumeration request.
    ///
    /// This skeleton mirrors `smb2_share_enum_sync` and is intended for IPC$ connections.
    ///
    ///
    /// # Errors
    ///
    /// Always returns `ErrorCode(-38)` until SRVSVC transport binding and NDR coding are
    /// implemented.
    pub fn share_enum_sync(&mut self, _level: ShareInfoLevel) -> Result<NetrShareEnumResponse> {
        Err(not_implemented())
    }

    /// Starts an asynchronous SRVSVC share information query.
    ///
    /// # Errors
    ///
    /// Always returns `ErrorCode(-38)` until SRVSVC transport binding and NDR coding are
    /// implemented. The callback is not invoked when this error is returned.
    pub fn share_get_info_async(
        &mut self,
        _netname: &str,
        _level: ShareInfoLevel,
        _callback: SrvsvcCommandCallback<NetrShareGetInfoResponse>,
    ) -> Result<()> {
        Err(not_implemented())
    }

    /// Performs a synchronous SRVSVC share information query.
    ///
    /// # Errors
    ///
    /// Always returns `ErrorCode(-38)` until SRVSVC transport binding and NDR coding are
    /// implemented.
    pub fn share_get_info_sync(
        &mut self,
        _netname: &str,
        _level: ShareInfoLevel,
    ) -> Result<NetrShareGetInfoResponse> {
        Err(not_implemented())
    }
}

fn not_implemented() -> ErrorCode {
    ErrorCode(ERROR_FUNCTION_NOT_IMPLEMENTED)
}

fn to_lib_share_enum_request(
    value: &NetrShareEnumRequest,
) -> Result<lib_srvsvc::SrvsvcNetrShareEnumReq> {
    let mut req = lib_srvsvc::SrvsvcNetrShareEnumReq::new(to_lib_level(value.share_enum.level)?);
    req.server_name = non_empty_option(value.server_name.clone());
    req.share_enum = to_lib_share_enum_struct(&value.share_enum)?;
    req.preferred_maximum_length = value.preferred_maximum_length;
    req.resume_handle = if value.resume_handle == 0 {
        None
    } else {
        Some(value.resume_handle)
    };
    Ok(req)
}

fn to_lib_share_get_info_request(
    value: &NetrShareGetInfoRequest,
) -> Result<lib_srvsvc::SrvsvcNetrShareGetInfoReq> {
    let mut req = lib_srvsvc::SrvsvcNetrShareGetInfoReq::new(
        value.netname.clone(),
        to_lib_level(value.level)?,
    );
    req.server_name = non_empty_option(value.server_name.clone());
    Ok(req)
}

fn to_lib_share_enum_reply(
    value: &NetrShareEnumResponse,
) -> Result<lib_srvsvc::SrvsvcNetrShareEnumRep> {
    Ok(lib_srvsvc::SrvsvcNetrShareEnumRep {
        share_enum: to_lib_share_enum_struct(&value.share_enum)?,
        total_entries: value.total_entries,
        resume_handle: if value.resume_handle == 0 {
            None
        } else {
            Some(value.resume_handle)
        },
        status: value.status,
    })
}

fn to_lib_share_get_info_reply(
    value: &NetrShareGetInfoResponse,
) -> Result<lib_srvsvc::SrvsvcNetrShareGetInfoRep> {
    Ok(lib_srvsvc::SrvsvcNetrShareGetInfoRep {
        info_struct: to_lib_share_info(&value.info)?,
        status: value.status,
    })
}

fn to_lib_share_info(value: &SrvsvcShareInfo) -> Result<lib_srvsvc::SrvsvcShareInfo> {
    match &value.info {
        SrvsvcShareInfoUnion::Level0(info) => Ok(lib_srvsvc::SrvsvcShareInfo::Level0(
            lib_srvsvc::SrvsvcShareInfo0 {
                netname: non_empty_option(info.netname.clone()),
            },
        )),
        SrvsvcShareInfoUnion::Level1(info) => Ok(lib_srvsvc::SrvsvcShareInfo::Level1(
            to_lib_share_info_1(info),
        )),
        SrvsvcShareInfoUnion::Unsupported { .. } => Err(not_implemented()),
    }
}

fn to_lib_share_enum_struct(
    value: &SrvsvcShareEnumStruct,
) -> Result<lib_srvsvc::SrvsvcShareEnumStruct> {
    let share_info = match &value.share_info {
        SrvsvcShareEnumUnion::Level0(container) => {
            lib_srvsvc::SrvsvcShareEnumUnion::Level0(lib_srvsvc::SrvsvcShareInfo0Container::new(
                container
                    .shares
                    .iter()
                    .map(|share| lib_srvsvc::SrvsvcShareInfo0 {
                        netname: non_empty_option(share.netname.clone()),
                    })
                    .collect(),
            ))
        }
        SrvsvcShareEnumUnion::Level1(container) => {
            lib_srvsvc::SrvsvcShareEnumUnion::Level1(lib_srvsvc::SrvsvcShareInfo1Container::new(
                container.shares.iter().map(to_lib_share_info_1).collect(),
            ))
        }
        SrvsvcShareEnumUnion::Unsupported { level } => {
            empty_lib_share_enum_union_for_level(*level)?
        }
    };
    Ok(lib_srvsvc::SrvsvcShareEnumStruct { share_info })
}

fn empty_lib_share_enum_union_for_level(level: u32) -> Result<lib_srvsvc::SrvsvcShareEnumUnion> {
    match ShareInfoLevel::from(level) {
        ShareInfoLevel::Level0 => Ok(lib_srvsvc::SrvsvcShareEnumUnion::Level0(
            lib_srvsvc::SrvsvcShareInfo0Container::default(),
        )),
        ShareInfoLevel::Level1 => Ok(lib_srvsvc::SrvsvcShareEnumUnion::Level1(
            lib_srvsvc::SrvsvcShareInfo1Container::default(),
        )),
        ShareInfoLevel::Unknown(level) => Ok(lib_srvsvc::SrvsvcShareEnumUnion::Raw {
            level,
            bytes: Vec::new(),
        }),
    }
}

fn to_lib_share_info_1(value: &SrvsvcShareInfo1) -> lib_srvsvc::SrvsvcShareInfo1 {
    lib_srvsvc::SrvsvcShareInfo1 {
        netname: non_empty_option(value.netname.clone()),
        share_type: value.share_type,
        remark: non_empty_option(value.remark.clone()),
    }
}

fn from_lib_share_enum_reply(value: lib_srvsvc::SrvsvcNetrShareEnumRep) -> NetrShareEnumResponse {
    NetrShareEnumResponse {
        status: value.status,
        share_enum: from_lib_share_enum_struct(value.share_enum),
        total_entries: value.total_entries,
        resume_handle: value
            .resume_handle
            .map_or_else(u32::default, core::convert::identity),
    }
}

fn from_lib_share_get_info_reply(
    value: lib_srvsvc::SrvsvcNetrShareGetInfoRep,
) -> NetrShareGetInfoResponse {
    NetrShareGetInfoResponse {
        status: value.status,
        info: from_lib_share_info(value.info_struct),
    }
}

fn from_lib_share_enum_struct(value: lib_srvsvc::SrvsvcShareEnumStruct) -> SrvsvcShareEnumStruct {
    match value.share_info {
        lib_srvsvc::SrvsvcShareEnumUnion::Level0(container) => SrvsvcShareEnumStruct {
            level: ShareInfoLevel::Level0,
            share_info: SrvsvcShareEnumUnion::Level0(SrvsvcShareInfo0Container {
                entries_read: container.entries_read,
                shares: container
                    .share_info_0
                    .into_iter()
                    .map(|share| SrvsvcShareInfo0 {
                        netname: share
                            .netname
                            .map_or_else(String::new, core::convert::identity),
                    })
                    .collect(),
            }),
        },
        lib_srvsvc::SrvsvcShareEnumUnion::Level1(container) => SrvsvcShareEnumStruct {
            level: ShareInfoLevel::Level1,
            share_info: SrvsvcShareEnumUnion::Level1(SrvsvcShareInfo1Container {
                entries_read: container.entries_read,
                shares: container
                    .share_info_1
                    .into_iter()
                    .map(from_lib_share_info_1)
                    .collect(),
            }),
        },
        lib_srvsvc::SrvsvcShareEnumUnion::Raw { level, .. } => SrvsvcShareEnumStruct {
            level: ShareInfoLevel::Unknown(level),
            share_info: SrvsvcShareEnumUnion::Unsupported { level },
        },
    }
}

fn from_lib_share_info(value: lib_srvsvc::SrvsvcShareInfo) -> SrvsvcShareInfo {
    match value {
        lib_srvsvc::SrvsvcShareInfo::Level0(info) => SrvsvcShareInfo {
            level: ShareInfoLevel::Level0,
            info: SrvsvcShareInfoUnion::Level0(SrvsvcShareInfo0 {
                netname: info
                    .netname
                    .map_or_else(String::new, core::convert::identity),
            }),
        },
        lib_srvsvc::SrvsvcShareInfo::Level1(info) => SrvsvcShareInfo {
            level: ShareInfoLevel::Level1,
            info: SrvsvcShareInfoUnion::Level1(from_lib_share_info_1(info)),
        },
        lib_srvsvc::SrvsvcShareInfo::Raw { level, .. } => SrvsvcShareInfo {
            level: ShareInfoLevel::Unknown(level),
            info: SrvsvcShareInfoUnion::Unsupported { level },
        },
    }
}

fn from_lib_share_info_1(value: lib_srvsvc::SrvsvcShareInfo1) -> SrvsvcShareInfo1 {
    SrvsvcShareInfo1 {
        netname: value
            .netname
            .map_or_else(String::new, core::convert::identity),
        share_type: value.share_type,
        remark: value
            .remark
            .map_or_else(String::new, core::convert::identity),
    }
}

fn to_lib_level(level: ShareInfoLevel) -> Result<lib_srvsvc::ShareInfoLevel> {
    match level {
        ShareInfoLevel::Level0 => Ok(lib_srvsvc::ShareInfoLevel::Level0),
        ShareInfoLevel::Level1 => Ok(lib_srvsvc::ShareInfoLevel::Level1),
        ShareInfoLevel::Unknown(level) => Ok(lib_srvsvc::ShareInfoLevel::Unknown(level)),
    }
}

fn non_empty_option(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn map_dcerpc_error(error: crate::lib::dcerpc::DceRpcError) -> ErrorCode {
    match error {
        crate::lib::dcerpc::DceRpcError::ProtocolNotImplemented(_)
        | crate::lib::dcerpc::DceRpcError::UnsupportedPduBody { .. } => not_implemented(),
        crate::lib::dcerpc::DceRpcError::BufferTooSmall { .. }
        | crate::lib::dcerpc::DceRpcError::TooManyDeferredPointers { .. }
        | crate::lib::dcerpc::DceRpcError::AllocHintOutOfRange { .. }
        | crate::lib::dcerpc::DceRpcError::CountOutOfRange { .. }
        | crate::lib::dcerpc::DceRpcError::InvalidUtf16
        | crate::lib::dcerpc::DceRpcError::InvalidPduType { .. }
        | crate::lib::dcerpc::DceRpcError::InvalidAuthVerifier { .. }
        | crate::lib::dcerpc::DceRpcError::NullPointer => ErrorCode(-22),
    }
}
