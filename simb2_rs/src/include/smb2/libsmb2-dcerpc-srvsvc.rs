//! SRVSVC DCERPC skeleton from `include/smb2/libsmb2-dcerpc-srvsvc.h`.

use super::libsmb2::{ErrorCode, Result, Smb2Client};

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
pub fn srvsvc_share_info_0_coder(_value: &mut SrvsvcShareInfo0) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes a level 1 share information structure.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until SRVSVC NDR coding is implemented.
pub fn srvsvc_share_info_1_coder(_value: &mut SrvsvcShareInfo1) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes a level 1 share information container.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until SRVSVC NDR coding is implemented.
pub fn srvsvc_share_info_1_container_coder(_value: &mut SrvsvcShareInfo1Container) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes a `NetrShareEnum` response.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until SRVSVC NDR coding is implemented.
pub fn srvsvc_netr_share_enum_response_coder(_value: &mut NetrShareEnumResponse) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes a `NetrShareEnum` request.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until SRVSVC NDR coding is implemented.
pub fn srvsvc_netr_share_enum_request_coder(_value: &mut NetrShareEnumRequest) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes a `NetrShareGetInfo` response.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until SRVSVC NDR coding is implemented.
pub fn srvsvc_netr_share_get_info_response_coder(
    _value: &mut NetrShareGetInfoResponse,
) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes a `NetrShareGetInfo` request.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until SRVSVC NDR coding is implemented.
pub fn srvsvc_netr_share_get_info_request_coder(
    _value: &mut NetrShareGetInfoRequest,
) -> Result<()> {
    Err(not_implemented())
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
