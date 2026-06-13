//! SET_INFO command pack/unpack skeleton migrated from `lib/smb2-cmd-set-info.c`.

use crate::include::libsmb2_private::SMB2_HEADER_SIZE;

/// SMB2 command id for SET_INFO.
pub const SMB2_SET_INFO: u16 = 17;
/// SMB2 file id size in bytes.
pub const SMB2_FD_SIZE: usize = 16;
/// Fixed SET_INFO request structure size from the SMB2 wire format.
pub const SMB2_SET_INFO_REQUEST_SIZE: usize = 33;
/// Fixed SET_INFO reply structure size from the SMB2 wire format.
pub const SMB2_SET_INFO_REPLY_SIZE: usize = 2;

/// SET_INFO file information namespace.
pub const SMB2_0_INFO_FILE: u8 = 0x01;

/// FILE_BASIC_INFORMATION class id accepted by the legacy SET_INFO encoder.
pub const SMB2_FILE_BASIC_INFORMATION: u8 = 0x04;
/// FILE_RENAME_INFORMATION class id accepted by the legacy SET_INFO encoder.
pub const SMB2_FILE_RENAME_INFORMATION: u8 = 0x0a;
/// FILE_DISPOSITION_INFORMATION class id accepted by the legacy SET_INFO encoder.
pub const SMB2_FILE_DISPOSITION_INFORMATION: u8 = 0x0d;
/// FILE_END_OF_FILE_INFORMATION class id accepted by the legacy SET_INFO encoder.
pub const SMB2_FILE_END_OF_FILE_INFORMATION: u8 = 0x14;

/// Errors returned by the SET_INFO migration skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetInfoError {
    /// A fixed or variable buffer is shorter than the requested field.
    BufferTooShort,
    /// A declared input buffer extends beyond the containing PDU.
    BufferOutOfBounds,
    /// A variable buffer overlaps its fixed command header.
    BufferOverlap,
    /// A fixed structure size field does not match the expected SMB2 size.
    InvalidStructureSize,
    /// A checked offset or length calculation overflowed.
    LengthOverflow,
    /// The skeleton intentionally does not encode this info type/class pair.
    UnsupportedInfoClass {
        /// SET_INFO info type.
        info_type: u8,
        /// SET_INFO file information class.
        file_info_class: u8,
    },
}

impl core::fmt::Display for SetInfoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooShort => f.write_str("buffer is shorter than the fixed SET_INFO field"),
            Self::BufferOutOfBounds => {
                f.write_str("SET_INFO variable buffer extends beyond the PDU")
            }
            Self::BufferOverlap => {
                f.write_str("SET_INFO variable buffer overlaps the fixed header")
            }
            Self::InvalidStructureSize => f.write_str("unexpected SET_INFO structure size"),
            Self::LengthOverflow => f.write_str("SET_INFO offset or length calculation overflowed"),
            Self::UnsupportedInfoClass { .. } => {
                f.write_str("SET_INFO info type/class is not encoded by this skeleton")
            }
        }
    }
}

impl std::error::Error for SetInfoError {}

/// Result type for SET_INFO skeleton helpers.
pub type SetInfoResult<T> = core::result::Result<T, SetInfoError>;

/// Raw SMB2 file id carried by SET_INFO requests.
pub type Smb2FileId = [u8; SMB2_FD_SIZE];

/// Typed category for SET_INFO payloads recognized by the C switch statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetInfoPayloadKind {
    /// FILE_BASIC_INFORMATION payload.
    FileBasicInformation,
    /// FILE_END_OF_FILE_INFORMATION payload.
    FileEndOfFileInformation,
    /// FILE_RENAME_INFORMATION payload.
    FileRenameInformation,
    /// FILE_DISPOSITION_INFORMATION payload.
    FileDispositionInformation,
}

/// Rust-owned counterpart of `struct smb2_file_basic_info` for SET_INFO use.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SetInfoFileBasicInformation {
    /// Creation time in SMB timestamp units.
    pub creation_time: u64,
    /// Last access time in SMB timestamp units.
    pub last_access_time: u64,
    /// Last write time in SMB timestamp units.
    pub last_write_time: u64,
    /// Change time in SMB timestamp units.
    pub change_time: u64,
    /// File attributes written by FILE_BASIC_INFORMATION.
    pub file_attributes: u32,
}

/// Rust-owned counterpart of `struct smb2_file_end_of_file_info`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SetInfoFileEndOfFileInformation {
    /// New end-of-file value.
    pub end_of_file: u64,
}

/// Rust-owned counterpart of `struct smb2_file_disposition_info`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SetInfoFileDispositionInformation {
    /// Non-zero when the file should be marked delete-pending.
    pub delete_pending: u8,
}

impl SetInfoFileDispositionInformation {
    /// Creates a disposition payload from a boolean delete-pending flag.
    #[must_use]
    pub const fn from_bool(delete_pending: bool) -> Self {
        Self {
            delete_pending: if delete_pending { 1 } else { 0 },
        }
    }

    /// Returns whether the payload requests delete-pending state.
    #[must_use]
    pub const fn is_delete_pending(&self) -> bool {
        self.delete_pending != 0
    }
}

/// Rust-owned counterpart of `struct smb2_file_rename_info`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SetInfoFileRenameInformation {
    /// Non-zero when an existing destination may be replaced.
    pub replace_if_exist: u8,
    /// UTF-8 destination name before the legacy UTF-16 wire conversion.
    pub file_name: String,
}

impl SetInfoFileRenameInformation {
    /// Creates a rename payload skeleton.
    #[must_use]
    pub fn new(file_name: impl Into<String>, replace_if_exist: bool) -> Self {
        Self {
            replace_if_exist: u8::from(replace_if_exist),
            file_name: file_name.into(),
        }
    }

    /// Returns whether the payload allows replacing an existing destination.
    #[must_use]
    pub const fn replaces_existing(&self) -> bool {
        self.replace_if_exist != 0
    }

    /// Returns the UTF-16LE byte length that the legacy encoder would reserve for the name.
    #[must_use]
    pub fn utf16_wire_len(&self) -> usize {
        utf16_wire_len(&self.file_name)
    }
}

/// SET_INFO input payloads supported or preserved by this skeleton.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum SetInfoPayload {
    /// No input payload is attached.
    #[default]
    None,
    /// Raw bytes used for passthrough or not-yet-translated callers.
    Raw(Vec<u8>),
    /// FILE_BASIC_INFORMATION payload placeholder.
    FileBasicInformation(SetInfoFileBasicInformation),
    /// FILE_END_OF_FILE_INFORMATION payload placeholder.
    FileEndOfFileInformation(SetInfoFileEndOfFileInformation),
    /// FILE_RENAME_INFORMATION payload placeholder.
    FileRenameInformation(SetInfoFileRenameInformation),
    /// FILE_DISPOSITION_INFORMATION payload placeholder.
    FileDispositionInformation(SetInfoFileDispositionInformation),
}

impl SetInfoPayload {
    /// Returns the payload class represented by this value, if it is typed.
    #[must_use]
    pub const fn kind(&self) -> Option<SetInfoPayloadKind> {
        match self {
            Self::None | Self::Raw(_) => None,
            Self::FileBasicInformation(_) => Some(SetInfoPayloadKind::FileBasicInformation),
            Self::FileEndOfFileInformation(_) => Some(SetInfoPayloadKind::FileEndOfFileInformation),
            Self::FileRenameInformation(_) => Some(SetInfoPayloadKind::FileRenameInformation),
            Self::FileDispositionInformation(_) => {
                Some(SetInfoPayloadKind::FileDispositionInformation)
            }
        }
    }

    /// Returns the wire payload length reserved by the legacy encoder skeleton.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Raw(bytes) => bytes.len(),
            Self::FileBasicInformation(_) => 40,
            Self::FileEndOfFileInformation(_) => 8,
            Self::FileRenameInformation(rename) => 28 + rename.utf16_wire_len(),
            Self::FileDispositionInformation(_) => 1,
        }
    }

    /// Returns whether the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.wire_len() == 0
    }
}

/// Rust-owned counterpart of `struct smb2_set_info_request`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SetInfoRequest {
    /// SET_INFO info type.
    pub info_type: u8,
    /// File information class for the SET_INFO request.
    pub file_info_class: u8,
    /// Wire byte length of the input buffer.
    pub buffer_length: u32,
    /// Wire offset of the input buffer.
    pub buffer_offset: u16,
    /// Additional information copied into the fixed request header.
    pub additional_information: u32,
    /// SMB2 file id of the target handle.
    pub file_id: Smb2FileId,
    /// Optional typed or raw input payload.
    pub input_data: SetInfoPayload,
}

impl SetInfoRequest {
    /// Creates a SET_INFO request skeleton with fixed metadata and no payload.
    #[must_use]
    pub fn new(info_type: u8, file_info_class: u8, file_id: Smb2FileId) -> Self {
        Self {
            info_type,
            file_info_class,
            file_id,
            buffer_offset: request_payload_offset() as u16,
            ..Self::default()
        }
    }

    /// Creates a FILE_BASIC_INFORMATION SET_INFO request skeleton.
    #[must_use]
    pub fn file_basic(file_id: Smb2FileId, payload: SetInfoFileBasicInformation) -> Self {
        Self::new(SMB2_0_INFO_FILE, SMB2_FILE_BASIC_INFORMATION, file_id)
            .with_payload(SetInfoPayload::FileBasicInformation(payload))
    }

    /// Creates a FILE_END_OF_FILE_INFORMATION SET_INFO request skeleton.
    #[must_use]
    pub fn file_end_of_file(file_id: Smb2FileId, payload: SetInfoFileEndOfFileInformation) -> Self {
        Self::new(SMB2_0_INFO_FILE, SMB2_FILE_END_OF_FILE_INFORMATION, file_id)
            .with_payload(SetInfoPayload::FileEndOfFileInformation(payload))
    }

    /// Creates a FILE_RENAME_INFORMATION SET_INFO request skeleton.
    #[must_use]
    pub fn file_rename(file_id: Smb2FileId, payload: SetInfoFileRenameInformation) -> Self {
        Self::new(SMB2_0_INFO_FILE, SMB2_FILE_RENAME_INFORMATION, file_id)
            .with_payload(SetInfoPayload::FileRenameInformation(payload))
    }

    /// Creates a FILE_DISPOSITION_INFORMATION SET_INFO request skeleton.
    #[must_use]
    pub fn file_disposition(
        file_id: Smb2FileId,
        payload: SetInfoFileDispositionInformation,
    ) -> Self {
        Self::new(SMB2_0_INFO_FILE, SMB2_FILE_DISPOSITION_INFORMATION, file_id)
            .with_payload(SetInfoPayload::FileDispositionInformation(payload))
    }

    /// Returns the fixed request size rounded the same way as the C encoder.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        aligned_fixed_len(SMB2_SET_INFO_REQUEST_SIZE)
    }

    /// Attaches input data and refreshes `buffer_length` from the skeleton payload size.
    #[must_use]
    pub fn with_payload(mut self, input_data: SetInfoPayload) -> Self {
        self.buffer_length = len_to_u32_saturating(input_data.wire_len());
        self.input_data = input_data;
        self
    }

    /// Creates a no-I/O encoding plan corresponding to `smb2_encode_set_info_request`.
    #[must_use]
    pub fn encode_plan(&self, passthrough: bool) -> SetInfoEncodePlan {
        let variable_len = if passthrough {
            self.buffer_length as usize
        } else {
            self.input_data.wire_len()
        };
        SetInfoEncodePlan {
            command: SetInfoCommandKind::Request,
            fixed_len: Self::fixed_wire_len(),
            variable_len,
        }
    }
}

/// Rust-owned counterpart of the empty SET_INFO reply structure.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SetInfoReply;

impl SetInfoReply {
    /// Creates an empty SET_INFO reply skeleton.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the fixed reply size rounded the same way as the C encoder.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        aligned_fixed_len(SMB2_SET_INFO_REPLY_SIZE)
    }

    /// Creates a no-I/O encoding plan corresponding to `smb2_encode_set_info_reply`.
    #[must_use]
    pub const fn encode_plan(&self) -> SetInfoEncodePlan {
        SetInfoEncodePlan {
            command: SetInfoCommandKind::Reply,
            fixed_len: Self::fixed_wire_len(),
            variable_len: 0,
        }
    }
}

/// Lightweight PDU model returned by SET_INFO async command skeleton builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetInfoPduSkeleton<T> {
    /// SMB2 command id for SET_INFO.
    pub command: u16,
    /// Request or reply payload associated with the PDU skeleton.
    pub payload: T,
}

/// SET_INFO command direction represented by an encoding plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetInfoCommandKind {
    /// Client-to-server SET_INFO request.
    Request,
    /// Server-to-client SET_INFO reply.
    Reply,
}

/// Side-effect-free summary of what the C encoder would append to a PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetInfoEncodePlan {
    /// Request or reply direction.
    pub command: SetInfoCommandKind,
    /// Fixed SET_INFO structure length after legacy even-size alignment.
    pub fixed_len: usize,
    /// Variable input payload length.
    pub variable_len: usize,
}

/// Encodes fixed SET_INFO request fields and reserves a typed payload area.
///
/// The returned bytes are a migration skeleton only: typed payload bytes are zero-filled instead
/// of fully serialized, while passthrough raw bytes are copied unchanged.
///
/// # Errors
///
/// Returns an error if the info type/class is not recognized by the skeleton or if a length
/// calculation overflows.
pub fn smb2_encode_set_info_request(
    req: &SetInfoRequest,
    passthrough: bool,
) -> SetInfoResult<Vec<u8>> {
    if !passthrough && recognized_payload_kind(req.info_type, req.file_info_class).is_none() {
        return Err(SetInfoError::UnsupportedInfoClass {
            info_type: req.info_type,
            file_info_class: req.file_info_class,
        });
    }

    let variable_len = if passthrough {
        usize::try_from(req.buffer_length).map_err(|_| SetInfoError::LengthOverflow)?
    } else {
        req.input_data.wire_len()
    };
    let mut buf = vec![0; SetInfoRequest::fixed_wire_len() + pad_to_64bit(variable_len)];
    write_u16(&mut buf, 0, SMB2_SET_INFO_REQUEST_SIZE as u16)?;
    write_u8(&mut buf, 2, req.info_type)?;
    write_u8(&mut buf, 3, req.file_info_class)?;
    write_u32(&mut buf, 4, len_to_u32(variable_len)?)?;
    write_u16(&mut buf, 8, request_payload_offset() as u16)?;
    write_u32(&mut buf, 12, req.additional_information)?;
    write_bytes(&mut buf, 16, &req.file_id)?;

    if let SetInfoPayload::Raw(bytes) = &req.input_data {
        let len = bytes.len().min(variable_len);
        write_bytes(&mut buf, SetInfoRequest::fixed_wire_len(), &bytes[..len])?;
    }

    Ok(buf)
}

/// Builds a SET_INFO request PDU skeleton corresponding to `smb2_cmd_set_info_async`.
///
/// # Errors
///
/// Returns an error if request encoding would fail.
pub fn smb2_cmd_set_info_async(
    req: &SetInfoRequest,
    passthrough: bool,
) -> SetInfoResult<SetInfoPduSkeleton<Vec<u8>>> {
    Ok(SetInfoPduSkeleton {
        command: SMB2_SET_INFO,
        payload: smb2_encode_set_info_request(req, passthrough)?,
    })
}

/// Encodes a fixed SET_INFO reply skeleton.
///
/// # Errors
///
/// Returns an error if the fixed reply buffer cannot be written.
pub fn smb2_encode_set_info_reply(_req: &SetInfoRequest) -> SetInfoResult<Vec<u8>> {
    let mut buf = vec![0; SetInfoReply::fixed_wire_len()];
    write_u16(&mut buf, 0, SMB2_SET_INFO_REPLY_SIZE as u16)?;
    Ok(buf)
}

/// Builds a SET_INFO reply PDU skeleton corresponding to `smb2_cmd_set_info_reply_async`.
///
/// # Errors
///
/// Returns an error if reply encoding would fail.
pub fn smb2_cmd_set_info_reply_async(
    req: &SetInfoRequest,
) -> SetInfoResult<SetInfoPduSkeleton<Vec<u8>>> {
    Ok(SetInfoPduSkeleton {
        command: SMB2_SET_INFO,
        payload: smb2_encode_set_info_reply(req)?,
    })
}

/// Processes fixed SET_INFO reply fields.
///
/// # Errors
///
/// Returns an error if the fixed reply header is invalid.
pub fn smb2_process_set_info_fixed(fixed: &[u8]) -> SetInfoResult<SetInfoReply> {
    validate_fixed_size(fixed, SMB2_SET_INFO_REPLY_SIZE)?;
    Ok(SetInfoReply::new())
}

/// Processes fixed SET_INFO request fields and returns the expected variable byte count.
///
/// # Errors
///
/// Returns an error if the fixed request header is invalid or references bytes outside the PDU.
pub fn smb2_process_set_info_request_fixed(
    fixed: &[u8],
    pdu_size: usize,
) -> SetInfoResult<(SetInfoRequest, usize)> {
    validate_fixed_size(fixed, SMB2_SET_INFO_REQUEST_SIZE)?;
    let buffer_length = read_u32(fixed, 4)?;
    let buffer_offset = read_u16(fixed, 8)?;

    if buffer_length == 0 {
        return Ok((
            decode_request_fixed(fixed, buffer_offset, buffer_length)?,
            0,
        ));
    }

    let len = usize::try_from(buffer_length).map_err(|_| SetInfoError::LengthOverflow)?;
    let buffer_end = usize::from(buffer_offset)
        .checked_add(len)
        .ok_or(SetInfoError::LengthOverflow)?;
    if buffer_end > pdu_size {
        return Err(SetInfoError::BufferOutOfBounds);
    }
    if usize::from(buffer_offset) < request_payload_offset() {
        return Err(SetInfoError::BufferOverlap);
    }

    Ok((
        decode_request_fixed(fixed, buffer_offset, buffer_length)?,
        request_iov_offset(buffer_offset)?.saturating_add(len),
    ))
}

/// Attaches the variable SET_INFO request buffer.
///
/// The C implementation only preserves the buffer in passthrough mode; this skeleton follows that
/// boundary and does not interpret non-passthrough bytes yet.
///
/// # Errors
///
/// Returns an error if `passthrough` is false or the input slice does not fit in `variable`.
pub fn smb2_process_set_info_request_variable(
    req: &mut SetInfoRequest,
    variable: &[u8],
    passthrough: bool,
) -> SetInfoResult<()> {
    if req.buffer_length == 0 {
        req.input_data = SetInfoPayload::None;
        return Ok(());
    }
    if !passthrough {
        return Err(SetInfoError::UnsupportedInfoClass {
            info_type: req.info_type,
            file_info_class: req.file_info_class,
        });
    }

    let offset = request_iov_offset(req.buffer_offset)?;
    let len = usize::try_from(req.buffer_length).map_err(|_| SetInfoError::LengthOverflow)?;
    req.input_data = SetInfoPayload::Raw(slice_at(variable, offset, len)?.to_vec());
    Ok(())
}

/// Returns the fixed request payload offset from the SMB2 header start.
#[must_use]
pub const fn request_payload_offset() -> usize {
    SMB2_HEADER_SIZE + SetInfoRequest::fixed_wire_len()
}

/// Returns the offset used by the request variable iovec in the C implementation.
///
/// # Errors
///
/// Returns [`SetInfoError::LengthOverflow`] when the input offset points before the request payload.
pub fn request_iov_offset(buffer_offset: u16) -> SetInfoResult<usize> {
    usize::from(buffer_offset)
        .checked_sub(request_payload_offset())
        .ok_or(SetInfoError::LengthOverflow)
}

/// Rounds `len` up to the next 64-bit boundary.
#[must_use]
pub const fn pad_to_64bit(len: usize) -> usize {
    (len + 7) & !7
}

fn recognized_payload_kind(info_type: u8, file_info_class: u8) -> Option<SetInfoPayloadKind> {
    match (info_type, file_info_class) {
        (SMB2_0_INFO_FILE, SMB2_FILE_BASIC_INFORMATION) => {
            Some(SetInfoPayloadKind::FileBasicInformation)
        }
        (SMB2_0_INFO_FILE, SMB2_FILE_END_OF_FILE_INFORMATION) => {
            Some(SetInfoPayloadKind::FileEndOfFileInformation)
        }
        (SMB2_0_INFO_FILE, SMB2_FILE_RENAME_INFORMATION) => {
            Some(SetInfoPayloadKind::FileRenameInformation)
        }
        (SMB2_0_INFO_FILE, SMB2_FILE_DISPOSITION_INFORMATION) => {
            Some(SetInfoPayloadKind::FileDispositionInformation)
        }
        _ => None,
    }
}

const fn aligned_fixed_len(len: usize) -> usize {
    len & !1
}

fn validate_fixed_size(buf: &[u8], expected: usize) -> SetInfoResult<()> {
    if buf.len() < aligned_fixed_len(expected) {
        return Err(SetInfoError::BufferTooShort);
    }

    let struct_size = read_u16(buf, 0)?;
    if usize::from(struct_size) != expected
        || aligned_fixed_len(usize::from(struct_size)) != buf.len()
    {
        return Err(SetInfoError::InvalidStructureSize);
    }

    Ok(())
}

fn decode_request_fixed(
    fixed: &[u8],
    buffer_offset: u16,
    buffer_length: u32,
) -> SetInfoResult<SetInfoRequest> {
    let mut file_id = [0; SMB2_FD_SIZE];
    file_id.copy_from_slice(slice_at(fixed, 16, SMB2_FD_SIZE)?);
    Ok(SetInfoRequest {
        info_type: read_u8(fixed, 2)?,
        file_info_class: read_u8(fixed, 3)?,
        buffer_length,
        buffer_offset,
        additional_information: read_u32(fixed, 12)?,
        file_id,
        input_data: SetInfoPayload::None,
    })
}

fn utf16_wire_len(name: &str) -> usize {
    name.encode_utf16().count().saturating_mul(2)
}

fn read_u8(data: &[u8], offset: usize) -> SetInfoResult<u8> {
    data.get(offset)
        .copied()
        .ok_or(SetInfoError::BufferTooShort)
}

fn read_u16(data: &[u8], offset: usize) -> SetInfoResult<u16> {
    let bytes = slice_at(data, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> SetInfoResult<u32> {
    let bytes = slice_at(data, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u8(data: &mut [u8], offset: usize, value: u8) -> SetInfoResult<()> {
    let Some(slot) = data.get_mut(offset) else {
        return Err(SetInfoError::BufferTooShort);
    };
    *slot = value;
    Ok(())
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) -> SetInfoResult<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) -> SetInfoResult<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_bytes(data: &mut [u8], offset: usize, value: &[u8]) -> SetInfoResult<()> {
    let end = offset
        .checked_add(value.len())
        .ok_or(SetInfoError::LengthOverflow)?;
    let Some(dst) = data.get_mut(offset..end) else {
        return Err(SetInfoError::BufferTooShort);
    };
    dst.copy_from_slice(value);
    Ok(())
}

fn slice_at(data: &[u8], offset: usize, len: usize) -> SetInfoResult<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(SetInfoError::LengthOverflow)?;
    data.get(offset..end).ok_or(SetInfoError::BufferTooShort)
}

fn len_to_u32(len: usize) -> SetInfoResult<u32> {
    u32::try_from(len).map_err(|_| SetInfoError::LengthOverflow)
}

fn len_to_u32_saturating(len: usize) -> u32 {
    if len > u32::MAX as usize {
        u32::MAX
    } else {
        len as u32
    }
}
