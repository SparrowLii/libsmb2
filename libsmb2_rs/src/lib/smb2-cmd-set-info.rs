//! SET_INFO command pack/unpack skeleton migrated from `lib/smb2-cmd-set-info.c`.

use crate::include::libsmb2_private::SMB2_HEADER_SIZE;

use super::smb2_data_file_info::{
    smb2_decode_file_basic_info, smb2_decode_file_disposition_info,
    smb2_decode_file_end_of_file_info, smb2_decode_file_rename_info, smb2_encode_file_basic_info,
    smb2_encode_file_disposition_info, smb2_encode_file_end_of_file_info,
    smb2_encode_file_rename_info, FileInfoError, Smb2FileBasicInfo, Smb2FileDispositionInfo,
    Smb2FileEndOfFileInfo, Smb2FileRenameInfo, FILE_BASIC_INFO_SIZE, FILE_DISPOSITION_INFO_SIZE,
    FILE_END_OF_FILE_INFO_SIZE, FILE_RENAME_INFO_PREFIX_SIZE,
};

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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// A typed SET_INFO buffer is malformed for its class.
    MalformedPayload,
    /// File information typed payload codec failed.
    FileInfo(FileInfoError),
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
            Self::MalformedPayload => f.write_str("SET_INFO typed payload is malformed"),
            Self::FileInfo(error) => write!(f, "SET_INFO file information payload error: {error}"),
        }
    }
}

impl std::error::Error for SetInfoError {}

impl From<FileInfoError> for SetInfoError {
    fn from(error: FileInfoError) -> Self {
        Self::FileInfo(error)
    }
}

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

/// SET_INFO alias for the shared `smb2_file_basic_info` typed payload.
pub type SetInfoFileBasicInformation = Smb2FileBasicInfo;
/// SET_INFO alias for the shared `smb2_file_end_of_file_info` typed payload.
pub type SetInfoFileEndOfFileInformation = Smb2FileEndOfFileInfo;
/// SET_INFO alias for the shared `smb2_file_disposition_info` typed payload.
pub type SetInfoFileDispositionInformation = Smb2FileDispositionInfo;
/// SET_INFO alias for the shared `smb2_file_rename_info` typed payload.
pub type SetInfoFileRenameInformation = Smb2FileRenameInfo;

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
            Self::FileBasicInformation(_) => FILE_BASIC_INFO_SIZE,
            Self::FileEndOfFileInformation(_) => FILE_END_OF_FILE_INFO_SIZE,
            Self::FileRenameInformation(rename) => {
                FILE_RENAME_INFO_PREFIX_SIZE + rename.utf16_wire_len()
            }
            Self::FileDispositionInformation(_) => FILE_DISPOSITION_INFO_SIZE,
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

/// Encodes fixed SET_INFO request fields and the input payload area.
///
/// # Errors
///
/// Returns an error if a typed payload is malformed, raw payload metadata is inconsistent, or a
/// length calculation overflows.
pub fn smb2_encode_set_info_request(
    req: &SetInfoRequest,
    passthrough: bool,
) -> SetInfoResult<Vec<u8>> {
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

    encode_payload(
        &req.input_data,
        &mut buf[SetInfoRequest::fixed_wire_len()..SetInfoRequest::fixed_wire_len() + variable_len],
        passthrough,
    )?;

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

/// Attaches and decodes the variable SET_INFO request buffer.
///
/// # Errors
///
/// Returns an error if the input slice does not fit in `variable` or a recognized typed class is
/// malformed.
pub fn smb2_process_set_info_request_variable(
    req: &mut SetInfoRequest,
    variable: &[u8],
    passthrough: bool,
) -> SetInfoResult<()> {
    if req.buffer_length == 0 {
        req.input_data = SetInfoPayload::None;
        return Ok(());
    }
    let offset = request_iov_offset(req.buffer_offset)?;
    let len = usize::try_from(req.buffer_length).map_err(|_| SetInfoError::LengthOverflow)?;
    let bytes = slice_at(variable, offset, len)?;
    req.input_data = if passthrough {
        SetInfoPayload::Raw(bytes.to_vec())
    } else {
        decode_payload(req.info_type, req.file_info_class, bytes)?
    };
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

fn encode_payload(
    payload: &SetInfoPayload,
    buf: &mut [u8],
    passthrough: bool,
) -> SetInfoResult<()> {
    match payload {
        SetInfoPayload::None => Ok(()),
        SetInfoPayload::Raw(bytes) => {
            if !passthrough && bytes.len() != buf.len() {
                return Err(SetInfoError::MalformedPayload);
            }
            let len = if passthrough {
                bytes.len().min(buf.len())
            } else {
                bytes.len()
            };
            write_bytes(buf, 0, &bytes[..len])
        }
        SetInfoPayload::FileBasicInformation(info) => {
            smb2_encode_file_basic_info(info, buf)?;
            Ok(())
        }
        SetInfoPayload::FileEndOfFileInformation(info) => {
            smb2_encode_file_end_of_file_info(info, buf)?;
            Ok(())
        }
        SetInfoPayload::FileRenameInformation(info) => {
            smb2_encode_file_rename_info(info, buf)?;
            Ok(())
        }
        SetInfoPayload::FileDispositionInformation(info) => {
            smb2_encode_file_disposition_info(info, buf)?;
            Ok(())
        }
    }
}

fn decode_payload(
    info_type: u8,
    file_info_class: u8,
    bytes: &[u8],
) -> SetInfoResult<SetInfoPayload> {
    match recognized_payload_kind(info_type, file_info_class) {
        Some(SetInfoPayloadKind::FileBasicInformation) => Ok(SetInfoPayload::FileBasicInformation(
            smb2_decode_file_basic_info(bytes)?,
        )),
        Some(SetInfoPayloadKind::FileEndOfFileInformation) => Ok(
            SetInfoPayload::FileEndOfFileInformation(smb2_decode_file_end_of_file_info(bytes)?),
        ),
        Some(SetInfoPayloadKind::FileRenameInformation) => Ok(
            SetInfoPayload::FileRenameInformation(smb2_decode_file_rename_info(bytes)?),
        ),
        Some(SetInfoPayloadKind::FileDispositionInformation) => Ok(
            SetInfoPayload::FileDispositionInformation(smb2_decode_file_disposition_info(bytes)?),
        ),
        None => Ok(SetInfoPayload::Raw(bytes.to_vec())),
    }
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
