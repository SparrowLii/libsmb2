//! QUERY_INFO command pack/unpack skeleton migrated from `lib/smb2-cmd-query-info.c`.

use crate::include::libsmb2_private::SMB2_HEADER_SIZE;

use super::smb2_data_file_info::{
    smb2_decode_file_all_info, smb2_decode_file_basic_info, smb2_decode_file_network_open_info,
    smb2_decode_file_normalized_name_info, smb2_decode_file_position_info,
    smb2_decode_file_standard_info, smb2_decode_file_stream_info, smb2_encode_file_all_info,
    smb2_encode_file_basic_info, smb2_encode_file_network_open_info,
    smb2_encode_file_normalized_name_info, smb2_encode_file_position_info,
    smb2_encode_file_standard_info, smb2_encode_file_stream_info, FileInfoError, Smb2FileAllInfo,
    Smb2FileBasicInfo, Smb2FileNameInfo, Smb2FileNetworkOpenInfo, Smb2FilePositionInfo,
    Smb2FileStandardInfo, Smb2FileStreamInfo, FILE_ALL_INFO_PREFIX_SIZE, FILE_BASIC_INFO_SIZE,
    FILE_NAME_INFO_PREFIX_SIZE, FILE_NETWORK_OPEN_INFO_SIZE, FILE_POSITION_INFO_SIZE,
    FILE_STANDARD_INFO_SIZE, FILE_STREAM_INFO_HEADER_SIZE,
};
use super::smb2_data_filesystem_info::{
    smb2_decode_file_fs_attribute_info, smb2_decode_file_fs_control_info,
    smb2_decode_file_fs_device_info, smb2_decode_file_fs_full_size_info,
    smb2_decode_file_fs_object_id_info, smb2_decode_file_fs_sector_size_info,
    smb2_decode_file_fs_size_info, smb2_decode_file_fs_volume_info, FilesystemInfoError,
    Smb2FileFsAttributeInfo, Smb2FileFsControlInfo, Smb2FileFsDeviceInfo, Smb2FileFsFullSizeInfo,
    Smb2FileFsObjectIdInfo, Smb2FileFsSectorSizeInfo, Smb2FileFsSizeInfo, Smb2FileFsVolumeInfo,
};
use super::smb2_data_security_descriptor::{
    smb2_decode_security_descriptor, smb2_encode_security_descriptor, SecurityDescriptorCodecError,
    Smb2Ace, Smb2Acl, Smb2SecurityDescriptor, Smb2Sid, SMB2_ACCESS_ALLOWED_ACE_TYPE,
    SMB2_ACCESS_ALLOWED_CALLBACK_ACE_TYPE, SMB2_ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    SMB2_ACCESS_DENIED_ACE_TYPE, SMB2_ACCESS_DENIED_CALLBACK_ACE_TYPE,
    SMB2_ACCESS_DENIED_OBJECT_ACE_TYPE, SMB2_SYSTEM_AUDIT_ACE_TYPE,
    SMB2_SYSTEM_AUDIT_OBJECT_ACE_TYPE, SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    SMB2_SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, SMB2_SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
};

/// SMB2 command id for QUERY_INFO.
pub const SMB2_QUERY_INFO: u16 = 16;
/// SMB2 file id size in bytes.
pub const SMB2_FD_SIZE: usize = 16;
/// Fixed QUERY_INFO request structure size from the SMB2 wire format.
pub const SMB2_QUERY_INFO_REQUEST_SIZE: usize = 41;
/// Fixed QUERY_INFO reply structure size from the SMB2 wire format.
pub const SMB2_QUERY_INFO_REPLY_SIZE: usize = 9;
/// Status used when an encoded reply is truncated to the requested output size.
pub const SMB2_STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

/// QUERY_INFO file information namespace.
pub const SMB2_0_INFO_FILE: u8 = 0x01;
/// QUERY_INFO filesystem information namespace.
pub const SMB2_0_INFO_FILESYSTEM: u8 = 0x02;
/// QUERY_INFO security information namespace.
pub const SMB2_0_INFO_SECURITY: u8 = 0x03;
/// QUERY_INFO quota information namespace.
pub const SMB2_0_INFO_QUOTA: u8 = 0x04;

/// FILE_ACCESS_INFORMATION class id.
pub const SMB2_FILE_ACCESS_INFORMATION: u8 = 0x08;
/// FILE_ALIGNMENT_INFORMATION class id.
pub const SMB2_FILE_ALIGNMENT_INFORMATION: u8 = 0x11;
/// FILE_ALL_INFORMATION class id.
pub const SMB2_FILE_ALL_INFORMATION: u8 = 0x12;
/// FILE_ALTERNATE_NAME_INFORMATION class id.
pub const SMB2_FILE_ALTERNATE_NAME_INFORMATION: u8 = 0x15;
/// FILE_ATTRIBUTE_TAG_INFORMATION class id.
pub const SMB2_FILE_ATTRIBUTE_TAG_INFORMATION: u8 = 0x23;
/// FILE_BASIC_INFORMATION class id.
pub const SMB2_FILE_BASIC_INFORMATION: u8 = 0x04;
/// FILE_COMPRESSION_INFORMATION class id.
pub const SMB2_FILE_COMPRESSION_INFORMATION: u8 = 0x1c;
/// FILE_EA_INFORMATION class id.
pub const SMB2_FILE_EA_INFORMATION: u8 = 0x07;
/// FILE_FULL_EA_INFORMATION class id.
pub const SMB2_FILE_FULL_EA_INFORMATION: u8 = 0x0f;
/// FILE_ID_INFORMATION class id.
pub const SMB2_FILE_ID_INFORMATION: u8 = 0x3b;
/// FILE_MODE_INFORMATION class id.
pub const SMB2_FILE_MODE_INFORMATION: u8 = 0x10;
/// FILE_NETWORK_OPEN_INFORMATION class id.
pub const SMB2_FILE_NETWORK_OPEN_INFORMATION: u8 = 0x22;
/// FILE_NORMALIZED_NAME_INFORMATION class id.
pub const SMB2_FILE_NORMALIZED_NAME_INFORMATION: u8 = 0x30;
/// FILE_PIPE_INFORMATION class id.
pub const SMB2_FILE_PIPE_INFORMATION: u8 = 0x17;
/// FILE_PIPE_LOCAL_INFORMATION class id.
pub const SMB2_FILE_PIPE_LOCAL_INFORMATION: u8 = 0x18;
/// FILE_PIPE_REMOTE_INFORMATION class id.
pub const SMB2_FILE_PIPE_REMOTE_INFORMATION: u8 = 0x19;
/// FILE_POSITION_INFORMATION class id.
pub const SMB2_FILE_POSITION_INFORMATION: u8 = 0x0e;
/// FILE_STANDARD_INFORMATION class id.
pub const SMB2_FILE_STANDARD_INFORMATION: u8 = 0x05;
/// FILE_STREAM_INFORMATION class id.
pub const SMB2_FILE_STREAM_INFORMATION: u8 = 0x16;
/// Reserved file information class id.
pub const SMB2_FILE_INFO_CLASS_RESERVED: u8 = 0x40;

/// FILE_FS_ATTRIBUTE_INFORMATION class id.
pub const SMB2_FILE_FS_ATTRIBUTE_INFORMATION: u8 = 5;
/// FILE_FS_CONTROL_INFORMATION class id.
pub const SMB2_FILE_FS_CONTROL_INFORMATION: u8 = 6;
/// FILE_FS_DEVICE_INFORMATION class id.
pub const SMB2_FILE_FS_DEVICE_INFORMATION: u8 = 4;
/// FILE_FS_FULL_SIZE_INFORMATION class id.
pub const SMB2_FILE_FS_FULL_SIZE_INFORMATION: u8 = 7;
/// FILE_FS_OBJECT_ID_INFORMATION class id.
pub const SMB2_FILE_FS_OBJECT_ID_INFORMATION: u8 = 8;
/// FILE_FS_SECTOR_SIZE_INFORMATION class id.
pub const SMB2_FILE_FS_SECTOR_SIZE_INFORMATION: u8 = 11;
/// FILE_FS_SIZE_INFORMATION class id.
pub const SMB2_FILE_FS_SIZE_INFORMATION: u8 = 3;
/// FILE_FS_VOLUME_INFORMATION class id.
pub const SMB2_FILE_FS_VOLUME_INFORMATION: u8 = 1;

/// OWNER_SECURITY_INFORMATION selector copied into `additional_information`.
pub const SMB2_OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
/// GROUP_SECURITY_INFORMATION selector copied into `additional_information`.
pub const SMB2_GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
/// DACL_SECURITY_INFORMATION selector copied into `additional_information`.
pub const SMB2_DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
/// SACL_SECURITY_INFORMATION selector copied into `additional_information`.
pub const SMB2_SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;
/// LABEL_SECURITY_INFORMATION selector copied into `additional_information`.
pub const SMB2_LABEL_SECURITY_INFORMATION: u32 = 0x0000_0010;

/// Errors returned by the QUERY_INFO migration skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryInfoError {
    /// A fixed or variable buffer is shorter than the requested field.
    BufferTooShort,
    /// A declared input or output buffer extends beyond the containing PDU.
    BufferOutOfBounds,
    /// A variable buffer overlaps its fixed command header.
    BufferOverlap,
    /// A fixed structure size field does not match the expected SMB2 size.
    InvalidStructureSize,
    /// A checked offset or length calculation overflowed.
    LengthOverflow,
    /// Query Info request input buffers are not supported by the legacy encoder.
    UnsupportedInputBuffer,
    /// Query Info output classes without a decoder/encoder require passthrough mode.
    UnsupportedOutputClass {
        /// QUERY_INFO info type.
        info_type: u8,
        /// QUERY_INFO file or filesystem information class.
        info_class: u8,
    },
    /// A typed payload was paired with a different QUERY_INFO type/class.
    PayloadClassMismatch {
        /// QUERY_INFO info type.
        info_type: u8,
        /// QUERY_INFO file or filesystem information class.
        info_class: u8,
    },
    /// File information typed payload codec failed.
    FileInfo(FileInfoError),
    /// Filesystem information typed payload codec failed.
    FilesystemInfo(FilesystemInfoError),
    /// Security descriptor typed payload codec failed.
    SecurityDescriptor(SecurityDescriptorCodecError),
}

impl core::fmt::Display for QueryInfoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooShort => {
                f.write_str("buffer is shorter than the fixed QUERY_INFO field")
            }
            Self::BufferOutOfBounds => {
                f.write_str("QUERY_INFO variable buffer extends beyond the PDU")
            }
            Self::BufferOverlap => {
                f.write_str("QUERY_INFO variable buffer overlaps the fixed header")
            }
            Self::InvalidStructureSize => f.write_str("unexpected QUERY_INFO structure size"),
            Self::LengthOverflow => {
                f.write_str("QUERY_INFO offset or length calculation overflowed")
            }
            Self::UnsupportedInputBuffer => f.write_str("QUERY_INFO input buffer is unsupported"),
            Self::UnsupportedOutputClass { .. } => {
                f.write_str("QUERY_INFO output class is unsupported without passthrough")
            }
            Self::PayloadClassMismatch { .. } => {
                f.write_str("QUERY_INFO payload does not match the requested info type/class")
            }
            Self::FileInfo(error) => write!(f, "file information payload error: {error}"),
            Self::FilesystemInfo(error) => {
                write!(f, "filesystem information payload error: {error}")
            }
            Self::SecurityDescriptor(error) => {
                write!(f, "security descriptor payload error: {error}")
            }
        }
    }
}

impl std::error::Error for QueryInfoError {}

impl From<FileInfoError> for QueryInfoError {
    fn from(error: FileInfoError) -> Self {
        Self::FileInfo(error)
    }
}

impl From<FilesystemInfoError> for QueryInfoError {
    fn from(error: FilesystemInfoError) -> Self {
        Self::FilesystemInfo(error)
    }
}

impl From<SecurityDescriptorCodecError> for QueryInfoError {
    fn from(error: SecurityDescriptorCodecError) -> Self {
        Self::SecurityDescriptor(error)
    }
}

/// Result type for QUERY_INFO skeleton helpers.
pub type QueryInfoResult<T> = core::result::Result<T, QueryInfoError>;

/// Raw SMB2 file id carried by QUERY_INFO requests.
pub type Smb2FileId = [u8; SMB2_FD_SIZE];

/// Typed category for a QUERY_INFO info type and class pair recognized by the C file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryInfoPayloadKind {
    /// FILE_ALL_INFORMATION payload.
    FileAllInformation,
    /// FILE_BASIC_INFORMATION payload.
    FileBasicInformation,
    /// FILE_NETWORK_OPEN_INFORMATION payload.
    FileNetworkOpenInformation,
    /// FILE_NORMALIZED_NAME_INFORMATION payload.
    FileNormalizedNameInformation,
    /// FILE_POSITION_INFORMATION payload.
    FilePositionInformation,
    /// FILE_STANDARD_INFORMATION payload.
    FileStandardInformation,
    /// FILE_STREAM_INFORMATION payload.
    FileStreamInformation,
    /// FILE_FS_ATTRIBUTE_INFORMATION payload.
    FileFsAttributeInformation,
    /// FILE_FS_CONTROL_INFORMATION payload.
    FileFsControlInformation,
    /// FILE_FS_DEVICE_INFORMATION payload.
    FileFsDeviceInformation,
    /// FILE_FS_FULL_SIZE_INFORMATION payload.
    FileFsFullSizeInformation,
    /// FILE_FS_OBJECT_ID_INFORMATION payload.
    FileFsObjectIdInformation,
    /// FILE_FS_SECTOR_SIZE_INFORMATION payload.
    FileFsSectorSizeInformation,
    /// FILE_FS_SIZE_INFORMATION payload.
    FileFsSizeInformation,
    /// FILE_FS_VOLUME_INFORMATION payload.
    FileFsVolumeInformation,
    /// SECURITY_DESCRIPTOR payload.
    SecurityDescriptor,
}

/// Decoded or passthrough QUERY_INFO variable payload.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum QueryInfoPayload {
    /// No output buffer is present.
    #[default]
    None,
    /// Raw bytes used for passthrough or not-yet-translated encoders.
    Raw(Vec<u8>),
    /// FILE_ALL_INFORMATION payload.
    FileAllInformation(Smb2FileAllInfo),
    /// FILE_BASIC_INFORMATION payload.
    FileBasicInformation(Smb2FileBasicInfo),
    /// FILE_NETWORK_OPEN_INFORMATION payload.
    FileNetworkOpenInformation(Smb2FileNetworkOpenInfo),
    /// FILE_NORMALIZED_NAME_INFORMATION payload.
    FileNormalizedNameInformation(Smb2FileNameInfo),
    /// FILE_POSITION_INFORMATION payload.
    FilePositionInformation(Smb2FilePositionInfo),
    /// FILE_STANDARD_INFORMATION payload.
    FileStandardInformation(Smb2FileStandardInfo),
    /// FILE_STREAM_INFORMATION payload.
    FileStreamInformation(Vec<Smb2FileStreamInfo>),
    /// FILE_FS_ATTRIBUTE_INFORMATION payload.
    FileFsAttributeInformation(Smb2FileFsAttributeInfo),
    /// FILE_FS_CONTROL_INFORMATION payload.
    FileFsControlInformation(Smb2FileFsControlInfo),
    /// FILE_FS_DEVICE_INFORMATION payload.
    FileFsDeviceInformation(Smb2FileFsDeviceInfo),
    /// FILE_FS_FULL_SIZE_INFORMATION payload.
    FileFsFullSizeInformation(Smb2FileFsFullSizeInfo),
    /// FILE_FS_OBJECT_ID_INFORMATION payload.
    FileFsObjectIdInformation(Smb2FileFsObjectIdInfo),
    /// FILE_FS_SECTOR_SIZE_INFORMATION payload.
    FileFsSectorSizeInformation(Smb2FileFsSectorSizeInfo),
    /// FILE_FS_SIZE_INFORMATION payload.
    FileFsSizeInformation(Smb2FileFsSizeInfo),
    /// FILE_FS_VOLUME_INFORMATION payload.
    FileFsVolumeInformation(Smb2FileFsVolumeInfo),
    /// SECURITY_DESCRIPTOR payload.
    SecurityDescriptor(Smb2SecurityDescriptor),
}

impl QueryInfoPayload {
    /// Returns the payload length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Raw(bytes) => bytes.len(),
            Self::FileAllInformation(info) => {
                FILE_ALL_INFO_PREFIX_SIZE + utf16_name_len(&info.name)
            }
            Self::FileBasicInformation(_) => FILE_BASIC_INFO_SIZE,
            Self::FileNetworkOpenInformation(_) => FILE_NETWORK_OPEN_INFO_SIZE,
            Self::FileNormalizedNameInformation(info) => {
                FILE_NAME_INFO_PREFIX_SIZE
                    + (info.file_name_length as usize).max(utf16_name_len(&info.name))
            }
            Self::FilePositionInformation(_) => FILE_POSITION_INFO_SIZE,
            Self::FileStandardInformation(_) => FILE_STANDARD_INFO_SIZE,
            Self::FileStreamInformation(entries) => file_stream_info_len(entries),
            Self::FileFsAttributeInformation(info) => {
                Smb2FileFsAttributeInfo::fixed_wire_len() + info.filesystem_name.len()
            }
            Self::FileFsControlInformation(_) => Smb2FileFsControlInfo::fixed_wire_len(),
            Self::FileFsDeviceInformation(_) => Smb2FileFsDeviceInfo::fixed_wire_len(),
            Self::FileFsFullSizeInformation(_) => Smb2FileFsFullSizeInfo::fixed_wire_len(),
            Self::FileFsObjectIdInformation(_) => Smb2FileFsObjectIdInfo::fixed_wire_len(),
            Self::FileFsSectorSizeInformation(_) => Smb2FileFsSectorSizeInfo::fixed_wire_len(),
            Self::FileFsSizeInformation(_) => Smb2FileFsSizeInfo::fixed_wire_len(),
            Self::FileFsVolumeInformation(info) => {
                Smb2FileFsVolumeInfo::fixed_wire_len() + info.volume_label.len()
            }
            Self::SecurityDescriptor(info) => security_descriptor_len(info),
        }
    }

    /// Returns whether the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the payload bytes, if any.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::None => &[],
            Self::Raw(bytes) => bytes,
            _ => &[],
        }
    }

    /// Encodes a typed payload to SMB2 wire bytes, or returns raw bytes unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error when a typed payload cannot be encoded or does not match the requested
    /// QUERY_INFO type/class pair.
    pub fn encode_for(&self, info_type: u8, file_info_class: u8) -> QueryInfoResult<Vec<u8>> {
        encode_payload_for(self, info_type, file_info_class)
    }
}

/// Rust-owned counterpart of `struct smb2_query_info_request`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QueryInfoRequest {
    /// QUERY_INFO info type.
    pub info_type: u8,
    /// File, filesystem, security, or quota information class.
    pub file_info_class: u8,
    /// Requested output buffer length.
    pub output_buffer_length: u32,
    /// Wire offset of the optional input buffer.
    pub input_buffer_offset: u16,
    /// Wire byte length of the optional input buffer.
    pub input_buffer_length: u32,
    /// Additional information bitset, used mainly for security queries.
    pub additional_information: u32,
    /// QUERY_INFO flags.
    pub flags: u32,
    /// SMB2 file id of the target handle.
    pub file_id: Smb2FileId,
    /// Optional variable input bytes retained by request-variable processing.
    pub input: Vec<u8>,
}

impl QueryInfoRequest {
    /// Creates a request skeleton with the required info type, class, file id, and output size.
    #[must_use]
    pub fn new(
        info_type: u8,
        file_info_class: u8,
        file_id: Smb2FileId,
        output_buffer_length: u32,
    ) -> Self {
        Self {
            info_type,
            file_info_class,
            output_buffer_length,
            file_id,
            input_buffer_offset: request_payload_offset() as u16,
            ..Self::default()
        }
    }

    /// Returns the fixed request size rounded the same way as the C encoder.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        aligned_fixed_len(SMB2_QUERY_INFO_REQUEST_SIZE)
    }

    /// Returns the input buffer byte count represented by this request.
    #[must_use]
    pub fn input_len(&self) -> usize {
        self.input.len()
    }

    /// Creates a no-I/O encoding plan corresponding to `smb2_encode_query_info_request`.
    #[must_use]
    pub fn encode_plan(&self) -> QueryInfoEncodePlan {
        QueryInfoEncodePlan {
            command: QueryInfoCommandKind::Request,
            fixed_len: Self::fixed_wire_len(),
            variable_len: self.input.len(),
            status: None,
        }
    }
}

/// Rust-owned counterpart of `struct smb2_query_info_reply`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QueryInfoReply {
    /// Wire offset of the output buffer.
    pub output_buffer_offset: u16,
    /// Wire byte length of the output buffer.
    pub output_buffer_length: u32,
    /// Optional decoded or passthrough output buffer.
    pub output_buffer: QueryInfoPayload,
}

impl QueryInfoReply {
    /// Creates an empty reply skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the fixed reply size rounded the same way as the C encoder.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        aligned_fixed_len(SMB2_QUERY_INFO_REPLY_SIZE)
    }

    /// Attaches raw output bytes and updates `output_buffer_length`.
    ///
    /// # Errors
    ///
    /// Returns [`QueryInfoError::LengthOverflow`] if the buffer length cannot fit in `u32`.
    pub fn with_raw_output(mut self, output_buffer: Vec<u8>) -> QueryInfoResult<Self> {
        self.output_buffer_length = len_to_u32(output_buffer.len())?;
        self.output_buffer = QueryInfoPayload::Raw(output_buffer);
        Ok(self)
    }

    /// Creates a no-I/O encoding plan corresponding to `smb2_encode_query_info_reply`.
    #[must_use]
    pub fn encode_plan(&self, requested_output_length: u32) -> QueryInfoEncodePlan {
        let mut variable_len = self.output_buffer.len();
        let mut status = None;
        let requested = requested_output_length as usize;
        if variable_len > requested {
            variable_len = requested;
            status = Some(SMB2_STATUS_BUFFER_OVERFLOW);
        }

        QueryInfoEncodePlan {
            command: QueryInfoCommandKind::Reply,
            fixed_len: Self::fixed_wire_len(),
            variable_len,
            status,
        }
    }
}

/// Lightweight PDU model returned by async command skeleton builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfoPduSkeleton {
    /// SMB2 command id for QUERY_INFO.
    pub command: u16,
    /// Encoded command payload bytes managed by the skeleton.
    pub payload: Vec<u8>,
    /// Info type remembered for reply variable decoding.
    pub info_type: u8,
    /// Information class remembered for reply variable decoding.
    pub file_info_class: u8,
    /// Optional NT status that a full PDU layer would place in the SMB2 header.
    pub status: Option<u32>,
}

/// QUERY_INFO command direction represented by an encoding plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryInfoCommandKind {
    /// Client-to-server QUERY_INFO request.
    Request,
    /// Server-to-client QUERY_INFO reply.
    Reply,
}

/// Side-effect-free summary of what the C encoder would append to a PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryInfoEncodePlan {
    /// Request or reply direction.
    pub command: QueryInfoCommandKind,
    /// Fixed QUERY_INFO structure length after legacy even-size alignment.
    pub fixed_len: usize,
    /// Variable input or output payload length.
    pub variable_len: usize,
    /// Optional NT status selected by reply encoding.
    pub status: Option<u32>,
}

/// Encodes fixed QUERY_INFO request fields and raw input bytes.
///
/// # Errors
///
/// Returns an error if declared lengths cannot fit in SMB2 fields.
pub fn smb2_encode_query_info_request(req: &QueryInfoRequest) -> QueryInfoResult<Vec<u8>> {
    let input_len = req.input.len();
    if input_len > 0 || req.input_buffer_length > 0 {
        return Err(QueryInfoError::UnsupportedInputBuffer);
    }
    let mut buf = vec![0; QueryInfoRequest::fixed_wire_len() + pad_to_64bit(input_len)];
    write_u16(&mut buf, 0, SMB2_QUERY_INFO_REQUEST_SIZE as u16)?;
    write_u8(&mut buf, 2, req.info_type)?;
    write_u8(&mut buf, 3, req.file_info_class)?;
    write_u32(&mut buf, 4, req.output_buffer_length)?;
    write_u16(&mut buf, 8, request_payload_offset() as u16)?;
    write_u32(&mut buf, 12, len_to_u32(input_len)?)?;
    if input_len > 0 {
        write_bytes(&mut buf, QueryInfoRequest::fixed_wire_len(), &req.input)?;
    }
    write_u32(&mut buf, 16, req.additional_information)?;
    write_u32(&mut buf, 20, req.flags)?;
    write_bytes(&mut buf, 24, &req.file_id)?;
    Ok(buf)
}

/// Builds a QUERY_INFO request PDU skeleton corresponding to `smb2_cmd_query_info_async`.
///
/// # Errors
///
/// Returns an error if request encoding fails.
pub fn smb2_cmd_query_info_async(req: &QueryInfoRequest) -> QueryInfoResult<QueryInfoPduSkeleton> {
    Ok(QueryInfoPduSkeleton {
        command: SMB2_QUERY_INFO,
        payload: smb2_encode_query_info_request(req)?,
        info_type: req.info_type,
        file_info_class: req.file_info_class,
        status: None,
    })
}

/// Encodes a QUERY_INFO reply skeleton header and optional passthrough output bytes.
///
/// # Errors
///
/// Returns an error if declared lengths cannot fit in SMB2 fields or the output is unsupported.
pub fn smb2_encode_query_info_reply(
    req: &QueryInfoRequest,
    rep: &QueryInfoReply,
    passthrough: bool,
) -> QueryInfoResult<(Vec<u8>, Option<u32>)> {
    if rep.output_buffer.len() > 0
        && recognized_payload_kind(req.info_type, req.file_info_class).is_none()
        && !passthrough
    {
        return Err(QueryInfoError::UnsupportedOutputClass {
            info_type: req.info_type,
            info_class: req.file_info_class,
        });
    }
    let encoded = rep
        .output_buffer
        .encode_for(req.info_type, req.file_info_class)?;

    let requested_len = req.output_buffer_length as usize;
    let created_len = encoded.len().min(requested_len);
    let status = (encoded.len() > requested_len).then_some(SMB2_STATUS_BUFFER_OVERFLOW);
    let mut buf = vec![0; QueryInfoReply::fixed_wire_len() + pad_to_64bit(created_len)];
    write_u16(&mut buf, 0, SMB2_QUERY_INFO_REPLY_SIZE as u16)?;
    if created_len > 0 {
        write_u16(&mut buf, 2, reply_payload_offset() as u16)?;
    }
    write_u32(&mut buf, 4, len_to_u32(created_len)?)?;
    if created_len > 0 {
        write_bytes(
            &mut buf,
            QueryInfoReply::fixed_wire_len(),
            &encoded[..created_len],
        )?;
    }
    Ok((buf, status))
}

/// Builds a QUERY_INFO reply PDU skeleton corresponding to `smb2_cmd_query_info_reply_async`.
///
/// # Errors
///
/// Returns an error if reply encoding fails.
pub fn smb2_cmd_query_info_reply_async(
    req: &QueryInfoRequest,
    rep: &QueryInfoReply,
    passthrough: bool,
) -> QueryInfoResult<QueryInfoPduSkeleton> {
    let (payload, status) = smb2_encode_query_info_reply(req, rep, passthrough)?;
    Ok(QueryInfoPduSkeleton {
        command: SMB2_QUERY_INFO,
        payload,
        info_type: req.info_type,
        file_info_class: req.file_info_class,
        status,
    })
}

/// Processes fixed QUERY_INFO reply fields and returns the expected variable byte count.
///
/// # Errors
///
/// Returns an error if the fixed reply header is invalid or references bytes outside the PDU.
pub fn smb2_process_query_info_fixed(
    fixed: &[u8],
    pdu_size: usize,
    next_command: Option<usize>,
) -> QueryInfoResult<(QueryInfoReply, usize)> {
    validate_fixed_size(fixed, SMB2_QUERY_INFO_REPLY_SIZE)?;
    let output_buffer_offset = read_u16(fixed, 2)?;
    let output_buffer_length = read_u32(fixed, 4)?;

    if output_buffer_length == 0 {
        return Ok((
            QueryInfoReply {
                output_buffer_offset,
                output_buffer_length,
                output_buffer: QueryInfoPayload::None,
            },
            0,
        ));
    }

    let output_end = usize::from(output_buffer_offset)
        .checked_add(
            usize::try_from(output_buffer_length).map_err(|_| QueryInfoError::LengthOverflow)?,
        )
        .ok_or(QueryInfoError::LengthOverflow)?;
    if output_end > pdu_size || next_command.is_some_and(|limit| output_end > limit) {
        return Err(QueryInfoError::BufferOutOfBounds);
    }
    if usize::from(output_buffer_offset) < reply_payload_offset() {
        return Err(QueryInfoError::BufferOverlap);
    }

    Ok((
        QueryInfoReply {
            output_buffer_offset,
            output_buffer_length,
            output_buffer: QueryInfoPayload::None,
        },
        reply_iov_offset(output_buffer_offset)?.saturating_add(
            usize::try_from(output_buffer_length).map_err(|_| QueryInfoError::LengthOverflow)?,
        ),
    ))
}

/// Attaches or tags the variable QUERY_INFO reply output buffer.
///
/// # Errors
///
/// Returns an error if the output slice does not fit.
pub fn smb2_process_query_info_variable(
    rep: &mut QueryInfoReply,
    info_type: u8,
    file_info_class: u8,
    variable: &[u8],
    passthrough: bool,
) -> QueryInfoResult<()> {
    if rep.output_buffer_length == 0 {
        rep.output_buffer = QueryInfoPayload::None;
        return Ok(());
    }

    let offset = reply_iov_offset(rep.output_buffer_offset)?;
    let len =
        usize::try_from(rep.output_buffer_length).map_err(|_| QueryInfoError::LengthOverflow)?;
    let bytes = slice_at(variable, offset, len)?.to_vec();
    rep.output_buffer = match recognized_payload_kind(info_type, file_info_class) {
        Some(kind) => decode_payload(kind, &bytes)?,
        None if passthrough => QueryInfoPayload::Raw(bytes),
        None => {
            return Err(QueryInfoError::UnsupportedOutputClass {
                info_type,
                info_class: file_info_class,
            })
        }
    };
    Ok(())
}

/// Processes fixed QUERY_INFO request fields and returns the expected variable byte count.
///
/// # Errors
///
/// Returns an error if the fixed request header is invalid or references bytes outside the PDU.
pub fn smb2_process_query_info_request_fixed(
    fixed: &[u8],
    pdu_size: usize,
) -> QueryInfoResult<(QueryInfoRequest, usize)> {
    validate_fixed_size(fixed, SMB2_QUERY_INFO_REQUEST_SIZE)?;
    let input_buffer_offset = read_u16(fixed, 8)?;
    let input_buffer_length = read_u32(fixed, 12)?;

    if input_buffer_length == 0 {
        return Ok((
            decode_request_fixed(fixed, input_buffer_offset, input_buffer_length)?,
            0,
        ));
    }

    let input_end = usize::from(input_buffer_offset)
        .checked_add(
            usize::try_from(input_buffer_length).map_err(|_| QueryInfoError::LengthOverflow)?,
        )
        .ok_or(QueryInfoError::LengthOverflow)?;
    if input_end > pdu_size {
        return Err(QueryInfoError::BufferOutOfBounds);
    }
    if usize::from(input_buffer_offset) < request_payload_offset() {
        return Err(QueryInfoError::BufferOverlap);
    }

    Ok((
        decode_request_fixed(fixed, input_buffer_offset, input_buffer_length)?,
        request_iov_offset(input_buffer_offset)?.saturating_add(
            usize::try_from(input_buffer_length).map_err(|_| QueryInfoError::LengthOverflow)?,
        ),
    ))
}

/// Attaches the variable QUERY_INFO request input buffer.
///
/// # Errors
///
/// Returns an error if the input slice does not fit in `variable`.
pub fn smb2_process_query_info_request_variable(
    req: &mut QueryInfoRequest,
    variable: &[u8],
) -> QueryInfoResult<()> {
    if req.input_buffer_length == 0 {
        return Ok(());
    }

    let offset = request_iov_offset(req.input_buffer_offset)?;
    let len =
        usize::try_from(req.input_buffer_length).map_err(|_| QueryInfoError::LengthOverflow)?;
    req.input = slice_at(variable, offset, len)?.to_vec();
    Ok(())
}

/// Returns the fixed request payload offset from the SMB2 header start.
#[must_use]
pub const fn request_payload_offset() -> usize {
    SMB2_HEADER_SIZE + QueryInfoRequest::fixed_wire_len()
}

/// Returns the fixed reply payload offset from the SMB2 header start.
#[must_use]
pub const fn reply_payload_offset() -> usize {
    SMB2_HEADER_SIZE + QueryInfoReply::fixed_wire_len()
}

/// Returns the offset used by `IOVREQ_OFFSET_QUERY` in the C implementation.
///
/// # Errors
///
/// Returns [`QueryInfoError::LengthOverflow`] when the input offset points before the request payload.
pub fn request_iov_offset(input_buffer_offset: u16) -> QueryInfoResult<usize> {
    usize::from(input_buffer_offset)
        .checked_sub(request_payload_offset())
        .ok_or(QueryInfoError::LengthOverflow)
}

/// Returns the offset used by `IOV_OFFSET_QUERY` in the C implementation.
///
/// # Errors
///
/// Returns [`QueryInfoError::LengthOverflow`] when the output offset points before the reply payload.
pub fn reply_iov_offset(output_buffer_offset: u16) -> QueryInfoResult<usize> {
    usize::from(output_buffer_offset)
        .checked_sub(reply_payload_offset())
        .ok_or(QueryInfoError::LengthOverflow)
}

/// Rounds `len` up to the next 64-bit boundary.
#[must_use]
pub const fn pad_to_64bit(len: usize) -> usize {
    (len + 7) & !7
}

fn recognized_payload_kind(info_type: u8, file_info_class: u8) -> Option<QueryInfoPayloadKind> {
    match (info_type, file_info_class) {
        (SMB2_0_INFO_FILE, SMB2_FILE_ALL_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileAllInformation)
        }
        (SMB2_0_INFO_FILE, SMB2_FILE_BASIC_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileBasicInformation)
        }
        (SMB2_0_INFO_FILE, SMB2_FILE_NETWORK_OPEN_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileNetworkOpenInformation)
        }
        (SMB2_0_INFO_FILE, SMB2_FILE_NORMALIZED_NAME_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileNormalizedNameInformation)
        }
        (SMB2_0_INFO_FILE, SMB2_FILE_POSITION_INFORMATION) => {
            Some(QueryInfoPayloadKind::FilePositionInformation)
        }
        (SMB2_0_INFO_FILE, SMB2_FILE_STANDARD_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileStandardInformation)
        }
        (SMB2_0_INFO_FILE, SMB2_FILE_STREAM_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileStreamInformation)
        }
        (SMB2_0_INFO_FILESYSTEM, SMB2_FILE_FS_ATTRIBUTE_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileFsAttributeInformation)
        }
        (SMB2_0_INFO_FILESYSTEM, SMB2_FILE_FS_CONTROL_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileFsControlInformation)
        }
        (SMB2_0_INFO_FILESYSTEM, SMB2_FILE_FS_DEVICE_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileFsDeviceInformation)
        }
        (SMB2_0_INFO_FILESYSTEM, SMB2_FILE_FS_FULL_SIZE_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileFsFullSizeInformation)
        }
        (SMB2_0_INFO_FILESYSTEM, SMB2_FILE_FS_OBJECT_ID_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileFsObjectIdInformation)
        }
        (SMB2_0_INFO_FILESYSTEM, SMB2_FILE_FS_SECTOR_SIZE_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileFsSectorSizeInformation)
        }
        (SMB2_0_INFO_FILESYSTEM, SMB2_FILE_FS_SIZE_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileFsSizeInformation)
        }
        (SMB2_0_INFO_FILESYSTEM, SMB2_FILE_FS_VOLUME_INFORMATION) => {
            Some(QueryInfoPayloadKind::FileFsVolumeInformation)
        }
        (SMB2_0_INFO_SECURITY, _) => Some(QueryInfoPayloadKind::SecurityDescriptor),
        _ => None,
    }
}

fn decode_payload(kind: QueryInfoPayloadKind, bytes: &[u8]) -> QueryInfoResult<QueryInfoPayload> {
    match kind {
        QueryInfoPayloadKind::FileAllInformation => Ok(QueryInfoPayload::FileAllInformation(
            smb2_decode_file_all_info(bytes)?,
        )),
        QueryInfoPayloadKind::FileBasicInformation => Ok(QueryInfoPayload::FileBasicInformation(
            smb2_decode_file_basic_info(bytes)?,
        )),
        QueryInfoPayloadKind::FileNetworkOpenInformation => {
            Ok(QueryInfoPayload::FileNetworkOpenInformation(
                smb2_decode_file_network_open_info(bytes)?,
            ))
        }
        QueryInfoPayloadKind::FileNormalizedNameInformation => {
            Ok(QueryInfoPayload::FileNormalizedNameInformation(
                smb2_decode_file_normalized_name_info(bytes)?,
            ))
        }
        QueryInfoPayloadKind::FilePositionInformation => Ok(
            QueryInfoPayload::FilePositionInformation(smb2_decode_file_position_info(bytes)?),
        ),
        QueryInfoPayloadKind::FileStandardInformation => Ok(
            QueryInfoPayload::FileStandardInformation(smb2_decode_file_standard_info(bytes)?),
        ),
        QueryInfoPayloadKind::FileStreamInformation => Ok(QueryInfoPayload::FileStreamInformation(
            smb2_decode_file_stream_info(bytes)?,
        )),
        QueryInfoPayloadKind::FileFsAttributeInformation => {
            Ok(QueryInfoPayload::FileFsAttributeInformation(
                smb2_decode_file_fs_attribute_info(bytes)?,
            ))
        }
        QueryInfoPayloadKind::FileFsControlInformation => Ok(
            QueryInfoPayload::FileFsControlInformation(smb2_decode_file_fs_control_info(bytes)?),
        ),
        QueryInfoPayloadKind::FileFsDeviceInformation => Ok(
            QueryInfoPayload::FileFsDeviceInformation(smb2_decode_file_fs_device_info(bytes)?),
        ),
        QueryInfoPayloadKind::FileFsFullSizeInformation => Ok(
            QueryInfoPayload::FileFsFullSizeInformation(smb2_decode_file_fs_full_size_info(bytes)?),
        ),
        QueryInfoPayloadKind::FileFsObjectIdInformation => Ok(
            QueryInfoPayload::FileFsObjectIdInformation(smb2_decode_file_fs_object_id_info(bytes)?),
        ),
        QueryInfoPayloadKind::FileFsSectorSizeInformation => {
            Ok(QueryInfoPayload::FileFsSectorSizeInformation(
                smb2_decode_file_fs_sector_size_info(bytes)?,
            ))
        }
        QueryInfoPayloadKind::FileFsSizeInformation => Ok(QueryInfoPayload::FileFsSizeInformation(
            smb2_decode_file_fs_size_info(bytes)?,
        )),
        QueryInfoPayloadKind::FileFsVolumeInformation => Ok(
            QueryInfoPayload::FileFsVolumeInformation(smb2_decode_file_fs_volume_info(bytes)?),
        ),
        QueryInfoPayloadKind::SecurityDescriptor => Ok(QueryInfoPayload::SecurityDescriptor(
            smb2_decode_security_descriptor(bytes).map_err(SecurityDescriptorCodecError::from)?,
        )),
    }
}

fn encode_payload_for(
    payload: &QueryInfoPayload,
    info_type: u8,
    file_info_class: u8,
) -> QueryInfoResult<Vec<u8>> {
    let Some(kind) = recognized_payload_kind(info_type, file_info_class) else {
        return match payload {
            QueryInfoPayload::Raw(bytes) => Ok(bytes.clone()),
            QueryInfoPayload::None => Ok(Vec::new()),
            _ => Err(QueryInfoError::PayloadClassMismatch {
                info_type,
                info_class: file_info_class,
            }),
        };
    };

    match (kind, payload) {
        (_, QueryInfoPayload::None) => Ok(Vec::new()),
        (_, QueryInfoPayload::Raw(bytes)) => Ok(bytes.clone()),
        (QueryInfoPayloadKind::FileAllInformation, QueryInfoPayload::FileAllInformation(info)) => {
            encode_with_len(payload.len(), |buf| smb2_encode_file_all_info(info, buf))
        }
        (
            QueryInfoPayloadKind::FileBasicInformation,
            QueryInfoPayload::FileBasicInformation(info),
        ) => encode_with_len(FILE_BASIC_INFO_SIZE, |buf| {
            smb2_encode_file_basic_info(info, buf)
        }),
        (
            QueryInfoPayloadKind::FileNetworkOpenInformation,
            QueryInfoPayload::FileNetworkOpenInformation(info),
        ) => encode_with_len(FILE_NETWORK_OPEN_INFO_SIZE, |buf| {
            smb2_encode_file_network_open_info(info, buf)
        }),
        (
            QueryInfoPayloadKind::FileNormalizedNameInformation,
            QueryInfoPayload::FileNormalizedNameInformation(info),
        ) => encode_with_len(payload.len(), |buf| {
            smb2_encode_file_normalized_name_info(info, buf)
        }),
        (
            QueryInfoPayloadKind::FilePositionInformation,
            QueryInfoPayload::FilePositionInformation(info),
        ) => encode_with_len(FILE_POSITION_INFO_SIZE, |buf| {
            smb2_encode_file_position_info(info, buf)
        }),
        (
            QueryInfoPayloadKind::FileStandardInformation,
            QueryInfoPayload::FileStandardInformation(info),
        ) => encode_with_len(FILE_STANDARD_INFO_SIZE, |buf| {
            smb2_encode_file_standard_info(info, buf)
        }),
        (
            QueryInfoPayloadKind::FileStreamInformation,
            QueryInfoPayload::FileStreamInformation(info),
        ) => encode_with_len(payload.len(), |buf| smb2_encode_file_stream_info(info, buf)),
        (
            QueryInfoPayloadKind::FileFsAttributeInformation,
            QueryInfoPayload::FileFsAttributeInformation(info),
        ) => info.encode().map_err(QueryInfoError::from),
        (
            QueryInfoPayloadKind::FileFsControlInformation,
            QueryInfoPayload::FileFsControlInformation(info),
        ) => Ok(info.encode()),
        (
            QueryInfoPayloadKind::FileFsDeviceInformation,
            QueryInfoPayload::FileFsDeviceInformation(info),
        ) => Ok(info.encode()),
        (
            QueryInfoPayloadKind::FileFsFullSizeInformation,
            QueryInfoPayload::FileFsFullSizeInformation(info),
        ) => Ok(info.encode()),
        (
            QueryInfoPayloadKind::FileFsObjectIdInformation,
            QueryInfoPayload::FileFsObjectIdInformation(info),
        ) => Ok(info.encode()),
        (
            QueryInfoPayloadKind::FileFsSectorSizeInformation,
            QueryInfoPayload::FileFsSectorSizeInformation(info),
        ) => Ok(info.encode()),
        (
            QueryInfoPayloadKind::FileFsSizeInformation,
            QueryInfoPayload::FileFsSizeInformation(info),
        ) => Ok(info.encode()),
        (
            QueryInfoPayloadKind::FileFsVolumeInformation,
            QueryInfoPayload::FileFsVolumeInformation(info),
        ) => info.encode().map_err(QueryInfoError::from),
        (QueryInfoPayloadKind::SecurityDescriptor, QueryInfoPayload::SecurityDescriptor(info)) => {
            smb2_encode_security_descriptor(info).map_err(QueryInfoError::from)
        }
        _ => Err(QueryInfoError::PayloadClassMismatch {
            info_type,
            info_class: file_info_class,
        }),
    }
}

fn encode_with_len(
    len: usize,
    encode: impl FnOnce(&mut [u8]) -> Result<usize, FileInfoError>,
) -> QueryInfoResult<Vec<u8>> {
    let mut buf = vec![0; len];
    let written = encode(&mut buf)?;
    buf.truncate(written);
    Ok(buf)
}

fn utf16_name_len(name: &Option<String>) -> usize {
    name.as_deref()
        .map_or(0, |name| name.encode_utf16().count().saturating_mul(2))
}

fn file_stream_info_len(entries: &[Smb2FileStreamInfo]) -> usize {
    let mut total = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let name_len = utf16_name_len(&entry.stream_name);
        let entry_len = FILE_STREAM_INFO_HEADER_SIZE.saturating_add(name_len);
        if index + 1 == entries.len() {
            total = total.saturating_add(entry_len);
        } else {
            total = total.saturating_add(pad_to_64bit(entry_len));
        }
    }
    total
}

fn security_descriptor_len(info: &Smb2SecurityDescriptor) -> usize {
    20usize
        .saturating_add(info.owner.as_ref().map_or(0, sid_len))
        .saturating_add(info.group.as_ref().map_or(0, sid_len))
        .saturating_add(info.sacl.as_ref().map_or(0, acl_len))
        .saturating_add(info.dacl.as_ref().map_or(0, acl_len))
}

fn sid_len(sid: &Smb2Sid) -> usize {
    8usize.saturating_add(sid.sub_auth.len().saturating_mul(4))
}

fn acl_len(acl: &Smb2Acl) -> usize {
    acl.aces
        .iter()
        .fold(8usize, |total, ace| total.saturating_add(ace_len(ace)))
}

fn ace_len(ace: &Smb2Ace) -> usize {
    4usize.saturating_add(ace_payload_len(ace))
}

fn ace_payload_len(ace: &Smb2Ace) -> usize {
    match ace.ace_type {
        SMB2_ACCESS_ALLOWED_ACE_TYPE
        | SMB2_ACCESS_DENIED_ACE_TYPE
        | SMB2_SYSTEM_AUDIT_ACE_TYPE
        | SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE
        | SMB2_SYSTEM_SCOPED_POLICY_ID_ACE_TYPE => {
            4usize.saturating_add(ace.sid.as_ref().map_or(0, sid_len))
        }
        SMB2_ACCESS_ALLOWED_OBJECT_ACE_TYPE
        | SMB2_ACCESS_DENIED_OBJECT_ACE_TYPE
        | SMB2_SYSTEM_AUDIT_OBJECT_ACE_TYPE => {
            40usize.saturating_add(ace.sid.as_ref().map_or(0, sid_len))
        }
        SMB2_ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        | SMB2_ACCESS_DENIED_CALLBACK_ACE_TYPE
        | SMB2_SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => 4usize
            .saturating_add(ace.sid.as_ref().map_or(0, sid_len))
            .saturating_add(ace.application_data.len()),
        _ => ace.raw_data.len(),
    }
}

const fn aligned_fixed_len(len: usize) -> usize {
    len & !1
}

fn validate_fixed_size(buf: &[u8], expected: usize) -> QueryInfoResult<()> {
    if buf.len() < aligned_fixed_len(expected) {
        return Err(QueryInfoError::BufferTooShort);
    }

    let struct_size = read_u16(buf, 0)?;
    if usize::from(struct_size) != expected
        || aligned_fixed_len(usize::from(struct_size)) != buf.len()
    {
        return Err(QueryInfoError::InvalidStructureSize);
    }

    Ok(())
}

fn decode_request_fixed(
    fixed: &[u8],
    input_buffer_offset: u16,
    input_buffer_length: u32,
) -> QueryInfoResult<QueryInfoRequest> {
    let mut file_id = [0; SMB2_FD_SIZE];
    file_id.copy_from_slice(slice_at(fixed, 24, SMB2_FD_SIZE)?);
    Ok(QueryInfoRequest {
        info_type: read_u8(fixed, 2)?,
        file_info_class: read_u8(fixed, 3)?,
        output_buffer_length: read_u32(fixed, 4)?,
        input_buffer_offset,
        input_buffer_length,
        additional_information: read_u32(fixed, 16)?,
        flags: read_u32(fixed, 20)?,
        file_id,
        input: Vec::new(),
    })
}

fn read_u8(data: &[u8], offset: usize) -> QueryInfoResult<u8> {
    data.get(offset)
        .copied()
        .ok_or(QueryInfoError::BufferTooShort)
}

fn read_u16(data: &[u8], offset: usize) -> QueryInfoResult<u16> {
    let bytes = slice_at(data, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> QueryInfoResult<u32> {
    let bytes = slice_at(data, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u8(data: &mut [u8], offset: usize, value: u8) -> QueryInfoResult<()> {
    let Some(slot) = data.get_mut(offset) else {
        return Err(QueryInfoError::BufferTooShort);
    };
    *slot = value;
    Ok(())
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) -> QueryInfoResult<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) -> QueryInfoResult<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_bytes(data: &mut [u8], offset: usize, value: &[u8]) -> QueryInfoResult<()> {
    let end = offset
        .checked_add(value.len())
        .ok_or(QueryInfoError::LengthOverflow)?;
    let Some(dst) = data.get_mut(offset..end) else {
        return Err(QueryInfoError::BufferTooShort);
    };
    dst.copy_from_slice(value);
    Ok(())
}

fn slice_at(data: &[u8], offset: usize, len: usize) -> QueryInfoResult<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(QueryInfoError::LengthOverflow)?;
    data.get(offset..end).ok_or(QueryInfoError::BufferTooShort)
}

fn len_to_u32(len: usize) -> QueryInfoResult<u32> {
    u32::try_from(len).map_err(|_| QueryInfoError::LengthOverflow)
}
