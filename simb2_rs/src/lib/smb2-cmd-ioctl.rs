//! IOCTL command pack/unpack skeleton migrated from `lib/smb2-cmd-ioctl.c`.

use crate::include::libsmb2_private::SMB2_HEADER_SIZE;
use crate::include::smb2::smb2_ioctl::FSCTL_VALIDATE_NEGOTIATE_INFO;

/// Number of bytes in an SMB2 file identifier.
pub const SMB2_FD_SIZE: usize = 16;
/// Wire structure size for `struct smb2_ioctl_request`.
pub const SMB2_IOCTL_REQUEST_SIZE: usize = 57;
/// Wire structure size for `struct smb2_ioctl_reply`.
pub const SMB2_IOCTL_REPLY_SIZE: usize = 49;
/// Wire structure size for validate-negotiate IOCTL data.
pub const SMB2_IOCTL_VALIDATE_NEGOTIATE_INFO_SIZE: usize = 24;
/// Compatibility alias preserving the legacy C macro spelling.
pub const SMB2_IOCTL_VALIDIATE_NEGOTIATE_INFO_SIZE: usize = SMB2_IOCTL_VALIDATE_NEGOTIATE_INFO_SIZE;
/// IOCTL flag indicating an FSCTL control code.
pub const SMB2_0_IOCTL_IS_FSCTL: u32 = 0x0000_0001;
/// Default maximum output response used by the legacy request encoder.
pub const SMB2_IOCTL_MAX_OUTPUT_RESPONSE: u32 = 65_535;

const EINVAL: i32 = -22;

/// Raw SMB2 file id carried by IOCTL requests and replies.
pub type Smb2FileId = [u8; SMB2_FD_SIZE];

/// Errors returned by IOCTL skeleton parsers and pack-planning helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoctlSkeletonError {
    /// The fixed buffer is shorter than the requested field.
    BufferTooSmall,
    /// The SMB2 structure size does not match the expected IOCTL size.
    UnexpectedStructSize {
        /// Structure size read from the wire buffer.
        actual: u16,
        /// Expected SMB2 IOCTL structure size.
        expected: u16,
    },
    /// A variable buffer offset points into the fixed header.
    BufferOverlapsHeader,
    /// A checked offset or length calculation overflowed.
    OffsetOverflow,
    /// The input or output variable data length exceeds the available bytes.
    VariableBufferTooSmall,
    /// The IOCTL control code is intentionally not decoded by this skeleton.
    UnsupportedCtlCode(u32),
}

impl IoctlSkeletonError {
    /// Returns the errno-style code used by the legacy C implementation.
    #[must_use]
    pub fn errno(self) -> i32 {
        match self {
            Self::BufferTooSmall
            | Self::UnexpectedStructSize { .. }
            | Self::BufferOverlapsHeader
            | Self::OffsetOverflow
            | Self::VariableBufferTooSmall
            | Self::UnsupportedCtlCode(_) => EINVAL,
        }
    }
}

/// Result type used by this IOCTL migration skeleton.
pub type IoctlResult<T> = core::result::Result<T, IoctlSkeletonError>;

/// Rust-owned counterpart of `struct smb2_ioctl_validate_negotiate_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoctlValidateNegotiateInfo {
    /// Negotiated server capabilities.
    pub capabilities: u32,
    /// Server GUID.
    pub guid: [u8; 16],
    /// Negotiated security mode.
    pub security_mode: u16,
    /// Negotiated dialect.
    pub dialect: u16,
}

impl IoctlValidateNegotiateInfo {
    /// Creates validate-negotiate information from decoded fields.
    #[must_use]
    pub fn new(capabilities: u32, guid: [u8; 16], security_mode: u16, dialect: u16) -> Self {
        Self {
            capabilities,
            guid,
            security_mode,
            dialect,
        }
    }

    /// Encodes the fixed validate-negotiate payload layout.
    #[must_use]
    pub fn encode_fixed(self) -> [u8; SMB2_IOCTL_VALIDATE_NEGOTIATE_INFO_SIZE] {
        let mut out = [0; SMB2_IOCTL_VALIDATE_NEGOTIATE_INFO_SIZE];
        out[0..4].copy_from_slice(&self.capabilities.to_le_bytes());
        out[4..20].copy_from_slice(&self.guid);
        out[20..22].copy_from_slice(&self.security_mode.to_le_bytes());
        out[22..24].copy_from_slice(&self.dialect.to_le_bytes());
        out
    }

    /// Decodes the fixed validate-negotiate payload layout.
    ///
    /// # Errors
    ///
    /// Returns `BufferTooSmall` when `buf` is shorter than the legacy fixed
    /// validate-negotiate layout.
    pub fn decode_fixed(buf: &[u8]) -> IoctlResult<Self> {
        if buf.len() < SMB2_IOCTL_VALIDATE_NEGOTIATE_INFO_SIZE {
            return Err(IoctlSkeletonError::BufferTooSmall);
        }

        let mut guid = [0; 16];
        guid.copy_from_slice(&buf[4..20]);

        Ok(Self {
            capabilities: read_u32_le(buf, 0)?,
            guid,
            security_mode: read_u16_le(buf, 20)?,
            dialect: read_u16_le(buf, 22)?,
        })
    }
}

/// Variable IOCTL request payload recognized by the migration skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoctlRequestInput {
    /// No request input buffer is present.
    None,
    /// Decoded `SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO` input.
    ValidateNegotiateInfo(IoctlValidateNegotiateInfo),
    /// Raw passthrough bytes for control codes not decoded here.
    Raw(Vec<u8>),
}

impl IoctlRequestInput {
    /// Returns the input buffer length represented by this payload.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::ValidateNegotiateInfo(_) => SMB2_IOCTL_VALIDATE_NEGOTIATE_INFO_SIZE,
            Self::Raw(bytes) => bytes.len(),
        }
    }

    /// Returns whether this payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Variable IOCTL reply payload recognized by the migration skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoctlReplyOutput {
    /// No reply output buffer is present.
    None,
    /// Decoded `SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO` output.
    ValidateNegotiateInfo(IoctlValidateNegotiateInfo),
    /// Raw passthrough bytes for control codes not decoded here.
    Raw(Vec<u8>),
}

impl IoctlReplyOutput {
    /// Returns the output buffer length represented by this payload.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::ValidateNegotiateInfo(_) => SMB2_IOCTL_VALIDATE_NEGOTIATE_INFO_SIZE,
            Self::Raw(bytes) => bytes.len(),
        }
    }

    /// Returns whether this payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Rust-owned counterpart of `struct smb2_ioctl_request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoctlRequest {
    /// IOCTL control code.
    pub ctl_code: u32,
    /// Target file id.
    pub file_id: Smb2FileId,
    /// Input buffer offset from the SMB2 header start.
    pub input_offset: u32,
    /// Input buffer length.
    pub input_count: u32,
    /// Maximum accepted input response length.
    pub max_input_response: u32,
    /// Output buffer offset from the SMB2 header start.
    pub output_offset: u32,
    /// Output buffer length.
    pub output_count: u32,
    /// Maximum accepted output response length.
    pub max_output_response: u32,
    /// IOCTL request flags.
    pub flags: u32,
    /// Optional decoded or raw request input.
    pub input: IoctlRequestInput,
}

impl IoctlRequest {
    /// Creates a request skeleton with legacy encoder defaults.
    #[must_use]
    pub fn new(ctl_code: u32, file_id: Smb2FileId, input: IoctlRequestInput, flags: u32) -> Self {
        let input_count = saturating_u32(input.len());
        Self {
            ctl_code,
            file_id,
            input_offset: request_payload_offset() as u32,
            input_count,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response: SMB2_IOCTL_MAX_OUTPUT_RESPONSE,
            flags,
            input,
        }
    }

    /// Parses the fixed request fields produced by `smb2_process_ioctl_request_fixed`.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed buffer is too short, has an unexpected
    /// structure size, or contains an input offset that overlaps the fixed header.
    pub fn decode_fixed(buf: &[u8]) -> IoctlResult<Self> {
        validate_fixed_size(buf, SMB2_IOCTL_REQUEST_SIZE)?;
        let input_offset = read_u32_le(buf, 24)?;
        let input_count = read_u32_le(buf, 28)?;

        if input_count != 0 && (input_offset as usize) < request_payload_offset() {
            return Err(IoctlSkeletonError::BufferOverlapsHeader);
        }

        Ok(Self {
            ctl_code: read_u32_le(buf, 4)?,
            file_id: read_file_id(buf, 8)?,
            input_offset,
            input_count,
            max_input_response: read_u32_le(buf, 32)?,
            output_offset: read_u32_le(buf, 36)?,
            output_count: read_u32_le(buf, 40)?,
            max_output_response: read_u32_le(buf, 44)?,
            flags: read_u32_le(buf, 48)?,
            input: IoctlRequestInput::None,
        })
    }

    /// Builds a decoded input payload from the variable request bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `variable` cannot satisfy `input_count`, or if a
    /// recognized control-code payload is shorter than its fixed layout.
    pub fn decode_input(&mut self, variable: &[u8], passthrough: bool) -> IoctlResult<()> {
        let input_count = self.input_count as usize;
        if input_count > variable.len() {
            return Err(IoctlSkeletonError::VariableBufferTooSmall);
        }

        self.input = match self.ctl_code {
            FSCTL_VALIDATE_NEGOTIATE_INFO => IoctlRequestInput::ValidateNegotiateInfo(
                IoctlValidateNegotiateInfo::decode_fixed(variable)?,
            ),
            _ if passthrough => IoctlRequestInput::Raw(variable[..input_count].to_vec()),
            _ => return Err(IoctlSkeletonError::UnsupportedCtlCode(self.ctl_code)),
        };
        self.input_count = saturating_u32(self.input.len());
        Ok(())
    }

    /// Returns the variable byte count requested by the fixed request header.
    ///
    /// # Errors
    ///
    /// Returns `OffsetOverflow` if the offset math cannot be represented.
    pub fn variable_span_len(&self) -> IoctlResult<usize> {
        Ok(request_iov_offset(self.input_offset)?.saturating_add(self.input_count as usize))
    }

    /// Creates a no-I/O encoding plan corresponding to `smb2_encode_ioctl_request`.
    #[must_use]
    pub fn encode_plan(&self) -> IoctlEncodePlan {
        IoctlEncodePlan {
            command: IoctlCommandKind::Request,
            fixed_len: aligned_fixed_len(SMB2_IOCTL_REQUEST_SIZE),
            input_len: self.input.len(),
            output_len: 0,
            flags: self.flags,
        }
    }
}

/// Rust-owned counterpart of `struct smb2_ioctl_reply`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoctlReply {
    /// IOCTL control code.
    pub ctl_code: u32,
    /// Target file id.
    pub file_id: Smb2FileId,
    /// Input buffer offset from the SMB2 header start.
    pub input_offset: u32,
    /// Input buffer length.
    pub input_count: u32,
    /// Output buffer offset from the SMB2 header start.
    pub output_offset: u32,
    /// Output buffer length.
    pub output_count: u32,
    /// IOCTL reply flags.
    pub flags: u32,
    /// Optional decoded or raw reply output.
    pub output: IoctlReplyOutput,
}

impl IoctlReply {
    /// Creates a reply skeleton with legacy encoder offsets.
    #[must_use]
    pub fn new(ctl_code: u32, file_id: Smb2FileId, output: IoctlReplyOutput, flags: u32) -> Self {
        let output_count = saturating_u32(output.len());
        let input_offset = reply_payload_offset() as u32;
        let output_offset = reply_payload_offset() as u32;
        Self {
            ctl_code,
            file_id,
            input_offset,
            input_count: 0,
            output_offset,
            output_count,
            flags,
            output,
        }
    }

    /// Parses the fixed reply fields produced by `smb2_process_ioctl_fixed`.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed buffer is too short, has an unexpected
    /// structure size, or contains an output offset that overlaps the fixed header.
    pub fn decode_fixed(buf: &[u8]) -> IoctlResult<Self> {
        validate_fixed_size(buf, SMB2_IOCTL_REPLY_SIZE)?;
        let output_offset = read_u32_le(buf, 32)?;
        let output_count = read_u32_le(buf, 36)?;

        if output_count != 0 && (output_offset as usize) < reply_payload_offset() {
            return Err(IoctlSkeletonError::BufferOverlapsHeader);
        }

        Ok(Self {
            ctl_code: read_u32_le(buf, 4)?,
            file_id: read_file_id(buf, 8)?,
            input_offset: read_u32_le(buf, 24)?,
            input_count: read_u32_le(buf, 28)?,
            output_offset,
            output_count,
            flags: read_u32_le(buf, 40)?,
            output: IoctlReplyOutput::None,
        })
    }

    /// Builds a decoded output payload from the variable reply bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `variable` cannot satisfy `output_count`, or if a
    /// recognized control-code payload is shorter than its fixed layout.
    pub fn decode_output(&mut self, variable: &[u8], passthrough: bool) -> IoctlResult<()> {
        let output_count = self.output_count as usize;
        if output_count > variable.len() {
            return Err(IoctlSkeletonError::VariableBufferTooSmall);
        }

        self.output = match self.ctl_code {
            FSCTL_VALIDATE_NEGOTIATE_INFO => IoctlReplyOutput::ValidateNegotiateInfo(
                IoctlValidateNegotiateInfo::decode_fixed(variable)?,
            ),
            _ if passthrough => IoctlReplyOutput::Raw(variable[..output_count].to_vec()),
            _ => return Err(IoctlSkeletonError::UnsupportedCtlCode(self.ctl_code)),
        };
        self.output_count = saturating_u32(self.output.len());
        Ok(())
    }

    /// Returns the variable byte count requested by the fixed reply header.
    ///
    /// # Errors
    ///
    /// Returns `OffsetOverflow` if the offset math cannot be represented.
    pub fn variable_span_len(&self) -> IoctlResult<usize> {
        let output_start = reply_iov_offset(self.output_offset)?;
        Ok(output_start
            .saturating_add(pad_to_64bit(self.input_count as usize))
            .saturating_add(self.output_count as usize))
    }

    /// Creates a no-I/O encoding plan corresponding to `smb2_encode_ioctl_reply`.
    #[must_use]
    pub fn encode_plan(&self) -> IoctlEncodePlan {
        IoctlEncodePlan {
            command: IoctlCommandKind::Reply,
            fixed_len: aligned_fixed_len(SMB2_IOCTL_REPLY_SIZE),
            input_len: self.input_count as usize,
            output_len: self.output.len(),
            flags: self.flags,
        }
    }
}

/// IOCTL command direction represented by an encoding plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoctlCommandKind {
    /// Client-to-server IOCTL request.
    Request,
    /// Server-to-client IOCTL reply.
    Reply,
}

/// Side-effect-free summary of what the C encoder would append to a PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoctlEncodePlan {
    /// Request or reply direction.
    pub command: IoctlCommandKind,
    /// Fixed IOCTL structure length after legacy even-size alignment.
    pub fixed_len: usize,
    /// Variable input payload length.
    pub input_len: usize,
    /// Variable output payload length.
    pub output_len: usize,
    /// IOCTL flags copied into the fixed structure.
    pub flags: u32,
}

/// Returns the fixed request payload offset from the SMB2 header start.
#[must_use]
pub const fn request_payload_offset() -> usize {
    SMB2_HEADER_SIZE + aligned_fixed_len(SMB2_IOCTL_REQUEST_SIZE)
}

/// Returns the fixed reply payload offset from the SMB2 header start.
#[must_use]
pub const fn reply_payload_offset() -> usize {
    SMB2_HEADER_SIZE + aligned_fixed_len(SMB2_IOCTL_REPLY_SIZE)
}

/// Returns the offset used by `IOVREQ_OFFSET_IOCTL` in the C implementation.
///
/// # Errors
///
/// Returns `OffsetOverflow` when `input_offset` points before the fixed request
/// payload boundary.
pub fn request_iov_offset(input_offset: u32) -> IoctlResult<usize> {
    (input_offset as usize)
        .checked_sub(request_payload_offset())
        .ok_or(IoctlSkeletonError::OffsetOverflow)
}

/// Returns the offset used by `IOV_OFFSET_IOCTL` in the C implementation.
///
/// # Errors
///
/// Returns `OffsetOverflow` when `output_offset` points before the fixed reply
/// payload boundary.
pub fn reply_iov_offset(output_offset: u32) -> IoctlResult<usize> {
    (output_offset as usize)
        .checked_sub(reply_payload_offset())
        .ok_or(IoctlSkeletonError::OffsetOverflow)
}

/// Rounds `len` up to the next 64-bit boundary.
#[must_use]
pub const fn pad_to_64bit(len: usize) -> usize {
    (len + 7) & !7
}

const fn aligned_fixed_len(len: usize) -> usize {
    len & !1
}

fn saturating_u32(len: usize) -> u32 {
    if len > u32::MAX as usize {
        u32::MAX
    } else {
        len as u32
    }
}

fn validate_fixed_size(buf: &[u8], expected: usize) -> IoctlResult<()> {
    if buf.len() < aligned_fixed_len(expected) {
        return Err(IoctlSkeletonError::BufferTooSmall);
    }

    let actual = read_u16_le(buf, 0)?;
    if actual as usize != expected || aligned_fixed_len(actual as usize) != buf.len() {
        return Err(IoctlSkeletonError::UnexpectedStructSize {
            actual,
            expected: expected as u16,
        });
    }

    Ok(())
}

fn read_u16_le(buf: &[u8], offset: usize) -> IoctlResult<u16> {
    let end = offset
        .checked_add(2)
        .ok_or(IoctlSkeletonError::OffsetOverflow)?;
    let bytes = buf
        .get(offset..end)
        .ok_or(IoctlSkeletonError::BufferTooSmall)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(buf: &[u8], offset: usize) -> IoctlResult<u32> {
    let end = offset
        .checked_add(4)
        .ok_or(IoctlSkeletonError::OffsetOverflow)?;
    let bytes = buf
        .get(offset..end)
        .ok_or(IoctlSkeletonError::BufferTooSmall)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_file_id(buf: &[u8], offset: usize) -> IoctlResult<Smb2FileId> {
    let end = offset
        .checked_add(SMB2_FD_SIZE)
        .ok_or(IoctlSkeletonError::OffsetOverflow)?;
    let bytes = buf
        .get(offset..end)
        .ok_or(IoctlSkeletonError::BufferTooSmall)?;
    let mut file_id = [0; SMB2_FD_SIZE];
    file_id.copy_from_slice(bytes);
    Ok(file_id)
}
