//! IOCTL command pack/unpack skeleton migrated from `lib/smb2-cmd-ioctl.c`.

use crate::include::libsmb2_private::SMB2_HEADER_SIZE;
use crate::include::smb2::smb2_ioctl::{FSCTL_GET_REPARSE_POINT, FSCTL_VALIDATE_NEGOTIATE_INFO};

use super::smb2_data_reparse_point::{
    smb2_decode_reparse_data_buffer, smb2_encode_reparse_data_buffer, Smb2ReparseDataBuffer,
};

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
    /// A typed output payload does not match the selected control code.
    PayloadKindMismatch,
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
            | Self::PayloadKindMismatch => EINVAL,
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
    /// Decoded `SMB2_FSCTL_GET_REPARSE_POINT` output.
    ReparseDataBuffer(Smb2ReparseDataBuffer),
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
            Self::ReparseDataBuffer(data) => usize::from(data.reparse_data_length) + 8,
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
    pub fn decode_input(&mut self, variable: &[u8], _passthrough: bool) -> IoctlResult<()> {
        let input_count = self.input_count as usize;
        let input_start = request_iov_offset(self.input_offset)?;
        let input_end = input_start
            .checked_add(input_count)
            .ok_or(IoctlSkeletonError::OffsetOverflow)?;
        if input_end > variable.len() {
            return Err(IoctlSkeletonError::VariableBufferTooSmall);
        }
        let input = &variable[input_start..input_end];

        self.input = match self.ctl_code {
            FSCTL_VALIDATE_NEGOTIATE_INFO => IoctlRequestInput::ValidateNegotiateInfo(
                IoctlValidateNegotiateInfo::decode_fixed(input)?,
            ),
            _ => IoctlRequestInput::Raw(input.to_vec()),
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
    pub fn decode_output(&mut self, variable: &[u8], _passthrough: bool) -> IoctlResult<()> {
        let output_count = self.output_count as usize;
        let output_start = reply_iov_offset(self.output_offset)?;
        let output_end = output_start
            .checked_add(output_count)
            .ok_or(IoctlSkeletonError::OffsetOverflow)?;
        if output_end > variable.len() {
            return Err(IoctlSkeletonError::VariableBufferTooSmall);
        }
        let output = &variable[output_start..output_end];

        self.output = match self.ctl_code {
            FSCTL_VALIDATE_NEGOTIATE_INFO => IoctlReplyOutput::ValidateNegotiateInfo(
                IoctlValidateNegotiateInfo::decode_fixed(output)?,
            ),
            FSCTL_GET_REPARSE_POINT => IoctlReplyOutput::ReparseDataBuffer(
                smb2_decode_reparse_data_buffer(output)
                    .map_err(|_| IoctlSkeletonError::VariableBufferTooSmall)?,
            ),
            _ => IoctlReplyOutput::Raw(output.to_vec()),
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

/// Lightweight PDU model returned by IOCTL async command skeleton builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoctlPduSkeleton {
    /// SMB2 command id for IOCTL.
    pub command: u16,
    /// Encoded command payload bytes managed by the skeleton.
    pub payload: Vec<u8>,
}

/// SMB2 command id for IOCTL.
pub const SMB2_IOCTL: u16 = 0x000b;

/// Encodes an IOCTL request fixed header and optional input bytes.
///
/// # Errors
///
/// Returns an error if fixed fields or variable bytes cannot be represented.
pub fn smb2_encode_ioctl_request(req: &IoctlRequest) -> IoctlResult<Vec<u8>> {
    let input = encode_request_input(&req.input)?;
    let mut buf = vec![0; aligned_fixed_len(SMB2_IOCTL_REQUEST_SIZE) + pad_to_64bit(input.len())];
    write_u16_le(&mut buf, 0, SMB2_IOCTL_REQUEST_SIZE as u16)?;
    write_u32_le(&mut buf, 4, req.ctl_code)?;
    write_bytes(&mut buf, 8, &req.file_id)?;
    write_u32_le(&mut buf, 24, request_payload_offset() as u32)?;
    write_u32_le(&mut buf, 28, usize_to_u32(input.len())?)?;
    write_u32_le(&mut buf, 32, req.max_input_response)?;
    write_u32_le(&mut buf, 36, req.output_offset)?;
    write_u32_le(&mut buf, 40, req.output_count)?;
    write_u32_le(&mut buf, 44, req.max_output_response)?;
    write_u32_le(&mut buf, 48, req.flags)?;
    write_bytes(&mut buf, aligned_fixed_len(SMB2_IOCTL_REQUEST_SIZE), &input)?;
    Ok(buf)
}

/// Builds an IOCTL request PDU skeleton corresponding to `smb2_cmd_ioctl_async`.
///
/// # Errors
///
/// Returns an error if request encoding fails.
pub fn smb2_cmd_ioctl_async(req: &IoctlRequest) -> IoctlResult<IoctlPduSkeleton> {
    Ok(IoctlPduSkeleton {
        command: SMB2_IOCTL,
        payload: smb2_encode_ioctl_request(req)?,
    })
}

/// Encodes an IOCTL reply fixed header and optional output bytes.
///
/// # Errors
///
/// Returns an error if the payload is unsupported or cannot fit in wire fields.
pub fn smb2_encode_ioctl_reply(rep: &IoctlReply, _passthrough: bool) -> IoctlResult<Vec<u8>> {
    let output = encode_reply_output(rep)?;
    let fixed_len = aligned_fixed_len(SMB2_IOCTL_REPLY_SIZE);
    let input_padding = pad_to_64bit(rep.input_count as usize);
    let output_offset = fixed_len
        .checked_add(input_padding)
        .ok_or(IoctlSkeletonError::OffsetOverflow)?;
    let total_len = output_offset
        .checked_add(pad_to_64bit(output.len()))
        .ok_or(IoctlSkeletonError::OffsetOverflow)?;
    let mut buf = vec![0; total_len];
    write_u16_le(&mut buf, 0, SMB2_IOCTL_REPLY_SIZE as u16)?;
    write_u32_le(&mut buf, 4, rep.ctl_code)?;
    write_bytes(&mut buf, 8, &rep.file_id)?;
    write_u32_le(&mut buf, 24, reply_payload_offset() as u32)?;
    write_u32_le(&mut buf, 28, rep.input_count)?;
    write_u32_le(
        &mut buf,
        32,
        usize_to_u32(SMB2_HEADER_SIZE + output_offset)?,
    )?;
    write_u32_le(&mut buf, 36, usize_to_u32(output.len())?)?;
    write_u32_le(&mut buf, 40, rep.flags)?;
    write_bytes(&mut buf, output_offset, &output)?;
    Ok(buf)
}

/// Builds an IOCTL reply PDU skeleton corresponding to `smb2_cmd_ioctl_reply_async`.
///
/// # Errors
///
/// Returns an error if reply encoding fails.
pub fn smb2_cmd_ioctl_reply_async(
    rep: &IoctlReply,
    passthrough: bool,
) -> IoctlResult<IoctlPduSkeleton> {
    Ok(IoctlPduSkeleton {
        command: SMB2_IOCTL,
        payload: smb2_encode_ioctl_reply(rep, passthrough)?,
    })
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

fn usize_to_u32(len: usize) -> IoctlResult<u32> {
    u32::try_from(len).map_err(|_| IoctlSkeletonError::OffsetOverflow)
}

fn encode_request_input(input: &IoctlRequestInput) -> IoctlResult<Vec<u8>> {
    match input {
        IoctlRequestInput::None => Ok(Vec::new()),
        IoctlRequestInput::ValidateNegotiateInfo(info) => Ok(info.encode_fixed().to_vec()),
        IoctlRequestInput::Raw(bytes) => Ok(bytes.clone()),
    }
}

fn encode_reply_output(rep: &IoctlReply) -> IoctlResult<Vec<u8>> {
    match (&rep.output, rep.ctl_code) {
        (IoctlReplyOutput::None, _) => Ok(Vec::new()),
        (IoctlReplyOutput::ValidateNegotiateInfo(info), FSCTL_VALIDATE_NEGOTIATE_INFO) => {
            Ok(info.encode_fixed().to_vec())
        }
        (IoctlReplyOutput::ReparseDataBuffer(data), FSCTL_GET_REPARSE_POINT) => {
            smb2_encode_reparse_data_buffer(data)
                .map_err(|_| IoctlSkeletonError::PayloadKindMismatch)
        }
        (IoctlReplyOutput::Raw(bytes), ctl_code)
            if !matches!(
                ctl_code,
                FSCTL_VALIDATE_NEGOTIATE_INFO | FSCTL_GET_REPARSE_POINT
            ) =>
        {
            Ok(bytes.clone())
        }
        _ => Err(IoctlSkeletonError::PayloadKindMismatch),
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

fn write_u16_le(buf: &mut [u8], offset: usize, value: u16) -> IoctlResult<()> {
    write_bytes(buf, offset, &value.to_le_bytes())
}

fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) -> IoctlResult<()> {
    write_bytes(buf, offset, &value.to_le_bytes())
}

fn write_bytes(buf: &mut [u8], offset: usize, value: &[u8]) -> IoctlResult<()> {
    let end = offset
        .checked_add(value.len())
        .ok_or(IoctlSkeletonError::OffsetOverflow)?;
    let Some(dst) = buf.get_mut(offset..end) else {
        return Err(IoctlSkeletonError::BufferTooSmall);
    };
    dst.copy_from_slice(value);
    Ok(())
}
