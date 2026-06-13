//! CHANGE_NOTIFY command pack/unpack skeleton migrated from `lib/smb2-cmd-notify-change.c`.

use crate::include::libsmb2_private::SMB2_HEADER_SIZE;

/// Fixed CHANGE_NOTIFY request structure size from the SMB2 wire format.
pub const SMB2_CHANGE_NOTIFY_REQUEST_SIZE: usize = 32;
/// Fixed CHANGE_NOTIFY reply structure size from the SMB2 wire format.
pub const SMB2_CHANGE_NOTIFY_REPLY_SIZE: usize = 9;
/// SMB2 file id size in bytes.
pub const SMB2_FD_SIZE: usize = 16;
/// SMB2 CHANGE_NOTIFY command id.
pub const SMB2_CHANGE_NOTIFY_COMMAND: u16 = 0x000f;

/// Recursive watch flag used by CHANGE_NOTIFY requests.
pub const SMB2_WATCH_TREE: u16 = 0x0001;
/// Fixed FILE_NOTIFY_INFORMATION prefix size.
pub const SMB2_FILE_NOTIFY_INFORMATION_SIZE: usize = 12;

/// Notify on file name changes.
pub const SMB2_NOTIFY_CHANGE_FILE_NAME: u32 = 0x0000_0001;
/// Notify on directory name changes.
pub const SMB2_NOTIFY_CHANGE_DIR_NAME: u32 = 0x0000_0002;
/// Notify on file attribute changes.
pub const SMB2_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x0000_0004;
/// Notify on file size changes.
pub const SMB2_NOTIFY_CHANGE_SIZE: u32 = 0x0000_0008;
/// Notify on last write timestamp changes.
pub const SMB2_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x0000_0010;
/// Notify on last access timestamp changes.
pub const SMB2_NOTIFY_CHANGE_LAST_ACCESS: u32 = 0x0000_0020;
/// Notify on creation timestamp changes.
pub const SMB2_NOTIFY_CHANGE_CREATION: u32 = 0x0000_0040;
/// Notify on extended attribute changes.
pub const SMB2_NOTIFY_CHANGE_EA: u32 = 0x0000_0080;
/// Notify on security descriptor changes.
pub const SMB2_NOTIFY_CHANGE_SECURITY: u32 = 0x0000_0100;
/// Notify on stream name changes.
pub const SMB2_NOTIFY_CHANGE_STREAM_NAME: u32 = 0x0000_0200;
/// Notify on stream size changes.
pub const SMB2_NOTIFY_CHANGE_STREAM_SIZE: u32 = 0x0000_0400;
/// Notify on stream write timestamp changes.
pub const SMB2_NOTIFY_CHANGE_STREAM_WRITE: u32 = 0x0000_0800;

/// Errors returned by the CHANGE_NOTIFY migration skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeNotifyError {
    /// A fixed structure was shorter than the SMB2 structure size.
    BufferTooShort,
    /// A variable buffer extends beyond the containing PDU.
    BufferOutOfBounds,
    /// A variable buffer overlaps its fixed command header.
    BufferOverlap,
    /// The fixed structure size field does not match the expected value.
    InvalidStructureSize,
    /// A notify record has a malformed name or next-entry offset.
    MalformedNotifyRecord,
    /// A length field does not fit in the destination integer type.
    LengthOverflow,
}

impl core::fmt::Display for ChangeNotifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::BufferTooShort => "buffer is shorter than the fixed CHANGE_NOTIFY structure",
            Self::BufferOutOfBounds => "variable CHANGE_NOTIFY buffer extends beyond the PDU",
            Self::BufferOverlap => "variable CHANGE_NOTIFY buffer overlaps the fixed header",
            Self::InvalidStructureSize => "unexpected CHANGE_NOTIFY structure size",
            Self::MalformedNotifyRecord => "CHANGE_NOTIFY record is malformed",
            Self::LengthOverflow => "CHANGE_NOTIFY length does not fit in the wire field",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ChangeNotifyError {}

/// Result type for CHANGE_NOTIFY skeleton helpers.
pub type ChangeNotifyResult<T> = Result<T, ChangeNotifyError>;

/// Rust-owned counterpart of `struct smb2_change_notify_request`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ChangeNotifyRequest {
    /// Request flags, including [`SMB2_WATCH_TREE`].
    pub flags: u16,
    /// Requested reply output buffer length.
    pub output_buffer_length: u32,
    /// SMB2 file id of the watched directory handle.
    pub file_id: [u8; SMB2_FD_SIZE],
    /// Completion filter bitset selecting which changes trigger notifications.
    pub completion_filter: u32,
}

impl ChangeNotifyRequest {
    /// Creates a CHANGE_NOTIFY request skeleton for a directory handle.
    #[must_use]
    pub const fn new(
        file_id: [u8; SMB2_FD_SIZE],
        flags: u16,
        output_buffer_length: u32,
        completion_filter: u32,
    ) -> Self {
        Self {
            flags,
            output_buffer_length,
            file_id,
            completion_filter,
        }
    }

    /// Returns the fixed request size rounded the same way as the C encoder.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        SMB2_CHANGE_NOTIFY_REQUEST_SIZE & 0xfffe
    }
}

/// Rust-owned counterpart of `struct smb2_change_notify_reply`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ChangeNotifyReply {
    /// Wire offset of the output buffer.
    pub output_buffer_offset: u16,
    /// Wire byte length of the output buffer.
    pub output_buffer_length: u32,
    /// Raw notify-change output bytes.
    pub output: Vec<u8>,
}

/// Decoded FILE_NOTIFY_INFORMATION record from a CHANGE_NOTIFY reply buffer.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileNotifyInformation {
    /// Offset to the next record in the output buffer.
    pub next_entry_offset: u32,
    /// File action code reported by the server.
    pub action: u32,
    /// UTF-16LE file name byte length as carried on the wire.
    pub file_name_length: u32,
    /// UTF-8 file name decoded from the record.
    pub file_name: String,
}

impl ChangeNotifyReply {
    /// Creates an empty CHANGE_NOTIFY reply skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the fixed reply size rounded the same way as the C encoder.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        SMB2_CHANGE_NOTIFY_REPLY_SIZE & 0xfffe
    }

    /// Attaches passthrough output bytes and updates `output_buffer_length`.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeNotifyError::LengthOverflow`] if the buffer length cannot fit in `u32`.
    pub fn with_output(mut self, output: Vec<u8>) -> ChangeNotifyResult<Self> {
        self.output_buffer_length = len_to_u32(output.len())?;
        self.output = output;
        Ok(self)
    }

    /// Decodes the raw output buffer as FILE_NOTIFY_INFORMATION records.
    ///
    /// # Errors
    ///
    /// Returns an error if any record is malformed or points outside the output buffer.
    pub fn decode_records(&self) -> ChangeNotifyResult<Vec<FileNotifyInformation>> {
        smb2_decode_file_notify_information_records(&self.output)
    }
}

/// Lightweight PDU model returned by async command skeleton builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeNotifyPduSkeleton {
    /// SMB2 command id for CHANGE_NOTIFY.
    pub command: u16,
    /// Encoded command payload bytes managed by the skeleton.
    pub payload: Vec<u8>,
}

/// Encodes the fixed CHANGE_NOTIFY request fields.
///
/// # Errors
///
/// Returns an error if the fixed output buffer cannot be written.
pub fn smb2_encode_change_notify_request(req: &ChangeNotifyRequest) -> ChangeNotifyResult<Vec<u8>> {
    let mut buf = vec![0; ChangeNotifyRequest::fixed_wire_len()];
    write_u16(&mut buf, 0, SMB2_CHANGE_NOTIFY_REQUEST_SIZE as u16)?;
    write_u16(&mut buf, 2, req.flags)?;
    write_u32(&mut buf, 4, req.output_buffer_length)?;
    write_bytes(&mut buf, 8, &req.file_id)?;
    write_u32(&mut buf, 24, req.completion_filter)?;
    Ok(buf)
}

/// Builds a CHANGE_NOTIFY request PDU skeleton corresponding to `smb2_cmd_change_notify_async`.
///
/// # Errors
///
/// Returns an error if request encoding fails.
pub fn smb2_cmd_change_notify_async(
    req: &ChangeNotifyRequest,
) -> ChangeNotifyResult<ChangeNotifyPduSkeleton> {
    Ok(ChangeNotifyPduSkeleton {
        command: SMB2_CHANGE_NOTIFY_COMMAND,
        payload: smb2_encode_change_notify_request(req)?,
    })
}

/// Encodes a CHANGE_NOTIFY reply skeleton header and optional passthrough output bytes.
///
/// This mirrors only the passthrough branch in the C encoder; parsing packed file notify records is
/// intentionally left to a later protocol-complete implementation.
///
/// # Errors
///
/// Returns an error if output buffer lengths cannot fit in SMB2 fields.
pub fn smb2_encode_change_notify_reply(rep: &ChangeNotifyReply) -> ChangeNotifyResult<Vec<u8>> {
    let output_len =
        usize::try_from(rep.output_buffer_length).map_err(|_| ChangeNotifyError::LengthOverflow)?;
    let fixed_len = ChangeNotifyReply::fixed_wire_len();
    let mut buf = vec![0; fixed_len + pad_to_32bit(output_len)];
    write_u16(&mut buf, 0, SMB2_CHANGE_NOTIFY_REPLY_SIZE as u16)?;
    write_u16(&mut buf, 2, (SMB2_HEADER_SIZE + fixed_len) as u16)?;
    write_u32(&mut buf, 4, rep.output_buffer_length)?;
    if output_len > 0 {
        write_bytes(&mut buf, fixed_len, slice_at(&rep.output, 0, output_len)?)?;
    }
    Ok(buf)
}

/// Builds a CHANGE_NOTIFY reply PDU skeleton corresponding to `smb2_cmd_change_notify_reply_async`.
///
/// # Errors
///
/// Returns an error if reply encoding fails.
pub fn smb2_cmd_change_notify_reply_async(
    rep: &ChangeNotifyReply,
) -> ChangeNotifyResult<ChangeNotifyPduSkeleton> {
    Ok(ChangeNotifyPduSkeleton {
        command: SMB2_CHANGE_NOTIFY_COMMAND,
        payload: smb2_encode_change_notify_reply(rep)?,
    })
}

/// Decodes chained FILE_NOTIFY_INFORMATION records from a CHANGE_NOTIFY output buffer.
///
/// # Errors
///
/// Returns an error if a fixed record, UTF-16LE name, or next-entry offset is malformed.
pub fn smb2_decode_file_notify_information_records(
    data: &[u8],
) -> ChangeNotifyResult<Vec<FileNotifyInformation>> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let remaining = slice_at(data, offset, data.len() - offset)?;
        if remaining.len() < SMB2_FILE_NOTIFY_INFORMATION_SIZE {
            return Err(ChangeNotifyError::BufferTooShort);
        }

        let next_entry_offset = read_u32(remaining, 0)?;
        let file_name_length = read_u32(remaining, 8)?;
        let name_len =
            usize::try_from(file_name_length).map_err(|_| ChangeNotifyError::LengthOverflow)?;
        if name_len % 2 != 0 {
            return Err(ChangeNotifyError::MalformedNotifyRecord);
        }
        let record_len = SMB2_FILE_NOTIFY_INFORMATION_SIZE
            .checked_add(name_len)
            .ok_or(ChangeNotifyError::LengthOverflow)?;
        if record_len > remaining.len() {
            return Err(ChangeNotifyError::BufferTooShort);
        }

        records.push(FileNotifyInformation {
            next_entry_offset,
            action: read_u32(remaining, 4)?,
            file_name_length,
            file_name: decode_utf16le_lossy(slice_at(
                remaining,
                SMB2_FILE_NOTIFY_INFORMATION_SIZE,
                name_len,
            )?),
        });

        if next_entry_offset == 0 {
            break;
        }
        let next =
            usize::try_from(next_entry_offset).map_err(|_| ChangeNotifyError::LengthOverflow)?;
        if next < record_len || next > remaining.len() {
            return Err(ChangeNotifyError::MalformedNotifyRecord);
        }
        offset = offset
            .checked_add(next)
            .ok_or(ChangeNotifyError::LengthOverflow)?;
    }

    Ok(records)
}

/// Processes the fixed CHANGE_NOTIFY reply fields and returns the expected variable byte count.
///
/// # Errors
///
/// Returns an error if the fixed reply header is invalid or references bytes outside the PDU.
pub fn smb2_process_change_notify_fixed(
    fixed: &[u8],
    pdu_size: usize,
) -> ChangeNotifyResult<(ChangeNotifyReply, usize)> {
    let struct_size = read_u16(fixed, 0)?;
    if struct_size != SMB2_CHANGE_NOTIFY_REPLY_SIZE as u16
        || usize::from(struct_size & 0xfffe) != fixed.len()
    {
        return Err(ChangeNotifyError::InvalidStructureSize);
    }

    let output_buffer_offset = read_u16(fixed, 2)?;
    let output_buffer_length = read_u32(fixed, 4)?;
    let output_len =
        usize::try_from(output_buffer_length).map_err(|_| ChangeNotifyError::LengthOverflow)?;
    let output_end = usize::from(output_buffer_offset)
        .checked_add(output_len)
        .ok_or(ChangeNotifyError::LengthOverflow)?;
    if output_buffer_length > 0 && output_end > pdu_size {
        return Err(ChangeNotifyError::BufferOutOfBounds);
    }
    if output_buffer_length > 0
        && usize::from(output_buffer_offset)
            < SMB2_HEADER_SIZE + ChangeNotifyReply::fixed_wire_len()
    {
        return Err(ChangeNotifyError::BufferOverlap);
    }

    let variable_offset = usize::from(output_buffer_offset)
        .saturating_sub(SMB2_HEADER_SIZE)
        .saturating_sub(ChangeNotifyReply::fixed_wire_len());
    Ok((
        ChangeNotifyReply {
            output_buffer_offset,
            output_buffer_length,
            output: Vec::new(),
        },
        variable_offset + output_len,
    ))
}

/// Attaches the variable CHANGE_NOTIFY reply output buffer.
///
/// # Errors
///
/// Returns an error if the reply output slice does not fit in `variable`.
pub fn smb2_process_change_notify_variable(
    rep: &mut ChangeNotifyReply,
    variable: &[u8],
) -> ChangeNotifyResult<()> {
    let offset = usize::from(rep.output_buffer_offset)
        .saturating_sub(SMB2_HEADER_SIZE)
        .saturating_sub(ChangeNotifyReply::fixed_wire_len());
    let len =
        usize::try_from(rep.output_buffer_length).map_err(|_| ChangeNotifyError::LengthOverflow)?;
    rep.output = slice_at(variable, offset, len)?.to_vec();
    Ok(())
}

/// Processes the fixed CHANGE_NOTIFY request fields.
///
/// # Errors
///
/// Returns an error if the fixed request header is invalid or too short.
pub fn smb2_process_change_notify_request_fixed(
    fixed: &[u8],
) -> ChangeNotifyResult<ChangeNotifyRequest> {
    let struct_size = read_u16(fixed, 0)?;
    if struct_size != SMB2_CHANGE_NOTIFY_REQUEST_SIZE as u16
        || usize::from(struct_size & 0xfffe) != fixed.len()
    {
        return Err(ChangeNotifyError::InvalidStructureSize);
    }

    let mut file_id = [0; SMB2_FD_SIZE];
    file_id.copy_from_slice(slice_at(fixed, 8, SMB2_FD_SIZE)?);
    Ok(ChangeNotifyRequest {
        flags: read_u16(fixed, 2)?,
        output_buffer_length: read_u32(fixed, 4)?,
        file_id,
        completion_filter: read_u32(fixed, 24)?,
    })
}

fn read_u16(data: &[u8], offset: usize) -> ChangeNotifyResult<u16> {
    let bytes = slice_at(data, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> ChangeNotifyResult<u32> {
    let bytes = slice_at(data, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) -> ChangeNotifyResult<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) -> ChangeNotifyResult<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_bytes(data: &mut [u8], offset: usize, value: &[u8]) -> ChangeNotifyResult<()> {
    let end = offset
        .checked_add(value.len())
        .ok_or(ChangeNotifyError::LengthOverflow)?;
    let Some(dst) = data.get_mut(offset..end) else {
        return Err(ChangeNotifyError::BufferTooShort);
    };
    dst.copy_from_slice(value);
    Ok(())
}

fn slice_at(data: &[u8], offset: usize, len: usize) -> ChangeNotifyResult<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(ChangeNotifyError::LengthOverflow)?;
    data.get(offset..end)
        .ok_or(ChangeNotifyError::BufferTooShort)
}

fn len_to_u32(len: usize) -> ChangeNotifyResult<u32> {
    u32::try_from(len).map_err(|_| ChangeNotifyError::LengthOverflow)
}

fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&units)
}

const fn pad_to_32bit(value: usize) -> usize {
    (value + 3) & !3
}
