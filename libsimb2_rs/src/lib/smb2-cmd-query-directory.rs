//! QUERY_DIRECTORY command pack/unpack skeleton migrated from `lib/smb2-cmd-query-directory.c`.

use crate::include::libsmb2_private::SMB2_HEADER_SIZE;

use super::timestamps::{smb2_timeval_to_win, smb2_win_to_timeval};

/// Fixed QUERY_DIRECTORY request structure size from the SMB2 wire format.
pub const SMB2_QUERY_DIRECTORY_REQUEST_SIZE: usize = 33;
/// Fixed QUERY_DIRECTORY reply structure size from the SMB2 wire format.
pub const SMB2_QUERY_DIRECTORY_REPLY_SIZE: usize = 9;
/// Fixed FILE_ID_FULL_DIRECTORY_INFORMATION prefix size.
pub const SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE: usize = 80;
/// Fixed FILE_ID_BOTH_DIRECTORY_INFORMATION prefix size.
pub const SMB2_FILEID_BOTH_DIRECTORY_INFORMATION_SIZE: usize = 104;
/// SMB2 file id size in bytes.
pub const SMB2_FD_SIZE: usize = 16;

/// FILE_ID_FULL_DIRECTORY_INFORMATION class id.
pub const SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION: u8 = 0x26;
/// FILE_ID_BOTH_DIRECTORY_INFORMATION class id.
pub const SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 0x25;

/// RESTART_SCANS query-directory flag.
pub const SMB2_RESTART_SCANS: u8 = 0x01;
/// RETURN_SINGLE_ENTRY query-directory flag.
pub const SMB2_RETURN_SINGLE_ENTRY: u8 = 0x02;
/// INDEX_SPECIFIED query-directory flag.
pub const SMB2_INDEX_SPECIFIED: u8 = 0x04;
/// REOPEN query-directory flag.
pub const SMB2_REOPEN: u8 = 0x10;

/// Errors returned by the QUERY_DIRECTORY migration skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryDirectoryError {
    /// A fixed structure was shorter than the SMB2 structure size.
    BufferTooShort,
    /// A declared name or output buffer extends beyond the containing PDU.
    BufferOutOfBounds,
    /// A variable buffer overlaps its fixed command header.
    BufferOverlap,
    /// The fixed structure size field does not match the expected value.
    InvalidStructureSize,
    /// A directory entry name length does not fit in the provided buffer.
    MalformedName,
    /// A chained directory entry offset is invalid.
    MalformedEntryChain,
    /// A length field does not fit in the destination integer type.
    LengthOverflow,
}

impl core::fmt::Display for QueryDirectoryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::BufferTooShort => "buffer is shorter than the fixed QUERY_DIRECTORY structure",
            Self::BufferOutOfBounds => "variable QUERY_DIRECTORY buffer extends beyond the PDU",
            Self::BufferOverlap => "variable QUERY_DIRECTORY buffer overlaps the fixed header",
            Self::InvalidStructureSize => "unexpected QUERY_DIRECTORY structure size",
            Self::MalformedName => "directory entry name length is malformed",
            Self::MalformedEntryChain => "directory entry chain offset is malformed",
            Self::LengthOverflow => "QUERY_DIRECTORY length does not fit in the wire field",
        };
        f.write_str(message)
    }
}

impl std::error::Error for QueryDirectoryError {}

/// Result type for QUERY_DIRECTORY skeleton helpers.
pub type QueryDirectoryResult<T> = Result<T, QueryDirectoryError>;

/// Rust-owned counterpart of `struct smb2_timeval` used by directory entries.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Smb2Timeval {
    /// Seconds since the Unix epoch.
    pub tv_sec: i64,
    /// Microseconds within `tv_sec`.
    pub tv_usec: i64,
}

/// Rust-owned counterpart of `struct smb2_fileidfulldirectoryinformation`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileIdFullDirectoryInformation {
    /// Offset to the next directory entry in the output buffer.
    pub next_entry_offset: u32,
    /// Server-provided file index.
    pub file_index: u32,
    /// Creation timestamp placeholder.
    pub creation_time: Smb2Timeval,
    /// Last access timestamp placeholder.
    pub last_access_time: Smb2Timeval,
    /// Last write timestamp placeholder.
    pub last_write_time: Smb2Timeval,
    /// Metadata change timestamp placeholder.
    pub change_time: Smb2Timeval,
    /// File size in bytes.
    pub end_of_file: u64,
    /// Allocated size in bytes.
    pub allocation_size: u64,
    /// SMB2 file attributes bitset.
    pub file_attributes: u32,
    /// UTF-16LE name byte length as carried on the wire.
    pub file_name_length: u32,
    /// Extended attribute size.
    pub ea_size: u32,
    /// Persistent file id.
    pub file_id: u64,
    /// UTF-8 directory entry name.
    pub name: String,
}

/// Rust-owned counterpart of `struct smb2_fileidbothdirectoryinformation`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileIdBothDirectoryInformation {
    /// Offset to the next directory entry in the output buffer.
    pub next_entry_offset: u32,
    /// Server-provided file index.
    pub file_index: u32,
    /// Creation timestamp placeholder.
    pub creation_time: Smb2Timeval,
    /// Last access timestamp placeholder.
    pub last_access_time: Smb2Timeval,
    /// Last write timestamp placeholder.
    pub last_write_time: Smb2Timeval,
    /// Metadata change timestamp placeholder.
    pub change_time: Smb2Timeval,
    /// File size in bytes.
    pub end_of_file: u64,
    /// Allocated size in bytes.
    pub allocation_size: u64,
    /// SMB2 file attributes bitset.
    pub file_attributes: u32,
    /// UTF-16LE name byte length as carried on the wire.
    pub file_name_length: u32,
    /// Extended attribute size.
    pub ea_size: u32,
    /// Short 8.3 name length in bytes.
    pub short_name_length: u8,
    /// Raw UTF-16LE short name area.
    pub short_name: [u8; 24],
    /// Persistent file id.
    pub file_id: u64,
    /// UTF-8 directory entry name.
    pub name: String,
}

/// Rust-owned counterpart of `struct smb2_query_directory_request`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QueryDirectoryRequest {
    /// Requested file information class.
    pub file_information_class: u8,
    /// Query-directory flags.
    pub flags: u8,
    /// Optional file index for indexed queries.
    pub file_index: u32,
    /// SMB2 file id of the directory handle.
    pub file_id: [u8; SMB2_FD_SIZE],
    /// Requested output buffer length.
    pub output_buffer_length: u32,
    /// Wire offset of the optional filename.
    pub file_name_offset: u16,
    /// Wire byte length of the optional UTF-16LE filename.
    pub file_name_length: u16,
    /// Optional UTF-8 filename pattern.
    pub name: Option<String>,
}

impl QueryDirectoryRequest {
    /// Creates a request skeleton with the required information class, file id, and output size.
    pub fn new(
        file_information_class: u8,
        file_id: [u8; SMB2_FD_SIZE],
        output_buffer_length: u32,
    ) -> Self {
        Self {
            file_information_class,
            file_id,
            output_buffer_length,
            ..Self::default()
        }
    }

    /// Returns the fixed request size rounded the same way as the C encoder.
    pub const fn fixed_wire_len() -> usize {
        SMB2_QUERY_DIRECTORY_REQUEST_SIZE & 0xfffe
    }

    /// Returns the UTF-16LE filename byte length that would be appended by the C encoder.
    pub fn name_wire_len(&self) -> QueryDirectoryResult<u16> {
        let Some(name) = self.name.as_deref() else {
            return Ok(0);
        };
        if name.is_empty() {
            return Ok(0);
        }
        utf16le_len(name)
    }
}

/// Rust-owned counterpart of `struct smb2_query_directory_reply`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QueryDirectoryReply {
    /// Wire offset of the output buffer.
    pub output_buffer_offset: u16,
    /// Wire byte length of the output buffer.
    pub output_buffer_length: u32,
    /// Rust-owned output buffer bytes.
    pub output_buffer: Vec<u8>,
}

impl QueryDirectoryReply {
    /// Creates an empty reply skeleton.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the fixed reply size rounded the same way as the C encoder.
    pub const fn fixed_wire_len() -> usize {
        SMB2_QUERY_DIRECTORY_REPLY_SIZE & 0xfffe
    }

    /// Attaches output bytes and updates `output_buffer_length`.
    ///
    /// # Errors
    ///
    /// Returns [`QueryDirectoryError::LengthOverflow`] if the buffer length cannot fit in `u32`.
    pub fn with_output_buffer(mut self, output_buffer: Vec<u8>) -> QueryDirectoryResult<Self> {
        self.output_buffer_length = len_to_u32(output_buffer.len())?;
        self.output_buffer = output_buffer;
        Ok(self)
    }
}

/// Lightweight PDU model returned by async command skeleton builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDirectoryPduSkeleton {
    /// SMB2 command id for QUERY_DIRECTORY.
    pub command: u16,
    /// Encoded command payload bytes managed by the skeleton.
    pub payload: Vec<u8>,
    /// Credit charge calculated for large output buffers.
    pub credit_charge: u16,
}

/// Decodes a FILE_ID_FULL_DIRECTORY_INFORMATION entry from a wire buffer.
///
/// # Errors
///
/// Returns an error if fixed fields or the trailing name do not fit in `data`.
pub fn smb2_decode_fileidfulldirectoryinformation(
    data: &[u8],
) -> QueryDirectoryResult<FileIdFullDirectoryInformation> {
    let name_len = read_u32(data, 60)? as usize;
    if name_len % 2 != 0 {
        return Err(QueryDirectoryError::MalformedName);
    }
    if name_len
        > data
            .len()
            .saturating_sub(SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE)
    {
        return Err(QueryDirectoryError::MalformedName);
    }

    Ok(FileIdFullDirectoryInformation {
        next_entry_offset: read_u32(data, 0)?,
        file_index: read_u32(data, 4)?,
        creation_time: decode_filetime(read_u64(data, 8)?),
        last_access_time: decode_filetime(read_u64(data, 16)?),
        last_write_time: decode_filetime(read_u64(data, 24)?),
        change_time: decode_filetime(read_u64(data, 32)?),
        end_of_file: read_u64(data, 40)?,
        allocation_size: read_u64(data, 48)?,
        file_attributes: read_u32(data, 56)?,
        file_name_length: read_u32(data, 60)?,
        ea_size: read_u32(data, 64)?,
        file_id: read_u64(data, 72)?,
        name: decode_utf16le_lossy(slice_at(
            data,
            SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE,
            name_len,
        )?),
    })
}

/// Decodes a FILE_ID_BOTH_DIRECTORY_INFORMATION entry from a wire buffer.
///
/// # Errors
///
/// Returns an error if fixed fields or the trailing name do not fit in `data`.
pub fn smb2_decode_fileidbothdirectoryinformation(
    data: &[u8],
) -> QueryDirectoryResult<FileIdBothDirectoryInformation> {
    let name_len = read_u32(data, 60)? as usize;
    if name_len % 2 != 0 {
        return Err(QueryDirectoryError::MalformedName);
    }
    if name_len
        > data
            .len()
            .saturating_sub(SMB2_FILEID_BOTH_DIRECTORY_INFORMATION_SIZE)
    {
        return Err(QueryDirectoryError::MalformedName);
    }

    let mut short_name = [0; 24];
    short_name.copy_from_slice(slice_at(data, 70, 24)?);
    Ok(FileIdBothDirectoryInformation {
        next_entry_offset: read_u32(data, 0)?,
        file_index: read_u32(data, 4)?,
        creation_time: decode_filetime(read_u64(data, 8)?),
        last_access_time: decode_filetime(read_u64(data, 16)?),
        last_write_time: decode_filetime(read_u64(data, 24)?),
        change_time: decode_filetime(read_u64(data, 32)?),
        end_of_file: read_u64(data, 40)?,
        allocation_size: read_u64(data, 48)?,
        file_attributes: read_u32(data, 56)?,
        file_name_length: read_u32(data, 60)?,
        ea_size: read_u32(data, 64)?,
        short_name_length: read_u8(data, 68)?,
        short_name,
        file_id: read_u64(data, 96)?,
        name: decode_utf16le_lossy(slice_at(
            data,
            SMB2_FILEID_BOTH_DIRECTORY_INFORMATION_SIZE,
            name_len,
        )?),
    })
}

/// Decodes a chained FILE_ID_FULL_DIRECTORY_INFORMATION buffer.
///
/// # Errors
///
/// Returns an error if any entry is malformed, out of bounds, or has an invalid next offset.
pub fn smb2_decode_fileidfulldirectoryinformation_entries(
    data: &[u8],
) -> QueryDirectoryResult<Vec<FileIdFullDirectoryInformation>> {
    decode_directory_entry_chain(
        data,
        SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE,
        smb2_decode_fileidfulldirectoryinformation,
    )
}

/// Decodes a chained FILE_ID_BOTH_DIRECTORY_INFORMATION buffer.
///
/// # Errors
///
/// Returns an error if any entry is malformed, out of bounds, or has an invalid next offset.
pub fn smb2_decode_fileidbothdirectoryinformation_entries(
    data: &[u8],
) -> QueryDirectoryResult<Vec<FileIdBothDirectoryInformation>> {
    decode_directory_entry_chain(
        data,
        SMB2_FILEID_BOTH_DIRECTORY_INFORMATION_SIZE,
        smb2_decode_fileidbothdirectoryinformation,
    )
}

/// Encodes one FILE_ID_FULL_DIRECTORY_INFORMATION entry.
///
/// # Errors
///
/// Returns an error if the encoded name or output buffer cannot fit.
pub fn smb2_encode_fileidfulldirectoryinformation(
    entry: &FileIdFullDirectoryInformation,
    next_entry_offset: u32,
    buf: &mut [u8],
) -> QueryDirectoryResult<usize> {
    let name = encode_utf16le(&entry.name);
    let len = SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE
        .checked_add(name.len())
        .ok_or(QueryDirectoryError::LengthOverflow)?;
    require_len(buf, len)?;
    write_u32(buf, 0, next_entry_offset)?;
    write_u32(buf, 4, entry.file_index)?;
    write_u64(buf, 8, encode_filetime(entry.creation_time))?;
    write_u64(buf, 16, encode_filetime(entry.last_access_time))?;
    write_u64(buf, 24, encode_filetime(entry.last_write_time))?;
    write_u64(buf, 32, encode_filetime(entry.change_time))?;
    write_u64(buf, 40, entry.end_of_file)?;
    write_u64(buf, 48, entry.allocation_size)?;
    write_u32(buf, 56, entry.file_attributes)?;
    write_u32(buf, 60, len_to_u32(name.len())?)?;
    write_u32(buf, 64, entry.ea_size)?;
    write_u32(buf, 68, 0)?;
    write_u64(buf, 72, entry.file_id)?;
    write_bytes(buf, SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE, &name)?;
    Ok(len)
}

/// Encodes chained FILE_ID_FULL_DIRECTORY_INFORMATION entries into `buf`.
///
/// # Errors
///
/// Returns an error if the encoded entries cannot fit in `buf` or in wire length fields.
pub fn smb2_encode_fileidfulldirectoryinformation_entries(
    entries: &[FileIdFullDirectoryInformation],
    buf: &mut [u8],
) -> QueryDirectoryResult<usize> {
    encode_directory_entry_chain(entries, buf, smb2_encode_fileidfulldirectoryinformation)
}

/// Encodes chained FILE_ID_FULL_DIRECTORY_INFORMATION entries into an owned buffer.
///
/// # Errors
///
/// Returns an error if the encoded entries cannot fit in wire length fields.
pub fn smb2_encode_fileidfulldirectoryinformation_entries_vec(
    entries: &[FileIdFullDirectoryInformation],
) -> QueryDirectoryResult<Vec<u8>> {
    let len = directory_entry_chain_len(
        entries,
        |entry| encode_utf16le(&entry.name).len(),
        SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE,
    )?;
    let mut buf = vec![0; len];
    let written = smb2_encode_fileidfulldirectoryinformation_entries(entries, &mut buf)?;
    buf.truncate(written);
    Ok(buf)
}

/// Encodes one FILE_ID_BOTH_DIRECTORY_INFORMATION entry.
///
/// # Errors
///
/// Returns an error if the encoded name or output buffer cannot fit.
pub fn smb2_encode_fileidbothdirectoryinformation(
    entry: &FileIdBothDirectoryInformation,
    next_entry_offset: u32,
    buf: &mut [u8],
) -> QueryDirectoryResult<usize> {
    let name = encode_utf16le(&entry.name);
    let len = SMB2_FILEID_BOTH_DIRECTORY_INFORMATION_SIZE
        .checked_add(name.len())
        .ok_or(QueryDirectoryError::LengthOverflow)?;
    require_len(buf, len)?;
    write_u32(buf, 0, next_entry_offset)?;
    write_u32(buf, 4, entry.file_index)?;
    write_u64(buf, 8, encode_filetime(entry.creation_time))?;
    write_u64(buf, 16, encode_filetime(entry.last_access_time))?;
    write_u64(buf, 24, encode_filetime(entry.last_write_time))?;
    write_u64(buf, 32, encode_filetime(entry.change_time))?;
    write_u64(buf, 40, entry.end_of_file)?;
    write_u64(buf, 48, entry.allocation_size)?;
    write_u32(buf, 56, entry.file_attributes)?;
    write_u32(buf, 60, len_to_u32(name.len())?)?;
    write_u32(buf, 64, entry.ea_size)?;
    write_u8(buf, 68, entry.short_name_length)?;
    write_u8(buf, 69, 0)?;
    write_bytes(buf, 70, &entry.short_name)?;
    write_u16(buf, 94, 0)?;
    write_u64(buf, 96, entry.file_id)?;
    write_bytes(buf, SMB2_FILEID_BOTH_DIRECTORY_INFORMATION_SIZE, &name)?;
    Ok(len)
}

/// Encodes chained FILE_ID_BOTH_DIRECTORY_INFORMATION entries into `buf`.
///
/// # Errors
///
/// Returns an error if the encoded entries cannot fit in `buf` or in wire length fields.
pub fn smb2_encode_fileidbothdirectoryinformation_entries(
    entries: &[FileIdBothDirectoryInformation],
    buf: &mut [u8],
) -> QueryDirectoryResult<usize> {
    encode_directory_entry_chain(entries, buf, smb2_encode_fileidbothdirectoryinformation)
}

/// Encodes chained FILE_ID_BOTH_DIRECTORY_INFORMATION entries into an owned buffer.
///
/// # Errors
///
/// Returns an error if the encoded entries cannot fit in wire length fields.
pub fn smb2_encode_fileidbothdirectoryinformation_entries_vec(
    entries: &[FileIdBothDirectoryInformation],
) -> QueryDirectoryResult<Vec<u8>> {
    let len = directory_entry_chain_len(
        entries,
        |entry| encode_utf16le(&entry.name).len(),
        SMB2_FILEID_BOTH_DIRECTORY_INFORMATION_SIZE,
    )?;
    let mut buf = vec![0; len];
    let written = smb2_encode_fileidbothdirectoryinformation_entries(entries, &mut buf)?;
    buf.truncate(written);
    Ok(buf)
}

/// Encodes the fixed QUERY_DIRECTORY request fields and optional name bytes.
///
/// # Errors
///
/// Returns an error if the optional filename is too large for the SMB2 length field.
pub fn smb2_encode_query_directory_request(
    req: &QueryDirectoryRequest,
) -> QueryDirectoryResult<Vec<u8>> {
    let name_len = usize::from(req.name_wire_len()?);
    let mut buf = vec![0; QueryDirectoryRequest::fixed_wire_len() + name_len];
    write_u16(&mut buf, 0, SMB2_QUERY_DIRECTORY_REQUEST_SIZE as u16)?;
    write_u8(&mut buf, 2, req.file_information_class)?;
    write_u8(&mut buf, 3, req.flags)?;
    write_u32(&mut buf, 4, req.file_index)?;
    write_bytes(&mut buf, 8, &req.file_id)?;
    write_u16(
        &mut buf,
        24,
        (SMB2_HEADER_SIZE + QueryDirectoryRequest::fixed_wire_len()) as u16,
    )?;
    write_u16(&mut buf, 26, req.name_wire_len()?)?;
    write_u32(&mut buf, 28, req.output_buffer_length)?;

    if name_len > 0 {
        let Some(name) = req.name.as_deref() else {
            return Ok(buf);
        };
        let encoded = encode_utf16le(name);
        write_bytes(&mut buf, QueryDirectoryRequest::fixed_wire_len(), &encoded)?;
    }

    Ok(buf)
}

/// Builds a QUERY_DIRECTORY request PDU skeleton corresponding to `smb2_cmd_query_directory_async`.
///
/// # Errors
///
/// Returns an error if request encoding fails.
pub fn smb2_cmd_query_directory_async(
    req: &QueryDirectoryRequest,
    supports_multi_credit: bool,
) -> QueryDirectoryResult<QueryDirectoryPduSkeleton> {
    let payload = smb2_encode_query_directory_request(req)?;
    let credit_charge = if supports_multi_credit {
        ((req.output_buffer_length.saturating_sub(1)) / 65_536 + 1) as u16
    } else {
        1
    };
    Ok(QueryDirectoryPduSkeleton {
        command: 0x000e,
        payload,
        credit_charge,
    })
}

/// Encodes a QUERY_DIRECTORY reply skeleton header and optional output bytes.
///
/// # Errors
///
/// Returns an error if output buffer lengths cannot fit in SMB2 fields.
pub fn smb2_encode_query_directory_reply(
    rep: &QueryDirectoryReply,
) -> QueryDirectoryResult<Vec<u8>> {
    let fixed_len = pad_to_32bit(QueryDirectoryReply::fixed_wire_len());
    let output_len = usize::try_from(rep.output_buffer_length)
        .map_err(|_| QueryDirectoryError::LengthOverflow)?;
    let mut buf = vec![0; fixed_len + pad_to_32bit(output_len)];
    write_u16(&mut buf, 0, SMB2_QUERY_DIRECTORY_REPLY_SIZE as u16)?;
    write_u16(&mut buf, 2, (SMB2_HEADER_SIZE + fixed_len) as u16)?;
    write_u32(&mut buf, 4, rep.output_buffer_length)?;
    if output_len > 0 {
        write_bytes(
            &mut buf,
            fixed_len,
            slice_at(&rep.output_buffer, 0, output_len)?,
        )?;
    }
    Ok(buf)
}

/// Builds a QUERY_DIRECTORY reply PDU skeleton corresponding to `smb2_cmd_query_directory_reply_async`.
///
/// # Errors
///
/// Returns an error if reply encoding fails.
pub fn smb2_cmd_query_directory_reply_async(
    rep: &QueryDirectoryReply,
) -> QueryDirectoryResult<QueryDirectoryPduSkeleton> {
    Ok(QueryDirectoryPduSkeleton {
        command: 0x000e,
        payload: smb2_encode_query_directory_reply(rep)?,
        credit_charge: 1,
    })
}

/// Processes the fixed QUERY_DIRECTORY reply fields and returns the expected variable byte count.
///
/// # Errors
///
/// Returns an error if the fixed reply header is invalid or references bytes outside the PDU.
pub fn smb2_process_query_directory_fixed(
    fixed: &[u8],
    pdu_size: usize,
) -> QueryDirectoryResult<(QueryDirectoryReply, usize)> {
    let struct_size = read_u16(fixed, 0)?;
    if struct_size != SMB2_QUERY_DIRECTORY_REPLY_SIZE as u16
        || usize::from(struct_size & 0xfffe) != fixed.len()
    {
        return Err(QueryDirectoryError::InvalidStructureSize);
    }
    let output_buffer_offset = read_u16(fixed, 2)?;
    let output_buffer_length = read_u32(fixed, 4)?;
    let output_end = usize::from(output_buffer_offset)
        .checked_add(
            usize::try_from(output_buffer_length)
                .map_err(|_| QueryDirectoryError::LengthOverflow)?,
        )
        .ok_or(QueryDirectoryError::LengthOverflow)?;
    if output_buffer_length > 0 && output_end > pdu_size {
        return Err(QueryDirectoryError::BufferOutOfBounds);
    }
    if output_buffer_length > 0
        && usize::from(output_buffer_offset)
            < SMB2_HEADER_SIZE + QueryDirectoryReply::fixed_wire_len()
    {
        return Err(QueryDirectoryError::BufferOverlap);
    }

    let variable_offset = usize::from(output_buffer_offset)
        .saturating_sub(SMB2_HEADER_SIZE)
        .saturating_sub(QueryDirectoryReply::fixed_wire_len());
    Ok((
        QueryDirectoryReply {
            output_buffer_offset,
            output_buffer_length,
            output_buffer: Vec::new(),
        },
        variable_offset
            + usize::try_from(output_buffer_length)
                .map_err(|_| QueryDirectoryError::LengthOverflow)?,
    ))
}

/// Attaches the variable QUERY_DIRECTORY reply output buffer.
///
/// # Errors
///
/// Returns an error if the reply output slice does not fit in the variable bytes.
pub fn smb2_process_query_directory_variable(
    rep: &mut QueryDirectoryReply,
    variable: &[u8],
) -> QueryDirectoryResult<()> {
    let offset = usize::from(rep.output_buffer_offset)
        .saturating_sub(SMB2_HEADER_SIZE)
        .saturating_sub(QueryDirectoryReply::fixed_wire_len());
    let len = usize::try_from(rep.output_buffer_length)
        .map_err(|_| QueryDirectoryError::LengthOverflow)?;
    rep.output_buffer = slice_at(variable, offset, len)?.to_vec();
    Ok(())
}

/// Processes the fixed QUERY_DIRECTORY request fields and returns the expected variable byte count.
///
/// # Errors
///
/// Returns an error if the fixed request header is invalid or references bytes outside the PDU.
pub fn smb2_process_query_directory_request_fixed(
    fixed: &[u8],
    pdu_size: usize,
) -> QueryDirectoryResult<(QueryDirectoryRequest, usize)> {
    let struct_size = read_u16(fixed, 0)?;
    if struct_size != SMB2_QUERY_DIRECTORY_REQUEST_SIZE as u16
        || usize::from(struct_size & 0xfffe) != fixed.len()
    {
        return Err(QueryDirectoryError::InvalidStructureSize);
    }

    let mut file_id = [0; SMB2_FD_SIZE];
    file_id.copy_from_slice(slice_at(fixed, 8, SMB2_FD_SIZE)?);
    let file_name_offset = read_u16(fixed, 24)?;
    let file_name_length = read_u16(fixed, 26)?;
    let name_end = usize::from(file_name_offset)
        .checked_add(usize::from(file_name_length))
        .ok_or(QueryDirectoryError::LengthOverflow)?;
    if file_name_length > 0 && name_end > pdu_size {
        return Err(QueryDirectoryError::BufferOutOfBounds);
    }
    if file_name_length > 0
        && usize::from(file_name_offset)
            < SMB2_HEADER_SIZE + QueryDirectoryRequest::fixed_wire_len()
    {
        return Err(QueryDirectoryError::BufferOverlap);
    }

    let variable_offset = usize::from(file_name_offset)
        .saturating_sub(SMB2_HEADER_SIZE)
        .saturating_sub(QueryDirectoryRequest::fixed_wire_len());
    Ok((
        QueryDirectoryRequest {
            file_information_class: read_u8(fixed, 2)?,
            flags: read_u8(fixed, 3)?,
            file_index: read_u32(fixed, 4)?,
            file_id,
            output_buffer_length: read_u32(fixed, 28)?,
            file_name_offset,
            file_name_length,
            name: None,
        },
        variable_offset + usize::from(file_name_length),
    ))
}

/// Decodes the optional variable QUERY_DIRECTORY request filename.
///
/// # Errors
///
/// Returns an error if the filename slice does not fit in `variable`.
pub fn smb2_process_query_directory_request_variable(
    req: &mut QueryDirectoryRequest,
    variable: &[u8],
) -> QueryDirectoryResult<()> {
    if req.file_name_length == 0 {
        return Ok(());
    }
    let offset = usize::from(req.file_name_offset)
        .saturating_sub(SMB2_HEADER_SIZE)
        .saturating_sub(QueryDirectoryRequest::fixed_wire_len());
    let bytes = slice_at(variable, offset, usize::from(req.file_name_length))?;
    req.name = Some(decode_utf16le_lossy(bytes));
    Ok(())
}

fn read_u8(data: &[u8], offset: usize) -> QueryDirectoryResult<u8> {
    data.get(offset)
        .copied()
        .ok_or(QueryDirectoryError::BufferTooShort)
}

fn read_u16(data: &[u8], offset: usize) -> QueryDirectoryResult<u16> {
    let bytes = slice_at(data, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> QueryDirectoryResult<u32> {
    let bytes = slice_at(data, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> QueryDirectoryResult<u64> {
    let bytes = slice_at(data, offset, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn write_u8(data: &mut [u8], offset: usize, value: u8) -> QueryDirectoryResult<()> {
    let Some(slot) = data.get_mut(offset) else {
        return Err(QueryDirectoryError::BufferTooShort);
    };
    *slot = value;
    Ok(())
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) -> QueryDirectoryResult<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) -> QueryDirectoryResult<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_u64(data: &mut [u8], offset: usize, value: u64) -> QueryDirectoryResult<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_bytes(data: &mut [u8], offset: usize, value: &[u8]) -> QueryDirectoryResult<()> {
    let end = offset
        .checked_add(value.len())
        .ok_or(QueryDirectoryError::LengthOverflow)?;
    let Some(dst) = data.get_mut(offset..end) else {
        return Err(QueryDirectoryError::BufferTooShort);
    };
    dst.copy_from_slice(value);
    Ok(())
}

fn slice_at(data: &[u8], offset: usize, len: usize) -> QueryDirectoryResult<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(QueryDirectoryError::LengthOverflow)?;
    data.get(offset..end)
        .ok_or(QueryDirectoryError::BufferTooShort)
}

fn len_to_u32(len: usize) -> QueryDirectoryResult<u32> {
    u32::try_from(len).map_err(|_| QueryDirectoryError::LengthOverflow)
}

fn require_len(data: &[u8], len: usize) -> QueryDirectoryResult<()> {
    if data.len() < len {
        return Err(QueryDirectoryError::BufferTooShort);
    }
    Ok(())
}

fn decode_directory_entry_chain<T>(
    data: &[u8],
    fixed_len: usize,
    decode: fn(&[u8]) -> QueryDirectoryResult<T>,
) -> QueryDirectoryResult<Vec<T>> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let remaining = &data[offset..];
        require_len(remaining, fixed_len)?;
        let next_entry_offset = read_u32(remaining, 0)? as usize;
        let entry_len = if next_entry_offset == 0 {
            remaining.len()
        } else {
            if next_entry_offset < fixed_len || next_entry_offset > remaining.len() {
                return Err(QueryDirectoryError::MalformedEntryChain);
            }
            next_entry_offset
        };
        entries.push(decode(slice_at(data, offset, entry_len)?)?);
        if next_entry_offset == 0 {
            break;
        }
        offset = offset
            .checked_add(next_entry_offset)
            .ok_or(QueryDirectoryError::LengthOverflow)?;
    }
    Ok(entries)
}

fn encode_directory_entry_chain<T>(
    entries: &[T],
    buf: &mut [u8],
    encode: fn(&T, u32, &mut [u8]) -> QueryDirectoryResult<usize>,
) -> QueryDirectoryResult<usize> {
    let mut offset = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let available_len = buf.len().saturating_sub(offset);
        let entry_len = encode(entry, 0, slice_mut_at(buf, offset, available_len)?)?;
        let padded_len = pad_to_32bit(entry_len);
        let next_entry_offset = if index + 1 == entries.len() {
            0
        } else {
            len_to_u32(padded_len)?
        };
        write_u32(buf, offset, next_entry_offset)?;
        let padding_start = offset
            .checked_add(entry_len)
            .ok_or(QueryDirectoryError::LengthOverflow)?;
        let padding_end = offset
            .checked_add(padded_len)
            .ok_or(QueryDirectoryError::LengthOverflow)?;
        require_len(buf, padding_end)?;
        for byte in slice_mut_at(buf, padding_start, padding_end - padding_start)? {
            *byte = 0;
        }
        offset = padding_end;
    }
    Ok(offset)
}

fn directory_entry_chain_len<T>(
    entries: &[T],
    name_len: fn(&T) -> usize,
    fixed_len: usize,
) -> QueryDirectoryResult<usize> {
    let mut total = 0usize;
    for entry in entries {
        let len = fixed_len
            .checked_add(name_len(entry))
            .ok_or(QueryDirectoryError::LengthOverflow)?;
        total = total
            .checked_add(pad_to_32bit(len))
            .ok_or(QueryDirectoryError::LengthOverflow)?;
    }
    Ok(total)
}

fn slice_mut_at(data: &mut [u8], offset: usize, len: usize) -> QueryDirectoryResult<&mut [u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(QueryDirectoryError::LengthOverflow)?;
    data.get_mut(offset..end)
        .ok_or(QueryDirectoryError::BufferTooShort)
}

fn utf16le_len(value: &str) -> QueryDirectoryResult<u16> {
    let units = value.encode_utf16().count();
    let bytes = units
        .checked_mul(2)
        .ok_or(QueryDirectoryError::LengthOverflow)?;
    u16::try_from(bytes).map_err(|_| QueryDirectoryError::LengthOverflow)
}

fn encode_utf16le(value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.encode_utf16().count() * 2);
    for unit in value.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&units)
}

fn decode_filetime(value: u64) -> Smb2Timeval {
    let timeval = smb2_win_to_timeval(value);
    Smb2Timeval {
        tv_sec: timeval.tv_sec,
        tv_usec: timeval.tv_usec,
    }
}

fn encode_filetime(value: Smb2Timeval) -> u64 {
    smb2_timeval_to_win(&super::timestamps::Smb2Timeval {
        tv_sec: value.tv_sec,
        tv_usec: value.tv_usec,
    })
}

const fn pad_to_32bit(value: usize) -> usize {
    (value + 3) & !3
}
