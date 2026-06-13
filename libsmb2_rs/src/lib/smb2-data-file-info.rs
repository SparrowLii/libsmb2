//! File information encoders/decoders migrated from `lib/smb2-data-file-info.c`.

use std::fmt;

use super::timestamps::{smb2_timeval_to_win, smb2_win_to_timeval, Smb2Timeval};
use super::unicode::{smb2_utf16_to_utf8, smb2_utf8_to_utf16, Utf8ValidationError};

/// Encoded size of `struct smb2_file_basic_info`.
pub const FILE_BASIC_INFO_SIZE: usize = 40;

/// Encoded size of `struct smb2_file_standard_info`.
pub const FILE_STANDARD_INFO_SIZE: usize = 24;

/// Encoded size of one `struct smb2_file_stream_info` header before the name.
pub const FILE_STREAM_INFO_HEADER_SIZE: usize = 24;

/// Encoded size of `struct smb2_file_position_info`.
pub const FILE_POSITION_INFO_SIZE: usize = 8;

/// Encoded size of `struct smb2_file_end_of_file_info`.
pub const FILE_END_OF_FILE_INFO_SIZE: usize = 8;

/// Encoded size of `struct smb2_file_disposition_info`.
pub const FILE_DISPOSITION_INFO_SIZE: usize = 1;

/// Encoded prefix size of `struct smb2_file_rename_info` before the UTF-16 name.
pub const FILE_RENAME_INFO_PREFIX_SIZE: usize = 20;

/// Encoded prefix size of `struct smb2_file_all_info` before the UTF-16 name.
pub const FILE_ALL_INFO_PREFIX_SIZE: usize = 100;

/// Encoded size of `struct smb2_file_network_open_info`.
pub const FILE_NETWORK_OPEN_INFO_SIZE: usize = 56;

/// Encoded prefix size of `struct smb2_file_name_info` before the UTF-16 name.
pub const FILE_NAME_INFO_PREFIX_SIZE: usize = 4;

/// Result type used by file information encoders and decoders.
pub type Result<T> = std::result::Result<T, FileInfoError>;

/// Errors reported by file information encoders and decoders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileInfoError {
    /// The provided buffer is shorter than the required SMB2 structure size.
    BufferTooShort {
        /// Required byte count.
        required: usize,
        /// Actual byte count available to the operation.
        actual: usize,
    },
    /// A byte offset or length could not be represented safely.
    IntegerOverflow,
    /// UTF-8 input could not be converted to UTF-16 for wire encoding.
    InvalidUtf8(Utf8ValidationError),
    /// A declared UTF-16LE name length is not divisible by two bytes.
    InvalidUtf16NameLength { length: usize },
}

impl fmt::Display for FileInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { required, actual } => {
                write!(
                    f,
                    "buffer too short: required {required} bytes, got {actual}"
                )
            }
            Self::IntegerOverflow => write!(f, "integer overflow while sizing file info buffer"),
            Self::InvalidUtf8(error) => {
                write!(f, "invalid UTF-8 while encoding file info: {error}")
            }
            Self::InvalidUtf16NameLength { length } => {
                write!(f, "invalid UTF-16LE name byte length {length}")
            }
        }
    }
}

impl std::error::Error for FileInfoError {}

impl From<Utf8ValidationError> for FileInfoError {
    fn from(error: Utf8ValidationError) -> Self {
        Self::InvalidUtf8(error)
    }
}

/// Rust counterpart of `struct smb2_file_basic_info`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2FileBasicInfo {
    /// File creation time.
    pub creation_time: Smb2Timeval,
    /// Last access time.
    pub last_access_time: Smb2Timeval,
    /// Last write time.
    pub last_write_time: Smb2Timeval,
    /// Metadata change time.
    pub change_time: Smb2Timeval,
    /// SMB2 file attributes bitmask.
    pub file_attributes: u32,
}

impl Smb2FileBasicInfo {
    /// Decodes `FileBasicInformation` from an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when fewer than
    /// [`FILE_BASIC_INFO_SIZE`] bytes are available.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        smb2_decode_file_basic_info(buf)
    }

    /// Encodes `FileBasicInformation` into an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when fewer than
    /// [`FILE_BASIC_INFO_SIZE`] bytes are available.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        smb2_encode_file_basic_info(self, buf)
    }
}

/// Rust counterpart of `struct smb2_file_standard_info`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2FileStandardInfo {
    /// Number of bytes allocated for the file.
    pub allocation_size: u64,
    /// Logical end-of-file offset.
    pub end_of_file: u64,
    /// Number of hard links.
    pub number_of_links: u32,
    /// Non-zero when deletion is pending.
    pub delete_pending: u8,
    /// Non-zero when the object is a directory.
    pub directory: u8,
}

impl Smb2FileStandardInfo {
    /// Decodes `FileStandardInformation` from an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when fewer than
    /// [`FILE_STANDARD_INFO_SIZE`] bytes are available.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        smb2_decode_file_standard_info(buf)
    }

    /// Encodes `FileStandardInformation` into an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when fewer than
    /// [`FILE_STANDARD_INFO_SIZE`] bytes are available.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        smb2_encode_file_standard_info(self, buf)
    }
}

/// Rust counterpart of `struct smb2_file_stream_info`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2FileStreamInfo {
    /// Stream name length in UTF-8 bytes after decode, or UTF-16LE bytes on wire.
    pub stream_name_length: u32,
    /// Number of bytes in the stream.
    pub stream_size: u64,
    /// Number of bytes allocated for the stream.
    pub stream_allocation_size: u64,
    /// Stream name decoded from UTF-16LE when present.
    pub stream_name: Option<String>,
}

/// Rust counterpart of `struct smb2_file_position_info`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2FilePositionInfo {
    /// Current byte offset for the open file.
    pub current_byte_offset: u64,
}

/// Rust counterpart of `struct smb2_file_end_of_file_info`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2FileEndOfFileInfo {
    /// New end-of-file value.
    pub end_of_file: u64,
}

impl Smb2FileEndOfFileInfo {
    /// Decodes `FileEndOfFileInformation` from an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when fewer than
    /// [`FILE_END_OF_FILE_INFO_SIZE`] bytes are available.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        smb2_decode_file_end_of_file_info(buf)
    }

    /// Encodes `FileEndOfFileInformation` into an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when fewer than
    /// [`FILE_END_OF_FILE_INFO_SIZE`] bytes are available.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        smb2_encode_file_end_of_file_info(self, buf)
    }
}

/// Rust counterpart of `struct smb2_file_disposition_info`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2FileDispositionInfo {
    /// Non-zero when the file should be marked delete-pending.
    pub delete_pending: u8,
}

impl Smb2FileDispositionInfo {
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

    /// Decodes `FileDispositionInformation` from an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when fewer than
    /// [`FILE_DISPOSITION_INFO_SIZE`] bytes are available.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        smb2_decode_file_disposition_info(buf)
    }

    /// Encodes `FileDispositionInformation` into an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when fewer than
    /// [`FILE_DISPOSITION_INFO_SIZE`] bytes are available.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        smb2_encode_file_disposition_info(self, buf)
    }
}

/// Rust counterpart of `struct smb2_file_rename_info`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2FileRenameInfo {
    /// Non-zero when an existing destination may be replaced.
    pub replace_if_exist: u8,
    /// UTF-8 destination name before the UTF-16 wire conversion.
    pub file_name: String,
}

impl Smb2FileRenameInfo {
    /// Creates a rename payload.
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

    /// Returns the UTF-16LE byte length reserved for the name on the wire.
    #[must_use]
    pub fn utf16_wire_len(&self) -> usize {
        self.file_name.encode_utf16().count().saturating_mul(2)
    }

    /// Decodes `FileRenameInformation` from an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when the fixed or declared name bytes are absent.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        smb2_decode_file_rename_info(buf)
    }

    /// Encodes `FileRenameInformation` into an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short, or
    /// [`FileInfoError::InvalidUtf8`] when the file name is not valid UTF-8.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        smb2_encode_file_rename_info(self, buf)
    }
}

impl Smb2FilePositionInfo {
    /// Decodes `FilePositionInformation` from an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when fewer than
    /// [`FILE_POSITION_INFO_SIZE`] bytes are available.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        smb2_decode_file_position_info(buf)
    }

    /// Encodes `FilePositionInformation` into an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when fewer than
    /// [`FILE_POSITION_INFO_SIZE`] bytes are available.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        smb2_encode_file_position_info(self, buf)
    }
}

/// Rust counterpart of `struct smb2_file_all_info`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2FileAllInfo {
    /// Embedded basic information block.
    pub basic: Smb2FileBasicInfo,
    /// Embedded standard information block.
    pub standard: Smb2FileStandardInfo,
    /// File index number.
    pub index_number: u64,
    /// Extended attribute size.
    pub ea_size: u32,
    /// Access flags for the file.
    pub access_flags: u32,
    /// Current byte offset for the file.
    pub current_byte_offset: u64,
    /// File mode flags.
    pub mode: u32,
    /// Alignment requirement value.
    pub alignment_requirement: u32,
    /// Optional file name decoded from UTF-16LE.
    pub name: Option<String>,
}

/// Rust counterpart of `struct smb2_file_network_open_info`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2FileNetworkOpenInfo {
    /// File creation time.
    pub creation_time: Smb2Timeval,
    /// Last access time.
    pub last_access_time: Smb2Timeval,
    /// Last write time.
    pub last_write_time: Smb2Timeval,
    /// Metadata change time.
    pub change_time: Smb2Timeval,
    /// Number of bytes allocated for the file.
    pub allocation_size: u64,
    /// Logical end-of-file offset.
    pub end_of_file: u64,
    /// SMB2 file attributes bitmask.
    pub file_attributes: u32,
}

impl Smb2FileNetworkOpenInfo {
    /// Decodes `FileNetworkOpenInformation` from an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when fewer than
    /// [`FILE_NETWORK_OPEN_INFO_SIZE`] bytes are available.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        smb2_decode_file_network_open_info(buf)
    }

    /// Encodes `FileNetworkOpenInformation` into an SMB2 wire buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FileInfoError::BufferTooShort`] when fewer than
    /// [`FILE_NETWORK_OPEN_INFO_SIZE`] bytes are available.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        smb2_encode_file_network_open_info(self, buf)
    }
}

/// Rust counterpart of `struct smb2_file_name_info`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2FileNameInfo {
    /// File name length in UTF-16LE bytes on the wire.
    pub file_name_length: u32,
    /// Optional file name decoded from UTF-16LE.
    pub name: Option<String>,
}

/// Decodes `smb2_file_basic_info` from a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_decode_file_basic_info(buf: &[u8]) -> Result<Smb2FileBasicInfo> {
    require_len(buf, FILE_BASIC_INFO_SIZE)?;
    Ok(Smb2FileBasicInfo {
        creation_time: smb2_win_to_timeval(read_u64_le(buf, 0)?),
        last_access_time: smb2_win_to_timeval(read_u64_le(buf, 8)?),
        last_write_time: smb2_win_to_timeval(read_u64_le(buf, 16)?),
        change_time: smb2_win_to_timeval(read_u64_le(buf, 24)?),
        file_attributes: read_u32_le(buf, 32)?,
    })
}

/// Encodes `smb2_file_basic_info` into a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_encode_file_basic_info(info: &Smb2FileBasicInfo, buf: &mut [u8]) -> Result<usize> {
    require_len(buf, FILE_BASIC_INFO_SIZE)?;
    write_u64_le(buf, 0, smb2_tv_timeval_to_win(&info.creation_time))?;
    write_u64_le(buf, 8, smb2_tv_timeval_to_win(&info.last_access_time))?;
    write_u64_le(buf, 16, smb2_tv_timeval_to_win(&info.last_write_time))?;
    write_u64_le(buf, 24, smb2_tv_timeval_to_win(&info.change_time))?;
    write_u32_le(buf, 32, info.file_attributes)?;
    write_u32_le(buf, 36, 0)?;
    Ok(FILE_BASIC_INFO_SIZE)
}

/// Decodes `smb2_file_standard_info` from a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_decode_file_standard_info(buf: &[u8]) -> Result<Smb2FileStandardInfo> {
    require_len(buf, FILE_STANDARD_INFO_SIZE)?;
    Ok(Smb2FileStandardInfo {
        allocation_size: read_u64_le(buf, 0)?,
        end_of_file: read_u64_le(buf, 8)?,
        number_of_links: read_u32_le(buf, 16)?,
        delete_pending: read_u8(buf, 20)?,
        directory: read_u8(buf, 21)?,
    })
}

/// Encodes `smb2_file_standard_info` into a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_encode_file_standard_info(
    info: &Smb2FileStandardInfo,
    buf: &mut [u8],
) -> Result<usize> {
    require_len(buf, FILE_STANDARD_INFO_SIZE)?;
    write_u64_le(buf, 0, info.allocation_size)?;
    write_u64_le(buf, 8, info.end_of_file)?;
    write_u32_le(buf, 16, info.number_of_links)?;
    write_u8(buf, 20, info.delete_pending)?;
    write_u8(buf, 21, info.directory)?;
    write_u16_le(buf, 22, 0)?;
    Ok(FILE_STANDARD_INFO_SIZE)
}

/// Decodes a sequence of `smb2_file_stream_info` entries from a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when an advertised entry extends
/// beyond the provided buffer.
pub fn smb2_decode_file_stream_info(buf: &[u8]) -> Result<Vec<Smb2FileStreamInfo>> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    loop {
        require_len_at(buf, offset, FILE_STREAM_INFO_HEADER_SIZE)?;
        let next_offset = read_u32_le(buf, offset)? as usize;
        let name_len = read_u32_le(buf, offset + 4)? as usize;
        let stream_size = read_u64_le(buf, offset + 8)?;
        let stream_allocation_size = read_u64_le(buf, offset + 16)?;
        validate_utf16_name_len(name_len)?;
        let entry_len = FILE_STREAM_INFO_HEADER_SIZE
            .checked_add(name_len)
            .ok_or(FileInfoError::IntegerOverflow)?;
        let entry_bound = if next_offset == 0 {
            entry_len
        } else if next_offset < entry_len {
            return Err(FileInfoError::BufferTooShort {
                required: offset + entry_len,
                actual: offset + next_offset,
            });
        } else {
            next_offset
        };
        require_len_at(buf, offset, entry_bound)?;
        let stream_name =
            decode_optional_utf16_name(buf, offset + FILE_STREAM_INFO_HEADER_SIZE, name_len)?;

        entries.push(Smb2FileStreamInfo {
            stream_name_length: read_u32_le(buf, offset + 4)?,
            stream_size,
            stream_allocation_size,
            stream_name,
        });

        if next_offset == 0 {
            break;
        }
        offset = offset
            .checked_add(next_offset)
            .ok_or(FileInfoError::IntegerOverflow)?;
    }

    Ok(entries)
}

/// Encodes a sequence of `smb2_file_stream_info` entries into a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short, or
/// [`FileInfoError::InvalidUtf8`] when a stream name is not valid UTF-8.
pub fn smb2_encode_file_stream_info(
    entries: &[Smb2FileStreamInfo],
    buf: &mut [u8],
) -> Result<usize> {
    let mut offset = 0usize;

    for (index, entry) in entries.iter().enumerate() {
        let encoded_name = encode_optional_utf16_name(entry.stream_name.as_deref())?;
        let name_len = encoded_name
            .len()
            .checked_mul(2)
            .ok_or(FileInfoError::IntegerOverflow)?;
        let entry_len = FILE_STREAM_INFO_HEADER_SIZE
            .checked_add(name_len)
            .ok_or(FileInfoError::IntegerOverflow)?;
        require_len_at(buf, offset, entry_len)?;

        let has_next = index + 1 < entries.len();
        let next_offset = if has_next {
            pad_to_64bit(entry_len)?
        } else {
            0
        };
        write_u32_le(buf, offset, usize_to_u32(next_offset)?)?;
        write_u32_le(buf, offset + 4, usize_to_u32(name_len)?)?;
        write_u64_le(buf, offset + 8, entry.stream_size)?;
        write_u64_le(buf, offset + 16, entry.stream_allocation_size)?;
        write_utf16_units(buf, offset + FILE_STREAM_INFO_HEADER_SIZE, &encoded_name)?;

        offset = offset
            .checked_add(entry_len)
            .ok_or(FileInfoError::IntegerOverflow)?;
        if has_next {
            let padded_end = offset
                .checked_add(next_offset - entry_len)
                .ok_or(FileInfoError::IntegerOverflow)?;
            require_len(buf, padded_end)?;
            buf[offset..padded_end].fill(0);
            offset = padded_end;
        }
    }

    Ok(offset)
}

/// Decodes `smb2_file_position_info` from a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_decode_file_position_info(buf: &[u8]) -> Result<Smb2FilePositionInfo> {
    require_len(buf, FILE_POSITION_INFO_SIZE)?;
    Ok(Smb2FilePositionInfo {
        current_byte_offset: read_u64_le(buf, 0)?,
    })
}

/// Encodes `smb2_file_position_info` into a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_encode_file_position_info(
    info: &Smb2FilePositionInfo,
    buf: &mut [u8],
) -> Result<usize> {
    require_len(buf, FILE_POSITION_INFO_SIZE)?;
    write_u64_le(buf, 0, info.current_byte_offset)?;
    Ok(FILE_POSITION_INFO_SIZE)
}

/// Decodes `smb2_file_end_of_file_info` from a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_decode_file_end_of_file_info(buf: &[u8]) -> Result<Smb2FileEndOfFileInfo> {
    require_len(buf, FILE_END_OF_FILE_INFO_SIZE)?;
    Ok(Smb2FileEndOfFileInfo {
        end_of_file: read_u64_le(buf, 0)?,
    })
}

/// Encodes `smb2_file_end_of_file_info` into a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_encode_file_end_of_file_info(
    info: &Smb2FileEndOfFileInfo,
    buf: &mut [u8],
) -> Result<usize> {
    require_len(buf, FILE_END_OF_FILE_INFO_SIZE)?;
    write_u64_le(buf, 0, info.end_of_file)?;
    Ok(FILE_END_OF_FILE_INFO_SIZE)
}

/// Decodes `smb2_file_disposition_info` from a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_decode_file_disposition_info(buf: &[u8]) -> Result<Smb2FileDispositionInfo> {
    require_len(buf, FILE_DISPOSITION_INFO_SIZE)?;
    Ok(Smb2FileDispositionInfo {
        delete_pending: read_u8(buf, 0)?,
    })
}

/// Encodes `smb2_file_disposition_info` into a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_encode_file_disposition_info(
    info: &Smb2FileDispositionInfo,
    buf: &mut [u8],
) -> Result<usize> {
    require_len(buf, FILE_DISPOSITION_INFO_SIZE)?;
    write_u8(buf, 0, info.delete_pending)?;
    Ok(FILE_DISPOSITION_INFO_SIZE)
}

/// Decodes `smb2_file_rename_info` from a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the fixed or declared name bytes are absent.
pub fn smb2_decode_file_rename_info(buf: &[u8]) -> Result<Smb2FileRenameInfo> {
    require_len(buf, FILE_RENAME_INFO_PREFIX_SIZE)?;
    let name_len = read_u32_le(buf, 16)? as usize;
    validate_utf16_name_len(name_len)?;
    require_len_at(buf, FILE_RENAME_INFO_PREFIX_SIZE, name_len)?;
    let mut units = Vec::with_capacity(name_len / 2);
    for chunk in
        buf[FILE_RENAME_INFO_PREFIX_SIZE..FILE_RENAME_INFO_PREFIX_SIZE + name_len].chunks_exact(2)
    {
        let mut unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        if unit == 0x005c {
            unit = 0x002f;
        }
        units.push(unit);
    }
    Ok(Smb2FileRenameInfo {
        replace_if_exist: read_u8(buf, 0)?,
        file_name: String::from_utf16_lossy(&units),
    })
}

/// Encodes `smb2_file_rename_info` into a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short, or
/// [`FileInfoError::InvalidUtf8`] when the file name is not valid UTF-8.
pub fn smb2_encode_file_rename_info(info: &Smb2FileRenameInfo, buf: &mut [u8]) -> Result<usize> {
    let mut encoded_name = encode_optional_utf16_name(Some(&info.file_name))?;
    for unit in &mut encoded_name {
        if *unit == 0x002f {
            *unit = 0x005c;
        }
    }
    let name_len = encoded_name
        .len()
        .checked_mul(2)
        .ok_or(FileInfoError::IntegerOverflow)?;
    let total_len = FILE_RENAME_INFO_PREFIX_SIZE
        .checked_add(name_len)
        .ok_or(FileInfoError::IntegerOverflow)?;
    require_len(buf, total_len)?;
    write_u8(buf, 0, info.replace_if_exist)?;
    buf[1..8].fill(0);
    write_u64_le(buf, 8, 0)?;
    write_u32_le(buf, 16, usize_to_u32(name_len)?)?;
    write_utf16_units(buf, FILE_RENAME_INFO_PREFIX_SIZE, &encoded_name)?;
    Ok(total_len)
}

/// Decodes the fixed and name fields of `smb2_file_all_info`.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_decode_file_all_info(buf: &[u8]) -> Result<Smb2FileAllInfo> {
    require_len(buf, FILE_ALL_INFO_PREFIX_SIZE)?;
    let name_len = read_u32_le(buf, 96)? as usize;
    validate_utf16_name_len(name_len)?;
    require_len_at(buf, FILE_ALL_INFO_PREFIX_SIZE, name_len)?;

    Ok(Smb2FileAllInfo {
        basic: smb2_decode_file_basic_info(&buf[0..FILE_BASIC_INFO_SIZE])?,
        standard: smb2_decode_file_standard_info(&buf[40..64])?,
        index_number: read_u64_le(buf, 64)?,
        ea_size: read_u32_le(buf, 72)?,
        access_flags: read_u32_le(buf, 76)?,
        current_byte_offset: read_u64_le(buf, 80)?,
        mode: read_u32_le(buf, 88)?,
        alignment_requirement: read_u32_le(buf, 92)?,
        name: decode_optional_utf16_name(buf, FILE_ALL_INFO_PREFIX_SIZE, name_len)?,
    })
}

/// Encodes the fixed and name fields of `smb2_file_all_info`.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short, or
/// [`FileInfoError::InvalidUtf8`] when the file name is not valid UTF-8.
pub fn smb2_encode_file_all_info(info: &Smb2FileAllInfo, buf: &mut [u8]) -> Result<usize> {
    let encoded_name = encode_optional_utf16_name(info.name.as_deref())?;
    let name_len = encoded_name
        .len()
        .checked_mul(2)
        .ok_or(FileInfoError::IntegerOverflow)?;
    let total_len = FILE_ALL_INFO_PREFIX_SIZE
        .checked_add(name_len)
        .ok_or(FileInfoError::IntegerOverflow)?;
    require_len(buf, total_len)?;

    smb2_encode_file_basic_info(&info.basic, &mut buf[0..FILE_BASIC_INFO_SIZE])?;
    smb2_encode_file_standard_info(&info.standard, &mut buf[40..64])?;
    write_u64_le(buf, 64, info.index_number)?;
    write_u32_le(buf, 72, info.ea_size)?;
    write_u32_le(buf, 76, info.access_flags)?;
    write_u64_le(buf, 80, info.current_byte_offset)?;
    write_u32_le(buf, 88, info.mode)?;
    write_u32_le(buf, 92, info.alignment_requirement)?;
    write_u32_le(buf, 96, usize_to_u32(name_len)?)?;
    write_utf16_units(buf, FILE_ALL_INFO_PREFIX_SIZE, &encoded_name)?;
    Ok(total_len)
}

/// Decodes `smb2_file_network_open_info` from a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_decode_file_network_open_info(buf: &[u8]) -> Result<Smb2FileNetworkOpenInfo> {
    require_len(buf, FILE_NETWORK_OPEN_INFO_SIZE)?;
    Ok(Smb2FileNetworkOpenInfo {
        creation_time: smb2_win_to_timeval(read_u64_le(buf, 0)?),
        last_access_time: smb2_win_to_timeval(read_u64_le(buf, 8)?),
        last_write_time: smb2_win_to_timeval(read_u64_le(buf, 16)?),
        change_time: smb2_win_to_timeval(read_u64_le(buf, 24)?),
        allocation_size: read_u64_le(buf, 32)?,
        end_of_file: read_u64_le(buf, 40)?,
        file_attributes: read_u32_le(buf, 48)?,
    })
}

/// Encodes `smb2_file_network_open_info` into a wire buffer.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_encode_file_network_open_info(
    info: &Smb2FileNetworkOpenInfo,
    buf: &mut [u8],
) -> Result<usize> {
    require_len(buf, FILE_NETWORK_OPEN_INFO_SIZE)?;
    write_u64_le(buf, 0, smb2_tv_timeval_to_win(&info.creation_time))?;
    write_u64_le(buf, 8, smb2_tv_timeval_to_win(&info.last_access_time))?;
    write_u64_le(buf, 16, smb2_tv_timeval_to_win(&info.last_write_time))?;
    write_u64_le(buf, 24, smb2_tv_timeval_to_win(&info.change_time))?;
    write_u64_le(buf, 32, info.allocation_size)?;
    write_u64_le(buf, 40, info.end_of_file)?;
    write_u32_le(buf, 48, info.file_attributes)?;
    write_u32_le(buf, 52, 0)?;
    Ok(FILE_NETWORK_OPEN_INFO_SIZE)
}

/// Decodes `smb2_file_name_info` used by normalized-name information.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short.
pub fn smb2_decode_file_normalized_name_info(buf: &[u8]) -> Result<Smb2FileNameInfo> {
    require_len(buf, FILE_NAME_INFO_PREFIX_SIZE)?;
    let file_name_length = read_u32_le(buf, 0)?;
    let name_len = file_name_length as usize;
    validate_utf16_name_len(name_len)?;
    require_len_at(buf, FILE_NAME_INFO_PREFIX_SIZE, name_len)?;
    Ok(Smb2FileNameInfo {
        file_name_length,
        name: decode_optional_utf16_name(buf, FILE_NAME_INFO_PREFIX_SIZE, name_len)?,
    })
}

/// Encodes `smb2_file_name_info` used by normalized-name information.
///
/// # Errors
///
/// Returns [`FileInfoError::BufferTooShort`] when the buffer is too short, or
/// [`FileInfoError::InvalidUtf8`] when the file name is not valid UTF-8.
pub fn smb2_encode_file_normalized_name_info(
    info: &Smb2FileNameInfo,
    buf: &mut [u8],
) -> Result<usize> {
    let encoded_name = encode_optional_utf16_name(info.name.as_deref())?;
    let encoded_len = encoded_name
        .len()
        .checked_mul(2)
        .ok_or(FileInfoError::IntegerOverflow)?;
    let name_len = encoded_len;
    let total_len = FILE_NAME_INFO_PREFIX_SIZE
        .checked_add(name_len)
        .ok_or(FileInfoError::IntegerOverflow)?;
    require_len(buf, total_len)?;

    write_u32_le(buf, 0, usize_to_u32(name_len)?)?;
    write_utf16_units(buf, FILE_NAME_INFO_PREFIX_SIZE, &encoded_name)?;
    Ok(total_len)
}

fn smb2_tv_timeval_to_win(tv: &Smb2Timeval) -> u64 {
    if tv.tv_sec == 0 && tv.tv_usec == 0 {
        0
    } else if tv.tv_sec == 0xffff_ffff && tv.tv_usec == 0xffff_ffff {
        u64::MAX
    } else {
        smb2_timeval_to_win(tv)
    }
}

fn decode_optional_utf16_name(
    buf: &[u8],
    offset: usize,
    byte_len: usize,
) -> Result<Option<String>> {
    if byte_len == 0 {
        return Ok(None);
    }
    validate_utf16_name_len(byte_len)?;
    require_len_at(buf, offset, byte_len)?;

    let mut units = Vec::with_capacity(byte_len / 2);
    for chunk in buf[offset..offset + byte_len].chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }

    Ok(Some(smb2_utf16_to_utf8(&units)))
}

fn encode_optional_utf16_name(name: Option<&str>) -> Result<Vec<u16>> {
    match name {
        Some(name) => Ok(smb2_utf8_to_utf16(name.as_bytes())?.into_units_le()),
        None => Ok(Vec::new()),
    }
}

fn validate_utf16_name_len(byte_len: usize) -> Result<()> {
    if byte_len % 2 != 0 {
        return Err(FileInfoError::InvalidUtf16NameLength { length: byte_len });
    }
    Ok(())
}

fn pad_to_64bit(value: usize) -> Result<usize> {
    let with_padding = value.checked_add(7).ok_or(FileInfoError::IntegerOverflow)?;
    Ok(with_padding & !7)
}

fn usize_to_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| FileInfoError::IntegerOverflow)
}

fn require_len(buf: &[u8], required: usize) -> Result<()> {
    if buf.len() < required {
        Err(FileInfoError::BufferTooShort {
            required,
            actual: buf.len(),
        })
    } else {
        Ok(())
    }
}

fn require_len_at(buf: &[u8], offset: usize, len: usize) -> Result<()> {
    let required = offset
        .checked_add(len)
        .ok_or(FileInfoError::IntegerOverflow)?;
    require_len(buf, required)
}

fn read_u8(buf: &[u8], offset: usize) -> Result<u8> {
    require_len_at(buf, offset, 1)?;
    Ok(buf[offset])
}

fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32> {
    require_len_at(buf, offset, 4)?;
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64_le(buf: &[u8], offset: usize) -> Result<u64> {
    require_len_at(buf, offset, 8)?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    Ok(u64::from_le_bytes(bytes))
}

fn write_u8(buf: &mut [u8], offset: usize, value: u8) -> Result<()> {
    require_len_at(buf, offset, 1)?;
    buf[offset] = value;
    Ok(())
}

fn write_u16_le(buf: &mut [u8], offset: usize, value: u16) -> Result<()> {
    require_len_at(buf, offset, 2)?;
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) -> Result<()> {
    require_len_at(buf, offset, 4)?;
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64_le(buf: &mut [u8], offset: usize, value: u64) -> Result<()> {
    require_len_at(buf, offset, 8)?;
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_utf16_units(buf: &mut [u8], offset: usize, units: &[u16]) -> Result<()> {
    let byte_len = units
        .len()
        .checked_mul(2)
        .ok_or(FileInfoError::IntegerOverflow)?;
    require_len_at(buf, offset, byte_len)?;
    for (index, unit) in units.iter().enumerate() {
        let byte_offset = offset + index * 2;
        buf[byte_offset..byte_offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_all_info_rejects_truncated_declared_name() {
        let mut buf = vec![0; FILE_ALL_INFO_PREFIX_SIZE + 2];
        buf[96..100].copy_from_slice(&4u32.to_le_bytes());

        assert_eq!(
            smb2_decode_file_all_info(&buf),
            Err(FileInfoError::BufferTooShort {
                required: FILE_ALL_INFO_PREFIX_SIZE + 4,
                actual: FILE_ALL_INFO_PREFIX_SIZE + 2,
            })
        );
    }

    #[test]
    fn normalized_name_uses_actual_utf16_wire_length() {
        let info = Smb2FileNameInfo {
            file_name_length: 64,
            name: Some("a/名".to_string()),
        };
        let mut buf = vec![0; 64];

        let written = smb2_encode_file_normalized_name_info(&info, &mut buf).unwrap();
        let decoded = smb2_decode_file_normalized_name_info(&buf[..written]).unwrap();

        assert_eq!(written, FILE_NAME_INFO_PREFIX_SIZE + 6);
        assert_eq!(decoded.file_name_length, 6);
        assert_eq!(decoded.name.as_deref(), Some("a/名"));
    }

    #[test]
    fn stream_info_roundtrips_utf16_name_and_padding() {
        let entries = vec![
            Smb2FileStreamInfo {
                stream_size: 7,
                stream_allocation_size: 8,
                stream_name: Some(":数据:$DATA".to_string()),
                ..Smb2FileStreamInfo::default()
            },
            Smb2FileStreamInfo {
                stream_size: 9,
                stream_allocation_size: 16,
                stream_name: Some(":alt:$DATA".to_string()),
                ..Smb2FileStreamInfo::default()
            },
        ];
        let mut buf = vec![0; 128];

        let written = smb2_encode_file_stream_info(&entries, &mut buf).unwrap();
        let decoded = smb2_decode_file_stream_info(&buf[..written]).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].stream_name.as_deref(), Some(":数据:$DATA"));
        assert_eq!(decoded[0].stream_name_length, 18);
        assert_eq!(decoded[1].stream_name.as_deref(), Some(":alt:$DATA"));
    }
}
