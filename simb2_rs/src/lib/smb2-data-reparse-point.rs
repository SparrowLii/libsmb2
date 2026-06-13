//! Reparse point encoders/decoders migrated from `lib/smb2-data-reparse-point.c`.

/// SMB2 symlink reparse tag value used by `SMB2_REPARSE_TAG_SYMLINK`.
pub const SMB2_REPARSE_TAG_SYMLINK: u32 = 0xa000_000c;

/// Symlink reparse flag indicating that the substitute name is relative.
pub const SMB2_SYMLINK_FLAG_RELATIVE: u32 = 0x0000_0001;

/// Size of the common `smb2_reparse_data_buffer` wire header.
pub const SMB2_REPARSE_DATA_HEADER_SIZE: usize = 8;

/// Minimum wire size of a symlink reparse data buffer including the common header.
pub const SMB2_SYMLINK_REPARSE_MIN_SIZE: usize = 20;

const SYMLINK_SUBSTITUTE_NAME_OFFSET_FIELD: usize = 8;
const SYMLINK_SUBSTITUTE_NAME_LENGTH_FIELD: usize = 10;
const SYMLINK_PRINT_NAME_OFFSET_FIELD: usize = 12;
const SYMLINK_PRINT_NAME_LENGTH_FIELD: usize = 14;
const SYMLINK_FLAGS_FIELD: usize = 16;
const SYMLINK_PATH_BUFFER_OFFSET: usize = 20;
const SYMLINK_REPARSE_DATA_PREFIX: usize = 12;

/// Result type used by reparse point decoding helpers.
pub type ReparseDataResult<T> = Result<T, ReparseDataError>;

/// Errors returned while decoding an SMB2 reparse data buffer skeleton.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ReparseDataError {
    /// The input buffer is too short for the requested fixed field.
    BufferTooShort,
    /// A wire length or offset calculation overflowed `usize`.
    LengthOverflow,
    /// The common reparse data length does not fit in the supplied buffer.
    InvalidReparseDataLength,
    /// A symlink name range falls outside the reparse payload bounds.
    InvalidSymlinkNameRange,
}

/// Byte range for a UTF-16LE symlink name inside a reparse point buffer.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ReparseNameRange {
    /// Offset of the UTF-16LE name relative to the beginning of the full buffer.
    pub offset: usize,
    /// Length of the UTF-16LE name in bytes.
    pub length: usize,
}

impl ReparseNameRange {
    /// Creates a range for a symlink name in the full reparse data buffer.
    #[must_use]
    pub const fn new(offset: usize, length: usize) -> Self {
        Self { offset, length }
    }

    /// Returns `true` when this name range contains no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.length == 0
    }
}

/// Rust counterpart of `struct smb2_symlink_reparse_buffer`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Smb2SymlinkReparseBuffer {
    /// Symlink flags from the wire buffer.
    pub flags: u32,
    /// Decoded substitute name placeholder matching the C `subname` field.
    pub subname: Option<String>,
    /// Decoded print name placeholder matching the C `printname` field.
    pub printname: Option<String>,
    /// Raw UTF-16LE substitute-name range retained until full string decoding is ported.
    pub subname_range: Option<ReparseNameRange>,
    /// Raw UTF-16LE print-name range retained until full string decoding is ported.
    pub printname_range: Option<ReparseNameRange>,
}

impl Smb2SymlinkReparseBuffer {
    /// Creates an empty symlink reparse buffer with the supplied flags.
    #[must_use]
    pub const fn new(flags: u32) -> Self {
        Self {
            flags,
            subname: None,
            printname: None,
            subname_range: None,
            printname_range: None,
        }
    }

    /// Returns `true` when the symlink target is marked relative.
    #[must_use]
    pub const fn is_relative(&self) -> bool {
        self.flags & SMB2_SYMLINK_FLAG_RELATIVE != 0
    }

    /// Records the raw UTF-16LE name ranges found in the wire buffer.
    #[must_use]
    pub const fn with_name_ranges(
        mut self,
        subname_range: ReparseNameRange,
        printname_range: ReparseNameRange,
    ) -> Self {
        self.subname_range = Some(subname_range);
        self.printname_range = Some(printname_range);
        self
    }
}

/// Decoded reparse-point payload variants currently represented by the Rust skeleton.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Smb2ReparseDataPayload {
    /// Symlink payload corresponding to `SMB2_REPARSE_TAG_SYMLINK`.
    Symlink(Smb2SymlinkReparseBuffer),
    /// Placeholder for tags whose protocol-specific payloads have not been migrated yet.
    Unknown,
}

/// Rust counterpart of `struct smb2_reparse_data_buffer`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Smb2ReparseDataBuffer {
    /// Reparse tag read from offset 0 of the wire buffer.
    pub reparse_tag: u32,
    /// Reparse data length read from offset 4 of the wire buffer.
    pub reparse_data_length: u16,
    /// Tag-specific payload skeleton.
    pub payload: Smb2ReparseDataPayload,
}

impl Smb2ReparseDataBuffer {
    /// Creates a reparse data buffer skeleton with an unknown payload.
    #[must_use]
    pub const fn new(reparse_tag: u32, reparse_data_length: u16) -> Self {
        Self {
            reparse_tag,
            reparse_data_length,
            payload: Smb2ReparseDataPayload::Unknown,
        }
    }

    /// Creates a symlink reparse data buffer skeleton.
    #[must_use]
    pub const fn symlink(reparse_data_length: u16, symlink: Smb2SymlinkReparseBuffer) -> Self {
        Self {
            reparse_tag: SMB2_REPARSE_TAG_SYMLINK,
            reparse_data_length,
            payload: Smb2ReparseDataPayload::Symlink(symlink),
        }
    }

    /// Returns `true` when this buffer carries a symlink reparse tag.
    #[must_use]
    pub const fn is_symlink(&self) -> bool {
        self.reparse_tag == SMB2_REPARSE_TAG_SYMLINK
    }

    /// Returns the symlink payload when the buffer contains one.
    #[must_use]
    pub const fn as_symlink(&self) -> Option<&Smb2SymlinkReparseBuffer> {
        match &self.payload {
            Smb2ReparseDataPayload::Symlink(symlink) => Some(symlink),
            Smb2ReparseDataPayload::Unknown => None,
        }
    }

    /// Decodes the fixed reparse data fields from a wire buffer.
    ///
    /// This mirrors the shape of `smb2_decode_reparse_data_buffer` without porting the
    /// complete UTF-16 to UTF-8 name conversion logic. Symlink name byte ranges are
    /// validated and retained for a future full decoder.
    ///
    /// # Errors
    ///
    /// Returns [`ReparseDataError`] when the buffer is too short, length arithmetic
    /// overflows, the declared reparse payload length does not fit in the input, or
    /// a symlink name range points outside the declared reparse payload.
    pub fn decode_reparse_data_buffer(input: &[u8]) -> ReparseDataResult<Self> {
        smb2_decode_reparse_data_buffer(input)
    }
}

/// Decodes the fixed fields of an SMB2 reparse data buffer.
///
/// The function name follows the C source entry point. It intentionally stops short
/// of performing full protocol string conversion and instead stores validated raw
/// symlink name ranges in [`Smb2SymlinkReparseBuffer`].
///
/// # Errors
///
/// Returns [`ReparseDataError`] when the input is too short, the declared payload
/// length exceeds the supplied buffer, offset arithmetic overflows, or a symlink
/// name range is outside the declared payload.
pub fn smb2_decode_reparse_data_buffer(input: &[u8]) -> ReparseDataResult<Smb2ReparseDataBuffer> {
    if input.len() < SMB2_REPARSE_DATA_HEADER_SIZE {
        return Err(ReparseDataError::BufferTooShort);
    }

    let reparse_tag = read_u32(input, 0)?;
    let reparse_data_length = read_u16(input, 4)?;
    let declared_len = usize::from(reparse_data_length)
        .checked_add(SMB2_REPARSE_DATA_HEADER_SIZE)
        .ok_or(ReparseDataError::LengthOverflow)?;

    if input.len() < declared_len {
        return Err(ReparseDataError::InvalidReparseDataLength);
    }

    if reparse_tag != SMB2_REPARSE_TAG_SYMLINK {
        return Ok(Smb2ReparseDataBuffer::new(reparse_tag, reparse_data_length));
    }

    if input.len() < SMB2_SYMLINK_REPARSE_MIN_SIZE {
        return Err(ReparseDataError::BufferTooShort);
    }

    let flags = read_u32(input, SYMLINK_FLAGS_FIELD)?;
    let subname_range = read_symlink_name_range(
        input,
        reparse_data_length,
        SYMLINK_SUBSTITUTE_NAME_OFFSET_FIELD,
        SYMLINK_SUBSTITUTE_NAME_LENGTH_FIELD,
    )?;
    let printname_range = read_symlink_name_range(
        input,
        reparse_data_length,
        SYMLINK_PRINT_NAME_OFFSET_FIELD,
        SYMLINK_PRINT_NAME_LENGTH_FIELD,
    )?;
    let symlink =
        Smb2SymlinkReparseBuffer::new(flags).with_name_ranges(subname_range, printname_range);

    Ok(Smb2ReparseDataBuffer::symlink(reparse_data_length, symlink))
}

fn read_symlink_name_range(
    input: &[u8],
    reparse_data_length: u16,
    offset_field: usize,
    length_field: usize,
) -> ReparseDataResult<ReparseNameRange> {
    let relative_offset = usize::from(read_u16(input, offset_field)?);
    let length = usize::from(read_u16(input, length_field)?);
    let reparse_bound = usize::from(reparse_data_length);
    let relative_end = relative_offset
        .checked_add(length)
        .and_then(|end| end.checked_add(SYMLINK_REPARSE_DATA_PREFIX))
        .ok_or(ReparseDataError::LengthOverflow)?;

    if relative_end > reparse_bound {
        return Err(ReparseDataError::InvalidSymlinkNameRange);
    }

    let offset = relative_offset
        .checked_add(SYMLINK_PATH_BUFFER_OFFSET)
        .ok_or(ReparseDataError::LengthOverflow)?;
    let end = offset
        .checked_add(length)
        .ok_or(ReparseDataError::LengthOverflow)?;

    if end > input.len() {
        return Err(ReparseDataError::BufferTooShort);
    }

    Ok(ReparseNameRange::new(offset, length))
}

fn read_u16(input: &[u8], offset: usize) -> ReparseDataResult<u16> {
    let bytes = read_bytes::<2>(input, offset)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(input: &[u8], offset: usize) -> ReparseDataResult<u32> {
    let bytes = read_bytes::<4>(input, offset)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_bytes<const N: usize>(input: &[u8], offset: usize) -> ReparseDataResult<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or(ReparseDataError::LengthOverflow)?;
    let Some(bytes) = input.get(offset..end) else {
        return Err(ReparseDataError::BufferTooShort);
    };
    let mut out = [0; N];
    out.copy_from_slice(bytes);
    Ok(out)
}
