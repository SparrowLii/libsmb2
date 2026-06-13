//! Reparse point encoders/decoders migrated from `lib/smb2-data-reparse-point.c`.

use core::fmt;

use super::unicode::smb2_utf16_to_utf8;

/// SMB2 symlink reparse tag value used by `SMB2_REPARSE_TAG_SYMLINK`.
pub const SMB2_REPARSE_TAG_SYMLINK: u32 = 0xa000_000c;

/// SMB2 mount-point reparse tag value used by `IO_REPARSE_TAG_MOUNT_POINT`.
pub const SMB2_REPARSE_TAG_MOUNT_POINT: u32 = 0xa000_0003;

/// Symlink reparse flag indicating that the substitute name is relative.
pub const SMB2_SYMLINK_FLAG_RELATIVE: u32 = 0x0000_0001;

/// Size of the common `smb2_reparse_data_buffer` wire header.
pub const SMB2_REPARSE_DATA_HEADER_SIZE: usize = 8;

/// Minimum wire size of a symlink reparse data buffer including the common header.
pub const SMB2_SYMLINK_REPARSE_MIN_SIZE: usize = 20;

/// Minimum wire size of a mount-point reparse data buffer including the common header.
pub const SMB2_MOUNT_POINT_REPARSE_MIN_SIZE: usize = 16;

const SYMLINK_SUBSTITUTE_NAME_OFFSET_FIELD: usize = 8;
const SYMLINK_SUBSTITUTE_NAME_LENGTH_FIELD: usize = 10;
const SYMLINK_PRINT_NAME_OFFSET_FIELD: usize = 12;
const SYMLINK_PRINT_NAME_LENGTH_FIELD: usize = 14;
const SYMLINK_FLAGS_FIELD: usize = 16;
const SYMLINK_PATH_BUFFER_OFFSET: usize = 20;
const SYMLINK_REPARSE_DATA_PREFIX: usize = 12;
const MOUNT_POINT_SUBSTITUTE_NAME_OFFSET_FIELD: usize = 8;
const MOUNT_POINT_SUBSTITUTE_NAME_LENGTH_FIELD: usize = 10;
const MOUNT_POINT_PRINT_NAME_OFFSET_FIELD: usize = 12;
const MOUNT_POINT_PRINT_NAME_LENGTH_FIELD: usize = 14;
const MOUNT_POINT_PATH_BUFFER_OFFSET: usize = 16;
const MOUNT_POINT_REPARSE_DATA_PREFIX: usize = 8;

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
    /// A UTF-16LE symlink name length is not divisible by two bytes.
    OddUtf16NameLength,
    /// The payload cannot be encoded from the available Rust-owned fields.
    UnsupportedPayload,
}

impl fmt::Display for ReparseDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort => f.write_str("reparse data buffer is too short"),
            Self::LengthOverflow => f.write_str("reparse data length calculation overflowed"),
            Self::InvalidReparseDataLength => f.write_str("invalid reparse data length"),
            Self::InvalidSymlinkNameRange => f.write_str("invalid reparse point name range"),
            Self::OddUtf16NameLength => f.write_str("reparse point UTF-16LE name length is odd"),
            Self::UnsupportedPayload => f.write_str("unsupported reparse data payload"),
        }
    }
}

impl std::error::Error for ReparseDataError {}

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

/// Rust counterpart of a mount-point reparse buffer.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Smb2MountPointReparseBuffer {
    /// Decoded substitute name.
    pub subname: Option<String>,
    /// Decoded print name.
    pub printname: Option<String>,
    /// Raw UTF-16LE substitute-name range in the full reparse data buffer.
    pub subname_range: Option<ReparseNameRange>,
    /// Raw UTF-16LE print-name range in the full reparse data buffer.
    pub printname_range: Option<ReparseNameRange>,
}

impl Smb2MountPointReparseBuffer {
    /// Creates an empty mount-point reparse buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            subname: None,
            printname: None,
            subname_range: None,
            printname_range: None,
        }
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

impl Default for Smb2MountPointReparseBuffer {
    fn default() -> Self {
        Self::new()
    }
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
    /// Mount-point payload corresponding to `SMB2_REPARSE_TAG_MOUNT_POINT`.
    MountPoint(Smb2MountPointReparseBuffer),
    /// Raw payload for reparse tags not decoded by this module.
    Raw(Vec<u8>),
    /// Placeholder for buffers where protocol-specific raw bytes are not available.
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

    /// Creates a reparse data buffer carrying raw tag-specific payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReparseDataError::LengthOverflow`] if `payload` length cannot fit in `u16`.
    pub fn raw(reparse_tag: u32, payload: Vec<u8>) -> ReparseDataResult<Self> {
        let reparse_data_length = len_to_u16(payload.len())?;
        Ok(Self {
            reparse_tag,
            reparse_data_length,
            payload: Smb2ReparseDataPayload::Raw(payload),
        })
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
            Smb2ReparseDataPayload::MountPoint(_) => None,
            Smb2ReparseDataPayload::Raw(_) => None,
            Smb2ReparseDataPayload::Unknown => None,
        }
    }

    /// Encodes this reparse data buffer to the SMB2 wire layout.
    ///
    /// # Errors
    ///
    /// Returns [`ReparseDataError`] if lengths overflow or a payload cannot be written.
    pub fn encode_reparse_data_buffer(&self) -> ReparseDataResult<Vec<u8>> {
        smb2_encode_reparse_data_buffer(self)
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

/// Decodes the fixed fields and symlink names of an SMB2 reparse data buffer.
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

    match reparse_tag {
        SMB2_REPARSE_TAG_SYMLINK => decode_symlink_reparse_data_buffer(input, reparse_data_length),
        SMB2_REPARSE_TAG_MOUNT_POINT => {
            decode_mount_point_reparse_data_buffer(input, reparse_data_length)
        }
        _ => {
            let payload = input[SMB2_REPARSE_DATA_HEADER_SIZE..declared_len].to_vec();
            Ok(Smb2ReparseDataBuffer {
                reparse_tag,
                reparse_data_length,
                payload: Smb2ReparseDataPayload::Raw(payload),
            })
        }
    }
}

/// Encodes an SMB2 reparse data buffer.
///
/// # Errors
///
/// Returns [`ReparseDataError`] if lengths overflow or a payload cannot be written.
pub fn smb2_encode_reparse_data_buffer(data: &Smb2ReparseDataBuffer) -> ReparseDataResult<Vec<u8>> {
    match &data.payload {
        Smb2ReparseDataPayload::Symlink(symlink) => encode_symlink_reparse_data_buffer(symlink),
        Smb2ReparseDataPayload::MountPoint(mount_point) => {
            encode_mount_point_reparse_data_buffer(mount_point)
        }
        Smb2ReparseDataPayload::Raw(payload) => {
            encode_raw_reparse_data_buffer(data.reparse_tag, payload)
        }
        Smb2ReparseDataPayload::Unknown => {
            let payload = vec![0; usize::from(data.reparse_data_length)];
            encode_raw_reparse_data_buffer(data.reparse_tag, &payload)
        }
    }
}

fn decode_symlink_reparse_data_buffer(
    input: &[u8],
    reparse_data_length: u16,
) -> ReparseDataResult<Smb2ReparseDataBuffer> {
    if input.len() < SMB2_SYMLINK_REPARSE_MIN_SIZE {
        return Err(ReparseDataError::BufferTooShort);
    }
    if usize::from(reparse_data_length) < SYMLINK_REPARSE_DATA_PREFIX {
        return Err(ReparseDataError::InvalidReparseDataLength);
    }

    let flags = read_u32(input, SYMLINK_FLAGS_FIELD)?;
    let subname_range = read_reparse_name_range(
        input,
        reparse_data_length,
        SYMLINK_SUBSTITUTE_NAME_OFFSET_FIELD,
        SYMLINK_SUBSTITUTE_NAME_LENGTH_FIELD,
        SYMLINK_REPARSE_DATA_PREFIX,
        SYMLINK_PATH_BUFFER_OFFSET,
    )?;
    let printname_range = read_reparse_name_range(
        input,
        reparse_data_length,
        SYMLINK_PRINT_NAME_OFFSET_FIELD,
        SYMLINK_PRINT_NAME_LENGTH_FIELD,
        SYMLINK_REPARSE_DATA_PREFIX,
        SYMLINK_PATH_BUFFER_OFFSET,
    )?;
    let symlink =
        Smb2SymlinkReparseBuffer::new(flags).with_name_ranges(subname_range, printname_range);
    let symlink = Smb2SymlinkReparseBuffer {
        subname: decode_utf16le_name(input, subname_range)?,
        printname: decode_utf16le_name(input, printname_range)?,
        ..symlink
    };

    Ok(Smb2ReparseDataBuffer::symlink(reparse_data_length, symlink))
}

fn decode_mount_point_reparse_data_buffer(
    input: &[u8],
    reparse_data_length: u16,
) -> ReparseDataResult<Smb2ReparseDataBuffer> {
    if input.len() < SMB2_MOUNT_POINT_REPARSE_MIN_SIZE {
        return Err(ReparseDataError::BufferTooShort);
    }
    if usize::from(reparse_data_length) < MOUNT_POINT_REPARSE_DATA_PREFIX {
        return Err(ReparseDataError::InvalidReparseDataLength);
    }

    let subname_range = read_reparse_name_range(
        input,
        reparse_data_length,
        MOUNT_POINT_SUBSTITUTE_NAME_OFFSET_FIELD,
        MOUNT_POINT_SUBSTITUTE_NAME_LENGTH_FIELD,
        MOUNT_POINT_REPARSE_DATA_PREFIX,
        MOUNT_POINT_PATH_BUFFER_OFFSET,
    )?;
    let printname_range = read_reparse_name_range(
        input,
        reparse_data_length,
        MOUNT_POINT_PRINT_NAME_OFFSET_FIELD,
        MOUNT_POINT_PRINT_NAME_LENGTH_FIELD,
        MOUNT_POINT_REPARSE_DATA_PREFIX,
        MOUNT_POINT_PATH_BUFFER_OFFSET,
    )?;
    let mount_point =
        Smb2MountPointReparseBuffer::new().with_name_ranges(subname_range, printname_range);
    let mount_point = Smb2MountPointReparseBuffer {
        subname: decode_utf16le_name(input, subname_range)?,
        printname: decode_utf16le_name(input, printname_range)?,
        ..mount_point
    };

    Ok(Smb2ReparseDataBuffer {
        reparse_tag: SMB2_REPARSE_TAG_MOUNT_POINT,
        reparse_data_length,
        payload: Smb2ReparseDataPayload::MountPoint(mount_point),
    })
}

fn encode_symlink_reparse_data_buffer(
    symlink: &Smb2SymlinkReparseBuffer,
) -> ReparseDataResult<Vec<u8>> {
    let subname = symlink.subname.as_deref().unwrap_or_default();
    let printname = symlink.printname.as_deref().unwrap_or_default();
    let subname_bytes = encode_utf16le(subname);
    let printname_bytes = encode_utf16le(printname);
    let subname_len = len_to_u16(subname_bytes.len())?;
    let printname_offset = len_to_u16(subname_bytes.len())?;
    let printname_len = len_to_u16(printname_bytes.len())?;
    let reparse_data_length = SYMLINK_REPARSE_DATA_PREFIX
        .checked_add(subname_bytes.len())
        .and_then(|len| len.checked_add(printname_bytes.len()))
        .ok_or(ReparseDataError::LengthOverflow)?;
    let reparse_data_length_u16 = len_to_u16(reparse_data_length)?;
    let total_len = SMB2_REPARSE_DATA_HEADER_SIZE
        .checked_add(reparse_data_length)
        .ok_or(ReparseDataError::LengthOverflow)?;
    let mut out = vec![0; total_len];
    write_u32(&mut out, 0, SMB2_REPARSE_TAG_SYMLINK)?;
    write_u16(&mut out, 4, reparse_data_length_u16)?;
    write_u16(&mut out, SYMLINK_SUBSTITUTE_NAME_OFFSET_FIELD, 0)?;
    write_u16(&mut out, SYMLINK_SUBSTITUTE_NAME_LENGTH_FIELD, subname_len)?;
    write_u16(&mut out, SYMLINK_PRINT_NAME_OFFSET_FIELD, printname_offset)?;
    write_u16(&mut out, SYMLINK_PRINT_NAME_LENGTH_FIELD, printname_len)?;
    write_u32(&mut out, SYMLINK_FLAGS_FIELD, symlink.flags)?;
    write_bytes(&mut out, SYMLINK_PATH_BUFFER_OFFSET, &subname_bytes)?;
    write_bytes(
        &mut out,
        SYMLINK_PATH_BUFFER_OFFSET + subname_bytes.len(),
        &printname_bytes,
    )?;
    Ok(out)
}

fn encode_mount_point_reparse_data_buffer(
    mount_point: &Smb2MountPointReparseBuffer,
) -> ReparseDataResult<Vec<u8>> {
    let subname = mount_point.subname.as_deref().unwrap_or_default();
    let printname = mount_point.printname.as_deref().unwrap_or_default();
    let subname_bytes = encode_utf16le(subname);
    let printname_bytes = encode_utf16le(printname);
    let subname_len = len_to_u16(subname_bytes.len())?;
    let printname_offset = len_to_u16(subname_bytes.len())?;
    let printname_len = len_to_u16(printname_bytes.len())?;
    let reparse_data_length = MOUNT_POINT_REPARSE_DATA_PREFIX
        .checked_add(subname_bytes.len())
        .and_then(|len| len.checked_add(printname_bytes.len()))
        .ok_or(ReparseDataError::LengthOverflow)?;
    let reparse_data_length_u16 = len_to_u16(reparse_data_length)?;
    let total_len = SMB2_REPARSE_DATA_HEADER_SIZE
        .checked_add(reparse_data_length)
        .ok_or(ReparseDataError::LengthOverflow)?;
    let mut out = vec![0; total_len];
    write_u32(&mut out, 0, SMB2_REPARSE_TAG_MOUNT_POINT)?;
    write_u16(&mut out, 4, reparse_data_length_u16)?;
    write_u16(&mut out, MOUNT_POINT_SUBSTITUTE_NAME_OFFSET_FIELD, 0)?;
    write_u16(
        &mut out,
        MOUNT_POINT_SUBSTITUTE_NAME_LENGTH_FIELD,
        subname_len,
    )?;
    write_u16(
        &mut out,
        MOUNT_POINT_PRINT_NAME_OFFSET_FIELD,
        printname_offset,
    )?;
    write_u16(&mut out, MOUNT_POINT_PRINT_NAME_LENGTH_FIELD, printname_len)?;
    write_bytes(&mut out, MOUNT_POINT_PATH_BUFFER_OFFSET, &subname_bytes)?;
    write_bytes(
        &mut out,
        MOUNT_POINT_PATH_BUFFER_OFFSET + subname_bytes.len(),
        &printname_bytes,
    )?;
    Ok(out)
}

fn encode_raw_reparse_data_buffer(reparse_tag: u32, payload: &[u8]) -> ReparseDataResult<Vec<u8>> {
    let total_len = SMB2_REPARSE_DATA_HEADER_SIZE
        .checked_add(payload.len())
        .ok_or(ReparseDataError::LengthOverflow)?;
    let mut out = vec![0; total_len];
    write_u32(&mut out, 0, reparse_tag)?;
    write_u16(&mut out, 4, len_to_u16(payload.len())?)?;
    write_bytes(&mut out, SMB2_REPARSE_DATA_HEADER_SIZE, payload)?;
    Ok(out)
}

fn decode_utf16le_name(input: &[u8], range: ReparseNameRange) -> ReparseDataResult<Option<String>> {
    if range.is_empty() {
        return Ok(None);
    }
    let end = range
        .offset
        .checked_add(range.length)
        .ok_or(ReparseDataError::LengthOverflow)?;
    let Some(bytes) = input.get(range.offset..end) else {
        return Err(ReparseDataError::BufferTooShort);
    };
    if bytes.len() % 2 != 0 {
        return Err(ReparseDataError::OddUtf16NameLength);
    }
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    Ok(Some(smb2_utf16_to_utf8(&units)))
}

fn read_reparse_name_range(
    input: &[u8],
    reparse_data_length: u16,
    offset_field: usize,
    length_field: usize,
    data_prefix: usize,
    path_buffer_offset: usize,
) -> ReparseDataResult<ReparseNameRange> {
    let relative_offset = usize::from(read_u16(input, offset_field)?);
    let length = usize::from(read_u16(input, length_field)?);
    let reparse_bound = usize::from(reparse_data_length);
    let relative_end = relative_offset
        .checked_add(length)
        .and_then(|end| end.checked_add(data_prefix))
        .ok_or(ReparseDataError::LengthOverflow)?;

    if relative_end > reparse_bound {
        return Err(ReparseDataError::InvalidSymlinkNameRange);
    }
    if length % 2 != 0 {
        return Err(ReparseDataError::OddUtf16NameLength);
    }

    let offset = relative_offset
        .checked_add(path_buffer_offset)
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

fn write_u16(output: &mut [u8], offset: usize, value: u16) -> ReparseDataResult<()> {
    write_bytes(output, offset, &value.to_le_bytes())
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) -> ReparseDataResult<()> {
    write_bytes(output, offset, &value.to_le_bytes())
}

fn write_bytes(output: &mut [u8], offset: usize, value: &[u8]) -> ReparseDataResult<()> {
    let end = offset
        .checked_add(value.len())
        .ok_or(ReparseDataError::LengthOverflow)?;
    let Some(dst) = output.get_mut(offset..end) else {
        return Err(ReparseDataError::BufferTooShort);
    };
    dst.copy_from_slice(value);
    Ok(())
}

fn len_to_u16(len: usize) -> ReparseDataResult<u16> {
    u16::try_from(len).map_err(|_| ReparseDataError::LengthOverflow)
}

fn encode_utf16le(value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.encode_utf16().count() * 2);
    for unit in value.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symlink_reparse_roundtrips_utf16_names() {
        let data = Smb2ReparseDataBuffer::symlink(
            0,
            Smb2SymlinkReparseBuffer {
                flags: SMB2_SYMLINK_FLAG_RELATIVE,
                subname: Some("target/数据".to_string()),
                printname: Some("display".to_string()),
                subname_range: None,
                printname_range: None,
            },
        );

        let encoded = smb2_encode_reparse_data_buffer(&data).unwrap();
        let decoded = smb2_decode_reparse_data_buffer(&encoded).unwrap();

        let symlink = decoded.as_symlink().unwrap();
        assert!(symlink.is_relative());
        assert_eq!(symlink.subname.as_deref(), Some("target/数据"));
        assert_eq!(symlink.printname.as_deref(), Some("display"));
        assert_eq!(usize::from(decoded.reparse_data_length) + 8, encoded.len());
    }

    #[test]
    fn mount_point_reparse_roundtrips_utf16_names() {
        let data = Smb2ReparseDataBuffer {
            reparse_tag: SMB2_REPARSE_TAG_MOUNT_POINT,
            reparse_data_length: 0,
            payload: Smb2ReparseDataPayload::MountPoint(Smb2MountPointReparseBuffer {
                subname: Some("\\??\\C:\\数据".to_string()),
                printname: Some("C:\\数据".to_string()),
                subname_range: None,
                printname_range: None,
            }),
        };

        let encoded = smb2_encode_reparse_data_buffer(&data).unwrap();
        let decoded = smb2_decode_reparse_data_buffer(&encoded).unwrap();

        match decoded.payload {
            Smb2ReparseDataPayload::MountPoint(mount_point) => {
                assert_eq!(mount_point.subname.as_deref(), Some("\\??\\C:\\数据"));
                assert_eq!(mount_point.printname.as_deref(), Some("C:\\数据"));
            }
            _ => panic!("expected mount-point payload"),
        }
    }

    #[test]
    fn reparse_rejects_truncated_declared_payload() {
        let input = [0x34, 0x12, 0, 0, 4, 0, 0, 0, 1, 2];

        assert_eq!(
            smb2_decode_reparse_data_buffer(&input),
            Err(ReparseDataError::InvalidReparseDataLength)
        );
    }

    #[test]
    fn reparse_rejects_odd_utf16_name_length() {
        let mut input = vec![0; SMB2_SYMLINK_REPARSE_MIN_SIZE + 1];
        input[0..4].copy_from_slice(&SMB2_REPARSE_TAG_SYMLINK.to_le_bytes());
        input[4..6].copy_from_slice(&(13u16).to_le_bytes());
        input[10..12].copy_from_slice(&(1u16).to_le_bytes());

        assert_eq!(
            smb2_decode_reparse_data_buffer(&input),
            Err(ReparseDataError::OddUtf16NameLength)
        );
    }
}
