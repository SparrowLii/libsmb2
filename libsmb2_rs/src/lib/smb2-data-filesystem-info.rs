//! Filesystem information data skeletons migrated from `lib/smb2-data-filesystem-info.c`.

use super::timestamps::smb2_win_to_timeval as smb2_win_to_shared_timeval;
use super::unicode::smb2_utf16_to_utf8;

/// SMB2 GUID size used by FILE_FS_OBJECT_ID_INFORMATION.
pub const SMB2_GUID_SIZE: usize = 16;
/// FILE_FS_VOLUME_INFORMATION fixed byte count before the UTF-16 label.
pub const FILE_FS_VOLUME_INFO_FIXED_LEN: usize = 18;
/// FILE_FS_SIZE_INFORMATION byte count.
pub const FILE_FS_SIZE_INFO_LEN: usize = 24;
/// FILE_FS_DEVICE_INFORMATION byte count.
pub const FILE_FS_DEVICE_INFO_LEN: usize = 8;
/// FILE_FS_ATTRIBUTE_INFORMATION fixed byte count before the UTF-16 filesystem name.
pub const FILE_FS_ATTRIBUTE_INFO_FIXED_LEN: usize = 12;
/// Minimum FILE_FS_ATTRIBUTE_INFORMATION byte count accepted by the C decoder.
pub const FILE_FS_ATTRIBUTE_INFO_MIN_LEN: usize = 20;
/// FILE_FS_CONTROL_INFORMATION byte count returned by the C encoder/decoder.
pub const FILE_FS_CONTROL_INFO_LEN: usize = 44;
/// FILE_FS_FULL_SIZE_INFORMATION byte count.
pub const FILE_FS_FULL_SIZE_INFO_LEN: usize = 32;
/// FILE_FS_OBJECT_ID_INFORMATION byte count.
pub const FILE_FS_OBJECT_ID_INFO_LEN: usize = 64;
/// FILE_FS_OBJECT_ID_INFORMATION extended-info byte count.
pub const FILE_FS_OBJECT_ID_EXTENDED_INFO_LEN: usize = 48;
/// FILE_FS_SECTOR_SIZE_INFORMATION byte count.
pub const FILE_FS_SECTOR_SIZE_INFO_LEN: usize = 28;

/// Errors returned by filesystem information skeleton helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemInfoError {
    /// A fixed or variable buffer is shorter than the requested field.
    BufferTooShort,
    /// A checked offset or length calculation overflowed.
    LengthOverflow,
    /// A variable-length field cannot be represented in the C wire field width.
    LengthOutOfRange,
    /// A declared UTF-16LE name length is not divisible by two bytes.
    OddUtf16NameLength,
}

impl core::fmt::Display for FilesystemInfoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooShort => f.write_str("filesystem information buffer is too short"),
            Self::LengthOverflow => {
                f.write_str("filesystem information length calculation overflowed")
            }
            Self::LengthOutOfRange => f.write_str("filesystem information length is out of range"),
            Self::OddUtf16NameLength => {
                f.write_str("filesystem information UTF-16LE name length is odd")
            }
        }
    }
}

impl std::error::Error for FilesystemInfoError {}

/// Result type for filesystem information skeleton helpers.
pub type FilesystemInfoResult<T> = core::result::Result<T, FilesystemInfoError>;

/// Rust-owned counterpart of `struct smb2_timeval` usage in this C file.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Smb2Timeval {
    /// Whole seconds since the Unix epoch.
    pub seconds: i64,
    /// Microseconds within the second.
    pub microseconds: i32,
}

impl Smb2Timeval {
    /// Creates a timestamp skeleton from Unix seconds and microseconds.
    #[must_use]
    pub const fn new(seconds: i64, microseconds: i32) -> Self {
        Self {
            seconds,
            microseconds,
        }
    }

    /// Returns the placeholder zero timestamp used when only wire layout is decoded.
    #[must_use]
    pub const fn zero() -> Self {
        Self::new(0, 0)
    }
}

/// Rust-owned counterpart of `struct smb2_file_fs_volume_info`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Smb2FileFsVolumeInfo {
    /// Volume creation time after full timestamp conversion is implemented.
    pub creation_time: Smb2Timeval,
    /// Raw Windows FILETIME value retained by this skeleton.
    pub creation_time_windows: u64,
    /// Volume serial number.
    pub volume_serial_number: u32,
    /// UTF-16LE volume label bytes from the wire payload.
    pub volume_label: Vec<u8>,
    /// Volume label decoded from UTF-16LE when present.
    pub volume_label_text: Option<String>,
    /// Non-zero when object identifiers are supported.
    pub supports_objects: u8,
    /// Reserved byte from the wire payload.
    pub reserved: u8,
}

impl Smb2FileFsVolumeInfo {
    /// Creates an empty volume-info skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the C fixed payload length before `volume_label` bytes.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        FILE_FS_VOLUME_INFO_FIXED_LEN
    }

    /// Returns the label length encoded in the C `volume_label_length` field.
    #[must_use]
    pub fn volume_label_length(&self) -> usize {
        self.volume_label.len()
    }

    /// Decodes the fixed fields and preserves UTF-16LE label bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemInfoError::BufferTooShort`] if the fixed or declared label bytes are absent.
    pub fn decode(buf: &[u8]) -> FilesystemInfoResult<Self> {
        smb2_decode_file_fs_volume_info(buf)
    }

    /// Encodes the fixed fields and already-owned UTF-16LE label bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemInfoError::LengthOutOfRange`] if the label length does not fit in `u32`.
    pub fn encode(&self) -> FilesystemInfoResult<Vec<u8>> {
        smb2_encode_file_fs_volume_info(self)
    }
}

/// Rust-owned counterpart of `struct smb2_file_fs_size_info`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Smb2FileFsSizeInfo {
    /// Total allocation units on the filesystem.
    pub total_allocation_units: u64,
    /// Allocation units available to the caller.
    pub available_allocation_units: u64,
    /// Sectors per allocation unit.
    pub sectors_per_allocation_unit: u32,
    /// Bytes per sector.
    pub bytes_per_sector: u32,
}

impl Smb2FileFsSizeInfo {
    /// Creates a size-info skeleton with all counters set to zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            total_allocation_units: 0,
            available_allocation_units: 0,
            sectors_per_allocation_unit: 0,
            bytes_per_sector: 0,
        }
    }

    /// Returns the fixed wire length used by the C encoder and decoder.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        FILE_FS_SIZE_INFO_LEN
    }

    /// Decodes FILE_FS_SIZE_INFORMATION fields.
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` is shorter than 24 bytes.
    pub fn decode(buf: &[u8]) -> FilesystemInfoResult<Self> {
        smb2_decode_file_fs_size_info(buf)
    }

    /// Encodes FILE_FS_SIZE_INFORMATION fields.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        smb2_encode_file_fs_size_info(self)
    }
}

/// Rust-owned counterpart of `struct smb2_file_fs_device_info`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Smb2FileFsDeviceInfo {
    /// Device type identifier.
    pub device_type: u32,
    /// Device characteristics bitset.
    pub characteristics: u32,
}

impl Smb2FileFsDeviceInfo {
    /// Creates a device-info skeleton with all fields set to zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            device_type: 0,
            characteristics: 0,
        }
    }

    /// Returns the fixed wire length used by the C encoder and decoder.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        FILE_FS_DEVICE_INFO_LEN
    }

    /// Decodes FILE_FS_DEVICE_INFORMATION fields.
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` is shorter than 8 bytes.
    pub fn decode(buf: &[u8]) -> FilesystemInfoResult<Self> {
        smb2_decode_file_fs_device_info(buf)
    }

    /// Encodes FILE_FS_DEVICE_INFORMATION fields.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        smb2_encode_file_fs_device_info(self)
    }
}

/// Rust-owned counterpart of `struct smb2_file_fs_attribute_info`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Smb2FileFsAttributeInfo {
    /// Filesystem attribute flags.
    pub filesystem_attributes: u32,
    /// Maximum component name length supported by the filesystem.
    pub maximum_component_name_length: u32,
    /// UTF-16LE filesystem name bytes from the wire payload.
    pub filesystem_name: Vec<u8>,
    /// Filesystem name decoded from UTF-16LE when present.
    pub filesystem_name_text: Option<String>,
}

impl Smb2FileFsAttributeInfo {
    /// Creates an empty attribute-info skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the C fixed payload length before `filesystem_name` bytes.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        FILE_FS_ATTRIBUTE_INFO_FIXED_LEN
    }

    /// Returns the name length encoded in the C `filesystem_name` length field.
    #[must_use]
    pub fn filesystem_name_length(&self) -> usize {
        self.filesystem_name.len()
    }

    /// Decodes fixed fields and preserves UTF-16LE filesystem name bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemInfoError::BufferTooShort`] if the fixed or declared name bytes are absent.
    pub fn decode(buf: &[u8]) -> FilesystemInfoResult<Self> {
        smb2_decode_file_fs_attribute_info(buf)
    }

    /// Encodes fixed fields and already-owned UTF-16LE filesystem name bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemInfoError::LengthOutOfRange`] if the name length does not fit in `u32`.
    pub fn encode(&self) -> FilesystemInfoResult<Vec<u8>> {
        smb2_encode_file_fs_attribute_info(self)
    }
}

/// Rust-owned counterpart of `struct smb2_file_fs_control_info`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Smb2FileFsControlInfo {
    /// Free-space filtering start threshold.
    pub free_space_start_filtering: u64,
    /// Free-space threshold.
    pub free_space_threshold: u64,
    /// Free-space filtering stop threshold.
    pub free_space_stop_filtering: u64,
    /// Default quota warning threshold.
    pub default_quota_threshold: u64,
    /// Default quota limit.
    pub default_quota_limit: u64,
    /// Filesystem control flags.
    pub file_system_control_flags: u32,
}

impl Smb2FileFsControlInfo {
    /// Creates a control-info skeleton with all counters set to zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            free_space_start_filtering: 0,
            free_space_threshold: 0,
            free_space_stop_filtering: 0,
            default_quota_threshold: 0,
            default_quota_limit: 0,
            file_system_control_flags: 0,
        }
    }

    /// Returns the byte count returned by the C encoder and decoder.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        FILE_FS_CONTROL_INFO_LEN
    }

    /// Decodes FILE_FS_CONTROL_INFORMATION fields.
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` is shorter than 44 bytes.
    pub fn decode(buf: &[u8]) -> FilesystemInfoResult<Self> {
        smb2_decode_file_fs_control_info(buf)
    }

    /// Encodes FILE_FS_CONTROL_INFORMATION fields.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        smb2_encode_file_fs_control_info(self)
    }
}

/// Rust-owned counterpart of `struct smb2_file_fs_full_size_info`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Smb2FileFsFullSizeInfo {
    /// Total allocation units on the filesystem.
    pub total_allocation_units: u64,
    /// Allocation units available to the caller.
    pub caller_available_allocation_units: u64,
    /// Actual available allocation units.
    pub actual_available_allocation_units: u64,
    /// Sectors per allocation unit.
    pub sectors_per_allocation_unit: u32,
    /// Bytes per sector.
    pub bytes_per_sector: u32,
}

impl Smb2FileFsFullSizeInfo {
    /// Creates a full-size-info skeleton with all counters set to zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            total_allocation_units: 0,
            caller_available_allocation_units: 0,
            actual_available_allocation_units: 0,
            sectors_per_allocation_unit: 0,
            bytes_per_sector: 0,
        }
    }

    /// Returns the fixed wire length used by the C encoder and decoder.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        FILE_FS_FULL_SIZE_INFO_LEN
    }

    /// Decodes FILE_FS_FULL_SIZE_INFORMATION fields.
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` is shorter than 32 bytes.
    pub fn decode(buf: &[u8]) -> FilesystemInfoResult<Self> {
        smb2_decode_file_fs_full_size_info(buf)
    }

    /// Encodes FILE_FS_FULL_SIZE_INFORMATION fields.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        smb2_encode_file_fs_full_size_info(self)
    }
}

/// Rust-owned counterpart of `struct smb2_file_fs_object_id_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2FileFsObjectIdInfo {
    /// Filesystem object GUID bytes.
    pub object_id: [u8; SMB2_GUID_SIZE],
    /// Extended object identifier bytes.
    pub extended_info: [u8; FILE_FS_OBJECT_ID_EXTENDED_INFO_LEN],
}

impl Default for Smb2FileFsObjectIdInfo {
    fn default() -> Self {
        Self {
            object_id: [0; SMB2_GUID_SIZE],
            extended_info: [0; FILE_FS_OBJECT_ID_EXTENDED_INFO_LEN],
        }
    }
}

impl Smb2FileFsObjectIdInfo {
    /// Creates an object-id-info skeleton with all bytes set to zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            object_id: [0; SMB2_GUID_SIZE],
            extended_info: [0; FILE_FS_OBJECT_ID_EXTENDED_INFO_LEN],
        }
    }

    /// Returns the fixed wire length used by the C encoder and decoder.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        FILE_FS_OBJECT_ID_INFO_LEN
    }

    /// Decodes FILE_FS_OBJECT_ID_INFORMATION fields.
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` is shorter than 64 bytes.
    pub fn decode(buf: &[u8]) -> FilesystemInfoResult<Self> {
        smb2_decode_file_fs_object_id_info(buf)
    }

    /// Encodes FILE_FS_OBJECT_ID_INFORMATION fields.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        smb2_encode_file_fs_object_id_info(self)
    }
}

/// Rust-owned counterpart of `struct smb2_file_fs_sector_size_info`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Smb2FileFsSectorSizeInfo {
    /// Logical bytes per sector.
    pub logical_bytes_per_sector: u32,
    /// Physical bytes per sector for atomicity.
    pub physical_bytes_per_sector_for_atomicity: u32,
    /// Physical bytes per sector for performance.
    pub physical_bytes_per_sector_for_performance: u32,
    /// Effective physical bytes per sector for filesystem atomicity.
    pub file_system_effective_physical_bytes_per_sector_for_atomicity: u32,
    /// Sector-size flags.
    pub flags: u32,
    /// Byte offset for sector alignment.
    pub byte_offset_for_sector_alignment: u32,
    /// Byte offset for partition alignment.
    pub byte_offset_for_partition_alignment: u32,
}

impl Smb2FileFsSectorSizeInfo {
    /// Creates a sector-size-info skeleton with all fields set to zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            logical_bytes_per_sector: 0,
            physical_bytes_per_sector_for_atomicity: 0,
            physical_bytes_per_sector_for_performance: 0,
            file_system_effective_physical_bytes_per_sector_for_atomicity: 0,
            flags: 0,
            byte_offset_for_sector_alignment: 0,
            byte_offset_for_partition_alignment: 0,
        }
    }

    /// Returns the fixed wire length used by the C encoder and decoder.
    #[must_use]
    pub const fn fixed_wire_len() -> usize {
        FILE_FS_SECTOR_SIZE_INFO_LEN
    }

    /// Decodes FILE_FS_SECTOR_SIZE_INFORMATION fields.
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` is shorter than 28 bytes.
    pub fn decode(buf: &[u8]) -> FilesystemInfoResult<Self> {
        smb2_decode_file_fs_sector_size_info(buf)
    }

    /// Encodes FILE_FS_SECTOR_SIZE_INFORMATION fields.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        smb2_encode_file_fs_sector_size_info(self)
    }
}

/// Decodes `smb2_file_fs_volume_info` fixed fields and raw UTF-16LE label bytes.
///
/// # Errors
///
/// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` does not contain the fixed fields or declared label.
pub fn smb2_decode_file_fs_volume_info(buf: &[u8]) -> FilesystemInfoResult<Smb2FileFsVolumeInfo> {
    require_len(buf, FILE_FS_VOLUME_INFO_FIXED_LEN)?;
    let creation_time_windows = read_u64(buf, 0)?;
    let label_len = read_u32(buf, 12)? as usize;
    validate_utf16_name_len(label_len)?;
    let label = slice_at(buf, FILE_FS_VOLUME_INFO_FIXED_LEN, label_len)?.to_vec();
    let volume_label_text = decode_optional_utf16_name(&label)?;
    Ok(Smb2FileFsVolumeInfo {
        creation_time: smb2_win_to_timeval(creation_time_windows),
        creation_time_windows,
        volume_serial_number: read_u32(buf, 8)?,
        volume_label: label,
        volume_label_text,
        supports_objects: read_u8(buf, 16)?,
        reserved: read_u8(buf, 17)?,
    })
}

/// Encodes `smb2_file_fs_volume_info` fixed fields and raw UTF-16LE label bytes.
///
/// # Errors
///
/// Returns [`FilesystemInfoError::LengthOutOfRange`] if the label length cannot fit in `u32`.
pub fn smb2_encode_file_fs_volume_info(fs: &Smb2FileFsVolumeInfo) -> FilesystemInfoResult<Vec<u8>> {
    let label_len = len_to_u32(fs.volume_label.len())?;
    let mut buf = vec![0; FILE_FS_VOLUME_INFO_FIXED_LEN + fs.volume_label.len()];
    write_u64(&mut buf, 0, fs.creation_time_windows)?;
    write_u32(&mut buf, 8, fs.volume_serial_number)?;
    write_u32(&mut buf, 12, label_len)?;
    write_u8(&mut buf, 16, fs.supports_objects)?;
    write_u8(&mut buf, 17, fs.reserved)?;
    write_bytes(&mut buf, FILE_FS_VOLUME_INFO_FIXED_LEN, &fs.volume_label)?;
    Ok(buf)
}

/// Decodes `smb2_file_fs_size_info` fields.
///
/// # Errors
///
/// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` is shorter than 24 bytes.
pub fn smb2_decode_file_fs_size_info(buf: &[u8]) -> FilesystemInfoResult<Smb2FileFsSizeInfo> {
    require_len(buf, FILE_FS_SIZE_INFO_LEN)?;
    Ok(Smb2FileFsSizeInfo {
        total_allocation_units: read_u64(buf, 0)?,
        available_allocation_units: read_u64(buf, 8)?,
        sectors_per_allocation_unit: read_u32(buf, 16)?,
        bytes_per_sector: read_u32(buf, 20)?,
    })
}

/// Encodes `smb2_file_fs_size_info` fields.
#[must_use]
pub fn smb2_encode_file_fs_size_info(fs: &Smb2FileFsSizeInfo) -> Vec<u8> {
    let mut buf = vec![0; FILE_FS_SIZE_INFO_LEN];
    write_u64_infallible(&mut buf, 0, fs.total_allocation_units);
    write_u64_infallible(&mut buf, 8, fs.available_allocation_units);
    write_u32_infallible(&mut buf, 16, fs.sectors_per_allocation_unit);
    write_u32_infallible(&mut buf, 20, fs.bytes_per_sector);
    buf
}

/// Decodes `smb2_file_fs_device_info` fields.
///
/// # Errors
///
/// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` is shorter than 8 bytes.
pub fn smb2_decode_file_fs_device_info(buf: &[u8]) -> FilesystemInfoResult<Smb2FileFsDeviceInfo> {
    require_len(buf, FILE_FS_DEVICE_INFO_LEN)?;
    Ok(Smb2FileFsDeviceInfo {
        device_type: read_u32(buf, 0)?,
        characteristics: read_u32(buf, 4)?,
    })
}

/// Encodes `smb2_file_fs_device_info` fields.
#[must_use]
pub fn smb2_encode_file_fs_device_info(fs: &Smb2FileFsDeviceInfo) -> Vec<u8> {
    let mut buf = vec![0; FILE_FS_DEVICE_INFO_LEN];
    write_u32_infallible(&mut buf, 0, fs.device_type);
    write_u32_infallible(&mut buf, 4, fs.characteristics);
    buf
}

/// Decodes `smb2_file_fs_attribute_info` fixed fields and raw UTF-16LE name bytes.
///
/// # Errors
///
/// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` does not contain the fixed fields or declared name.
pub fn smb2_decode_file_fs_attribute_info(
    buf: &[u8],
) -> FilesystemInfoResult<Smb2FileFsAttributeInfo> {
    require_len(buf, FILE_FS_ATTRIBUTE_INFO_FIXED_LEN)?;
    let name_len = read_u32(buf, 8)? as usize;
    validate_utf16_name_len(name_len)?;
    let name = if name_len == 0 {
        Vec::new()
    } else {
        slice_at(buf, FILE_FS_ATTRIBUTE_INFO_FIXED_LEN, name_len)?.to_vec()
    };
    Ok(Smb2FileFsAttributeInfo {
        filesystem_attributes: read_u32(buf, 0)?,
        maximum_component_name_length: read_u32(buf, 4)?,
        filesystem_name_text: decode_optional_utf16_name(&name)?,
        filesystem_name: name,
    })
}

/// Encodes `smb2_file_fs_attribute_info` fixed fields and raw UTF-16LE name bytes.
///
/// # Errors
///
/// Returns [`FilesystemInfoError::LengthOutOfRange`] if the name length cannot fit in `u32`.
pub fn smb2_encode_file_fs_attribute_info(
    fs: &Smb2FileFsAttributeInfo,
) -> FilesystemInfoResult<Vec<u8>> {
    let name_len = len_to_u32(fs.filesystem_name.len())?;
    let mut buf = vec![0; FILE_FS_ATTRIBUTE_INFO_FIXED_LEN + fs.filesystem_name.len()];
    write_u32(&mut buf, 0, fs.filesystem_attributes)?;
    write_u32(&mut buf, 4, fs.maximum_component_name_length)?;
    write_u32(&mut buf, 8, name_len)?;
    write_bytes(
        &mut buf,
        FILE_FS_ATTRIBUTE_INFO_FIXED_LEN,
        &fs.filesystem_name,
    )?;
    Ok(buf)
}

/// Decodes `smb2_file_fs_control_info` fields.
///
/// # Errors
///
/// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` is shorter than 44 bytes.
pub fn smb2_decode_file_fs_control_info(buf: &[u8]) -> FilesystemInfoResult<Smb2FileFsControlInfo> {
    require_len(buf, FILE_FS_CONTROL_INFO_LEN)?;
    Ok(Smb2FileFsControlInfo {
        free_space_start_filtering: read_u64(buf, 0)?,
        free_space_threshold: read_u64(buf, 8)?,
        free_space_stop_filtering: read_u64(buf, 16)?,
        default_quota_threshold: read_u64(buf, 24)?,
        default_quota_limit: read_u64(buf, 32)?,
        file_system_control_flags: read_u32(buf, 40)?,
    })
}

/// Encodes `smb2_file_fs_control_info` fields.
#[must_use]
pub fn smb2_encode_file_fs_control_info(fs: &Smb2FileFsControlInfo) -> Vec<u8> {
    let mut buf = vec![0; FILE_FS_CONTROL_INFO_LEN];
    write_u64_infallible(&mut buf, 0, fs.free_space_start_filtering);
    write_u64_infallible(&mut buf, 8, fs.free_space_threshold);
    write_u64_infallible(&mut buf, 16, fs.free_space_stop_filtering);
    write_u64_infallible(&mut buf, 24, fs.default_quota_threshold);
    write_u64_infallible(&mut buf, 32, fs.default_quota_limit);
    write_u32_infallible(&mut buf, 40, fs.file_system_control_flags);
    buf
}

/// Decodes `smb2_file_fs_full_size_info` fields.
///
/// # Errors
///
/// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` is shorter than 32 bytes.
pub fn smb2_decode_file_fs_full_size_info(
    buf: &[u8],
) -> FilesystemInfoResult<Smb2FileFsFullSizeInfo> {
    require_len(buf, FILE_FS_FULL_SIZE_INFO_LEN)?;
    Ok(Smb2FileFsFullSizeInfo {
        total_allocation_units: read_u64(buf, 0)?,
        caller_available_allocation_units: read_u64(buf, 8)?,
        actual_available_allocation_units: read_u64(buf, 16)?,
        sectors_per_allocation_unit: read_u32(buf, 24)?,
        bytes_per_sector: read_u32(buf, 28)?,
    })
}

/// Encodes `smb2_file_fs_full_size_info` fields.
#[must_use]
pub fn smb2_encode_file_fs_full_size_info(fs: &Smb2FileFsFullSizeInfo) -> Vec<u8> {
    let mut buf = vec![0; FILE_FS_FULL_SIZE_INFO_LEN];
    write_u64_infallible(&mut buf, 0, fs.total_allocation_units);
    write_u64_infallible(&mut buf, 8, fs.caller_available_allocation_units);
    write_u64_infallible(&mut buf, 16, fs.actual_available_allocation_units);
    write_u32_infallible(&mut buf, 24, fs.sectors_per_allocation_unit);
    write_u32_infallible(&mut buf, 28, fs.bytes_per_sector);
    buf
}

/// Decodes `smb2_file_fs_object_id_info` fields.
///
/// # Errors
///
/// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` is shorter than 64 bytes.
pub fn smb2_decode_file_fs_object_id_info(
    buf: &[u8],
) -> FilesystemInfoResult<Smb2FileFsObjectIdInfo> {
    require_len(buf, FILE_FS_OBJECT_ID_INFO_LEN)?;
    let mut object_id = [0; SMB2_GUID_SIZE];
    let mut extended_info = [0; FILE_FS_OBJECT_ID_EXTENDED_INFO_LEN];
    object_id.copy_from_slice(slice_at(buf, 0, SMB2_GUID_SIZE)?);
    extended_info.copy_from_slice(slice_at(
        buf,
        SMB2_GUID_SIZE,
        FILE_FS_OBJECT_ID_EXTENDED_INFO_LEN,
    )?);
    Ok(Smb2FileFsObjectIdInfo {
        object_id,
        extended_info,
    })
}

/// Encodes `smb2_file_fs_object_id_info` fields.
#[must_use]
pub fn smb2_encode_file_fs_object_id_info(fs: &Smb2FileFsObjectIdInfo) -> Vec<u8> {
    let mut buf = vec![0; FILE_FS_OBJECT_ID_INFO_LEN];
    copy_into_fixed(&mut buf, 0, &fs.object_id);
    copy_into_fixed(&mut buf, SMB2_GUID_SIZE, &fs.extended_info);
    buf
}

/// Decodes `smb2_file_fs_sector_size_info` fields.
///
/// # Errors
///
/// Returns [`FilesystemInfoError::BufferTooShort`] when `buf` is shorter than 28 bytes.
pub fn smb2_decode_file_fs_sector_size_info(
    buf: &[u8],
) -> FilesystemInfoResult<Smb2FileFsSectorSizeInfo> {
    require_len(buf, FILE_FS_SECTOR_SIZE_INFO_LEN)?;
    Ok(Smb2FileFsSectorSizeInfo {
        logical_bytes_per_sector: read_u32(buf, 0)?,
        physical_bytes_per_sector_for_atomicity: read_u32(buf, 4)?,
        physical_bytes_per_sector_for_performance: read_u32(buf, 8)?,
        file_system_effective_physical_bytes_per_sector_for_atomicity: read_u32(buf, 12)?,
        flags: read_u32(buf, 16)?,
        byte_offset_for_sector_alignment: read_u32(buf, 20)?,
        byte_offset_for_partition_alignment: read_u32(buf, 24)?,
    })
}

/// Encodes `smb2_file_fs_sector_size_info` fields.
#[must_use]
pub fn smb2_encode_file_fs_sector_size_info(fs: &Smb2FileFsSectorSizeInfo) -> Vec<u8> {
    let mut buf = vec![0; FILE_FS_SECTOR_SIZE_INFO_LEN];
    write_u32_infallible(&mut buf, 0, fs.logical_bytes_per_sector);
    write_u32_infallible(&mut buf, 4, fs.physical_bytes_per_sector_for_atomicity);
    write_u32_infallible(&mut buf, 8, fs.physical_bytes_per_sector_for_performance);
    write_u32_infallible(
        &mut buf,
        12,
        fs.file_system_effective_physical_bytes_per_sector_for_atomicity,
    );
    write_u32_infallible(&mut buf, 16, fs.flags);
    write_u32_infallible(&mut buf, 20, fs.byte_offset_for_sector_alignment);
    write_u32_infallible(&mut buf, 24, fs.byte_offset_for_partition_alignment);
    buf
}

fn require_len(data: &[u8], len: usize) -> FilesystemInfoResult<()> {
    if data.len() < len {
        return Err(FilesystemInfoError::BufferTooShort);
    }
    Ok(())
}

fn read_u8(data: &[u8], offset: usize) -> FilesystemInfoResult<u8> {
    data.get(offset)
        .copied()
        .ok_or(FilesystemInfoError::BufferTooShort)
}

fn read_u32(data: &[u8], offset: usize) -> FilesystemInfoResult<u32> {
    let bytes = slice_at(data, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> FilesystemInfoResult<u64> {
    let bytes = slice_at(data, offset, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn decode_optional_utf16_name(bytes: &[u8]) -> FilesystemInfoResult<Option<String>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() % 2 != 0 {
        return Err(FilesystemInfoError::OddUtf16NameLength);
    }

    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    Ok(Some(smb2_utf16_to_utf8(&units)))
}

fn smb2_win_to_timeval(windows_time: u64) -> Smb2Timeval {
    let shared = smb2_win_to_shared_timeval(windows_time);
    Smb2Timeval::new(shared.tv_sec, shared.tv_usec as i32)
}

fn write_u8(data: &mut [u8], offset: usize, value: u8) -> FilesystemInfoResult<()> {
    let Some(slot) = data.get_mut(offset) else {
        return Err(FilesystemInfoError::BufferTooShort);
    };
    *slot = value;
    Ok(())
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) -> FilesystemInfoResult<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_u64(data: &mut [u8], offset: usize, value: u64) -> FilesystemInfoResult<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_bytes(data: &mut [u8], offset: usize, value: &[u8]) -> FilesystemInfoResult<()> {
    let end = offset
        .checked_add(value.len())
        .ok_or(FilesystemInfoError::LengthOverflow)?;
    let Some(dst) = data.get_mut(offset..end) else {
        return Err(FilesystemInfoError::BufferTooShort);
    };
    dst.copy_from_slice(value);
    Ok(())
}

fn write_u32_infallible(data: &mut [u8], offset: usize, value: u32) {
    copy_into_fixed(data, offset, &value.to_le_bytes());
}

fn write_u64_infallible(data: &mut [u8], offset: usize, value: u64) {
    copy_into_fixed(data, offset, &value.to_le_bytes());
}

fn copy_into_fixed(data: &mut [u8], offset: usize, value: &[u8]) {
    let end = offset + value.len();
    if let Some(dst) = data.get_mut(offset..end) {
        dst.copy_from_slice(value);
    }
}

fn slice_at(data: &[u8], offset: usize, len: usize) -> FilesystemInfoResult<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(FilesystemInfoError::LengthOverflow)?;
    data.get(offset..end)
        .ok_or(FilesystemInfoError::BufferTooShort)
}

fn validate_utf16_name_len(len: usize) -> FilesystemInfoResult<()> {
    if len % 2 != 0 {
        return Err(FilesystemInfoError::OddUtf16NameLength);
    }
    Ok(())
}

fn len_to_u32(len: usize) -> FilesystemInfoResult<u32> {
    u32::try_from(len).map_err(|_| FilesystemInfoError::LengthOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn volume_info_roundtrips_declared_utf16_label() {
        let info = Smb2FileFsVolumeInfo {
            creation_time_windows: 42,
            volume_serial_number: 7,
            volume_label: utf16le("卷标"),
            supports_objects: 1,
            reserved: 0,
            ..Smb2FileFsVolumeInfo::default()
        };

        let encoded = smb2_encode_file_fs_volume_info(&info).unwrap();
        let decoded = smb2_decode_file_fs_volume_info(&encoded).unwrap();

        assert_eq!(decoded.volume_label, info.volume_label);
        assert_eq!(decoded.volume_label_text.as_deref(), Some("卷标"));
        assert_eq!(decoded.volume_label_length(), 4);
    }

    #[test]
    fn volume_info_rejects_truncated_label() {
        let mut buf = vec![0; FILE_FS_VOLUME_INFO_FIXED_LEN + 2];
        buf[12..16].copy_from_slice(&4u32.to_le_bytes());

        assert_eq!(
            smb2_decode_file_fs_volume_info(&buf),
            Err(FilesystemInfoError::BufferTooShort)
        );
    }

    #[test]
    fn attribute_info_accepts_empty_variable_buffer() {
        let mut buf = vec![0; FILE_FS_ATTRIBUTE_INFO_FIXED_LEN];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes());
        buf[4..8].copy_from_slice(&255u32.to_le_bytes());

        let decoded = smb2_decode_file_fs_attribute_info(&buf).unwrap();

        assert_eq!(decoded.filesystem_attributes, 1);
        assert_eq!(decoded.maximum_component_name_length, 255);
        assert_eq!(decoded.filesystem_name_text, None);
    }

    #[test]
    fn attribute_info_rejects_odd_utf16_name_length() {
        let mut buf = vec![0; FILE_FS_ATTRIBUTE_INFO_FIXED_LEN + 1];
        buf[8..12].copy_from_slice(&1u32.to_le_bytes());

        assert_eq!(
            smb2_decode_file_fs_attribute_info(&buf),
            Err(FilesystemInfoError::OddUtf16NameLength)
        );
    }
}

// ===========================================================================
// C-parity filesystem-info codec facade mirroring the safe `legacy` binding.
// Used by spec tests. Offsets and return codes follow lib/smb2-data-filesystem-info.c.
// ===========================================================================

use super::timestamps::{smb2_timeval_to_win, Smb2Timeval as TsTimeval};
use super::unicode::smb2_utf8_to_utf16;

/// FILE_FS_SIZE_INFORMATION parity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsSizeInfo {
    /// Total allocation units.
    pub total_allocation_units: u64,
    /// Available allocation units.
    pub available_allocation_units: u64,
    /// Sectors per allocation unit.
    pub sectors_per_allocation_unit: u32,
    /// Bytes per sector.
    pub bytes_per_sector: u32,
}

/// FILE_FS_DEVICE_INFORMATION parity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsDeviceInfo {
    /// Device type.
    pub device_type: u32,
    /// Device characteristics.
    pub characteristics: u32,
}

/// FILE_FS_VOLUME_INFORMATION parity record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsVolumeInfo {
    /// Creation time seconds (Unix epoch).
    pub creation_time_seconds: i64,
    /// Creation time microseconds.
    pub creation_time_microseconds: i64,
    /// Volume serial number.
    pub volume_serial_number: u32,
    /// Object support flag.
    pub supports_objects: u8,
    /// Reserved byte.
    pub reserved: u8,
    /// UTF-8 volume label.
    pub volume_label: String,
}

/// FILE_FS_ATTRIBUTE_INFORMATION parity record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsAttributeInfo {
    /// Filesystem attribute flags.
    pub filesystem_attributes: u32,
    /// Maximum component name length.
    pub maximum_component_name_length: u32,
    /// UTF-8 filesystem name.
    pub filesystem_name: String,
}

/// FILE_FS_CONTROL_INFORMATION parity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsControlInfo {
    /// Free-space start-filtering threshold.
    pub free_space_start_filtering: u64,
    /// Free-space threshold.
    pub free_space_threshold: u64,
    /// Free-space stop-filtering threshold.
    pub free_space_stop_filtering: u64,
    /// Default quota threshold.
    pub default_quota_threshold: u64,
    /// Default quota limit.
    pub default_quota_limit: u64,
    /// Filesystem control flags.
    pub file_system_control_flags: u32,
}

/// FILE_FS_FULL_SIZE_INFORMATION parity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsFullSizeInfo {
    /// Total allocation units.
    pub total_allocation_units: u64,
    /// Caller-available allocation units.
    pub caller_available_allocation_units: u64,
    /// Actual-available allocation units.
    pub actual_available_allocation_units: u64,
    /// Sectors per allocation unit.
    pub sectors_per_allocation_unit: u32,
    /// Bytes per sector.
    pub bytes_per_sector: u32,
}

/// FILE_FS_OBJECTID_INFORMATION parity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsObjectIdInfo {
    /// Object id (16 bytes).
    pub object_id: [u8; 16],
    /// Extended info (48 bytes).
    pub extended_info: [u8; 48],
}

fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([b[o], b[o+1], b[o+2], b[o+3], b[o+4], b[o+5], b[o+6], b[o+7]])
}
/// `decode_size`: parse FILE_FS_SIZE_INFORMATION (>= 24 bytes).
pub fn decode_size(buf: &[u8]) -> core::result::Result<FsSizeInfo, i32> {
    if buf.len() < 24 { return Err(-1); }
    Ok(FsSizeInfo {
        total_allocation_units: rd_u64(buf, 0),
        available_allocation_units: rd_u64(buf, 8),
        sectors_per_allocation_unit: rd_u32(buf, 16),
        bytes_per_sector: rd_u32(buf, 20),
    })
}

/// `encode_size`: emit FILE_FS_SIZE_INFORMATION into a buffer of `out_len` bytes.
pub fn encode_size(info: FsSizeInfo, out_len: usize) -> core::result::Result<(Vec<u8>, i32), i32> {
    if out_len < 24 { return Err(-1); }
    let mut buf = vec![0u8; out_len];
    buf[0..8].copy_from_slice(&info.total_allocation_units.to_le_bytes());
    buf[8..16].copy_from_slice(&info.available_allocation_units.to_le_bytes());
    buf[16..20].copy_from_slice(&info.sectors_per_allocation_unit.to_le_bytes());
    buf[20..24].copy_from_slice(&info.bytes_per_sector.to_le_bytes());
    Ok((buf, 24))
}

/// `decode_device`: parse FILE_FS_DEVICE_INFORMATION (>= 8 bytes).
pub fn decode_device(buf: &[u8]) -> core::result::Result<FsDeviceInfo, i32> {
    if buf.len() < 8 { return Err(-1); }
    Ok(FsDeviceInfo { device_type: rd_u32(buf, 0), characteristics: rd_u32(buf, 4) })
}

/// `encode_device`: emit FILE_FS_DEVICE_INFORMATION.
pub fn encode_device(info: FsDeviceInfo, out_len: usize) -> core::result::Result<(Vec<u8>, i32), i32> {
    if out_len < 8 { return Err(-1); }
    let mut buf = vec![0u8; out_len];
    buf[0..4].copy_from_slice(&info.device_type.to_le_bytes());
    buf[4..8].copy_from_slice(&info.characteristics.to_le_bytes());
    Ok((buf, 8))
}

/// `decode_volume`: parse FILE_FS_VOLUME_INFORMATION (>= 18 bytes + UTF-16 label).
pub fn decode_volume(buf: &[u8]) -> core::result::Result<FsVolumeInfo, i32> {
    if buf.len() < 18 { return Err(-1); }
    let win = rd_u64(buf, 0);
    let tv: TsTimeval = smb2_win_to_shared_timeval(win);
    let label_len = rd_u32(buf, 12) as usize;
    if 18 + label_len > buf.len() { return Err(-1); }
    let units: Vec<u16> = buf[18..18 + label_len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(FsVolumeInfo {
        creation_time_seconds: tv.tv_sec,
        creation_time_microseconds: tv.tv_usec,
        volume_serial_number: rd_u32(buf, 8),
        supports_objects: buf[16],
        reserved: buf[17],
        volume_label: smb2_utf16_to_utf8(&units),
    })
}

/// `encode_volume`: emit FILE_FS_VOLUME_INFORMATION, returning `18 + name_len`.
pub fn encode_volume(info: &FsVolumeInfo, out_len: usize) -> core::result::Result<(Vec<u8>, i32), i32> {
    let units = smb2_utf8_to_utf16(info.volume_label.as_bytes()).map_err(|_| -1)?;
    let name_bytes: Vec<u8> = units.as_units_le().iter().flat_map(|u| u.to_le_bytes()).collect();
    let total = 18 + name_bytes.len();
    if out_len < total { return Err(-1); }
    let mut buf = vec![0u8; out_len];
    let win = smb2_timeval_to_win(&TsTimeval::new(info.creation_time_seconds, info.creation_time_microseconds));
    buf[0..8].copy_from_slice(&win.to_le_bytes());
    buf[8..12].copy_from_slice(&info.volume_serial_number.to_le_bytes());
    buf[12..16].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    buf[16] = info.supports_objects;
    buf[17] = info.reserved;
    buf[18..18 + name_bytes.len()].copy_from_slice(&name_bytes);
    Ok((buf, total as i32))
}

/// `decode_attribute`: parse FILE_FS_ATTRIBUTE_INFORMATION (>= 20 bytes).
pub fn decode_attribute(buf: &[u8]) -> core::result::Result<FsAttributeInfo, i32> {
    if buf.len() < 20 { return Err(-1); }
    let name_len = rd_u32(buf, 8) as usize;
    if 12 + name_len > buf.len() { return Err(-1); }
    let units: Vec<u16> = buf[12..12 + name_len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(FsAttributeInfo {
        filesystem_attributes: rd_u32(buf, 0),
        maximum_component_name_length: rd_u32(buf, 4),
        filesystem_name: smb2_utf16_to_utf8(&units),
    })
}

/// `encode_attribute`: emit FILE_FS_ATTRIBUTE_INFORMATION, returning `12 + name_len`.
pub fn encode_attribute(info: &FsAttributeInfo, out_len: usize) -> core::result::Result<(Vec<u8>, i32), i32> {
    if out_len < 12 { return Err(-1); }
    let units = smb2_utf8_to_utf16(info.filesystem_name.as_bytes()).map_err(|_| -1)?;
    let name_bytes: Vec<u8> = units.as_units_le().iter().flat_map(|u| u.to_le_bytes()).collect();
    let total = 12 + name_bytes.len();
    if out_len < total { return Err(-1); }
    let mut buf = vec![0u8; out_len];
    buf[0..4].copy_from_slice(&info.filesystem_attributes.to_le_bytes());
    buf[4..8].copy_from_slice(&info.maximum_component_name_length.to_le_bytes());
    buf[8..12].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    buf[12..12 + name_bytes.len()].copy_from_slice(&name_bytes);
    Ok((buf, total as i32))
}

/// `decode_control`: parse FILE_FS_CONTROL_INFORMATION (>= 44 bytes), returns `(info, 44)`.
pub fn decode_control(buf: &[u8]) -> core::result::Result<(FsControlInfo, i32), i32> {
    if buf.len() < 44 { return Err(-1); }
    Ok((FsControlInfo {
        free_space_start_filtering: rd_u64(buf, 0),
        free_space_threshold: rd_u64(buf, 8),
        free_space_stop_filtering: rd_u64(buf, 16),
        default_quota_threshold: rd_u64(buf, 24),
        default_quota_limit: rd_u64(buf, 32),
        file_system_control_flags: rd_u32(buf, 40),
    }, 44))
}

/// `encode_control`: emit FILE_FS_CONTROL_INFORMATION; needs >= 48 bytes, returns 44.
pub fn encode_control(info: FsControlInfo, out_len: usize) -> core::result::Result<(Vec<u8>, i32), i32> {
    if out_len < 48 { return Err(-1); }
    let mut buf = vec![0u8; out_len];
    buf[0..8].copy_from_slice(&info.free_space_start_filtering.to_le_bytes());
    buf[8..16].copy_from_slice(&info.free_space_threshold.to_le_bytes());
    buf[16..24].copy_from_slice(&info.free_space_stop_filtering.to_le_bytes());
    buf[24..32].copy_from_slice(&info.default_quota_threshold.to_le_bytes());
    buf[32..40].copy_from_slice(&info.default_quota_limit.to_le_bytes());
    buf[40..44].copy_from_slice(&info.file_system_control_flags.to_le_bytes());
    Ok((buf, 44))
}

/// `decode_full_size`: parse FILE_FS_FULL_SIZE_INFORMATION (>= 32 bytes).
pub fn decode_full_size(buf: &[u8]) -> core::result::Result<FsFullSizeInfo, i32> {
    if buf.len() < 32 { return Err(-1); }
    Ok(FsFullSizeInfo {
        total_allocation_units: rd_u64(buf, 0),
        caller_available_allocation_units: rd_u64(buf, 8),
        actual_available_allocation_units: rd_u64(buf, 16),
        sectors_per_allocation_unit: rd_u32(buf, 24),
        bytes_per_sector: rd_u32(buf, 28),
    })
}

/// `encode_full_size`: emit FILE_FS_FULL_SIZE_INFORMATION.
pub fn encode_full_size(info: FsFullSizeInfo, out_len: usize) -> core::result::Result<(Vec<u8>, i32), i32> {
    if out_len < 32 { return Err(-1); }
    let mut buf = vec![0u8; out_len];
    buf[0..8].copy_from_slice(&info.total_allocation_units.to_le_bytes());
    buf[8..16].copy_from_slice(&info.caller_available_allocation_units.to_le_bytes());
    buf[16..24].copy_from_slice(&info.actual_available_allocation_units.to_le_bytes());
    buf[24..28].copy_from_slice(&info.sectors_per_allocation_unit.to_le_bytes());
    buf[28..32].copy_from_slice(&info.bytes_per_sector.to_le_bytes());
    Ok((buf, 32))
}

/// `decode_object_id`: parse FILE_FS_OBJECTID_INFORMATION (>= 64 bytes).
pub fn decode_object_id(buf: &[u8]) -> core::result::Result<FsObjectIdInfo, i32> {
    if buf.len() < 64 { return Err(-1); }
    let mut object_id = [0u8; 16];
    object_id.copy_from_slice(&buf[0..16]);
    let mut extended_info = [0u8; 48];
    extended_info.copy_from_slice(&buf[16..64]);
    Ok(FsObjectIdInfo { object_id, extended_info })
}
