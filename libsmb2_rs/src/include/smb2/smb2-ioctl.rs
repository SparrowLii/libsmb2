//! IOCTL control-code skeleton from `include/smb2/smb2-ioctl.h`.

/// Typed wrapper for an SMB2 IOCTL FSCTL control code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct IoctlCode(pub u32);

impl IoctlCode {
    /// Creates an IOCTL control-code wrapper from its raw 32-bit value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw 32-bit IOCTL control-code value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Create or get an object identifier for a file.
pub const FSCTL_CREATE_OR_GET_OBJECT_ID: u32 = 0x0009_00C0;
/// Delete an object identifier from a file.
pub const FSCTL_DELETE_OBJECT_ID: u32 = 0x0009_00A0;
/// Delete a reparse point from a file or directory.
pub const FSCTL_DELETE_REPARSE_POINT: u32 = 0x0009_00AC;
/// Duplicate extents from one file to another.
pub const FSCTL_DUPLICATE_EXTENTS_TO_FILE: u32 = 0x0009_8344;
/// Duplicate extents from one file to another using the extended request shape.
pub const FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX: u32 = 0x0009_83E8;
/// Request filesystem statistics.
pub const FSCTL_FILESYSTEM_GET_STATISTICS: u32 = 0x0009_0060;
/// Trim file-level storage ranges.
pub const FSCTL_FILE_LEVEL_TRIM: u32 = 0x0009_8208;
/// Find files owned by a security identifier.
pub const FSCTL_FIND_FILES_BY_SID: u32 = 0x0009_008F;
/// Query file compression state.
pub const FSCTL_GET_COMPRESSION: u32 = 0x0009_003C;
/// Query integrity information for a file or stream.
pub const FSCTL_GET_INTEGRITY_INFORMATION: u32 = 0x0009_027C;
/// Query NTFS volume data.
pub const FSCTL_GET_NTFS_VOLUME_DATA: u32 = 0x0009_0064;
/// Query ReFS volume data.
pub const FSCTL_GET_REFS_VOLUME_DATA: u32 = 0x0009_02D8;
/// Query an object identifier from a file.
pub const FSCTL_GET_OBJECT_ID: u32 = 0x0009_009C;
/// Query reparse-point data.
pub const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00A8;
/// Query the count of retrieval pointers.
pub const FSCTL_GET_RETRIEVAL_POINTER_COUNT: u32 = 0x0009_042B;
/// Query retrieval pointers for allocated file ranges.
pub const FSCTL_GET_RETRIEVAL_POINTERS: u32 = 0x0009_0073;
/// Query retrieval pointers and reference counts.
pub const FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT: u32 = 0x0009_03D3;
/// Validate a pathname string.
pub const FSCTL_IS_PATHNAME_VALID: u32 = 0x0009_002C;
/// Set link-tracking information for a file.
pub const FSCTL_LMR_SET_LINK_TRACKING_INFORMATION: u32 = 0x0014_00EC;
/// Mark a file handle with control flags.
pub const FSCTL_MARK_HANDLE: u32 = 0x0009_00FC;
/// Request offloaded read data.
pub const FSCTL_OFFLOAD_READ: u32 = 0x0009_4264;
/// Request offloaded write data.
pub const FSCTL_OFFLOAD_WRITE: u32 = 0x0009_8268;
/// Peek data from a named pipe.
pub const FSCTL_PIPE_PEEK: u32 = 0x0011_400C;
/// Transceive data through a named pipe.
pub const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;
/// Wait for a named pipe instance.
pub const FSCTL_PIPE_WAIT: u32 = 0x0011_0018;
/// Query allocated file ranges.
pub const FSCTL_QUERY_ALLOCATED_RANGES: u32 = 0x0009_40CF;
/// Query a FAT BIOS parameter block.
pub const FSCTL_QUERY_FAT_BPB: u32 = 0x0009_0058;
/// Query file regions.
pub const FSCTL_QUERY_FILE_REGIONS: u32 = 0x0009_0284;
/// Query on-disk volume information.
pub const FSCTL_QUERY_ON_DISK_VOLUME_INFO: u32 = 0x0009_013C;
/// Query sparing information for a volume.
pub const FSCTL_QUERY_SPARING_INFO: u32 = 0x0009_0138;
/// Read USN data for a file.
pub const FSCTL_READ_FILE_USN_DATA: u32 = 0x0009_00EB;
/// Recall a file from remote or offline storage.
pub const FSCTL_RECALL_FILE: u32 = 0x0009_0117;
/// Manage ReFS stream snapshots.
pub const FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT: u32 = 0x0009_0440;
/// Set file compression state.
pub const FSCTL_SET_COMPRESSION: u32 = 0x0009_C040;
/// Set defect-management state for a volume.
pub const FSCTL_SET_DEFECT_MANAGEMENT: u32 = 0x0009_8134;
/// Set file encryption state.
pub const FSCTL_SET_ENCRYPTION: u32 = 0x0009_00D7;
/// Set integrity information for a file or stream.
pub const FSCTL_SET_INTEGRITY_INFORMATION: u32 = 0x0009_C280;
/// Set extended integrity information for a file or stream.
pub const FSCTL_SET_INTEGRITY_INFORMATION_EX: u32 = 0x0009_0380;
/// Set an object identifier on a file.
pub const FSCTL_SET_OBJECT_ID: u32 = 0x0009_0098;
/// Set extended object-identifier data on a file.
pub const FSCTL_SET_OBJECT_ID_EXTENDED: u32 = 0x0009_00BC;
/// Set reparse-point data.
pub const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
/// Mark a file as sparse.
pub const FSCTL_SET_SPARSE: u32 = 0x0009_00C4;
/// Zero a file-data range.
pub const FSCTL_SET_ZERO_DATA: u32 = 0x0009_80C8;
/// Request zeroing on deallocation.
pub const FSCTL_SET_ZERO_ON_DEALLOCATION: u32 = 0x0009_0194;
/// Copy a file through single-instance storage semantics.
pub const FSCTL_SIS_COPYFILE: u32 = 0x0009_0100;
/// Write a close record to the USN journal.
pub const FSCTL_WRITE_USN_CLOSE_RECORD: u32 = 0x0009_00EF;
/// Enumerate previous snapshots available on the server.
pub const FSCTL_SRV_ENUMERATE_SNAPSHOTS: u32 = 0x0014_4064;
/// Query shadow-copy data; aliases `FSCTL_SRV_ENUMERATE_SNAPSHOTS` in the C header.
pub const FSCTL_GET_SHADOW_COPY_DATA: u32 = 0x0014_4064;

/// Request validation information for a negotiated SMB connection.
pub const FSCTL_VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;
/// Server-side copy chunk command.
pub const FSCTL_SRV_COPYCHUNK: u32 = 0x0014_40F2;
