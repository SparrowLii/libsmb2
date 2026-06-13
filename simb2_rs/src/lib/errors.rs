//! Error helpers migrated from `lib/errors.c`.
//!
//! The legacy C file provides two table-style responsibilities: converting an
//! NTSTATUS value to a stable textual name and translating selected NTSTATUS
//! values to errno-style categories. This module keeps those responsibilities
//! separate so the generated skeleton can grow without embedding protocol flow
//! logic in the lookup functions.

/// NTSTATUS value carried by SMB2 responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtStatus(u32);

impl NtStatus {
    /// Creates an NTSTATUS wrapper from its raw 32-bit value.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw 32-bit NTSTATUS value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for NtStatus {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

/// Named NTSTATUS entry corresponding to one `nterror_to_str` switch arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtStatusName {
    /// Numeric status value matched by the legacy C switch.
    pub status: NtStatus,
    /// Stable status name returned to callers.
    pub name: &'static str,
}

impl NtStatusName {
    /// Creates a status-name mapping entry.
    #[must_use]
    pub const fn new(status: u32, name: &'static str) -> Self {
        Self {
            status: NtStatus::new(status),
            name,
        }
    }

    /// Returns `true` when this entry matches the supplied raw status value.
    #[must_use]
    pub const fn matches(self, status: u32) -> bool {
        self.status.raw() == status
    }
}

/// Errno-style category used by `nterror_to_errno`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smb2Errno {
    /// Operation completed successfully.
    Ok,
    /// Operation should be retried later.
    Again,
    /// Status uses the legacy C shutdown sentinel conversion.
    Shutdown(NtStatus),
    /// No such file, path, or device.
    NoEntry,
    /// Bad or stale file descriptor/handle.
    BadFileDescriptor,
    /// Permission or authentication denied.
    AccessDenied,
    /// Operation is not permitted for this state or object.
    PermissionDenied,
    /// Directory is not empty.
    NotEmpty,
    /// No more directory data is available.
    NoData,
    /// Connection or logon was refused.
    ConnectionRefused,
    /// Path component is not a directory.
    NotDirectory,
    /// Invalid argument or unsupported request.
    InvalidArgument,
    /// Symbolic link traversal cannot continue.
    NoLink,
    /// Too many open files.
    TooManyOpenFiles,
    /// Memory or server resources are exhausted.
    NoMemory,
    /// Cross-device operation.
    CrossDevice,
    /// Text file or shared object is busy.
    TextBusy,
    /// Lock conflict or deadlock condition.
    Deadlock,
    /// Object already exists.
    Exists,
    /// Pipe is closed or disconnected.
    Pipe,
    /// Read-only media or filesystem.
    ReadOnly,
    /// Device is missing or unavailable.
    NoDevice,
    /// Input/output failure.
    Io,
    /// No space is available on the target.
    NoSpace,
    /// Network state was reset and the caller may retry.
    NetworkReset,
    /// No exact POSIX errno exists for the NTSTATUS.
    NoExec,
    /// I/O operation timed out.
    TimedOut,
    /// Resource is busy.
    Busy,
}

impl Smb2Errno {
    /// Returns the errno integer used by the C-facing migration skeleton.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::Again => 11,
            Self::Shutdown(status) => -(status.raw() as i32),
            Self::NoEntry => 2,
            Self::BadFileDescriptor => 9,
            Self::AccessDenied => 13,
            Self::PermissionDenied => 1,
            Self::NotEmpty => 39,
            Self::NoData => 61,
            Self::ConnectionRefused => 111,
            Self::NotDirectory => 20,
            Self::InvalidArgument => 22,
            Self::NoLink => 67,
            Self::TooManyOpenFiles => 24,
            Self::NoMemory => 12,
            Self::CrossDevice => 18,
            Self::TextBusy => 26,
            Self::Deadlock => 35,
            Self::Exists => 17,
            Self::Pipe => 32,
            Self::ReadOnly => 30,
            Self::NoDevice => 19,
            Self::Io => 5,
            Self::NoSpace => 28,
            Self::NetworkReset => 102,
            Self::NoExec => 8,
            Self::TimedOut => 110,
            Self::Busy => 16,
        }
    }
}

/// NTSTATUS to errno-style mapping entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtStatusErrno {
    /// Numeric status value matched by the legacy C switch.
    pub status: NtStatus,
    /// Errno-style category returned for the status.
    pub errno: Smb2Errno,
}

impl NtStatusErrno {
    /// Creates a status-to-errno mapping entry.
    #[must_use]
    pub const fn new(status: u32, errno: Smb2Errno) -> Self {
        Self {
            status: NtStatus::new(status),
            errno,
        }
    }

    /// Returns `true` when this entry matches the supplied raw status value.
    #[must_use]
    pub const fn matches(self, status: u32) -> bool {
        self.status.raw() == status
    }
}

/// Successful NTSTATUS value.
pub const SMB2_STATUS_SUCCESS: u32 = 0x0000_0000;
/// Asynchronous operation is still pending.
pub const SMB2_STATUS_PENDING: u32 = 0x0000_0103;
/// No more directory entries are available.
pub const SMB2_STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
/// Symbolic link traversal stopped.
pub const SMB2_STATUS_STOPPED_ON_SYMLINK: u32 = 0x8000_002D;
/// Generic unsuccessful status.
pub const SMB2_STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
/// Operation is not implemented.
pub const SMB2_STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
/// Invalid handle status.
pub const SMB2_STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
/// Invalid parameter status.
pub const SMB2_STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// No such device status.
pub const SMB2_STATUS_NO_SUCH_DEVICE: u32 = 0xC000_000E;
/// No such file status.
pub const SMB2_STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
/// Invalid device request status.
pub const SMB2_STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
/// End of file status.
pub const SMB2_STATUS_END_OF_FILE: u32 = 0xC000_0011;
/// No media in device status.
pub const SMB2_STATUS_NO_MEDIA_IN_DEVICE: u32 = 0xC000_0013;
/// More processing is required.
pub const SMB2_STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
/// Invalid lock sequence status.
pub const SMB2_STATUS_INVALID_LOCK_SEQUENCE: u32 = 0xC000_001E;
/// Invalid view size status.
pub const SMB2_STATUS_INVALID_VIEW_SIZE: u32 = 0xC000_001F;
/// Memory has already been committed.
pub const SMB2_STATUS_ALREADY_COMMITTED: u32 = 0xC000_0021;
/// Access denied status.
pub const SMB2_STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
/// Object type mismatch status.
pub const SMB2_STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
/// Object name was not found.
pub const SMB2_STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
/// Object name collision status.
pub const SMB2_STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
/// Port disconnected status.
pub const SMB2_STATUS_PORT_DISCONNECTED: u32 = 0xC000_0037;
/// Object path is invalid.
pub const SMB2_STATUS_OBJECT_PATH_INVALID: u32 = 0xC000_0039;
/// Object path was not found.
pub const SMB2_STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
/// Object path syntax is invalid.
pub const SMB2_STATUS_OBJECT_PATH_SYNTAX_BAD: u32 = 0xC000_003B;
/// Data error status.
pub const SMB2_STATUS_DATA_ERROR: u32 = 0xC000_003E;
/// CRC error status.
pub const SMB2_STATUS_CRC_ERROR: u32 = 0xC000_003F;
/// Section too big status.
pub const SMB2_STATUS_SECTION_TOO_BIG: u32 = 0xC000_0040;
/// Port connection refused status.
pub const SMB2_STATUS_PORT_CONNECTION_REFUSED: u32 = 0xC000_0041;
/// Invalid port handle status.
pub const SMB2_STATUS_INVALID_PORT_HANDLE: u32 = 0xC000_0042;
/// Sharing violation status.
pub const SMB2_STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
/// Thread is terminating status.
pub const SMB2_STATUS_THREAD_IS_TERMINATING: u32 = 0xC000_004B;
/// File lock conflict status.
pub const SMB2_STATUS_FILE_LOCK_CONFLICT: u32 = 0xC000_0054;
/// Lock not granted status.
pub const SMB2_STATUS_LOCK_NOT_GRANTED: u32 = 0xC000_0055;
/// Delete pending status.
pub const SMB2_STATUS_DELETE_PENDING: u32 = 0xC000_0056;
/// Privilege not held status.
pub const SMB2_STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
/// Logon failure status.
pub const SMB2_STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
/// Account restriction status.
pub const SMB2_STATUS_ACCOUNT_RESTRICTION: u32 = 0xC000_006E;
/// Invalid logon hours status.
pub const SMB2_STATUS_INVALID_LOGON_HOURS: u32 = 0xC000_006F;
/// Password expired status.
pub const SMB2_STATUS_PASSWORD_EXPIRED: u32 = 0xC000_0071;
/// Account disabled status.
pub const SMB2_STATUS_ACCOUNT_DISABLED: u32 = 0xC000_0072;
/// Disk full status.
pub const SMB2_STATUS_DISK_FULL: u32 = 0xC000_007F;
/// Too many paging files status.
pub const SMB2_STATUS_TOO_MANY_PAGING_FILES: u32 = 0xC000_0097;
/// Insufficient resources status.
pub const SMB2_STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// DFS exit path found status.
pub const SMB2_STATUS_DFS_EXIT_PATH_FOUND: u32 = 0xC000_009B;
/// Device data error status.
pub const SMB2_STATUS_DEVICE_DATA_ERROR: u32 = 0xC000_009C;
/// Media is write protected.
pub const SMB2_STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xC000_00A2;
/// Illegal function status.
pub const SMB2_STATUS_ILLEGAL_FUNCTION: u32 = 0xC000_00AF;
/// Pipe disconnected status.
pub const SMB2_STATUS_PIPE_DISCONNECTED: u32 = 0xC000_00B0;
/// I/O timeout status.
pub const SMB2_STATUS_IO_TIMEOUT: u32 = 0xC000_00B5;
/// File is a directory status.
pub const SMB2_STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
/// Request not supported status.
pub const SMB2_STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// Invalid network response status.
pub const SMB2_STATUS_INVALID_NETWORK_RESPONSE: u32 = 0xC000_00C3;
/// Network name deleted status.
pub const SMB2_STATUS_NETWORK_NAME_DELETED: u32 = 0xC000_00C9;
/// Network access denied status.
pub const SMB2_STATUS_NETWORK_ACCESS_DENIED: u32 = 0xC000_00CA;
/// Bad network name status.
pub const SMB2_STATUS_BAD_NETWORK_NAME: u32 = 0xC000_00CC;
/// Not the same device status.
pub const SMB2_STATUS_NOT_SAME_DEVICE: u32 = 0xC000_00D4;
/// File renamed status.
pub const SMB2_STATUS_FILE_RENAMED: u32 = 0xC000_00D5;
/// Internal error status.
pub const SMB2_STATUS_INTERNAL_ERROR: u32 = 0xC000_00E5;
/// Redirector not started status.
pub const SMB2_STATUS_REDIRECTOR_NOT_STARTED: u32 = 0xC000_00FB;
/// Directory is not empty.
pub const SMB2_STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
/// Path component is not a directory.
pub const SMB2_STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
/// Process is terminating status.
pub const SMB2_STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
/// Too many opened files status.
pub const SMB2_STATUS_TOO_MANY_OPENED_FILES: u32 = 0xC000_011F;
/// Operation was cancelled.
pub const SMB2_STATUS_CANCELLED: u32 = 0xC000_0120;
/// Cannot delete status.
pub const SMB2_STATUS_CANNOT_DELETE: u32 = 0xC000_0121;
/// File was deleted.
pub const SMB2_STATUS_FILE_DELETED: u32 = 0xC000_0123;
/// File was closed.
pub const SMB2_STATUS_FILE_CLOSED: u32 = 0xC000_0128;
/// I/O device error status.
pub const SMB2_STATUS_IO_DEVICE_ERROR: u32 = 0xC000_0185;
/// Insufficient server resources status.
pub const SMB2_STATUS_INSUFF_SERVER_RESOURCES: u32 = 0xC000_0205;
/// Connection disconnected status.
pub const SMB2_STATUS_CONNECTION_DISCONNECTED: u32 = 0xC000_020C;
/// Connection reset status.
pub const SMB2_STATUS_CONNECTION_RESET: u32 = 0xC000_020D;
/// Status not found.
pub const SMB2_STATUS_NOT_FOUND: u32 = 0xC000_0225;
/// Handle cannot be closed.
pub const SMB2_STATUS_HANDLE_NOT_CLOSABLE: u32 = 0xC000_0235;
/// Connection invalid status.
pub const SMB2_STATUS_CONNECTION_INVALID: u32 = 0xC000_023A;
/// Connection aborted status.
pub const SMB2_STATUS_CONNECTION_ABORTED: u32 = 0xC000_0241;
/// Path was not covered.
pub const SMB2_STATUS_PATH_NOT_COVERED: u32 = 0xC000_0257;
/// Volume dismounted status.
pub const SMB2_STATUS_VOLUME_DISMOUNTED: u32 = 0xC000_026E;
/// Status is not a reparse point.
pub const SMB2_STATUS_NOT_A_REPARSE_POINT: u32 = 0xC000_0275;
/// Shutdown status handled specially by the C mapping.
pub const SMB2_STATUS_SHUTDOWN: u32 = 0xC000_02FE;

/// Representative name entries from the `nterror_to_str` switch table.
pub const NTERROR_NAME_TABLE: &[NtStatusName] = &[
    NtStatusName::new(SMB2_STATUS_SUCCESS, "STATUS_SUCCESS"),
    NtStatusName::new(SMB2_STATUS_SHUTDOWN, "STATUS_SHUTDOWN"),
    NtStatusName::new(SMB2_STATUS_PENDING, "STATUS_PENDING"),
    NtStatusName::new(SMB2_STATUS_NO_MORE_FILES, "STATUS_NO_MORE_FILES"),
    NtStatusName::new(SMB2_STATUS_UNSUCCESSFUL, "SMB2_STATUS_UNSUCCESSFUL"),
    NtStatusName::new(SMB2_STATUS_NOT_IMPLEMENTED, "STATUS_NOT_IMPLEMENTED"),
    NtStatusName::new(SMB2_STATUS_INVALID_HANDLE, "STATUS_INVALID_HANDLE"),
    NtStatusName::new(SMB2_STATUS_INVALID_PARAMETER, "STATUS_INVALID_PARAMETER"),
    NtStatusName::new(SMB2_STATUS_NO_SUCH_DEVICE, "STATUS_NO_SUCH_DEVICE"),
    NtStatusName::new(SMB2_STATUS_NO_SUCH_FILE, "STATUS_NO_SUCH_FILE"),
    NtStatusName::new(
        SMB2_STATUS_INVALID_DEVICE_REQUEST,
        "STATUS_INVALID_DEVICE_REQUEST",
    ),
    NtStatusName::new(SMB2_STATUS_END_OF_FILE, "STATUS_END_OF_FILE"),
    NtStatusName::new(
        SMB2_STATUS_MORE_PROCESSING_REQUIRED,
        "STATUS_MORE_PROCESSING_REQUIRED",
    ),
    NtStatusName::new(SMB2_STATUS_ACCESS_DENIED, "STATUS_ACCESS_DENIED"),
    NtStatusName::new(
        SMB2_STATUS_OBJECT_NAME_NOT_FOUND,
        "STATUS_OBJECT_NAME_NOT_FOUND",
    ),
    NtStatusName::new(
        SMB2_STATUS_OBJECT_PATH_NOT_FOUND,
        "STATUS_OBJECT_PATH_NOT_FOUND",
    ),
    NtStatusName::new(SMB2_STATUS_SHARING_VIOLATION, "STATUS_SHARING_VIOLATION"),
    NtStatusName::new(SMB2_STATUS_FILE_LOCK_CONFLICT, "STATUS_FILE_LOCK_CONFLICT"),
    NtStatusName::new(SMB2_STATUS_LOGON_FAILURE, "STATUS_LOGON_FAILURE"),
    NtStatusName::new(SMB2_STATUS_DISK_FULL, "STATUS_DISK_FULL"),
    NtStatusName::new(SMB2_STATUS_BAD_NETWORK_NAME, "STATUS_BAD_NETWORK_NAME"),
    NtStatusName::new(SMB2_STATUS_NOT_SAME_DEVICE, "STATUS_NOT_SAME_DEVICE"),
    NtStatusName::new(SMB2_STATUS_FILE_RENAMED, "STATUS_FILE_RENAMED"),
    NtStatusName::new(
        SMB2_STATUS_DIRECTORY_NOT_EMPTY,
        "STATUS_DIRECTORY_NOT_EMPTY",
    ),
    NtStatusName::new(SMB2_STATUS_NOT_A_DIRECTORY, "STATUS_NOT_A_DIRECTORY"),
    NtStatusName::new(
        SMB2_STATUS_TOO_MANY_OPENED_FILES,
        "STATUS_TOO_MANY_OPENED_FILES",
    ),
    NtStatusName::new(SMB2_STATUS_CANCELLED, "STATUS_CANCELLED"),
    NtStatusName::new(SMB2_STATUS_CANNOT_DELETE, "STATUS_CANNOT_DELETE"),
    NtStatusName::new(SMB2_STATUS_FILE_DELETED, "STATUS_FILE_DELETED"),
    NtStatusName::new(SMB2_STATUS_FILE_CLOSED, "STATUS_FILE_CLOSED"),
    NtStatusName::new(SMB2_STATUS_NOT_FOUND, "SMB2_STATUS_NOT_FOUND"),
    NtStatusName::new(
        SMB2_STATUS_NOT_A_REPARSE_POINT,
        "STATUS_NOT_A_REPARSE_POINT",
    ),
    NtStatusName::new(
        SMB2_STATUS_STOPPED_ON_SYMLINK,
        "SMB2_STATUS_STOPPED_ON_SYMLINK",
    ),
];

/// Representative errno entries from the `nterror_to_errno` switch table.
pub const NTERROR_ERRNO_TABLE: &[NtStatusErrno] = &[
    NtStatusErrno::new(SMB2_STATUS_SUCCESS, Smb2Errno::Ok),
    NtStatusErrno::new(SMB2_STATUS_END_OF_FILE, Smb2Errno::Ok),
    NtStatusErrno::new(SMB2_STATUS_PENDING, Smb2Errno::Again),
    NtStatusErrno::new(
        SMB2_STATUS_SHUTDOWN,
        Smb2Errno::Shutdown(NtStatus::new(SMB2_STATUS_SHUTDOWN)),
    ),
    NtStatusErrno::new(SMB2_STATUS_NO_SUCH_FILE, Smb2Errno::NoEntry),
    NtStatusErrno::new(SMB2_STATUS_NO_SUCH_DEVICE, Smb2Errno::NoEntry),
    NtStatusErrno::new(SMB2_STATUS_BAD_NETWORK_NAME, Smb2Errno::NoEntry),
    NtStatusErrno::new(SMB2_STATUS_OBJECT_NAME_NOT_FOUND, Smb2Errno::NoEntry),
    NtStatusErrno::new(SMB2_STATUS_OBJECT_PATH_INVALID, Smb2Errno::NoEntry),
    NtStatusErrno::new(SMB2_STATUS_OBJECT_PATH_NOT_FOUND, Smb2Errno::NoEntry),
    NtStatusErrno::new(SMB2_STATUS_OBJECT_PATH_SYNTAX_BAD, Smb2Errno::NoEntry),
    NtStatusErrno::new(SMB2_STATUS_DFS_EXIT_PATH_FOUND, Smb2Errno::NoEntry),
    NtStatusErrno::new(SMB2_STATUS_DELETE_PENDING, Smb2Errno::NoEntry),
    NtStatusErrno::new(SMB2_STATUS_REDIRECTOR_NOT_STARTED, Smb2Errno::NoEntry),
    NtStatusErrno::new(SMB2_STATUS_NOT_FOUND, Smb2Errno::NoEntry),
    NtStatusErrno::new(SMB2_STATUS_INVALID_HANDLE, Smb2Errno::BadFileDescriptor),
    NtStatusErrno::new(
        SMB2_STATUS_OBJECT_TYPE_MISMATCH,
        Smb2Errno::BadFileDescriptor,
    ),
    NtStatusErrno::new(SMB2_STATUS_PORT_DISCONNECTED, Smb2Errno::BadFileDescriptor),
    NtStatusErrno::new(
        SMB2_STATUS_INVALID_PORT_HANDLE,
        Smb2Errno::BadFileDescriptor,
    ),
    NtStatusErrno::new(
        SMB2_STATUS_HANDLE_NOT_CLOSABLE,
        Smb2Errno::BadFileDescriptor,
    ),
    NtStatusErrno::new(SMB2_STATUS_MORE_PROCESSING_REQUIRED, Smb2Errno::Again),
    NtStatusErrno::new(SMB2_STATUS_ACCESS_DENIED, Smb2Errno::AccessDenied),
    NtStatusErrno::new(SMB2_STATUS_NETWORK_ACCESS_DENIED, Smb2Errno::AccessDenied),
    NtStatusErrno::new(SMB2_STATUS_ACCOUNT_RESTRICTION, Smb2Errno::AccessDenied),
    NtStatusErrno::new(SMB2_STATUS_INVALID_LOGON_HOURS, Smb2Errno::AccessDenied),
    NtStatusErrno::new(SMB2_STATUS_PASSWORD_EXPIRED, Smb2Errno::AccessDenied),
    NtStatusErrno::new(SMB2_STATUS_ACCOUNT_DISABLED, Smb2Errno::AccessDenied),
    NtStatusErrno::new(
        SMB2_STATUS_INVALID_LOCK_SEQUENCE,
        Smb2Errno::PermissionDenied,
    ),
    NtStatusErrno::new(SMB2_STATUS_INVALID_VIEW_SIZE, Smb2Errno::PermissionDenied),
    NtStatusErrno::new(SMB2_STATUS_ALREADY_COMMITTED, Smb2Errno::PermissionDenied),
    NtStatusErrno::new(
        SMB2_STATUS_PORT_CONNECTION_REFUSED,
        Smb2Errno::PermissionDenied,
    ),
    NtStatusErrno::new(
        SMB2_STATUS_THREAD_IS_TERMINATING,
        Smb2Errno::PermissionDenied,
    ),
    NtStatusErrno::new(SMB2_STATUS_PRIVILEGE_NOT_HELD, Smb2Errno::PermissionDenied),
    NtStatusErrno::new(SMB2_STATUS_FILE_IS_A_DIRECTORY, Smb2Errno::PermissionDenied),
    NtStatusErrno::new(SMB2_STATUS_FILE_RENAMED, Smb2Errno::PermissionDenied),
    NtStatusErrno::new(
        SMB2_STATUS_PROCESS_IS_TERMINATING,
        Smb2Errno::PermissionDenied,
    ),
    NtStatusErrno::new(SMB2_STATUS_CANNOT_DELETE, Smb2Errno::PermissionDenied),
    NtStatusErrno::new(SMB2_STATUS_FILE_DELETED, Smb2Errno::PermissionDenied),
    NtStatusErrno::new(SMB2_STATUS_DIRECTORY_NOT_EMPTY, Smb2Errno::NotEmpty),
    NtStatusErrno::new(SMB2_STATUS_NO_MORE_FILES, Smb2Errno::NoData),
    NtStatusErrno::new(SMB2_STATUS_LOGON_FAILURE, Smb2Errno::ConnectionRefused),
    NtStatusErrno::new(SMB2_STATUS_NOT_A_DIRECTORY, Smb2Errno::NotDirectory),
    NtStatusErrno::new(SMB2_STATUS_NOT_IMPLEMENTED, Smb2Errno::InvalidArgument),
    NtStatusErrno::new(
        SMB2_STATUS_INVALID_DEVICE_REQUEST,
        Smb2Errno::InvalidArgument,
    ),
    NtStatusErrno::new(SMB2_STATUS_ILLEGAL_FUNCTION, Smb2Errno::InvalidArgument),
    NtStatusErrno::new(SMB2_STATUS_INVALID_PARAMETER, Smb2Errno::InvalidArgument),
    NtStatusErrno::new(SMB2_STATUS_NOT_SUPPORTED, Smb2Errno::InvalidArgument),
    NtStatusErrno::new(SMB2_STATUS_NOT_A_REPARSE_POINT, Smb2Errno::InvalidArgument),
    NtStatusErrno::new(SMB2_STATUS_STOPPED_ON_SYMLINK, Smb2Errno::NoLink),
    NtStatusErrno::new(
        SMB2_STATUS_TOO_MANY_OPENED_FILES,
        Smb2Errno::TooManyOpenFiles,
    ),
    NtStatusErrno::new(SMB2_STATUS_SECTION_TOO_BIG, Smb2Errno::NoMemory),
    NtStatusErrno::new(SMB2_STATUS_TOO_MANY_PAGING_FILES, Smb2Errno::NoMemory),
    NtStatusErrno::new(SMB2_STATUS_INSUFF_SERVER_RESOURCES, Smb2Errno::NoMemory),
    NtStatusErrno::new(SMB2_STATUS_NOT_SAME_DEVICE, Smb2Errno::CrossDevice),
    NtStatusErrno::new(SMB2_STATUS_SHARING_VIOLATION, Smb2Errno::TextBusy),
    NtStatusErrno::new(SMB2_STATUS_FILE_LOCK_CONFLICT, Smb2Errno::Deadlock),
    NtStatusErrno::new(SMB2_STATUS_LOCK_NOT_GRANTED, Smb2Errno::Deadlock),
    NtStatusErrno::new(SMB2_STATUS_OBJECT_NAME_COLLISION, Smb2Errno::Exists),
    NtStatusErrno::new(SMB2_STATUS_PIPE_DISCONNECTED, Smb2Errno::Pipe),
    NtStatusErrno::new(SMB2_STATUS_MEDIA_WRITE_PROTECTED, Smb2Errno::ReadOnly),
    NtStatusErrno::new(SMB2_STATUS_NO_MEDIA_IN_DEVICE, Smb2Errno::NoDevice),
    NtStatusErrno::new(SMB2_STATUS_DATA_ERROR, Smb2Errno::Io),
    NtStatusErrno::new(SMB2_STATUS_CRC_ERROR, Smb2Errno::Io),
    NtStatusErrno::new(SMB2_STATUS_DEVICE_DATA_ERROR, Smb2Errno::Io),
    NtStatusErrno::new(SMB2_STATUS_IO_DEVICE_ERROR, Smb2Errno::Io),
    NtStatusErrno::new(SMB2_STATUS_DISK_FULL, Smb2Errno::NoSpace),
    NtStatusErrno::new(SMB2_STATUS_CANCELLED, Smb2Errno::NetworkReset),
    NtStatusErrno::new(SMB2_STATUS_FILE_CLOSED, Smb2Errno::NetworkReset),
    NtStatusErrno::new(SMB2_STATUS_VOLUME_DISMOUNTED, Smb2Errno::NetworkReset),
    NtStatusErrno::new(SMB2_STATUS_CONNECTION_DISCONNECTED, Smb2Errno::NetworkReset),
    NtStatusErrno::new(SMB2_STATUS_CONNECTION_RESET, Smb2Errno::NetworkReset),
    NtStatusErrno::new(SMB2_STATUS_CONNECTION_INVALID, Smb2Errno::NetworkReset),
    NtStatusErrno::new(SMB2_STATUS_CONNECTION_ABORTED, Smb2Errno::NetworkReset),
    NtStatusErrno::new(SMB2_STATUS_NETWORK_NAME_DELETED, Smb2Errno::NetworkReset),
    NtStatusErrno::new(
        SMB2_STATUS_INVALID_NETWORK_RESPONSE,
        Smb2Errno::NetworkReset,
    ),
    NtStatusErrno::new(SMB2_STATUS_PATH_NOT_COVERED, Smb2Errno::NoExec),
    NtStatusErrno::new(SMB2_STATUS_IO_TIMEOUT, Smb2Errno::TimedOut),
    NtStatusErrno::new(SMB2_STATUS_INSUFFICIENT_RESOURCES, Smb2Errno::Busy),
];

/// Looks up the status name returned by the legacy `nterror_to_str` function.
#[must_use]
pub fn nterror_name(status: u32) -> Option<&'static str> {
    NTERROR_NAME_TABLE
        .iter()
        .find(|entry| entry.matches(status))
        .map(|entry| entry.name)
}

/// Converts an NT status code to a textual name.
#[must_use]
pub fn nterror_to_str(status: u32) -> &'static str {
    match nterror_name(status) {
        Some(name) => name,
        None => "Unknown",
    }
}

/// Looks up the errno-style category for an NTSTATUS value.
#[must_use]
pub fn nterror_errno(status: u32) -> Smb2Errno {
    NTERROR_ERRNO_TABLE
        .iter()
        .find(|entry| entry.matches(status))
        .map_or(Smb2Errno::Io, |entry| entry.errno)
}

/// Converts an NTSTATUS value to an errno-style integer code.
#[must_use]
pub fn nterror_to_errno(status: u32) -> i32 {
    nterror_errno(status).code()
}
