//! Error helpers migrated from `lib/errors.c`.
//!
//! The legacy C file provides two table-style responsibilities: converting an
//! NTSTATUS value to a stable textual name and translating selected NTSTATUS
//! values to errno-style categories. This module keeps those responsibilities
//! separate so the generated skeleton can grow without embedding protocol flow
//! logic in the lookup functions.

pub use crate::include::smb2::smb2_errors::NtStatus;

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

pub use crate::include::smb2::smb2_errors::{
    SMB2_STATUS_ACCESS_DENIED, SMB2_STATUS_ACCOUNT_DISABLED, SMB2_STATUS_ACCOUNT_RESTRICTION,
    SMB2_STATUS_ALREADY_COMMITTED, SMB2_STATUS_BAD_NETWORK_NAME, SMB2_STATUS_CANCELLED,
    SMB2_STATUS_CANNOT_DELETE, SMB2_STATUS_CONNECTION_ABORTED, SMB2_STATUS_CONNECTION_DISCONNECTED,
    SMB2_STATUS_CONNECTION_INVALID, SMB2_STATUS_CONNECTION_RESET, SMB2_STATUS_CRC_ERROR,
    SMB2_STATUS_DATA_ERROR, SMB2_STATUS_DELETE_PENDING, SMB2_STATUS_DEVICE_DATA_ERROR,
    SMB2_STATUS_DFS_EXIT_PATH_FOUND, SMB2_STATUS_DIRECTORY_NOT_EMPTY, SMB2_STATUS_DISK_FULL,
    SMB2_STATUS_END_OF_FILE, SMB2_STATUS_FILE_CLOSED, SMB2_STATUS_FILE_DELETED,
    SMB2_STATUS_FILE_IS_A_DIRECTORY, SMB2_STATUS_FILE_LOCK_CONFLICT, SMB2_STATUS_FILE_RENAMED,
    SMB2_STATUS_HANDLE_NOT_CLOSABLE, SMB2_STATUS_ILLEGAL_FUNCTION,
    SMB2_STATUS_INSUFFICIENT_RESOURCES, SMB2_STATUS_INSUFF_SERVER_RESOURCES,
    SMB2_STATUS_INVALID_DEVICE_REQUEST, SMB2_STATUS_INVALID_HANDLE,
    SMB2_STATUS_INVALID_LOCK_SEQUENCE, SMB2_STATUS_INVALID_LOGON_HOURS,
    SMB2_STATUS_INVALID_NETWORK_RESPONSE, SMB2_STATUS_INVALID_PARAMETER,
    SMB2_STATUS_INVALID_PORT_HANDLE, SMB2_STATUS_INVALID_VIEW_SIZE, SMB2_STATUS_IO_DEVICE_ERROR,
    SMB2_STATUS_IO_TIMEOUT, SMB2_STATUS_LOCK_NOT_GRANTED, SMB2_STATUS_LOGON_FAILURE,
    SMB2_STATUS_MEDIA_WRITE_PROTECTED, SMB2_STATUS_MORE_PROCESSING_REQUIRED,
    SMB2_STATUS_NETWORK_ACCESS_DENIED, SMB2_STATUS_NETWORK_NAME_DELETED,
    SMB2_STATUS_NOT_A_DIRECTORY, SMB2_STATUS_NOT_A_REPARSE_POINT, SMB2_STATUS_NOT_FOUND,
    SMB2_STATUS_NOT_IMPLEMENTED, SMB2_STATUS_NOT_SAME_DEVICE, SMB2_STATUS_NOT_SUPPORTED,
    SMB2_STATUS_NO_MEDIA_IN_DEVICE, SMB2_STATUS_NO_MORE_FILES, SMB2_STATUS_NO_SUCH_DEVICE,
    SMB2_STATUS_NO_SUCH_FILE, SMB2_STATUS_OBJECT_NAME_COLLISION, SMB2_STATUS_OBJECT_NAME_NOT_FOUND,
    SMB2_STATUS_OBJECT_PATH_INVALID, SMB2_STATUS_OBJECT_PATH_NOT_FOUND,
    SMB2_STATUS_OBJECT_PATH_SYNTAX_BAD, SMB2_STATUS_OBJECT_TYPE_MISMATCH,
    SMB2_STATUS_PASSWORD_EXPIRED, SMB2_STATUS_PATH_NOT_COVERED, SMB2_STATUS_PENDING,
    SMB2_STATUS_PIPE_DISCONNECTED, SMB2_STATUS_PORT_CONNECTION_REFUSED,
    SMB2_STATUS_PORT_DISCONNECTED, SMB2_STATUS_PRIVILEGE_NOT_HELD,
    SMB2_STATUS_PROCESS_IS_TERMINATING, SMB2_STATUS_REDIRECTOR_NOT_STARTED,
    SMB2_STATUS_SECTION_TOO_BIG, SMB2_STATUS_SHARING_VIOLATION, SMB2_STATUS_SHUTDOWN,
    SMB2_STATUS_STOPPED_ON_SYMLINK, SMB2_STATUS_SUCCESS, SMB2_STATUS_THREAD_IS_TERMINATING,
    SMB2_STATUS_TOO_MANY_OPENED_FILES, SMB2_STATUS_TOO_MANY_PAGING_FILES, SMB2_STATUS_UNSUCCESSFUL,
    SMB2_STATUS_VOLUME_DISMOUNTED,
};

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
    let legacy_name = NTERROR_NAME_TABLE
        .iter()
        .find(|entry| entry.matches(status))
        .map(|entry| entry.name);

    legacy_name.or_else(|| crate::include::smb2::smb2_errors::ntstatus_name(status))
}

/// Returns the unified NTSTATUS name for a raw status value when it is known.
#[must_use]
pub fn ntstatus_name(status: u32) -> Option<&'static str> {
    nterror_name(status)
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
