//! Blocking wrapper skeletons migrated from `lib/sync.c`.
//!
//! The C implementation turns asynchronous SMB2 requests into synchronous calls
//! by storing callback state, polling the context, and returning the callback
//! status or payload. This Rust file keeps the same responsibilities visible as
//! typed request and callback-state skeletons; it does not perform SMB2 protocol
//! I/O yet.

use crate::include::smb2::libsmb2::{
    DirectoryHandle, ErrorCode, FileHandle, Result, Smb2Client, Stat, StatVfs,
};

const EINVAL: i32 = -22;
const EINPROGRESS: i32 = -115;

/// Completion status used by synchronous wrappers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncStatus {
    code: i32,
}

impl SyncStatus {
    /// Successful completion status.
    pub const OK: Self = Self { code: 0 };

    /// Creates a status from a legacy errno or SMB2 status value.
    #[must_use]
    pub const fn new(code: i32) -> Self {
        Self { code }
    }

    /// Returns the raw legacy status code.
    #[must_use]
    pub const fn code(self) -> i32 {
        self.code
    }

    /// Returns whether this status represents success.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        self.code == 0
    }
}

/// Payload captured by a synchronous completion callback.
#[derive(Debug)]
pub enum SyncPayload {
    /// Callback completed without returning an object.
    None,
    /// Open-file result corresponding to `struct smb2fh *`.
    File(FileHandle),
    /// Open-directory result corresponding to `struct smb2dir *`.
    Directory(DirectoryHandle),
    /// Metadata result corresponding to `struct smb2_stat_64`.
    Stat(Stat),
    /// Filesystem metadata result corresponding to `struct smb2_statvfs`.
    StatVfs(StatVfs),
    /// Readlink response bytes.
    Readlink(Vec<u8>),
    /// Notify-change response entries.
    NotifyChanges(Vec<FileNotifyChangeInformation>),
    /// Share enumeration response.
    ShareEnum(ShareEnumReply),
}

/// Callback state equivalent to `struct sync_cb_data`.
#[derive(Debug)]
pub struct SyncCallbackData {
    /// Whether the asynchronous callback has completed.
    pub is_finished: bool,
    /// Status reported by the callback.
    pub status: SyncStatus,
    /// Optional command payload reported by the callback.
    pub payload: SyncPayload,
}

impl Default for SyncCallbackData {
    fn default() -> Self {
        Self {
            is_finished: false,
            status: SyncStatus::OK,
            payload: SyncPayload::None,
        }
    }
}

impl SyncCallbackData {
    /// Creates pending callback state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the callback as cancelled.
    pub fn cancel(&mut self) {
        self.is_finished = true;
        self.status = SyncStatus::new(SMB2_STATUS_CANCELLED);
        self.payload = SyncPayload::None;
    }

    /// Completes the callback with status only.
    pub fn complete_status(&mut self, status: SyncStatus) {
        self.is_finished = true;
        self.status = status;
        self.payload = SyncPayload::None;
    }

    /// Completes the callback with status and payload.
    pub fn complete_payload(&mut self, status: SyncStatus, payload: SyncPayload) {
        self.is_finished = true;
        self.status = status;
        self.payload = payload;
    }
}

/// Skeleton value for `SMB2_STATUS_CANCELLED` handling in sync callbacks.
pub const SMB2_STATUS_CANCELLED: i32 = -125;

/// Skeleton value for `SMB2_STATUS_SHUTDOWN` handling in sync callbacks.
pub const SMB2_STATUS_SHUTDOWN: i32 = -108;

/// Temporary readlink callback storage corresponding to `sync_readlink_cb_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReadlinkCallbackData {
    /// Maximum number of bytes the caller can receive.
    pub len: usize,
}

impl SyncReadlinkCallbackData {
    /// Creates readlink callback storage metadata.
    #[must_use]
    pub const fn new(len: usize) -> Self {
        Self { len }
    }
}

/// Notify-change item returned by the sync notify skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileNotifyChangeInformation {
    /// Action code from the server response.
    pub action: u32,
    /// Name associated with the action.
    pub name: String,
}

/// Share enumeration reply returned by the sync share-enum skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEnumReply {
    /// Requested SRVSVC share information level.
    pub level: u32,
    /// Share names discovered by the request.
    pub shares: Vec<String>,
}

/// Kind of blocking operation represented by a sync wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncRequestKind {
    /// `smb2_connect_share` responsibility.
    ConnectShare {
        /// Server name or address.
        server: String,
        /// Share name.
        share: String,
        /// Optional user name.
        user: Option<String>,
    },
    /// `smb2_disconnect_share` responsibility.
    DisconnectShare,
    /// `smb2_opendir` responsibility.
    OpenDir {
        /// Directory path.
        path: String,
    },
    /// `smb2_open` responsibility.
    Open {
        /// File path.
        path: String,
        /// Open flags from the legacy caller.
        flags: i32,
    },
    /// `smb2_close` responsibility.
    Close {
        /// SMB2 file id being closed.
        file_id: [u8; 16],
    },
    /// `smb2_fsync` responsibility.
    Fsync {
        /// SMB2 file id being flushed.
        file_id: [u8; 16],
    },
    /// `smb2_pread` responsibility.
    Pread {
        /// SMB2 file id being read.
        file_id: [u8; 16],
        /// Requested byte count.
        count: usize,
        /// File offset.
        offset: u64,
    },
    /// `smb2_pwrite` responsibility.
    Pwrite {
        /// SMB2 file id being written.
        file_id: [u8; 16],
        /// Requested byte count.
        count: usize,
        /// File offset.
        offset: u64,
    },
    /// `smb2_read` responsibility.
    Read {
        /// SMB2 file id being read.
        file_id: [u8; 16],
        /// Requested byte count.
        count: usize,
    },
    /// `smb2_write` responsibility.
    Write {
        /// SMB2 file id being written.
        file_id: [u8; 16],
        /// Requested byte count.
        count: usize,
    },
    /// Path-only filesystem mutation responsibility.
    PathOperation {
        /// Operation name matching the legacy wrapper.
        operation: PathOperation,
        /// Target path.
        path: String,
    },
    /// `smb2_rename` responsibility.
    Rename {
        /// Existing path.
        oldpath: String,
        /// New path.
        newpath: String,
    },
    /// Path metadata query responsibility.
    Stat {
        /// Target path.
        path: String,
    },
    /// File metadata query responsibility.
    Fstat {
        /// SMB2 file id being queried.
        file_id: [u8; 16],
    },
    /// Filesystem metadata query responsibility.
    StatVfs {
        /// Target path.
        path: String,
    },
    /// Path truncate responsibility.
    Truncate {
        /// Target path.
        path: String,
        /// Requested length.
        length: u64,
    },
    /// File truncate responsibility.
    Ftruncate {
        /// SMB2 file id being truncated.
        file_id: [u8; 16],
        /// Requested length.
        length: u64,
    },
    /// `smb2_readlink` responsibility.
    Readlink {
        /// Link path.
        path: String,
        /// Caller buffer length.
        len: usize,
    },
    /// `smb2_echo` responsibility.
    Echo,
    /// `smb2_notify_change` responsibility.
    NotifyChange {
        /// Watched path.
        path: String,
        /// Watch flags.
        flags: u16,
        /// Completion filter.
        filter: u32,
    },
    /// `smb2_share_enum_sync` responsibility.
    ShareEnum {
        /// Requested SRVSVC share information level.
        level: u32,
    },
}

/// Path-only operation names used by several sync wrappers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathOperation {
    /// `smb2_unlink` responsibility.
    Unlink,
    /// `smb2_rmdir` responsibility.
    Rmdir,
    /// `smb2_mkdir` responsibility.
    Mkdir,
}

/// Description of a synchronous operation queued by this migration skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequest {
    kind: SyncRequestKind,
}

impl SyncRequest {
    /// Creates a request descriptor from an operation kind.
    #[must_use]
    pub const fn new(kind: SyncRequestKind) -> Self {
        Self { kind }
    }

    /// Returns the operation kind represented by this request.
    #[must_use]
    pub const fn kind(&self) -> &SyncRequestKind {
        &self.kind
    }
}

/// Polls callback state once and returns the completed status.
///
/// # Errors
///
/// Returns `ErrorCode(-115)` while the callback is still pending.
pub fn wait_for_reply(cb_data: &SyncCallbackData) -> Result<SyncStatus> {
    if cb_data.is_finished {
        Ok(cb_data.status)
    } else {
        Err(ErrorCode(EINPROGRESS))
    }
}

/// Builds the `smb2_connect_share` synchronous request skeleton.
///
/// # Errors
///
/// Returns an error if the server or share is empty, or if the underlying client
/// placeholder rejects the connection parameters.
pub fn smb2_connect_share(
    client: &mut Smb2Client,
    server: &str,
    share: &str,
    user: Option<&str>,
) -> Result<SyncRequest> {
    validate_path(server)?;
    validate_path(share)?;
    if let Some(user) = user {
        client.set_user(user);
    }
    client.connect_share(server, share)?;
    Ok(SyncRequest::new(SyncRequestKind::ConnectShare {
        server: server.to_owned(),
        share: share.to_owned(),
        user: user.map(str::to_owned),
    }))
}

/// Builds the `smb2_disconnect_share` synchronous request skeleton.
///
/// # Errors
///
/// Returns an error if the underlying client placeholder rejects disconnect.
pub fn smb2_disconnect_share(client: &mut Smb2Client) -> Result<SyncRequest> {
    client.disconnect_share()?;
    Ok(SyncRequest::new(SyncRequestKind::DisconnectShare))
}

/// Builds the `smb2_opendir` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_opendir(client: &Smb2Client, path: &str) -> Result<SyncRequest> {
    touch_client(client);
    validate_path(path)?;
    Ok(SyncRequest::new(SyncRequestKind::OpenDir {
        path: path.to_owned(),
    }))
}

/// Builds the `smb2_open` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_open(client: &Smb2Client, path: &str, flags: i32) -> Result<SyncRequest> {
    touch_client(client);
    validate_path(path)?;
    Ok(SyncRequest::new(SyncRequestKind::Open {
        path: path.to_owned(),
        flags,
    }))
}

/// Builds the `smb2_close` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes.
pub fn smb2_close(client: &Smb2Client, fh: &FileHandle) -> Result<SyncRequest> {
    touch_client(client);
    validate_file_id(fh.id())?;
    Ok(SyncRequest::new(SyncRequestKind::Close {
        file_id: fh.id(),
    }))
}

/// Builds the `smb2_fsync` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes.
pub fn smb2_fsync(client: &Smb2Client, fh: &FileHandle) -> Result<SyncRequest> {
    touch_client(client);
    validate_file_id(fh.id())?;
    Ok(SyncRequest::new(SyncRequestKind::Fsync {
        file_id: fh.id(),
    }))
}

/// Builds the `smb2_pread` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes or `count` exceeds
/// the supplied buffer length.
pub fn smb2_pread(
    client: &Smb2Client,
    fh: &FileHandle,
    buf: &mut [u8],
    count: usize,
    offset: u64,
) -> Result<SyncRequest> {
    touch_client(client);
    validate_file_id(fh.id())?;
    validate_count(count, buf.len())?;
    Ok(SyncRequest::new(SyncRequestKind::Pread {
        file_id: fh.id(),
        count,
        offset,
    }))
}

/// Builds the `smb2_pwrite` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes or `count` exceeds
/// the supplied buffer length.
pub fn smb2_pwrite(
    client: &Smb2Client,
    fh: &FileHandle,
    buf: &[u8],
    count: usize,
    offset: u64,
) -> Result<SyncRequest> {
    touch_client(client);
    validate_file_id(fh.id())?;
    validate_count(count, buf.len())?;
    Ok(SyncRequest::new(SyncRequestKind::Pwrite {
        file_id: fh.id(),
        count,
        offset,
    }))
}

/// Builds the `smb2_read` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes or `count` exceeds
/// the supplied buffer length.
pub fn smb2_read(
    client: &Smb2Client,
    fh: &FileHandle,
    buf: &mut [u8],
    count: usize,
) -> Result<SyncRequest> {
    touch_client(client);
    validate_file_id(fh.id())?;
    validate_count(count, buf.len())?;
    Ok(SyncRequest::new(SyncRequestKind::Read {
        file_id: fh.id(),
        count,
    }))
}

/// Builds the `smb2_write` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes or `count` exceeds
/// the supplied buffer length.
pub fn smb2_write(
    client: &Smb2Client,
    fh: &FileHandle,
    buf: &[u8],
    count: usize,
) -> Result<SyncRequest> {
    touch_client(client);
    validate_file_id(fh.id())?;
    validate_count(count, buf.len())?;
    Ok(SyncRequest::new(SyncRequestKind::Write {
        file_id: fh.id(),
        count,
    }))
}

/// Builds the `smb2_unlink` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_unlink(client: &Smb2Client, path: &str) -> Result<SyncRequest> {
    path_operation(client, PathOperation::Unlink, path)
}

/// Builds the `smb2_rmdir` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_rmdir(client: &Smb2Client, path: &str) -> Result<SyncRequest> {
    path_operation(client, PathOperation::Rmdir, path)
}

/// Builds the `smb2_mkdir` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_mkdir(client: &Smb2Client, path: &str) -> Result<SyncRequest> {
    path_operation(client, PathOperation::Mkdir, path)
}

/// Builds the `smb2_fstat` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes.
pub fn smb2_fstat(client: &Smb2Client, fh: &FileHandle) -> Result<SyncRequest> {
    touch_client(client);
    validate_file_id(fh.id())?;
    Ok(SyncRequest::new(SyncRequestKind::Fstat {
        file_id: fh.id(),
    }))
}

/// Builds the `smb2_stat` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_stat(client: &Smb2Client, path: &str) -> Result<SyncRequest> {
    touch_client(client);
    validate_path(path)?;
    Ok(SyncRequest::new(SyncRequestKind::Stat {
        path: path.to_owned(),
    }))
}

/// Builds the `smb2_rename` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if either path is empty.
pub fn smb2_rename(client: &Smb2Client, oldpath: &str, newpath: &str) -> Result<SyncRequest> {
    touch_client(client);
    validate_path(oldpath)?;
    validate_path(newpath)?;
    Ok(SyncRequest::new(SyncRequestKind::Rename {
        oldpath: oldpath.to_owned(),
        newpath: newpath.to_owned(),
    }))
}

/// Builds the `smb2_statvfs` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_statvfs(client: &Smb2Client, path: &str) -> Result<SyncRequest> {
    touch_client(client);
    validate_path(path)?;
    Ok(SyncRequest::new(SyncRequestKind::StatVfs {
        path: path.to_owned(),
    }))
}

/// Builds the `smb2_truncate` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_truncate(client: &Smb2Client, path: &str, length: u64) -> Result<SyncRequest> {
    touch_client(client);
    validate_path(path)?;
    Ok(SyncRequest::new(SyncRequestKind::Truncate {
        path: path.to_owned(),
        length,
    }))
}

/// Builds the `smb2_ftruncate` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes.
pub fn smb2_ftruncate(client: &Smb2Client, fh: &FileHandle, length: u64) -> Result<SyncRequest> {
    touch_client(client);
    validate_file_id(fh.id())?;
    Ok(SyncRequest::new(SyncRequestKind::Ftruncate {
        file_id: fh.id(),
        length,
    }))
}

/// Builds the `smb2_readlink` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty or `len` is zero.
pub fn smb2_readlink(client: &Smb2Client, path: &str, len: usize) -> Result<SyncRequest> {
    touch_client(client);
    validate_path(path)?;
    if len == 0 {
        return Err(ErrorCode(EINVAL));
    }
    Ok(SyncRequest::new(SyncRequestKind::Readlink {
        path: path.to_owned(),
        len,
    }))
}

/// Builds the `smb2_echo` synchronous request skeleton.
///
/// # Errors
///
/// Returns an error once transport connectivity checks are migrated.
pub fn smb2_echo(client: &Smb2Client) -> Result<SyncRequest> {
    touch_client(client);
    Ok(SyncRequest::new(SyncRequestKind::Echo))
}

/// Builds the `smb2_notify_change` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_notify_change(
    client: &Smb2Client,
    path: &str,
    flags: u16,
    filter: u32,
) -> Result<SyncRequest> {
    touch_client(client);
    validate_path(path)?;
    Ok(SyncRequest::new(SyncRequestKind::NotifyChange {
        path: path.to_owned(),
        flags,
        filter,
    }))
}

/// Builds the `smb2_share_enum_sync` synchronous request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the requested level is outside the basic SRVSVC
/// share-info range represented by this skeleton.
pub fn smb2_share_enum_sync(client: &Smb2Client, level: u32) -> Result<SyncRequest> {
    touch_client(client);
    if level > 503 {
        return Err(ErrorCode(EINVAL));
    }
    Ok(SyncRequest::new(SyncRequestKind::ShareEnum { level }))
}

fn path_operation(
    client: &Smb2Client,
    operation: PathOperation,
    path: &str,
) -> Result<SyncRequest> {
    touch_client(client);
    validate_path(path)?;
    Ok(SyncRequest::new(SyncRequestKind::PathOperation {
        operation,
        path: path.to_owned(),
    }))
}

fn touch_client(client: &Smb2Client) -> Option<usize> {
    client.opaque()
}

fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        Err(ErrorCode(EINVAL))
    } else {
        Ok(())
    }
}

fn validate_file_id(file_id: [u8; 16]) -> Result<()> {
    if file_id == [0; 16] {
        Err(ErrorCode(EINVAL))
    } else {
        Ok(())
    }
}

fn validate_count(count: usize, available: usize) -> Result<()> {
    if count > available {
        Err(ErrorCode(EINVAL))
    } else {
        Ok(())
    }
}
