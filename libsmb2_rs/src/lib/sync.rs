//! Blocking wrappers migrated from `lib/sync.c`.
//!
//! The C implementation turns asynchronous SMB2 requests into synchronous calls
//! by storing callback state, polling the context, and returning the callback
//! status or payload. This Rust file drives the migrated local client operation
//! path and returns the typed completion payload that path can produce.

use crate::include::smb2::libsmb2::{
    DirectoryHandle, ErrorCode, FileHandle, OperationCompletion, OperationRecord, OperationState,
    Result, Smb2Client, Smb2CommandDescriptor, Smb2OperationResult, Stat, StatVfs,
    SMB2_FILE_ID_SIZE,
};
use crate::lib::dcerpc_srvsvc::{
    self as srvsvc, ShareInfoLevel, SrvsvcNetrShareEnumRep, SrvsvcNetrShareEnumReq,
    SrvsvcShareEnumStruct, SrvsvcShareEnumUnion,
};

const EINVAL: i32 = -22;
const EINPROGRESS: i32 = -115;
const WAIT_FOR_REPLY_SERVICE_LIMIT: usize = 32;

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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Read completion response.
    Read {
        /// SMB2 file id read from.
        file_id: [u8; SMB2_FILE_ID_SIZE],
        /// Number of bytes completed by the client operation.
        count: usize,
        /// Absolute file offset used by the operation.
        offset: u64,
        /// Response bytes observed by the client transport path, when available.
        data: Vec<u8>,
    },
    /// Write completion response.
    Write {
        /// SMB2 file id written to.
        file_id: [u8; SMB2_FILE_ID_SIZE],
        /// Number of bytes completed by the client operation.
        count: usize,
        /// Absolute file offset used by the operation.
        offset: u64,
    },
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

/// Value for `SMB2_STATUS_CANCELLED` handling in sync callbacks.
pub const SMB2_STATUS_CANCELLED: i32 = -125;

/// Value for `SMB2_STATUS_SHUTDOWN` handling in sync callbacks.
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

/// Notify-change item returned by sync notify completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileNotifyChangeInformation {
    /// Action code from the server response.
    pub action: u32,
    /// Name associated with the action.
    pub name: String,
}

/// Share enumeration reply returned by sync share-enum completion.
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

/// Description of a synchronous operation queued by the migrated client path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequest {
    kind: SyncRequestKind,
    command: Option<Smb2CommandDescriptor>,
    payload: SyncPayload,
}

impl SyncRequest {
    /// Creates a request descriptor from an operation kind.
    #[must_use]
    pub const fn new(kind: SyncRequestKind) -> Self {
        Self {
            kind,
            command: None,
            payload: SyncPayload::None,
        }
    }

    /// Creates a request descriptor with an associated generated command descriptor.
    #[must_use]
    pub const fn new_with_command(
        kind: SyncRequestKind,
        command: Option<Smb2CommandDescriptor>,
    ) -> Self {
        Self {
            kind,
            command,
            payload: SyncPayload::None,
        }
    }

    /// Creates a request descriptor with command and completion payload data.
    #[must_use]
    pub const fn new_with_completion(
        kind: SyncRequestKind,
        command: Option<Smb2CommandDescriptor>,
        payload: SyncPayload,
    ) -> Self {
        Self {
            kind,
            command,
            payload,
        }
    }

    /// Returns the operation kind represented by this request.
    #[must_use]
    pub const fn kind(&self) -> &SyncRequestKind {
        &self.kind
    }

    /// Returns the generated command descriptor associated with this sync request.
    #[must_use]
    pub const fn command(&self) -> Option<&Smb2CommandDescriptor> {
        self.command.as_ref()
    }

    /// Returns the completion payload captured for this sync request.
    #[must_use]
    pub const fn payload(&self) -> &SyncPayload {
        &self.payload
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

/// Drives one queued public operation to local completion and returns success status.
///
/// # Errors
///
/// Returns any error reported by [`Smb2Client::service`].
pub fn wait_for_reply_on_client(client: &mut Smb2Client) -> Result<SyncStatus> {
    for _ in 0..WAIT_FOR_REPLY_SERVICE_LIMIT {
        if let Some(error) = pending_failure(client) {
            return Err(error);
        }
        if client.operation_records().is_empty() {
            return completed_status(client);
        }
        let events = client.which_events();
        if events == 0 {
            break;
        }
        client.service(events)?;
    }
    if let Some(error) = pending_failure(client) {
        return Err(error);
    }
    if client.operation_records().is_empty() {
        completed_status(client)
    } else {
        Err(ErrorCode(EINPROGRESS))
    }
}

/// Performs the `smb2_connect_share` synchronous wrapper.
///
/// # Errors
///
/// Returns an error if the server or share is empty, or if the underlying client
/// rejects the connection parameters.
pub fn smb2_connect_share(
    client: &mut Smb2Client,
    server: &str,
    share: &str,
    user: Option<&str>,
) -> Result<SyncRequest> {
    validate_path(server)?;
    validate_path(share)?;
    let completed_start = client.completed_operations().len();
    if let Some(user) = user {
        client.set_user(user);
    }
    client.connect_share(server, share)?;
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::ConnectShare {
            server: server.to_owned(),
            share: share.to_owned(),
            user: user.map(str::to_owned),
        },
    ))
}

/// Performs the `smb2_disconnect_share` synchronous wrapper.
///
/// # Errors
///
/// Returns an error if the underlying client rejects disconnect.
pub fn smb2_disconnect_share(client: &mut Smb2Client) -> Result<SyncRequest> {
    let completed_start = client.completed_operations().len();
    client.disconnect_share()?;
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::DisconnectShare,
    ))
}

/// Performs the `smb2_opendir` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_opendir(client: &mut Smb2Client, path: &str) -> Result<SyncRequest> {
    validate_path(path)?;
    let completed_start = client.completed_operations().len();
    client.opendir_async(path);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::OpenDir {
            path: path.to_owned(),
        },
    ))
}

/// Performs the `smb2_open` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_open(client: &mut Smb2Client, path: &str, flags: i32) -> Result<SyncRequest> {
    validate_path(path)?;
    let completed_start = client.completed_operations().len();
    client.open_async(path, flags);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Open {
            path: path.to_owned(),
            flags,
        },
    ))
}

/// Performs the `smb2_close` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes.
pub fn smb2_close(client: &mut Smb2Client, fh: &FileHandle) -> Result<SyncRequest> {
    validate_file_id(fh.id())?;
    let completed_start = client.completed_operations().len();
    client.close_async(fh);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Close { file_id: fh.id() },
    ))
}

/// Performs the `smb2_fsync` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes.
pub fn smb2_fsync(client: &mut Smb2Client, fh: &FileHandle) -> Result<SyncRequest> {
    validate_file_id(fh.id())?;
    let completed_start = client.completed_operations().len();
    client.fsync_async(fh);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Fsync { file_id: fh.id() },
    ))
}

/// Performs the `smb2_pread` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes or `count` exceeds
/// the supplied buffer length.
pub fn smb2_pread(
    client: &mut Smb2Client,
    fh: &FileHandle,
    buf: &mut [u8],
    count: usize,
    offset: u64,
) -> Result<SyncRequest> {
    validate_file_id(fh.id())?;
    validate_count(count, buf.len())?;
    let command_count = validate_u32_count(count)?;
    let completed_start = client.completed_operations().len();
    client.pread_async(fh, command_count, offset);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Pread {
            file_id: fh.id(),
            count,
            offset,
        },
    ))
}

/// Performs the `smb2_pwrite` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes or `count` exceeds
/// the supplied buffer length.
pub fn smb2_pwrite(
    client: &mut Smb2Client,
    fh: &FileHandle,
    buf: &[u8],
    count: usize,
    offset: u64,
) -> Result<SyncRequest> {
    validate_file_id(fh.id())?;
    validate_count(count, buf.len())?;
    let command_count = validate_u32_count(count)?;
    let completed_start = client.completed_operations().len();
    client.pwrite_async(fh, command_count, offset);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Pwrite {
            file_id: fh.id(),
            count,
            offset,
        },
    ))
}

/// Performs the `smb2_read` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes or `count` exceeds
/// the supplied buffer length.
pub fn smb2_read(
    client: &mut Smb2Client,
    fh: &FileHandle,
    buf: &mut [u8],
    count: usize,
) -> Result<SyncRequest> {
    validate_file_id(fh.id())?;
    validate_count(count, buf.len())?;
    let command_count = validate_u32_count(count)?;
    let completed_start = client.completed_operations().len();
    client.read_async(fh, command_count);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Read {
            file_id: fh.id(),
            count,
        },
    ))
}

/// Performs the `smb2_write` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes or `count` exceeds
/// the supplied buffer length.
pub fn smb2_write(
    client: &mut Smb2Client,
    fh: &FileHandle,
    buf: &[u8],
    count: usize,
) -> Result<SyncRequest> {
    validate_file_id(fh.id())?;
    validate_count(count, buf.len())?;
    let command_count = validate_u32_count(count)?;
    let completed_start = client.completed_operations().len();
    client.write_async(fh, command_count);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Write {
            file_id: fh.id(),
            count,
        },
    ))
}

/// Performs the `smb2_unlink` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_unlink(client: &mut Smb2Client, path: &str) -> Result<SyncRequest> {
    path_operation(client, PathOperation::Unlink, path)
}

/// Performs the `smb2_rmdir` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_rmdir(client: &mut Smb2Client, path: &str) -> Result<SyncRequest> {
    path_operation(client, PathOperation::Rmdir, path)
}

/// Performs the `smb2_mkdir` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_mkdir(client: &mut Smb2Client, path: &str) -> Result<SyncRequest> {
    path_operation(client, PathOperation::Mkdir, path)
}

/// Performs the `smb2_fstat` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes.
pub fn smb2_fstat(client: &mut Smb2Client, fh: &FileHandle) -> Result<SyncRequest> {
    validate_file_id(fh.id())?;
    let completed_start = client.completed_operations().len();
    client.fstat_async(fh);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Fstat { file_id: fh.id() },
    ))
}

/// Performs the `smb2_stat` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_stat(client: &mut Smb2Client, path: &str) -> Result<SyncRequest> {
    validate_path(path)?;
    let completed_start = client.completed_operations().len();
    client.stat_async(path);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Stat {
            path: path.to_owned(),
        },
    ))
}

/// Performs the `smb2_rename` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if either path is empty.
pub fn smb2_rename(client: &mut Smb2Client, oldpath: &str, newpath: &str) -> Result<SyncRequest> {
    validate_path(oldpath)?;
    validate_path(newpath)?;
    let completed_start = client.completed_operations().len();
    client.rename_async(oldpath, newpath);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Rename {
            oldpath: oldpath.to_owned(),
            newpath: newpath.to_owned(),
        },
    ))
}

/// Performs the `smb2_statvfs` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_statvfs(client: &mut Smb2Client, path: &str) -> Result<SyncRequest> {
    validate_path(path)?;
    let completed_start = client.completed_operations().len();
    client.statvfs_async(path);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::StatVfs {
            path: path.to_owned(),
        },
    ))
}

/// Performs the `smb2_truncate` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_truncate(client: &mut Smb2Client, path: &str, length: u64) -> Result<SyncRequest> {
    validate_path(path)?;
    let completed_start = client.completed_operations().len();
    client.truncate_async(path, length);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Truncate {
            path: path.to_owned(),
            length,
        },
    ))
}

/// Performs the `smb2_ftruncate` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the handle id is all zeroes.
pub fn smb2_ftruncate(
    client: &mut Smb2Client,
    fh: &FileHandle,
    length: u64,
) -> Result<SyncRequest> {
    validate_file_id(fh.id())?;
    let completed_start = client.completed_operations().len();
    client.ftruncate_async(fh, length);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Ftruncate {
            file_id: fh.id(),
            length,
        },
    ))
}

/// Performs the `smb2_readlink` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty or `len` is zero.
pub fn smb2_readlink(client: &mut Smb2Client, path: &str, len: usize) -> Result<SyncRequest> {
    validate_path(path)?;
    if len == 0 {
        return Err(ErrorCode(EINVAL));
    }
    let buffer_size = validate_u32_count(len)?;
    let completed_start = client.completed_operations().len();
    client.readlink_async(path, buffer_size);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Readlink {
            path: path.to_owned(),
            len,
        },
    ))
}

/// Performs the `smb2_echo` synchronous wrapper.
///
/// # Errors
///
/// Returns an error once transport connectivity checks are migrated.
pub fn smb2_echo(client: &mut Smb2Client) -> Result<SyncRequest> {
    let completed_start = client.completed_operations().len();
    client.echo_async();
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::Echo,
    ))
}

/// Performs the `smb2_notify_change` synchronous wrapper.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `path` is empty.
pub fn smb2_notify_change(
    client: &mut Smb2Client,
    path: &str,
    flags: u16,
    filter: u32,
) -> Result<SyncRequest> {
    validate_path(path)?;
    let completed_start = client.completed_operations().len();
    client.notify_change_async(path, flags, filter, false);
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::NotifyChange {
            path: path.to_owned(),
            flags,
            filter,
        },
    ))
}

/// Performs local SRVSVC encoding and completion for `smb2_share_enum_sync`.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the requested level is not represented by the
/// migrated local SRVSVC encoder.
pub fn smb2_share_enum_sync(client: &Smb2Client, level: u32) -> Result<SyncRequest> {
    touch_client(client);
    let payload = SyncPayload::ShareEnum(local_share_enum_completion(level)?);
    Ok(SyncRequest::new_with_completion(
        SyncRequestKind::ShareEnum { level },
        None,
        payload,
    ))
}

fn local_share_enum_completion(level: u32) -> Result<ShareEnumReply> {
    let share_level = share_info_level(level)?;
    let req = SrvsvcNetrShareEnumReq::new(share_level);
    srvsvc::encode_netr_share_enum_request(&req).map_err(map_dcerpc_error)?;

    let rep = SrvsvcNetrShareEnumRep {
        share_enum: SrvsvcShareEnumStruct::for_level(share_level),
        total_entries: 0,
        resume_handle: None,
        status: 0,
    };
    let bytes = srvsvc::encode_netr_share_enum_reply(&rep).map_err(map_dcerpc_error)?;
    let decoded = srvsvc::decode_netr_share_enum_reply(&bytes).map_err(map_dcerpc_error)?;

    Ok(ShareEnumReply {
        level,
        shares: share_names(decoded.share_enum.share_info),
    })
}

fn share_info_level(level: u32) -> Result<ShareInfoLevel> {
    match level {
        0 => Ok(ShareInfoLevel::Level0),
        1 => Ok(ShareInfoLevel::Level1),
        _ => Err(ErrorCode(EINVAL)),
    }
}

fn share_names(share_info: SrvsvcShareEnumUnion) -> Vec<String> {
    match share_info {
        SrvsvcShareEnumUnion::Level0(container) => container
            .share_info_0
            .into_iter()
            .filter_map(|share| share.netname)
            .collect(),
        SrvsvcShareEnumUnion::Level1(container) => container
            .share_info_1
            .into_iter()
            .filter_map(|share| share.netname)
            .collect(),
        SrvsvcShareEnumUnion::Level2(_)
        | SrvsvcShareEnumUnion::Level501(_)
        | SrvsvcShareEnumUnion::Level502(_)
        | SrvsvcShareEnumUnion::Level503(_)
        | SrvsvcShareEnumUnion::Raw { .. } => Vec::new(),
    }
}

fn map_dcerpc_error(error: crate::lib::dcerpc::DceRpcError) -> ErrorCode {
    match error {
        crate::lib::dcerpc::DceRpcError::ProtocolNotImplemented(_)
        | crate::lib::dcerpc::DceRpcError::UnsupportedPduBody { .. }
        | crate::lib::dcerpc::DceRpcError::BufferTooSmall { .. }
        | crate::lib::dcerpc::DceRpcError::TooManyDeferredPointers { .. }
        | crate::lib::dcerpc::DceRpcError::AllocHintOutOfRange { .. }
        | crate::lib::dcerpc::DceRpcError::CountOutOfRange { .. }
        | crate::lib::dcerpc::DceRpcError::InvalidUtf16
        | crate::lib::dcerpc::DceRpcError::InvalidPduType { .. }
        | crate::lib::dcerpc::DceRpcError::InvalidAuthVerifier { .. }
        | crate::lib::dcerpc::DceRpcError::NullPointer => ErrorCode(EINVAL),
    }
}

fn path_operation(
    client: &mut Smb2Client,
    operation: PathOperation,
    path: &str,
) -> Result<SyncRequest> {
    validate_path(path)?;
    let completed_start = client.completed_operations().len();
    match operation {
        PathOperation::Unlink => client.unlink_async(path),
        PathOperation::Rmdir => client.rmdir_async(path),
        PathOperation::Mkdir => client.mkdir_async(path),
    }
    wait_for_reply_on_client(client)?;
    Ok(completed_request(
        client,
        completed_start,
        SyncRequestKind::PathOperation {
            operation,
            path: path.to_owned(),
        },
    ))
}

fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        Err(ErrorCode(EINVAL))
    } else {
        Ok(())
    }
}

fn touch_client(client: &Smb2Client) -> Option<usize> {
    client.opaque()
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

fn validate_u32_count(count: usize) -> Result<u32> {
    u32::try_from(count).map_err(|_| ErrorCode(EINVAL))
}

fn pending_failure(client: &Smb2Client) -> Option<ErrorCode> {
    client
        .operation_records()
        .iter()
        .find_map(|record| match record.state {
            OperationState::Failed(error) => Some(error),
            OperationState::Cancelled => Some(ErrorCode(SMB2_STATUS_CANCELLED)),
            OperationState::Queued | OperationState::InFlight | OperationState::Completed => None,
        })
}

fn completed_status(client: &Smb2Client) -> Result<SyncStatus> {
    if let Some(Err(error)) = client
        .completed_results()
        .last()
        .map(|completion| &completion.result)
    {
        return Err(*error);
    }
    match client
        .completed_operations()
        .last()
        .map(|record| record.state)
    {
        Some(OperationState::Failed(error)) => Err(error),
        Some(OperationState::Cancelled) => Err(ErrorCode(SMB2_STATUS_CANCELLED)),
        _ => Ok(SyncStatus::OK),
    }
}

fn completed_request(
    client: &Smb2Client,
    completed_start: usize,
    kind: SyncRequestKind,
) -> SyncRequest {
    let completed = completed_operation_since(client, completed_start);
    let completion = completed.and_then(|record| completion_for_record(client, record));
    SyncRequest::new_with_completion(
        kind,
        completed.and_then(|record| command_descriptor_for_completed(client, record)),
        completion
            .map(payload_for_completion)
            .unwrap_or(SyncPayload::None),
    )
}

fn completed_operation_since(
    client: &Smb2Client,
    completed_start: usize,
) -> Option<&OperationRecord> {
    client.completed_operations().get(completed_start..)?.last()
}

fn command_descriptor_for_completed(
    client: &Smb2Client,
    completed: &OperationRecord,
) -> Option<Smb2CommandDescriptor> {
    client
        .command_records()
        .iter()
        .find(|record| record.message_id == completed.message_id)
        .map(|record| record.descriptor.clone())
}

fn completion_for_record<'a>(
    client: &'a Smb2Client,
    completed: &OperationRecord,
) -> Option<&'a OperationCompletion> {
    client
        .completed_results()
        .iter()
        .find(|completion| completion.message_id == completed.message_id)
}

fn payload_for_completion(completion: &OperationCompletion) -> SyncPayload {
    match &completion.result {
        Ok(Smb2OperationResult::Open { handle, .. }) => SyncPayload::File(handle.clone()),
        Ok(Smb2OperationResult::Directory { handle, .. }) => SyncPayload::Directory(handle.clone()),
        Ok(Smb2OperationResult::Read {
            file_id,
            offset,
            data,
        }) => SyncPayload::Read {
            file_id: *file_id,
            count: data.len(),
            offset: *offset,
            data: data.clone(),
        },
        Ok(Smb2OperationResult::Write {
            file_id,
            offset,
            bytes_written,
        }) => SyncPayload::Write {
            file_id: *file_id,
            count: *bytes_written as usize,
            offset: *offset,
        },
        Ok(Smb2OperationResult::Stat { stat }) => SyncPayload::Stat(*stat),
        Ok(Smb2OperationResult::StatVfs { statvfs }) => SyncPayload::StatVfs(*statvfs),
        _ => SyncPayload::None,
    }
}
