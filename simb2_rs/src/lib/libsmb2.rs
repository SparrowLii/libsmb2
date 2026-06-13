//! High-level client operation skeletons migrated from `lib/libsmb2.c`.
//!
//! This module mirrors the responsibilities of the legacy C implementation while
//! deliberately avoiding protocol I/O. The types below are placeholders for the
//! future Rust implementation of share connection, handle management, directory
//! iteration, compound file operations, notifications, and server dispatch.

use crate::include::smb2::libsmb2::{
    DirectoryEntry, DirectoryHandle, ErrorCode, FileHandle, Result, Stat, StatVfs,
};

pub use crate::include::smb2::libsmb2::Smb2Client;

/// Size of an SMB2 file id in bytes.
pub const SMB2_FILE_ID_SIZE: usize = 16;

/// Compound placeholder file id used by create/set-info/close chains.
pub const COMPOUND_FILE_ID: [u8; SMB2_FILE_ID_SIZE] = [0xff; SMB2_FILE_ID_SIZE];

/// Default placeholder status for operations that have not reached the server.
pub const SMB2_STATUS_LOCAL_PLACEHOLDER: u32 = 0;

/// Connection state carried through `smb2_connect_share_async` callbacks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectData {
    /// Server name or address.
    pub server: String,
    /// Share name being connected.
    pub share: String,
    /// Optional user name for authentication.
    pub user: Option<String>,
    /// UTF-8 UNC form for the share.
    pub utf8_unc: Option<String>,
    /// UTF-16 UNC form for the share.
    pub utf16_unc: Vec<u16>,
    /// Whether the connection is owned by an embedded server context.
    pub server_context: bool,
}

impl ConnectData {
    /// Creates connection callback state for a server/share pair.
    #[must_use]
    pub fn new(server: impl Into<String>, share: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            share: share.into(),
            ..Self::default()
        }
    }

    /// Returns a best-effort UNC path using the legacy `\\server\share` shape.
    #[must_use]
    pub fn unc(&self) -> String {
        format!("\\\\{}\\{}", self.server, self.share)
    }
}

/// Rust-side model of the private `struct smb2fh` fields used in `libsmb2.c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2FileHandle {
    /// Raw SMB2 file id.
    pub file_id: [u8; SMB2_FILE_ID_SIZE],
    /// Cached sequential file offset.
    pub offset: u64,
    /// Cached end-of-file value when known.
    pub end_of_file: Option<u64>,
}

impl Smb2FileHandle {
    /// Creates a handle skeleton from a raw SMB2 file id.
    #[must_use]
    pub fn new(file_id: [u8; SMB2_FILE_ID_SIZE]) -> Self {
        Self {
            file_id,
            offset: 0,
            end_of_file: None,
        }
    }

    /// Converts this skeleton into the shared safe API handle type.
    #[must_use]
    pub fn into_file_handle(self) -> FileHandle {
        FileHandle::new(self.file_id)
    }

    /// Advances the cached sequential offset after a read or write completion.
    pub fn advance_offset(&mut self, count: u64) {
        self.offset = self.offset.saturating_add(count);
    }
}

/// Directory state backing `smb2_readdir`, `smb2_seekdir`, and friends.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2Directory {
    entries: Vec<DirectoryEntry>,
    index: usize,
}

impl Smb2Directory {
    /// Creates an empty directory cursor.
    #[must_use]
    pub fn new(entries: Vec<DirectoryEntry>) -> Self {
        Self { entries, index: 0 }
    }

    /// Moves the directory cursor to `loc`, clamped to the available entries.
    pub fn seekdir(&mut self, loc: usize) {
        self.index = loc.min(self.entries.len());
    }

    /// Returns the current directory cursor position.
    #[must_use]
    pub fn telldir(&self) -> usize {
        self.index
    }

    /// Resets the directory cursor to the first entry.
    pub fn rewinddir(&mut self) {
        self.index = 0;
    }

    /// Returns the next directory entry and advances the cursor.
    #[must_use]
    pub fn readdir(&mut self) -> Option<&DirectoryEntry> {
        let entry = self.entries.get(self.index);
        if entry.is_some() {
            self.index += 1;
        }
        entry
    }

    /// Returns the number of decoded entries held by this directory cursor.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the cursor has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Open disposition requested by the high-level create/open helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateDisposition {
    /// Open an existing object.
    Open,
    /// Create a new object and fail if it exists.
    Create,
    /// Open an existing object or create it when missing.
    OpenIf,
    /// Replace an existing object.
    Overwrite,
}

/// File object kind used by create/unlink/truncate skeletons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// Regular file object.
    File,
    /// Directory object.
    Directory,
    /// Symbolic link or reparse point.
    ReparsePoint,
}

/// Request shape corresponding to `_smb2_open_async_with_oplock_or_lease`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRequest {
    /// Path relative to the connected share.
    pub path: String,
    /// Legacy open flags passed by callers.
    pub flags: i32,
    /// Requested oplock level.
    pub oplock_level: u8,
    /// Requested lease state.
    pub lease_state: u32,
    /// Optional lease key.
    pub lease_key: Option<[u8; 16]>,
}

impl OpenRequest {
    /// Creates an open request skeleton for `smb2_open_async`.
    #[must_use]
    pub fn new(path: impl Into<String>, flags: i32) -> Self {
        Self {
            path: path.into(),
            flags,
            oplock_level: 0,
            lease_state: 0,
            lease_key: None,
        }
    }
}

/// Request shape used by `smb2_pread_async` and `smb2_read_async`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    /// File handle to read from.
    pub file_id: [u8; SMB2_FILE_ID_SIZE],
    /// Requested byte count.
    pub count: u32,
    /// Absolute file offset.
    pub offset: u64,
}

/// Request shape used by `smb2_pwrite_async` and `smb2_write_async`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRequest {
    /// File handle to write to.
    pub file_id: [u8; SMB2_FILE_ID_SIZE],
    /// Bytes to write.
    pub data: Vec<u8>,
    /// Absolute file offset.
    pub offset: u64,
}

/// Callback state corresponding to `struct read_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadData {
    /// Original read request.
    pub request: ReadRequest,
    /// Number of bytes completed by the placeholder path.
    pub completed: u32,
}

/// Callback state corresponding to `struct write_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteData {
    /// Original write request.
    pub request: WriteRequest,
    /// Number of bytes completed by the placeholder path.
    pub completed: u32,
}

/// Callback state shared by create, mkdir, unlink, and rmdir compound helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCallbackData {
    /// Path being created, opened, or deleted.
    pub path: String,
    /// Kind of object addressed by the request.
    pub kind: ObjectKind,
    /// Create disposition requested by the helper.
    pub disposition: CreateDisposition,
}

/// Query-info state corresponding to `struct stat_cb_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatCallbackData {
    /// Information type requested by the caller.
    pub info_type: u8,
    /// File information class requested by the caller.
    pub file_info_class: u8,
    /// Last NT status observed by the callback chain.
    pub status: u32,
    /// Decoded stat payload, when available.
    pub stat: Option<Stat>,
    /// Decoded filesystem stat payload, when available.
    pub statvfs: Option<StatVfs>,
}

/// Rename compound state corresponding to `struct rename_cb_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameCallbackData {
    /// Source path opened by the CREATE leg.
    pub old_path: String,
    /// Destination path passed to SET_INFO using SMB backslash separators.
    pub new_path: String,
    /// Last NT status observed by the compound chain.
    pub status: u32,
}

impl RenameCallbackData {
    /// Creates rename state and normalizes `/` to `\\` for the target path.
    #[must_use]
    pub fn new(old_path: impl Into<String>, new_path: impl Into<String>) -> Self {
        Self {
            old_path: old_path.into(),
            new_path: new_path.into().replace('/', "\\"),
            status: SMB2_STATUS_LOCAL_PLACEHOLDER,
        }
    }
}

/// Readlink compound state corresponding to `struct readlink_cb_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadlinkCallbackData {
    /// Path being opened and queried.
    pub path: String,
    /// Last NT status observed by the compound chain.
    pub status: u32,
    /// Reparse target decoded from the IOCTL leg, when available.
    pub target: Option<String>,
}

/// Disconnect state corresponding to `struct disconnect_data`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DisconnectData {
    /// Whether tree disconnect has been queued.
    pub tree_disconnect_queued: bool,
    /// Whether logoff has been queued.
    pub logoff_queued: bool,
}

/// Echo state corresponding to `struct smb2_echo_data`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EchoData {
    /// Last NT status returned by echo completion.
    pub status: u32,
}

/// File notification entry decoded from CHANGE_NOTIFY output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileNotifyChangeInformation {
    /// Action code reported by the server.
    pub action: u32,
    /// File name affected by the action.
    pub name: String,
}

/// Callback state corresponding to `struct notify_change_cb_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyChangeCallbackData {
    /// Directory handle being watched.
    pub directory_file_id: [u8; SMB2_FILE_ID_SIZE],
    /// Completion filter flags.
    pub filter: u32,
    /// CHANGE_NOTIFY flags such as watch-tree.
    pub flags: u16,
    /// Whether the notification should be re-armed after completion.
    pub repeat: bool,
    /// Decoded changes from the current completion.
    pub changes: Vec<FileNotifyChangeInformation>,
}

/// Oplock or lease break response selected by the notification handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OplockBreakResponse {
    /// No response PDU is needed.
    None,
    /// Reply with a new oplock level.
    Oplock {
        file_id: [u8; SMB2_FILE_ID_SIZE],
        level: u8,
    },
    /// Reply with a new lease state.
    Lease {
        lease_key: [u8; 16],
        state: u32,
        flags: u32,
    },
}

/// Server-side request kind dispatched by the callback table in `libsmb2.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRequestKind {
    /// LOGOFF request.
    Logoff,
    /// TREE_CONNECT request.
    TreeConnect,
    /// TREE_DISCONNECT request.
    TreeDisconnect,
    /// CREATE request.
    Create,
    /// CLOSE request.
    Close,
    /// FLUSH request.
    Flush,
    /// READ request.
    Read,
    /// WRITE request.
    Write,
    /// OPLOCK_BREAK request.
    OplockBreak,
    /// LOCK request.
    Lock,
    /// IOCTL request.
    Ioctl,
    /// CANCEL request.
    Cancel,
    /// ECHO request.
    Echo,
    /// QUERY_DIRECTORY request.
    QueryDirectory,
    /// CHANGE_NOTIFY request.
    ChangeNotify,
    /// QUERY_INFO request.
    QueryInfo,
    /// SET_INFO request.
    SetInfo,
    /// SESSION_SETUP request.
    SessionSetup,
    /// NEGOTIATE request.
    Negotiate,
}

/// Server-side dispatch record for the callback skeletons near the end of `libsmb2.c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerRequest {
    /// Request kind being dispatched.
    pub kind: ServerRequestKind,
    /// Message id associated with the request when known.
    pub message_id: Option<u64>,
}

impl Smb2Client {
    /// Records the shape of `smb2_close_context` without closing a socket.
    pub fn close_context_skeleton(&mut self) -> DisconnectData {
        let _ = self;
        DisconnectData::default()
    }

    /// Builds connection state for the future `smb2_connect_share_async` flow.
    pub fn connect_share_async_skeleton(
        &mut self,
        server: &str,
        share: &str,
        user: Option<&str>,
    ) -> Result<ConnectData> {
        self.connect_share(server, share)?;
        let mut data = ConnectData::new(server, share);
        data.user = user.map(str::to_owned);
        data.utf8_unc = Some(data.unc());
        data.utf16_unc = data.unc().encode_utf16().collect();
        Ok(data)
    }

    /// Builds an open request skeleton matching `smb2_open_async`.
    pub fn open_async_skeleton(&mut self, path: &str, flags: i32) -> Result<OpenRequest> {
        validate_path(path)?;
        let _ = self;
        Ok(OpenRequest::new(path, flags))
    }

    /// Builds a close request skeleton matching `smb2_close_async`.
    pub fn close_async_skeleton(&mut self, handle: &FileHandle) -> Result<[u8; SMB2_FILE_ID_SIZE]> {
        let _ = self;
        Ok(handle.id())
    }

    /// Builds a flush request skeleton matching `smb2_fsync_async`.
    pub fn fsync_async_skeleton(&mut self, handle: &FileHandle) -> Result<[u8; SMB2_FILE_ID_SIZE]> {
        let _ = self;
        Ok(handle.id())
    }

    /// Builds read callback state matching `smb2_pread_async`.
    pub fn pread_async_skeleton(
        &mut self,
        handle: &FileHandle,
        count: u32,
        offset: u64,
    ) -> Result<ReadData> {
        let _ = self;
        Ok(ReadData {
            request: ReadRequest {
                file_id: handle.id(),
                count,
                offset,
            },
            completed: 0,
        })
    }

    /// Builds read callback state matching `smb2_read_async`.
    pub fn read_async_skeleton(&mut self, handle: &FileHandle, count: u32) -> Result<ReadData> {
        self.pread_async_skeleton(handle, count, handle.offset())
    }

    /// Builds write callback state matching `smb2_pwrite_async`.
    pub fn pwrite_async_skeleton(
        &mut self,
        handle: &FileHandle,
        data: &[u8],
        offset: u64,
    ) -> Result<WriteData> {
        let _ = self;
        Ok(WriteData {
            request: WriteRequest {
                file_id: handle.id(),
                data: data.to_vec(),
                offset,
            },
            completed: 0,
        })
    }

    /// Builds write callback state matching `smb2_write_async`.
    pub fn write_async_skeleton(&mut self, handle: &FileHandle, data: &[u8]) -> Result<WriteData> {
        self.pwrite_async_skeleton(handle, data, handle.offset())
    }

    /// Builds a directory cursor skeleton matching `smb2_opendir_async`.
    pub fn opendir_async_skeleton(
        &mut self,
        path: &str,
        entries: Vec<DirectoryEntry>,
    ) -> Result<Smb2Directory> {
        validate_path(path)?;
        let _ = self;
        Ok(Smb2Directory::new(entries))
    }

    /// Builds a directory handle skeleton from a known SMB2 file id.
    #[must_use]
    pub fn directory_handle_from_file_id(
        &self,
        file_id: [u8; SMB2_FILE_ID_SIZE],
    ) -> DirectoryHandle {
        let _ = self;
        DirectoryHandle::new(file_id)
    }

    /// Builds create callback state matching `smb2_mkdir_async`.
    pub fn mkdir_async_skeleton(&mut self, path: &str) -> Result<CreateCallbackData> {
        validate_path(path)?;
        let _ = self;
        Ok(CreateCallbackData {
            path: path.to_owned(),
            kind: ObjectKind::Directory,
            disposition: CreateDisposition::Create,
        })
    }

    /// Builds create callback state matching `smb2_unlink_async`.
    pub fn unlink_async_skeleton(&mut self, path: &str) -> Result<CreateCallbackData> {
        self.unlink_internal_skeleton(path, ObjectKind::File)
    }

    /// Builds create callback state matching `smb2_rmdir_async`.
    pub fn rmdir_async_skeleton(&mut self, path: &str) -> Result<CreateCallbackData> {
        self.unlink_internal_skeleton(path, ObjectKind::Directory)
    }

    /// Builds stat callback state matching `smb2_fstat_async`.
    pub fn fstat_async_skeleton(&mut self, handle: &FileHandle) -> Result<StatCallbackData> {
        let _ = self;
        let _ = handle.id();
        Ok(StatCallbackData {
            info_type: 1,
            file_info_class: 18,
            status: SMB2_STATUS_LOCAL_PLACEHOLDER,
            stat: None,
            statvfs: None,
        })
    }

    /// Builds stat callback state matching `smb2_stat_async`.
    pub fn stat_async_skeleton(&mut self, path: &str) -> Result<StatCallbackData> {
        validate_path(path)?;
        self.fstat_async_skeleton(&FileHandle::new(COMPOUND_FILE_ID))
    }

    /// Builds statvfs callback state matching `smb2_statvfs_async`.
    pub fn statvfs_async_skeleton(&mut self, path: &str) -> Result<StatCallbackData> {
        validate_path(path)?;
        let _ = self;
        Ok(StatCallbackData {
            info_type: 2,
            file_info_class: 0,
            status: SMB2_STATUS_LOCAL_PLACEHOLDER,
            stat: None,
            statvfs: None,
        })
    }

    /// Builds truncate callback state matching `smb2_truncate_async`.
    pub fn truncate_async_skeleton(
        &mut self,
        path: &str,
        length: u64,
    ) -> Result<CreateCallbackData> {
        validate_path(path)?;
        let _ = self;
        let _ = length;
        Ok(CreateCallbackData {
            path: path.to_owned(),
            kind: ObjectKind::File,
            disposition: CreateDisposition::Open,
        })
    }

    /// Builds rename callback state matching `smb2_rename_async`.
    pub fn rename_async_skeleton(
        &mut self,
        old_path: &str,
        new_path: &str,
    ) -> Result<RenameCallbackData> {
        validate_path(old_path)?;
        validate_path(new_path)?;
        let _ = self;
        Ok(RenameCallbackData::new(old_path, new_path))
    }

    /// Builds ftruncate callback state matching `smb2_ftruncate_async`.
    pub fn ftruncate_async_skeleton(
        &mut self,
        handle: &FileHandle,
        length: u64,
    ) -> Result<CreateCallbackData> {
        let _ = self;
        let _ = length;
        Ok(CreateCallbackData {
            path: format!("file-id:{:02x?}", handle.id()),
            kind: ObjectKind::File,
            disposition: CreateDisposition::Open,
        })
    }

    /// Builds readlink callback state matching `smb2_readlink_async`.
    pub fn readlink_async_skeleton(&mut self, path: &str) -> Result<ReadlinkCallbackData> {
        validate_path(path)?;
        let _ = self;
        Ok(ReadlinkCallbackData {
            path: path.to_owned(),
            status: SMB2_STATUS_LOCAL_PLACEHOLDER,
            target: None,
        })
    }

    /// Builds disconnect state matching `smb2_disconnect_share_async`.
    pub fn disconnect_share_async_skeleton(&mut self) -> Result<DisconnectData> {
        self.disconnect_share()?;
        Ok(DisconnectData {
            tree_disconnect_queued: true,
            logoff_queued: true,
        })
    }

    /// Builds echo state matching `smb2_echo_async`.
    pub fn echo_async_skeleton(&mut self) -> Result<EchoData> {
        let _ = self;
        Ok(EchoData::default())
    }

    /// Returns the current placeholder maximum read size.
    #[must_use]
    pub fn max_read_size_skeleton(&self) -> u32 {
        0
    }

    /// Returns the current placeholder maximum write size.
    #[must_use]
    pub fn max_write_size_skeleton(&self) -> u32 {
        0
    }

    /// Builds a file handle skeleton matching `smb2_fh_from_file_id`.
    #[must_use]
    pub fn file_handle_from_file_id(&self, file_id: [u8; SMB2_FILE_ID_SIZE]) -> FileHandle {
        let _ = self;
        FileHandle::new(file_id)
    }

    /// Builds notification callback state matching `smb2_notify_change_async`.
    pub fn notify_change_async_skeleton(
        &mut self,
        directory: &DirectoryHandle,
        flags: u16,
        filter: u32,
        repeat: bool,
    ) -> Result<NotifyChangeCallbackData> {
        let _ = self;
        Ok(NotifyChangeCallbackData {
            directory_file_id: directory.id(),
            filter,
            flags,
            repeat,
            changes: Vec::new(),
        })
    }

    /// Records the selected oplock/lease response without queuing a PDU.
    pub fn oplock_break_notify_skeleton(
        &mut self,
        response: OplockBreakResponse,
    ) -> Result<OplockBreakResponse> {
        let _ = self;
        Ok(response)
    }

    /// Builds a server request dispatch record for the callback table skeleton.
    #[must_use]
    pub fn server_request_skeleton(
        &self,
        kind: ServerRequestKind,
        message_id: Option<u64>,
    ) -> ServerRequest {
        ServerRequest { kind, message_id }
    }

    fn unlink_internal_skeleton(
        &mut self,
        path: &str,
        kind: ObjectKind,
    ) -> Result<CreateCallbackData> {
        validate_path(path)?;
        let _ = self;
        Ok(CreateCallbackData {
            path: path.to_owned(),
            kind,
            disposition: CreateDisposition::Open,
        })
    }
}

fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(ErrorCode(-22));
    }
    Ok(())
}
