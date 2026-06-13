//! Dreamcast VFS adapter skeleton migrated from `lib/dreamcast/vfs.c`.
//!
//! The C source registers a KallistiOS VFS handler at `/smb`, owns one global
//! SMB2 context/URL pair, serializes VFS callbacks behind a mutex, and forwards
//! file, directory, metadata, and lifecycle operations into libsmb2. This Rust
//! module keeps that shape visible as typed data structures and request-building
//! methods without implementing KallistiOS registration or SMB2 protocol I/O.

use crate::include::smb2::libsmb2::{
    DirectoryEntry, DirectoryHandle, ErrorCode, FileHandle, FileType, Result, Smb2Client, Smb2Url,
    Stat,
};
use crate::legacy_lib::sync::{self, SyncPayload, SyncRequest};

const EINVAL: i32 = -22;
const EIO: i32 = -5;
const ENOENT: i32 = -2;
const ENOSYS: i32 = -38;

/// Mount point used by the legacy Dreamcast VFS handler.
pub const SMB_VFS_MOUNT: &str = "/smb";

/// Version value assigned to the KallistiOS `nmmgr` handler in the C source.
pub const SMB_VFS_VERSION: u32 = 0x0001_0000;

/// Maximum filename bytes copied into a Dreamcast directory entry.
pub const DREAMCAST_NAME_MAX: usize = 256;

/// Open-mode bit used by KallistiOS callers to request a directory handle.
pub const O_DIR: i32 = 0x4000;

/// File type stored in a Dreamcast VFS descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbFdKind {
    /// Descriptor wraps a regular SMB2 file handle.
    File,
    /// Descriptor wraps an SMB2 directory handle and cached directory entry.
    Directory,
}

/// Opaque identifier for a Dreamcast VFS descriptor tracked by the Rust model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamcastHandleId(pub usize);

/// Lifecycle state for a VFS descriptor shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbFdState {
    /// Request metadata exists but no platform handle has been installed.
    Pending,
    /// Descriptor owns a file or directory handle placeholder.
    Open,
    /// Descriptor has been closed by the neutral skeleton.
    Closed,
}

impl SmbFdKind {
    /// Converts legacy open flags into the descriptor kind used by `smb_open`.
    #[must_use]
    pub const fn from_open_mode(mode: i32) -> Self {
        if mode & O_DIR != 0 {
            Self::Directory
        } else {
            Self::File
        }
    }

    /// Returns whether this descriptor represents a directory.
    #[must_use]
    pub const fn is_dir(self) -> bool {
        matches!(self, Self::Directory)
    }
}

/// Handle storage corresponding to `struct smb_fd` in the C VFS adapter.
#[derive(Debug)]
pub struct SmbFd {
    handle_id: Option<DreamcastHandleId>,
    kind: SmbFdKind,
    state: SmbFdState,
    file: Option<FileHandle>,
    directory: Option<DirectoryHandle>,
    dirent: Option<DreamcastDirent>,
    stat: Option<DreamcastStat>,
    last_read: Vec<u8>,
    written: Vec<u8>,
}

impl SmbFd {
    /// Creates a file descriptor wrapper from a known SMB2 file handle.
    #[must_use]
    pub fn file(handle: FileHandle) -> Self {
        Self {
            handle_id: None,
            kind: SmbFdKind::File,
            state: SmbFdState::Open,
            file: Some(handle),
            directory: None,
            dirent: None,
            stat: None,
            last_read: Vec::new(),
            written: Vec::new(),
        }
    }

    /// Creates a directory descriptor wrapper from a known SMB2 directory handle.
    #[must_use]
    pub fn directory(handle: DirectoryHandle) -> Self {
        Self {
            handle_id: None,
            kind: SmbFdKind::Directory,
            state: SmbFdState::Open,
            file: None,
            directory: Some(handle),
            dirent: None,
            stat: None,
            last_read: Vec::new(),
            written: Vec::new(),
        }
    }

    /// Creates a descriptor shell for an open request whose platform handle is not available yet.
    #[must_use]
    pub const fn pending(kind: SmbFdKind) -> Self {
        Self {
            handle_id: None,
            kind,
            state: SmbFdState::Pending,
            file: None,
            directory: None,
            dirent: None,
            stat: None,
            last_read: Vec::new(),
            written: Vec::new(),
        }
    }

    /// Returns the descriptor kind.
    #[must_use]
    pub const fn kind(&self) -> SmbFdKind {
        self.kind
    }

    /// Returns the handle-table id assigned by [`DreamcastVfs::smb_open`].
    #[must_use]
    pub const fn handle_id(&self) -> Option<DreamcastHandleId> {
        self.handle_id
    }

    /// Returns the descriptor lifecycle state.
    #[must_use]
    pub const fn state(&self) -> SmbFdState {
        self.state
    }

    /// Returns whether this descriptor represents a directory.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.kind.is_dir()
    }

    /// Returns the wrapped file handle, if this descriptor has one.
    #[must_use]
    pub const fn file_handle(&self) -> Option<&FileHandle> {
        self.file.as_ref()
    }

    /// Returns the wrapped directory handle, if this descriptor has one.
    #[must_use]
    pub const fn directory_handle(&self) -> Option<&DirectoryHandle> {
        self.directory.as_ref()
    }

    /// Returns the cached directory entry populated by `smb_readdir`.
    #[must_use]
    pub const fn dirent(&self) -> Option<&DreamcastDirent> {
        self.dirent.as_ref()
    }

    /// Returns the most recent metadata cached by `smb_stat` or `smb_fstat`.
    #[must_use]
    pub const fn stat(&self) -> Option<&DreamcastStat> {
        self.stat.as_ref()
    }

    /// Returns the deterministic bytes cached by the most recent `smb_read`.
    #[must_use]
    pub fn last_read(&self) -> &[u8] {
        &self.last_read
    }

    /// Returns bytes accepted by local `smb_write` calls on this descriptor.
    #[must_use]
    pub fn written(&self) -> &[u8] {
        &self.written
    }

    /// Marks a pending file descriptor as backed by a handle placeholder.
    pub fn attach_file_handle(&mut self, handle: FileHandle) -> Result<()> {
        if self.kind != SmbFdKind::File || self.state == SmbFdState::Closed {
            return Err(ErrorCode(EINVAL));
        }
        self.file = Some(handle);
        self.state = SmbFdState::Open;
        Ok(())
    }

    /// Marks a pending directory descriptor as backed by a handle placeholder.
    pub fn attach_directory_handle(&mut self, handle: DirectoryHandle) -> Result<()> {
        if self.kind != SmbFdKind::Directory || self.state == SmbFdState::Closed {
            return Err(ErrorCode(EINVAL));
        }
        self.directory = Some(handle);
        self.state = SmbFdState::Open;
        Ok(())
    }

    /// Marks the descriptor closed and drops any cached handle placeholder.
    pub fn mark_closed(&mut self) {
        self.handle_id = None;
        self.state = SmbFdState::Closed;
        self.file = None;
        self.directory = None;
        self.dirent = None;
        self.stat = None;
        self.last_read.clear();
        self.written.clear();
    }

    /// Updates the cached directory entry from an SMB2 directory entry.
    pub fn cache_dirent(&mut self, entry: &DirectoryEntry) -> Result<&DreamcastDirent> {
        if !self.is_dir() {
            return Err(ErrorCode(EINVAL));
        }

        self.dirent = Some(DreamcastDirent::from_directory_entry(entry));
        self.dirent.as_ref().ok_or(ErrorCode(EIO))
    }

    fn cache_stat(&mut self, stat: &Stat) {
        self.stat = Some(DreamcastStat::from_smb2_stat(stat));
    }

    fn cache_read(&mut self, data: &[u8]) {
        self.last_read.clear();
        self.last_read.extend_from_slice(data);
    }

    fn cache_write(&mut self, data: &[u8]) {
        self.written.extend_from_slice(data);
    }

    fn assign_handle_id(&mut self, handle_id: DreamcastHandleId) {
        self.handle_id = Some(handle_id);
    }
}

/// Directory entry shape returned by the Dreamcast VFS `readdir` callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamcastDirent {
    /// Entry size in bytes.
    pub size: u64,
    /// Entry name truncated to the Dreamcast `NAME_MAX - 1` behavior.
    pub name: String,
    /// Platform attribute flags; kept as zero until KallistiOS mapping is migrated.
    pub attr: u32,
    /// Platform timestamp field; kept as zero until KallistiOS mapping is migrated.
    pub time: u64,
}

impl DreamcastDirent {
    /// Builds a VFS directory entry from an SMB2 directory entry skeleton.
    #[must_use]
    pub fn from_directory_entry(entry: &DirectoryEntry) -> Self {
        Self {
            size: entry.stat.size,
            name: truncate_name(&entry.name),
            attr: 0,
            time: 0,
        }
    }
}

/// File mode written by `smb2_stat_convert` for Dreamcast `struct stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamcastFileMode {
    /// Regular file mode equivalent to `S_IFREG`.
    Regular,
    /// Directory mode equivalent to `S_IFDIR`.
    Directory,
    /// Symbolic link mode equivalent to `S_IFLNK`.
    Symlink,
}

impl From<FileType> for DreamcastFileMode {
    fn from(file_type: FileType) -> Self {
        match file_type {
            FileType::File => Self::Regular,
            FileType::Directory => Self::Directory,
            FileType::Link | FileType::Unknown(_) => Self::Symlink,
        }
    }
}

/// Rust-side subset of the Dreamcast `struct stat` fields populated by `vfs.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamcastStat {
    /// File identifier.
    pub ino: u64,
    /// Link count.
    pub nlink: u32,
    /// File size in bytes.
    pub size: u64,
    /// Access time seconds.
    pub atime: u64,
    /// Modification time seconds.
    pub mtime: u64,
    /// Change time seconds.
    pub ctime: u64,
    /// Dreamcast file mode derived from the SMB2 file type.
    pub mode: DreamcastFileMode,
}

impl DreamcastStat {
    /// Converts an SMB2 stat skeleton into the Dreamcast fields filled by `smb2_stat_convert`.
    #[must_use]
    pub fn from_smb2_stat(stat: &Stat) -> Self {
        Self {
            ino: stat.ino,
            nlink: stat.nlink,
            size: stat.size,
            atime: stat.atime,
            mtime: stat.mtime,
            ctime: stat.ctime,
            mode: DreamcastFileMode::from(stat.file_type),
        }
    }
}

/// Metadata registered with KallistiOS for the `/smb` VFS handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VfsHandlerInfo {
    /// Handler mount path.
    pub mount: String,
    /// Handler version copied from the C `nmmgr` descriptor.
    pub version: u32,
    /// Whether directory cache support is enabled.
    pub cache: bool,
}

/// Result of asking a Dreamcast platform backend to install the VFS handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsRegistration {
    /// A real KallistiOS VFS handler was registered by the backend.
    Platform,
    /// No platform SDK registration was attempted; operations use local fallback state.
    LocalFallback,
}

/// Platform adapter boundary for Dreamcast VFS registration.
pub trait DreamcastPlatformBackend {
    /// Registers or prepares the `/smb` VFS handler.
    ///
    /// # Errors
    ///
    /// Returns a platform error when the backend cannot install or prepare the handler.
    fn register_vfs(
        &mut self,
        handler: &VfsHandlerInfo,
        mount: &SmbMount,
    ) -> Result<VfsRegistration>;

    /// Unregisters or tears down backend-owned VFS state.
    ///
    /// # Errors
    ///
    /// Returns a platform error when teardown fails.
    fn unregister_vfs(&mut self, handler: &VfsHandlerInfo) -> Result<()>;
}

/// Native Rust fallback backend used when the Dreamcast SDK is not linked.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LocalDreamcastBackend;

impl DreamcastPlatformBackend for LocalDreamcastBackend {
    fn register_vfs(
        &mut self,
        _handler: &VfsHandlerInfo,
        _mount: &SmbMount,
    ) -> Result<VfsRegistration> {
        Ok(VfsRegistration::LocalFallback)
    }

    fn unregister_vfs(&mut self, _handler: &VfsHandlerInfo) -> Result<()> {
        Ok(())
    }
}

/// Backend that reports the absence of KallistiOS VFS support explicitly.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UnavailableDreamcastBackend;

impl DreamcastPlatformBackend for UnavailableDreamcastBackend {
    fn register_vfs(
        &mut self,
        _handler: &VfsHandlerInfo,
        _mount: &SmbMount,
    ) -> Result<VfsRegistration> {
        Err(ErrorCode(ENOSYS))
    }

    fn unregister_vfs(&mut self, _handler: &VfsHandlerInfo) -> Result<()> {
        Err(ErrorCode(ENOSYS))
    }
}

impl Default for VfsHandlerInfo {
    fn default() -> Self {
        Self {
            mount: SMB_VFS_MOUNT.to_owned(),
            version: SMB_VFS_VERSION,
            cache: true,
        }
    }
}

/// Parsed mount state owned by the Dreamcast SMB VFS adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbMount {
    /// URL text passed to `kos_smb_init`.
    pub url: String,
    /// Parsed SMB URL fields retained for future `smb2_parse_url` migration.
    pub smb_url: Option<Smb2Url>,
}

impl SmbMount {
    /// Creates mount state from the caller supplied URL.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if `url` is empty.
    pub fn new(url: &str) -> Result<Self> {
        if url.is_empty() {
            return Err(ErrorCode(EINVAL));
        }

        Ok(Self {
            url: url.to_owned(),
            smb_url: None,
        })
    }

    /// Attaches parsed SMB URL fields once URL parsing is available.
    #[must_use]
    pub fn with_smb_url(mut self, smb_url: Smb2Url) -> Self {
        self.smb_url = Some(smb_url);
        self
    }
}

/// Result of `smb_open`: the queued SMB request and the VFS descriptor shell.
#[derive(Debug)]
pub struct SmbOpenRequest {
    /// Descriptor shell matching the C `struct smb_fd` allocation.
    pub fd: SmbFd,
    /// SMB2 request descriptor built for the future platform implementation.
    pub request: SyncRequest,
}

/// Result of `smb_close` for either supported descriptor kind.
#[derive(Debug)]
pub enum SmbCloseRequest {
    /// Close request for a file handle.
    File(Box<SyncRequest>),
    /// Close request for a directory handle.
    Directory(DirectoryRequest),
}

/// VFS adapter lifecycle state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DreamcastVfsState {
    /// No SMB context or mount URL is modeled.
    #[default]
    Uninitialized,
    /// Mount state exists and operations use the Rust local fallback backend.
    LocalFallback,
    /// Mount state exists and a platform backend registered the handler.
    PlatformRegistered,
    /// Shutdown has been called and owned state has been released.
    Shutdown,
}

/// Dreamcast SMB VFS state corresponding to the C file's global context, URL, and handler.
#[derive(Debug)]
pub struct DreamcastVfs<B = LocalDreamcastBackend> {
    client: Option<Smb2Client>,
    mount: Option<SmbMount>,
    handles: Vec<Option<SmbFdKind>>,
    handler: VfsHandlerInfo,
    state: DreamcastVfsState,
    backend: B,
}

impl Default for DreamcastVfs<LocalDreamcastBackend> {
    fn default() -> Self {
        Self::new()
    }
}

impl DreamcastVfs<LocalDreamcastBackend> {
    /// Creates an uninitialized Dreamcast VFS adapter using the local fallback backend.
    #[must_use]
    pub fn new() -> Self {
        Self::with_backend(LocalDreamcastBackend)
    }
}

impl<B> DreamcastVfs<B> {
    /// Creates an uninitialized Dreamcast VFS adapter with a platform backend.
    #[must_use]
    pub fn with_backend(backend: B) -> Self {
        Self {
            client: None,
            mount: None,
            handles: Vec::new(),
            handler: VfsHandlerInfo::default(),
            state: DreamcastVfsState::Uninitialized,
            backend,
        }
    }

    /// Returns the static VFS handler metadata.
    #[must_use]
    pub const fn handler(&self) -> &VfsHandlerInfo {
        &self.handler
    }

    /// Returns shared access to the configured platform backend.
    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// Returns mutable access to the configured platform backend.
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Returns whether a real platform backend registered the VFS handler.
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        matches!(self.state, DreamcastVfsState::PlatformRegistered)
    }

    /// Returns whether the VFS has usable mounted state through any backend.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(
            self.state,
            DreamcastVfsState::LocalFallback | DreamcastVfsState::PlatformRegistered
        )
    }

    /// Returns the modeled VFS lifecycle state.
    #[must_use]
    pub const fn state(&self) -> DreamcastVfsState {
        self.state
    }

    /// Returns the current mount state, if initialized.
    #[must_use]
    pub const fn mount(&self) -> Option<&SmbMount> {
        self.mount.as_ref()
    }

    /// Returns the current SMB2 client skeleton, if initialized.
    #[must_use]
    pub const fn client(&self) -> Option<&Smb2Client> {
        self.client.as_ref()
    }

    /// Returns the number of active Dreamcast VFS handles tracked by the model.
    #[must_use]
    pub fn handle_count(&self) -> usize {
        self.handles.iter().flatten().count()
    }

    /// Mirrors `kos_smb_init` by creating client and mount state for a URL.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if `url` is empty. Future platform code may also
    /// return SMB2 connection or KallistiOS registration errors.
    pub fn kos_smb_init(&mut self, url: &str) -> Result<()>
    where
        B: DreamcastPlatformBackend,
    {
        let mount = SmbMount::new(url)?;
        let mut client = Smb2Client::new();
        let parsed_url = client.set_url(url)?;
        let registration = self.backend.register_vfs(&self.handler, &mount)?;
        client.connect_share_local(&parsed_url.server, &parsed_url.share)?;
        self.client = Some(client);
        self.mount = Some(mount.with_smb_url(parsed_url));
        self.state = match registration {
            VfsRegistration::Platform => DreamcastVfsState::PlatformRegistered,
            VfsRegistration::LocalFallback => DreamcastVfsState::LocalFallback,
        };
        Ok(())
    }

    /// Mirrors `kos_smb_shutdown` by clearing handler, mount, and client state.
    pub fn kos_smb_shutdown(&mut self) -> Result<()>
    where
        B: DreamcastPlatformBackend,
    {
        if self.is_active() {
            self.backend.unregister_vfs(&self.handler)?;
        }
        self.state = DreamcastVfsState::Shutdown;
        self.mount = None;
        self.client = None;
        self.handles.clear();
        Ok(())
    }

    /// Builds the `smb_open` operation skeleton for files or directories.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if the VFS is not initialized, or an SMB2 skeleton
    /// validation error such as `ErrorCode(-22)` for an empty path.
    pub fn smb_open(&mut self, path: &str, mode: i32) -> Result<SmbOpenRequest> {
        let kind = SmbFdKind::from_open_mode(mode);
        let prepared_path = prepare_vfs_path(path)?;
        let request = if kind.is_dir() {
            sync::smb2_opendir(self.required_client_mut()?, &prepared_path)?
        } else {
            sync::smb2_open(self.required_client_mut()?, &prepared_path, mode)?
        };

        let mut fd = SmbFd::pending(kind);
        match request.payload() {
            SyncPayload::Directory(handle) => fd.attach_directory_handle(handle.clone())?,
            SyncPayload::File(handle) => fd.attach_file_handle(handle.clone())?,
            _ => return Err(ErrorCode(EIO)),
        }

        let handle_id = self.insert_handle(fd.kind());
        fd.assign_handle_id(handle_id);

        Ok(SmbOpenRequest { fd, request })
    }

    /// Builds the `smb_close` operation skeleton for a descriptor with a known handle.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if the VFS is not initialized or the descriptor has
    /// no file handle available for the current skeleton.
    pub fn smb_close(&mut self, fd: &mut SmbFd) -> Result<SmbCloseRequest> {
        if fd.is_dir() {
            let _client = self.required_client()?;
            self.ensure_handle(fd, SmbFdKind::Directory)?;
            let handle = fd.directory_handle().ok_or(ErrorCode(EIO))?;
            let file_id = handle.id();
            self.remove_handle(fd.handle_id(), SmbFdKind::Directory)?;
            let request = SmbCloseRequest::Directory(DirectoryRequest {
                file_id,
                operation: DirectoryOperation::Close,
            });
            fd.mark_closed();
            return Ok(request);
        }

        self.ensure_handle(fd, SmbFdKind::File)?;
        let handle = fd.file_handle().ok_or(ErrorCode(EIO))?;
        let request = sync::smb2_close(self.required_client_mut()?, handle)?;
        self.remove_handle(fd.handle_id(), SmbFdKind::File)?;
        fd.mark_closed();
        Ok(SmbCloseRequest::File(Box::new(request)))
    }

    /// Builds the `smb_read` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if the VFS is not initialized or `fd` has no file
    /// handle, or a validation error if `count` exceeds `buffer.len()`.
    pub fn smb_read(
        &mut self,
        fd: &mut SmbFd,
        buffer: &mut [u8],
        count: usize,
    ) -> Result<SyncRequest> {
        self.ensure_handle(fd, SmbFdKind::File)?;
        let handle = fd.file_handle().ok_or(ErrorCode(EIO))?;
        let request = sync::smb2_read(self.required_client_mut()?, handle, buffer, count)?;
        let SyncPayload::Read { data, .. } = request.payload() else {
            return Err(ErrorCode(EIO));
        };
        let copy_len = data.len().min(buffer.len()).min(count);
        buffer[..copy_len].copy_from_slice(&data[..copy_len]);
        fd.cache_read(&data[..copy_len]);
        Ok(request)
    }

    /// Builds the `smb_write` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if the VFS is not initialized or `fd` has no file
    /// handle, or a validation error if `count` exceeds `buffer.len()`.
    pub fn smb_write(
        &mut self,
        fd: &mut SmbFd,
        buffer: &[u8],
        count: usize,
    ) -> Result<SyncRequest> {
        self.ensure_handle(fd, SmbFdKind::File)?;
        let handle = fd.file_handle().ok_or(ErrorCode(EIO))?;
        let request = sync::smb2_write(self.required_client_mut()?, handle, buffer, count)?;
        let SyncPayload::Write { count: written, .. } = request.payload() else {
            return Err(ErrorCode(EIO));
        };
        fd.cache_write(&buffer[..(*written).min(buffer.len())]);
        Ok(request)
    }

    /// Caches and returns a Dreamcast directory entry for `smb_readdir`.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if `fd` is not a directory descriptor.
    pub fn smb_readdir<'a>(
        &self,
        fd: &'a mut SmbFd,
        entry: &DirectoryEntry,
    ) -> Result<&'a DreamcastDirent> {
        let _client = self.required_client()?;
        self.ensure_handle(fd, SmbFdKind::Directory)?;
        fd.cache_dirent(entry)
    }

    /// Builds the `smb_rename` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized or `ErrorCode(-22)` for empty paths.
    pub fn smb_rename(&mut self, old_path: &str, new_path: &str) -> Result<SyncRequest> {
        let old_path = prepare_vfs_path(old_path)?;
        let new_path = prepare_vfs_path(new_path)?;
        sync::smb2_rename(self.required_client_mut()?, &old_path, &new_path)
    }

    /// Builds the `smb_unlink` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized or `ErrorCode(-22)` for an empty path.
    pub fn smb_unlink(&mut self, path: &str) -> Result<SyncRequest> {
        let path = prepare_vfs_path(path)?;
        sync::smb2_unlink(self.required_client_mut()?, &path)
    }

    /// Converts SMB2 stat fields to Dreamcast stat fields.
    #[must_use]
    pub fn smb2_stat_convert(stat: &Stat) -> DreamcastStat {
        DreamcastStat::from_smb2_stat(stat)
    }

    /// Builds the `smb_stat` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized or `ErrorCode(-22)` for an empty path.
    pub fn smb_stat(&mut self, path: &str) -> Result<SyncRequest> {
        let path = prepare_vfs_path(path)?;
        let request = sync::smb2_stat(self.required_client_mut()?, &path)?;
        if !matches!(request.payload(), SyncPayload::Stat(_)) {
            return Err(ErrorCode(EIO));
        }
        Ok(request)
    }

    /// Builds the `smb_mkdir` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized or `ErrorCode(-22)` for an empty path.
    pub fn smb_mkdir(&mut self, path: &str) -> Result<SyncRequest> {
        let path = prepare_vfs_path(path)?;
        sync::smb2_mkdir(self.required_client_mut()?, &path)
    }

    /// Builds the `smb_rmdir` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized or `ErrorCode(-22)` for an empty path.
    pub fn smb_rmdir(&mut self, path: &str) -> Result<SyncRequest> {
        let path = prepare_vfs_path(path)?;
        sync::smb2_rmdir(self.required_client_mut()?, &path)
    }

    /// Builds the `smb_seek64` operation skeleton metadata.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` because platform seek execution has not been migrated.
    pub fn smb_seek64(&self, fd: &SmbFd, offset: i64, whence: SeekWhence) -> Result<Seek64Request> {
        let _client = self.required_client()?;
        self.ensure_handle(fd, SmbFdKind::File)?;
        let _handle = fd.file_handle().ok_or(ErrorCode(EIO))?;
        Ok(Seek64Request { offset, whence })
    }

    /// Builds the `smb_tell64` operation skeleton metadata.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized or `fd` has no file handle.
    pub fn smb_tell64(&self, fd: &SmbFd) -> Result<Seek64Request> {
        let _client = self.required_client()?;
        self.ensure_handle(fd, SmbFdKind::File)?;
        let _handle = fd.file_handle().ok_or(ErrorCode(EIO))?;
        Ok(Seek64Request {
            offset: 0,
            whence: SeekWhence::Current,
        })
    }

    /// Builds the `smb_readlink` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized, `ErrorCode(-22)` for an empty
    /// path, or `ErrorCode(-22)` for a zero buffer length.
    pub fn smb_readlink(&mut self, path: &str, buffer_len: usize) -> Result<SyncRequest> {
        let path = prepare_vfs_path(path)?;
        sync::smb2_readlink(self.required_client_mut()?, &path, buffer_len)
    }

    /// Builds the `smb_rewinddir` operation skeleton for a known directory descriptor.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized or `ErrorCode(-22)` if `fd` is not
    /// a directory descriptor.
    pub fn smb_rewinddir(&self, fd: &SmbFd) -> Result<DirectoryRequest> {
        let _client = self.required_client()?;
        self.ensure_handle(fd, SmbFdKind::Directory)?;
        let handle = fd.directory_handle().ok_or(ErrorCode(EINVAL))?;
        Ok(DirectoryRequest {
            file_id: handle.id(),
            operation: DirectoryOperation::Rewind,
        })
    }

    /// Builds the `smb_fstat` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized or `fd` has no file handle.
    pub fn smb_fstat(&mut self, fd: &mut SmbFd) -> Result<SyncRequest> {
        self.ensure_handle(fd, SmbFdKind::File)?;
        let handle = fd.file_handle().ok_or(ErrorCode(EIO))?;
        let request = sync::smb2_fstat(self.required_client_mut()?, handle)?;
        let SyncPayload::Stat(stat) = request.payload() else {
            return Err(ErrorCode(EIO));
        };
        fd.cache_stat(stat);
        Ok(request)
    }

    fn required_client(&self) -> Result<&Smb2Client> {
        self.client.as_ref().ok_or(ErrorCode(EIO))
    }

    fn required_client_mut(&mut self) -> Result<&mut Smb2Client> {
        self.client.as_mut().ok_or(ErrorCode(EIO))
    }

    fn insert_handle(&mut self, kind: SmbFdKind) -> DreamcastHandleId {
        if let Some((index, slot)) = self
            .handles
            .iter_mut()
            .enumerate()
            .find(|(_index, slot)| slot.is_none())
        {
            *slot = Some(kind);
            return DreamcastHandleId(index);
        }

        self.handles.push(Some(kind));
        DreamcastHandleId(self.handles.len() - 1)
    }

    fn remove_handle(
        &mut self,
        handle_id: Option<DreamcastHandleId>,
        expected: SmbFdKind,
    ) -> Result<()> {
        let handle_id = handle_id.ok_or(ErrorCode(EIO))?;
        let Some(slot) = self.handles.get_mut(handle_id.0) else {
            return Err(ErrorCode(EIO));
        };
        let Some(kind) = slot.take() else {
            return Err(ErrorCode(EIO));
        };
        if kind == expected {
            Ok(())
        } else {
            *slot = Some(kind);
            Err(ErrorCode(EINVAL))
        }
    }

    fn ensure_handle(&self, fd: &SmbFd, expected: SmbFdKind) -> Result<()> {
        let handle_id = fd.handle_id().ok_or(ErrorCode(EIO))?;
        match self.handles.get(handle_id.0).and_then(Option::as_ref) {
            Some(kind) if *kind == expected && fd.state() == SmbFdState::Open => Ok(()),
            Some(_) => Err(ErrorCode(EINVAL)),
            None => Err(ErrorCode(EIO)),
        }
    }
}

/// Seek origin used by `smb_seek64` and `smb_tell64` skeletons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekWhence {
    /// Seek from the beginning of the file.
    Start,
    /// Seek from the current file offset.
    Current,
    /// Seek from the end of the file.
    End,
}

/// Request metadata for a future `smb2_lseek` binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seek64Request {
    /// Signed seek offset.
    pub offset: i64,
    /// Seek origin.
    pub whence: SeekWhence,
}

/// Directory-only VFS operation names that are not represented by sync wrappers yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryOperation {
    /// Close an open directory stream.
    Close,
    /// Rewind an open directory stream.
    Rewind,
}

/// Request metadata for directory-only VFS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryRequest {
    /// SMB2 file id associated with the directory stream.
    pub file_id: [u8; 16],
    /// Directory operation to perform later.
    pub operation: DirectoryOperation,
}

fn truncate_name(name: &str) -> String {
    name.chars()
        .scan(0usize, |used, ch| {
            let len = ch.len_utf8();
            if used.saturating_add(len) >= DREAMCAST_NAME_MAX {
                None
            } else {
                *used += len;
                Some(ch)
            }
        })
        .collect()
}

/// Normalizes a KallistiOS VFS path into the share-relative form used by libsmb2.
///
/// # Errors
///
/// Returns `ErrorCode(-2)` if `..` would escape above the mount root, or
/// `ErrorCode(-22)` for an empty input path.
pub fn prepare_vfs_path(path: &str) -> Result<String> {
    if path.is_empty() {
        return Err(ErrorCode(EINVAL));
    }

    let replaced = path.replace('\\', "/");
    let without_mount = match replaced.strip_prefix(SMB_VFS_MOUNT) {
        Some(rest) => rest,
        None => replaced.as_str(),
    };

    let mut components: Vec<&str> = Vec::new();
    for component in without_mount.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(ErrorCode(ENOENT));
                }
            }
            value => components.push(value),
        }
    }

    if components.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(components.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smb_open_and_close_track_handle_table() {
        let mut vfs = DreamcastVfs::new();
        vfs.kos_smb_init("smb://server/share").unwrap();

        let mut open = vfs.smb_open("/file.txt", 0).unwrap();
        assert_eq!(vfs.handle_count(), 1);
        assert_eq!(open.fd.handle_id(), Some(DreamcastHandleId(0)));

        vfs.smb_close(&mut open.fd).unwrap();
        assert_eq!(vfs.handle_count(), 0);
        assert_eq!(open.fd.state(), SmbFdState::Closed);
    }

    #[test]
    fn closed_handle_is_rejected() {
        let mut vfs = DreamcastVfs::new();
        vfs.kos_smb_init("smb://server/share").unwrap();

        let mut open = vfs.smb_open("/file.txt", 0).unwrap();
        vfs.smb_close(&mut open.fd).unwrap();

        let err = vfs.smb_tell64(&open.fd).unwrap_err();
        assert_eq!(err, ErrorCode(EIO));
    }

    #[test]
    fn unavailable_backend_returns_unsupported() {
        let mut vfs = DreamcastVfs::with_backend(UnavailableDreamcastBackend);

        let err = vfs.kos_smb_init("smb://server/share").unwrap_err();
        assert_eq!(err, ErrorCode(ENOSYS));
    }
}
