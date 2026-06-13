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
use crate::legacy_lib::sync::{self, SyncRequest};

const EINVAL: i32 = -22;
const EIO: i32 = -5;

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
    kind: SmbFdKind,
    file: Option<FileHandle>,
    directory: Option<DirectoryHandle>,
    dirent: Option<DreamcastDirent>,
}

impl SmbFd {
    /// Creates a file descriptor wrapper from a known SMB2 file handle.
    #[must_use]
    pub fn file(handle: FileHandle) -> Self {
        Self {
            kind: SmbFdKind::File,
            file: Some(handle),
            directory: None,
            dirent: None,
        }
    }

    /// Creates a directory descriptor wrapper from a known SMB2 directory handle.
    #[must_use]
    pub fn directory(handle: DirectoryHandle) -> Self {
        Self {
            kind: SmbFdKind::Directory,
            file: None,
            directory: Some(handle),
            dirent: None,
        }
    }

    /// Creates a descriptor shell for an open request whose platform handle is not available yet.
    #[must_use]
    pub const fn pending(kind: SmbFdKind) -> Self {
        Self {
            kind,
            file: None,
            directory: None,
            dirent: None,
        }
    }

    /// Returns the descriptor kind.
    #[must_use]
    pub const fn kind(&self) -> SmbFdKind {
        self.kind
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

    /// Updates the cached directory entry from an SMB2 directory entry.
    pub fn cache_dirent(&mut self, entry: &DirectoryEntry) -> Result<&DreamcastDirent> {
        if !self.is_dir() {
            return Err(ErrorCode(EINVAL));
        }

        self.dirent = Some(DreamcastDirent::from_directory_entry(entry));
        self.dirent.as_ref().ok_or(ErrorCode(EIO))
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

/// Dreamcast SMB VFS state corresponding to the C file's global context, URL, and handler.
#[derive(Debug, Default)]
pub struct DreamcastVfs {
    client: Option<Smb2Client>,
    mount: Option<SmbMount>,
    handler: VfsHandlerInfo,
    registered: bool,
}

impl DreamcastVfs {
    /// Creates an uninitialized Dreamcast VFS adapter skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the static VFS handler metadata.
    #[must_use]
    pub const fn handler(&self) -> &VfsHandlerInfo {
        &self.handler
    }

    /// Returns whether `kos_smb_init` has registered the handler skeleton.
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        self.registered
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

    /// Mirrors `kos_smb_init` by creating client and mount state for a URL.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if `url` is empty. Future platform code may also
    /// return SMB2 connection or KallistiOS registration errors.
    pub fn kos_smb_init(&mut self, url: &str) -> Result<()> {
        let mount = SmbMount::new(url)?;
        self.client = Some(Smb2Client::new());
        self.mount = Some(mount);
        self.registered = true;
        Ok(())
    }

    /// Mirrors `kos_smb_shutdown` by clearing handler, mount, and client state.
    pub fn kos_smb_shutdown(&mut self) {
        self.registered = false;
        self.mount = None;
        self.client = None;
    }

    /// Builds the `smb_open` operation skeleton for files or directories.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if the VFS is not initialized, or an SMB2 skeleton
    /// validation error such as `ErrorCode(-22)` for an empty path.
    pub fn smb_open(&self, path: &str, mode: i32) -> Result<SmbOpenRequest> {
        let client = self.required_client()?;
        let kind = SmbFdKind::from_open_mode(mode);
        let request = if kind.is_dir() {
            sync::smb2_opendir(client, path)?
        } else {
            sync::smb2_open(client, path, mode)?
        };

        Ok(SmbOpenRequest {
            fd: SmbFd::pending(kind),
            request,
        })
    }

    /// Builds the `smb_close` operation skeleton for a descriptor with a known handle.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if the VFS is not initialized or the descriptor has
    /// no file handle available for the current skeleton.
    pub fn smb_close(&self, fd: &SmbFd) -> Result<SyncRequest> {
        let client = self.required_client()?;
        if fd.is_dir() {
            return Err(ErrorCode(EIO));
        }

        let handle = fd.file_handle().ok_or(ErrorCode(EIO))?;
        sync::smb2_close(client, handle)
    }

    /// Builds the `smb_read` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if the VFS is not initialized or `fd` has no file
    /// handle, or a validation error if `count` exceeds `buffer.len()`.
    pub fn smb_read(&self, fd: &SmbFd, buffer: &mut [u8], count: usize) -> Result<SyncRequest> {
        let client = self.required_client()?;
        let handle = fd.file_handle().ok_or(ErrorCode(EIO))?;
        sync::smb2_read(client, handle, buffer, count)
    }

    /// Builds the `smb_write` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if the VFS is not initialized or `fd` has no file
    /// handle, or a validation error if `count` exceeds `buffer.len()`.
    pub fn smb_write(&self, fd: &SmbFd, buffer: &[u8], count: usize) -> Result<SyncRequest> {
        let client = self.required_client()?;
        let handle = fd.file_handle().ok_or(ErrorCode(EIO))?;
        sync::smb2_write(client, handle, buffer, count)
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
        fd.cache_dirent(entry)
    }

    /// Builds the `smb_rename` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized or `ErrorCode(-22)` for empty paths.
    pub fn smb_rename(&self, old_path: &str, new_path: &str) -> Result<SyncRequest> {
        sync::smb2_rename(self.required_client()?, old_path, new_path)
    }

    /// Builds the `smb_unlink` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized or `ErrorCode(-22)` for an empty path.
    pub fn smb_unlink(&self, path: &str) -> Result<SyncRequest> {
        sync::smb2_unlink(self.required_client()?, path)
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
    pub fn smb_stat(&self, path: &str) -> Result<SyncRequest> {
        sync::smb2_stat(self.required_client()?, path)
    }

    /// Builds the `smb_mkdir` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized or `ErrorCode(-22)` for an empty path.
    pub fn smb_mkdir(&self, path: &str) -> Result<SyncRequest> {
        sync::smb2_mkdir(self.required_client()?, path)
    }

    /// Builds the `smb_rmdir` operation skeleton.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized or `ErrorCode(-22)` for an empty path.
    pub fn smb_rmdir(&self, path: &str) -> Result<SyncRequest> {
        sync::smb2_rmdir(self.required_client()?, path)
    }

    /// Builds the `smb_seek64` operation skeleton metadata.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` because platform seek execution has not been migrated.
    pub fn smb_seek64(&self, fd: &SmbFd, offset: i64, whence: SeekWhence) -> Result<Seek64Request> {
        let _client = self.required_client()?;
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
    pub fn smb_readlink(&self, path: &str, buffer_len: usize) -> Result<SyncRequest> {
        sync::smb2_readlink(self.required_client()?, path, buffer_len)
    }

    /// Builds the `smb_rewinddir` operation skeleton for a known directory descriptor.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-5)` if uninitialized or `ErrorCode(-22)` if `fd` is not
    /// a directory descriptor.
    pub fn smb_rewinddir(&self, fd: &SmbFd) -> Result<DirectoryRequest> {
        let _client = self.required_client()?;
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
    pub fn smb_fstat(&self, fd: &SmbFd) -> Result<SyncRequest> {
        let client = self.required_client()?;
        let handle = fd.file_handle().ok_or(ErrorCode(EIO))?;
        sync::smb2_fstat(client, handle)
    }

    fn required_client(&self) -> Result<&Smb2Client> {
        self.client.as_ref().ok_or(ErrorCode(EIO))
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
