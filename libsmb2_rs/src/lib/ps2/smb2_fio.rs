//! PS2 file I/O adapter migrated from `lib/ps2/smb2_fio.c`.
//!
//! This module mirrors the C driver responsibilities without binding to the
//! PS2 IOP runtime or performing SMB2 network I/O. It provides owned Rust data
//! structures and method skeletons that can be wired to a platform backend later.

use std::collections::VecDeque;

/// Rust result type used by the PS2 SMB2 file I/O skeleton.
pub type Smb2FioResult<T> = core::result::Result<T, Smb2FioError>;

/// Maximum share name length used by the C-side `SMB2_MAX_NAME_LEN` buffer.
pub const SMB2_MAX_NAME_LEN: usize = 256;

/// Maximum directory entry name length used by the C-side `iox_dirent_t` copy.
pub const SMB2_DIRENT_NAME_LEN: usize = 256;

/// Read-only open flag accepted by the C `SMB2_open` implementation.
pub const O_RDONLY: i32 = 0;

/// Read/write open flag accepted by the local fallback write path.
pub const O_RDWR: i32 = 0x0002;

/// File mode bit used when a stat entry represents a directory.
pub const FIO_S_IFDIR: u32 = 0x4000;

/// File mode bit used when a stat entry represents a regular file.
pub const FIO_S_IFREG: u32 = 0x8000;

const EIO: i32 = 5;
const EBADF: i32 = 9;
const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;
const ENOENT: i32 = 2;
const EROFS: i32 = 30;

/// Error values corresponding to negative errno returns in `smb2_fio.c`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Smb2FioError {
    /// A path, share, file, or directory entry was not found.
    NoEntry,
    /// The operation was attempted with an invalid or absent file handle.
    BadFileDescriptor,
    /// The operation is unsupported by this skeleton or failed as generic I/O.
    Io,
    /// The operation is invalid for the provided arguments or current state.
    InvalidInput,
    /// The C implementation would have failed an allocation.
    OutOfMemory,
    /// The current C open path rejects writes and reports a read-only file system.
    ReadOnlyFileSystem,
}

impl Smb2FioError {
    /// Returns the negative errno-style value used by the C implementation.
    #[must_use]
    pub const fn errno_code(&self) -> i32 {
        match self {
            Self::NoEntry => -ENOENT,
            Self::BadFileDescriptor => -EBADF,
            Self::Io => -EIO,
            Self::InvalidInput => -EINVAL,
            Self::OutOfMemory => -ENOMEM,
            Self::ReadOnlyFileSystem => -EROFS,
        }
    }
}

impl core::fmt::Display for Smb2FioError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::NoEntry => "entry not found",
            Self::BadFileDescriptor => "bad file descriptor",
            Self::Io => "I/O operation is not available in the skeleton",
            Self::InvalidInput => "invalid input",
            Self::OutOfMemory => "out of memory",
            Self::ReadOnlyFileSystem => "read-only file system",
        };
        f.write_str(message)
    }
}

impl std::error::Error for Smb2FioError {}

/// Input payload for `SMB2_DEVCTL_CONNECT` and the C `smb2_Connect` helper.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Smb2ConnectIn {
    /// SMB URL passed to `smb2_parse_url` in the C implementation.
    pub url: String,
    /// Virtual share name exposed as `smb:/<name>`.
    pub name: String,
    /// Username passed to `smb2_connect_share`.
    pub username: String,
    /// Password assigned on the SMB2 context before connecting.
    pub password: String,
}

/// Output payload for `SMB2_DEVCTL_CONNECT`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Smb2ConnectOut {
    /// Opaque context identifier for the connected share in this Rust skeleton.
    pub ctx: Option<Smb2ContextId>,
}

/// Opaque identifier for a stored SMB2 context.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Smb2ContextId(pub usize);

/// Opaque identifier for a file or directory handle tracked by the skeleton.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Smb2HandleId(pub usize);

/// Rust-owned counterpart of `struct smb2_share_list`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Smb2Share {
    /// Virtual share name used as the first path component under `smb:/`.
    pub name: String,
    /// Opaque SMB2 context identity associated with this share.
    pub context: Smb2ContextId,
    /// Original URL used when the share was registered.
    pub url: String,
    /// Username associated with the share registration.
    pub username: String,
}

/// Rust-owned counterpart of `struct file_fh`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Smb2FileHandle {
    /// Opaque SMB2 context identity associated with this file handle.
    pub context: Smb2ContextId,
    /// Share-relative path opened by `SMB2_open`.
    pub path: String,
    /// Open flags passed by the caller.
    pub flags: i32,
    /// Current seek offset tracked by the skeleton.
    pub position: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Smb2LocalFile {
    context: Smb2ContextId,
    path: String,
    data: Vec<u8>,
}

/// Rust-owned counterpart of `struct dir_fh`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Smb2DirHandle {
    /// Opaque SMB2 context identity associated with this directory handle.
    pub context: Smb2ContextId,
    /// Share-relative path opened by `SMB2_dopen`.
    pub path: String,
    /// Whether this handle enumerates the virtual root share list.
    pub is_root: bool,
    /// Pending virtual-root share names for `SMB2_dread` skeleton responses.
    pub shares: VecDeque<String>,
    /// Pending local directory entries for non-root `SMB2_dread` fallback responses.
    pub entries: VecDeque<IoxDirent>,
}

/// File or directory private data corresponding to `iop_file_t::privdata`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Smb2PrivData {
    /// Private data for file operations such as read, seek, and close.
    File(Smb2FileHandle),
    /// Private data for directory operations such as dread and dclose.
    Directory(Smb2DirHandle),
}

/// Minimal Rust representation of `iop_file_t` for this migration skeleton.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IopFile {
    /// Opaque handle-table id assigned by the skeleton.
    pub handle_id: Option<Smb2HandleId>,
    /// Private file or directory handle state.
    pub privdata: Option<Smb2PrivData>,
}

/// Minimal Rust representation of `iop_device_t` for init/deinit skeletons.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IopDevice {
    /// Device name registered by `SMB2_initdev` in the C implementation.
    pub name: String,
    /// Device description corresponding to the C `iop_device_t` entry.
    pub description: String,
}

impl Default for IopDevice {
    fn default() -> Self {
        Self {
            name: "smb".to_owned(),
            description: "SMB".to_owned(),
        }
    }
}

/// PS2 packed date/time bytes filled by the C `FileTimeToDate` helper.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FileTimeDate {
    /// Reserved byte written as zero by the C helper.
    pub reserved: u8,
    /// Seconds component.
    pub seconds: u8,
    /// Minutes component.
    pub minutes: u8,
    /// Hours component.
    pub hours: u8,
    /// One-based day of month.
    pub day: u8,
    /// One-based month.
    pub month: u8,
    /// Full year represented as little-endian bytes in the PS2 stat structure.
    pub year: u16,
}

impl FileTimeDate {
    /// Returns the eight bytes written into `iox_stat_t` date fields by C code.
    #[must_use]
    pub const fn to_iox_bytes(self) -> [u8; 8] {
        [
            self.reserved,
            self.seconds,
            self.minutes,
            self.hours,
            self.day,
            self.month,
            (self.year & 0x00ff) as u8,
            ((self.year >> 8) & 0x00ff) as u8,
        ]
    }
}

/// Rust-owned counterpart of the stat fields filled through `iox_stat_t`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IoxStat {
    /// Creation time bytes.
    pub ctime: [u8; 8],
    /// Last access time bytes.
    pub atime: [u8; 8],
    /// Last modification time bytes.
    pub mtime: [u8; 8],
    /// Low 32 bits of the file size.
    pub size: u32,
    /// High 32 bits of the file size.
    pub hisize: u32,
    /// File type mode bits such as `FIO_S_IFDIR` or `FIO_S_IFREG`.
    pub mode: u32,
}

/// Rust-owned counterpart of `iox_dirent_t` used by `SMB2_dread`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IoxDirent {
    /// Entry name copied from an SMB2 directory entry or virtual share list.
    pub name: String,
    /// Entry metadata filled by `smb2_statFiller` in the C implementation.
    pub stat: IoxStat,
}

/// Rust-owned counterpart of `struct smb2_stat_64` fields consumed here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Smb2Stat64 {
    /// SMB2 creation time as FILETIME ticks.
    pub ctime: u64,
    /// SMB2 last access time as FILETIME ticks.
    pub atime: u64,
    /// SMB2 last modification time as FILETIME ticks.
    pub mtime: u64,
    /// File size in bytes.
    pub size: u64,
    /// Whether this stat entry is a directory.
    pub is_directory: bool,
}

/// Devctl commands handled by `SMB2_devctl`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Smb2DevctlCommand {
    /// Register a share, corresponding to `SMB2_DEVCTL_CONNECT`.
    Connect(Smb2ConnectIn),
    /// Command value not modeled by the skeleton.
    Unknown(i32),
}

/// Device lifecycle state modeled after `SMB2_init` and `SMB2_deinit`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Smb2DeviceState {
    /// Device operations have not created their synchronization primitive yet.
    #[default]
    Uninitialized,
    /// Device operations may allocate file and directory handles.
    Initialized,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Smb2HandleRecord {
    File(Smb2FileHandle),
    Directory(Smb2DirHandle),
}

/// In-memory skeleton for the PS2 SMB2 file I/O device operations table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Smb2Fio {
    shares: Vec<Smb2Share>,
    curdir: Option<String>,
    handles: Vec<Option<Smb2HandleRecord>>,
    files: Vec<Smb2LocalFile>,
    next_context: usize,
    state: Smb2DeviceState,
}

impl Smb2Fio {
    /// Creates an empty PS2 SMB2 file I/O skeleton.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            shares: Vec::new(),
            curdir: None,
            handles: Vec::new(),
            files: Vec::new(),
            next_context: 0,
            state: Smb2DeviceState::Uninitialized,
        }
    }

    /// Mirrors `SMB2_init` by marking the skeleton as initialized.
    pub fn init(&mut self, _dev: &mut IopDevice) -> Smb2FioResult<()> {
        self.state = Smb2DeviceState::Initialized;
        Ok(())
    }

    /// Mirrors `SMB2_deinit` by clearing initialization-only state.
    pub fn deinit(&mut self, _dev: &mut IopDevice) -> Smb2FioResult<()> {
        self.state = Smb2DeviceState::Uninitialized;
        self.handles.clear();
        self.files.clear();
        Ok(())
    }

    /// Mirrors `SMB2_initdev` without registering a PS2 kernel driver.
    #[must_use]
    pub fn initdev(&self) -> IopDevice {
        IopDevice::default()
    }

    /// Mirrors `SMB2_devctl` command dispatch for supported skeleton commands.
    pub fn devctl(&mut self, command: Smb2DevctlCommand) -> Smb2FioResult<Smb2ConnectOut> {
        match command {
            Smb2DevctlCommand::Connect(input) => self.connect(input),
            Smb2DevctlCommand::Unknown(_) => Err(Smb2FioError::InvalidInput),
        }
    }

    /// Mirrors the C `smb2_Connect` helper by registering a virtual share.
    pub fn connect(&mut self, input: Smb2ConnectIn) -> Smb2FioResult<Smb2ConnectOut> {
        if input.name.is_empty()
            || input.name.len() >= SMB2_MAX_NAME_LEN
            || input.name.contains(['/', '\\', ':'])
            || input.url.is_empty()
        {
            return Err(Smb2FioError::InvalidInput);
        }

        let context = Smb2ContextId(self.next_context);
        self.next_context = self.next_context.saturating_add(1);
        self.shares.insert(
            0,
            Smb2Share {
                name: input.name,
                context,
                url: input.url,
                username: input.username,
            },
        );

        Ok(Smb2ConnectOut { ctx: Some(context) })
    }

    /// Mirrors `SMB2_open` path selection and backs handles with local fallback state.
    pub fn open(
        &mut self,
        file: &mut IopFile,
        filename: &str,
        flags: i32,
        _mode: i32,
    ) -> Smb2FioResult<()> {
        if flags != O_RDONLY && flags != O_RDWR {
            return Err(Smb2FioError::ReadOnlyFileSystem);
        }
        let prepared = self.prepare_path(filename)?;
        self.ensure_initialized()?;
        let (context, path) = self.find_context(&prepared)?;
        if path.is_empty() {
            return Err(Smb2FioError::InvalidInput);
        }
        let path = path.to_owned();
        self.ensure_file(context, &path);
        let handle = Smb2FileHandle {
            context,
            path,
            flags,
            position: 0,
        };
        let handle_id = self.insert_handle(Smb2HandleRecord::File(handle.clone()));
        file.handle_id = Some(handle_id);
        file.privdata = Some(Smb2PrivData::File(handle));
        Ok(())
    }

    /// Mirrors `SMB2_close` by dropping file private data.
    pub fn close(&mut self, file: &mut IopFile) -> Smb2FioResult<()> {
        match file.privdata.take() {
            Some(Smb2PrivData::File(_)) => {
                self.remove_handle(file.handle_id, true)?;
                file.handle_id = None;
                Ok(())
            }
            Some(other) => {
                file.privdata = Some(other);
                Err(Smb2FioError::BadFileDescriptor)
            }
            None => Err(Smb2FioError::BadFileDescriptor),
        }
    }

    /// Mirrors `SMB2_dopen` by preparing a directory handle or virtual-root iterator.
    pub fn dopen(&mut self, file: &mut IopFile, dirname: &str) -> Smb2FioResult<()> {
        self.ensure_initialized()?;
        let prepared = self.prepare_path(dirname)?;
        let handle = if prepared.is_empty() {
            Smb2DirHandle {
                context: Smb2ContextId(0),
                path: String::new(),
                is_root: true,
                shares: self.shares.iter().map(|share| share.name.clone()).collect(),
                entries: VecDeque::new(),
            }
        } else {
            let (context, path) = self.find_context(&prepared)?;
            let entries = self.local_dir_entries(context, path)?;
            Smb2DirHandle {
                context,
                path: path.to_owned(),
                is_root: path.is_empty(),
                shares: self.shares.iter().map(|share| share.name.clone()).collect(),
                entries,
            }
        };
        let handle_id = self.insert_handle(Smb2HandleRecord::Directory(handle.clone()));
        file.handle_id = Some(handle_id);
        file.privdata = Some(Smb2PrivData::Directory(handle));
        Ok(())
    }

    /// Mirrors `SMB2_dclose` by dropping directory private data.
    pub fn dclose(&mut self, file: &mut IopFile) -> Smb2FioResult<()> {
        match file.privdata.take() {
            Some(Smb2PrivData::Directory(_)) => {
                self.remove_handle(file.handle_id, false)?;
                file.handle_id = None;
                Ok(())
            }
            Some(other) => {
                file.privdata = Some(other);
                Err(Smb2FioError::BadFileDescriptor)
            }
            None => Err(Smb2FioError::BadFileDescriptor),
        }
    }

    /// Mirrors `SMB2_dread` using virtual-root shares or local directory entries.
    pub fn dread(&self, file: &mut IopFile) -> Smb2FioResult<Option<IoxDirent>> {
        match file.privdata.as_mut() {
            Some(Smb2PrivData::Directory(handle)) if handle.is_root => {
                Ok(handle.shares.pop_front().map(|name| IoxDirent {
                    name,
                    stat: IoxStat {
                        mode: FIO_S_IFDIR,
                        ..IoxStat::default()
                    },
                }))
            }
            Some(Smb2PrivData::Directory(handle)) => Ok(handle.entries.pop_front()),
            _ => Err(Smb2FioError::BadFileDescriptor),
        }
    }

    /// Mirrors `SMB2_getstat` using deterministic local fallback metadata.
    pub fn getstat(&self, filename: &str) -> Smb2FioResult<IoxStat> {
        let prepared = self.prepare_path(filename)?;
        if prepared.is_empty() {
            return Ok(IoxStat {
                mode: FIO_S_IFDIR,
                ..IoxStat::default()
            });
        }
        let (context, path) = self.find_context(&prepared)?;
        self.local_stat(context, path)
    }

    /// Mirrors `SMB2_lseek64` by updating the skeleton file offset.
    pub fn lseek64(
        &mut self,
        file: &mut IopFile,
        pos: i64,
        whence: SeekWhence,
    ) -> Smb2FioResult<i64> {
        match file.privdata.as_mut() {
            Some(Smb2PrivData::File(handle)) => {
                let next = match whence {
                    SeekWhence::Set => pos,
                    SeekWhence::Current => handle.position.saturating_add(pos),
                    SeekWhence::End => pos,
                };
                if next < 0 {
                    return Err(Smb2FioError::InvalidInput);
                }
                handle.position = next;
                self.update_file_handle(file.handle_id, handle.clone())?;
                Ok(next)
            }
            _ => Err(Smb2FioError::BadFileDescriptor),
        }
    }

    /// Mirrors `SMB2_lseek` using a 32-bit position argument.
    pub fn lseek(
        &mut self,
        file: &mut IopFile,
        pos: i32,
        whence: SeekWhence,
    ) -> Smb2FioResult<i32> {
        let next = self.lseek64(file, i64::from(pos), whence)?;
        i32::try_from(next).map_err(|_err| Smb2FioError::InvalidInput)
    }

    /// Mirrors `SMB2_read` against deterministic local fallback file contents.
    pub fn read(&mut self, file: &mut IopFile, buf: &mut [u8]) -> Smb2FioResult<usize> {
        match file.privdata.as_mut() {
            Some(Smb2PrivData::File(handle)) => {
                let index = self
                    .find_file_index(handle.context, &handle.path)
                    .ok_or(Smb2FioError::NoEntry)?;
                let start =
                    usize::try_from(handle.position).map_err(|_err| Smb2FioError::InvalidInput)?;
                let data = &self.files[index].data;
                let available = data.len().saturating_sub(start);
                let count = available.min(buf.len());
                buf[..count].copy_from_slice(&data[start..start + count]);
                handle.position = handle.position.saturating_add(count as i64);
                self.update_file_handle(file.handle_id, handle.clone())?;
                Ok(count)
            }
            _ => Err(Smb2FioError::BadFileDescriptor),
        }
    }

    /// Mirrors `SMB2_write` against deterministic local fallback file contents.
    pub fn write(&mut self, file: &mut IopFile, buf: &[u8]) -> Smb2FioResult<usize> {
        match file.privdata.as_mut() {
            Some(Smb2PrivData::File(handle)) => {
                if handle.flags == O_RDONLY {
                    return Err(Smb2FioError::ReadOnlyFileSystem);
                }
                let index = self.ensure_file(handle.context, &handle.path);
                let start =
                    usize::try_from(handle.position).map_err(|_err| Smb2FioError::InvalidInput)?;
                let end = start.saturating_add(buf.len());
                if self.files[index].data.len() < end {
                    self.files[index].data.resize(end, 0);
                }
                self.files[index].data[start..end].copy_from_slice(buf);
                handle.position = handle.position.saturating_add(buf.len() as i64);
                self.update_file_handle(file.handle_id, handle.clone())?;
                Ok(buf.len())
            }
            _ => Err(Smb2FioError::BadFileDescriptor),
        }
    }

    /// Mirrors `SMB2_mkdir`; validates share routing but performs no SMB request.
    pub fn mkdir(&self, dirname: &str, _mode: i32) -> Smb2FioResult<()> {
        let prepared = self.prepare_path(dirname)?;
        let _resolved = self.find_context(&prepared)?;
        Err(Smb2FioError::Io)
    }

    /// Mirrors `SMB2_rmdir`; validates share routing but performs no SMB request.
    pub fn rmdir(&self, dirname: &str) -> Smb2FioResult<()> {
        let prepared = self.prepare_path(dirname)?;
        let _resolved = self.find_context(&prepared)?;
        Err(Smb2FioError::Io)
    }

    /// Mirrors `SMB2_remove`; validates share routing but performs no SMB request.
    pub fn remove(&self, filename: &str) -> Smb2FioResult<()> {
        let prepared = self.prepare_path(filename)?;
        let _resolved = self.find_context(&prepared)?;
        Err(Smb2FioError::Io)
    }

    /// Mirrors `SMB2_rename`; validates both paths resolve to the same share.
    pub fn rename(&self, oldname: &str, newname: &str) -> Smb2FioResult<()> {
        let oldpath = self.prepare_path(oldname)?;
        let newpath = self.prepare_path(newname)?;
        let (old_context, _old_remainder) = self.find_context(&oldpath)?;
        let (new_context, _new_remainder) = self.find_context(&newpath)?;
        if old_context != new_context {
            return Err(Smb2FioError::InvalidInput);
        }
        Err(Smb2FioError::Io)
    }

    /// Mirrors `SMB2_chdir` by storing the prepared current directory path.
    pub fn chdir(&mut self, dirname: &str) -> Smb2FioResult<()> {
        let path = self.prepare_path(dirname)?;
        if !path.is_empty() {
            let _resolved = self.find_context(&path)?;
        }
        self.curdir = Some(path);
        Ok(())
    }

    /// Mirrors `SMB2_dummy` for unsupported operation table slots.
    pub const fn dummy(&self) -> Smb2FioResult<()> {
        Err(Smb2FioError::Io)
    }

    /// Returns registered virtual shares in the same newest-first order as C.
    #[must_use]
    pub fn shares(&self) -> &[Smb2Share] {
        &self.shares
    }

    /// Returns the prepared current directory, if `chdir` has been called.
    #[must_use]
    pub fn curdir(&self) -> Option<&str> {
        self.curdir.as_deref()
    }

    /// Returns the modeled device state.
    #[must_use]
    pub const fn state(&self) -> Smb2DeviceState {
        self.state
    }

    /// Returns the number of active handles tracked by the skeleton.
    #[must_use]
    pub fn handle_count(&self) -> usize {
        self.handles.iter().flatten().count()
    }

    /// Prepares a path following the C `prepare_path` normalization rules.
    pub fn prepare_path(&self, path: &str) -> Smb2FioResult<String> {
        let mut source = path.replace('\\', "/");
        if let Some(stripped) = source.strip_prefix("smb:") {
            source = stripped.trim_start_matches('/').to_owned();
        }

        let mut combined = String::new();
        if !source.starts_with('/') {
            if let Some(curdir) = &self.curdir {
                if !curdir.is_empty() {
                    combined.push_str(curdir);
                    combined.push('/');
                }
            }
        }
        combined.push_str(source.trim_start_matches('/'));

        let mut components: Vec<&str> = Vec::new();
        for component in combined.split('/') {
            match component {
                "" | "." => {}
                ".." => {
                    if components.pop().is_none() {
                        return Err(Smb2FioError::NoEntry);
                    }
                }
                value => components.push(value),
            }
        }

        Ok(components.join("/"))
    }

    fn find_context<'a>(&'a self, path: &'a str) -> Smb2FioResult<(Smb2ContextId, &'a str)> {
        let (share_name, remainder) = match path.split_once('/') {
            Some(parts) => parts,
            None => (path, ""),
        };
        if share_name.is_empty() {
            return Err(Smb2FioError::NoEntry);
        }
        self.shares
            .iter()
            .find(|share| share.name == share_name)
            .map(|share| (share.context, remainder))
            .ok_or(Smb2FioError::NoEntry)
    }

    fn ensure_initialized(&self) -> Smb2FioResult<()> {
        if self.state == Smb2DeviceState::Initialized {
            Ok(())
        } else {
            Err(Smb2FioError::Io)
        }
    }

    fn insert_handle(&mut self, record: Smb2HandleRecord) -> Smb2HandleId {
        if let Some((index, slot)) = self
            .handles
            .iter_mut()
            .enumerate()
            .find(|(_index, slot)| slot.is_none())
        {
            *slot = Some(record);
            return Smb2HandleId(index);
        }

        self.handles.push(Some(record));
        Smb2HandleId(self.handles.len() - 1)
    }

    fn remove_handle(
        &mut self,
        handle_id: Option<Smb2HandleId>,
        expect_file: bool,
    ) -> Smb2FioResult<()> {
        let handle_id = handle_id.ok_or(Smb2FioError::BadFileDescriptor)?;
        let Some(slot) = self.handles.get_mut(handle_id.0) else {
            return Err(Smb2FioError::BadFileDescriptor);
        };
        let Some(record) = slot.take() else {
            return Err(Smb2FioError::BadFileDescriptor);
        };
        let matches_kind = matches!(
            (expect_file, record),
            (true, Smb2HandleRecord::File(_)) | (false, Smb2HandleRecord::Directory(_))
        );
        if matches_kind {
            Ok(())
        } else {
            Err(Smb2FioError::BadFileDescriptor)
        }
    }

    fn update_file_handle(
        &mut self,
        handle_id: Option<Smb2HandleId>,
        handle: Smb2FileHandle,
    ) -> Smb2FioResult<()> {
        let handle_id = handle_id.ok_or(Smb2FioError::BadFileDescriptor)?;
        let Some(slot) = self.handles.get_mut(handle_id.0) else {
            return Err(Smb2FioError::BadFileDescriptor);
        };
        match slot {
            Some(Smb2HandleRecord::File(record)) => {
                *record = handle;
                Ok(())
            }
            _ => Err(Smb2FioError::BadFileDescriptor),
        }
    }

    fn find_file_index(&self, context: Smb2ContextId, path: &str) -> Option<usize> {
        self.files
            .iter()
            .position(|file| file.context == context && file.path == path)
    }

    fn ensure_file(&mut self, context: Smb2ContextId, path: &str) -> usize {
        if let Some(index) = self.find_file_index(context, path) {
            return index;
        }
        self.files.push(Smb2LocalFile {
            context,
            path: path.to_owned(),
            data: Vec::new(),
        });
        self.files.len() - 1
    }

    fn local_stat(&self, context: Smb2ContextId, path: &str) -> Smb2FioResult<IoxStat> {
        if path.is_empty() {
            return Ok(IoxStat {
                mode: FIO_S_IFDIR,
                ..IoxStat::default()
            });
        }
        if let Some(file) = self
            .files
            .iter()
            .find(|file| file.context == context && file.path == path)
        {
            let size = file.data.len() as u64;
            return Ok(IoxStat {
                size: (size & 0xffff_ffff) as u32,
                hisize: ((size >> 32) & 0xffff_ffff) as u32,
                mode: FIO_S_IFREG,
                ..IoxStat::default()
            });
        }
        let prefix = format!("{path}/");
        if self
            .files
            .iter()
            .any(|file| file.context == context && file.path.starts_with(&prefix))
        {
            Ok(IoxStat {
                mode: FIO_S_IFDIR,
                ..IoxStat::default()
            })
        } else {
            Err(Smb2FioError::NoEntry)
        }
    }

    fn local_dir_entries(
        &self,
        context: Smb2ContextId,
        path: &str,
    ) -> Smb2FioResult<VecDeque<IoxDirent>> {
        if !path.is_empty() {
            self.local_stat(context, path)?;
        }
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{path}/")
        };
        let mut entries = VecDeque::new();
        let mut seen = Vec::new();
        for file in self.files.iter().filter(|file| file.context == context) {
            let Some(rest) = file.path.strip_prefix(&prefix) else {
                continue;
            };
            if rest.is_empty() {
                continue;
            }
            let (name, is_directory) = match rest.split_once('/') {
                Some((name, _tail)) => (name, true),
                None => (rest, false),
            };
            if seen.iter().any(|existing: &String| existing == name) {
                continue;
            }
            seen.push(name.to_owned());
            entries.push_back(IoxDirent {
                name: name.to_owned(),
                stat: IoxStat {
                    mode: if is_directory {
                        FIO_S_IFDIR
                    } else {
                        FIO_S_IFREG
                    },
                    size: if is_directory {
                        0
                    } else {
                        file.data.len() as u32
                    },
                    ..IoxStat::default()
                },
            });
        }
        Ok(entries)
    }
}

/// Seek origin values corresponding to `SMB2_lseek` and `SMB2_lseek64`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeekWhence {
    /// Seek from the start of the file.
    Set,
    /// Seek from the current file position.
    Current,
    /// Seek from the end of the file; size lookup is backend-defined later.
    End,
}

/// Converts an SMB FILETIME value to the PS2 date/time byte layout.
#[must_use]
pub fn file_time_to_date(ticks: u64) -> FileTimeDate {
    let mut days_per_month = [31_u16, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut time = ticks / 10_000_000;
    let mut years = (time / (60 * 60 * 24 * 365)) as u16;
    time -= u64::from(years) * 60 * 60 * 24 * 365;

    let leapdays = (years / 4) - (years / 100) + (years / 400);
    years = years.saturating_add(1601);

    let mut days = (time / (60 * 60 * 24)) as u16;
    time -= u64::from(days) * 60 * 60 * 24;
    days = days.saturating_sub(leapdays);

    if years.is_multiple_of(4) && (!years.is_multiple_of(100) || years.is_multiple_of(400)) {
        days_per_month[1] += 1;
    }

    let mut months = 0_u8;
    for days_in_month in days_per_month {
        if days > days_in_month {
            days -= days_in_month;
            months = months.saturating_add(1);
        } else {
            break;
        }
    }

    if months >= 12 {
        months -= 12;
        years = years.saturating_add(1);
    }

    let hours = (time / (60 * 60)) as u8;
    time -= u64::from(hours) * 60 * 60;
    let minutes = (time / 60) as u8;
    time -= u64::from(minutes) * 60;

    FileTimeDate {
        reserved: 0,
        seconds: time as u8,
        minutes,
        hours,
        day: days.saturating_add(1) as u8,
        month: months.saturating_add(1),
        year: years,
    }
}

/// Fills an `IoxStat` value from the SMB2 stat subset consumed by `smb2_statFiller`.
#[must_use]
pub fn smb2_stat_filler(stat: &Smb2Stat64) -> IoxStat {
    IoxStat {
        ctime: file_time_to_date(stat.ctime).to_iox_bytes(),
        atime: file_time_to_date(stat.atime).to_iox_bytes(),
        mtime: file_time_to_date(stat.mtime).to_iox_bytes(),
        size: (stat.size & 0xffff_ffff) as u32,
        hisize: ((stat.size >> 32) & 0xffff_ffff) as u32,
        mode: if stat.is_directory {
            FIO_S_IFDIR
        } else {
            FIO_S_IFREG
        },
    }
}
