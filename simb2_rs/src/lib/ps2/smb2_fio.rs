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

/// Read/write open flag rejected by the current C `SMB2_open` implementation.
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

/// In-memory skeleton for the PS2 SMB2 file I/O device operations table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Smb2Fio {
    shares: Vec<Smb2Share>,
    curdir: Option<String>,
    next_context: usize,
    initialized: bool,
}

impl Smb2Fio {
    /// Creates an empty PS2 SMB2 file I/O skeleton.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            shares: Vec::new(),
            curdir: None,
            next_context: 0,
            initialized: false,
        }
    }

    /// Mirrors `SMB2_init` by marking the skeleton as initialized.
    pub fn init(&mut self, _dev: &mut IopDevice) -> Smb2FioResult<()> {
        self.initialized = true;
        Ok(())
    }

    /// Mirrors `SMB2_deinit` by clearing initialization-only state.
    pub fn deinit(&mut self, _dev: &mut IopDevice) -> Smb2FioResult<()> {
        self.initialized = false;
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
        if input.name.is_empty() || input.name.len() >= SMB2_MAX_NAME_LEN || input.url.is_empty() {
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

    /// Mirrors `SMB2_open` path selection and read-only policy.
    pub fn open(
        &self,
        file: &mut IopFile,
        filename: &str,
        flags: i32,
        _mode: i32,
    ) -> Smb2FioResult<()> {
        if flags != O_RDONLY {
            return Err(Smb2FioError::ReadOnlyFileSystem);
        }
        let prepared = self.prepare_path(filename)?;
        let (context, path) = self.find_context(&prepared)?;
        file.privdata = Some(Smb2PrivData::File(Smb2FileHandle {
            context,
            path: path.to_owned(),
            flags,
            position: 0,
        }));
        Ok(())
    }

    /// Mirrors `SMB2_close` by dropping file private data.
    pub fn close(&self, file: &mut IopFile) -> Smb2FioResult<()> {
        match file.privdata.take() {
            Some(Smb2PrivData::File(_)) => Ok(()),
            Some(other) => {
                file.privdata = Some(other);
                Err(Smb2FioError::BadFileDescriptor)
            }
            None => Err(Smb2FioError::BadFileDescriptor),
        }
    }

    /// Mirrors `SMB2_dopen` by preparing a directory handle or virtual-root iterator.
    pub fn dopen(&self, file: &mut IopFile, dirname: &str) -> Smb2FioResult<()> {
        let prepared = self.prepare_path(dirname)?;
        if prepared.is_empty() {
            file.privdata = Some(Smb2PrivData::Directory(Smb2DirHandle {
                context: Smb2ContextId(0),
                path: String::new(),
                is_root: true,
                shares: self.shares.iter().map(|share| share.name.clone()).collect(),
            }));
            return Ok(());
        }

        let (context, path) = self.find_context(&prepared)?;
        file.privdata = Some(Smb2PrivData::Directory(Smb2DirHandle {
            context,
            path: path.to_owned(),
            is_root: path.is_empty(),
            shares: self.shares.iter().map(|share| share.name.clone()).collect(),
        }));
        Ok(())
    }

    /// Mirrors `SMB2_dclose` by dropping directory private data.
    pub fn dclose(&self, file: &mut IopFile) -> Smb2FioResult<()> {
        match file.privdata.take() {
            Some(Smb2PrivData::Directory(_)) => Ok(()),
            Some(other) => {
                file.privdata = Some(other);
                Err(Smb2FioError::BadFileDescriptor)
            }
            None => Err(Smb2FioError::BadFileDescriptor),
        }
    }

    /// Mirrors `SMB2_dread`; only virtual-root share enumeration is modeled.
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
            Some(Smb2PrivData::Directory(_)) => Ok(None),
            _ => Err(Smb2FioError::BadFileDescriptor),
        }
    }

    /// Mirrors `SMB2_getstat` path validation and returns an empty stat skeleton.
    pub fn getstat(&self, filename: &str) -> Smb2FioResult<IoxStat> {
        let prepared = self.prepare_path(filename)?;
        let _resolved = self.find_context(&prepared)?;
        Ok(IoxStat::default())
    }

    /// Mirrors `SMB2_lseek64` by updating the skeleton file offset.
    pub fn lseek64(&self, file: &mut IopFile, pos: i64, whence: SeekWhence) -> Smb2FioResult<i64> {
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
                Ok(next)
            }
            _ => Err(Smb2FioError::BadFileDescriptor),
        }
    }

    /// Mirrors `SMB2_lseek` using a 32-bit position argument.
    pub fn lseek(&self, file: &mut IopFile, pos: i32, whence: SeekWhence) -> Smb2FioResult<i32> {
        let next = self.lseek64(file, i64::from(pos), whence)?;
        i32::try_from(next).map_err(|_err| Smb2FioError::InvalidInput)
    }

    /// Mirrors `SMB2_read`; platform I/O is intentionally not implemented.
    pub fn read(&self, file: &IopFile, _buf: &mut [u8]) -> Smb2FioResult<usize> {
        match file.privdata {
            Some(Smb2PrivData::File(_)) => Err(Smb2FioError::Io),
            _ => Err(Smb2FioError::BadFileDescriptor),
        }
    }

    /// Mirrors `SMB2_write`; platform I/O is intentionally not implemented.
    pub fn write(&self, file: &IopFile, _buf: &[u8]) -> Smb2FioResult<usize> {
        match file.privdata {
            Some(Smb2PrivData::File(_)) => Err(Smb2FioError::Io),
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

    /// Prepares a path following the C `prepare_path` normalization rules.
    pub fn prepare_path(&self, path: &str) -> Smb2FioResult<String> {
        let mut prepared = String::new();
        if let Some(curdir) = &self.curdir {
            if !curdir.is_empty() {
                prepared.push_str(curdir);
                prepared.push('/');
            }
        }
        prepared.push_str(path);
        prepared = prepared.replace('\\', "/");

        if prepared.len() > 2 && prepared.ends_with("/.") {
            prepared.truncate(prepared.len() - 2);
        }

        if prepared.len() > 3 && prepared.ends_with("/..") {
            prepared.truncate(prepared.len() - 3);
            if let Some(index) = prepared.rfind('/') {
                prepared.truncate(index);
            } else {
                return Err(Smb2FioError::NoEntry);
            }
        }

        Ok(prepared)
    }

    fn find_context<'a>(&'a self, path: &'a str) -> Smb2FioResult<(Smb2ContextId, &'a str)> {
        let Some((share_name, remainder)) = path.split_once('/') else {
            return Err(Smb2FioError::NoEntry);
        };
        self.shares
            .iter()
            .find(|share| share.name == share_name)
            .map(|share| (share.context, remainder))
            .ok_or(Smb2FioError::NoEntry)
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
