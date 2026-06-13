//! Safe Rust-facing API skeleton for `include/smb2/libsmb2.h`.
//!
//! The items in this module mirror the public responsibilities of the C header:
//! context configuration, event-loop integration, URL parsing, file and
//! directory operation request shapes, notification state, and server-side
//! dispatch records. They intentionally do not implement SMB2 transport or wire
//! protocol behavior.

use std::ffi::CString;
use std::os::raw::c_void;

/// Crate-local result type for SMB2 operations.
pub type Result<T> = std::result::Result<T, ErrorCode>;

/// Negative errno-style error code returned by the legacy API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCode(pub i32);

/// Error code used when a string cannot be represented as a C string.
pub const EINVAL: i32 = -22;

/// Version marker for SRVSVC share enumeration compatibility.
pub const LIBSMB2_SHARE_ENUM_V2: u32 = 1;

/// File type constant for a regular file.
pub const SMB2_TYPE_FILE: u32 = 0x0000_0000;

/// File type constant for a directory.
pub const SMB2_TYPE_DIRECTORY: u32 = 0x0000_0001;

/// File type constant for a symbolic link or reparse point.
pub const SMB2_TYPE_LINK: u32 = 0x0000_0002;

/// Event callback command indicating a file descriptor was added.
pub const SMB2_ADD_FD: i32 = 0;

/// Event callback command indicating a file descriptor was removed.
pub const SMB2_DEL_FD: i32 = 1;

/// Wildcard dialect value used while negotiating SMB2 dialects.
pub const SMB2_VERSION_WILDCARD: u16 = 0x02ff;

/// Major version of the mirrored libsmb2 C API.
pub const LIBSMB2_MAJOR_VERSION: u8 = 4;

/// Minor version of the mirrored libsmb2 C API.
pub const LIBSMB2_MINOR_VERSION: u8 = 0;

/// Patch version of the mirrored libsmb2 C API.
pub const LIBSMB2_PATCH_VERSION: u8 = 0;

/// Size in bytes of SMB2 GUID values.
pub const SMB2_GUID_SIZE: usize = 16;

/// Size in bytes of SMB2 file identifiers.
pub const SMB2_FILE_ID_SIZE: usize = 16;

/// Default maximum read size used by the skeleton before negotiation completes.
pub const DEFAULT_MAX_READ_SIZE: u32 = 0;

/// Default maximum write size used by the skeleton before negotiation completes.
pub const DEFAULT_MAX_WRITE_SIZE: u32 = 0;

/// Socket descriptor type corresponding to `t_socket` on non-Windows platforms.
pub type Socket = i32;

/// Callback shape for freeing caller-owned buffers associated with an I/O vector.
pub type FreeCallback = Box<dyn FnOnce(*mut c_void) + Send + 'static>;

/// Completion callback shape for asynchronous operations.
pub type CommandCallback = Box<dyn FnOnce(&mut Smb2Client, Result<*mut c_void>) + Send + 'static>;

/// Error callback shape used when the context error string changes.
pub type ErrorCallback = Box<dyn Fn(&Smb2Client, &str) + Send + Sync + 'static>;

/// Callback shape for accepting a new server-side connection.
pub type AcceptedCallback = Box<dyn Fn(Socket, *mut c_void) -> i32 + Send + Sync + 'static>;

/// Callback shape invoked when a server creates a client context for a connection.
pub type ClientConnectionCallback = Box<dyn Fn(&mut Smb2Client, *mut c_void) + Send + 'static>;

/// Callback shape for file-descriptor add/remove notifications.
pub type ChangeFdCallback = Box<dyn Fn(&Smb2Client, Socket, i32) + Send + Sync + 'static>;

/// Callback shape for file-descriptor event-mask changes.
pub type ChangeEventsCallback = Box<dyn Fn(&Smb2Client, Socket, i32) + Send + Sync + 'static>;

/// Callback shape for oplock or lease-break notifications.
pub type OplockOrLeaseBreakCallback = Box<dyn Fn(&mut Smb2Client, OplockOrLeaseBreak) + Send>;

/// Rust representation of `struct smb2_iovec` ownership responsibilities.
pub struct Smb2Iovec {
    /// Data buffer referenced by the vector.
    pub buffer: Vec<u8>,
    /// Optional release callback preserved for FFI-oriented callers.
    pub free: Option<FreeCallback>,
}

impl Smb2Iovec {
    /// Creates an I/O vector skeleton from owned bytes.
    #[must_use]
    pub const fn new(buffer: Vec<u8>) -> Self {
        Self { buffer, free: None }
    }

    /// Returns the visible byte length of the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns whether the I/O vector contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl std::fmt::Debug for Smb2Iovec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Smb2Iovec")
            .field("buffer", &self.buffer)
            .field("has_free", &self.free.is_some())
            .finish()
    }
}

/// File type reported by `smb2_stat_64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link or reparse point.
    Link,
    /// Unknown legacy value.
    Unknown(u32),
}

impl FileType {
    /// Converts the C `SMB2_TYPE_*` value into a Rust file type.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            SMB2_TYPE_FILE => Self::File,
            SMB2_TYPE_DIRECTORY => Self::Directory,
            SMB2_TYPE_LINK => Self::Link,
            other => Self::Unknown(other),
        }
    }

    /// Converts this file type back to the C `SMB2_TYPE_*` value.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::File => SMB2_TYPE_FILE,
            Self::Directory => SMB2_TYPE_DIRECTORY,
            Self::Link => SMB2_TYPE_LINK,
            Self::Unknown(raw) => raw,
        }
    }
}

/// Rust representation of `struct smb2_stat_64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    /// SMB2 file type.
    pub file_type: FileType,
    /// Link count.
    pub nlink: u32,
    /// File identifier.
    pub ino: u64,
    /// File size in bytes.
    pub size: u64,
    /// Access time seconds.
    pub atime: u64,
    /// Access time nanoseconds.
    pub atime_nsec: u64,
    /// Modification time seconds.
    pub mtime: u64,
    /// Modification time nanoseconds.
    pub mtime_nsec: u64,
    /// Change time seconds.
    pub ctime: u64,
    /// Change time nanoseconds.
    pub ctime_nsec: u64,
    /// Birth time seconds.
    pub btime: u64,
    /// Birth time nanoseconds.
    pub btime_nsec: u64,
}

/// Rust representation of `struct smb2_statvfs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatVfs {
    /// Filesystem block size.
    pub block_size: u32,
    /// Fragment size.
    pub fragment_size: u32,
    /// Total block count.
    pub blocks: u64,
    /// Free block count.
    pub blocks_free: u64,
    /// Available block count.
    pub blocks_available: u64,
    /// Total file node count.
    pub files: u32,
    /// Free file node count.
    pub files_free: u32,
    /// Available file node count.
    pub files_available: u32,
    /// Filesystem id.
    pub filesystem_id: u32,
    /// Filesystem flags.
    pub flags: u32,
    /// Maximum filename length.
    pub name_max: u32,
}

/// Directory entry returned by `smb2_readdir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// Entry name.
    pub name: String,
    /// Entry metadata.
    pub stat: Stat,
}

/// SMB dialect selector used by `smb2_set_version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiateVersion {
    /// Let the server pick any supported dialect.
    Any,
    /// Let the server pick any SMB2 dialect.
    Any2,
    /// Let the server pick any SMB3 dialect.
    Any3,
    /// SMB 2.0.2 dialect.
    V0202,
    /// SMB 2.1 dialect.
    V0210,
    /// SMB 3.0 dialect.
    V0300,
    /// SMB 3.0.2 dialect.
    V0302,
    /// SMB 3.1.1 dialect.
    V0311,
    /// Unknown or future dialect selector.
    Unknown(u16),
}

impl NegotiateVersion {
    /// Converts a C `enum smb2_negotiate_version` value into Rust.
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        match raw {
            0 => Self::Any,
            2 => Self::Any2,
            3 => Self::Any3,
            0x0202 => Self::V0202,
            0x0210 => Self::V0210,
            0x0300 => Self::V0300,
            0x0302 => Self::V0302,
            0x0311 => Self::V0311,
            other => Self::Unknown(other),
        }
    }

    /// Converts this version selector to the C enum value.
    #[must_use]
    pub const fn as_raw(self) -> u16 {
        match self {
            Self::Any => 0,
            Self::Any2 => 2,
            Self::Any3 => 3,
            Self::V0202 => 0x0202,
            Self::V0210 => 0x0210,
            Self::V0300 => 0x0300,
            Self::V0302 => 0x0302,
            Self::V0311 => 0x0311,
            Self::Unknown(raw) => raw,
        }
    }
}

/// Authentication method selector corresponding to `enum smb2_sec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationMethod {
    /// Let libsmb2 choose Kerberos when available, otherwise NTLMSSP.
    Undefined,
    /// Use NTLMSSP authentication.
    NtlmSsp,
    /// Use Kerberos authentication.
    Krb5,
}

impl Default for AuthenticationMethod {
    fn default() -> Self {
        Self::Undefined
    }
}

/// Linked libsmb2 version information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LibVersion {
    /// Major version component.
    pub major_version: u8,
    /// Minor version component.
    pub minor_version: u8,
    /// Patch version component.
    pub patch_version: u8,
}

impl LibVersion {
    /// Version value mirrored from the C header constants.
    pub const CURRENT: Self = Self {
        major_version: LIBSMB2_MAJOR_VERSION,
        minor_version: LIBSMB2_MINOR_VERSION,
        patch_version: LIBSMB2_PATCH_VERSION,
    };
}

/// Time value used by timestamp conversion helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeVal {
    /// Seconds since the Unix epoch.
    pub seconds: i64,
    /// Microseconds within the current second.
    pub microseconds: i64,
}

/// Parsed SMB2 URL fields from `smb2_parse_url`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2Url {
    /// Optional authentication domain.
    pub domain: Option<String>,
    /// Optional username.
    pub user: Option<String>,
    /// Server name or address.
    pub server: String,
    /// Share name.
    pub share: String,
    /// Optional path within the share.
    pub path: Option<String>,
}

/// Opaque file handle corresponding to `struct smb2fh`.
#[derive(Debug)]
pub struct FileHandle {
    pub(crate) id: [u8; SMB2_FILE_ID_SIZE],
    pub(crate) offset: u64,
}

impl FileHandle {
    /// Creates a file handle placeholder from a raw SMB2 file id.
    #[must_use]
    pub fn new(id: [u8; SMB2_FILE_ID_SIZE]) -> Self {
        Self { id, offset: 0 }
    }

    /// Returns the raw SMB2 file id.
    #[must_use]
    pub fn id(&self) -> [u8; SMB2_FILE_ID_SIZE] {
        self.id
    }

    /// Returns the current cached file offset.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

/// Opaque directory handle corresponding to `struct smb2dir`.
#[derive(Debug)]
pub struct DirectoryHandle {
    pub(crate) id: [u8; SMB2_FILE_ID_SIZE],
    pub(crate) index: usize,
}

impl DirectoryHandle {
    /// Creates a directory handle placeholder from a raw SMB2 file id.
    #[must_use]
    pub fn new(id: [u8; SMB2_FILE_ID_SIZE]) -> Self {
        Self { id, index: 0 }
    }

    /// Returns the raw SMB2 file id.
    #[must_use]
    pub fn id(&self) -> [u8; SMB2_FILE_ID_SIZE] {
        self.id
    }

    /// Returns the current directory entry index.
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }
}

/// Opaque protocol data unit corresponding to `struct smb2_pdu`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PduHandle {
    /// Optional tree id associated with the PDU.
    pub tree_id: Option<u32>,
    /// Optional SMB2 message id associated with the PDU.
    pub message_id: Option<u64>,
    /// Last completion status assigned to the PDU.
    pub status: i32,
    /// Whether this PDU belongs to a compound chain.
    pub is_compound: bool,
}

/// Read callback data corresponding to `struct smb2_read_cb_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadCallbackData {
    /// File identifier being read.
    pub file_id: [u8; SMB2_FILE_ID_SIZE],
    /// Caller-provided buffer length.
    pub count: u32,
    /// File offset used by the read.
    pub offset: u64,
}

/// Write callback data corresponding to `struct smb2_write_cb_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteCallbackData {
    /// File identifier being written.
    pub file_id: [u8; SMB2_FILE_ID_SIZE],
    /// Caller-provided byte count.
    pub count: u32,
    /// File offset used by the write.
    pub offset: u64,
}

/// Lease key passed to open-with-lease operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeaseKey(pub [u8; SMB2_GUID_SIZE]);

/// Oplock or lease break acknowledgement selected by a callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OplockOrLeaseBreak {
    /// Legacy status value for the break notification.
    pub status: i32,
    /// New oplock level requested by the application.
    pub new_oplock_level: Option<u8>,
    /// New lease state requested by the application.
    pub new_lease_state: Option<u32>,
}

/// UTF-16 string container corresponding to `struct smb2_utf16`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utf16String {
    /// UTF-16 code units in little-endian SMB order.
    pub value: Vec<u16>,
}

impl Utf16String {
    /// Creates a UTF-16 skeleton value from code units.
    #[must_use]
    pub const fn new(value: Vec<u16>) -> Self {
        Self { value }
    }

    /// Returns the number of UTF-16 code units.
    #[must_use]
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Returns whether the UTF-16 string has no code units.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

/// One file notification entry returned by CHANGE_NOTIFY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileNotifyChangeInformation {
    /// Action code reported by the server.
    pub action: u32,
    /// File name associated with the action.
    pub name: String,
}

/// Generic operation request mirrored from the public libsmb2 functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Smb2Operation {
    /// Connect the TCP transport to a server.
    Connect { server: String },
    /// Connect to a share on a server.
    ConnectShare {
        /// Server name or address.
        server: String,
        /// Share name.
        share: String,
        /// Optional user name.
        user: Option<String>,
    },
    /// Disconnect from the current share.
    DisconnectShare,
    /// Open a directory path.
    OpenDir { path: String },
    /// Open or create a file path.
    Open {
        /// Path relative to the share.
        path: String,
        /// POSIX-style open flags from the caller.
        flags: i32,
        /// Requested oplock level.
        oplock_level: Option<u8>,
        /// Requested lease state.
        lease_state: Option<u32>,
        /// Requested lease key.
        lease_key: Option<LeaseKey>,
    },
    /// Close a file handle.
    Close { file_id: [u8; SMB2_FILE_ID_SIZE] },
    /// Flush a file handle.
    Fsync { file_id: [u8; SMB2_FILE_ID_SIZE] },
    /// Read from a file handle.
    Read {
        /// File id to read from.
        file_id: [u8; SMB2_FILE_ID_SIZE],
        /// Byte count requested.
        count: u32,
        /// Absolute file offset.
        offset: Option<u64>,
    },
    /// Write to a file handle.
    Write {
        /// File id to write to.
        file_id: [u8; SMB2_FILE_ID_SIZE],
        /// Byte count requested.
        count: u32,
        /// Absolute file offset.
        offset: Option<u64>,
    },
    /// Seek a file handle.
    Lseek {
        /// File id to seek.
        file_id: [u8; SMB2_FILE_ID_SIZE],
        /// Offset argument.
        offset: i64,
        /// `SEEK_*` selector.
        whence: i32,
    },
    /// Remove a file path.
    Unlink { path: String },
    /// Remove a directory path.
    Rmdir { path: String },
    /// Create a directory path.
    Mkdir { path: String },
    /// Query filesystem metadata.
    StatVfs { path: String },
    /// Query file-handle metadata.
    Fstat { file_id: [u8; SMB2_FILE_ID_SIZE] },
    /// Query path metadata.
    Stat { path: String },
    /// Rename a path.
    Rename { old_path: String, new_path: String },
    /// Truncate a path.
    Truncate { path: String, length: u64 },
    /// Truncate a file handle.
    Ftruncate {
        /// File id to truncate.
        file_id: [u8; SMB2_FILE_ID_SIZE],
        /// New length.
        length: u64,
    },
    /// Read a symbolic link target.
    Readlink { path: String, buffer_size: u32 },
    /// Send an SMB2 echo request.
    Echo,
    /// Watch a path for changes.
    NotifyChange {
        /// Path to watch.
        path: String,
        /// Watch flags.
        flags: u16,
        /// Completion filter.
        filter: u32,
        /// Whether the watch loops.
        repeat: bool,
    },
    /// Watch an already-open directory handle for changes.
    NotifyChangeFileHandle {
        /// Directory file id to watch.
        file_id: [u8; SMB2_FILE_ID_SIZE],
        /// Watch flags.
        flags: u16,
        /// Completion filter.
        filter: u32,
        /// Whether the watch loops.
        repeat: bool,
    },
}

/// File-descriptor event callback registrations.
#[derive(Default)]
pub struct FdEventCallbacks {
    /// Callback invoked when a descriptor is added or removed.
    pub change_fd: Option<ChangeFdCallback>,
    /// Callback invoked when an event mask changes.
    pub change_events: Option<ChangeEventsCallback>,
}

impl std::fmt::Debug for FdEventCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FdEventCallbacks")
            .field("has_change_fd", &self.change_fd.is_some())
            .field("has_change_events", &self.change_events.is_some())
            .finish()
    }
}

/// Server-side handler result matching the C convention of negative, zero, or positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerHandlerResult {
    /// Handler failed; the library should create an error reply.
    Error(i32),
    /// Handler succeeded; the library should build a reply from output state.
    Ok,
    /// Handler already created and queued a reply.
    ReplyQueued(i32),
}

/// Server-side request kind from `struct smb2_server_request_handlers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRequestKind {
    /// Context destruction event.
    DestructionEvent,
    /// User authorization hook.
    AuthorizeUser,
    /// Session-established hook.
    SessionEstablished,
    /// LOGOFF command.
    Logoff,
    /// TREE_CONNECT command.
    TreeConnect,
    /// TREE_DISCONNECT command.
    TreeDisconnect,
    /// CREATE command.
    Create,
    /// CLOSE command.
    Close,
    /// FLUSH command.
    Flush,
    /// READ command.
    Read,
    /// WRITE command.
    Write,
    /// OPLOCK_BREAK acknowledgement command.
    OplockBreak,
    /// LEASE_BREAK acknowledgement command.
    LeaseBreak,
    /// LOCK command.
    Lock,
    /// IOCTL command.
    Ioctl,
    /// CANCEL command.
    Cancel,
    /// ECHO command.
    Echo,
    /// QUERY_DIRECTORY command.
    QueryDirectory,
    /// CHANGE_NOTIFY command.
    ChangeNotify,
    /// QUERY_INFO command.
    QueryInfo,
    /// SET_INFO command.
    SetInfo,
}

/// Server-side dispatch record carrying the command kind and optional ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerRequest {
    /// Request kind being dispatched.
    pub kind: ServerRequestKind,
    /// Tree id associated with the command, when known.
    pub tree_id: Option<u32>,
    /// Message id associated with the command, when known.
    pub message_id: Option<u64>,
}

/// Server configuration corresponding to `struct smb2_server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2Server {
    /// Server GUID.
    pub guid: [u8; SMB2_GUID_SIZE],
    /// Hostname advertised by the server.
    pub hostname: String,
    /// Authentication domain advertised by the server.
    pub domain: String,
    /// Listening socket descriptor.
    pub fd: Socket,
    /// Listening port.
    pub port: u16,
    /// Monotonic session counter used by the server skeleton.
    pub session_counter: u64,
    /// Maximum transact size advertised by the server.
    pub max_transact_size: u32,
    /// Maximum read size advertised by the server.
    pub max_read_size: u32,
    /// Maximum write size advertised by the server.
    pub max_write_size: u32,
    /// Whether signing is enabled for server sessions.
    pub signing_enabled: bool,
    /// Whether anonymous authentication is allowed.
    pub allow_anonymous: bool,
    /// Whether authentication may be delegated to a proxy client.
    pub proxy_authentication: bool,
    /// Capabilities saved from negotiation.
    pub capabilities: u32,
    /// Security mode saved from negotiation.
    pub security_mode: u32,
    /// Optional Kerberos keytab path.
    pub keytab_path: Option<String>,
    /// Last server-side error string.
    pub error: Option<String>,
    /// Opaque authentication data address-sized value.
    pub auth_data: Option<usize>,
}

impl Default for Smb2Server {
    fn default() -> Self {
        Self {
            guid: [0; SMB2_GUID_SIZE],
            hostname: String::new(),
            domain: String::new(),
            fd: -1,
            port: 0,
            session_counter: 0,
            max_transact_size: 0,
            max_read_size: 0,
            max_write_size: 0,
            signing_enabled: false,
            allow_anonymous: false,
            proxy_authentication: false,
            capabilities: 0,
            security_mode: 0,
            keytab_path: None,
            error: None,
            auth_data: None,
        }
    }
}

/// High-level SMB2 client context corresponding to `struct smb2_context`.
#[derive(Debug)]
pub struct Smb2Client {
    server: Option<String>,
    share: Option<String>,
    user: Option<String>,
    domain: Option<String>,
    workstation: Option<String>,
    password: Option<CString>,
    opaque: Option<usize>,
    timeout_seconds: i32,
    passthrough: bool,
    version: NegotiateVersion,
    dialect: u16,
    security_mode: u16,
    seal: bool,
    sign: bool,
    authentication: AuthenticationMethod,
    client_guid: Option<[u8; SMB2_GUID_SIZE]>,
    error_string: Option<String>,
    nterror: i32,
    fd: Socket,
    fds: Vec<Socket>,
    events: i32,
    fd_event_callbacks: FdEventCallbacks,
    active: bool,
    session_id: Option<u64>,
    tree_id: Option<u32>,
    last_request_message_id: u64,
    last_reply_message_id: u64,
    max_read_size: u32,
    max_write_size: u32,
    queued_operations: Vec<Smb2Operation>,
}

impl Default for Smb2Client {
    fn default() -> Self {
        Self {
            server: None,
            share: None,
            user: None,
            domain: None,
            workstation: None,
            password: None,
            opaque: None,
            timeout_seconds: 0,
            passthrough: false,
            version: NegotiateVersion::Any,
            dialect: 0,
            security_mode: 0,
            seal: false,
            sign: false,
            authentication: AuthenticationMethod::Undefined,
            client_guid: None,
            error_string: None,
            nterror: 0,
            fd: -1,
            fds: Vec::new(),
            events: 0,
            fd_event_callbacks: FdEventCallbacks::default(),
            active: true,
            session_id: None,
            tree_id: None,
            last_request_message_id: 0,
            last_reply_message_id: 0,
            max_read_size: DEFAULT_MAX_READ_SIZE,
            max_write_size: DEFAULT_MAX_WRITE_SIZE,
            queued_operations: Vec::new(),
        }
    }
}

impl Smb2Client {
    /// Creates an empty SMB2 client context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the context as closed while leaving allocated state available.
    pub fn close_context(&mut self) {
        self.fd = -1;
        self.fds.clear();
        self.events = 0;
    }

    /// Marks the context as destroyed and clears queued operation skeletons.
    pub fn destroy_context(&mut self) {
        self.close_context();
        self.active = false;
        self.queued_operations.clear();
    }

    /// Returns whether the context is currently active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the primary socket descriptor used by the context skeleton.
    #[must_use]
    pub const fn fd(&self) -> Socket {
        self.fd
    }

    /// Replaces the primary socket descriptor used by event-loop integration tests.
    pub fn set_fd(&mut self, fd: Socket) {
        self.fd = fd;
        self.fds.clear();
        if fd >= 0 {
            self.fds.push(fd);
        }
    }

    /// Returns the event mask currently requested by the context skeleton.
    #[must_use]
    pub const fn which_events(&self) -> i32 {
        self.events
    }

    /// Sets the event mask requested by the context skeleton.
    pub fn set_events(&mut self, events: i32) {
        self.events = events;
    }

    /// Returns all socket descriptors known to the context skeleton.
    #[must_use]
    pub fn fds(&self) -> &[Socket] {
        &self.fds
    }

    /// Registers descriptor and event-mask callbacks for event-loop integration.
    pub fn set_fd_event_callbacks(
        &mut self,
        change_fd: Option<ChangeFdCallback>,
        change_events: Option<ChangeEventsCallback>,
    ) {
        self.fd_event_callbacks = FdEventCallbacks {
            change_fd,
            change_events,
        };
    }

    /// Processes an event mask without performing protocol I/O.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the context has been destroyed.
    pub fn service(&mut self, revents: i32) -> Result<()> {
        if !self.active {
            self.error_string = Some("context is not active".to_owned());
            return Err(ErrorCode(EINVAL));
        }
        self.events = revents;
        Ok(())
    }

    /// Processes events for a specific descriptor without performing protocol I/O.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the descriptor is not the current descriptor,
    /// a known pending descriptor, or `-1` for the timeout path.
    pub fn service_fd(&mut self, fd: Socket, revents: i32) -> Result<()> {
        if fd != -1 && fd != self.fd && !self.fds.contains(&fd) {
            self.error_string = Some("unknown file descriptor".to_owned());
            return Err(ErrorCode(EINVAL));
        }
        self.service(revents)
    }

    /// Sets the timeout in seconds for future command skeletons.
    pub const fn set_timeout(&mut self, seconds: i32) {
        self.timeout_seconds = seconds;
    }

    /// Returns the configured timeout in seconds.
    #[must_use]
    pub const fn timeout(&self) -> i32 {
        self.timeout_seconds
    }

    /// Enables or disables passthrough handling for uninterpreted command data.
    pub const fn set_passthrough(&mut self, passthrough: bool) {
        self.passthrough = passthrough;
    }

    /// Returns whether passthrough handling is enabled.
    #[must_use]
    pub const fn passthrough(&self) -> bool {
        self.passthrough
    }

    /// Sets the SMB dialect negotiation selector.
    pub const fn set_version(&mut self, version: NegotiateVersion) {
        self.version = version;
    }

    /// Returns the SMB dialect negotiation selector.
    #[must_use]
    pub const fn version(&self) -> NegotiateVersion {
        self.version
    }

    /// Returns the libsmb2 version mirrored by this skeleton.
    #[must_use]
    pub const fn libsmb2_version(&self) -> LibVersion {
        let _ = self;
        LibVersion::CURRENT
    }

    /// Returns the negotiated dialect recorded on the context skeleton.
    #[must_use]
    pub const fn dialect(&self) -> u16 {
        self.dialect
    }

    /// Records a negotiated dialect for tests or adapters that already know it.
    pub const fn set_dialect(&mut self, dialect: u16) {
        self.dialect = dialect;
    }

    /// Sets the SMB2 security mode bitmask.
    pub const fn set_security_mode(&mut self, security_mode: u16) {
        self.security_mode = security_mode;
    }

    /// Returns the SMB2 security mode bitmask.
    #[must_use]
    pub const fn security_mode(&self) -> u16 {
        self.security_mode
    }

    /// Enables or disables SMB3 encryption for future connection skeletons.
    pub const fn set_seal(&mut self, val: bool) {
        self.seal = val;
    }

    /// Returns whether SMB3 encryption was requested.
    #[must_use]
    pub const fn seal(&self) -> bool {
        self.seal
    }

    /// Enables or disables required signing for future connection skeletons.
    pub const fn set_sign(&mut self, val: bool) {
        self.sign = val;
    }

    /// Returns whether signing is required.
    #[must_use]
    pub const fn sign(&self) -> bool {
        self.sign
    }

    /// Sets the authentication method used by future session setup skeletons.
    pub const fn set_authentication(&mut self, authentication: AuthenticationMethod) {
        self.authentication = authentication;
    }

    /// Returns the configured authentication method.
    #[must_use]
    pub const fn authentication(&self) -> AuthenticationMethod {
        self.authentication
    }

    /// Sets the username used for authentication.
    pub fn set_user(&mut self, user: impl Into<String>) {
        self.user = Some(user.into());
    }

    /// Returns the configured username, if any.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Sets the authentication domain.
    pub fn set_domain(&mut self, domain: impl Into<String>) {
        self.domain = Some(domain.into());
    }

    /// Returns the configured authentication domain, if any.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Sets the workstation used for authentication.
    pub fn set_workstation(&mut self, workstation: impl Into<String>) {
        self.workstation = Some(workstation.into());
    }

    /// Returns the configured workstation, if any.
    #[must_use]
    pub fn workstation(&self) -> Option<&str> {
        self.workstation.as_deref()
    }

    /// Sets the password used for authentication.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if `password` contains an interior NUL byte and
    /// therefore cannot be represented as a C-compatible string.
    pub fn set_password(&mut self, password: &str) -> Result<()> {
        self.password = Some(CString::new(password).map_err(|_| ErrorCode(EINVAL))?);
        Ok(())
    }

    /// Records that password-from-file resolution should happen in a future backend.
    pub fn set_password_from_file(&mut self) {
        self.password = None;
    }

    /// Returns whether a password has been configured.
    #[must_use]
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// Stores caller-defined opaque data as an integer address-sized value.
    pub fn set_opaque(&mut self, opaque: Option<usize>) {
        self.opaque = opaque;
    }

    /// Returns caller-defined opaque data.
    #[must_use]
    pub const fn opaque(&self) -> Option<usize> {
        self.opaque
    }

    /// Records a client GUID for future negotiation skeletons.
    pub const fn set_client_guid(&mut self, guid: [u8; SMB2_GUID_SIZE]) {
        self.client_guid = Some(guid);
    }

    /// Returns the configured client GUID.
    #[must_use]
    pub const fn client_guid(&self) -> Option<[u8; SMB2_GUID_SIZE]> {
        self.client_guid
    }

    /// Sets the context error string.
    pub fn set_error(&mut self, error_string: impl Into<String>) {
        self.error_string = Some(error_string.into());
    }

    /// Returns a description of the last encountered error.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error_string.as_deref()
    }

    /// Records the last NT status code observed by a backend.
    pub const fn set_nterror(&mut self, nterror: i32) {
        self.nterror = nterror;
    }

    /// Returns the last NT status code observed by a backend.
    #[must_use]
    pub const fn nterror(&self) -> i32 {
        self.nterror
    }

    /// Transfers credential state from this context into another context.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if there is no password, user, or domain state to
    /// transfer from the source context.
    pub fn delegate_credentials(&mut self, out: &mut Smb2Client) -> Result<()> {
        let has_credentials =
            self.password.is_some() || self.user.is_some() || self.domain.is_some();
        if !has_credentials {
            return Err(ErrorCode(EINVAL));
        }
        out.password = self.password.take();
        out.user = self.user.clone();
        out.domain = self.domain.clone();
        Ok(())
    }

    /// Opens a connection to a share.
    ///
    /// # Errors
    ///
    /// Returns an error once transport/session negotiation is implemented and
    /// the underlying SMB2 operation fails.
    pub fn connect_share(&mut self, server: &str, share: &str) -> Result<()> {
        self.server = Some(server.to_owned());
        self.share = Some(share.to_owned());
        self.queue_operation(Smb2Operation::ConnectShare {
            server: server.to_owned(),
            share: share.to_owned(),
            user: None,
        });
        Ok(())
    }

    /// Builds an asynchronous TCP connect request skeleton.
    pub fn connect_async(&mut self, server: &str) {
        self.server = Some(server.to_owned());
        self.queue_operation(Smb2Operation::Connect {
            server: server.to_owned(),
        });
    }

    /// Builds an asynchronous share-connect request skeleton.
    pub fn connect_share_async(&mut self, server: &str, share: &str, user: Option<&str>) {
        self.server = Some(server.to_owned());
        self.share = Some(share.to_owned());
        if let Some(user) = user {
            self.user = Some(user.to_owned());
        }
        self.queue_operation(Smb2Operation::ConnectShare {
            server: server.to_owned(),
            share: share.to_owned(),
            user: user.map(str::to_owned),
        });
    }

    /// Disconnects from the current share.
    ///
    /// # Errors
    ///
    /// Returns an error once tree disconnect is implemented and the underlying
    /// SMB2 operation fails.
    pub fn disconnect_share(&mut self) -> Result<()> {
        self.share = None;
        self.queue_operation(Smb2Operation::DisconnectShare);
        Ok(())
    }

    /// Selects a connected tree id for subsequent request skeletons.
    pub const fn select_tree_id(&mut self, tree_id: u32) {
        self.tree_id = Some(tree_id);
    }

    /// Returns the selected tree id.
    #[must_use]
    pub const fn tree_id(&self) -> Option<u32> {
        self.tree_id
    }

    /// Records a tree id on a PDU skeleton.
    pub const fn set_tree_id_for_pdu(&self, pdu: &mut PduHandle, tree_id: u32) {
        let _ = self;
        pdu.tree_id = Some(tree_id);
    }

    /// Reads a tree id from a PDU skeleton.
    #[must_use]
    pub const fn tree_id_for_pdu(&self, pdu: &PduHandle) -> Option<u32> {
        let _ = self;
        pdu.tree_id
    }

    /// Returns the current session id, if a backend has recorded one.
    #[must_use]
    pub const fn session_id(&self) -> Option<u64> {
        self.session_id
    }

    /// Records a session id for tests or future backend adapters.
    pub const fn set_session_id(&mut self, session_id: u64) {
        self.session_id = Some(session_id);
    }

    /// Adds a PDU to a compound chain skeleton.
    pub const fn add_compound_pdu(&self, pdu: &mut PduHandle, next_pdu: &mut PduHandle) {
        let _ = self;
        pdu.is_compound = true;
        next_pdu.is_compound = true;
    }

    /// Queues a PDU skeleton by advancing the last request message id.
    pub const fn queue_pdu(&mut self, pdu: &mut PduHandle) {
        self.last_request_message_id = self.last_request_message_id.saturating_add(1);
        pdu.message_id = Some(self.last_request_message_id);
    }

    /// Sets a completion status on a PDU skeleton.
    pub const fn set_pdu_status(&self, pdu: &mut PduHandle, status: i32) {
        let _ = self;
        pdu.status = status;
    }

    /// Sets an SMB2 message id on a PDU skeleton.
    pub const fn set_pdu_message_id(&self, pdu: &mut PduHandle, message_id: u64) {
        let _ = self;
        pdu.message_id = Some(message_id);
    }

    /// Returns the SMB2 message id recorded on a PDU skeleton.
    #[must_use]
    pub const fn pdu_message_id(&self, pdu: &PduHandle) -> Option<u64> {
        let _ = self;
        pdu.message_id
    }

    /// Returns the last request message id assigned by `queue_pdu`.
    #[must_use]
    pub const fn last_request_message_id(&self) -> u64 {
        self.last_request_message_id
    }

    /// Returns the last reply message id recorded by a backend.
    #[must_use]
    pub const fn last_reply_message_id(&self) -> u64 {
        self.last_reply_message_id
    }

    /// Records the last reply message id observed by a backend.
    pub const fn set_last_reply_message_id(&mut self, message_id: u64) {
        self.last_reply_message_id = message_id;
    }

    /// Returns whether the selected PDU chain is compound.
    #[must_use]
    pub const fn pdu_is_compound(&self, pdu: &PduHandle) -> bool {
        let _ = self;
        pdu.is_compound
    }

    /// Builds an opendir request skeleton.
    pub fn opendir_async(&mut self, path: &str) {
        self.queue_operation(Smb2Operation::OpenDir {
            path: path.to_owned(),
        });
    }

    /// Builds an open request skeleton.
    pub fn open_async(&mut self, path: &str, flags: i32) {
        self.queue_operation(Smb2Operation::Open {
            path: path.to_owned(),
            flags,
            oplock_level: None,
            lease_state: None,
            lease_key: None,
        });
    }

    /// Builds an open-with-oplock-or-lease request skeleton.
    pub fn open_async_with_oplock_or_lease(
        &mut self,
        path: &str,
        flags: i32,
        oplock_level: u8,
        lease_state: u32,
        lease_key: LeaseKey,
    ) {
        self.queue_operation(Smb2Operation::Open {
            path: path.to_owned(),
            flags,
            oplock_level: Some(oplock_level),
            lease_state: Some(lease_state),
            lease_key: Some(lease_key),
        });
    }

    /// Builds a close request skeleton.
    pub fn close_async(&mut self, handle: &FileHandle) {
        self.queue_operation(Smb2Operation::Close {
            file_id: handle.id(),
        });
    }

    /// Builds an fsync request skeleton.
    pub fn fsync_async(&mut self, handle: &FileHandle) {
        self.queue_operation(Smb2Operation::Fsync {
            file_id: handle.id(),
        });
    }

    /// Returns the maximum read size recorded for the context skeleton.
    #[must_use]
    pub const fn max_read_size(&self) -> u32 {
        self.max_read_size
    }

    /// Returns the maximum write size recorded for the context skeleton.
    #[must_use]
    pub const fn max_write_size(&self) -> u32 {
        self.max_write_size
    }

    /// Records negotiated maximum read and write sizes.
    pub const fn set_max_io_sizes(&mut self, max_read_size: u32, max_write_size: u32) {
        self.max_read_size = max_read_size;
        self.max_write_size = max_write_size;
    }

    /// Builds a positioned read request skeleton.
    pub fn pread_async(&mut self, handle: &FileHandle, count: u32, offset: u64) {
        self.queue_operation(Smb2Operation::Read {
            file_id: handle.id(),
            count,
            offset: Some(offset),
        });
    }

    /// Builds a positioned write request skeleton.
    pub fn pwrite_async(&mut self, handle: &FileHandle, count: u32, offset: u64) {
        self.queue_operation(Smb2Operation::Write {
            file_id: handle.id(),
            count,
            offset: Some(offset),
        });
    }

    /// Builds a sequential read request skeleton.
    pub fn read_async(&mut self, handle: &FileHandle, count: u32) {
        self.queue_operation(Smb2Operation::Read {
            file_id: handle.id(),
            count,
            offset: None,
        });
    }

    /// Builds a sequential write request skeleton.
    pub fn write_async(&mut self, handle: &FileHandle, count: u32) {
        self.queue_operation(Smb2Operation::Write {
            file_id: handle.id(),
            count,
            offset: None,
        });
    }

    /// Builds an lseek request skeleton and returns the requested resulting offset.
    #[must_use]
    pub fn lseek(&mut self, handle: &FileHandle, offset: i64, whence: i32) -> Option<u64> {
        self.queue_operation(Smb2Operation::Lseek {
            file_id: handle.id(),
            offset,
            whence,
        });
        u64::try_from(offset).ok()
    }

    /// Builds an unlink request skeleton.
    pub fn unlink_async(&mut self, path: &str) {
        self.queue_operation(Smb2Operation::Unlink {
            path: path.to_owned(),
        });
    }

    /// Builds an rmdir request skeleton.
    pub fn rmdir_async(&mut self, path: &str) {
        self.queue_operation(Smb2Operation::Rmdir {
            path: path.to_owned(),
        });
    }

    /// Builds a mkdir request skeleton.
    pub fn mkdir_async(&mut self, path: &str) {
        self.queue_operation(Smb2Operation::Mkdir {
            path: path.to_owned(),
        });
    }

    /// Builds a statvfs request skeleton.
    pub fn statvfs_async(&mut self, path: &str) {
        self.queue_operation(Smb2Operation::StatVfs {
            path: path.to_owned(),
        });
    }

    /// Builds an fstat request skeleton.
    pub fn fstat_async(&mut self, handle: &FileHandle) {
        self.queue_operation(Smb2Operation::Fstat {
            file_id: handle.id(),
        });
    }

    /// Builds a stat request skeleton.
    pub fn stat_async(&mut self, path: &str) {
        self.queue_operation(Smb2Operation::Stat {
            path: path.to_owned(),
        });
    }

    /// Builds a rename request skeleton.
    pub fn rename_async(&mut self, old_path: &str, new_path: &str) {
        self.queue_operation(Smb2Operation::Rename {
            old_path: old_path.to_owned(),
            new_path: new_path.to_owned(),
        });
    }

    /// Builds a truncate request skeleton.
    pub fn truncate_async(&mut self, path: &str, length: u64) {
        self.queue_operation(Smb2Operation::Truncate {
            path: path.to_owned(),
            length,
        });
    }

    /// Builds an ftruncate request skeleton.
    pub fn ftruncate_async(&mut self, handle: &FileHandle, length: u64) {
        self.queue_operation(Smb2Operation::Ftruncate {
            file_id: handle.id(),
            length,
        });
    }

    /// Builds a readlink request skeleton.
    pub fn readlink_async(&mut self, path: &str, buffer_size: u32) {
        self.queue_operation(Smb2Operation::Readlink {
            path: path.to_owned(),
            buffer_size,
        });
    }

    /// Builds an echo request skeleton.
    pub fn echo_async(&mut self) {
        self.queue_operation(Smb2Operation::Echo);
    }

    /// Builds a path-based notify-change request skeleton.
    pub fn notify_change_async(&mut self, path: &str, flags: u16, filter: u32, repeat: bool) {
        self.queue_operation(Smb2Operation::NotifyChange {
            path: path.to_owned(),
            flags,
            filter,
            repeat,
        });
    }

    /// Builds a filehandle-based notify-change request skeleton.
    pub fn notify_change_filehandle_async(
        &mut self,
        handle: &FileHandle,
        flags: u16,
        filter: u32,
        repeat: bool,
    ) {
        self.queue_operation(Smb2Operation::NotifyChangeFileHandle {
            file_id: handle.id(),
            flags,
            filter,
            repeat,
        });
    }

    /// Returns queued operation skeletons in submission order.
    #[must_use]
    pub fn queued_operations(&self) -> &[Smb2Operation] {
        &self.queued_operations
    }

    /// Removes all queued operation skeletons.
    pub fn clear_queued_operations(&mut self) {
        self.queued_operations.clear();
    }

    fn queue_operation(&mut self, operation: Smb2Operation) {
        self.queued_operations.push(operation);
    }
}

/// Converts a Windows FILETIME-like SMB timestamp to a Unix timeval skeleton.
#[must_use]
pub const fn win_to_timeval(smb2_time: u64) -> TimeVal {
    const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    if smb2_time <= WINDOWS_TO_UNIX_EPOCH_100NS {
        return TimeVal {
            seconds: 0,
            microseconds: 0,
        };
    }
    let unix_100ns = smb2_time - WINDOWS_TO_UNIX_EPOCH_100NS;
    TimeVal {
        seconds: (unix_100ns / 10_000_000) as i64,
        microseconds: ((unix_100ns % 10_000_000) / 10) as i64,
    }
}

/// Converts a Unix timeval skeleton to a Windows FILETIME-like SMB timestamp.
#[must_use]
pub const fn timeval_to_win(tv: TimeVal) -> u64 {
    const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    let seconds = if tv.seconds < 0 { 0 } else { tv.seconds as u64 };
    let micros = if tv.microseconds < 0 {
        0
    } else {
        tv.microseconds as u64
    };
    WINDOWS_TO_UNIX_EPOCH_100NS + seconds.saturating_mul(10_000_000) + micros.saturating_mul(10)
}

/// Converts a known NT status code into a static string skeleton.
#[must_use]
pub const fn nterror_to_str(status: u32) -> &'static str {
    match status {
        0 => "STATUS_SUCCESS",
        _ => "STATUS_UNKNOWN",
    }
}

/// Converts a known NT status code into an errno-style value skeleton.
#[must_use]
pub const fn nterror_to_errno(status: u32) -> i32 {
    match status {
        0 => 0,
        _ => EINVAL,
    }
}

/// Builds UTF-16 code units from a UTF-8 string using SMB little-endian semantics.
#[must_use]
pub fn utf8_to_utf16(utf8: &str) -> Utf16String {
    Utf16String::new(utf8.encode_utf16().collect())
}

/// Builds a UTF-8 string from UTF-16 code units.
///
/// Invalid UTF-16 sequences are replaced using Rust's standard lossy conversion,
/// matching this module's non-protocol placeholder role.
#[must_use]
pub fn utf16_to_utf8(str: &[u16]) -> String {
    String::from_utf16_lossy(str)
}

/// Builds a bind-and-listen server socket request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `max_connections` is negative.
pub fn bind_and_listen(port: u16, max_connections: i32) -> Result<Smb2Server> {
    if max_connections < 0 {
        return Err(ErrorCode(EINVAL));
    }
    let mut server = Smb2Server {
        port,
        ..Smb2Server::default()
    };
    server.fd = -1;
    Ok(server)
}

/// Builds an accept-connection request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `fd` is negative.
pub const fn accept_connection_async(fd: Socket, timeout_msecs: i32) -> Result<(Socket, i32)> {
    if fd < 0 {
        return Err(ErrorCode(EINVAL));
    }
    Ok((fd, timeout_msecs))
}

/// Builds a serve-port context skeleton for a listening descriptor.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `fd` is negative.
pub fn serve_port_async(fd: Socket, timeout_msecs: i32) -> Result<Smb2Client> {
    if fd < 0 {
        return Err(ErrorCode(EINVAL));
    }
    let mut client = Smb2Client::new();
    client.set_fd(fd);
    client.set_timeout(timeout_msecs);
    Ok(client)
}

/// Builds a synchronous serve-port loop skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the server socket descriptor is negative.
pub const fn serve_port(server: &Smb2Server, max_connections: i32) -> Result<i32> {
    if server.fd < 0 || max_connections < 0 {
        return Err(ErrorCode(EINVAL));
    }
    Ok(0)
}
