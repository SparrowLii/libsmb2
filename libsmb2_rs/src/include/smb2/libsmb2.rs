//! Safe Rust-facing API model for `include/smb2/libsmb2.h`.
//!
//! The items in this module mirror the public responsibilities of the C header:
//! context configuration, event-loop integration, URL parsing, file and
//! directory operation request shapes, notification state, and server-side
//! dispatch records. The high-level client supports deterministic local
//! completions and a transport-adapter wire boundary that writes SMB Direct TCP
//! frames with SMB2 headers, parses framed SMB2 replies, dispatches responses by
//! message id, and falls back to local payload completion when full session
//! negotiation is not yet available.

use std::ffi::CString;
use std::os::raw::c_void;

use crate::include::libsmb2_private::{
    Context, IoVec, IoVectors, Pdu, Smb2Header, SMB2_HEADER_SIZE, SMB2_MAX_PDU_SIZE,
};
use crate::lib::pdu::{
    smb2_decode_header_bytes, smb2_decode_pdu_payload_with_context,
    smb2_encode_pdu_frame_with_context, smb2_get_fixed_reply_size, smb2_get_fixed_request_size,
    smb2_header_for_command, smb2_process_reply_payload_fixed, smb2_process_reply_payload_variable,
    Smb2Command, SMB2_FLAGS_SERVER_TO_REDIR, SMB2_STATUS_MORE_PROCESSING_REQUIRED,
    SMB2_STATUS_SEVERITY_ERROR, SMB2_STATUS_SEVERITY_MASK, SMB2_STATUS_SEVERITY_WARNING,
    SMB2_STATUS_STOPPED_ON_SYMLINK,
};
use crate::lib::smb2_cmd_close::{smb2_cmd_close_async, Smb2CloseRequest};
use crate::lib::smb2_cmd_create::{smb2_cmd_create_async, Smb2CreateRequest};
use crate::lib::smb2_cmd_echo::smb2_cmd_echo_async;
use crate::lib::smb2_cmd_flush::{smb2_cmd_flush_async, Smb2FlushRequest};
use crate::lib::smb2_cmd_read::Smb2ReadRequest;
use crate::lib::smb2_cmd_tree_connect::{smb2_cmd_tree_connect_async, Smb2TreeConnectRequest};
use crate::lib::smb2_cmd_tree_disconnect::smb2_cmd_tree_disconnect_async;
use crate::lib::smb2_cmd_write::{
    smb2_cmd_write_async, Smb2WriteRequest, WriteBufferOwnership, WriteEncodeOptions,
};
use crate::lib::smb2_signing::{derive_session_keys, SessionDerivedKeys};
use crate::lib::socket::{
    connect_tcp_stream, poll_internal_fd, Events, SocketAddress, SocketError, StdTcpTransport,
    TransportAdapter,
};

/// Crate-local result type for SMB2 operations.
pub type Result<T> = std::result::Result<T, ErrorCode>;

/// Negative errno-style error code returned by the legacy API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCode(pub i32);

impl ErrorCode {
    /// Creates an error code from the public negative errno convention.
    #[must_use]
    pub const fn new(code: i32) -> Self {
        Self(code)
    }

    /// Creates an error code from a positive errno value.
    #[must_use]
    pub const fn from_errno(errno: i32) -> Self {
        if errno <= 0 {
            Self(errno)
        } else {
            Self(-errno)
        }
    }

    /// Creates an error code from an NTSTATUS value using the shared table.
    #[must_use]
    pub fn from_ntstatus(status: u32) -> Self {
        Self::from_errno(crate::lib::errors::nterror_to_errno(status))
    }

    /// Returns the stored negative errno-style code.
    #[must_use]
    pub const fn code(self) -> i32 {
        self.0
    }

    /// Returns the positive errno value represented by this error code.
    #[must_use]
    pub const fn errno(self) -> i32 {
        if self.0 < 0 {
            -self.0
        } else {
            self.0
        }
    }
}

/// Error code used when a string cannot be represented as a C string.
pub const EINVAL: i32 = -22;

/// Error code used when a migrated API boundary has no backend implementation.
pub const ENOSYS: i32 = -38;

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

/// Poll-style read readiness bit used by event-loop integration.
pub const SMB2_POLLIN: i32 = 0x0001;

/// Poll-style write readiness bit used by event-loop integration.
pub const SMB2_POLLOUT: i32 = 0x0004;

/// Poll-style error bit used by event-loop integration.
pub const SMB2_POLLERR: i32 = 0x0008;

/// Poll-style hang-up bit used by event-loop integration.
pub const SMB2_POLLHUP: i32 = 0x0010;

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

/// Default maximum read size used before negotiation completes.
pub const DEFAULT_MAX_READ_SIZE: u32 = 0;

/// Default maximum write size used before negotiation completes.
pub const DEFAULT_MAX_WRITE_SIZE: u32 = 0;

const SYNTHETIC_CONNECTED_FD: Socket = 0;
const EISCONN: i32 = -106;
const ENOTCONN: i32 = -107;

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

/// Callback shape for server-side request dispatch handlers.
pub type ServerRequestHandler =
    Box<dyn Fn(&mut Smb2Client, &ServerRequest) -> ServerHandlerResult + Send + 'static>;

/// Callback shape for file-descriptor add/remove notifications.
pub type ChangeFdCallback = Box<dyn Fn(&Smb2Client, Socket, i32) + Send + Sync + 'static>;

/// Callback shape for file-descriptor event-mask changes.
pub type ChangeEventsCallback = Box<dyn Fn(&Smb2Client, Socket, i32) + Send + Sync + 'static>;

/// Callback shape for oplock or lease-break notifications.
pub type OplockOrLeaseBreakCallback = Box<dyn Fn(&mut Smb2Client, OplockOrLeaseBreak) + Send>;

/// Platform-neutral byte transport used by injected service loops.
pub trait Smb2TransportAdapter {
    /// Reads bytes from `fd` into `buf`.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] when the adapter cannot service the read.
    fn read(&mut self, fd: Socket, buf: &mut [u8]) -> Result<usize>;

    /// Writes bytes for `fd` from `buf`.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] when the adapter cannot service the write.
    fn write(&mut self, fd: Socket, buf: &[u8]) -> Result<usize>;

    /// Returns readiness bits for `fd` from the supplied requested event mask.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] when `fd` is not handled by the adapter.
    fn ready_events(&self, fd: Socket, requested: i32) -> Result<i32>;
}

/// In-memory transport adapter for deterministic `Smb2Client` service loops.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemorySmb2Transport {
    fd: Socket,
    readable: Vec<u8>,
    read_offset: usize,
    written: Vec<u8>,
    max_read_chunk: Option<usize>,
    max_write_chunk: Option<usize>,
}

impl MemorySmb2Transport {
    /// Creates an empty memory transport bound to `fd`.
    #[must_use]
    pub fn new(fd: Socket) -> Self {
        Self {
            fd,
            ..Self::default()
        }
    }

    /// Creates a memory transport seeded with response bytes.
    #[must_use]
    pub fn with_readable(fd: Socket, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            fd,
            readable: bytes.into(),
            ..Self::default()
        }
    }

    /// Returns the descriptor served by this transport.
    #[must_use]
    pub const fn fd(&self) -> Socket {
        self.fd
    }

    /// Appends bytes that future reads will consume.
    pub fn push_readable(&mut self, bytes: &[u8]) {
        self.compact_readable();
        self.readable.extend_from_slice(bytes);
    }

    /// Returns bytes captured from writes.
    #[must_use]
    pub fn written(&self) -> &[u8] {
        &self.written
    }

    /// Removes and returns all bytes captured from writes.
    #[must_use]
    pub fn take_written(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.written)
    }

    /// Limits each read call to at most `chunk_size` bytes when non-zero.
    pub fn set_max_read_chunk(&mut self, chunk_size: Option<usize>) {
        self.max_read_chunk = chunk_size.filter(|size| *size > 0);
    }

    /// Limits each write call to at most `chunk_size` bytes when non-zero.
    pub fn set_max_write_chunk(&mut self, chunk_size: Option<usize>) {
        self.max_write_chunk = chunk_size.filter(|size| *size > 0);
    }

    fn readable_len(&self) -> usize {
        self.readable.len().saturating_sub(self.read_offset)
    }

    fn compact_readable(&mut self) {
        if self.read_offset == 0 {
            return;
        }
        if self.read_offset >= self.readable.len() {
            self.readable.clear();
            self.read_offset = 0;
        } else if self.read_offset > 4096 {
            self.readable.drain(..self.read_offset);
            self.read_offset = 0;
        }
    }
}

impl Smb2TransportAdapter for MemorySmb2Transport {
    fn read(&mut self, fd: Socket, buf: &mut [u8]) -> Result<usize> {
        if fd != self.fd {
            return Err(ErrorCode(EINVAL));
        }
        if buf.is_empty() || self.readable_len() == 0 {
            return Ok(0);
        }
        let limit = match self.max_read_chunk {
            Some(limit) => limit,
            None => buf.len(),
        };
        let copy_len = self.readable_len().min(buf.len()).min(limit);
        let end = self.read_offset + copy_len;
        buf[..copy_len].copy_from_slice(&self.readable[self.read_offset..end]);
        self.read_offset = end;
        self.compact_readable();
        Ok(copy_len)
    }

    fn write(&mut self, fd: Socket, buf: &[u8]) -> Result<usize> {
        if fd != self.fd {
            return Err(ErrorCode(EINVAL));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let limit = match self.max_write_chunk {
            Some(limit) => limit,
            None => buf.len(),
        };
        let write_len = buf.len().min(limit);
        self.written.extend_from_slice(&buf[..write_len]);
        Ok(write_len)
    }

    fn ready_events(&self, fd: Socket, requested: i32) -> Result<i32> {
        if fd != self.fd {
            return Err(ErrorCode(EINVAL));
        }
        let mut ready = 0;
        if requested & SMB2_POLLIN != 0 && self.readable_len() > 0 {
            ready |= SMB2_POLLIN;
        }
        if requested & SMB2_POLLOUT != 0 {
            ready |= SMB2_POLLOUT;
        }
        Ok(ready)
    }
}

/// Standard-library TCP transport adapter backed by `std::net::TcpStream`.
#[derive(Debug, Default)]
pub struct StdSmb2Transport {
    inner: StdTcpTransport,
}

impl StdSmb2Transport {
    /// Creates an empty TCP transport adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: StdTcpTransport,
        }
    }

    /// Connects `client` to `server` and installs the registry-backed TCP descriptor.
    ///
    /// `server` accepts the same `host[:port]` and `[ipv6]:port` form as the
    /// socket migration layer. Missing ports default to SMB Direct TCP port 445.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` when the endpoint is invalid or the TCP backend
    /// cannot connect/register the stream.
    pub fn connect(&mut self, client: &mut Smb2Client, server: &str) -> Result<Socket> {
        client.ensure_context_active()?;
        let address = SocketAddress::parse(server).map_err(socket_error_to_error_code)?;
        let fd = connect_tcp_stream(&address).map_err(socket_error_to_error_code)?;
        client.server = Some(server.to_owned());
        client.share_connection = ShareConnectionState::Disconnected;
        client.set_fd(fd);
        client.refresh_events();
        Ok(fd)
    }
}

impl Smb2TransportAdapter for StdSmb2Transport {
    fn read(&mut self, fd: Socket, buf: &mut [u8]) -> Result<usize> {
        self.inner.read(fd, buf).map_err(socket_error_to_error_code)
    }

    fn write(&mut self, fd: Socket, buf: &[u8]) -> Result<usize> {
        self.inner
            .write(fd, buf)
            .map_err(socket_error_to_error_code)
    }

    fn ready_events(&self, fd: Socket, requested: i32) -> Result<i32> {
        let ready = poll_internal_fd(fd, Events::from_poll_bits(requested))
            .map_err(socket_error_to_error_code)?;
        Ok(ready.to_poll_bits())
    }
}

fn socket_error_to_error_code(error: SocketError) -> ErrorCode {
    match error {
        SocketError::WouldBlock => ErrorCode(-11),
        SocketError::InvalidSocket | SocketError::InvalidAddress => ErrorCode(EINVAL),
        SocketError::NotConnected | SocketError::Unsupported(_) | SocketError::Transport(_) => {
            ErrorCode(EINVAL)
        }
    }
}

/// Rust representation of `struct smb2_iovec` ownership responsibilities.
pub struct Smb2Iovec {
    /// Data buffer referenced by the vector.
    pub buffer: Vec<u8>,
    /// Optional release callback preserved for FFI-oriented callers.
    pub free: Option<FreeCallback>,
}

impl Smb2Iovec {
    /// Creates an I/O vector from owned bytes.
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

/// Local directory result produced by the high-level client completion path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDirectoryResult {
    /// Path used to open the directory.
    pub path: String,
    /// Directory handle assigned to the completion.
    pub handle: DirectoryHandle,
    /// Directory entries parsed from a synthetic payload or generated locally.
    pub entries: Vec<DirectoryEntry>,
}

/// Local readlink result produced by the high-level client completion path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalReadlinkResult {
    /// Path used for the readlink request.
    pub path: String,
    /// Link target bytes parsed from a synthetic payload or generated locally.
    pub target: Vec<u8>,
}

/// Local stat result produced by the high-level client completion path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalStatResult {
    /// Metadata parsed from a synthetic payload or generated locally.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthenticationMethod {
    /// Let libsmb2 choose Kerberos when available, otherwise NTLMSSP.
    #[default]
    Undefined,
    /// Use NTLMSSP authentication.
    NtlmSsp,
    /// Use Kerberos authentication.
    Krb5,
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

/// Observable lifecycle state for an [`Smb2Client`] context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smb2ClientState {
    /// The context can be configured and can queue local operations.
    Active,
    /// The context was closed; allocated configuration remains available.
    Closed,
    /// The context was destroyed and no further operations may be queued.
    Destroyed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShareConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

/// Opaque file handle corresponding to `struct smb2fh`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHandle {
    pub(crate) id: [u8; SMB2_FILE_ID_SIZE],
    pub(crate) offset: u64,
}

impl FileHandle {
    /// Creates a file handle from a raw SMB2 file id.
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

    /// Sets the cached sequential file offset.
    pub fn set_offset(&mut self, offset: u64) {
        self.offset = offset;
    }

    /// Advances the cached sequential file offset using saturating arithmetic.
    pub fn advance_offset(&mut self, count: u64) {
        self.offset = self.offset.saturating_add(count);
    }
}

/// Opaque directory handle corresponding to `struct smb2dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryHandle {
    pub(crate) id: [u8; SMB2_FILE_ID_SIZE],
    pub(crate) index: usize,
}

impl DirectoryHandle {
    /// Creates a directory handle from a raw SMB2 file id.
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

/// Runtime state for an operation submitted through the public async API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationState {
    /// Operation is queued and waiting for write readiness.
    Queued,
    /// Operation has been submitted to the transport state machine.
    InFlight,
    /// Operation completed locally or through a future backend callback.
    Completed,
    /// Operation was cancelled because the context was closed or destroyed.
    Cancelled,
    /// Operation failed before it could be submitted.
    Failed(ErrorCode),
}

/// Public operation record carrying an assigned message id and state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRecord {
    /// Synthetic message id assigned when the operation is queued.
    pub message_id: u64,
    /// Operation payload submitted by the caller.
    pub operation: Smb2Operation,
    /// Current operation state.
    pub state: OperationState,
}

/// Typed result produced when the local high-level client loop completes an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Smb2OperationResult {
    /// TCP connect completed locally.
    Connect { server: String },
    /// Tree connect completed locally.
    ConnectShare {
        /// Server name or address.
        server: String,
        /// Share name.
        share: String,
        /// Optional user name.
        user: Option<String>,
    },
    /// Tree disconnect completed locally.
    DisconnectShare,
    /// Operation completed locally without returning a typed payload.
    Complete,
    /// File open/create completed with a deterministic local handle.
    Open {
        /// Path relative to the share.
        path: String,
        /// Newly opened file handle.
        handle: FileHandle,
    },
    /// Directory open completed with a deterministic local handle and entries.
    Directory {
        /// Path relative to the share.
        path: String,
        /// Newly opened directory handle.
        handle: DirectoryHandle,
        /// Deterministic local directory entries.
        entries: Vec<DirectoryEntry>,
    },
    /// Read completed with local bytes and the resolved file offset.
    Read {
        /// File id read from.
        file_id: [u8; SMB2_FILE_ID_SIZE],
        /// Absolute file offset used for the read.
        offset: u64,
        /// Bytes returned by the local response path.
        data: Vec<u8>,
    },
    /// Write completed with a byte count and resolved file offset.
    Write {
        /// File id written to.
        file_id: [u8; SMB2_FILE_ID_SIZE],
        /// Absolute file offset used for the write.
        offset: u64,
        /// Number of bytes accepted by the local response path.
        bytes_written: u32,
    },
    /// Path or handle metadata query completed locally.
    Stat { stat: Stat },
    /// Readlink completed with local target bytes.
    Readlink {
        /// Path used for the readlink request.
        path: String,
        /// Link target bytes returned by the local response path.
        target: Vec<u8>,
    },
    /// Filesystem metadata query completed locally.
    StatVfs { statvfs: StatVfs },
    /// Echo completed locally.
    Echo,
}

/// Public completion record carrying the operation message id and typed result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationCompletion {
    /// Synthetic message id shared with the completed operation record.
    pub message_id: u64,
    /// Legacy completion status: zero for success or a negative errno-style code.
    pub status: i32,
    /// Typed result produced by the local completion path.
    pub result: Result<Smb2OperationResult>,
}

impl OperationCompletion {
    /// Creates a completion record from a typed operation result.
    #[must_use]
    pub fn new(message_id: u64, result: Result<Smb2OperationResult>) -> Self {
        let status = match &result {
            Ok(_) => 0,
            Err(error) => error.code(),
        };
        Self {
            message_id,
            status,
            result,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyntheticResponse {
    message_id: Option<u64>,
    status: i32,
    payload: Vec<u8>,
    smb2_packet: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HandleOffset {
    file_id: [u8; SMB2_FILE_ID_SIZE],
    offset: u64,
    path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalObject {
    path: String,
    file_type: FileType,
    data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransportWriteState {
    message_id: u64,
    frame: Vec<u8>,
    done: usize,
}

/// Encoded command descriptor produced for public operations that map to SMB2 commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Smb2CommandDescriptor {
    /// CREATE command descriptor used by open/stat path flows.
    Create {
        /// Path encoded by the CREATE command.
        path: String,
        /// POSIX-style open flags from the caller.
        flags: i32,
        /// Encoded output vector lengths.
        out_vector_lengths: Vec<usize>,
    },
    /// READ command descriptor.
    Read {
        /// File id to read from.
        file_id: [u8; SMB2_FILE_ID_SIZE],
        /// Requested byte count.
        count: u32,
        /// Absolute file offset used by the descriptor.
        offset: u64,
        /// Encoded output vector lengths.
        out_vector_lengths: Vec<usize>,
        /// Expected input vector lengths.
        input_vector_lengths: Vec<usize>,
        /// Calculated credit charge.
        credit_charge: u16,
    },
    /// WRITE command descriptor.
    Write {
        /// File id to write to.
        file_id: [u8; SMB2_FILE_ID_SIZE],
        /// Requested byte count.
        count: u32,
        /// Absolute file offset used by the descriptor.
        offset: u64,
        /// Encoded output vector lengths.
        out_vector_lengths: Vec<usize>,
        /// Calculated credit charge.
        credit_charge: u16,
    },
    /// CLOSE command descriptor.
    Close {
        /// File id being closed.
        file_id: [u8; SMB2_FILE_ID_SIZE],
        /// Encoded output vector lengths.
        out_vector_lengths: Vec<usize>,
    },
    /// QUERY_INFO-style descriptor for stat/fstat/statvfs flows.
    QueryInfo {
        /// Target path for path-based stat flows.
        path: Option<String>,
        /// File id for handle-based stat flows.
        file_id: [u8; SMB2_FILE_ID_SIZE],
        /// SMB2 information type.
        info_type: u8,
        /// SMB2 file information class.
        file_info_class: u8,
        /// Whether this descriptor is part of a synthetic compound flow.
        compound: bool,
    },
    /// Descriptor build failed; the original queued operation remains available.
    BuildError {
        /// Command name that failed descriptor generation.
        command: &'static str,
        /// Negative errno-style error code when available.
        code: i32,
    },
}

/// Command descriptor associated with an operation message id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRecord {
    /// Synthetic message id shared with the queued operation record.
    pub message_id: u64,
    /// Descriptor generated for the queued operation.
    pub descriptor: Smb2CommandDescriptor,
}

impl OperationRecord {
    /// Creates a queued operation record.
    #[must_use]
    pub const fn queued(message_id: u64, operation: Smb2Operation) -> Self {
        Self {
            message_id,
            operation,
            state: OperationState::Queued,
        }
    }
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

/// Minimal server socket lifecycle represented by the migrated skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerSocketState {
    /// No bind/listen request has been recorded.
    Unbound,
    /// Bind/listen arguments were validated but no OS listener was created.
    BindRequested {
        /// Requested listening port.
        port: u16,
        /// Requested maximum connection backlog.
        max_connections: i32,
    },
    /// A real listener descriptor is available from a backend.
    Listening {
        /// Listener descriptor.
        fd: Socket,
        /// Listening port.
        port: u16,
        /// Requested maximum connection backlog.
        max_connections: i32,
    },
}

/// Server configuration corresponding to `struct smb2_server`.
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
    /// Minimal socket lifecycle state for server-mode operations.
    pub socket_state: ServerSocketState,
    accepted_callback: Option<AcceptedCallback>,
    client_connection_callback: Option<ClientConnectionCallback>,
    request_handlers: Vec<(ServerRequestKind, ServerRequestHandler)>,
}

impl std::fmt::Debug for Smb2Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Smb2Server")
            .field("guid", &self.guid)
            .field("hostname", &self.hostname)
            .field("domain", &self.domain)
            .field("fd", &self.fd)
            .field("port", &self.port)
            .field("session_counter", &self.session_counter)
            .field("max_transact_size", &self.max_transact_size)
            .field("max_read_size", &self.max_read_size)
            .field("max_write_size", &self.max_write_size)
            .field("signing_enabled", &self.signing_enabled)
            .field("allow_anonymous", &self.allow_anonymous)
            .field("proxy_authentication", &self.proxy_authentication)
            .field("capabilities", &self.capabilities)
            .field("security_mode", &self.security_mode)
            .field("keytab_path", &self.keytab_path)
            .field("error", &self.error)
            .field("auth_data", &self.auth_data)
            .field("socket_state", &self.socket_state)
            .field("has_accepted_callback", &self.accepted_callback.is_some())
            .field(
                "has_client_connection_callback",
                &self.client_connection_callback.is_some(),
            )
            .field("request_handler_count", &self.request_handlers.len())
            .finish()
    }
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
            socket_state: ServerSocketState::Unbound,
            accepted_callback: None,
            client_connection_callback: None,
            request_handlers: Vec::new(),
        }
    }
}

impl Smb2Server {
    /// Returns the current minimal socket lifecycle state.
    #[must_use]
    pub const fn socket_state(&self) -> ServerSocketState {
        self.socket_state
    }

    /// Records a real listener descriptor supplied by a future backend.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if `fd` or `max_connections` is negative.
    pub fn set_listening(&mut self, fd: Socket, port: u16, max_connections: i32) -> Result<()> {
        if fd < 0 || max_connections < 0 {
            self.error = Some("invalid server listener arguments".to_owned());
            return Err(ErrorCode(EINVAL));
        }
        self.fd = fd;
        self.port = port;
        self.socket_state = ServerSocketState::Listening {
            fd,
            port,
            max_connections,
        };
        Ok(())
    }

    /// Registers the callback invoked after a connection is accepted.
    pub fn set_accepted_callback(&mut self, callback: Option<AcceptedCallback>) {
        self.accepted_callback = callback;
    }

    /// Registers the callback invoked when a client context is created.
    pub fn set_client_connection_callback(&mut self, callback: Option<ClientConnectionCallback>) {
        self.client_connection_callback = callback;
    }

    /// Registers or replaces a server request handler for `kind`.
    pub fn set_request_handler<F>(&mut self, kind: ServerRequestKind, handler: F)
    where
        F: Fn(&mut Smb2Client, &ServerRequest) -> ServerHandlerResult + Send + 'static,
    {
        self.request_handlers
            .retain(|(registered, _)| *registered != kind);
        self.request_handlers.push((kind, Box::new(handler)));
    }

    /// Removes a registered server request handler.
    pub fn clear_request_handler(&mut self, kind: ServerRequestKind) {
        self.request_handlers
            .retain(|(registered, _)| *registered != kind);
    }

    /// Dispatches one request to a registered handler.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-38)` when no handler is registered, or the negative
    /// handler result when the handler reports failure.
    pub fn dispatch_request(
        &mut self,
        client: &mut Smb2Client,
        request: &ServerRequest,
    ) -> Result<ServerHandlerResult> {
        let Some((_, handler)) = self
            .request_handlers
            .iter()
            .find(|(kind, _)| *kind == request.kind)
        else {
            self.error = Some("server request handler is not registered".to_owned());
            client.set_error("server request handler is not registered");
            return Err(ErrorCode(ENOSYS));
        };

        match handler(client, request) {
            ServerHandlerResult::Error(code) => {
                self.error = Some(format!("server request handler failed: {code}"));
                client.set_error(format!("server request handler failed: {code}"));
                Err(ErrorCode(code))
            }
            result @ (ServerHandlerResult::Ok | ServerHandlerResult::ReplyQueued(_)) => Ok(result),
        }
    }

    /// Records an accepted connection supplied by a backend and invokes callbacks.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if `client_fd` is negative, or the callback's
    /// negative return value when the accepted callback rejects the connection.
    pub fn accept_backend_connection(
        &mut self,
        client_fd: Socket,
        opaque: *mut c_void,
    ) -> Result<Smb2Client> {
        if client_fd < 0 {
            self.error = Some("invalid accepted server socket".to_owned());
            return Err(ErrorCode(EINVAL));
        }
        if let Some(callback) = &self.accepted_callback {
            let status = callback(client_fd, opaque);
            if status < 0 {
                self.error = Some(format!("server accept callback failed: {status}"));
                return Err(ErrorCode(status));
            }
        }

        let mut client = Smb2Client::new();
        client.set_fd(client_fd);
        client.set_opaque(Some(opaque as usize));
        if let Some(callback) = &self.client_connection_callback {
            callback(&mut client, opaque);
        }
        Ok(client)
    }
}

/// High-level SMB2 client context corresponding to `struct smb2_context`.
#[derive(Debug)]
pub struct Smb2Client {
    server: Option<String>,
    share: Option<String>,
    share_connection: ShareConnectionState,
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
    lifecycle: Smb2ClientState,
    active: bool,
    session_id: Option<u64>,
    session_key: Vec<u8>,
    derived_keys: Option<SessionDerivedKeys>,
    encryption_cipher: Option<u16>,
    tree_id: Option<u32>,
    last_request_message_id: u64,
    last_reply_message_id: u64,
    max_read_size: u32,
    max_write_size: u32,
    queued_operations: Vec<Smb2Operation>,
    operation_records: Vec<OperationRecord>,
    command_records: Vec<CommandRecord>,
    completed_operations: Vec<OperationRecord>,
    completed_results: Vec<OperationCompletion>,
    handle_offsets: Vec<HandleOffset>,
    local_objects: Vec<LocalObject>,
    transport_write: Option<TransportWriteState>,
    transport_read_bytes: Vec<u8>,
    transport_read_buffer: Vec<u8>,
}

impl Default for Smb2Client {
    fn default() -> Self {
        Self {
            server: None,
            share: None,
            share_connection: ShareConnectionState::Disconnected,
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
            lifecycle: Smb2ClientState::Active,
            active: true,
            session_id: None,
            session_key: Vec::new(),
            derived_keys: None,
            encryption_cipher: None,
            tree_id: None,
            last_request_message_id: 0,
            last_reply_message_id: 0,
            max_read_size: DEFAULT_MAX_READ_SIZE,
            max_write_size: DEFAULT_MAX_WRITE_SIZE,
            queued_operations: Vec::new(),
            operation_records: Vec::new(),
            command_records: Vec::new(),
            completed_operations: Vec::new(),
            completed_results: Vec::new(),
            handle_offsets: Vec::new(),
            local_objects: Vec::new(),
            transport_write: None,
            transport_read_bytes: Vec::new(),
            transport_read_buffer: Vec::new(),
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
        self.cancel_pending_operations();
        self.fd = -1;
        self.fds.clear();
        self.events = 0;
        self.transport_write = None;
        self.transport_read_bytes.clear();
        self.transport_read_buffer.clear();
        self.share_connection = ShareConnectionState::Disconnected;
        self.session_id = None;
        self.session_key.clear();
        self.derived_keys = None;
        self.encryption_cipher = None;
        self.tree_id = None;
        self.lifecycle = Smb2ClientState::Closed;
        self.active = true;
    }

    /// Marks the context as destroyed and clears queued operation skeletons.
    pub fn destroy_context(&mut self) {
        self.close_context();
        self.queued_operations.clear();
        self.operation_records.clear();
        self.command_records.clear();
        self.handle_offsets.clear();
        self.local_objects.clear();
        self.completed_operations.clear();
        self.completed_results.clear();
        self.lifecycle = Smb2ClientState::Destroyed;
        self.active = false;
    }

    /// Returns whether the context is currently active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.lifecycle, Smb2ClientState::Active)
    }

    /// Returns the observable lifecycle state of this context.
    #[must_use]
    pub const fn state(&self) -> Smb2ClientState {
        self.lifecycle
    }

    /// Returns the primary socket descriptor used by the context skeleton.
    #[must_use]
    pub const fn fd(&self) -> Socket {
        self.fd
    }

    /// Replaces the primary socket descriptor used by event-loop integration tests.
    pub fn set_fd(&mut self, fd: Socket) {
        if !self.ensure_context_open() {
            return;
        }
        let old_fd = self.fd;
        self.fd = fd;
        self.fds.clear();
        if fd >= 0 {
            self.fds.push(fd);
        }
        if old_fd >= 0 && old_fd != fd {
            self.notify_fd_change(old_fd, SMB2_DEL_FD);
        }
        if fd >= 0 && old_fd != fd {
            self.notify_fd_change(fd, SMB2_ADD_FD);
        }
    }

    /// Returns the event mask currently requested by the context skeleton.
    #[must_use]
    pub const fn which_events(&self) -> i32 {
        self.events
    }

    /// Sets the event mask requested by the context skeleton.
    pub fn set_events(&mut self, events: i32) {
        if !self.ensure_context_open() {
            return;
        }
        self.change_events(events);
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

    /// Processes an event mask and advances the local operation state machine.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the context has been destroyed.
    pub fn service(&mut self, revents: i32) -> Result<()> {
        self.ensure_context_active()?;
        if revents & SMB2_POLLERR != 0 {
            self.error_string = Some("smb2_service: socket error".to_owned());
            self.fail_pending_operations(ErrorCode(EINVAL));
            return Err(ErrorCode(EINVAL));
        }
        if revents & SMB2_POLLHUP != 0 {
            self.error_string = Some("smb2_service: socket hang-up".to_owned());
            self.fail_pending_operations(ErrorCode(EINVAL));
            return Err(ErrorCode(EINVAL));
        }
        if self.fd < 0 && revents & SMB2_POLLOUT != 0 {
            self.set_fd(SYNTHETIC_CONNECTED_FD);
        }
        if revents & SMB2_POLLOUT != 0 {
            self.submit_next_operation();
        }
        if revents & SMB2_POLLIN != 0 {
            self.complete_inflight_operation(None);
        }
        self.refresh_events();
        Ok(())
    }

    /// Advances one deterministic local async operation without an OS socket.
    ///
    /// This is used by C ABI adapters that provide their own poll-compatible
    /// wake descriptor before real network transport is available.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the context has been closed or destroyed.
    pub fn service_local_ready(&mut self) -> Result<()> {
        self.ensure_context_active()?;
        self.submit_next_operation();
        self.complete_inflight_operation(None);
        self.refresh_events();
        Ok(())
    }

    /// Processes an event mask using an injected byte transport instead of an OS socket.
    ///
    /// This writes deterministic local request frames for queued operations and
    /// completes one in-flight operation when response bytes are read. It does
    /// not parse SMB2 protocol payloads yet.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the context is inactive, an error/hang-up
    /// event is supplied, or the injected transport rejects the descriptor.
    pub fn service_with_transport<T: Smb2TransportAdapter + ?Sized>(
        &mut self,
        revents: i32,
        transport: &mut T,
    ) -> Result<()> {
        self.ensure_context_active()?;
        if revents & SMB2_POLLERR != 0 {
            self.error_string = Some("smb2_service: socket error".to_owned());
            self.fail_pending_operations(ErrorCode(EINVAL));
            return Err(ErrorCode(EINVAL));
        }
        if revents & SMB2_POLLHUP != 0 {
            self.error_string = Some("smb2_service: socket hang-up".to_owned());
            self.fail_pending_operations(ErrorCode(EINVAL));
            return Err(ErrorCode(EINVAL));
        }
        if self.fd < 0 && revents & SMB2_POLLOUT != 0 {
            self.set_fd(SYNTHETIC_CONNECTED_FD);
        }
        if revents & SMB2_POLLOUT != 0 {
            self.submit_next_operation_to_transport(transport)?;
        }
        if revents & SMB2_POLLIN != 0 {
            self.complete_inflight_operation_from_transport(transport)?;
        }
        let requested = self.requested_events();
        let ready = if self.fd >= 0 {
            transport.ready_events(self.fd, requested)?
        } else {
            requested & SMB2_POLLOUT
        };
        self.change_events(ready | self.local_pending_events());
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

    /// Processes events for a descriptor using an injected byte transport.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the descriptor is not known to this context or
    /// if the injected transport rejects the descriptor.
    pub fn service_fd_with_transport<T: Smb2TransportAdapter + ?Sized>(
        &mut self,
        fd: Socket,
        revents: i32,
        transport: &mut T,
    ) -> Result<()> {
        if fd != -1 && fd != self.fd && !self.fds.contains(&fd) {
            self.error_string = Some("unknown file descriptor".to_owned());
            return Err(ErrorCode(EINVAL));
        }
        self.service_with_transport(revents, transport)
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

    /// Sets the remembered server name without opening a network connection.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the context is destroyed or `server` is empty.
    pub fn set_server(&mut self, server: &str) -> Result<()> {
        self.ensure_context_active()?;
        self.validate_non_empty_arg("server", server)?;
        self.server = Some(server.to_owned());
        self.share_connection = ShareConnectionState::Disconnected;
        Ok(())
    }

    /// Returns the remembered server name, if any.
    #[must_use]
    pub fn server(&self) -> Option<&str> {
        self.server.as_deref()
    }

    /// Sets the remembered share name without opening a tree connection.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the context is destroyed or `share` is empty.
    pub fn set_share(&mut self, share: &str) -> Result<()> {
        self.ensure_context_active()?;
        self.validate_non_empty_arg("share", share)?;
        self.share = Some(share.to_owned());
        self.share_connection = ShareConnectionState::Disconnected;
        Ok(())
    }

    /// Returns the currently connected or configured share name, if any.
    #[must_use]
    pub fn share(&self) -> Option<&str> {
        self.share.as_deref()
    }

    /// Parses an `smb://[[domain;]user@]server/share[/path]` URL.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` when the URL has an unsupported scheme or lacks
    /// a server/share component.
    pub fn parse_url(&mut self, url: &str) -> Result<Smb2Url> {
        self.ensure_context_active()?;
        let Some(body) = url.strip_prefix("smb://") else {
            return self.error_result("URL does not start with 'smb://'", ErrorCode(EINVAL));
        };
        let (path_part, _) = body.split_once('?').unwrap_or((body, ""));
        let Some((auth_server, share_path)) = path_part.split_once('/') else {
            return self.error_result("Wrong URL format", ErrorCode(EINVAL));
        };
        let (share, path) = share_path
            .split_once('/')
            .map_or((share_path, None), |(share, path)| {
                (share, Some(path.to_owned()))
            });
        if auth_server.is_empty() || share.is_empty() {
            return self.error_result("Wrong URL format", ErrorCode(EINVAL));
        }
        let (domain, auth_server) = match auth_server.split_once(';') {
            Some((domain, rest)) if !domain.is_empty() && !rest.is_empty() => {
                (Some(domain.to_owned()), rest)
            }
            Some(_) => return self.error_result("Wrong URL format", ErrorCode(EINVAL)),
            None => (None, auth_server),
        };
        let (user, server) = match auth_server.split_once('@') {
            Some((user, server)) if !user.is_empty() && !server.is_empty() => {
                (Some(user.to_owned()), server)
            }
            Some(_) => return self.error_result("Wrong URL format", ErrorCode(EINVAL)),
            None => (None, auth_server),
        };
        if server.is_empty() {
            return self.error_result("Wrong URL format", ErrorCode(EINVAL));
        }
        Ok(Smb2Url {
            domain,
            user,
            server: server.to_owned(),
            share: share.to_owned(),
            path,
        })
    }

    /// Applies parsed URL fields to this context without queueing I/O.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the context is destroyed or the parsed URL has
    /// empty server/share fields.
    pub fn apply_url(&mut self, url: &Smb2Url) -> Result<()> {
        self.ensure_context_active()?;
        self.validate_non_empty_arg("server", &url.server)?;
        self.validate_non_empty_arg("share", &url.share)?;
        self.domain = url.domain.clone();
        if let Some(user) = &url.user {
            self.user = Some(user.clone());
        }
        self.server = Some(url.server.clone());
        self.share = Some(url.share.clone());
        self.share_connection = ShareConnectionState::Disconnected;
        Ok(())
    }

    /// Parses and applies an SMB URL without queueing network I/O.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if parsing or applying the URL fails.
    pub fn set_url(&mut self, url: &str) -> Result<Smb2Url> {
        let parsed = self.parse_url(url)?;
        self.apply_url(&parsed)?;
        Ok(parsed)
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
        self.ensure_context_active()?;
        if self.share_connection != ShareConnectionState::Disconnected {
            return self.error_result("share is already connected", ErrorCode(EISCONN));
        }
        self.validate_non_empty_arg("server", server)?;
        self.validate_non_empty_arg("share", share)?;
        self.server = Some(server.to_owned());
        self.share = Some(share.to_owned());
        self.share_connection = ShareConnectionState::Connecting;
        self.queue_operation(Smb2Operation::ConnectShare {
            server: server.to_owned(),
            share: share.to_owned(),
            user: None,
        });
        Ok(())
    }

    /// Builds an asynchronous TCP connect request skeleton.
    pub fn connect_async(&mut self, server: &str) {
        if self.ensure_context_active().is_err()
            || self.validate_non_empty_arg("server", server).is_err()
        {
            return;
        }
        self.server = Some(server.to_owned());
        self.share_connection = ShareConnectionState::Disconnected;
        self.queue_operation(Smb2Operation::Connect {
            server: server.to_owned(),
        });
    }

    /// Builds an asynchronous share-connect request skeleton.
    pub fn connect_share_async(&mut self, server: &str, share: &str, user: Option<&str>) {
        if self.ensure_context_active().is_err()
            || self.validate_non_empty_arg("server", server).is_err()
            || self.validate_non_empty_arg("share", share).is_err()
        {
            return;
        }
        if self.share_connection != ShareConnectionState::Disconnected {
            self.set_error_for_code("share is already connected", ErrorCode(EISCONN));
            return;
        }
        self.server = Some(server.to_owned());
        self.share = Some(share.to_owned());
        self.share_connection = ShareConnectionState::Connecting;
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
        self.ensure_context_active()?;
        if self.share_connection != ShareConnectionState::Connected {
            return self.error_result("share is not connected", ErrorCode(ENOTCONN));
        }
        self.share_connection = ShareConnectionState::Disconnecting;
        self.queue_operation(Smb2Operation::DisconnectShare);
        Ok(())
    }

    /// Parses an SMB URL and queues a local share connection operation.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if parsing fails or a share is already connected.
    pub fn connect_url(&mut self, url: &str) -> Result<()> {
        let parsed = self.parse_url(url)?;
        self.domain = parsed.domain.clone();
        if let Some(user) = &parsed.user {
            self.user = Some(user.clone());
        }
        self.connect_share(&parsed.server, &parsed.share)
    }

    /// Completes a share connection through the deterministic local state machine.
    ///
    /// This does not perform socket or SMB2 protocol I/O.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if validation fails or local completion fails.
    pub fn connect_share_local(
        &mut self,
        server: &str,
        share: &str,
    ) -> Result<Smb2OperationResult> {
        self.connect_share(server, share)?;
        self.complete_next_local_operation()
    }

    /// Completes a queued share disconnect through the deterministic local state machine.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if there is no connected share or completion fails.
    pub fn disconnect_share_local(&mut self) -> Result<Smb2OperationResult> {
        self.disconnect_share()?;
        self.complete_next_local_operation()
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

    /// Records an authenticated session key and derives signing/sealing keys.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` when key derivation fails for the selected dialect.
    pub fn apply_session_setup_keys(
        &mut self,
        session_id: u64,
        session_key: &[u8],
        preauth_hash: Option<&[u8; crate::include::libsmb2_private::SMB2_PREAUTH_HASH_SIZE]>,
    ) -> Result<()> {
        let keys = derive_session_keys(self.dialect, session_key, preauth_hash).map_err(|_| {
            self.set_error_for_code("failed to derive SMB session keys", ErrorCode(EINVAL));
            ErrorCode(EINVAL)
        })?;
        self.session_id = Some(session_id);
        self.session_key.clear();
        self.session_key.extend_from_slice(session_key);
        self.derived_keys = Some(keys);
        Ok(())
    }

    /// Records the selected SMB3 encryption cipher for sealing.
    pub const fn set_encryption_cipher(&mut self, cipher: Option<u16>) {
        self.encryption_cipher = cipher;
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
        if !self.prepare_share_path_operation(path) {
            return;
        }
        self.queue_operation(Smb2Operation::OpenDir {
            path: path.to_owned(),
        });
    }

    /// Builds an open request skeleton.
    pub fn open_async(&mut self, path: &str, flags: i32) {
        if !self.prepare_share_path_operation(path) {
            return;
        }
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
        if !self.prepare_share_path_operation(path) {
            return;
        }
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
        if !self.prepare_handle_operation(handle) {
            return;
        }
        self.queue_operation(Smb2Operation::Close {
            file_id: handle.id(),
        });
    }

    /// Builds an fsync request skeleton.
    pub fn fsync_async(&mut self, handle: &FileHandle) {
        if !self.prepare_handle_operation(handle) {
            return;
        }
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
        if !self.prepare_read_operation(handle, count) {
            return;
        }
        self.queue_operation(Smb2Operation::Read {
            file_id: handle.id(),
            count,
            offset: Some(offset),
        });
    }

    /// Builds a positioned write request skeleton.
    pub fn pwrite_async(&mut self, handle: &FileHandle, count: u32, offset: u64) {
        if !self.prepare_write_operation(handle, count) {
            return;
        }
        self.queue_operation(Smb2Operation::Write {
            file_id: handle.id(),
            count,
            offset: Some(offset),
        });
    }

    /// Builds a sequential read request skeleton.
    pub fn read_async(&mut self, handle: &FileHandle, count: u32) {
        if !self.prepare_read_operation(handle, count) {
            return;
        }
        self.queue_operation(Smb2Operation::Read {
            file_id: handle.id(),
            count,
            offset: None,
        });
    }

    /// Builds a sequential write request skeleton.
    pub fn write_async(&mut self, handle: &FileHandle, count: u32) {
        if !self.prepare_write_operation(handle, count) {
            return;
        }
        self.queue_operation(Smb2Operation::Write {
            file_id: handle.id(),
            count,
            offset: None,
        });
    }

    /// Opens a path and completes it through the deterministic local state machine.
    ///
    /// This does not perform socket or SMB2 protocol I/O.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if the context is not share-connected, `path` is
    /// empty, or local completion does not produce an open result.
    pub fn open(&mut self, path: &str, flags: i32) -> Result<FileHandle> {
        self.ensure_share_connected()?;
        self.validate_non_empty_arg("path", path)?;
        self.open_async(path, flags);
        match self.complete_next_local_operation()? {
            Smb2OperationResult::Open { handle, .. } => Ok(handle),
            _ => self.error_result("open did not produce a file handle", ErrorCode(EINVAL)),
        }
    }

    /// Closes a handle through the deterministic local state machine.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if the context is not share-connected or the
    /// handle id is invalid.
    pub fn close(&mut self, handle: &FileHandle) -> Result<()> {
        self.ensure_share_connected()?;
        self.validate_handle_arg(handle)?;
        self.close_async(handle);
        self.complete_next_local_operation().map(|_| ())
    }

    /// Reads from `handle` at `offset` through the deterministic local state machine.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if validation or local completion fails.
    pub fn pread(&mut self, handle: &FileHandle, count: u32, offset: u64) -> Result<Vec<u8>> {
        self.ensure_share_connected()?;
        self.validate_handle_arg(handle)?;
        self.validate_read_count(count)?;
        self.pread_async(handle, count, offset);
        match self.complete_next_local_operation()? {
            Smb2OperationResult::Read { data, .. } => Ok(data),
            _ => self.error_result("read did not produce data", ErrorCode(EINVAL)),
        }
    }

    /// Reads sequentially from `handle` using the cached local handle offset.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if validation or local completion fails.
    pub fn read(&mut self, handle: &FileHandle, count: u32) -> Result<Vec<u8>> {
        self.ensure_share_connected()?;
        self.validate_handle_arg(handle)?;
        self.validate_read_count(count)?;
        self.read_async(handle, count);
        match self.complete_next_local_operation()? {
            Smb2OperationResult::Read { data, .. } => Ok(data),
            _ => self.error_result("read did not produce data", ErrorCode(EINVAL)),
        }
    }

    /// Writes zero-filled placeholder bytes at `offset` through the local state machine.
    ///
    /// The current public skeleton accepts a byte count, not a caller buffer, so
    /// the local object is extended with zeroes instead of real payload bytes.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if validation or local completion fails.
    pub fn pwrite(&mut self, handle: &FileHandle, count: u32, offset: u64) -> Result<u32> {
        self.ensure_share_connected()?;
        self.validate_handle_arg(handle)?;
        self.validate_write_count(count)?;
        self.pwrite_async(handle, count, offset);
        match self.complete_next_local_operation()? {
            Smb2OperationResult::Write { bytes_written, .. } => Ok(bytes_written),
            _ => self.error_result("write did not produce a byte count", ErrorCode(EINVAL)),
        }
    }

    /// Writes zero-filled placeholder bytes using the cached local handle offset.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if validation or local completion fails.
    pub fn write(&mut self, handle: &FileHandle, count: u32) -> Result<u32> {
        self.ensure_share_connected()?;
        self.validate_handle_arg(handle)?;
        self.validate_write_count(count)?;
        self.write_async(handle, count);
        match self.complete_next_local_operation()? {
            Smb2OperationResult::Write { bytes_written, .. } => Ok(bytes_written),
            _ => self.error_result("write did not produce a byte count", ErrorCode(EINVAL)),
        }
    }

    /// Creates a directory through the deterministic local state machine.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if the context is not share-connected, `path` is
    /// empty, or local completion fails.
    pub fn mkdir(&mut self, path: &str) -> Result<()> {
        self.ensure_share_connected()?;
        self.validate_non_empty_arg("path", path)?;
        self.mkdir_async(path);
        self.complete_next_local_operation().map(|_| ())
    }

    /// Builds an lseek request skeleton and returns the requested resulting offset.
    #[must_use]
    pub fn lseek(&mut self, handle: &FileHandle, offset: i64, whence: i32) -> Option<u64> {
        if !self.prepare_handle_operation(handle) {
            return None;
        }
        let resolved = resolve_lseek_offset(handle.offset(), offset, whence);
        if resolved.is_none() {
            self.set_error_for_code("invalid seek offset", ErrorCode(EINVAL));
            return None;
        }
        self.queue_operation(Smb2Operation::Lseek {
            file_id: handle.id(),
            offset,
            whence,
        });
        resolved
    }

    /// Builds an unlink request skeleton.
    pub fn unlink_async(&mut self, path: &str) {
        if !self.prepare_share_path_operation(path) {
            return;
        }
        self.queue_operation(Smb2Operation::Unlink {
            path: path.to_owned(),
        });
    }

    /// Builds an rmdir request skeleton.
    pub fn rmdir_async(&mut self, path: &str) {
        if !self.prepare_share_path_operation(path) {
            return;
        }
        self.queue_operation(Smb2Operation::Rmdir {
            path: path.to_owned(),
        });
    }

    /// Builds a mkdir request skeleton.
    pub fn mkdir_async(&mut self, path: &str) {
        if !self.prepare_share_path_operation(path) {
            return;
        }
        self.queue_operation(Smb2Operation::Mkdir {
            path: path.to_owned(),
        });
    }

    /// Builds a statvfs request skeleton.
    pub fn statvfs_async(&mut self, path: &str) {
        if !self.prepare_share_path_operation(path) {
            return;
        }
        self.queue_operation(Smb2Operation::StatVfs {
            path: path.to_owned(),
        });
    }

    /// Builds an fstat request skeleton.
    pub fn fstat_async(&mut self, handle: &FileHandle) {
        if !self.prepare_handle_operation(handle) {
            return;
        }
        self.queue_operation(Smb2Operation::Fstat {
            file_id: handle.id(),
        });
    }

    /// Builds a stat request skeleton.
    pub fn stat_async(&mut self, path: &str) {
        if !self.prepare_share_path_operation(path) {
            return;
        }
        self.queue_operation(Smb2Operation::Stat {
            path: path.to_owned(),
        });
    }

    /// Returns local metadata for `path` through the deterministic state machine.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if validation or local completion fails.
    pub fn stat(&mut self, path: &str) -> Result<Stat> {
        self.ensure_share_connected()?;
        self.validate_non_empty_arg("path", path)?;
        self.stat_async(path);
        match self.complete_next_local_operation()? {
            Smb2OperationResult::Stat { stat } => Ok(stat),
            _ => self.error_result("stat did not produce metadata", ErrorCode(EINVAL)),
        }
    }

    /// Returns local metadata for an open file handle.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if validation or local completion fails.
    pub fn fstat(&mut self, handle: &FileHandle) -> Result<Stat> {
        self.ensure_share_connected()?;
        self.validate_handle_arg(handle)?;
        self.fstat_async(handle);
        match self.complete_next_local_operation()? {
            Smb2OperationResult::Stat { stat } => Ok(stat),
            _ => self.error_result("fstat did not produce metadata", ErrorCode(EINVAL)),
        }
    }

    /// Returns local filesystem metadata for `path`.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if validation or local completion fails.
    pub fn statvfs(&mut self, path: &str) -> Result<StatVfs> {
        self.ensure_share_connected()?;
        self.validate_non_empty_arg("path", path)?;
        self.statvfs_async(path);
        match self.complete_next_local_operation()? {
            Smb2OperationResult::StatVfs { statvfs } => Ok(statvfs),
            _ => self.error_result("statvfs did not produce metadata", ErrorCode(EINVAL)),
        }
    }

    /// Builds a rename request skeleton.
    pub fn rename_async(&mut self, old_path: &str, new_path: &str) {
        if !self.prepare_share_path_operation(old_path)
            || !self.prepare_share_path_operation(new_path)
        {
            return;
        }
        self.queue_operation(Smb2Operation::Rename {
            old_path: old_path.to_owned(),
            new_path: new_path.to_owned(),
        });
    }

    /// Renames a local object in the deterministic local state machine.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if validation or local completion fails.
    pub fn rename(&mut self, old_path: &str, new_path: &str) -> Result<()> {
        self.ensure_share_connected()?;
        self.validate_non_empty_arg("old_path", old_path)?;
        self.validate_non_empty_arg("new_path", new_path)?;
        self.rename_async(old_path, new_path);
        self.complete_next_local_operation().map(|_| ())
    }

    /// Builds a truncate request skeleton.
    pub fn truncate_async(&mut self, path: &str, length: u64) {
        if !self.prepare_share_path_operation(path) {
            return;
        }
        self.queue_operation(Smb2Operation::Truncate {
            path: path.to_owned(),
            length,
        });
    }

    /// Truncates a local path in the deterministic local state machine.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if validation or local completion fails.
    pub fn truncate(&mut self, path: &str, length: u64) -> Result<()> {
        self.ensure_share_connected()?;
        self.validate_non_empty_arg("path", path)?;
        self.truncate_async(path, length);
        self.complete_next_local_operation().map(|_| ())
    }

    /// Builds an ftruncate request skeleton.
    pub fn ftruncate_async(&mut self, handle: &FileHandle, length: u64) {
        if !self.prepare_handle_operation(handle) {
            return;
        }
        self.queue_operation(Smb2Operation::Ftruncate {
            file_id: handle.id(),
            length,
        });
    }

    /// Truncates a local file handle in the deterministic local state machine.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if validation or local completion fails.
    pub fn ftruncate(&mut self, handle: &FileHandle, length: u64) -> Result<()> {
        self.ensure_share_connected()?;
        self.validate_handle_arg(handle)?;
        self.ftruncate_async(handle, length);
        self.complete_next_local_operation().map(|_| ())
    }

    /// Builds a readlink request skeleton.
    pub fn readlink_async(&mut self, path: &str, buffer_size: u32) {
        if !self.prepare_share_path_operation(path) {
            return;
        }
        self.queue_operation(Smb2Operation::Readlink {
            path: path.to_owned(),
            buffer_size,
        });
    }

    /// Builds an echo request skeleton.
    pub fn echo_async(&mut self) {
        if self.ensure_context_active().is_err() {
            return;
        }
        self.queue_operation(Smb2Operation::Echo);
    }

    /// Builds a path-based notify-change request skeleton.
    pub fn notify_change_async(&mut self, path: &str, flags: u16, filter: u32, repeat: bool) {
        if !self.prepare_share_path_operation(path) {
            return;
        }
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
        if !self.prepare_handle_operation(handle) {
            return;
        }
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
        self.operation_records.clear();
        self.command_records.clear();
        self.transport_write = None;
        self.transport_read_buffer.clear();
        self.handle_offsets.clear();
        self.refresh_events();
    }

    /// Returns operation records in queue/in-flight order.
    #[must_use]
    pub fn operation_records(&self) -> &[OperationRecord] {
        &self.operation_records
    }

    /// Returns operations that completed or were cancelled locally.
    #[must_use]
    pub fn completed_operations(&self) -> &[OperationRecord] {
        &self.completed_operations
    }

    /// Returns typed results completed by the local high-level client loop.
    #[must_use]
    pub fn completed_results(&self) -> &[OperationCompletion] {
        &self.completed_results
    }

    /// Removes and returns typed results completed by the local high-level client loop.
    #[must_use]
    pub fn take_completed_results(&mut self) -> Vec<OperationCompletion> {
        core::mem::take(&mut self.completed_results)
    }

    /// Returns the most recent typed completion result, if any.
    #[must_use]
    pub fn last_completed_result(&self) -> Option<&OperationCompletion> {
        self.completed_results.last()
    }

    /// Returns the cached sequential offset for a locally completed file handle.
    #[must_use]
    pub fn local_handle_offset(&self, file_id: [u8; SMB2_FILE_ID_SIZE]) -> Option<u64> {
        self.handle_offsets
            .iter()
            .find(|handle| handle.file_id == file_id)
            .map(|handle| handle.offset)
    }

    /// Returns raw response bytes consumed by [`Smb2Client::service_with_transport`].
    #[must_use]
    pub fn transport_read_bytes(&self) -> &[u8] {
        &self.transport_read_bytes
    }

    /// Removes and returns raw response bytes consumed by the injected transport path.
    #[must_use]
    pub fn take_transport_read_bytes(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.transport_read_bytes)
    }

    /// Returns generated command descriptors in queue order.
    #[must_use]
    pub fn command_records(&self) -> &[CommandRecord] {
        &self.command_records
    }

    /// Opens a named pipe through the injected SMB2 transport path.
    ///
    /// The returned file id is the same deterministic local handle used by the
    /// existing open completion path when the transport does not return one.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if the context or transport rejects the open.
    pub fn named_pipe_open_with_transport<T: Smb2TransportAdapter + ?Sized>(
        &mut self,
        path: &str,
        transport: &mut T,
    ) -> Result<[u8; SMB2_FILE_ID_SIZE]> {
        self.ensure_share_connected()?;
        validate_non_empty(path)?;
        let completed_start = self.completed_results.len();
        self.open_async(path, 0);
        self.service_with_transport(SMB2_POLLOUT, transport)?;
        self.service_with_transport(SMB2_POLLIN, transport)?;
        self.file_id_from_open_completion(completed_start)
    }

    /// Writes encoded named-pipe bytes through the injected SMB2 transport.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if the transport rejects the descriptor or cannot
    /// accept the complete buffer.
    pub fn named_pipe_write_with_transport<T: Smb2TransportAdapter + ?Sized>(
        &mut self,
        _file_id: [u8; SMB2_FILE_ID_SIZE],
        bytes: &[u8],
        transport: &mut T,
    ) -> Result<usize> {
        self.ensure_share_connected()?;
        if self.fd < 0 {
            self.set_fd(SYNTHETIC_CONNECTED_FD);
        }
        let mut written = 0usize;
        while written < bytes.len() {
            let count = transport.write(self.fd, &bytes[written..])?;
            if count == 0 {
                self.error_string = Some("named pipe transport write made no progress".to_owned());
                return Err(ErrorCode(EINVAL));
            }
            written = written.saturating_add(count).min(bytes.len());
        }
        Ok(written)
    }

    /// Reads named-pipe bytes through the injected SMB2 transport.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCode`] if the transport rejects the descriptor.
    pub fn named_pipe_read_with_transport<T: Smb2TransportAdapter + ?Sized>(
        &mut self,
        _file_id: [u8; SMB2_FILE_ID_SIZE],
        buf: &mut [u8],
        transport: &mut T,
    ) -> Result<usize> {
        self.ensure_share_connected()?;
        if self.fd < 0 {
            self.set_fd(SYNTHETIC_CONNECTED_FD);
        }
        transport.read(self.fd, buf)
    }

    fn ensure_context_open(&mut self) -> bool {
        if self.lifecycle == Smb2ClientState::Destroyed {
            self.set_error_for_code("context is destroyed", ErrorCode(EINVAL));
            return false;
        }
        true
    }

    fn ensure_context_active(&mut self) -> Result<()> {
        match self.lifecycle {
            Smb2ClientState::Active => Ok(()),
            Smb2ClientState::Closed => self.error_result("context is closed", ErrorCode(EINVAL)),
            Smb2ClientState::Destroyed => {
                self.error_result("context is destroyed", ErrorCode(EINVAL))
            }
        }
    }

    fn ensure_share_connected(&mut self) -> Result<()> {
        self.ensure_context_active()?;
        if self.share_connection == ShareConnectionState::Connected {
            Ok(())
        } else {
            self.error_result("share is not connected", ErrorCode(ENOTCONN))
        }
    }

    fn validate_non_empty_arg(&mut self, name: &str, value: &str) -> Result<()> {
        if value.is_empty() {
            self.error_result(&format!("{name} must not be empty"), ErrorCode(EINVAL))
        } else {
            Ok(())
        }
    }

    fn validate_handle_arg(&mut self, handle: &FileHandle) -> Result<()> {
        if handle.id().iter().all(|byte| *byte == 0) {
            self.error_result("file handle id must not be all zeroes", ErrorCode(EINVAL))
        } else {
            Ok(())
        }
    }

    fn validate_read_count(&mut self, count: u32) -> Result<()> {
        if self.max_read_size != 0 && count > self.max_read_size {
            self.error_result("read count exceeds negotiated maximum", ErrorCode(EINVAL))
        } else {
            Ok(())
        }
    }

    fn validate_write_count(&mut self, count: u32) -> Result<()> {
        if self.max_write_size != 0 && count > self.max_write_size {
            self.error_result("write count exceeds negotiated maximum", ErrorCode(EINVAL))
        } else {
            Ok(())
        }
    }

    fn prepare_share_path_operation(&mut self, path: &str) -> bool {
        self.ensure_share_connected().is_ok() && self.validate_non_empty_arg("path", path).is_ok()
    }

    fn prepare_handle_operation(&mut self, handle: &FileHandle) -> bool {
        self.ensure_share_connected().is_ok() && self.validate_handle_arg(handle).is_ok()
    }

    fn prepare_read_operation(&mut self, handle: &FileHandle, count: u32) -> bool {
        self.prepare_handle_operation(handle) && self.validate_read_count(count).is_ok()
    }

    fn prepare_write_operation(&mut self, handle: &FileHandle, count: u32) -> bool {
        self.prepare_handle_operation(handle) && self.validate_write_count(count).is_ok()
    }

    fn complete_next_local_operation(&mut self) -> Result<Smb2OperationResult> {
        let completed_start = self.completed_results.len();
        self.service(SMB2_POLLOUT)?;
        self.service(SMB2_POLLIN)?;
        match self.completed_results.get(completed_start) {
            Some(completion) => completion.result.clone(),
            None => self.error_result("operation did not complete", ErrorCode(EINVAL)),
        }
    }

    fn error_result<T>(&mut self, message: &str, error: ErrorCode) -> Result<T> {
        self.set_error_for_code(message, error);
        Err(error)
    }

    fn set_error_for_code(&mut self, message: &str, error: ErrorCode) {
        self.error_string = Some(message.to_owned());
        self.nterror = error.code();
    }

    fn queue_operation(&mut self, operation: Smb2Operation) {
        if self.ensure_context_active().is_err() {
            return;
        }
        self.last_request_message_id = self.last_request_message_id.saturating_add(1);
        let record = OperationRecord::queued(self.last_request_message_id, operation.clone());
        if let Some(descriptor) = command_descriptor_for_operation(&operation) {
            self.command_records.push(CommandRecord {
                message_id: self.last_request_message_id,
                descriptor,
            });
        }
        self.queued_operations.push(operation);
        self.operation_records.push(record);
        self.refresh_events();
    }

    fn change_events(&mut self, events: i32) {
        if self.events == events {
            return;
        }
        self.events = events;
        if self.fd >= 0 {
            self.notify_events_change(self.fd, events);
        }
    }

    fn refresh_events(&mut self) {
        self.change_events(self.requested_events());
    }

    fn requested_events(&self) -> i32 {
        let mut events = 0;
        if self.fd >= 0 {
            events |= SMB2_POLLIN;
        }
        events | self.local_pending_events()
    }

    fn local_pending_events(&self) -> i32 {
        if self.transport_write.is_some()
            || self
                .operation_records
                .iter()
                .any(|record| record.state == OperationState::Queued)
            || self.fd < 0 && self.server.is_some()
        {
            SMB2_POLLOUT
        } else {
            0
        }
    }

    fn submit_next_operation(&mut self) {
        if let Some(record) = self
            .operation_records
            .iter_mut()
            .find(|record| record.state == OperationState::Queued)
        {
            record.state = OperationState::InFlight;
        }
    }

    fn submit_next_operation_to_transport<T: Smb2TransportAdapter + ?Sized>(
        &mut self,
        transport: &mut T,
    ) -> Result<()> {
        if self.fd < 0 {
            return Ok(());
        }
        if self.transport_write.is_none() {
            let Some(record) = self
                .operation_records
                .iter()
                .find(|record| record.state == OperationState::Queued)
                .cloned()
            else {
                return Ok(());
            };
            self.transport_write = Some(TransportWriteState {
                message_id: record.message_id,
                frame: self.encode_operation_frame(&record)?,
                done: 0,
            });
        }

        let Some(write_state) = &mut self.transport_write else {
            return Ok(());
        };
        let written = transport.write(self.fd, &write_state.frame[write_state.done..])?;
        write_state.done = write_state
            .done
            .saturating_add(written)
            .min(write_state.frame.len());
        if write_state.done < write_state.frame.len() {
            return Ok(());
        }

        let message_id = write_state.message_id;
        self.transport_write = None;
        if let Some(record) = self.operation_records.iter_mut().find(|record| {
            record.message_id == message_id && record.state == OperationState::Queued
        }) {
            record.state = OperationState::InFlight;
        }
        Ok(())
    }

    fn complete_inflight_operation(&mut self, response: Option<SyntheticResponse>) {
        let response_message_id = response.as_ref().and_then(|response| response.message_id);
        let Some(index) = self.operation_records.iter().position(|record| {
            record.state == OperationState::InFlight
                && response_message_id.is_none_or(|message_id| record.message_id == message_id)
        }) else {
            return;
        };
        let mut record = self.operation_records.remove(index);
        let status = response.as_ref().map_or(0, |response| response.status);
        let completion_payload = response
            .as_ref()
            .map(|response| completion_payload_for_operation(&record.operation, response));
        let result = if status == 0 {
            self.apply_completed_operation(&record.operation, completion_payload.as_deref())
        } else {
            Err(ErrorCode(status))
        };
        record.state = if status == 0 {
            OperationState::Completed
        } else {
            OperationState::Failed(ErrorCode(status))
        };
        self.completed_results
            .push(OperationCompletion::new(record.message_id, result));
        self.completed_operations.push(record);
    }

    fn complete_inflight_operation_from_transport<T: Smb2TransportAdapter + ?Sized>(
        &mut self,
        transport: &mut T,
    ) -> Result<()> {
        if self.fd < 0 {
            return Ok(());
        }
        let mut buffer = [0; 4096];
        let read = transport.read(self.fd, &mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        let response_bytes = &buffer[..read];
        self.transport_read_bytes.extend_from_slice(response_bytes);
        self.transport_read_buffer.extend_from_slice(response_bytes);
        while let Some(response) = self.take_next_transport_response()? {
            if let Some(message_id) = response.message_id {
                self.last_reply_message_id = message_id;
            }
            self.apply_wire_response_metadata(&response);
            self.complete_inflight_operation(Some(response));
        }
        Ok(())
    }

    fn apply_wire_response_metadata(&mut self, response: &SyntheticResponse) {
        let Some(packet) = response.smb2_packet.as_deref() else {
            return;
        };
        let Ok(header) = smb2_decode_header_bytes(packet) else {
            return;
        };
        if response.status != 0 && header.status != SMB2_STATUS_MORE_PROCESSING_REQUIRED {
            return;
        }
        match Smb2Command::from_raw(header.command) {
            Some(Smb2Command::Negotiate) => self.apply_negotiate_reply_metadata(&response.payload),
            Some(Smb2Command::SessionSetup) => self.session_id = Some(header.session_id),
            Some(Smb2Command::TreeConnect) => self.tree_id = Some(header.tree_id),
            _ => {}
        }
    }

    fn apply_negotiate_reply_metadata(&mut self, body: &[u8]) {
        if body.len() < 64 {
            return;
        }
        self.security_mode = read_le_u16(body, 2).unwrap_or(self.security_mode);
        self.dialect = read_le_u16(body, 4).unwrap_or(self.dialect);
        let max_read_size = read_le_u32(body, 32).unwrap_or(self.max_read_size);
        let max_write_size = read_le_u32(body, 36).unwrap_or(self.max_write_size);
        self.set_max_io_sizes(max_read_size, max_write_size);
    }

    fn take_next_transport_response(&mut self) -> Result<Option<SyntheticResponse>> {
        let Some(frame_len) = transport_frame_payload_len(&self.transport_read_buffer)? else {
            return Ok(None);
        };
        let frame_end = 4usize.saturating_add(frame_len);
        if self.transport_read_buffer.len() < frame_end {
            return Ok(None);
        }
        let payload = self.transport_read_buffer[4..frame_end].to_vec();
        self.transport_read_buffer.drain(..frame_end);
        self.parse_transport_response_payload(&payload)
    }

    fn cancel_pending_operations(&mut self) {
        for mut record in self.operation_records.drain(..) {
            record.state = OperationState::Cancelled;
            self.completed_results.push(OperationCompletion::new(
                record.message_id,
                Err(ErrorCode(EINVAL)),
            ));
            self.completed_operations.push(record);
        }
        self.transport_write = None;
        self.transport_read_buffer.clear();
    }

    fn fail_pending_operations(&mut self, error: ErrorCode) {
        for mut record in self.operation_records.drain(..) {
            record.state = OperationState::Failed(error);
            self.completed_results
                .push(OperationCompletion::new(record.message_id, Err(error)));
            self.completed_operations.push(record);
        }
        self.transport_write = None;
        self.transport_read_buffer.clear();
    }

    fn apply_completed_operation(
        &mut self,
        operation: &Smb2Operation,
        payload: Option<&[u8]>,
    ) -> Result<Smb2OperationResult> {
        match operation {
            Smb2Operation::Connect { server } => {
                self.server = Some(server.clone());
                Ok(Smb2OperationResult::Connect {
                    server: server.clone(),
                })
            }
            Smb2Operation::ConnectShare {
                server,
                share,
                user,
            } => {
                self.server = Some(server.clone());
                self.share = Some(share.clone());
                if let Some(user) = user {
                    self.user = Some(user.clone());
                }
                self.share_connection = ShareConnectionState::Connected;
                Ok(Smb2OperationResult::ConnectShare {
                    server: server.clone(),
                    share: share.clone(),
                    user: user.clone(),
                })
            }
            Smb2Operation::DisconnectShare => {
                self.share = None;
                self.share_connection = ShareConnectionState::Disconnected;
                self.tree_id = None;
                Ok(Smb2OperationResult::DisconnectShare)
            }
            Smb2Operation::Open { path, .. } => {
                let handle = FileHandle::new(
                    payload
                        .and_then(parse_file_id)
                        .unwrap_or_else(|| local_file_id(self.last_reply_message_id, path)),
                );
                self.ensure_local_object(path, FileType::File);
                self.set_local_handle_path(handle.id(), path.clone(), handle.offset());
                Ok(Smb2OperationResult::Open {
                    path: path.clone(),
                    handle,
                })
            }
            Smb2Operation::OpenDir { path } => {
                self.ensure_local_object(path, FileType::Directory);
                let handle = DirectoryHandle::new(
                    payload
                        .and_then(parse_file_id)
                        .unwrap_or_else(|| local_file_id(self.last_reply_message_id, path)),
                );
                let entries = payload
                    .and_then(|payload| parse_directory_entries(payload, path))
                    .unwrap_or_else(|| self.local_directory_entries_for(path));
                self.set_local_handle_path(handle.id(), path.clone(), 0);
                Ok(Smb2OperationResult::Directory {
                    path: path.clone(),
                    handle,
                    entries,
                })
            }
            Smb2Operation::Read {
                file_id,
                count,
                offset,
            } => {
                let resolved_offset = self.resolve_operation_offset(*file_id, *offset);
                let data = payload
                    .filter(|payload| !payload.is_empty())
                    .map(|payload| payload[..payload.len().min(*count as usize)].to_vec())
                    .unwrap_or_else(|| self.local_read_data(*file_id, resolved_offset, *count));
                self.set_local_handle_offset(
                    *file_id,
                    resolved_offset.saturating_add(data.len() as u64),
                );
                Ok(Smb2OperationResult::Read {
                    file_id: *file_id,
                    offset: resolved_offset,
                    data,
                })
            }
            Smb2Operation::Write {
                file_id,
                count,
                offset,
            } => {
                let resolved_offset = self.resolve_operation_offset(*file_id, *offset);
                let bytes_written = payload
                    .and_then(parse_write_count)
                    .unwrap_or(*count)
                    .min(*count);
                self.local_write_data(*file_id, resolved_offset, bytes_written);
                self.set_local_handle_offset(
                    *file_id,
                    resolved_offset.saturating_add(u64::from(bytes_written)),
                );
                Ok(Smb2OperationResult::Write {
                    file_id: *file_id,
                    offset: resolved_offset,
                    bytes_written,
                })
            }
            Smb2Operation::Stat { path } => Ok(Smb2OperationResult::Stat {
                stat: payload
                    .and_then(parse_stat)
                    .unwrap_or_else(|| self.local_stat_for_path(path)),
            }),
            Smb2Operation::Fstat { file_id } => Ok(Smb2OperationResult::Stat {
                stat: payload.and_then(parse_stat).unwrap_or_else(|| {
                    self.local_path_for_file_id(*file_id)
                        .map(|path| self.local_stat_for_path(path))
                        .unwrap_or_else(|| local_stat_for_file_id(*file_id))
                }),
            }),
            Smb2Operation::StatVfs { .. } => Ok(Smb2OperationResult::StatVfs {
                statvfs: payload
                    .and_then(parse_statvfs)
                    .unwrap_or_else(local_statvfs),
            }),
            Smb2Operation::Readlink { path, buffer_size } => Ok(Smb2OperationResult::Readlink {
                path: path.clone(),
                target: payload
                    .filter(|payload| !payload.is_empty())
                    .map(|payload| payload[..payload.len().min(*buffer_size as usize)].to_vec())
                    .unwrap_or_else(|| self.local_readlink_target(path, *buffer_size)),
            }),
            Smb2Operation::Echo => Ok(Smb2OperationResult::Echo),
            Smb2Operation::Close { file_id } => {
                self.remove_local_handle(*file_id);
                Ok(Smb2OperationResult::Complete)
            }
            Smb2Operation::Lseek {
                file_id,
                offset,
                whence,
            } => {
                if let Some(offset) = resolve_lseek_offset(
                    self.resolve_operation_offset(*file_id, None),
                    *offset,
                    *whence,
                ) {
                    self.set_local_handle_offset(*file_id, offset);
                }
                Ok(Smb2OperationResult::Complete)
            }
            Smb2Operation::Unlink { path } | Smb2Operation::Rmdir { path } => {
                self.remove_local_object(path);
                Ok(Smb2OperationResult::Complete)
            }
            Smb2Operation::Mkdir { path } => {
                self.ensure_local_object(path, FileType::Directory);
                Ok(Smb2OperationResult::Complete)
            }
            Smb2Operation::Rename { old_path, new_path } => {
                self.rename_local_object(old_path, new_path);
                Ok(Smb2OperationResult::Complete)
            }
            Smb2Operation::Truncate { path, length } => {
                self.truncate_local_path(path, *length);
                Ok(Smb2OperationResult::Complete)
            }
            Smb2Operation::Ftruncate { file_id, length } => {
                self.truncate_local_file_id(*file_id, *length);
                Ok(Smb2OperationResult::Complete)
            }
            Smb2Operation::Fsync { .. }
            | Smb2Operation::NotifyChange { .. }
            | Smb2Operation::NotifyChangeFileHandle { .. } => Ok(Smb2OperationResult::Complete),
        }
    }

    fn resolve_operation_offset(
        &self,
        file_id: [u8; SMB2_FILE_ID_SIZE],
        offset: Option<u64>,
    ) -> u64 {
        match offset {
            Some(offset) => offset,
            None => self.local_handle_offset(file_id).unwrap_or(0),
        }
    }

    fn set_local_handle_offset(&mut self, file_id: [u8; SMB2_FILE_ID_SIZE], offset: u64) {
        if let Some(handle) = self
            .handle_offsets
            .iter_mut()
            .find(|handle| handle.file_id == file_id)
        {
            handle.offset = offset;
            return;
        }
        self.handle_offsets.push(HandleOffset {
            file_id,
            offset,
            path: None,
        });
    }

    fn set_local_handle_path(
        &mut self,
        file_id: [u8; SMB2_FILE_ID_SIZE],
        path: String,
        offset: u64,
    ) {
        if let Some(handle) = self
            .handle_offsets
            .iter_mut()
            .find(|handle| handle.file_id == file_id)
        {
            handle.offset = offset;
            handle.path = Some(path);
            return;
        }
        self.handle_offsets.push(HandleOffset {
            file_id,
            offset,
            path: Some(path),
        });
    }

    fn remove_local_handle(&mut self, file_id: [u8; SMB2_FILE_ID_SIZE]) {
        self.handle_offsets
            .retain(|handle| handle.file_id != file_id);
    }

    fn local_path_for_file_id(&self, file_id: [u8; SMB2_FILE_ID_SIZE]) -> Option<&str> {
        self.handle_offsets
            .iter()
            .find(|handle| handle.file_id == file_id)
            .and_then(|handle| handle.path.as_deref())
    }

    fn ensure_local_object(&mut self, path: &str, file_type: FileType) {
        if let Some(object) = self
            .local_objects
            .iter_mut()
            .find(|object| object.path == path)
        {
            object.file_type = file_type;
            return;
        }
        self.local_objects.push(LocalObject {
            path: path.to_owned(),
            file_type,
            data: Vec::new(),
        });
    }

    fn remove_local_object(&mut self, path: &str) {
        self.local_objects.retain(|object| object.path != path);
        self.handle_offsets
            .retain(|handle| handle.path.as_deref() != Some(path));
    }

    fn rename_local_object(&mut self, old_path: &str, new_path: &str) {
        if let Some(object) = self
            .local_objects
            .iter_mut()
            .find(|object| object.path == old_path)
        {
            object.path = new_path.to_owned();
        } else {
            self.local_objects.push(LocalObject {
                path: new_path.to_owned(),
                file_type: FileType::File,
                data: Vec::new(),
            });
        }
        for handle in &mut self.handle_offsets {
            if handle.path.as_deref() == Some(old_path) {
                handle.path = Some(new_path.to_owned());
            }
        }
    }

    fn truncate_local_path(&mut self, path: &str, length: u64) {
        self.ensure_local_object(path, FileType::File);
        if let Some(object) = self
            .local_objects
            .iter_mut()
            .find(|object| object.path == path)
        {
            object.data.resize(length as usize, 0);
            object.file_type = FileType::File;
        }
    }

    fn truncate_local_file_id(&mut self, file_id: [u8; SMB2_FILE_ID_SIZE], length: u64) {
        if let Some(path) = self.local_path_for_file_id(file_id).map(str::to_owned) {
            self.truncate_local_path(&path, length);
        }
    }

    fn local_write_data(&mut self, file_id: [u8; SMB2_FILE_ID_SIZE], offset: u64, count: u32) {
        let Some(path) = self.local_path_for_file_id(file_id).map(str::to_owned) else {
            return;
        };
        self.ensure_local_object(&path, FileType::File);
        if let Some(object) = self
            .local_objects
            .iter_mut()
            .find(|object| object.path == path)
        {
            let start = offset as usize;
            let end = start.saturating_add(count as usize);
            object.data.resize(object.data.len().max(end), 0);
        }
    }

    fn local_read_data(
        &self,
        file_id: [u8; SMB2_FILE_ID_SIZE],
        offset: u64,
        count: u32,
    ) -> Vec<u8> {
        if let Some(path) = self.local_path_for_file_id(file_id) {
            if let Some(object) = self.local_objects.iter().find(|object| object.path == path) {
                let start = offset as usize;
                if start >= object.data.len() {
                    return Vec::new();
                }
                let end = object.data.len().min(start.saturating_add(count as usize));
                return object.data[start..end].to_vec();
            }
        }
        local_read_data(file_id, offset, count)
    }

    fn local_stat_for_path(&self, path: &str) -> Stat {
        self.local_objects
            .iter()
            .find(|object| object.path == path)
            .map(|object| local_stat_with_size(path, object.file_type, object.data.len() as u64))
            .unwrap_or_else(|| local_stat(path, FileType::File))
    }

    fn local_directory_entries_for(&self, path: &str) -> Vec<DirectoryEntry> {
        let prefix = if path.ends_with('/') {
            path.to_owned()
        } else {
            format!("{path}/")
        };
        let mut entries: Vec<_> = self
            .local_objects
            .iter()
            .filter_map(|object| {
                let child = object.path.strip_prefix(&prefix)?;
                if child.is_empty() || child.contains('/') {
                    return None;
                }
                Some(DirectoryEntry {
                    name: child.to_owned(),
                    stat: local_stat_with_size(
                        &object.path,
                        object.file_type,
                        object.data.len() as u64,
                    ),
                })
            })
            .collect();
        if entries.is_empty() {
            entries = local_directory_entries(path);
        }
        entries
    }

    fn local_readlink_target(&self, path: &str, buffer_size: u32) -> Vec<u8> {
        self.local_objects
            .iter()
            .find(|object| object.path == path && object.file_type == FileType::Link)
            .map(|object| {
                object
                    .data
                    .iter()
                    .copied()
                    .take(buffer_size as usize)
                    .collect()
            })
            .unwrap_or_else(|| local_readlink_target(path, buffer_size))
    }

    fn notify_fd_change(&self, fd: Socket, cmd: i32) {
        if let Some(callback) = &self.fd_event_callbacks.change_fd {
            callback(self, fd, cmd);
        }
    }

    fn notify_events_change(&self, fd: Socket, events: i32) {
        if let Some(callback) = &self.fd_event_callbacks.change_events {
            callback(self, fd, events);
        }
    }

    fn file_id_from_open_completion(
        &self,
        completed_start: usize,
    ) -> Result<[u8; SMB2_FILE_ID_SIZE]> {
        self.completed_results
            .iter()
            .skip(completed_start)
            .find_map(|completion| match &completion.result {
                Ok(Smb2OperationResult::Open { handle, .. }) => Some(Ok(handle.id())),
                Err(error) => Some(Err(*error)),
                _ => None,
            })
            .unwrap_or(Err(ErrorCode(EINVAL)))
    }

    fn encode_operation_frame(&mut self, record: &OperationRecord) -> Result<Vec<u8>> {
        let mut pdu = operation_request_pdu(record)?;
        pdu.header.session_id = self.session_id.unwrap_or(0);
        if let Some(tree_id) = self.tree_id {
            pdu.header.tree_id = tree_id;
        }
        let mut context = self.session_context();
        smb2_encode_pdu_frame_with_context(&mut context, &mut pdu).map_err(|error| {
            self.set_error_for_code(
                &format!("failed to encode SMB2 PDU: {error:?}"),
                ErrorCode(EINVAL),
            );
            ErrorCode(EINVAL)
        })
    }

    fn parse_transport_response_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<Option<SyntheticResponse>> {
        let mut context = self.session_context();
        if let Ok(pdu) = smb2_decode_pdu_payload_with_context(&mut context, payload) {
            return Ok(Some(smb2_response_from_pdu(pdu)));
        }
        parse_transport_response_payload(payload)
    }

    fn session_context(&self) -> Context {
        let mut context = Context::new();
        context.session_id = self.session_id.unwrap_or(0);
        context.private.dialect = self.dialect;
        context.private.security_mode = self.security_mode;
        context.private.sign = self.sign;
        context.private.seal = self.seal;
        context.private.session_key = self.session_key.clone();
        context.private.cypher = self.encryption_cipher.unwrap_or_default();
        if let Some(keys) = self.derived_keys {
            context.private.signing_key = keys.signing_key;
            context.private.serverin_key = keys.serverin_key;
            context.private.serverout_key = keys.serverout_key;
        }
        context
    }
}

fn operation_request_pdu(record: &OperationRecord) -> Result<Pdu> {
    let command = command_for_operation(&record.operation);
    let mut pdu = match &record.operation {
        Smb2Operation::ConnectShare { server, share, .. } => {
            let unc = format!("\\\\{}\\{}", server, share);
            let path = utf16le_bytes(&unc);
            let req = Smb2TreeConnectRequest::new(0, path).map_err(|_| ErrorCode(EINVAL))?;
            let tree_pdu = smb2_cmd_tree_connect_async(&req).map_err(|_| ErrorCode(EINVAL))?;
            pdu_from_vectors(command, tree_pdu.out)
        }
        Smb2Operation::DisconnectShare => {
            let tree_pdu = smb2_cmd_tree_disconnect_async().map_err(|_| ErrorCode(EINVAL))?;
            pdu_from_vectors(command, tree_pdu.out)
        }
        Smb2Operation::Open { path, .. }
        | Smb2Operation::OpenDir { path }
        | Smb2Operation::Stat { path }
        | Smb2Operation::StatVfs { path } => {
            let create = smb2_cmd_create_async(Smb2CreateRequest::new().with_name(path), None)
                .map_err(|_| ErrorCode(EINVAL))?;
            pdu_from_vectors(command, create.out)
        }
        Smb2Operation::Close { file_id } => {
            smb2_cmd_close_async(&Smb2CloseRequest::new(0, *file_id), None)?
        }
        Smb2Operation::Fsync { file_id } => {
            smb2_cmd_flush_async(&Smb2FlushRequest::new(*file_id), None)?
        }
        Smb2Operation::Read {
            file_id,
            count,
            offset,
        } => {
            let mut req = Smb2ReadRequest {
                length: *count,
                offset: offset.unwrap_or(0),
                file_id: *file_id,
                reply_buffer_len: Some(*count),
                ..Smb2ReadRequest::default()
            };
            let read_pdu = req
                .cmd_read_async(true, false)
                .map_err(|_| ErrorCode(EINVAL))?;
            let mut pdu = pdu_from_vectors(
                command,
                read_pdu
                    .out
                    .iter()
                    .map(|iov| iov.as_slice().to_vec())
                    .collect(),
            );
            pdu.input = io_vectors_from_buffers(
                read_pdu
                    .input
                    .iter()
                    .map(|iov| iov.as_slice().to_vec())
                    .collect(),
            );
            pdu.header.credit_charge = read_pdu.credit_charge;
            pdu
        }
        Smb2Operation::Write {
            file_id,
            count,
            offset,
        } => {
            let buffer = vec![0; *count as usize];
            let write_pdu = smb2_cmd_write_async(
                WriteEncodeOptions {
                    supports_multi_credit: true,
                    passthrough: false,
                },
                Smb2WriteRequest::new(*file_id, offset.unwrap_or(0), &buffer),
                WriteBufferOwnership::Borrowed,
            )
            .map_err(|_| ErrorCode(EINVAL))?;
            let mut pdu = pdu_from_vectors(command, write_pdu.out);
            pdu.header.credit_charge = write_pdu.credit_charge;
            pdu
        }
        Smb2Operation::Echo | Smb2Operation::Lseek { .. } => smb2_cmd_echo_async(None)?,
        _ => generic_request_pdu(command),
    };
    pdu.header.message_id = record.message_id;
    pdu.header.credit_request_response = 1;
    pdu.header.tree_id = operation_tree_id(&record.operation);
    Ok(pdu)
}

fn pdu_from_vectors(command: Smb2Command, vectors: Vec<Vec<u8>>) -> Pdu {
    Pdu::from_parts(
        smb2_header_for_command(command),
        io_vectors_from_buffers(vectors),
        None,
    )
}

fn generic_request_pdu(command: Smb2Command) -> Pdu {
    let fixed_len = smb2_get_fixed_request_size(command) & !1;
    let mut fixed = vec![0; fixed_len];
    if fixed_len >= 2 {
        fixed[..2].copy_from_slice(&(smb2_get_fixed_request_size(command) as u16).to_le_bytes());
    }
    pdu_from_vectors(command, vec![fixed])
}

fn io_vectors_from_buffers(vectors: Vec<Vec<u8>>) -> IoVectors {
    let mut out = IoVectors::new();
    for buf in vectors {
        out.total_size = out.total_size.saturating_add(buf.len());
        out.vectors.push(IoVec { buf });
    }
    out
}

fn utf16le_bytes(value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len().saturating_mul(2));
    for unit in value.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn command_for_operation(operation: &Smb2Operation) -> Smb2Command {
    match operation {
        Smb2Operation::Connect { .. } => Smb2Command::Negotiate,
        Smb2Operation::ConnectShare { .. } => Smb2Command::TreeConnect,
        Smb2Operation::DisconnectShare => Smb2Command::TreeDisconnect,
        Smb2Operation::Open { .. }
        | Smb2Operation::OpenDir { .. }
        | Smb2Operation::Stat { .. }
        | Smb2Operation::StatVfs { .. } => Smb2Command::Create,
        Smb2Operation::Close { .. } => Smb2Command::Close,
        Smb2Operation::Fsync { .. } => Smb2Command::Flush,
        Smb2Operation::Read { .. } => Smb2Command::Read,
        Smb2Operation::Write { .. } => Smb2Command::Write,
        Smb2Operation::NotifyChange { .. } | Smb2Operation::NotifyChangeFileHandle { .. } => {
            Smb2Command::ChangeNotify
        }
        Smb2Operation::Fstat { .. } => Smb2Command::QueryInfo,
        Smb2Operation::Unlink { .. }
        | Smb2Operation::Rmdir { .. }
        | Smb2Operation::Mkdir { .. }
        | Smb2Operation::Rename { .. }
        | Smb2Operation::Truncate { .. }
        | Smb2Operation::Ftruncate { .. } => Smb2Command::SetInfo,
        Smb2Operation::Readlink { .. } => Smb2Command::Ioctl,
        Smb2Operation::Echo | Smb2Operation::Lseek { .. } => Smb2Command::Echo,
    }
}

fn operation_tree_id(operation: &Smb2Operation) -> u32 {
    match operation {
        Smb2Operation::Connect { .. }
        | Smb2Operation::ConnectShare { .. }
        | Smb2Operation::DisconnectShare
        | Smb2Operation::Echo => 0,
        _ => 0,
    }
}

fn transport_frame_payload_len(bytes: &[u8]) -> Result<Option<usize>> {
    if bytes.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if len > SMB2_MAX_PDU_SIZE {
        return Err(ErrorCode(EINVAL));
    }
    Ok(Some(len))
}

fn parse_transport_response_payload(payload: &[u8]) -> Result<Option<SyntheticResponse>> {
    if payload.len() >= SMB2_HEADER_SIZE {
        match smb2_decode_header_bytes(&payload[..SMB2_HEADER_SIZE]) {
            Ok(header) => return Ok(Some(smb2_response_from_header(header, payload))),
            Err(_) => {}
        }
    }
    Ok(Some(parse_synthetic_response_payload(payload)))
}

fn smb2_response_from_header(header: Smb2Header, payload: &[u8]) -> SyntheticResponse {
    let body = payload[SMB2_HEADER_SIZE..].to_vec();
    let status = if smb2_status_is_error(header.status) {
        ErrorCode::from_ntstatus(header.status).code()
    } else if let Some(command) = Smb2Command::from_raw(header.command) {
        let context = context_for_header(header);
        let mut pdu = Pdu::from_parts(header, IoVectors::new(), None);
        pdu.header.flags |= SMB2_FLAGS_SERVER_TO_REDIR;
        pdu.input = io_vectors_from_buffers(vec![body.clone()]);
        let fixed_size = smb2_get_fixed_reply_size(&context, command);
        if body.len() >= fixed_size && smb2_process_reply_payload_fixed(&context, &pdu).is_err() {
            ErrorCode(EINVAL).code()
        } else if body.len() > fixed_size
            && smb2_process_reply_payload_variable(&context, &pdu).is_err()
        {
            ErrorCode(EINVAL).code()
        } else {
            0
        }
    } else {
        ErrorCode(EINVAL).code()
    };
    SyntheticResponse {
        message_id: Some(header.message_id),
        status,
        payload: body,
        smb2_packet: Some(payload.to_vec()),
    }
}

fn smb2_response_from_pdu(pdu: Pdu) -> SyntheticResponse {
    let header = pdu.header;
    let mut payload = Vec::new();
    for iov in pdu.input.vectors.iter().skip(1) {
        payload.extend_from_slice(&iov.buf);
    }
    let mut packet = Vec::with_capacity(SMB2_HEADER_SIZE + payload.len());
    if let Some(header_iov) = pdu.input.vectors.first() {
        packet.extend_from_slice(&header_iov.buf);
    }
    packet.extend_from_slice(&payload);
    let status = if smb2_status_is_error(header.status) {
        ErrorCode::from_ntstatus(header.status).code()
    } else if let Some(command) = Smb2Command::from_raw(header.command) {
        let context = context_for_header(header);
        let mut process_pdu = Pdu::from_parts(header, IoVectors::new(), None);
        process_pdu.input = io_vectors_from_buffers(vec![payload.clone()]);
        let fixed_size = smb2_get_fixed_reply_size(&context, command);
        if payload.len() >= fixed_size
            && smb2_process_reply_payload_fixed(&context, &process_pdu).is_err()
        {
            ErrorCode(EINVAL).code()
        } else if payload.len() > fixed_size
            && smb2_process_reply_payload_variable(&context, &process_pdu).is_err()
        {
            ErrorCode(EINVAL).code()
        } else {
            0
        }
    } else {
        ErrorCode(EINVAL).code()
    };
    SyntheticResponse {
        message_id: Some(header.message_id),
        status,
        payload,
        smb2_packet: Some(packet),
    }
}

fn context_for_header(header: Smb2Header) -> crate::include::libsmb2_private::Context {
    let mut context = crate::include::libsmb2_private::Context::new();
    context.header = header;
    context
}

const fn smb2_status_is_error(status: u32) -> bool {
    let severity = status & SMB2_STATUS_SEVERITY_MASK;
    if severity == SMB2_STATUS_SEVERITY_ERROR {
        status != SMB2_STATUS_MORE_PROCESSING_REQUIRED
    } else if severity == SMB2_STATUS_SEVERITY_WARNING {
        status == SMB2_STATUS_STOPPED_ON_SYMLINK
    } else {
        false
    }
}

fn parse_synthetic_response_payload(bytes: &[u8]) -> SyntheticResponse {
    if bytes.len() >= 12 {
        SyntheticResponse {
            message_id: Some(u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])),
            status: i32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            payload: bytes[12..].to_vec(),
            smb2_packet: None,
        }
    } else {
        SyntheticResponse {
            message_id: None,
            status: 0,
            payload: bytes.to_vec(),
            smb2_packet: None,
        }
    }
}

fn completion_payload_for_operation(
    operation: &Smb2Operation,
    response: &SyntheticResponse,
) -> Vec<u8> {
    let Some(packet) = response.smb2_packet.as_deref() else {
        return response.payload.clone();
    };
    let body = &response.payload;
    match operation {
        Smb2Operation::Open { .. } | Smb2Operation::OpenDir { .. } => body
            .get(64..64 + SMB2_FILE_ID_SIZE)
            .map_or_else(|| response.payload.clone(), <[u8]>::to_vec),
        Smb2Operation::Read { .. } => {
            extract_read_reply_data(packet, body).unwrap_or_else(|| response.payload.clone())
        }
        Smb2Operation::Write { .. } => body
            .get(4..8)
            .map_or_else(|| response.payload.clone(), <[u8]>::to_vec),
        Smb2Operation::Stat { .. }
        | Smb2Operation::Fstat { .. }
        | Smb2Operation::StatVfs { .. } => {
            extract_offset_payload(packet, body, 2, 4).unwrap_or_else(|| response.payload.clone())
        }
        Smb2Operation::Readlink { .. } => {
            extract_offset_payload(packet, body, 24, 28).unwrap_or_else(|| response.payload.clone())
        }
        _ => response.payload.clone(),
    }
}

fn extract_read_reply_data(packet: &[u8], body: &[u8]) -> Option<Vec<u8>> {
    let data_offset = usize::from(*body.get(2)?);
    let data_length = read_le_u32(body, 4)? as usize;
    if data_length == 0 {
        return Some(Vec::new());
    }
    packet
        .get(data_offset..data_offset.checked_add(data_length)?)
        .map(<[u8]>::to_vec)
}

fn extract_offset_payload(
    packet: &[u8],
    body: &[u8],
    offset_field: usize,
    length_field: usize,
) -> Option<Vec<u8>> {
    let offset = usize::from(read_le_u16(body, offset_field)?);
    let length = read_le_u32(body, length_field)? as usize;
    if length == 0 {
        return Some(Vec::new());
    }
    packet
        .get(offset..offset.checked_add(length)?)
        .map(<[u8]>::to_vec)
}

fn read_le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let bytes = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let bytes = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn parse_file_id(bytes: &[u8]) -> Option<[u8; SMB2_FILE_ID_SIZE]> {
    if bytes.len() < SMB2_FILE_ID_SIZE {
        return None;
    }
    let mut file_id = [0; SMB2_FILE_ID_SIZE];
    file_id.copy_from_slice(&bytes[..SMB2_FILE_ID_SIZE]);
    Some(file_id)
}

fn parse_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn parse_write_count(bytes: &[u8]) -> Option<u32> {
    if bytes.len() == 4 {
        return parse_u32(bytes);
    }
    read_le_u32(bytes, 4).or_else(|| parse_u32(bytes))
}

fn parse_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let bytes = bytes.get(offset..end)?;
    Some(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn parse_stat(bytes: &[u8]) -> Option<Stat> {
    if bytes.len() < 88 {
        return None;
    }
    Some(Stat {
        file_type: FileType::from_raw(parse_u32(bytes)?),
        nlink: parse_u32(&bytes[4..])?,
        ino: parse_u64(bytes, 8)?,
        size: parse_u64(bytes, 16)?,
        atime: parse_u64(bytes, 24)?,
        atime_nsec: parse_u64(bytes, 32)?,
        mtime: parse_u64(bytes, 40)?,
        mtime_nsec: parse_u64(bytes, 48)?,
        ctime: parse_u64(bytes, 56)?,
        ctime_nsec: parse_u64(bytes, 64)?,
        btime: parse_u64(bytes, 72)?,
        btime_nsec: parse_u64(bytes, 80)?,
    })
}

fn parse_statvfs(bytes: &[u8]) -> Option<StatVfs> {
    if bytes.len() < 56 {
        return None;
    }
    Some(StatVfs {
        block_size: parse_u32(bytes)?,
        fragment_size: parse_u32(&bytes[4..])?,
        blocks: parse_u64(bytes, 8)?,
        blocks_free: parse_u64(bytes, 16)?,
        blocks_available: parse_u64(bytes, 24)?,
        files: parse_u32(&bytes[32..])?,
        files_free: parse_u32(&bytes[36..])?,
        files_available: parse_u32(&bytes[40..])?,
        filesystem_id: parse_u32(&bytes[44..])?,
        flags: parse_u32(&bytes[48..])?,
        name_max: parse_u32(&bytes[52..])?,
    })
}

fn parse_directory_entries(bytes: &[u8], fallback_path: &str) -> Option<Vec<DirectoryEntry>> {
    let names = if bytes.len() > SMB2_FILE_ID_SIZE {
        &bytes[SMB2_FILE_ID_SIZE..]
    } else {
        bytes
    };
    let names = std::str::from_utf8(names).ok()?;
    let entries: Vec<_> = names
        .lines()
        .filter(|name| !name.is_empty())
        .map(|name| DirectoryEntry {
            name: name.to_owned(),
            stat: local_stat(name, FileType::File),
        })
        .collect();
    if entries.is_empty() {
        Some(local_directory_entries(fallback_path))
    } else {
        Some(entries)
    }
}

fn local_file_id(message_id: u64, seed: &str) -> [u8; SMB2_FILE_ID_SIZE] {
    let mut id = [0; SMB2_FILE_ID_SIZE];
    id[..8].copy_from_slice(&message_id.to_be_bytes());
    let hash = local_hash(seed.as_bytes()) | 1;
    id[8..].copy_from_slice(&hash.to_be_bytes());
    id
}

fn local_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn local_read_data(file_id: [u8; SMB2_FILE_ID_SIZE], offset: u64, count: u32) -> Vec<u8> {
    let mut seed = u64::from_be_bytes([
        file_id[8],
        file_id[9],
        file_id[10],
        file_id[11],
        file_id[12],
        file_id[13],
        file_id[14],
        file_id[15],
    ]) ^ offset;
    let mut data = Vec::with_capacity(count as usize);
    for _ in 0..count {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        data.push((seed >> 56) as u8);
    }
    data
}

fn local_readlink_target(path: &str, buffer_size: u32) -> Vec<u8> {
    let target = format!("{path}.target");
    target
        .as_bytes()
        .iter()
        .copied()
        .take(buffer_size as usize)
        .collect()
}

fn local_directory_entries(path: &str) -> Vec<DirectoryEntry> {
    vec![DirectoryEntry {
        name: path.to_owned(),
        stat: local_stat(path, FileType::Directory),
    }]
}

fn local_stat(path: &str, file_type: FileType) -> Stat {
    local_stat_with_size(path, file_type, path.len() as u64)
}

fn local_stat_with_size(path: &str, file_type: FileType, size: u64) -> Stat {
    let hash = local_hash(path.as_bytes());
    Stat {
        file_type,
        nlink: 1,
        ino: hash,
        size,
        atime: 0,
        atime_nsec: 0,
        mtime: 0,
        mtime_nsec: 0,
        ctime: 0,
        ctime_nsec: 0,
        btime: 0,
        btime_nsec: 0,
    }
}

fn local_stat_for_file_id(file_id: [u8; SMB2_FILE_ID_SIZE]) -> Stat {
    let ino = u64::from_be_bytes([
        file_id[8],
        file_id[9],
        file_id[10],
        file_id[11],
        file_id[12],
        file_id[13],
        file_id[14],
        file_id[15],
    ]);
    Stat {
        file_type: FileType::File,
        nlink: 1,
        ino,
        size: 0,
        atime: 0,
        atime_nsec: 0,
        mtime: 0,
        mtime_nsec: 0,
        ctime: 0,
        ctime_nsec: 0,
        btime: 0,
        btime_nsec: 0,
    }
}

const fn local_statvfs() -> StatVfs {
    StatVfs {
        block_size: 4096,
        fragment_size: 4096,
        blocks: 1024,
        blocks_free: 512,
        blocks_available: 512,
        files: 1024,
        files_free: 512,
        files_available: 512,
        filesystem_id: 0,
        flags: 0,
        name_max: 255,
    }
}

fn command_descriptor_for_operation(operation: &Smb2Operation) -> Option<Smb2CommandDescriptor> {
    match operation {
        Smb2Operation::Open { path, flags, .. } => Some(create_descriptor(path, *flags)),
        Smb2Operation::Read {
            file_id,
            count,
            offset,
        } => Some(read_descriptor(
            *file_id,
            *count,
            match offset {
                Some(offset) => *offset,
                None => 0,
            },
        )),
        Smb2Operation::Write {
            file_id,
            count,
            offset,
        } => Some(write_descriptor(
            *file_id,
            *count,
            match offset {
                Some(offset) => *offset,
                None => 0,
            },
        )),
        Smb2Operation::Close { file_id } => Some(close_descriptor(*file_id)),
        Smb2Operation::Fstat { file_id } => {
            Some(query_info_descriptor(None, *file_id, 1, 18, false))
        }
        Smb2Operation::Stat { path } => Some(query_info_descriptor(
            Some(path.clone()),
            [0xff; SMB2_FILE_ID_SIZE],
            1,
            18,
            true,
        )),
        Smb2Operation::StatVfs { path } => Some(query_info_descriptor(
            Some(path.clone()),
            [0xff; SMB2_FILE_ID_SIZE],
            2,
            0,
            true,
        )),
        _ => None,
    }
}

fn create_descriptor(path: &str, flags: i32) -> Smb2CommandDescriptor {
    let request = Smb2CreateRequest::new().with_name(path);
    match smb2_cmd_create_async(request, None) {
        Ok(pdu) => Smb2CommandDescriptor::Create {
            path: path.to_owned(),
            flags,
            out_vector_lengths: pdu.out.iter().map(Vec::len).collect(),
        },
        Err(_) => Smb2CommandDescriptor::BuildError {
            command: "create",
            code: EINVAL,
        },
    }
}

fn read_descriptor(
    file_id: [u8; SMB2_FILE_ID_SIZE],
    count: u32,
    offset: u64,
) -> Smb2CommandDescriptor {
    let mut request = Smb2ReadRequest {
        length: count,
        offset,
        file_id,
        reply_buffer_len: Some(count),
        ..Smb2ReadRequest::default()
    };
    match request.cmd_read_async(true, false) {
        Ok(pdu) => Smb2CommandDescriptor::Read {
            file_id,
            count,
            offset,
            out_vector_lengths: pdu.out.iter().map(|iov| iov.len()).collect(),
            input_vector_lengths: pdu.input.iter().map(|iov| iov.len()).collect(),
            credit_charge: pdu.credit_charge,
        },
        Err(_) => Smb2CommandDescriptor::BuildError {
            command: "read",
            code: EINVAL,
        },
    }
}

fn write_descriptor(
    file_id: [u8; SMB2_FILE_ID_SIZE],
    count: u32,
    offset: u64,
) -> Smb2CommandDescriptor {
    let buffer = vec![0; count as usize];
    let request = Smb2WriteRequest::new(file_id, offset, &buffer);
    match smb2_cmd_write_async(
        WriteEncodeOptions {
            supports_multi_credit: true,
            passthrough: false,
        },
        request,
        WriteBufferOwnership::Borrowed,
    ) {
        Ok(pdu) => Smb2CommandDescriptor::Write {
            file_id,
            count: pdu.request.length,
            offset,
            out_vector_lengths: pdu.out.iter().map(Vec::len).collect(),
            credit_charge: pdu.credit_charge,
        },
        Err(_) => Smb2CommandDescriptor::BuildError {
            command: "write",
            code: EINVAL,
        },
    }
}

fn close_descriptor(file_id: [u8; SMB2_FILE_ID_SIZE]) -> Smb2CommandDescriptor {
    let request = Smb2CloseRequest::new(0, file_id);
    match smb2_cmd_close_async(&request, None) {
        Ok(pdu) => Smb2CommandDescriptor::Close {
            file_id,
            out_vector_lengths: pdu.out.vectors.iter().map(|iov| iov.buf.len()).collect(),
        },
        Err(error) => Smb2CommandDescriptor::BuildError {
            command: "close",
            code: error.0,
        },
    }
}

fn query_info_descriptor(
    path: Option<String>,
    file_id: [u8; SMB2_FILE_ID_SIZE],
    info_type: u8,
    file_info_class: u8,
    compound: bool,
) -> Smb2CommandDescriptor {
    Smb2CommandDescriptor::QueryInfo {
        path,
        file_id,
        info_type,
        file_info_class,
        compound,
    }
}

fn validate_non_empty(value: &str) -> Result<()> {
    if value.is_empty() {
        Err(ErrorCode(EINVAL))
    } else {
        Ok(())
    }
}

fn resolve_lseek_offset(current: u64, offset: i64, whence: i32) -> Option<u64> {
    match whence {
        0 => u64::try_from(offset).ok(),
        1 => {
            if offset < 0 {
                current.checked_sub(offset.unsigned_abs())
            } else {
                current.checked_add(offset as u64)
            }
        }
        2 => u64::try_from(offset).ok(),
        _ => None,
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

/// Converts an NT status code into the unified legacy error string.
#[must_use]
pub fn nterror_to_str(status: u32) -> &'static str {
    crate::lib::errors::nterror_to_str(status)
}

/// Returns the unified NTSTATUS name for a raw status value when it is known.
#[must_use]
pub fn nterror_name(status: u32) -> Option<&'static str> {
    crate::lib::errors::nterror_name(status)
}

/// Converts an NT status code into the public negative errno-style value.
#[must_use]
pub fn nterror_to_errno(status: u32) -> i32 {
    ErrorCode::from_ntstatus(status).code()
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
    server.socket_state = ServerSocketState::BindRequested {
        port,
        max_connections,
    };
    Ok(server)
}

/// Builds an accept-connection request skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `fd` is negative, otherwise `ErrorCode(-38)`
/// because this safe public skeleton has no server accept backend yet.
pub fn accept_connection_async(fd: Socket, timeout_msecs: i32) -> Result<(Socket, i32)> {
    if fd < 0 {
        return Err(ErrorCode(EINVAL));
    }
    let _ = timeout_msecs;
    Err(ErrorCode(ENOSYS))
}

/// Builds a serve-port context skeleton for a listening descriptor.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `fd` is negative, otherwise `ErrorCode(-38)`
/// because this safe public skeleton has no server accept backend yet.
pub fn serve_port_async(fd: Socket, timeout_msecs: i32) -> Result<Smb2Client> {
    if fd < 0 {
        return Err(ErrorCode(EINVAL));
    }
    let _ = timeout_msecs;
    Err(ErrorCode(ENOSYS))
}

/// Builds a synchronous serve-port loop skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the server socket descriptor or connection limit
/// is negative, otherwise `ErrorCode(-38)` because the synchronous server loop
/// has no safe migrated network backend yet.
pub fn serve_port(server: &Smb2Server, max_connections: i32) -> Result<i32> {
    if max_connections < 0 {
        return Err(ErrorCode(EINVAL));
    }
    match server.socket_state {
        ServerSocketState::Listening { fd, .. } if fd >= 0 => Err(ErrorCode(ENOSYS)),
        ServerSocketState::Listening { .. }
        | ServerSocketState::BindRequested { .. }
        | ServerSocketState::Unbound => Err(ErrorCode(EINVAL)),
    }
}
