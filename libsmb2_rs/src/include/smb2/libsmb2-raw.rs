//! Raw SMB2 request/reply data structure skeletons from `include/smb2/libsmb2-raw.h`.
//!
//! This module mirrors the C raw-command surface at the data-shape level. It is
//! intentionally a protocol skeleton: command helpers describe which raw
//! command would be issued and keep the supplied payload. Where a migrated
//! command constructor exists under `lib/smb2-cmd-*`, helpers also run that
//! side-effect-free constructor so bad parameters fail early. They still do not
//! perform socket/network I/O.

use core::fmt;

/// SMB2 GUID byte length.
pub const GUID_SIZE: usize = 16;

/// SMB2 file id byte length.
pub const FILE_ID_SIZE: usize = 16;

/// SMB2 lease key byte length.
pub const LEASE_KEY_SIZE: usize = 16;

/// Maximum number of dialects represented by the C negotiate request helper.
pub const NEGOTIATE_MAX_DIALECTS: usize = 10;

/// SMB2 GUID represented as the raw 16-byte value carried on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Guid(pub [u8; GUID_SIZE]);

/// SMB2 lease key represented as the raw 16-byte value carried on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeaseKey(pub [u8; LEASE_KEY_SIZE]);

/// SMB2 file id, represented as persistent and volatile halves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileId {
    /// Persistent file id.
    pub persistent: u64,
    /// Volatile file id.
    pub volatile: u64,
}

impl FileId {
    /// Creates a file id from the little-endian 16-byte C `smb2_file_id` form.
    #[must_use]
    pub fn from_le_bytes(bytes: [u8; FILE_ID_SIZE]) -> Self {
        let persistent = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let volatile = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        Self {
            persistent,
            volatile,
        }
    }

    /// Returns the little-endian 16-byte C `smb2_file_id` form.
    #[must_use]
    pub fn to_le_bytes(self) -> [u8; FILE_ID_SIZE] {
        let persistent = self.persistent.to_le_bytes();
        let volatile = self.volatile.to_le_bytes();
        [
            persistent[0],
            persistent[1],
            persistent[2],
            persistent[3],
            persistent[4],
            persistent[5],
            persistent[6],
            persistent[7],
            volatile[0],
            volatile[1],
            volatile[2],
            volatile[3],
            volatile[4],
            volatile[5],
            volatile[6],
            volatile[7],
        ]
    }
}

/// Timestamp shape used by directory and information replies in `smb2.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeVal {
    /// Seconds component.
    pub tv_sec: i64,
    /// Microseconds component.
    pub tv_usec: i64,
}

/// Raw SMB2 command identifier mirrored from `enum smb2_command`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawCommandKind {
    /// SMB2 NEGOTIATE command.
    Negotiate,
    /// SMB2 SESSION_SETUP command.
    SessionSetup,
    /// SMB2 LOGOFF command.
    Logoff,
    /// SMB2 TREE_CONNECT command.
    TreeConnect,
    /// SMB2 TREE_DISCONNECT command.
    TreeDisconnect,
    /// SMB2 CREATE command.
    Create,
    /// SMB2 CLOSE command.
    Close,
    /// SMB2 FLUSH command.
    Flush,
    /// SMB2 READ command.
    Read,
    /// SMB2 WRITE command.
    Write,
    /// SMB2 LOCK command.
    Lock,
    /// SMB2 IOCTL command.
    Ioctl,
    /// SMB2 ECHO command.
    Echo,
    /// SMB2 QUERY_DIRECTORY command.
    QueryDirectory,
    /// SMB2 CHANGE_NOTIFY command.
    ChangeNotify,
    /// SMB2 QUERY_INFO command.
    QueryInfo,
    /// SMB2 SET_INFO command.
    SetInfo,
    /// SMB2 OPLOCK_BREAK command.
    OplockBreak,
    /// SMB2 ERROR reply pseudo-command used by server-side helpers.
    Error,
}

/// Direction of a raw SMB2 command skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawCommandDirection {
    /// Client-to-server request skeleton.
    Request,
    /// Server-to-client reply or notification skeleton.
    Reply,
}

/// Data-release contract attached to raw reply payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RawDataRelease {
    /// No C-style `smb2_free_data` equivalent is required for this payload.
    #[default]
    None,
    /// The payload owns decoded data that the C API documents as `smb2_free_data` managed.
    FreeDataRequired,
}

/// Construction state for a raw SMB2 command helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawCommandState {
    /// The command was validated only by the raw header skeleton.
    Validated,
    /// A migrated side-effect-free command constructor was executed successfully.
    Constructed {
        /// Number of encoded output vectors produced by the constructor.
        output_vectors: usize,
        /// Number of expected input vectors produced by the constructor.
        input_vectors: usize,
        /// Credit charge selected by the command constructor, when represented.
        credit_charge: Option<u16>,
        /// Optional status that a full PDU layer would put into the SMB2 header.
        status: Option<u32>,
    },
}

impl Default for RawCommandState {
    fn default() -> Self {
        Self::Validated
    }
}

/// Errors returned by raw SMB2 command helper skeletons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawCommandError {
    /// A helper can only construct/validate metadata; it cannot perform network I/O.
    NetworkIoUnsupported,
    /// A declared byte or element count does not match the owned Rust data.
    LengthMismatch {
        /// Name of the field carrying the declared length.
        field: &'static str,
        /// Declared length or count.
        declared: usize,
        /// Actual length or count.
        actual: usize,
    },
    /// A value exceeds the maximum represented by the C raw API contract.
    ValueOutOfRange {
        /// Name of the field that is out of range.
        field: &'static str,
        /// Maximum accepted value.
        maximum: usize,
        /// Actual value.
        actual: usize,
    },
    /// A migrated pure command constructor rejected the request or reply.
    CommandConstructionFailed {
        /// Command whose constructor failed.
        command: RawCommandKind,
        /// Human-readable error detail from the constructor.
        reason: String,
    },
}

impl fmt::Display for RawCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkIoUnsupported => {
                f.write_str("raw SMB2 helpers cannot perform network I/O")
            }
            Self::LengthMismatch {
                field,
                declared,
                actual,
            } => write!(
                f,
                "raw SMB2 field {field} declares {declared} bytes/items but payload has {actual}"
            ),
            Self::ValueOutOfRange {
                field,
                maximum,
                actual,
            } => write!(
                f,
                "raw SMB2 field {field} value {actual} exceeds maximum {maximum}"
            ),
            Self::CommandConstructionFailed { command, reason } => {
                write!(f, "raw SMB2 {command:?} constructor failed: {reason}")
            }
        }
    }
}

impl std::error::Error for RawCommandError {}

/// Result type returned by raw SMB2 command helpers.
pub type RawCommandResult<T> = Result<T, RawCommandError>;

/// Protocol-free command descriptor returned by raw command helper skeletons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCommand<T> {
    /// SMB2 command represented by this descriptor.
    pub kind: RawCommandKind,
    /// Whether this descriptor represents a request or a reply path.
    pub direction: RawCommandDirection,
    /// Command-specific payload retained for a future encoder/dispatcher.
    pub payload: T,
    /// Minimal validation/construction state recorded by the helper.
    pub state: RawCommandState,
    /// Whether this payload follows the C `smb2_free_data` release contract.
    pub data_release: RawDataRelease,
}

impl<T> RawCommand<T> {
    /// Creates a raw command descriptor without performing SMB2 protocol work.
    #[must_use]
    pub const fn new(kind: RawCommandKind, direction: RawCommandDirection, payload: T) -> Self {
        Self {
            kind,
            direction,
            payload,
            state: RawCommandState::Validated,
            data_release: RawDataRelease::None,
        }
    }

    /// Records validation or pure-constructor state on a raw command descriptor.
    #[must_use]
    pub fn with_state(mut self, state: RawCommandState) -> Self {
        self.state = state;
        self
    }

    /// Records the C data-release contract on a raw command descriptor.
    #[must_use]
    pub fn with_data_release(mut self, data_release: RawDataRelease) -> Self {
        self.data_release = data_release;
        self
    }

    /// Network dispatch is intentionally not implemented in this migration skeleton.
    ///
    /// # Errors
    ///
    /// Always returns [`RawCommandError::NetworkIoUnsupported`].
    pub fn dispatch(self) -> RawCommandResult<Self> {
        Err(RawCommandError::NetworkIoUnsupported)
    }
}

trait RawPayloadContract {
    fn validate_raw(&self) -> RawCommandResult<()>;

    fn construction_state(
        &self,
        _kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        Ok(RawCommandState::Validated)
    }

    fn data_release(&self) -> RawDataRelease {
        RawDataRelease::None
    }
}

/// Error reply payload for `smb2_cmd_error_reply_async`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ErrorReply {
    /// Number of error contexts in `error_data`.
    pub error_context_count: u8,
    /// Error data byte count.
    pub byte_count: u32,
    /// Raw error data bytes.
    pub error_data: Vec<u8>,
}

/// Extra metadata supplied by `smb2_cmd_error_reply_async`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ErrorReplyCommand {
    /// Error reply payload.
    pub reply: ErrorReply,
    /// SMB2 command that caused the error.
    pub causing_command: u8,
    /// NT status code associated with the error reply.
    pub status: i32,
}

/// NEGOTIATE request payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NegotiateRequest {
    /// Number of dialect entries that are meaningful.
    pub dialect_count: u16,
    /// Requested security mode flags.
    pub security_mode: u16,
    /// Client capabilities bitmap.
    pub capabilities: u32,
    /// Client GUID.
    pub client_guid: Guid,
    /// Offset of negotiate contexts in the final PDU.
    pub negotiate_context_offset: u32,
    /// Number of negotiate contexts.
    pub negotiate_context_count: u16,
    /// Dialect revisions offered by the client.
    pub dialects: Vec<u16>,
}

/// NEGOTIATE reply payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NegotiateReply {
    /// Server-selected security mode.
    pub security_mode: u16,
    /// Server-selected dialect revision.
    pub dialect_revision: u16,
    /// Server-selected cipher identifier.
    pub cypher: u16,
    /// Server GUID.
    pub server_guid: Guid,
    /// Server capabilities bitmap.
    pub capabilities: u32,
    /// Maximum transaction size accepted by the server.
    pub max_transact_size: u32,
    /// Maximum read size accepted by the server.
    pub max_read_size: u32,
    /// Maximum write size accepted by the server.
    pub max_write_size: u32,
    /// Server system time.
    pub system_time: u64,
    /// Server start time.
    pub server_start_time: u64,
    /// Offset of negotiate contexts in the final PDU.
    pub negotiate_context_offset: u32,
    /// Number of negotiate contexts.
    pub negotiate_context_count: u16,
    /// Security buffer length.
    pub security_buffer_length: u16,
    /// Security buffer offset.
    pub security_buffer_offset: u16,
    /// Security blob returned by the server.
    pub security_buffer: Vec<u8>,
}

/// SESSION_SETUP request payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionSetupRequest {
    /// Session setup flags.
    pub flags: u8,
    /// Requested security mode.
    pub security_mode: u8,
    /// Client capabilities bitmap.
    pub capabilities: u32,
    /// Channel identifier.
    pub channel: u32,
    /// Previous session id for binding or reconnect flows.
    pub previous_session_id: u64,
    /// Security buffer length.
    pub security_buffer_length: u16,
    /// Security blob supplied by the client.
    pub security_buffer: Vec<u8>,
}

/// SESSION_SETUP reply payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionSetupReply {
    /// Session flags returned by the server.
    pub session_flags: u16,
    /// Security buffer length.
    pub security_buffer_length: u16,
    /// Security buffer offset.
    pub security_buffer_offset: u16,
    /// Security blob returned by the server.
    pub security_buffer: Vec<u8>,
}

/// TREE_CONNECT request payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TreeConnectRequest {
    /// Tree connect flags.
    pub flags: u16,
    /// UTF-16 path offset in the final PDU.
    pub path_offset: u16,
    /// UTF-16 path length in bytes.
    pub path_length: u16,
    /// Share path as UTF-16 code units.
    pub path: Vec<u16>,
}

/// TREE_CONNECT reply payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TreeConnectReply {
    /// Share type selected by the server.
    pub share_type: u8,
    /// Share flags bitmap.
    pub share_flags: u32,
    /// Share capabilities bitmap.
    pub capabilities: u32,
    /// Maximal access mask.
    pub maximal_access: u32,
}

/// TREE_CONNECT reply helper payload including the tree id argument from the C API.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TreeConnectReplyCommand {
    /// Tree connect reply payload.
    pub reply: TreeConnectReply,
    /// Tree id to stamp on the raw reply PDU.
    pub tree_id: u32,
}

/// CREATE request payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CreateRequest {
    /// Security flags byte.
    pub security_flags: u8,
    /// Requested oplock level.
    pub requested_oplock_level: u8,
    /// Impersonation level.
    pub impersonation_level: u32,
    /// SMB create flags.
    pub smb_create_flags: u64,
    /// Desired access mask.
    pub desired_access: u32,
    /// File attributes bitmap.
    pub file_attributes: u32,
    /// Share access bitmap.
    pub share_access: u32,
    /// Create disposition.
    pub create_disposition: u32,
    /// Create options bitmap.
    pub create_options: u32,
    /// Name offset in the final PDU.
    pub name_offset: u16,
    /// Name length in bytes.
    pub name_length: u16,
    /// UTF-8 object name.
    pub name: String,
    /// Create context offset in the final PDU.
    pub create_context_offset: u32,
    /// Create context length in bytes.
    pub create_context_length: u32,
    /// Raw create context bytes.
    pub create_context: Vec<u8>,
}

/// CREATE reply payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CreateReply {
    /// Granted oplock level.
    pub oplock_level: u8,
    /// Reply flags.
    pub flags: u8,
    /// Create action taken by the server.
    pub create_action: u32,
    /// Creation time.
    pub creation_time: u64,
    /// Last access time.
    pub last_access_time: u64,
    /// Last write time.
    pub last_write_time: u64,
    /// Change time.
    pub change_time: u64,
    /// Allocation size.
    pub allocation_size: u64,
    /// End-of-file position.
    pub end_of_file: u64,
    /// File attributes bitmap.
    pub file_attributes: u32,
    /// File id assigned by the server.
    pub file_id: FileId,
    /// Create context length in bytes.
    pub create_context_length: u32,
    /// Create context offset in the final PDU.
    pub create_context_offset: u32,
    /// Raw create context bytes.
    pub create_context: Vec<u8>,
}

/// CLOSE request payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CloseRequest {
    /// Close flags.
    pub flags: u16,
    /// File id being closed.
    pub file_id: FileId,
}

/// CLOSE reply payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CloseReply {
    /// Close reply flags.
    pub flags: u16,
    /// Creation time.
    pub creation_time: u64,
    /// Last access time.
    pub last_access_time: u64,
    /// Last write time.
    pub last_write_time: u64,
    /// Change time.
    pub change_time: u64,
    /// Allocation size.
    pub allocation_size: u64,
    /// End-of-file position.
    pub end_of_file: u64,
    /// File attributes bitmap.
    pub file_attributes: u32,
}

/// FLUSH request payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlushRequest {
    /// File id being flushed.
    pub file_id: FileId,
}

/// LOGOFF request payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LogoffRequest {
    /// Reserved field from the C structure.
    pub reserved: u16,
}

/// ECHO request payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EchoRequest {
    /// Reserved field from the C structure.
    pub reserved: u16,
}

/// Empty reply payload for raw commands whose C callback data is always NULL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmptyReply;

/// Directory entry shape for SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileIdFullDirectoryInformation {
    /// Offset of the next entry in a packed reply buffer.
    pub next_entry_offset: u32,
    /// File index.
    pub file_index: u32,
    /// Creation time.
    pub creation_time: TimeVal,
    /// Last access time.
    pub last_access_time: TimeVal,
    /// Last write time.
    pub last_write_time: TimeVal,
    /// Change time.
    pub change_time: TimeVal,
    /// End-of-file position.
    pub end_of_file: u64,
    /// Allocation size.
    pub allocation_size: u64,
    /// File attributes bitmap.
    pub file_attributes: u32,
    /// File name length in bytes.
    pub file_name_length: u32,
    /// Extended attribute size.
    pub ea_size: u32,
    /// Directory entry file id.
    pub file_id: u64,
    /// Entry name.
    pub name: String,
}

/// Directory entry shape for SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileIdBothDirectoryInformation {
    /// Offset of the next entry in a packed reply buffer.
    pub next_entry_offset: u32,
    /// File index.
    pub file_index: u32,
    /// Creation time.
    pub creation_time: TimeVal,
    /// Last access time.
    pub last_access_time: TimeVal,
    /// Last write time.
    pub last_write_time: TimeVal,
    /// Change time.
    pub change_time: TimeVal,
    /// End-of-file position.
    pub end_of_file: u64,
    /// Allocation size.
    pub allocation_size: u64,
    /// File attributes bitmap.
    pub file_attributes: u32,
    /// File name length in bytes.
    pub file_name_length: u32,
    /// Extended attribute size.
    pub ea_size: u32,
    /// Short name length in bytes.
    pub short_name_length: u8,
    /// Short name raw UTF-16 storage from the C shape.
    pub short_name: [u8; 24],
    /// Directory entry file id.
    pub file_id: u64,
    /// Entry name.
    pub name: String,
}

/// QUERY_DIRECTORY request payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryDirectoryRequest {
    /// Requested file information class.
    pub file_information_class: u8,
    /// Query flags.
    pub flags: u8,
    /// File index for indexed scans.
    pub file_index: u32,
    /// Directory file id.
    pub file_id: FileId,
    /// Requested output buffer length.
    pub output_buffer_length: u32,
    /// File name offset in the final PDU.
    pub file_name_offset: u16,
    /// File name length in bytes.
    pub file_name_length: u16,
    /// Optional UTF-8 search pattern.
    pub name: String,
}

/// QUERY_DIRECTORY reply payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryDirectoryReply {
    /// Output buffer offset in the final PDU.
    pub output_buffer_offset: u16,
    /// Output buffer length in bytes.
    pub output_buffer_length: u32,
    /// Raw directory information buffer.
    pub output_buffer: Vec<u8>,
}

/// QUERY_DIRECTORY reply helper payload including the request argument from the C API.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryDirectoryReplyCommand {
    /// Original query directory request shape.
    pub request: QueryDirectoryRequest,
    /// Query directory reply payload.
    pub reply: QueryDirectoryReply,
}

/// READ request payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReadRequest {
    /// Read flags.
    pub flags: u8,
    /// Number of bytes requested.
    pub length: u32,
    /// File offset to read from.
    pub offset: u64,
    /// Optional caller-provided read buffer placeholder.
    pub buf: Vec<u8>,
    /// File id to read from.
    pub file_id: FileId,
    /// Minimum number of bytes requested.
    pub minimum_count: u32,
    /// Channel identifier.
    pub channel: u32,
    /// Remaining bytes hint.
    pub remaining_bytes: u32,
    /// Read channel info offset in the final PDU.
    pub read_channel_info_offset: u16,
    /// Read channel info length in bytes.
    pub read_channel_info_length: u16,
    /// Raw read channel info bytes.
    pub read_channel_info: Vec<u8>,
}

/// READ reply payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReadReply {
    /// Data offset in the final PDU.
    pub data_offset: u8,
    /// Data length in bytes.
    pub data_length: u32,
    /// Remaining data hint.
    pub data_remaining: u32,
    /// Raw read data bytes.
    pub data: Vec<u8>,
}

/// WRITE request payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WriteRequest {
    /// Data offset in the final PDU.
    pub data_offset: u16,
    /// Number of bytes to write.
    pub length: u32,
    /// File offset to write to.
    pub offset: u64,
    /// Raw write data bytes.
    pub buf: Vec<u8>,
    /// File id to write to.
    pub file_id: FileId,
    /// Channel identifier.
    pub channel: u32,
    /// Remaining bytes hint.
    pub remaining_bytes: u32,
    /// Write channel info offset in the final PDU.
    pub write_channel_info_offset: u16,
    /// Write channel info length in bytes.
    pub write_channel_info_length: u16,
    /// Raw write channel info bytes.
    pub write_channel_info: Vec<u8>,
    /// Write flags.
    pub flags: u32,
}

/// WRITE request helper payload including the ownership flag from the C API.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WriteRequestCommand {
    /// Write request payload.
    pub request: WriteRequest,
    /// Whether a future PDU owner may take the request buffer.
    pub pass_buf_ownership: bool,
}

/// WRITE reply payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriteReply {
    /// Number of bytes written.
    pub count: u32,
    /// Remaining bytes hint.
    pub remaining: u32,
}

/// QUERY_INFO request payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryInfoRequest {
    /// Information type.
    pub info_type: u8,
    /// File information class.
    pub file_info_class: u8,
    /// Requested output buffer length.
    pub output_buffer_length: u32,
    /// Input buffer offset in the final PDU.
    pub input_buffer_offset: u16,
    /// Input buffer length in bytes.
    pub input_buffer_length: u32,
    /// Raw input buffer bytes.
    pub input_buffer: Vec<u8>,
    /// Additional information flags.
    pub additional_information: u32,
    /// Query flags.
    pub flags: u32,
    /// File id to query.
    pub file_id: FileId,
    /// Raw typed input bytes used by higher-level query helpers.
    pub input: Vec<u8>,
}

/// QUERY_INFO reply payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryInfoReply {
    /// Output buffer offset in the final PDU.
    pub output_buffer_offset: u16,
    /// Output buffer length in bytes.
    pub output_buffer_length: u32,
    /// Raw output buffer; callers of the C API free this with `smb2_free_data`.
    pub output_buffer: Vec<u8>,
}

/// QUERY_INFO reply helper payload including the request argument from the C API.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryInfoReplyCommand {
    /// Original query info request shape.
    pub request: QueryInfoRequest,
    /// Query info reply payload.
    pub reply: QueryInfoReply,
}

/// SET_INFO request payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetInfoRequest {
    /// Information type.
    pub info_type: u8,
    /// File information class.
    pub file_info_class: u8,
    /// Input buffer length in bytes.
    pub buffer_length: u32,
    /// Input buffer offset in the final PDU.
    pub buffer_offset: u16,
    /// Additional information flags.
    pub additional_information: u32,
    /// File id to update.
    pub file_id: FileId,
    /// Raw input data bytes.
    pub input_data: Vec<u8>,
}

/// IOCTL request payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IoctlRequest {
    /// Control code.
    pub ctl_code: u32,
    /// File id associated with the control request.
    pub file_id: FileId,
    /// Input offset in the final PDU.
    pub input_offset: u32,
    /// Input byte count.
    pub input_count: u32,
    /// Maximum input response length.
    pub max_input_response: u32,
    /// Output offset in the final PDU.
    pub output_offset: u32,
    /// Output byte count.
    pub output_count: u32,
    /// Maximum output response length.
    pub max_output_response: u32,
    /// IOCTL flags.
    pub flags: u32,
    /// Raw input bytes.
    pub input: Vec<u8>,
}

/// IOCTL reply payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IoctlReply {
    /// Control code.
    pub ctl_code: u32,
    /// File id associated with the control reply.
    pub file_id: FileId,
    /// Input offset in the final PDU.
    pub input_offset: u32,
    /// Input byte count.
    pub input_count: u32,
    /// Output offset in the final PDU.
    pub output_offset: u32,
    /// Output byte count.
    pub output_count: u32,
    /// IOCTL flags.
    pub flags: u32,
    /// Raw output bytes; callers of the C API free this with `smb2_free_data`.
    pub output: Vec<u8>,
}

/// CHANGE_NOTIFY request payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChangeNotifyRequest {
    /// Change notify flags.
    pub flags: u16,
    /// Requested output buffer length.
    pub output_buffer_length: u32,
    /// File id being watched.
    pub file_id: FileId,
    /// Completion filter bitmap.
    pub completion_filter: u32,
}

/// CHANGE_NOTIFY reply payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChangeNotifyReply {
    /// Output buffer offset in the final PDU.
    pub output_buffer_offset: u16,
    /// Output buffer length in bytes.
    pub output_buffer_length: u32,
    /// Raw notification output bytes.
    pub output: Vec<u8>,
}

/// Decoded change notification entry shape.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileNotifyChangeInformation {
    /// Notify action.
    pub action: u32,
    /// Changed file name.
    pub name: String,
}

/// OPLOCK_BREAK notification payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OplockBreakNotification {
    /// New oplock level.
    pub oplock_level: u8,
    /// File id affected by the break.
    pub file_id: FileId,
}

/// OPLOCK_BREAK acknowledgement payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OplockBreakAcknowledgement {
    /// Acknowledged oplock level.
    pub oplock_level: u8,
    /// File id affected by the break.
    pub file_id: FileId,
}

/// OPLOCK_BREAK reply payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OplockBreakReply {
    /// Resulting oplock level.
    pub oplock_level: u8,
    /// File id affected by the break.
    pub file_id: FileId,
}

/// LEASE_BREAK notification payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeaseBreakNotification {
    /// New epoch from the server notification.
    pub new_epoch: u16,
    /// Lease break flags.
    pub flags: u32,
    /// Lease key affected by the break.
    pub lease_key: LeaseKey,
    /// Current lease state.
    pub current_lease_state: u32,
    /// New lease state requested by the server.
    pub new_lease_state: u32,
    /// Break reason.
    pub break_reason: u32,
    /// Access mask hint.
    pub access_mask_hint: u32,
    /// Share mask hint.
    pub share_mask_hint: u32,
}

/// LEASE_BREAK acknowledgement payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeaseBreakAcknowledgement {
    /// Lease break acknowledgement flags.
    pub flags: u32,
    /// Lease key affected by the break.
    pub lease_key: LeaseKey,
    /// Lease state acknowledged by the client.
    pub lease_state: u32,
    /// Lease duration hint.
    pub lease_duration: u64,
}

/// LEASE_BREAK reply payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeaseBreakReply {
    /// Lease break reply flags.
    pub flags: u32,
    /// Lease key affected by the break.
    pub lease_key: LeaseKey,
    /// Lease state accepted by the server.
    pub lease_state: u32,
    /// Lease duration hint.
    pub lease_duration: u64,
}

/// Combined server-to-client oplock or lease break reply shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OplockOrLeaseBreakReplyLock {
    /// Oplock break notification variant.
    OplockNotification(OplockBreakNotification),
    /// Oplock break reply variant.
    OplockReply(OplockBreakReply),
    /// Lease break notification variant.
    LeaseNotification(LeaseBreakNotification),
    /// Lease break reply variant.
    LeaseReply(LeaseBreakReply),
}

impl Default for OplockOrLeaseBreakReplyLock {
    fn default() -> Self {
        Self::OplockNotification(OplockBreakNotification::default())
    }
}

/// Combined server-to-client oplock or lease break reply wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OplockOrLeaseBreakReply {
    /// Structure size from the raw SMB2 payload.
    pub struct_size: u16,
    /// Break type discriminator from the raw SMB2 payload.
    pub break_type: i32,
    /// Typed break payload.
    pub lock: OplockOrLeaseBreakReplyLock,
}

/// Combined client-to-server oplock or lease break acknowledgement shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OplockOrLeaseBreakRequestLock {
    /// Oplock acknowledgement variant.
    Oplock(OplockBreakAcknowledgement),
    /// Lease acknowledgement variant.
    Lease(LeaseBreakAcknowledgement),
}

impl Default for OplockOrLeaseBreakRequestLock {
    fn default() -> Self {
        Self::Oplock(OplockBreakAcknowledgement::default())
    }
}

/// Combined client-to-server oplock or lease break acknowledgement wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OplockOrLeaseBreakRequest {
    /// Structure size from the raw SMB2 payload.
    pub struct_size: u16,
    /// Break type discriminator from the raw SMB2 payload.
    pub break_type: i32,
    /// Typed acknowledgement payload.
    pub lock: OplockOrLeaseBreakRequestLock,
}

/// LOCK element payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LockElement {
    /// Locked byte-range offset.
    pub offset: u64,
    /// Locked byte-range length.
    pub length: u64,
    /// Lock flags.
    pub flags: u32,
    /// Reserved field from the C structure.
    pub reserved: u32,
}

/// LOCK request payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LockRequest {
    /// Number of lock elements.
    pub lock_count: u16,
    /// Lock sequence number.
    pub lock_sequence_number: u8,
    /// Lock sequence index.
    pub lock_sequence_index: u32,
    /// File id to lock.
    pub file_id: FileId,
    /// Lock elements.
    pub locks: Vec<LockElement>,
}

impl RawPayloadContract for () {
    fn validate_raw(&self) -> RawCommandResult<()> {
        Ok(())
    }
}

macro_rules! impl_validate_only {
    ($($payload:ty),+ $(,)?) => {
        $(
            impl RawPayloadContract for $payload {
                fn validate_raw(&self) -> RawCommandResult<()> {
                    Ok(())
                }
            }
        )+
    };
}

impl_validate_only!(CloseReply, LogoffRequest, EchoRequest,);

impl RawPayloadContract for EmptyReply {
    fn validate_raw(&self) -> RawCommandResult<()> {
        Ok(())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        match kind {
            RawCommandKind::TreeDisconnect => {
                let pdu =
                    crate::lib::smb2_cmd_tree_disconnect::smb2_cmd_tree_disconnect_reply_async()
                        .map_err(|error| command_failed(kind, error))?;
                Ok(constructed(pdu.out.len(), 0, None, None))
            }
            RawCommandKind::Echo => {
                let pdu = crate::lib::smb2_cmd_echo::smb2_cmd_echo_reply_async(None)
                    .map_err(|error| command_failed(kind, error))?;
                Ok(constructed(
                    pdu.out.vectors.len(),
                    pdu.input.vectors.len(),
                    None,
                    None,
                ))
            }
            RawCommandKind::Lock => {
                let pdu = crate::lib::smb2_cmd_lock::smb2_cmd_lock_reply_async()
                    .map_err(|error| command_failed(kind, error))?;
                Ok(constructed(pdu.out.len(), 0, None, None))
            }
            RawCommandKind::Logoff => {
                let pdu = crate::lib::smb2_cmd_logoff::smb2_cmd_logoff_reply_async(None)
                    .map_err(|error| command_failed(kind, error))?;
                Ok(constructed(
                    pdu.out.vectors.len(),
                    pdu.input.vectors.len(),
                    None,
                    None,
                ))
            }
            RawCommandKind::Flush => {
                let pdu = crate::lib::smb2_cmd_flush::smb2_cmd_flush_reply_async(None)
                    .map_err(|error| command_failed(kind, error))?;
                Ok(constructed(
                    pdu.out.vectors.len(),
                    pdu.input.vectors.len(),
                    None,
                    None,
                ))
            }
            _ => Ok(RawCommandState::Validated),
        }
    }
}

impl RawPayloadContract for FlushRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        Ok(())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let request = crate::lib::smb2_cmd_flush::Smb2FlushRequest::new(self.file_id.to_le_bytes());
        let pdu = crate::lib::smb2_cmd_flush::smb2_cmd_flush_async(&request, None)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(
            pdu.out.vectors.len(),
            pdu.input.vectors.len(),
            None,
            None,
        ))
    }
}

impl RawPayloadContract for ErrorReply {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "byte_count",
            self.byte_count as usize,
            self.error_data.len(),
        )
    }
}

impl RawPayloadContract for ErrorReplyCommand {
    fn validate_raw(&self) -> RawCommandResult<()> {
        self.reply.validate_raw()
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let reply = crate::lib::smb2_cmd_error::Smb2ErrorReply::new(
            self.reply.error_context_count,
            self.reply.byte_count,
        )
        .with_error_data(self.reply.error_data.clone());
        let pdu = crate::lib::smb2_cmd_error::smb2_cmd_error_reply_async(
            &reply,
            self.causing_command,
            self.status as u32,
            None,
        )
        .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(
            pdu.out.vectors.len(),
            pdu.input.vectors.len(),
            None,
            Some(pdu.header.status),
        ))
    }
}

impl RawPayloadContract for NegotiateRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "dialect_count",
            usize::from(self.dialect_count),
            self.dialects.len(),
        )?;
        check_max("dialect_count", NEGOTIATE_MAX_DIALECTS, self.dialects.len())
    }
}

impl RawPayloadContract for NegotiateReply {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "security_buffer_length",
            usize::from(self.security_buffer_length),
            self.security_buffer.len(),
        )
    }
}

impl RawPayloadContract for SessionSetupRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "security_buffer_length",
            usize::from(self.security_buffer_length),
            self.security_buffer.len(),
        )
    }
}

impl RawPayloadContract for SessionSetupReply {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "security_buffer_length",
            usize::from(self.security_buffer_length),
            self.security_buffer.len(),
        )
    }
}

impl RawPayloadContract for TreeConnectRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        let path_bytes =
            self.path
                .len()
                .checked_mul(2)
                .ok_or(RawCommandError::ValueOutOfRange {
                    field: "path_length",
                    maximum: usize::from(u16::MAX),
                    actual: usize::MAX,
                })?;
        check_declared_len("path_length", usize::from(self.path_length), path_bytes)
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let request = crate::lib::smb2_cmd_tree_connect::Smb2TreeConnectRequest::new(
            self.flags,
            utf16_units_to_le_bytes(&self.path),
        )
        .map_err(|error| command_failed(kind, error))?;
        let pdu = crate::lib::smb2_cmd_tree_connect::smb2_cmd_tree_connect_async(&request)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(pdu.out.len(), 0, None, None))
    }
}

impl RawPayloadContract for TreeConnectReplyCommand {
    fn validate_raw(&self) -> RawCommandResult<()> {
        Ok(())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let reply = crate::lib::smb2_cmd_tree_connect::Smb2TreeConnectReply::new(
            self.reply.share_type,
            self.reply.share_flags,
            self.reply.capabilities,
            self.reply.maximal_access,
        );
        let mut context = crate::lib::smb2_cmd_tree_connect::Smb2TreeConnectContext::new();
        let pdu = crate::lib::smb2_cmd_tree_connect::smb2_cmd_tree_connect_reply_async(
            &mut context,
            &reply,
            self.tree_id,
        )
        .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(pdu.out.len(), 0, None, None))
    }
}

impl RawPayloadContract for CreateRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "name_length",
            usize::from(self.name_length),
            utf16_byte_len(&self.name),
        )?;
        check_declared_len(
            "create_context_length",
            self.create_context_length as usize,
            self.create_context.len(),
        )
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let request = crate::lib::smb2_cmd_create::Smb2CreateRequest::new()
            .with_name(&self.name)
            .with_create_context(&self.create_context);
        let pdu = crate::lib::smb2_cmd_create::smb2_cmd_create_async(request, None)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(pdu.out.len(), 0, None, None))
    }
}

impl RawPayloadContract for CreateReply {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "create_context_length",
            self.create_context_length as usize,
            self.create_context.len(),
        )
    }
}

impl RawPayloadContract for CloseRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        Ok(())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let request = crate::lib::smb2_cmd_close::Smb2CloseRequest::new(
            self.flags,
            self.file_id.to_le_bytes(),
        );
        let pdu = crate::lib::smb2_cmd_close::smb2_cmd_close_async(&request, None)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(
            pdu.out.vectors.len(),
            pdu.input.vectors.len(),
            None,
            None,
        ))
    }
}

impl RawPayloadContract for ReadRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len("length", self.length as usize, self.buf.len())?;
        check_declared_len(
            "read_channel_info_length",
            usize::from(self.read_channel_info_length),
            self.read_channel_info.len(),
        )
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let mut request = crate::lib::smb2_cmd_read::Smb2ReadRequest {
            flags: self.flags,
            length: self.length,
            offset: self.offset,
            file_id: self.file_id.to_le_bytes(),
            minimum_count: self.minimum_count,
            channel: self.channel,
            remaining_bytes: self.remaining_bytes,
            read_channel_info_offset: self.read_channel_info_offset,
            read_channel_info_length: self.read_channel_info_length,
            read_channel_info: self.read_channel_info.clone(),
            reply_buffer_len: Some(self.length),
        };
        let pdu = request
            .cmd_read_async(true, false)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(
            pdu.out.len(),
            pdu.input.len(),
            Some(pdu.credit_charge),
            None,
        ))
    }
}

impl RawPayloadContract for ReadReply {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len("data_length", self.data_length as usize, self.data.len())
    }

    fn construction_state(
        &self,
        _kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let mut reply = crate::lib::smb2_cmd_read::Smb2ReadReply {
            data_offset: self.data_offset,
            data_length: self.data_length,
            data_remaining: self.data_remaining,
            data: self.data.clone(),
        };
        let pdu = reply.cmd_read_reply_async();
        Ok(constructed(pdu.out.len(), pdu.input.len(), None, None))
    }
}

impl RawPayloadContract for WriteRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len("length", self.length as usize, self.buf.len())?;
        check_declared_len(
            "write_channel_info_length",
            usize::from(self.write_channel_info_length),
            self.write_channel_info.len(),
        )
    }
}

impl RawPayloadContract for WriteRequestCommand {
    fn validate_raw(&self) -> RawCommandResult<()> {
        self.request.validate_raw()
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let mut request = crate::lib::smb2_cmd_write::Smb2WriteRequest::new(
            self.request.file_id.to_le_bytes(),
            self.request.offset,
            &self.request.buf,
        );
        request.channel = self.request.channel;
        request.remaining_bytes = self.request.remaining_bytes;
        request.write_channel_info_offset = self.request.write_channel_info_offset;
        request.write_channel_info_length = self.request.write_channel_info_length;
        request.write_channel_info = (!self.request.write_channel_info.is_empty())
            .then_some(self.request.write_channel_info.as_slice());
        request.flags = self.request.flags;
        let ownership = if self.pass_buf_ownership {
            crate::lib::smb2_cmd_write::WriteBufferOwnership::Transferred
        } else {
            crate::lib::smb2_cmd_write::WriteBufferOwnership::Borrowed
        };
        let pdu = crate::lib::smb2_cmd_write::smb2_cmd_write_async(
            crate::lib::smb2_cmd_write::WriteEncodeOptions {
                supports_multi_credit: true,
                passthrough: false,
            },
            request,
            ownership,
        )
        .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(pdu.out.len(), 0, Some(pdu.credit_charge), None))
    }
}

impl RawPayloadContract for WriteReply {
    fn validate_raw(&self) -> RawCommandResult<()> {
        Ok(())
    }

    fn construction_state(
        &self,
        _kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let reply = crate::lib::smb2_cmd_write::Smb2WriteReply {
            count: self.count,
            remaining: self.remaining,
        };
        let _ = crate::lib::smb2_cmd_write::encode_write_reply_fixed(reply);
        Ok(constructed(1, 0, None, None))
    }
}

impl RawPayloadContract for QueryDirectoryRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "file_name_length",
            usize::from(self.file_name_length),
            utf16_byte_len(&self.name),
        )
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let mut request = crate::lib::smb2_cmd_query_directory::QueryDirectoryRequest::new(
            self.file_information_class,
            self.file_id.to_le_bytes(),
            self.output_buffer_length,
        );
        request.flags = self.flags;
        request.file_index = self.file_index;
        request.file_name_offset = self.file_name_offset;
        request.file_name_length = self.file_name_length;
        request.name = (!self.name.is_empty()).then_some(self.name.clone());
        let pdu =
            crate::lib::smb2_cmd_query_directory::smb2_cmd_query_directory_async(&request, true)
                .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(1, 0, Some(pdu.credit_charge), None))
    }
}

impl RawPayloadContract for QueryDirectoryReply {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "output_buffer_length",
            self.output_buffer_length as usize,
            self.output_buffer.len(),
        )
    }
}

impl RawPayloadContract for QueryDirectoryReplyCommand {
    fn validate_raw(&self) -> RawCommandResult<()> {
        self.request.validate_raw()?;
        self.reply.validate_raw()
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let reply = crate::lib::smb2_cmd_query_directory::QueryDirectoryReply {
            output_buffer_offset: self.reply.output_buffer_offset,
            output_buffer_length: self.reply.output_buffer_length,
            output_buffer: self.reply.output_buffer.clone(),
        };
        let pdu =
            crate::lib::smb2_cmd_query_directory::smb2_cmd_query_directory_reply_async(&reply)
                .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(1, 0, Some(pdu.credit_charge), None))
    }
}

impl RawPayloadContract for ChangeNotifyRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        Ok(())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let request = crate::lib::smb2_cmd_notify_change::ChangeNotifyRequest::new(
            self.file_id.to_le_bytes(),
            self.flags,
            self.output_buffer_length,
            self.completion_filter,
        );
        let _ = crate::lib::smb2_cmd_notify_change::smb2_cmd_change_notify_async(&request)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(1, 0, None, None))
    }
}

impl RawPayloadContract for ChangeNotifyReply {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "output_buffer_length",
            self.output_buffer_length as usize,
            self.output.len(),
        )
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let reply = crate::lib::smb2_cmd_notify_change::ChangeNotifyReply {
            output_buffer_offset: self.output_buffer_offset,
            output_buffer_length: self.output_buffer_length,
            output: self.output.clone(),
        };
        let _ = crate::lib::smb2_cmd_notify_change::smb2_cmd_change_notify_reply_async(&reply)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(1, 0, None, None))
    }
}

impl RawPayloadContract for QueryInfoRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "input_buffer_length",
            self.input_buffer_length as usize,
            self.input_buffer.len(),
        )?;
        check_declared_len("input", self.input.len(), self.input.len())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let mut request = crate::lib::smb2_cmd_query_info::QueryInfoRequest::new(
            self.info_type,
            self.file_info_class,
            self.file_id.to_le_bytes(),
            self.output_buffer_length,
        );
        request.input_buffer_offset = self.input_buffer_offset;
        request.input_buffer_length = self.input_buffer_length;
        request.input = if self.input.is_empty() {
            self.input_buffer.clone()
        } else {
            self.input.clone()
        };
        request.additional_information = self.additional_information;
        request.flags = self.flags;
        let _ = crate::lib::smb2_cmd_query_info::smb2_cmd_query_info_async(&request)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(1, 0, None, None))
    }
}

impl RawPayloadContract for QueryInfoReply {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "output_buffer_length",
            self.output_buffer_length as usize,
            self.output_buffer.len(),
        )
    }

    fn data_release(&self) -> RawDataRelease {
        if self.output_buffer.is_empty() {
            RawDataRelease::None
        } else {
            RawDataRelease::FreeDataRequired
        }
    }
}

impl RawPayloadContract for QueryInfoReplyCommand {
    fn validate_raw(&self) -> RawCommandResult<()> {
        self.request.validate_raw()?;
        self.reply.validate_raw()
    }

    fn data_release(&self) -> RawDataRelease {
        self.reply.data_release()
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let mut request = crate::lib::smb2_cmd_query_info::QueryInfoRequest::new(
            self.request.info_type,
            self.request.file_info_class,
            self.request.file_id.to_le_bytes(),
            self.request.output_buffer_length,
        );
        request.input = if self.request.input.is_empty() {
            self.request.input_buffer.clone()
        } else {
            self.request.input.clone()
        };
        request.additional_information = self.request.additional_information;
        request.flags = self.request.flags;
        let reply = crate::lib::smb2_cmd_query_info::QueryInfoReply::new()
            .with_raw_output(self.reply.output_buffer.clone())
            .map_err(|error| command_failed(kind, error))?;
        let pdu = crate::lib::smb2_cmd_query_info::smb2_cmd_query_info_reply_async(
            &request, &reply, true,
        )
        .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(1, 0, None, pdu.status))
    }
}

impl RawPayloadContract for SetInfoRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "buffer_length",
            self.buffer_length as usize,
            self.input_data.len(),
        )
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let request = crate::lib::smb2_cmd_set_info::SetInfoRequest::new(
            self.info_type,
            self.file_info_class,
            self.file_id.to_le_bytes(),
        )
        .with_payload(crate::lib::smb2_cmd_set_info::SetInfoPayload::Raw(
            self.input_data.clone(),
        ));
        match direction {
            RawCommandDirection::Request => {
                let _ = crate::lib::smb2_cmd_set_info::smb2_cmd_set_info_async(&request, true)
                    .map_err(|error| command_failed(kind, error))?;
            }
            RawCommandDirection::Reply => {
                let _ = crate::lib::smb2_cmd_set_info::smb2_cmd_set_info_reply_async(&request)
                    .map_err(|error| command_failed(kind, error))?;
            }
        }
        Ok(constructed(1, 0, None, None))
    }
}

impl RawPayloadContract for IoctlRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len("input_count", self.input_count as usize, self.input.len())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let input = if self.input.is_empty() {
            crate::lib::smb2_cmd_ioctl::IoctlRequestInput::None
        } else {
            crate::lib::smb2_cmd_ioctl::IoctlRequestInput::Raw(self.input.clone())
        };
        let mut request = crate::lib::smb2_cmd_ioctl::IoctlRequest::new(
            self.ctl_code,
            self.file_id.to_le_bytes(),
            input,
            self.flags,
        );
        request.input_offset = self.input_offset;
        request.input_count = self.input_count;
        request.max_input_response = self.max_input_response;
        request.output_offset = self.output_offset;
        request.output_count = self.output_count;
        request.max_output_response = self.max_output_response;
        let _ = crate::lib::smb2_cmd_ioctl::smb2_cmd_ioctl_async(&request)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(1, 0, None, None))
    }
}

impl RawPayloadContract for IoctlReply {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len(
            "output_count",
            self.output_count as usize,
            self.output.len(),
        )
    }

    fn data_release(&self) -> RawDataRelease {
        if self.output.is_empty() {
            RawDataRelease::None
        } else {
            RawDataRelease::FreeDataRequired
        }
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let output = if self.output.is_empty() {
            crate::lib::smb2_cmd_ioctl::IoctlReplyOutput::None
        } else {
            crate::lib::smb2_cmd_ioctl::IoctlReplyOutput::Raw(self.output.clone())
        };
        let mut reply = crate::lib::smb2_cmd_ioctl::IoctlReply::new(
            self.ctl_code,
            self.file_id.to_le_bytes(),
            output,
            self.flags,
        );
        reply.input_offset = self.input_offset;
        reply.input_count = self.input_count;
        reply.output_offset = self.output_offset;
        reply.output_count = self.output_count;
        let _ = crate::lib::smb2_cmd_ioctl::smb2_cmd_ioctl_reply_async(&reply, true)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(1, 0, None, None))
    }
}

impl RawPayloadContract for OplockBreakAcknowledgement {
    fn validate_raw(&self) -> RawCommandResult<()> {
        Ok(())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let body = crate::lib::smb2_cmd_oplock_break::Smb2OplockBreakAcknowledgement::new(
            self.oplock_level,
            self.file_id.to_le_bytes(),
        );
        let pdu = crate::lib::smb2_cmd_oplock_break::smb2_cmd_oplock_break_async(&body, None)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(pdu.out.vectors.len(), 0, None, None))
    }
}

impl RawPayloadContract for OplockBreakReply {
    fn validate_raw(&self) -> RawCommandResult<()> {
        Ok(())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let body = crate::lib::smb2_cmd_oplock_break::Smb2OplockBreakReply::new(
            self.oplock_level,
            self.file_id.to_le_bytes(),
        );
        let pdu = crate::lib::smb2_cmd_oplock_break::smb2_cmd_oplock_break_reply_async(&body, None)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(pdu.out.vectors.len(), 0, None, None))
    }
}

impl RawPayloadContract for OplockBreakNotification {
    fn validate_raw(&self) -> RawCommandResult<()> {
        Ok(())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let body = crate::lib::smb2_cmd_oplock_break::Smb2OplockBreakNotification::new(
            self.oplock_level,
            self.file_id.to_le_bytes(),
        );
        let pdu = crate::lib::smb2_cmd_oplock_break::smb2_cmd_oplock_break_notification_async(
            &body, None,
        )
        .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(pdu.out.vectors.len(), 0, None, None))
    }
}

impl RawPayloadContract for LeaseBreakAcknowledgement {
    fn validate_raw(&self) -> RawCommandResult<()> {
        Ok(())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let body = crate::lib::smb2_cmd_oplock_break::Smb2LeaseBreakAcknowledgement::new(
            self.flags,
            self.lease_key.0,
            self.lease_state,
            self.lease_duration,
        );
        let pdu = crate::lib::smb2_cmd_oplock_break::smb2_cmd_lease_break_async(&body, None)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(pdu.out.vectors.len(), 0, None, None))
    }
}

impl RawPayloadContract for LeaseBreakReply {
    fn validate_raw(&self) -> RawCommandResult<()> {
        Ok(())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let body = crate::lib::smb2_cmd_oplock_break::Smb2LeaseBreakReply::new(
            self.flags,
            self.lease_key.0,
            self.lease_state,
            self.lease_duration,
        );
        let pdu = crate::lib::smb2_cmd_oplock_break::smb2_cmd_lease_break_reply_async(&body, None)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(pdu.out.vectors.len(), 0, None, None))
    }
}

impl RawPayloadContract for LeaseBreakNotification {
    fn validate_raw(&self) -> RawCommandResult<()> {
        Ok(())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let body = crate::lib::smb2_cmd_oplock_break::Smb2LeaseBreakNotification {
            new_epoch: self.new_epoch,
            flags: self.flags,
            lease_key: self.lease_key.0,
            current_lease_state: self.current_lease_state,
            new_lease_state: self.new_lease_state,
            break_reason: self.break_reason,
            access_mask_hint: self.access_mask_hint,
            share_mask_hint: self.share_mask_hint,
        };
        let pdu =
            crate::lib::smb2_cmd_oplock_break::smb2_cmd_lease_break_notification_async(&body, None)
                .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(pdu.out.vectors.len(), 0, None, None))
    }
}

impl RawPayloadContract for LockRequest {
    fn validate_raw(&self) -> RawCommandResult<()> {
        check_declared_len("lock_count", usize::from(self.lock_count), self.locks.len())
    }

    fn construction_state(
        &self,
        kind: RawCommandKind,
        _direction: RawCommandDirection,
    ) -> RawCommandResult<RawCommandState> {
        let locks = self
            .locks
            .iter()
            .map(|lock| crate::lib::smb2_cmd_lock::Smb2LockElement {
                offset: lock.offset,
                length: lock.length,
                flags: lock.flags,
            })
            .collect();
        let mut request =
            crate::lib::smb2_cmd_lock::Smb2LockRequest::new(self.file_id.to_le_bytes(), locks);
        request.lock_sequence_number = u32::from(self.lock_sequence_number);
        request.lock_sequence_index = self.lock_sequence_index;
        let pdu = crate::lib::smb2_cmd_lock::smb2_cmd_lock_async(request)
            .map_err(|error| command_failed(kind, error))?;
        Ok(constructed(pdu.out.len(), 0, None, None))
    }
}

fn constructed(
    output_vectors: usize,
    input_vectors: usize,
    credit_charge: Option<u16>,
    status: Option<u32>,
) -> RawCommandState {
    RawCommandState::Constructed {
        output_vectors,
        input_vectors,
        credit_charge,
        status,
    }
}

fn command_failed(kind: RawCommandKind, error: impl fmt::Debug) -> RawCommandError {
    RawCommandError::CommandConstructionFailed {
        command: kind,
        reason: format!("{error:?}"),
    }
}

fn check_declared_len(field: &'static str, declared: usize, actual: usize) -> RawCommandResult<()> {
    if declared == actual {
        Ok(())
    } else {
        Err(RawCommandError::LengthMismatch {
            field,
            declared,
            actual,
        })
    }
}

fn check_max(field: &'static str, maximum: usize, actual: usize) -> RawCommandResult<()> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(RawCommandError::ValueOutOfRange {
            field,
            maximum,
            actual,
        })
    }
}

fn utf16_byte_len(value: &str) -> usize {
    value.encode_utf16().count().saturating_mul(2)
}

fn utf16_units_to_le_bytes(units: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(units.len().saturating_mul(2));
    for unit in units {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

macro_rules! raw_request_fn {
    ($fn_name:ident, $payload:ty, $kind:expr, $doc:literal) => {
        #[doc = $doc]
        ///
        /// # Errors
        ///
        /// Returns an error when the payload length/count contract is invalid or
        /// a migrated pure command constructor rejects the payload.
        pub fn $fn_name(payload: $payload) -> RawCommandResult<RawCommand<$payload>> {
            build_raw_command($kind, RawCommandDirection::Request, payload)
        }
    };
}

macro_rules! raw_reply_fn {
    ($fn_name:ident, $payload:ty, $kind:expr, $doc:literal) => {
        #[doc = $doc]
        ///
        /// # Errors
        ///
        /// Returns an error when the payload length/count contract is invalid or
        /// a migrated pure command constructor rejects the payload.
        pub fn $fn_name(payload: $payload) -> RawCommandResult<RawCommand<$payload>> {
            build_raw_command($kind, RawCommandDirection::Reply, payload)
        }
    };
}

fn build_raw_command<T: RawPayloadContract>(
    kind: RawCommandKind,
    direction: RawCommandDirection,
    payload: T,
) -> RawCommandResult<RawCommand<T>> {
    payload.validate_raw()?;
    let state = payload.construction_state(kind, direction)?;
    let data_release = payload.data_release();
    Ok(RawCommand::new(kind, direction, payload)
        .with_state(state)
        .with_data_release(data_release))
}

raw_request_fn!(
    cmd_negotiate_async,
    NegotiateRequest,
    RawCommandKind::Negotiate,
    "Creates a protocol-free NEGOTIATE request command descriptor."
);
raw_reply_fn!(
    cmd_negotiate_reply_async,
    NegotiateReply,
    RawCommandKind::Negotiate,
    "Creates a protocol-free NEGOTIATE reply command descriptor."
);
raw_request_fn!(
    cmd_session_setup_async,
    SessionSetupRequest,
    RawCommandKind::SessionSetup,
    "Creates a protocol-free SESSION_SETUP request command descriptor."
);
raw_reply_fn!(
    cmd_session_setup_reply_async,
    SessionSetupReply,
    RawCommandKind::SessionSetup,
    "Creates a protocol-free SESSION_SETUP reply command descriptor."
);
raw_request_fn!(
    cmd_tree_connect_async,
    TreeConnectRequest,
    RawCommandKind::TreeConnect,
    "Creates a protocol-free TREE_CONNECT request command descriptor."
);
raw_reply_fn!(
    cmd_tree_connect_reply_async,
    TreeConnectReplyCommand,
    RawCommandKind::TreeConnect,
    "Creates a protocol-free TREE_CONNECT reply command descriptor."
);

/// Creates a protocol-free TREE_DISCONNECT request command descriptor.
///
/// # Errors
///
/// Returns an error if the migrated pure TREE_DISCONNECT constructor fails.
pub fn cmd_tree_disconnect_async() -> RawCommandResult<RawCommand<()>> {
    let pdu = crate::lib::smb2_cmd_tree_disconnect::smb2_cmd_tree_disconnect_async()
        .map_err(|error| command_failed(RawCommandKind::TreeDisconnect, error))?;
    Ok(RawCommand::new(
        RawCommandKind::TreeDisconnect,
        RawCommandDirection::Request,
        (),
    )
    .with_state(constructed(pdu.out.len(), 0, None, None)))
}

raw_reply_fn!(
    cmd_tree_disconnect_reply_async,
    EmptyReply,
    RawCommandKind::TreeDisconnect,
    "Creates a protocol-free TREE_DISCONNECT reply command descriptor."
);
raw_request_fn!(
    cmd_create_async,
    CreateRequest,
    RawCommandKind::Create,
    "Creates a protocol-free CREATE request command descriptor."
);
raw_reply_fn!(
    cmd_create_reply_async,
    CreateReply,
    RawCommandKind::Create,
    "Creates a protocol-free CREATE reply command descriptor."
);
raw_request_fn!(
    cmd_close_async,
    CloseRequest,
    RawCommandKind::Close,
    "Creates a protocol-free CLOSE request command descriptor."
);
raw_reply_fn!(
    cmd_close_reply_async,
    CloseReply,
    RawCommandKind::Close,
    "Creates a protocol-free CLOSE reply command descriptor."
);
raw_request_fn!(
    cmd_read_async,
    ReadRequest,
    RawCommandKind::Read,
    "Creates a protocol-free READ request command descriptor."
);
raw_reply_fn!(
    cmd_read_reply_async,
    ReadReply,
    RawCommandKind::Read,
    "Creates a protocol-free READ reply command descriptor."
);
raw_request_fn!(
    cmd_write_async,
    WriteRequestCommand,
    RawCommandKind::Write,
    "Creates a protocol-free WRITE request command descriptor."
);
raw_reply_fn!(
    cmd_write_reply_async,
    WriteReply,
    RawCommandKind::Write,
    "Creates a protocol-free WRITE reply command descriptor."
);
raw_request_fn!(
    cmd_query_directory_async,
    QueryDirectoryRequest,
    RawCommandKind::QueryDirectory,
    "Creates a protocol-free QUERY_DIRECTORY request command descriptor."
);
raw_reply_fn!(
    cmd_query_directory_reply_async,
    QueryDirectoryReplyCommand,
    RawCommandKind::QueryDirectory,
    "Creates a protocol-free QUERY_DIRECTORY reply command descriptor."
);
raw_request_fn!(
    cmd_change_notify_async,
    ChangeNotifyRequest,
    RawCommandKind::ChangeNotify,
    "Creates a protocol-free CHANGE_NOTIFY request command descriptor."
);
raw_reply_fn!(
    cmd_change_notify_reply_async,
    ChangeNotifyReply,
    RawCommandKind::ChangeNotify,
    "Creates a protocol-free CHANGE_NOTIFY reply command descriptor."
);
raw_request_fn!(
    cmd_query_info_async,
    QueryInfoRequest,
    RawCommandKind::QueryInfo,
    "Creates a protocol-free QUERY_INFO request command descriptor."
);
raw_reply_fn!(
    cmd_query_info_reply_async,
    QueryInfoReplyCommand,
    RawCommandKind::QueryInfo,
    "Creates a protocol-free QUERY_INFO reply command descriptor."
);
raw_request_fn!(
    cmd_set_info_async,
    SetInfoRequest,
    RawCommandKind::SetInfo,
    "Creates a protocol-free SET_INFO request command descriptor."
);
raw_reply_fn!(
    cmd_set_info_reply_async,
    SetInfoRequest,
    RawCommandKind::SetInfo,
    "Creates a protocol-free SET_INFO reply command descriptor."
);
raw_request_fn!(
    cmd_ioctl_async,
    IoctlRequest,
    RawCommandKind::Ioctl,
    "Creates a protocol-free IOCTL request command descriptor."
);
raw_reply_fn!(
    cmd_ioctl_reply_async,
    IoctlReply,
    RawCommandKind::Ioctl,
    "Creates a protocol-free IOCTL reply command descriptor."
);

/// Creates a protocol-free ECHO request command descriptor.
///
/// # Errors
///
/// Returns an error if the migrated pure ECHO constructor fails.
pub fn cmd_echo_async() -> RawCommandResult<RawCommand<EchoRequest>> {
    let pdu = crate::lib::smb2_cmd_echo::smb2_cmd_echo_async(None)
        .map_err(|error| command_failed(RawCommandKind::Echo, error))?;
    Ok(RawCommand::new(
        RawCommandKind::Echo,
        RawCommandDirection::Request,
        EchoRequest::default(),
    )
    .with_state(constructed(
        pdu.out.vectors.len(),
        pdu.input.vectors.len(),
        None,
        None,
    )))
}

raw_reply_fn!(
    cmd_echo_reply_async,
    EmptyReply,
    RawCommandKind::Echo,
    "Creates a protocol-free ECHO reply command descriptor."
);
raw_request_fn!(
    cmd_lock_async,
    LockRequest,
    RawCommandKind::Lock,
    "Creates a protocol-free LOCK request command descriptor."
);
raw_reply_fn!(
    cmd_lock_reply_async,
    EmptyReply,
    RawCommandKind::Lock,
    "Creates a protocol-free LOCK reply command descriptor."
);

/// Creates a protocol-free LOGOFF request command descriptor.
///
/// # Errors
///
/// Returns an error if the migrated pure LOGOFF constructor fails.
pub fn cmd_logoff_async() -> RawCommandResult<RawCommand<LogoffRequest>> {
    let pdu = crate::lib::smb2_cmd_logoff::smb2_cmd_logoff_async(None)
        .map_err(|error| command_failed(RawCommandKind::Logoff, error))?;
    Ok(RawCommand::new(
        RawCommandKind::Logoff,
        RawCommandDirection::Request,
        LogoffRequest::default(),
    )
    .with_state(constructed(
        pdu.out.vectors.len(),
        pdu.input.vectors.len(),
        None,
        None,
    )))
}

raw_reply_fn!(
    cmd_logoff_reply_async,
    EmptyReply,
    RawCommandKind::Logoff,
    "Creates a protocol-free LOGOFF reply command descriptor."
);
raw_request_fn!(
    cmd_flush_async,
    FlushRequest,
    RawCommandKind::Flush,
    "Creates a protocol-free FLUSH request command descriptor."
);
raw_reply_fn!(
    cmd_flush_reply_async,
    EmptyReply,
    RawCommandKind::Flush,
    "Creates a protocol-free FLUSH reply command descriptor."
);
raw_request_fn!(
    cmd_oplock_break_async,
    OplockBreakAcknowledgement,
    RawCommandKind::OplockBreak,
    "Creates a protocol-free OPLOCK_BREAK acknowledgement command descriptor."
);
raw_reply_fn!(
    cmd_oplock_break_reply_async,
    OplockBreakReply,
    RawCommandKind::OplockBreak,
    "Creates a protocol-free OPLOCK_BREAK reply command descriptor."
);
raw_reply_fn!(
    cmd_oplock_break_notification_async,
    OplockBreakNotification,
    RawCommandKind::OplockBreak,
    "Creates a protocol-free OPLOCK_BREAK notification command descriptor."
);
raw_request_fn!(
    cmd_lease_break_async,
    LeaseBreakAcknowledgement,
    RawCommandKind::OplockBreak,
    "Creates a protocol-free LEASE_BREAK acknowledgement command descriptor."
);
raw_reply_fn!(
    cmd_lease_break_reply_async,
    LeaseBreakReply,
    RawCommandKind::OplockBreak,
    "Creates a protocol-free LEASE_BREAK reply command descriptor."
);
raw_reply_fn!(
    cmd_lease_break_notification_async,
    LeaseBreakNotification,
    RawCommandKind::OplockBreak,
    "Creates a protocol-free LEASE_BREAK notification command descriptor."
);
raw_reply_fn!(
    cmd_error_reply_async,
    ErrorReplyCommand,
    RawCommandKind::Error,
    "Creates a protocol-free SMB2 error reply command descriptor."
);

/// SMB2 file-id size in bytes (`SMB2_FD_SIZE`).
pub const SMB2_FD_SIZE: usize = 16;

/// Special compound-request file-id sentinel (`compound_file_id`).
pub const COMPOUND_FILE_ID: [u8; SMB2_FD_SIZE] = [0xff; SMB2_FD_SIZE];
