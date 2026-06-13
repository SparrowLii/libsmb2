//! Raw SMB2 request/reply data structure skeletons from `include/smb2/libsmb2-raw.h`.
//!
//! This module mirrors the C raw-command surface at the data-shape level. It is
//! intentionally a protocol skeleton: command helpers only describe which raw
//! command would be issued and keep the supplied payload; they do not encode,
//! send, decode, or validate SMB2 PDUs.

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

/// Protocol-free command descriptor returned by raw command helper skeletons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCommand<T> {
    /// SMB2 command represented by this descriptor.
    pub kind: RawCommandKind,
    /// Whether this descriptor represents a request or a reply path.
    pub direction: RawCommandDirection,
    /// Command-specific payload retained for a future encoder/dispatcher.
    pub payload: T,
}

impl<T> RawCommand<T> {
    /// Creates a raw command descriptor without performing SMB2 protocol work.
    #[must_use]
    pub const fn new(kind: RawCommandKind, direction: RawCommandDirection, payload: T) -> Self {
        Self {
            kind,
            direction,
            payload,
        }
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

macro_rules! raw_request_fn {
    ($fn_name:ident, $payload:ty, $kind:expr, $doc:literal) => {
        #[doc = $doc]
        #[must_use]
        pub fn $fn_name(payload: $payload) -> RawCommand<$payload> {
            RawCommand::new($kind, RawCommandDirection::Request, payload)
        }
    };
}

macro_rules! raw_reply_fn {
    ($fn_name:ident, $payload:ty, $kind:expr, $doc:literal) => {
        #[doc = $doc]
        #[must_use]
        pub fn $fn_name(payload: $payload) -> RawCommand<$payload> {
            RawCommand::new($kind, RawCommandDirection::Reply, payload)
        }
    };
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
#[must_use]
pub fn cmd_tree_disconnect_async() -> RawCommand<()> {
    RawCommand::new(
        RawCommandKind::TreeDisconnect,
        RawCommandDirection::Request,
        (),
    )
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
#[must_use]
pub fn cmd_echo_async() -> RawCommand<EchoRequest> {
    RawCommand::new(
        RawCommandKind::Echo,
        RawCommandDirection::Request,
        EchoRequest::default(),
    )
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
#[must_use]
pub fn cmd_logoff_async() -> RawCommand<LogoffRequest> {
    RawCommand::new(
        RawCommandKind::Logoff,
        RawCommandDirection::Request,
        LogoffRequest::default(),
    )
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
