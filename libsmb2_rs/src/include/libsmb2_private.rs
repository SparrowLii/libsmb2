//! Internal Rust structures and interface skeletons mirroring `include/libsmb2-private.h`.
//!
//! This module intentionally keeps protocol logic shallow. It preserves the
//! Rust skeleton field shapes already used by the crate, while adding explicit
//! private-layout types for C-only fields that do not yet have migrated logic.

use std::ffi::CString;

use crate::include::smb2::libsmb2::{CommandCallback, DirectoryEntry, ErrorCode, FileType, Stat};
use crate::include::smb2::libsmb2_raw::FileId;
use crate::include::smb2::smb2::{
    Command, SMB2_CANCEL_REQUEST_SIZE, SMB2_CHANGE_NOTIFY_REPLY_SIZE,
    SMB2_CHANGE_NOTIFY_REQUEST_SIZE, SMB2_CLOSE_REPLY_SIZE, SMB2_CLOSE_REQUEST_SIZE,
    SMB2_CREATE_REPLY_SIZE, SMB2_CREATE_REQUEST_SIZE, SMB2_ECHO_REPLY_SIZE, SMB2_ECHO_REQUEST_SIZE,
    SMB2_ERROR_REPLY_SIZE, SMB2_FLUSH_REPLY_SIZE, SMB2_FLUSH_REQUEST_SIZE, SMB2_IOCTL_REPLY_SIZE,
    SMB2_IOCTL_REQUEST_SIZE, SMB2_LOCK_REPLY_SIZE, SMB2_LOCK_REQUEST_SIZE, SMB2_LOGOFF_REPLY_SIZE,
    SMB2_LOGOFF_REQUEST_SIZE, SMB2_NEGOTIATE_REPLY_SIZE, SMB2_NEGOTIATE_REQUEST_SIZE,
    SMB2_QUERY_DIRECTORY_REPLY_SIZE, SMB2_QUERY_DIRECTORY_REQUEST_SIZE, SMB2_QUERY_INFO_REPLY_SIZE,
    SMB2_QUERY_INFO_REQUEST_SIZE, SMB2_READ_REPLY_SIZE, SMB2_READ_REQUEST_SIZE,
    SMB2_SESSION_SETUP_REPLY_SIZE, SMB2_SESSION_SETUP_REQUEST_SIZE, SMB2_SET_INFO_REPLY_SIZE,
    SMB2_SET_INFO_REQUEST_SIZE, SMB2_TREE_CONNECT_REPLY_SIZE, SMB2_TREE_CONNECT_REQUEST_SIZE,
    SMB2_TREE_DISCONNECT_REPLY_SIZE, SMB2_TREE_DISCONNECT_REQUEST_SIZE, SMB2_WRITE_REPLY_SIZE,
    SMB2_WRITE_REQUEST_SIZE,
};

/// Maximum formatted error string size used by the C context.
pub const MAX_ERROR_SIZE: usize = 256;
/// Size of the NetBIOS-style session packet length prefix.
pub const SMB2_SPL_SIZE: usize = 4;
/// SMB2 header size in bytes.
pub const SMB2_HEADER_SIZE: usize = 64;
/// SMB2 signature size in bytes.
pub const SMB2_SIGNATURE_SIZE: usize = 16;
/// SMB2 signing and encryption key size in bytes.
pub const SMB2_KEY_SIZE: usize = 16;
/// Maximum number of SMB2 iovecs used by the legacy implementation.
pub const SMB2_MAX_VECTORS: usize = 256;
/// Maximum nested tree-id depth tracked by the C context.
pub const SMB2_MAX_TREE_NESTING: usize = 32;
/// Maximum credit count requested by the legacy implementation.
pub const MAX_CREDITS: i32 = 1024;
/// SMB3 pre-authentication salt size in bytes.
pub const SMB2_SALT_SIZE: usize = 32;
/// SMB3 pre-authentication hash size in bytes.
pub const SMB2_PREAUTH_HASH_SIZE: usize = 64;
/// Maximum PDU size accepted by the legacy implementation.
pub const SMB2_MAX_PDU_SIZE: usize = 16 * 1024 * 1024;
/// Sentinel used by the C `smb2_tree_id` macro when no tree id is active.
pub const DEAD_TREE_ID: u32 = 0xdead_beef;
/// SMB2 protocol signature used by normal SMB2 headers.
pub const SMB2_PROTOCOL_ID: [u8; 4] = [0xfe, b'S', b'M', b'B'];
/// SMB1 signature accepted only for legacy negotiate requests.
pub const SMB1_PROTOCOL_ID: [u8; 4] = [0xff, b'S', b'M', b'B'];
/// SMB1 negotiate command byte.
pub const SMB1_NEGOTIATE: u8 = 0x72;
/// Header flag indicating an async SMB2 command.
pub const SMB2_FLAGS_ASYNC_COMMAND: u32 = 0x0000_0002;

/// Pads `len` to the next 32-bit boundary using the C `PAD_TO_32BIT` rule.
#[must_use]
pub const fn pad_to_32bit(len: usize) -> usize {
    (len + 0x03) & !0x03
}

/// Pads `len` to the next 64-bit boundary using the C `PAD_TO_64BIT` rule.
#[must_use]
pub const fn pad_to_64bit_len(len: usize) -> usize {
    (len + 0x07) & !0x07
}

/// Internal result type for private SMB2 skeleton operations.
pub type PrivateResult<T> = std::result::Result<T, PrivateError>;

/// Errors returned by internal interface skeletons before protocol logic is ported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateError {
    /// The requested operation is only represented as an interface skeleton.
    ProtocolLogicUnavailable,
    /// The supplied vector offset or length is outside the buffer.
    BufferTooShort,
    /// The requested vector count would exceed [`SMB2_MAX_VECTORS`].
    TooManyVectors,
    /// The accumulated IO vector size would overflow `usize`.
    VectorSizeOverflow,
    /// The tree-id stack would exceed [`SMB2_MAX_TREE_NESTING`].
    TooManyTreeIds,
    /// No matching active tree id exists.
    NoCurrentTreeId,
    /// A command-specific fixed payload size is not known by this skeleton.
    UnknownFixedSize,
    /// The header signature is neither SMB2 nor an accepted SMB1 negotiate request.
    BadSignature,
    /// A requested PDU was not present.
    MissingPdu,
    /// A string could not be represented as a C-compatible string.
    InteriorNul,
    /// No credential fields are available for delegation.
    NoCredentials,
}

impl PrivateError {
    /// Returns a negative errno-style code compatible with the public skeleton API.
    #[must_use]
    pub const fn as_error_code(self) -> ErrorCode {
        let code = match self {
            Self::ProtocolLogicUnavailable => -38,
            Self::BufferTooShort => -22,
            Self::TooManyVectors | Self::TooManyTreeIds | Self::VectorSizeOverflow => -75,
            Self::NoCurrentTreeId | Self::UnknownFixedSize | Self::MissingPdu => -2,
            Self::BadSignature | Self::InteriorNul | Self::NoCredentials => -22,
        };
        ErrorCode(code)
    }
}

impl From<crate::lib::pdu::PduError> for PrivateError {
    fn from(error: crate::lib::pdu::PduError) -> Self {
        match error {
            crate::lib::pdu::PduError::OutOfBounds | crate::lib::pdu::PduError::HeaderTooSmall => {
                Self::BufferTooShort
            }
            crate::lib::pdu::PduError::BadSignature => Self::BadSignature,
            crate::lib::pdu::PduError::MissingTreeId
            | crate::lib::pdu::PduError::TreeIdNotFound => Self::NoCurrentTreeId,
            crate::lib::pdu::PduError::TreeNestingTooDeep => Self::TooManyTreeIds,
            crate::lib::pdu::PduError::MissingPdu | crate::lib::pdu::PduError::UnknownCommand => {
                Self::MissingPdu
            }
            crate::lib::pdu::PduError::TooManyVectors => Self::TooManyVectors,
            crate::lib::pdu::PduError::Signing(_) | crate::lib::pdu::PduError::Sealing(_) => {
                Self::ProtocolLogicUnavailable
            }
        }
    }
}

/// Authentication mechanism selected for a context.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum SecurityMode {
    /// Let the implementation choose Kerberos when available, otherwise NTLMSSP.
    #[default]
    Undefined,
    /// NTLMSSP authentication.
    Ntlmssp,
    /// Kerberos authentication.
    Krb5,
}

/// SMB dialect negotiation policy corresponding to `enum smb2_negotiate_version`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PrivateNegotiateVersion {
    /// Let the server choose any supported dialect.
    #[default]
    Any = 0,
    /// Negotiate any SMB2 dialect.
    Any2 = 2,
    /// Negotiate any SMB3 dialect.
    Any3 = 3,
    /// SMB 2.0.2.
    Smb202 = 0x0202,
    /// SMB 2.1.
    Smb210 = 0x0210,
    /// SMB 3.0.
    Smb300 = 0x0300,
    /// SMB 3.0.2.
    Smb302 = 0x0302,
    /// SMB 3.1.1.
    Smb311 = 0x0311,
}

/// Receive state used while decoding SMB2 or SMB3 frames.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecvState {
    /// NetBIOS session packet length prefix.
    #[default]
    Spl = 0,
    /// SMB2 or SMB3 transform header.
    Header,
    /// Fixed command payload.
    Fixed,
    /// Variable command payload.
    Variable,
    /// Command padding.
    Pad,
    /// SMB3 encrypted transform payload.
    Transform,
    /// Reply for a PDU that is no longer tracked.
    Unknown,
}

/// Rust-owned equivalent of `struct smb2_iovec`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IoVec {
    /// Backing bytes for this vector.
    pub buf: Vec<u8>,
}

impl IoVec {
    /// Creates a vector from owned bytes.
    #[must_use]
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf }
    }

    /// Returns the vector length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns true when the vector contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Rust-owned equivalent of `struct smb2_io_vectors`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IoVectors {
    /// Number of bytes already processed.
    pub done: usize,
    /// Total size represented by all vectors.
    pub total_size: usize,
    /// Vectors participating in the operation.
    pub vectors: Vec<IoVec>,
}

impl IoVectors {
    /// Creates an empty vector list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            done: 0,
            total_size: 0,
            vectors: Vec::new(),
        }
    }

    /// Returns the number of vectors, matching the C `niov` field.
    #[must_use]
    pub fn niov(&self) -> usize {
        self.vectors.len()
    }

    /// Adds a vector and updates the total size counter.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateError::TooManyVectors`] when the legacy vector limit would be exceeded, or
    /// [`PrivateError::VectorSizeOverflow`] when the accumulated byte count overflows.
    pub fn add_iovector(&mut self, iov: IoVec) -> PrivateResult<&mut IoVec> {
        if self.vectors.len() >= SMB2_MAX_VECTORS {
            return Err(PrivateError::TooManyVectors);
        }
        self.total_size = self
            .total_size
            .checked_add(iov.len())
            .ok_or(PrivateError::VectorSizeOverflow)?;
        self.vectors.push(iov);
        let index = self.vectors.len() - 1;
        Ok(&mut self.vectors[index])
    }

    /// Clears all vectors and processed byte counters.
    pub fn clear(&mut self) {
        self.done = 0;
        self.total_size = 0;
        self.vectors.clear();
    }
}

/// Async SMB2 header discriminator payload.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AsyncHeader {
    /// Async identifier used when the async flag is set.
    pub async_id: u64,
}

/// Sync SMB2 header discriminator payload.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncHeader {
    /// Process identifier.
    pub process_id: u32,
    /// Tree identifier.
    pub tree_id: u32,
}

/// Rust representation of the anonymous sync/async union in `struct smb2_header`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderId {
    /// Synchronous header fields.
    Sync(SyncHeader),
    /// Asynchronous header fields.
    Async(AsyncHeader),
}

impl Default for HeaderId {
    fn default() -> Self {
        Self::Sync(SyncHeader::default())
    }
}

/// SMB2 header model shared by packers and unpackers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2Header {
    /// Protocol id, normally `0xFE 'S' 'M' 'B'`.
    pub protocol_id: [u8; 4],
    /// Header structure size.
    pub struct_size: u16,
    /// Credit charge.
    pub credit_charge: u16,
    /// NT status in replies.
    pub status: u32,
    /// SMB2 command id.
    pub command: u16,
    /// Credit request or response.
    pub credit_request_response: u16,
    /// Header flags.
    pub flags: u32,
    /// Offset to next command in compound packets.
    pub next_command: u32,
    /// Message id.
    pub message_id: u64,
    /// Process id for sync headers.
    pub process_id: u32,
    /// Tree id for sync headers.
    pub tree_id: u32,
    /// Async id for async headers.
    pub async_id: u64,
    /// Session id.
    pub session_id: u64,
    /// SMB2 signature bytes.
    pub signature: [u8; SMB2_SIGNATURE_SIZE],
}

impl Default for Smb2Header {
    fn default() -> Self {
        Self {
            protocol_id: SMB2_PROTOCOL_ID,
            struct_size: SMB2_HEADER_SIZE as u16,
            credit_charge: 0,
            status: 0,
            command: 0,
            credit_request_response: 0,
            flags: 0,
            next_command: 0,
            message_id: 0,
            process_id: 0,
            tree_id: 0,
            async_id: 0,
            session_id: 0,
            signature: [0; SMB2_SIGNATURE_SIZE],
        }
    }
}

impl Smb2Header {
    /// Creates a normal SMB2 header for a command id.
    #[must_use]
    pub fn for_command(command: Command) -> Self {
        Self {
            command: command as u16,
            ..Self::default()
        }
    }

    /// Returns an explicit sync/async union view for this flat Rust header.
    #[must_use]
    pub const fn id(&self, is_async: bool) -> HeaderId {
        if is_async {
            HeaderId::Async(AsyncHeader {
                async_id: self.async_id,
            })
        } else {
            HeaderId::Sync(SyncHeader {
                process_id: self.process_id,
                tree_id: self.tree_id,
            })
        }
    }
}

/// Synchronous callback bookkeeping used by blocking wrappers.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncCallbackData {
    /// Non-zero once the pending operation has completed.
    pub is_finished: bool,
    /// Completion status.
    pub status: i32,
    /// Opaque payload address retained as an integer skeleton value.
    pub ptr: Option<usize>,
}

/// Socket descriptor placeholder corresponding to `t_socket`.
pub type Socket = i32;
/// Error callback shape matching `smb2_error_cb` without raw pointers.
pub type ErrorCallback = Box<dyn FnMut(&mut Context, &str) + Send + 'static>;
/// File-descriptor change callback shape matching `smb2_change_fd_cb`.
pub type ChangeFdCallback = Box<dyn FnMut(&mut Context, Socket, FdChange) + Send + 'static>;
/// Event-mask change callback shape matching `smb2_change_events_cb`.
pub type ChangeEventsCallback = Box<dyn FnMut(&mut Context, Socket, i32) + Send + 'static>;
/// Oplock or lease break callback shape matching `smb2_oplock_or_lease_break_cb`.
pub type OplockOrLeaseBreakCallback =
    Box<dyn FnMut(&mut Context, i32, &mut OplockOrLeaseBreakReply) + Send + 'static>;
/// Payload cleanup callback shape matching `smb2_free_payload`.
pub type FreePayloadCallback = Box<dyn FnOnce(&mut Context, Payload) + Send + 'static>;
/// Generic boxed cleanup callback used for callback data placeholders.
pub type FreeCallback = Box<dyn FnOnce(Payload) + Send + 'static>;

/// File descriptor callback operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdChange {
    /// Add or replace a descriptor in the event loop.
    Add,
    /// Remove a descriptor from the event loop.
    Delete,
}

/// Opaque callback or command payload retained by skeleton interfaces.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Payload {
    /// Raw payload bytes when a skeleton chooses to retain owned data.
    pub bytes: Vec<u8>,
}

/// Placeholder reply passed to oplock or lease break callbacks.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OplockOrLeaseBreakReply {
    /// Fixed response structure size used to distinguish oplock and lease breaks.
    pub struct_size: u16,
    /// New oplock level selected by the application.
    pub new_oplock_level: Option<u8>,
    /// New lease state selected by the application.
    pub new_lease_state: Option<u32>,
}

/// Private fields from `struct smb2_pdu` that are not part of the existing Rust `Pdu` shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduPrivateFields {
    /// Previous compound message id.
    pub prev_compound_mid: u64,
    /// Whether the caller is responsible for freeing this PDU.
    pub caller_frees_pdu: bool,
    /// Header scratch buffer.
    pub hdr: [u8; SMB2_HEADER_SIZE],
    /// QUERY_INFO info type retained between request and reply.
    pub info_type: u8,
    /// QUERY_INFO file information class retained between request and reply.
    pub file_info_class: u8,
    /// Whether this PDU should be encrypted.
    pub seal: bool,
    /// Encrypted payload length.
    pub crypt_len: u32,
    /// Encrypted payload bytes.
    pub crypt: Vec<u8>,
}

impl Default for PduPrivateFields {
    fn default() -> Self {
        Self {
            prev_compound_mid: 0,
            caller_frees_pdu: false,
            hdr: [0; SMB2_HEADER_SIZE],
            info_type: 0,
            file_info_class: 0,
            seal: false,
            crypt_len: 0,
            crypt: Vec::new(),
        }
    }
}

/// Internal PDU model corresponding to the currently migrated `struct smb2_pdu` skeleton.
pub struct Pdu {
    /// Decoded SMB2 header.
    pub header: Smb2Header,
    /// Outgoing vectors.
    pub out: IoVectors,
    /// Incoming vectors.
    pub input: IoVectors,
    /// Optional completion callback.
    pub callback: Option<CommandCallback>,
    /// Whether the PDU belongs to a compound chain.
    pub compound: bool,
    /// Next PDU in a compound chain.
    pub next_compound: Option<Box<Pdu>>,
    /// Previous compound message id.
    pub prev_compound_mid: u64,
    /// Decoded or caller-owned payload placeholder.
    pub payload: Option<Payload>,
    /// Timeout deadline placeholder as Unix timestamp seconds.
    pub timeout: Option<i64>,
}

impl core::fmt::Debug for Pdu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pdu")
            .field("header", &self.header)
            .field("out", &self.out)
            .field("input", &self.input)
            .field("callback", &self.callback.as_ref().map(|_| "<callback>"))
            .field("compound", &self.compound)
            .field("next_compound", &self.next_compound)
            .field("prev_compound_mid", &self.prev_compound_mid)
            .field("payload", &self.payload)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Pdu {
    /// Creates a PDU skeleton for a command and optional completion callback.
    #[must_use]
    pub fn new(command: Command, callback: Option<CommandCallback>) -> Self {
        Self::from_parts(Smb2Header::for_command(command), IoVectors::new(), callback)
    }

    /// Creates a PDU skeleton from an already prepared header and outgoing vectors.
    #[must_use]
    pub fn from_parts(
        header: Smb2Header,
        mut out: IoVectors,
        callback: Option<CommandCallback>,
    ) -> Self {
        out.total_size = out.vectors.iter().map(IoVec::len).sum();
        Self {
            header,
            out,
            input: IoVectors::new(),
            callback,
            compound: false,
            next_compound: None,
            prev_compound_mid: 0,
            payload: None,
            timeout: None,
        }
    }

    /// Creates a payload-only PDU; queueing adds or updates the SMB2 header vector.
    #[must_use]
    pub fn from_payload(
        command: Command,
        payload: Vec<u8>,
        callback: Option<CommandCallback>,
    ) -> Self {
        Self::from_parts(
            Smb2Header::for_command(command),
            IoVectors {
                done: 0,
                total_size: payload.len(),
                vectors: vec![IoVec::new(payload)],
            },
            callback,
        )
    }

    /// Returns true when this PDU is marked as part of a compound command chain.
    #[must_use]
    pub const fn is_compound(&self) -> bool {
        self.compound
    }
}

/// Internal linked-list node for directory entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirentInternal {
    /// Next directory entry in the decoded list.
    pub next: Option<Box<DirentInternal>>,
    /// Public directory entry payload.
    pub dirent: DirectoryEntry,
}

/// Internal directory handle corresponding to `struct smb2dir`.
#[derive(Default)]
pub struct Directory {
    /// Optional completion callback used by async readdir operations.
    pub callback: Option<CommandCallback>,
    /// Optional callback-data cleanup hook.
    pub free_cb_data: Option<FreeCallback>,
    /// Opaque callback data retained as owned bytes.
    pub cb_data: Option<Payload>,
    /// File id for the open directory.
    pub file_id: FileId,
    /// Decoded entries retained for iteration.
    pub entries: Vec<DirectoryEntry>,
    /// Current entry index.
    pub index: usize,
}

impl core::fmt::Debug for Directory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Directory")
            .field("callback", &self.callback.as_ref().map(|_| "<callback>"))
            .field("cb_data", &self.cb_data)
            .field("file_id", &self.file_id)
            .field("entries", &self.entries)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl Directory {
    /// Returns the current entry, if any.
    #[must_use]
    pub fn current_entry(&self) -> Option<&DirectoryEntry> {
        self.entries.get(self.index)
    }

    /// Rewinds directory iteration to the first entry.
    pub const fn rewind(&mut self) {
        self.index = 0;
    }
}

/// Server ownership placeholder for contexts used by server-side code paths.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ServerRef {
    /// Opaque server identifier retained by the skeleton.
    pub id: Option<usize>,
}

/// Address resolution placeholder corresponding to `struct addrinfo` pointers.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AddrInfoRef {
    /// Resolved address text when available to Rust-side skeletons.
    pub address: Option<String>,
}

/// Private fields from `struct smb2_context` not present in the current Rust `Context` shape.
pub struct ContextPrivateFields {
    /// Active connected socket.
    pub fd: Option<Socket>,
    /// Owning server for server-side contexts.
    pub owning_server: Option<ServerRef>,
    /// Sockets currently being connected.
    pub connecting_fds: Vec<Socket>,
    /// Resolved addresses retained during connection setup.
    pub addrinfos: Vec<AddrInfoRef>,
    /// Index of the next address candidate.
    pub next_addrinfo: Option<usize>,
    /// Operation timeout in seconds.
    pub timeout: i32,
    /// Selected security provider.
    pub sec: SecurityMode,
    /// Negotiated or requested security mode flags.
    pub security_mode: u16,
    /// Negotiated capabilities bitset.
    pub capabilities: u32,
    /// Whether cached credentials may be used.
    pub use_cached_creds: bool,
    /// Requested negotiate version.
    pub version: PrivateNegotiateVersion,
    /// Server name.
    pub server: Option<String>,
    /// Share name.
    pub share: Option<String>,
    /// User name.
    pub user: Option<String>,
    /// Password stored as a C-compatible string for staged FFI compatibility.
    pub password: Option<CString>,
    /// Authentication domain.
    pub domain: Option<String>,
    /// Workstation name.
    pub workstation: Option<String>,
    /// NTLM client challenge bytes.
    pub client_challenge: [u8; 8],
    /// Caller-defined opaque data retained as an address-sized value.
    pub opaque: Option<usize>,
    /// Synchronous connection callback bookkeeping.
    pub connect_cb_data: SyncCallbackData,
    /// Client GUID bytes.
    pub client_guid: [u8; 16],
    /// Top tree-id stack index.
    pub tree_id_top: isize,
    /// Current tree-id stack index.
    pub tree_id_cur: isize,
    /// Next async id.
    pub async_id: u64,
    /// Session key bytes.
    pub session_key: Vec<u8>,
    /// Whether encryption is enabled.
    pub seal: bool,
    /// Whether signing is required.
    pub sign: bool,
    /// SMB2 signing key bytes.
    pub signing_key: [u8; SMB2_KEY_SIZE],
    /// SMB3 server-in key bytes.
    pub serverin_key: [u8; SMB2_KEY_SIZE],
    /// SMB3 server-out key bytes.
    pub serverout_key: [u8; SMB2_KEY_SIZE],
    /// SMB3 pre-authentication salt bytes.
    pub salt: [u8; SMB2_SALT_SIZE],
    /// Negotiated encryption cipher.
    pub cypher: u16,
    /// SMB3 pre-authentication hash bytes.
    pub preauthhash: [u8; SMB2_PREAUTH_HASH_SIZE],
    /// Received encrypted blob bytes.
    pub enc: Vec<u8>,
    /// Read position in `enc`.
    pub enc_pos: usize,
    /// Header scratch buffer.
    pub header_scratch: [u8; SMB2_HEADER_SIZE],
    /// Offset into the input vectors where the current payload starts.
    pub payload_offset: usize,
    /// Whether complex command payloads should be passed through undecoded.
    pub passthrough: bool,
    /// Oplock break counter for notification/response discrimination.
    pub oplock_break_count: i32,
    /// Last file id from a create reply for related requests.
    pub last_file_id: FileId,
    /// Whether multi-credit operations are supported by the server.
    pub supports_multi_credit: bool,
    /// Server maximum transact size.
    pub max_transact_size: u32,
    /// Server maximum read size.
    pub max_read_size: u32,
    /// Server maximum write size.
    pub max_write_size: u32,
    /// Negotiated dialect.
    pub dialect: u16,
    /// Last error string.
    pub error_string: String,
    /// Last NT error code.
    pub nterror: i32,
    /// Event mask requested by the transport layer.
    pub events: i32,
    /// DCERPC NDR flag.
    pub ndr: u8,
    /// DCERPC byte order setting.
    pub endianness: i32,
}

impl Default for ContextPrivateFields {
    fn default() -> Self {
        Self {
            fd: None,
            owning_server: None,
            connecting_fds: Vec::new(),
            addrinfos: Vec::new(),
            next_addrinfo: None,
            timeout: 0,
            sec: SecurityMode::default(),
            security_mode: 0,
            capabilities: 0,
            use_cached_creds: false,
            version: PrivateNegotiateVersion::default(),
            server: None,
            share: None,
            user: None,
            password: None,
            domain: None,
            workstation: None,
            client_challenge: [0; 8],
            opaque: None,
            connect_cb_data: SyncCallbackData::default(),
            client_guid: [0; 16],
            tree_id_top: -1,
            tree_id_cur: -1,
            async_id: 0,
            session_key: Vec::new(),
            seal: false,
            sign: false,
            signing_key: [0; SMB2_KEY_SIZE],
            serverin_key: [0; SMB2_KEY_SIZE],
            serverout_key: [0; SMB2_KEY_SIZE],
            salt: [0; SMB2_SALT_SIZE],
            cypher: 0,
            preauthhash: [0; SMB2_PREAUTH_HASH_SIZE],
            enc: Vec::new(),
            enc_pos: 0,
            header_scratch: [0; SMB2_HEADER_SIZE],
            payload_offset: 0,
            passthrough: false,
            oplock_break_count: 0,
            last_file_id: FileId::default(),
            supports_multi_credit: false,
            max_transact_size: 0,
            max_read_size: 0,
            max_write_size: 0,
            dialect: 0,
            error_string: String::new(),
            nterror: 0,
            events: 0,
            ndr: 0,
            endianness: 0,
        }
    }
}

impl core::fmt::Debug for ContextPrivateFields {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ContextPrivateFields")
            .field("fd", &self.fd)
            .field("owning_server", &self.owning_server)
            .field("connecting_fds", &self.connecting_fds)
            .field("timeout", &self.timeout)
            .field("sec", &self.sec)
            .field("capabilities", &self.capabilities)
            .field("version", &self.version)
            .field("server", &self.server)
            .field("share", &self.share)
            .field("user", &self.user)
            .field("domain", &self.domain)
            .field("workstation", &self.workstation)
            .field("opaque", &self.opaque)
            .field("tree_id_top", &self.tree_id_top)
            .field("tree_id_cur", &self.tree_id_cur)
            .field("async_id", &self.async_id)
            .field("seal", &self.seal)
            .field("sign", &self.sign)
            .field("enc", &self.enc)
            .field("enc_pos", &self.enc_pos)
            .field("payload_offset", &self.payload_offset)
            .field("passthrough", &self.passthrough)
            .field("oplock_break_count", &self.oplock_break_count)
            .field("last_file_id", &self.last_file_id)
            .field("supports_multi_credit", &self.supports_multi_credit)
            .field("max_transact_size", &self.max_transact_size)
            .field("max_read_size", &self.max_read_size)
            .field("max_write_size", &self.max_write_size)
            .field("dialect", &self.dialect)
            .field("error_string", &self.error_string)
            .field("nterror", &self.nterror)
            .field("events", &self.events)
            .field("ndr", &self.ndr)
            .field("endianness", &self.endianness)
            .finish_non_exhaustive()
    }
}

/// Internal context state corresponding to the currently migrated `struct smb2_context` skeleton.
#[derive(Debug)]
pub struct Context {
    /// Current receive state.
    pub recv_state: RecvState,
    /// Available credits.
    pub credits: i32,
    /// Next message id.
    pub message_id: u64,
    /// Negotiated session id.
    pub session_id: u64,
    /// Current tree id stack.
    pub tree_ids: Vec<u32>,
    /// Incoming vectors.
    pub input: IoVectors,
    /// Last decoded header.
    pub header: Smb2Header,
    /// Pending outgoing PDUs.
    pub outqueue: Vec<Pdu>,
    /// Waiting PDUs.
    pub waitqueue: Vec<Pdu>,
    /// Rust-owned private fields migrated from `struct smb2_context`.
    pub private: ContextPrivateFields,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            recv_state: RecvState::Spl,
            credits: 0,
            message_id: 0,
            session_id: 0,
            tree_ids: Vec::new(),
            input: IoVectors::new(),
            header: Smb2Header::default(),
            outqueue: Vec::new(),
            waitqueue: Vec::new(),
            private: ContextPrivateFields::default(),
        }
    }
}

impl Context {
    /// Creates an empty internal context skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true when this context is owned by a server.
    #[must_use]
    pub const fn is_server(&self) -> bool {
        self.private.owning_server.is_some()
    }

    /// Releases socket, queue, vector, and private owned state while keeping the context reusable.
    pub fn close_context(&mut self) {
        self.private.fd = None;
        self.private.connecting_fds.clear();
        self.private.addrinfos.clear();
        self.private.next_addrinfo = None;
        self.private.enc.clear();
        self.private.enc_pos = 0;
        self.input.clear();
        self.outqueue.clear();
        self.waitqueue.clear();
        self.private.events = 0;
    }

    /// Releases all Rust-owned lifecycle state for this private context.
    pub fn destroy_context(&mut self) {
        self.close_context();
        self.private = ContextPrivateFields::default();
        self.recv_state = RecvState::Spl;
        self.credits = 0;
        self.message_id = 0;
        self.session_id = 0;
        self.tree_ids.clear();
        self.header = Smb2Header::default();
    }

    /// Stores a bounded error string and clears NT status when the message is empty.
    pub fn set_error(&mut self, error_string: impl Into<String>) {
        let error_string = truncate_error_string(error_string.into());
        if error_string.is_empty() {
            self.private.nterror = 0;
        }
        self.private.error_string = error_string;
    }

    /// Returns the last private-context error string.
    #[must_use]
    pub fn error(&self) -> &str {
        &self.private.error_string
    }

    /// Returns the current tree id or [`DEAD_TREE_ID`] when no tree id is active.
    #[must_use]
    pub fn current_tree_id(&self) -> u32 {
        match self.tree_ids.first().copied() {
            Some(tree_id) => tree_id,
            None => DEAD_TREE_ID,
        }
    }

    /// Records an NT error on the header status field and stores a bounded error code surrogate.
    pub fn set_nterror(&mut self, nterror: i32, error_string: impl Into<String>) {
        self.header.status = nterror as u32;
        self.private.nterror = nterror;
        self.private.error_string = truncate_error_string(error_string.into());
    }

    /// Returns the last private-context NT status.
    #[must_use]
    pub const fn nterror(&self) -> i32 {
        self.private.nterror
    }

    /// Closes and forgets sockets that are still in the connecting set.
    pub const fn close_connecting_fds(&mut self) {}

    /// Sets the operation timeout in seconds.
    pub const fn set_timeout(&mut self, timeout: i32) {
        self.private.timeout = timeout;
    }

    /// Returns the configured operation timeout in seconds.
    #[must_use]
    pub const fn timeout(&self) -> i32 {
        self.private.timeout
    }

    /// Sets the server name.
    pub fn set_server(&mut self, server: Option<&str>) {
        self.private.server = server.map(str::to_owned);
    }

    /// Returns the server name.
    #[must_use]
    pub fn server(&self) -> Option<&str> {
        self.private.server.as_deref()
    }

    /// Sets the share name.
    pub fn set_share(&mut self, share: Option<&str>) {
        self.private.share = share.map(str::to_owned);
    }

    /// Returns the share name.
    #[must_use]
    pub fn share(&self) -> Option<&str> {
        self.private.share.as_deref()
    }

    /// Sets the authentication user.
    pub fn set_user(&mut self, user: Option<&str>) {
        self.private.user = user.map(str::to_owned);
    }

    /// Returns the authentication user.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.private.user.as_deref()
    }

    /// Sets the authentication domain.
    pub fn set_domain(&mut self, domain: Option<&str>) {
        self.private.domain = domain.map(str::to_owned);
    }

    /// Returns the authentication domain.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.private.domain.as_deref()
    }

    /// Sets the authentication workstation.
    pub fn set_workstation(&mut self, workstation: Option<&str>) {
        self.private.workstation = workstation.map(str::to_owned);
    }

    /// Returns the authentication workstation.
    #[must_use]
    pub fn workstation(&self) -> Option<&str> {
        self.private.workstation.as_deref()
    }

    /// Sets the password as owned C-compatible state for staged FFI compatibility.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateError::InteriorNul`] when `password` contains an interior NUL byte.
    pub fn set_password(&mut self, password: Option<&str>) -> PrivateResult<()> {
        self.private.password = match password {
            Some(password) => Some(CString::new(password).map_err(|_| PrivateError::InteriorNul)?),
            None => None,
        };
        Ok(())
    }

    /// Returns the authentication password when configured.
    #[must_use]
    pub fn password(&self) -> Option<&str> {
        self.private
            .password
            .as_ref()
            .and_then(|password| password.to_str().ok())
    }

    /// Returns true when password state is owned by this context.
    #[must_use]
    pub fn has_password(&self) -> bool {
        self.private.password.is_some()
    }

    /// Sets caller-defined opaque data.
    pub const fn set_opaque(&mut self, opaque: Option<usize>) {
        self.private.opaque = opaque;
    }

    /// Returns caller-defined opaque data.
    #[must_use]
    pub const fn opaque(&self) -> Option<usize> {
        self.private.opaque
    }

    /// Transfers credential ownership into another context.
    ///
    /// The password is moved while identity fields are cloned, matching legacy
    /// delegation where password ownership leaves the source context.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateError::NoCredentials`] when no credential fields are configured.
    pub fn delegate_credentials(&mut self, out: &mut Context) -> PrivateResult<()> {
        let has_credentials = self.private.password.is_some()
            || self.private.user.is_some()
            || self.private.domain.is_some();
        if !has_credentials {
            self.set_error("No credentials to delegate");
            return Err(PrivateError::NoCredentials);
        }
        out.private.password = self.private.password.take();
        out.private.user = self.private.user.clone();
        out.private.domain = self.private.domain.clone();
        out.private.workstation = self.private.workstation.clone();
        out.private.sec = self.private.sec;
        out.private.use_cached_creds = self.private.use_cached_creds;
        Ok(())
    }

    /// Pushes a tree id onto the current tree-id stack.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateError::TooManyTreeIds`] when the legacy nesting limit would be exceeded.
    pub fn connect_tree_id(&mut self, tree_id: u32) -> PrivateResult<()> {
        if self.tree_ids.len() >= SMB2_MAX_TREE_NESTING {
            return Err(PrivateError::TooManyTreeIds);
        }
        self.tree_ids.insert(0, tree_id);
        Ok(())
    }

    /// Removes a tree id from the current tree-id stack when present.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateError::NoCurrentTreeId`] when no matching active tree id exists.
    pub fn disconnect_tree_id(&mut self, tree_id: u32) -> PrivateResult<()> {
        let Some(index) = self
            .tree_ids
            .iter()
            .position(|candidate| *candidate == tree_id)
        else {
            return Err(PrivateError::NoCurrentTreeId);
        };
        self.tree_ids.remove(index);
        Ok(())
    }

    /// Adds a PDU to the outgoing queue.
    pub fn push_outqueue(&mut self, pdu: Pdu) {
        self.outqueue.push(pdu);
    }

    /// Adds a PDU to the wait queue.
    pub fn push_waitqueue(&mut self, pdu: Pdu) {
        self.waitqueue.push(pdu);
    }

    /// Finds a PDU currently waiting for a reply by message id.
    #[must_use]
    pub fn find_waiting_pdu(&self, message_id: u64) -> Option<&Pdu> {
        self.waitqueue
            .iter()
            .find(|pdu| pdu.header.message_id == message_id)
    }

    /// Removes matching PDUs from both queues.
    pub fn remove_queued_pdu(&mut self, message_id: u64) {
        self.outqueue
            .retain(|queued| queued.header.message_id != message_id);
        self.waitqueue
            .retain(|queued| queued.header.message_id != message_id);
    }
}

/// Truncates an error string to the C `MAX_ERROR_SIZE` storage size.
#[must_use]
pub fn truncate_error_string(mut error_string: String) -> String {
    if error_string.len() <= MAX_ERROR_SIZE {
        return error_string;
    }
    let mut boundary = MAX_ERROR_SIZE;
    while !error_string.is_char_boundary(boundary) {
        boundary -= 1;
    }
    error_string.truncate(boundary);
    error_string
}

/// Adds an IO vector to a vector list, mirroring `smb2_add_iovector` ownership tracking.
///
/// # Errors
///
/// Returns [`PrivateError::TooManyVectors`] when the vector list is full.
pub fn smb2_add_iovector(vectors: &mut IoVectors, buf: Vec<u8>) -> PrivateResult<&mut IoVec> {
    vectors.add_iovector(IoVec::new(buf))
}

/// Adds an empty padding vector needed to align the vector list to a 64-bit boundary.
///
/// # Errors
///
/// Returns [`PrivateError::TooManyVectors`] when adding the padding vector would exceed the limit.
pub fn smb2_pad_to_64bit(vectors: &mut IoVectors) -> PrivateResult<usize> {
    let padded_len = pad_to_64bit_len(vectors.total_size);
    let pad_len = padded_len.saturating_sub(vectors.total_size);
    if pad_len != 0 {
        vectors.add_iovector(IoVec::new(vec![0; pad_len]))?;
    }
    Ok(pad_len)
}

/// Allocates a PDU skeleton for the supplied command.
#[must_use]
pub fn smb2_allocate_private_pdu(command: Command, callback: Option<CommandCallback>) -> Pdu {
    Pdu::new(command, callback)
}

/// Finds a waiting PDU by message id.
#[must_use]
pub fn smb2_find_pdu(context: &Context, message_id: u64) -> Option<&Pdu> {
    context.find_waiting_pdu(message_id)
}

/// Frees all IO vectors tracked by a vector list.
pub fn smb2_free_iovector(vectors: &mut IoVectors) {
    vectors.clear();
}

/// Records an oplock or lease break notification in the context skeleton.
pub fn smb2_oplock_break_notify(context: &mut Context, status: i32) {
    context.header.status = status as u32;
}

/// Decodes a header from an IO vector.
///
/// # Errors
///
/// Returns [`PrivateError::BufferTooShort`] when the vector does not contain a full SMB2 header.
pub fn smb2_decode_header(iov: &IoVec) -> PrivateResult<Smb2Header> {
    crate::lib::pdu::smb2_decode_header_bytes(&iov.buf).map_err(PrivateError::from)
}

/// Encodes a header into an IO vector.
///
/// # Errors
///
/// Returns [`PrivateError::BufferTooShort`] when the vector cannot hold a full SMB2 header.
pub fn smb2_encode_header(iov: &mut IoVec, header: &Smb2Header) -> PrivateResult<()> {
    crate::lib::pdu::smb2_encode_header_bytes(&mut iov.buf, header).map_err(PrivateError::from)
}

/// Calculates an SMB2 signature placeholder.
///
/// # Errors
///
/// Returns [`PrivateError::ProtocolLogicUnavailable`] until signing logic is ported.
pub fn smb2_calc_signature(
    _context: &Context,
    _iov: &[IoVec],
) -> PrivateResult<[u8; SMB2_SIGNATURE_SIZE]> {
    Err(PrivateError::ProtocolLogicUnavailable)
}

/// Writes a `u8` into an IO vector at `offset`.
///
/// # Errors
///
/// Returns [`PrivateError::BufferTooShort`] when the offset is outside the buffer.
pub fn smb2_set_uint8(iov: &mut IoVec, offset: usize, value: u8) -> PrivateResult<()> {
    let Some(slot) = iov.buf.get_mut(offset) else {
        return Err(PrivateError::BufferTooShort);
    };
    *slot = value;
    Ok(())
}

/// Writes a little-endian `u16` into an IO vector.
///
/// # Errors
///
/// Returns [`PrivateError::BufferTooShort`] when the requested range is outside the buffer.
pub fn smb2_set_uint16(iov: &mut IoVec, offset: usize, value: u16) -> PrivateResult<()> {
    write_bytes(iov, offset, &value.to_le_bytes())
}

/// Writes a little-endian `u32` into an IO vector.
///
/// # Errors
///
/// Returns [`PrivateError::BufferTooShort`] when the requested range is outside the buffer.
pub fn smb2_set_uint32(iov: &mut IoVec, offset: usize, value: u32) -> PrivateResult<()> {
    write_bytes(iov, offset, &value.to_le_bytes())
}

/// Writes a little-endian `u64` into an IO vector.
///
/// # Errors
///
/// Returns [`PrivateError::BufferTooShort`] when the requested range is outside the buffer.
pub fn smb2_set_uint64(iov: &mut IoVec, offset: usize, value: u64) -> PrivateResult<()> {
    write_bytes(iov, offset, &value.to_le_bytes())
}

/// Reads a `u8` from an IO vector.
///
/// # Errors
///
/// Returns [`PrivateError::BufferTooShort`] when the offset is outside the buffer.
pub fn smb2_get_uint8(iov: &IoVec, offset: usize) -> PrivateResult<u8> {
    iov.buf
        .get(offset)
        .copied()
        .ok_or(PrivateError::BufferTooShort)
}

/// Reads a little-endian `u16` from an IO vector.
///
/// # Errors
///
/// Returns [`PrivateError::BufferTooShort`] when the requested range is outside the buffer.
pub fn smb2_get_uint16(iov: &IoVec, offset: usize) -> PrivateResult<u16> {
    read_array::<2>(iov, offset).map(u16::from_le_bytes)
}

/// Reads a little-endian `u32` from an IO vector.
///
/// # Errors
///
/// Returns [`PrivateError::BufferTooShort`] when the requested range is outside the buffer.
pub fn smb2_get_uint32(iov: &IoVec, offset: usize) -> PrivateResult<u32> {
    read_array::<4>(iov, offset).map(u32::from_le_bytes)
}

/// Reads a little-endian `u64` from an IO vector.
///
/// # Errors
///
/// Returns [`PrivateError::BufferTooShort`] when the requested range is outside the buffer.
pub fn smb2_get_uint64(iov: &IoVec, offset: usize) -> PrivateResult<u64> {
    read_array::<8>(iov, offset).map(u64::from_le_bytes)
}

/// Returns the fixed payload size currently known for a command.
///
/// # Errors
///
/// Returns [`PrivateError::UnknownFixedSize`] for commands whose fixed size has not been mapped here.
pub const fn smb2_get_fixed_size(command: Command) -> PrivateResult<usize> {
    match command {
        Command::Negotiate => Ok(SMB2_NEGOTIATE_REPLY_SIZE as usize),
        Command::SessionSetup => Ok(SMB2_SESSION_SETUP_REPLY_SIZE as usize),
        Command::Logoff => Ok(SMB2_LOGOFF_REPLY_SIZE as usize),
        Command::TreeConnect => Ok(SMB2_TREE_CONNECT_REPLY_SIZE as usize),
        Command::TreeDisconnect => Ok(SMB2_TREE_DISCONNECT_REPLY_SIZE as usize),
        Command::Create => Ok(SMB2_CREATE_REPLY_SIZE as usize),
        Command::Close => Ok(SMB2_CLOSE_REPLY_SIZE as usize),
        Command::Flush => Ok(SMB2_FLUSH_REPLY_SIZE as usize),
        Command::Read => Ok(SMB2_READ_REPLY_SIZE as usize),
        Command::Write => Ok(SMB2_WRITE_REPLY_SIZE as usize),
        Command::Lock => Ok(SMB2_LOCK_REPLY_SIZE as usize),
        Command::Ioctl => Ok(SMB2_IOCTL_REPLY_SIZE as usize),
        Command::Echo => Ok(SMB2_ECHO_REPLY_SIZE as usize),
        Command::QueryDirectory => Ok(SMB2_QUERY_DIRECTORY_REPLY_SIZE as usize),
        Command::ChangeNotify => Ok(SMB2_CHANGE_NOTIFY_REPLY_SIZE as usize),
        Command::QueryInfo => Ok(SMB2_QUERY_INFO_REPLY_SIZE as usize),
        Command::SetInfo => Ok(SMB2_SET_INFO_REPLY_SIZE as usize),
        Command::OplockBreak => Ok(core::mem::size_of::<u16>()),
        Command::Cancel | Command::Smb1Negotiate => Err(PrivateError::UnknownFixedSize),
    }
}

/// Returns the fixed request payload size known for a command.
pub const fn smb2_get_fixed_request_size(command: Command) -> PrivateResult<usize> {
    match command {
        Command::Negotiate => Ok(SMB2_NEGOTIATE_REQUEST_SIZE as usize),
        Command::SessionSetup => Ok(SMB2_SESSION_SETUP_REQUEST_SIZE as usize),
        Command::Logoff => Ok(SMB2_LOGOFF_REQUEST_SIZE as usize),
        Command::TreeConnect => Ok(SMB2_TREE_CONNECT_REQUEST_SIZE as usize),
        Command::TreeDisconnect => Ok(SMB2_TREE_DISCONNECT_REQUEST_SIZE as usize),
        Command::Create => Ok(SMB2_CREATE_REQUEST_SIZE as usize),
        Command::Close => Ok(SMB2_CLOSE_REQUEST_SIZE as usize),
        Command::Flush => Ok(SMB2_FLUSH_REQUEST_SIZE as usize),
        Command::Read => Ok(SMB2_READ_REQUEST_SIZE as usize),
        Command::Write => Ok(SMB2_WRITE_REQUEST_SIZE as usize),
        Command::Lock => Ok(SMB2_LOCK_REQUEST_SIZE as usize),
        Command::Ioctl => Ok(SMB2_IOCTL_REQUEST_SIZE as usize),
        Command::Cancel => Ok(SMB2_CANCEL_REQUEST_SIZE as usize),
        Command::Echo => Ok(SMB2_ECHO_REQUEST_SIZE as usize),
        Command::QueryDirectory => Ok(SMB2_QUERY_DIRECTORY_REQUEST_SIZE as usize),
        Command::ChangeNotify => Ok(SMB2_CHANGE_NOTIFY_REQUEST_SIZE as usize),
        Command::QueryInfo => Ok(SMB2_QUERY_INFO_REQUEST_SIZE as usize),
        Command::SetInfo => Ok(SMB2_SET_INFO_REQUEST_SIZE as usize),
        Command::OplockBreak => Ok(core::mem::size_of::<u16>()),
        Command::Smb1Negotiate => Err(PrivateError::UnknownFixedSize),
    }
}

/// Returns the fixed error reply payload size with the legacy even-size mask applied.
pub const fn smb2_get_fixed_error_reply_size() -> usize {
    (SMB2_ERROR_REPLY_SIZE & 0xfffe) as usize
}

/// Process the fixed part of a reply payload.
///
/// # Errors
///
/// Returns [`PrivateError::ProtocolLogicUnavailable`] until command-specific unpackers are ported.
pub fn smb2_process_payload_fixed(_context: &mut Context, _pdu: &mut Pdu) -> PrivateResult<()> {
    Err(PrivateError::ProtocolLogicUnavailable)
}

/// Process the variable part of a reply payload.
///
/// # Errors
///
/// Returns [`PrivateError::ProtocolLogicUnavailable`] until command-specific unpackers are ported.
pub fn smb2_process_payload_variable(_context: &mut Context, _pdu: &mut Pdu) -> PrivateResult<()> {
    Err(PrivateError::ProtocolLogicUnavailable)
}

macro_rules! process_stub {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = "Command-specific packer or unpacker skeleton matching the private C interface."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "Returns [`PrivateError::ProtocolLogicUnavailable`] until the corresponding protocol logic is ported."]
            pub fn $name(_context: &mut Context, _pdu: &mut Pdu) -> PrivateResult<()> {
                Err(PrivateError::ProtocolLogicUnavailable)
            }
        )+
    };
}

process_stub!(
    smb2_process_error_fixed,
    smb2_process_error_variable,
    smb2_process_negotiate_fixed,
    smb2_process_negotiate_variable,
    smb2_process_negotiate_request_fixed,
    smb2_process_negotiate_request_variable,
    smb2_process_session_setup_fixed,
    smb2_process_session_setup_variable,
    smb2_process_session_setup_request_fixed,
    smb2_process_session_setup_request_variable,
    smb2_process_tree_connect_fixed,
    smb2_process_tree_connect_request_fixed,
    smb2_process_tree_connect_request_variable,
    smb2_process_create_fixed,
    smb2_process_create_variable,
    smb2_process_create_request_fixed,
    smb2_process_create_request_variable,
    smb2_process_query_directory_fixed,
    smb2_process_query_directory_variable,
    smb2_process_query_directory_request_fixed,
    smb2_process_query_directory_request_variable,
    smb2_process_change_notify_fixed,
    smb2_process_change_notify_variable,
    smb2_process_change_notify_request_fixed,
    smb2_process_query_info_fixed,
    smb2_process_query_info_variable,
    smb2_process_query_info_request_fixed,
    smb2_process_query_info_request_variable,
    smb2_process_close_fixed,
    smb2_process_close_request_fixed,
    smb2_process_set_info_fixed,
    smb2_process_set_info_request_fixed,
    smb2_process_set_info_request_variable,
    smb2_process_tree_disconnect_fixed,
    smb2_process_tree_disconnect_request_fixed,
    smb2_process_logoff_fixed,
    smb2_process_logoff_request_fixed,
    smb2_process_lock_fixed,
    smb2_process_lock_request_fixed,
    smb2_process_lock_request_variable,
    smb2_process_oplock_break_fixed,
    smb2_process_oplock_break_variable,
    smb2_process_oplock_break_request_fixed,
    smb2_process_oplock_break_request_variable,
    smb2_process_echo_fixed,
    smb2_process_echo_request_fixed,
    smb2_process_flush_fixed,
    smb2_process_flush_request_fixed,
    smb2_process_read_fixed,
    smb2_process_read_variable,
    smb2_process_read_request_fixed,
    smb2_process_read_request_variable,
    smb2_process_write_fixed,
    smb2_process_write_request_fixed,
    smb2_process_write_request_variable,
    smb2_process_ioctl_fixed,
    smb2_process_ioctl_variable,
    smb2_process_ioctl_request_fixed,
    smb2_process_ioctl_request_variable,
);

/// Decoded file information variants used by private decode skeletons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileInfoPayload {
    /// Basic file metadata placeholder.
    Basic,
    /// Standard file metadata placeholder.
    Standard,
    /// Stream information placeholder.
    Stream,
    /// Position information placeholder.
    Position,
    /// Aggregated file information placeholder.
    All,
    /// Network-open information placeholder.
    NetworkOpen,
    /// Name information placeholder.
    Name,
}

/// Decoded filesystem information variants used by private decode skeletons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsInfoPayload {
    /// Volume information placeholder.
    Volume,
    /// Size information placeholder.
    Size,
    /// Device information placeholder.
    Device,
    /// Attribute information placeholder.
    Attribute,
    /// Control information placeholder.
    Control,
    /// Full-size information placeholder.
    FullSize,
    /// Object-id information placeholder.
    ObjectId,
    /// Sector-size information placeholder.
    SectorSize,
}

macro_rules! data_stub {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = "Data encoder or decoder skeleton matching the private C interface."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "Returns [`PrivateError::ProtocolLogicUnavailable`] until the concrete data coder is wired here."]
            pub fn $name(
                _context: &mut Context,
                _memctx: Option<Payload>,
                _vec: &IoVec,
            ) -> PrivateResult<()> {
                Err(PrivateError::ProtocolLogicUnavailable)
            }
        )+
    };
}

data_stub!(
    smb2_decode_file_basic_info,
    smb2_encode_file_basic_info,
    smb2_decode_file_standard_info,
    smb2_encode_file_standard_info,
    smb2_decode_file_stream_info,
    smb2_encode_file_stream_info,
    smb2_decode_file_position_info,
    smb2_encode_file_position_info,
    smb2_decode_file_all_info,
    smb2_encode_file_all_info,
    smb2_decode_file_network_open_info,
    smb2_encode_file_network_open_info,
    smb2_decode_file_normalized_name_info,
    smb2_encode_file_normalized_name_info,
    smb2_decode_security_descriptor,
    smb2_decode_file_fs_volume_info,
    smb2_encode_file_fs_volume_info,
    smb2_decode_file_fs_size_info,
    smb2_encode_file_fs_size_info,
    smb2_decode_file_fs_device_info,
    smb2_encode_file_fs_device_info,
    smb2_decode_file_fs_attribute_info,
    smb2_encode_file_fs_attribute_info,
    smb2_decode_file_fs_control_info,
    smb2_encode_file_fs_control_info,
    smb2_decode_file_fs_full_size_info,
    smb2_encode_file_fs_full_size_info,
    smb2_decode_file_fs_object_id_info,
    smb2_encode_file_fs_object_id_info,
    smb2_decode_file_fs_sector_size_info,
    smb2_encode_file_fs_sector_size_info,
    smb2_decode_reparse_data_buffer,
);

/// Reads pending data from the context transport.
///
/// # Errors
///
/// Returns [`PrivateError::ProtocolLogicUnavailable`] until transport receive logic is ported.
pub fn smb2_read_from_buf(_context: &mut Context) -> PrivateResult<usize> {
    Err(PrivateError::ProtocolLogicUnavailable)
}

/// Updates the context event mask for a socket.
pub fn smb2_change_events(_context: &mut Context, _fd: Socket, _events: i32) {}

/// Expires pending PDUs according to their timeout metadata.
pub fn smb2_timeout_pdus(context: &mut Context) {
    context.waitqueue.retain(|pdu| pdu.timeout.is_some());
}

/// Writes queued data to the context socket.
///
/// # Errors
///
/// Returns [`PrivateError::ProtocolLogicUnavailable`] until transport send logic is ported.
pub fn smb2_write_to_socket(_context: &mut Context) -> PrivateResult<usize> {
    Err(PrivateError::ProtocolLogicUnavailable)
}

/// Sets a DCERPC `u8` field in an IO vector and advances `offset` on success.
///
/// # Errors
///
/// Returns [`PrivateError::BufferTooShort`] when the offset is outside the buffer.
pub fn dcerpc_set_uint8(iov: &mut IoVec, offset: &mut usize, value: u8) -> PrivateResult<()> {
    smb2_set_uint8(iov, *offset, value)?;
    *offset = offset.saturating_add(1);
    Ok(())
}

/// Direction placeholder for a DCERPC PDU.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DceRpcDirection {
    /// Request PDU direction.
    #[default]
    Request,
    /// Response PDU direction.
    Response,
}

/// DCERPC PDU placeholder used by private interfaces.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DceRpcPdu {
    /// Direction inferred from the PDU header.
    pub direction: DceRpcDirection,
}

/// Returns the direction for a DCERPC PDU skeleton.
#[must_use]
pub const fn dcerpc_pdu_direction(pdu: &DceRpcPdu) -> DceRpcDirection {
    pdu.direction
}

/// Aligns a DCERPC offset to a 4-byte boundary.
#[must_use]
pub const fn dcerpc_align_3264(offset: usize) -> usize {
    pad_to_32bit(offset)
}

/// Connection setup data placeholder owned by `libsmb2.c` in the C implementation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConnectData {
    /// Server name retained during connection setup.
    pub server: Option<String>,
    /// Share name retained during connection setup.
    pub share: Option<String>,
}

/// Frees connection setup data in the Rust-owned skeleton.
pub fn free_c_data(_context: &mut Context, connect_data: &mut ConnectData) {
    connect_data.server = None;
    connect_data.share = None;
}

/// Creates an empty stat value suitable for placeholder directory entries.
#[must_use]
pub const fn empty_stat() -> Stat {
    Stat {
        file_type: FileType::Unknown(0),
        nlink: 0,
        ino: 0,
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

fn write_bytes(iov: &mut IoVec, offset: usize, bytes: &[u8]) -> PrivateResult<()> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(PrivateError::BufferTooShort)?;
    let Some(dst) = iov.buf.get_mut(offset..end) else {
        return Err(PrivateError::BufferTooShort);
    };
    dst.copy_from_slice(bytes);
    Ok(())
}

fn read_array<const N: usize>(iov: &IoVec, offset: usize) -> PrivateResult<[u8; N]> {
    read_fixed::<N>(&iov.buf, offset)
}

fn read_fixed<const N: usize>(bytes: &[u8], offset: usize) -> PrivateResult<[u8; N]> {
    let end = offset.checked_add(N).ok_or(PrivateError::BufferTooShort)?;
    let Some(slice) = bytes.get(offset..end) else {
        return Err(PrivateError::BufferTooShort);
    };
    let mut out = [0; N];
    out.copy_from_slice(slice);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{Context, IoVec, IoVectors, PrivateError};

    #[test]
    fn iovector_add_rejects_size_overflow_without_push() {
        let mut vectors = IoVectors::new();
        vectors.total_size = usize::MAX;

        assert_eq!(
            vectors.add_iovector(IoVec::new(vec![0])).map(|_| ()),
            Err(PrivateError::VectorSizeOverflow)
        );
        assert_eq!(vectors.niov(), 0);
        assert_eq!(vectors.total_size, usize::MAX);
    }

    #[test]
    fn context_delegate_credentials_moves_password() {
        let mut source = Context::new();
        source.set_user(Some("alice"));
        source.set_domain(Some("DOMAIN"));
        source
            .set_password(Some("secret"))
            .expect("password has no interior NUL");
        let mut out = Context::new();

        source
            .delegate_credentials(&mut out)
            .expect("credentials are present");

        assert_eq!(source.user(), Some("alice"));
        assert!(!source.has_password());
        assert_eq!(out.user(), Some("alice"));
        assert_eq!(out.domain(), Some("DOMAIN"));
        assert_eq!(out.password(), Some("secret"));
    }

    #[test]
    fn context_delegate_credentials_reports_missing_state() {
        let mut source = Context::new();
        let mut out = Context::new();

        assert_eq!(
            source.delegate_credentials(&mut out),
            Err(PrivateError::NoCredentials)
        );
        assert_eq!(source.error(), "No credentials to delegate");
    }
}
