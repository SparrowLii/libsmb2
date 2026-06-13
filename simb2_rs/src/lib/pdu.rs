//! PDU allocation, queueing, packing, and unpacking migrated from `lib/pdu.c`.

use crate::include::libsmb2_private::{
    Context, IoVec, IoVectors, Smb2Header, SMB2_HEADER_SIZE, SMB2_MAX_VECTORS,
};
use crate::include::smb2::libsmb2::CommandCallback;
use crate::include::smb2::smb2::{
    SMB2_CANCEL_REQUEST_SIZE, SMB2_CHANGE_NOTIFY_REPLY_SIZE, SMB2_CHANGE_NOTIFY_REQUEST_SIZE,
    SMB2_CLOSE_REPLY_SIZE, SMB2_CLOSE_REQUEST_SIZE, SMB2_CREATE_REPLY_SIZE,
    SMB2_CREATE_REQUEST_SIZE, SMB2_ECHO_REPLY_SIZE, SMB2_ECHO_REQUEST_SIZE, SMB2_ERROR_REPLY_SIZE,
    SMB2_FLUSH_REPLY_SIZE, SMB2_FLUSH_REQUEST_SIZE, SMB2_IOCTL_REPLY_SIZE, SMB2_IOCTL_REQUEST_SIZE,
    SMB2_LOCK_REPLY_SIZE, SMB2_LOCK_REQUEST_SIZE, SMB2_LOGOFF_REPLY_SIZE, SMB2_LOGOFF_REQUEST_SIZE,
    SMB2_NEGOTIATE_REPLY_SIZE, SMB2_NEGOTIATE_REQUEST_SIZE, SMB2_QUERY_DIRECTORY_REPLY_SIZE,
    SMB2_QUERY_DIRECTORY_REQUEST_SIZE, SMB2_QUERY_INFO_REPLY_SIZE, SMB2_QUERY_INFO_REQUEST_SIZE,
    SMB2_READ_REPLY_SIZE, SMB2_READ_REQUEST_SIZE, SMB2_SESSION_SETUP_REPLY_SIZE,
    SMB2_SESSION_SETUP_REQUEST_SIZE, SMB2_SET_INFO_REPLY_SIZE, SMB2_SET_INFO_REQUEST_SIZE,
    SMB2_TREE_CONNECT_REPLY_SIZE, SMB2_TREE_CONNECT_REQUEST_SIZE, SMB2_TREE_DISCONNECT_REPLY_SIZE,
    SMB2_TREE_DISCONNECT_REQUEST_SIZE, SMB2_WRITE_REPLY_SIZE, SMB2_WRITE_REQUEST_SIZE,
};
use crate::lib::smb2_cmd_echo::{smb2_process_echo_fixed, smb2_process_echo_request_fixed};
use crate::lib::smb2_cmd_flush::{smb2_process_flush_fixed, smb2_process_flush_request_fixed};
use crate::lib::smb2_cmd_logoff::{smb2_process_logoff_fixed, smb2_process_logoff_request_fixed};

pub use crate::include::libsmb2_private::Pdu;

/// SMB2 protocol signature used in normal SMB2 headers.
pub const SMB2_PROTOCOL_ID: [u8; 4] = [0xfe, b'S', b'M', b'B'];

/// SMB1 protocol signature accepted only for SMB1 negotiate requests.
pub const SMB1_PROTOCOL_ID: [u8; 4] = [0xff, b'S', b'M', b'B'];

/// SMB1 negotiate command byte used by the legacy decoder exception.
pub const SMB1_NEGOTIATE: u8 = 0x72;

/// SMB2 header structure size.
pub const SMB2_HEADER_STRUCT_SIZE: u16 = SMB2_HEADER_SIZE as u16;

/// Placeholder for the C `MAX_CREDITS` credit target.
pub const MAX_CREDITS: i32 = 1024;

/// Maximum tree-id nesting tracked by the legacy context.
pub const SMB2_MAX_TREE_NESTING: usize = 32;

/// Header flag indicating an async SMB2 command.
pub const SMB2_FLAGS_ASYNC_COMMAND: u32 = 0x0000_0002;

/// Header flag indicating a server-to-redirector reply.
pub const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;

/// Header flag applied to related compound operations.
pub const SMB2_FLAGS_RELATED_OPERATIONS: u32 = 0x0000_0004;

/// NT status severity mask used by reply error classification.
pub const SMB2_STATUS_SEVERITY_MASK: u32 = 0xc000_0000;

/// NT status severity value for errors.
pub const SMB2_STATUS_SEVERITY_ERROR: u32 = 0xc000_0000;

/// NT status severity value for warnings.
pub const SMB2_STATUS_SEVERITY_WARNING: u32 = 0x8000_0000;

/// Status that continues session setup processing rather than ending as error.
pub const SMB2_STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xc000_0016;

/// Warning status treated as an error by the legacy client path.
pub const SMB2_STATUS_STOPPED_ON_SYMLINK: u32 = 0x8000_002d;

/// Timeout status used when queued PDUs expire.
pub const SMB2_STATUS_IO_TIMEOUT: u32 = 0x0020_0005;

/// SMB2 command identifiers mirrored from the C switch tables in `pdu.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Smb2Command {
    /// SMB2 NEGOTIATE command.
    Negotiate = 0x0000,
    /// SMB2 SESSION_SETUP command.
    SessionSetup = 0x0001,
    /// SMB2 LOGOFF command.
    Logoff = 0x0002,
    /// SMB2 TREE_CONNECT command.
    TreeConnect = 0x0003,
    /// SMB2 TREE_DISCONNECT command.
    TreeDisconnect = 0x0004,
    /// SMB2 CREATE command.
    Create = 0x0005,
    /// SMB2 CLOSE command.
    Close = 0x0006,
    /// SMB2 FLUSH command.
    Flush = 0x0007,
    /// SMB2 READ command.
    Read = 0x0008,
    /// SMB2 WRITE command.
    Write = 0x0009,
    /// SMB2 LOCK command.
    Lock = 0x000a,
    /// SMB2 IOCTL command.
    Ioctl = 0x000b,
    /// SMB2 CANCEL command.
    Cancel = 0x000c,
    /// SMB2 ECHO command.
    Echo = 0x000d,
    /// SMB2 QUERY_DIRECTORY command.
    QueryDirectory = 0x000e,
    /// SMB2 CHANGE_NOTIFY command.
    ChangeNotify = 0x000f,
    /// SMB2 QUERY_INFO command.
    QueryInfo = 0x0010,
    /// SMB2 SET_INFO command.
    SetInfo = 0x0011,
    /// SMB2 OPLOCK_BREAK command.
    OplockBreak = 0x0012,
}

impl Smb2Command {
    /// Converts a raw SMB2 command id into a known command.
    pub fn from_raw(command: u16) -> Option<Self> {
        match command {
            0x0000 => Some(Self::Negotiate),
            0x0001 => Some(Self::SessionSetup),
            0x0002 => Some(Self::Logoff),
            0x0003 => Some(Self::TreeConnect),
            0x0004 => Some(Self::TreeDisconnect),
            0x0005 => Some(Self::Create),
            0x0006 => Some(Self::Close),
            0x0007 => Some(Self::Flush),
            0x0008 => Some(Self::Read),
            0x0009 => Some(Self::Write),
            0x000a => Some(Self::Lock),
            0x000b => Some(Self::Ioctl),
            0x000c => Some(Self::Cancel),
            0x000d => Some(Self::Echo),
            0x000e => Some(Self::QueryDirectory),
            0x000f => Some(Self::ChangeNotify),
            0x0010 => Some(Self::QueryInfo),
            0x0011 => Some(Self::SetInfo),
            0x0012 => Some(Self::OplockBreak),
            _ => None,
        }
    }

    /// Returns the numeric SMB2 command id.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns whether the command uses tree id zero while allocating or decoding.
    pub const fn uses_zero_tree_id(self) -> bool {
        matches!(
            self,
            Self::Negotiate | Self::SessionSetup | Self::Logoff | Self::Echo | Self::TreeConnect
        )
    }

    /// Converts this PDU command to the public protocol enum used by private skeleton APIs.
    pub const fn to_private_command(self) -> crate::include::smb2::smb2::Command {
        match self {
            Self::Negotiate => crate::include::smb2::smb2::Command::Negotiate,
            Self::SessionSetup => crate::include::smb2::smb2::Command::SessionSetup,
            Self::Logoff => crate::include::smb2::smb2::Command::Logoff,
            Self::TreeConnect => crate::include::smb2::smb2::Command::TreeConnect,
            Self::TreeDisconnect => crate::include::smb2::smb2::Command::TreeDisconnect,
            Self::Create => crate::include::smb2::smb2::Command::Create,
            Self::Close => crate::include::smb2::smb2::Command::Close,
            Self::Flush => crate::include::smb2::smb2::Command::Flush,
            Self::Read => crate::include::smb2::smb2::Command::Read,
            Self::Write => crate::include::smb2::smb2::Command::Write,
            Self::Lock => crate::include::smb2::smb2::Command::Lock,
            Self::Ioctl => crate::include::smb2::smb2::Command::Ioctl,
            Self::Cancel => crate::include::smb2::smb2::Command::Cancel,
            Self::Echo => crate::include::smb2::smb2::Command::Echo,
            Self::QueryDirectory => crate::include::smb2::smb2::Command::QueryDirectory,
            Self::ChangeNotify => crate::include::smb2::smb2::Command::ChangeNotify,
            Self::QueryInfo => crate::include::smb2::smb2::Command::QueryInfo,
            Self::SetInfo => crate::include::smb2::smb2::Command::SetInfo,
            Self::OplockBreak => crate::include::smb2::smb2::Command::OplockBreak,
        }
    }
}

/// Error type for skeletal PDU helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduError {
    /// The requested offset and width do not fit inside the buffer.
    OutOfBounds,
    /// The buffer is too short to contain a complete SMB2 header.
    HeaderTooSmall,
    /// The header signature is neither SMB2 nor an accepted SMB1 negotiate.
    BadSignature,
    /// The operation requires at least one connected tree id.
    MissingTreeId,
    /// The requested tree id is not present in the context stack.
    TreeIdNotFound,
    /// The tree id stack already reached the migration skeleton limit.
    TreeNestingTooDeep,
    /// The PDU argument required by the C API was absent.
    MissingPdu,
    /// Adding another iovec would exceed the legacy vector limit.
    TooManyVectors,
    /// A command id is not part of the migrated SMB2 command table.
    UnknownCommand,
}

/// Result alias used by PDU skeleton helpers.
pub type PduResult<T> = core::result::Result<T, PduError>;

/// Fixed request and reply sizes used by PDU dispatch sizing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedSizes {
    /// Fixed request structure size in bytes.
    pub request: usize,
    /// Fixed reply structure size in bytes.
    pub reply: usize,
}

/// Lightweight description of a command-specific fixed/variable payload handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadHandler {
    /// SMB2 command handled by the entry.
    pub command: Smb2Command,
    /// Name of the C fixed request handler mirrored by this skeleton.
    pub request_fixed: &'static str,
    /// Name of the C variable request handler mirrored by this skeleton.
    pub request_variable: &'static str,
    /// Name of the C fixed reply handler mirrored by this skeleton.
    pub reply_fixed: &'static str,
    /// Name of the C variable reply handler mirrored by this skeleton.
    pub reply_variable: &'static str,
}

/// Command handler table matching the dispatch responsibility of `pdu.c`.
pub const PAYLOAD_HANDLERS: &[PayloadHandler] = &[
    PayloadHandler::new(Smb2Command::Negotiate, "smb2_process_negotiate"),
    PayloadHandler::new(Smb2Command::SessionSetup, "smb2_process_session_setup"),
    PayloadHandler::new(Smb2Command::Logoff, "smb2_process_logoff"),
    PayloadHandler::new(Smb2Command::TreeConnect, "smb2_process_tree_connect"),
    PayloadHandler::new(Smb2Command::TreeDisconnect, "smb2_process_tree_disconnect"),
    PayloadHandler::new(Smb2Command::Create, "smb2_process_create"),
    PayloadHandler::new(Smb2Command::Close, "smb2_process_close"),
    PayloadHandler::new(Smb2Command::Flush, "smb2_process_flush"),
    PayloadHandler::new(Smb2Command::Read, "smb2_process_read"),
    PayloadHandler::new(Smb2Command::Write, "smb2_process_write"),
    PayloadHandler::new(Smb2Command::Lock, "smb2_process_lock"),
    PayloadHandler::new(Smb2Command::Ioctl, "smb2_process_ioctl"),
    PayloadHandler::new(Smb2Command::Echo, "smb2_process_echo"),
    PayloadHandler::new(Smb2Command::QueryDirectory, "smb2_process_query_directory"),
    PayloadHandler::new(Smb2Command::ChangeNotify, "smb2_process_change_notify"),
    PayloadHandler::new(Smb2Command::QueryInfo, "smb2_process_query_info"),
    PayloadHandler::new(Smb2Command::SetInfo, "smb2_process_set_info"),
    PayloadHandler::new(Smb2Command::OplockBreak, "smb2_process_oplock_break"),
];

impl PayloadHandler {
    const fn new(command: Smb2Command, base_name: &'static str) -> Self {
        Self {
            command,
            request_fixed: base_name,
            request_variable: base_name,
            reply_fixed: base_name,
            reply_variable: base_name,
        }
    }
}

/// Creates an empty SMB2 header skeleton for a command.
pub fn smb2_header_for_command(command: Smb2Command) -> Smb2Header {
    let mut header = Smb2Header::for_command(command.to_private_command());
    header.struct_size = SMB2_HEADER_STRUCT_SIZE;
    header.process_id = 0xfeff;
    header
}

/// Allocates a Rust-owned PDU skeleton with an SMB2 header vector.
pub fn smb2_allocate_pdu(
    context: &Context,
    command: Smb2Command,
    callback: Option<CommandCallback>,
) -> Pdu {
    let mut header = smb2_header_for_command(command);
    header.credit_charge = if command == Smb2Command::Negotiate {
        0
    } else {
        1
    };
    header.credit_request_response = credit_request_response(context);
    header.tree_id = if command.uses_zero_tree_id() {
        0
    } else {
        smb2_tree_id(context).map_or(0, |tree_id| tree_id)
    };
    header.session_id = if command == Smb2Command::Negotiate {
        0
    } else {
        context.session_id
    };

    let mut pdu = Pdu::from_parts(header, IoVectors::new(), callback);
    ensure_header_vector(&mut pdu);
    pdu
}

/// Adds an owned I/O vector to a vector list.
pub fn smb2_add_iovector(vectors: &mut IoVectors, buf: Vec<u8>) -> PduResult<&mut IoVec> {
    if vectors.vectors.len() >= SMB2_MAX_VECTORS {
        return Err(PduError::TooManyVectors);
    }
    vectors.total_size = vectors.total_size.saturating_add(buf.len());
    vectors.vectors.push(IoVec { buf });
    let index = vectors.vectors.len().saturating_sub(1);
    vectors
        .vectors
        .get_mut(index)
        .ok_or(PduError::TooManyVectors)
}

/// Clears all owned vectors and counters from a vector list.
pub fn smb2_free_iovector(vectors: &mut IoVectors) {
    vectors.done = 0;
    vectors.total_size = 0;
    vectors.vectors.clear();
}

/// Pads an I/O vector list to the next 64-bit boundary using zero bytes.
pub fn smb2_pad_to_64bit(vectors: &mut IoVectors) -> usize {
    let len = vectors_total_len(vectors);
    let pad = (8 - (len & 0x07)) & 0x07;
    if pad > 0 {
        if smb2_add_iovector(vectors, vec![0; pad]).is_err() {
            return 0;
        }
    }
    pad
}

/// Selects a connected tree id as the current context tree.
pub fn smb2_select_tree_id(context: &mut Context, tree_id: u32) -> PduResult<()> {
    let Some(index) = context.tree_ids.iter().position(|value| *value == tree_id) else {
        return Err(PduError::TreeIdNotFound);
    };
    context.tree_ids.swap(0, index);
    Ok(())
}

/// Returns the tree id that should be associated with a PDU.
pub fn smb2_get_tree_id_for_pdu(context: &Context, pdu: Option<&Pdu>) -> PduResult<u32> {
    if let Some(pdu) = pdu {
        if Smb2Command::from_raw(pdu.header.command).is_some_and(Smb2Command::uses_zero_tree_id) {
            return Ok(0);
        }
    }

    smb2_tree_id(context).ok_or(PduError::MissingTreeId)
}

/// Sets the tree id on a PDU when the command carries one.
pub fn smb2_set_tree_id_for_pdu(pdu: Option<&mut Pdu>, tree_id: u32) -> PduResult<()> {
    let Some(pdu) = pdu else {
        return Err(PduError::MissingPdu);
    };
    if pdu.header.flags & SMB2_FLAGS_ASYNC_COMMAND != 0 {
        return Ok(());
    }
    if !Smb2Command::from_raw(pdu.header.command).is_some_and(Smb2Command::uses_zero_tree_id) {
        pdu.header.tree_id = tree_id;
    }
    Ok(())
}

/// Returns the current session id from the migration context.
pub const fn smb2_get_session_id(context: &Context) -> u64 {
    context.session_id
}

/// Adds a connected tree id to the context stack.
pub fn smb2_connect_tree_id(context: &mut Context, tree_id: u32) -> PduResult<()> {
    if context.tree_ids.len() >= SMB2_MAX_TREE_NESTING {
        return Err(PduError::TreeNestingTooDeep);
    }
    context.tree_ids.insert(0, tree_id);
    Ok(())
}

/// Removes a connected tree id from the context stack.
pub fn smb2_disconnect_tree_id(context: &mut Context, tree_id: u32) -> PduResult<()> {
    let Some(index) = context.tree_ids.iter().position(|value| *value == tree_id) else {
        return Err(PduError::TreeIdNotFound);
    };
    context.tree_ids.remove(index);
    Ok(())
}

/// Returns whether the last decoded context header starts a compound chain.
pub const fn smb2_pdu_is_compound(context: &Context) -> bool {
    context.header.next_command != 0
}

/// Marks two PDUs as a compound pair and fixes the first header's next offset.
pub fn smb2_add_compound_pdu(pdu: &mut Pdu, next_pdu: &mut Pdu) {
    pdu.compound = true;
    next_pdu.compound = true;
    pdu.header.next_command = vectors_total_len(&pdu.out) as u32;
    next_pdu.header.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    if let Some(first) = pdu.out.vectors.first_mut() {
        let _encode_result = smb2_set_uint32(first, 20, pdu.header.next_command);
    }
    if let Some(first) = next_pdu.out.vectors.first_mut() {
        let _encode_result = smb2_set_uint32(first, 16, next_pdu.header.flags);
    }
}

/// Reads a little-endian u8 from an I/O vector.
pub fn smb2_get_uint8(iov: &IoVec, offset: usize) -> PduResult<u8> {
    iov.buf.get(offset).copied().ok_or(PduError::OutOfBounds)
}

/// Writes a little-endian u8 into an I/O vector.
pub fn smb2_set_uint8(iov: &mut IoVec, offset: usize, value: u8) -> PduResult<()> {
    let Some(slot) = iov.buf.get_mut(offset) else {
        return Err(PduError::OutOfBounds);
    };
    *slot = value;
    Ok(())
}

/// Reads a little-endian u16 from an I/O vector.
pub fn smb2_get_uint16(iov: &IoVec, offset: usize) -> PduResult<u16> {
    let bytes = fixed_bytes::<2>(&iov.buf, offset)?;
    Ok(u16::from_le_bytes(bytes))
}

/// Writes a little-endian u16 into an I/O vector.
pub fn smb2_set_uint16(iov: &mut IoVec, offset: usize, value: u16) -> PduResult<()> {
    write_bytes(&mut iov.buf, offset, &value.to_le_bytes())
}

/// Reads a little-endian u32 from an I/O vector.
pub fn smb2_get_uint32(iov: &IoVec, offset: usize) -> PduResult<u32> {
    let bytes = fixed_bytes::<4>(&iov.buf, offset)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Writes a little-endian u32 into an I/O vector.
pub fn smb2_set_uint32(iov: &mut IoVec, offset: usize, value: u32) -> PduResult<()> {
    write_bytes(&mut iov.buf, offset, &value.to_le_bytes())
}

/// Reads a little-endian u64 from an I/O vector.
pub fn smb2_get_uint64(iov: &IoVec, offset: usize) -> PduResult<u64> {
    let bytes = fixed_bytes::<8>(&iov.buf, offset)?;
    Ok(u64::from_le_bytes(bytes))
}

/// Writes a little-endian u64 into an I/O vector.
pub fn smb2_set_uint64(iov: &mut IoVec, offset: usize, value: u64) -> PduResult<()> {
    write_bytes(&mut iov.buf, offset, &value.to_le_bytes())
}

/// Encodes an SMB2 header into a caller-provided byte buffer.
pub fn smb2_encode_header_bytes(buf: &mut [u8], header: &Smb2Header) -> PduResult<()> {
    if buf.len() < SMB2_HEADER_SIZE {
        return Err(PduError::HeaderTooSmall);
    }
    write_bytes(buf, 0, &header.protocol_id)?;
    write_bytes(buf, 4, &header.struct_size.to_le_bytes())?;
    write_bytes(buf, 6, &header.credit_charge.to_le_bytes())?;
    write_bytes(buf, 8, &header.status.to_le_bytes())?;
    write_bytes(buf, 12, &header.command.to_le_bytes())?;
    write_bytes(buf, 14, &header.credit_request_response.to_le_bytes())?;
    write_bytes(buf, 16, &header.flags.to_le_bytes())?;
    write_bytes(buf, 20, &header.next_command.to_le_bytes())?;
    write_bytes(buf, 24, &header.message_id.to_le_bytes())?;
    if header.flags & SMB2_FLAGS_ASYNC_COMMAND != 0 {
        write_bytes(buf, 32, &header.async_id.to_le_bytes())?;
    } else {
        write_bytes(buf, 32, &header.process_id.to_le_bytes())?;
        write_bytes(buf, 36, &header.tree_id.to_le_bytes())?;
    }
    write_bytes(buf, 40, &header.session_id.to_le_bytes())?;
    write_bytes(buf, 48, &header.signature)?;
    Ok(())
}

/// Assigns client message ids and encodes an SMB2 header into bytes.
pub fn smb2_encode_header(
    context: &mut Context,
    buf: &mut [u8],
    header: &mut Smb2Header,
) -> PduResult<()> {
    if !context.is_server() {
        header.message_id = context.message_id;
        context.message_id = context.message_id.saturating_add(1);
        if header.credit_charge > 1 {
            context.message_id = context
                .message_id
                .saturating_add(u64::from(header.credit_charge.saturating_sub(1)));
        }
    }
    smb2_encode_header_bytes(buf, header)
}

/// Decodes an SMB2 header from bytes into the Rust header model.
pub fn smb2_decode_header_bytes(buf: &[u8]) -> PduResult<Smb2Header> {
    if buf.len() < SMB2_HEADER_SIZE {
        return Err(PduError::HeaderTooSmall);
    }
    let protocol_id = fixed_bytes::<4>(buf, 0)?;
    if protocol_id == SMB1_PROTOCOL_ID && buf.get(4).copied() == Some(SMB1_NEGOTIATE) {
        let mut header = smb2_header_for_command(Smb2Command::Negotiate);
        header.protocol_id = SMB1_PROTOCOL_ID;
        return Ok(header);
    }
    if protocol_id != SMB2_PROTOCOL_ID {
        return Err(PduError::BadSignature);
    }

    let flags = u32::from_le_bytes(fixed_bytes::<4>(buf, 16)?);
    let mut header = Smb2Header {
        protocol_id,
        struct_size: u16::from_le_bytes(fixed_bytes::<2>(buf, 4)?),
        credit_charge: u16::from_le_bytes(fixed_bytes::<2>(buf, 6)?),
        status: u32::from_le_bytes(fixed_bytes::<4>(buf, 8)?),
        command: u16::from_le_bytes(fixed_bytes::<2>(buf, 12)?),
        credit_request_response: u16::from_le_bytes(fixed_bytes::<2>(buf, 14)?),
        flags,
        next_command: u32::from_le_bytes(fixed_bytes::<4>(buf, 20)?),
        message_id: u64::from_le_bytes(fixed_bytes::<8>(buf, 24)?),
        process_id: 0,
        tree_id: 0,
        async_id: 0,
        session_id: u64::from_le_bytes(fixed_bytes::<8>(buf, 40)?),
        signature: fixed_bytes::<16>(buf, 48)?,
    };
    if flags & SMB2_FLAGS_ASYNC_COMMAND != 0 {
        header.async_id = u64::from_le_bytes(fixed_bytes::<8>(buf, 32)?);
    } else {
        header.process_id = u32::from_le_bytes(fixed_bytes::<4>(buf, 32)?);
        header.tree_id = u32::from_le_bytes(fixed_bytes::<4>(buf, 36)?);
    }
    Ok(header)
}

/// Decodes a header from an I/O vector and updates context receive metadata.
pub fn smb2_decode_header(context: &mut Context, iov: &IoVec) -> PduResult<Smb2Header> {
    let header = smb2_decode_header_bytes(&iov.buf)?;
    if header.protocol_id == SMB2_PROTOCOL_ID && header.flags & SMB2_FLAGS_ASYNC_COMMAND == 0 {
        if header.flags & SMB2_FLAGS_SERVER_TO_REDIR == 0 {
            if let Some(command) = Smb2Command::from_raw(header.command) {
                if !command.uses_zero_tree_id() {
                    smb2_select_tree_id(context, header.tree_id)?;
                }
            }
        }
    }
    if context.is_server() {
        context.message_id = header.message_id;
    }
    context.header = header;
    Ok(header)
}

/// Queues a PDU in the outgoing context queue after encoding its header vector.
pub fn smb2_queue_pdu(context: &mut Context, mut pdu: Pdu) -> PduResult<()> {
    let mut prev_compound_mid = 0;
    encode_queued_pdu(context, &mut pdu, &mut prev_compound_mid)?;
    context.push_outqueue(pdu);
    Ok(())
}

/// Returns the next compound PDU placeholder, if the skeleton has one.
pub fn smb2_get_compound_pdu(pdu: &Pdu) -> Option<&Pdu> {
    pdu.next_compound.as_deref()
}

/// Frees a PDU and removes matching entries from the context queues.
pub fn smb2_free_pdu(context: &mut Context, pdu: &mut Pdu) {
    let message_id = pdu.header.message_id;
    context.remove_queued_pdu(message_id);
    pdu.next_compound = None;
    pdu.out.clear();
    pdu.input.clear();
    pdu.payload = None;
}

/// Sets the status field on a PDU header.
pub const fn smb2_set_pdu_status(pdu: &mut Pdu, status: u32) {
    pdu.header.status = status;
}

/// Sets the message id field on a PDU header.
pub const fn smb2_set_pdu_message_id(pdu: &mut Pdu, message_id: u64) {
    pdu.header.message_id = message_id;
}

/// Returns the message id field from a PDU header.
pub const fn smb2_get_pdu_message_id(pdu: Option<&Pdu>) -> u64 {
    match pdu {
        Some(pdu) => pdu.header.message_id,
        None => 0,
    }
}

/// Returns the most recent request message id tracked by the context.
pub const fn smb2_get_last_request_message_id(context: &Context) -> u64 {
    context.message_id
}

/// Returns the most recent reply message id tracked by the context header.
pub const fn smb2_get_last_reply_message_id(context: &Context) -> u64 {
    context.header.message_id
}

/// Finds a waiting PDU by message id.
pub fn smb2_find_pdu(context: &Context, message_id: u64) -> Option<&Pdu> {
    context.find_waiting_pdu(message_id)
}

/// Classifies whether a context header represents an error response.
pub const fn smb2_is_error_response(context: &Context) -> bool {
    let severity = context.header.status & SMB2_STATUS_SEVERITY_MASK;
    if severity == SMB2_STATUS_SEVERITY_ERROR {
        context.header.status != SMB2_STATUS_MORE_PROCESSING_REQUIRED
    } else if severity == SMB2_STATUS_SEVERITY_WARNING {
        context.header.status == SMB2_STATUS_STOPPED_ON_SYMLINK
    } else {
        false
    }
}

/// Returns fixed request/reply sizes for a command.
pub const fn smb2_get_fixed_sizes(command: Smb2Command) -> FixedSizes {
    let request = match command {
        Smb2Command::Negotiate => SMB2_NEGOTIATE_REQUEST_SIZE as usize,
        Smb2Command::SessionSetup => SMB2_SESSION_SETUP_REQUEST_SIZE as usize,
        Smb2Command::Logoff => SMB2_LOGOFF_REQUEST_SIZE as usize,
        Smb2Command::TreeConnect => SMB2_TREE_CONNECT_REQUEST_SIZE as usize,
        Smb2Command::TreeDisconnect => SMB2_TREE_DISCONNECT_REQUEST_SIZE as usize,
        Smb2Command::Create => SMB2_CREATE_REQUEST_SIZE as usize,
        Smb2Command::Close => SMB2_CLOSE_REQUEST_SIZE as usize,
        Smb2Command::Flush => SMB2_FLUSH_REQUEST_SIZE as usize,
        Smb2Command::Read => SMB2_READ_REQUEST_SIZE as usize,
        Smb2Command::Write => SMB2_WRITE_REQUEST_SIZE as usize,
        Smb2Command::Lock => SMB2_LOCK_REQUEST_SIZE as usize,
        Smb2Command::Ioctl => SMB2_IOCTL_REQUEST_SIZE as usize,
        Smb2Command::Cancel => SMB2_CANCEL_REQUEST_SIZE as usize,
        Smb2Command::Echo => SMB2_ECHO_REQUEST_SIZE as usize,
        Smb2Command::QueryDirectory => SMB2_QUERY_DIRECTORY_REQUEST_SIZE as usize,
        Smb2Command::ChangeNotify => SMB2_CHANGE_NOTIFY_REQUEST_SIZE as usize,
        Smb2Command::QueryInfo => SMB2_QUERY_INFO_REQUEST_SIZE as usize,
        Smb2Command::SetInfo => SMB2_SET_INFO_REQUEST_SIZE as usize,
        Smb2Command::OplockBreak => 2,
    };
    let reply = match command {
        Smb2Command::Negotiate => SMB2_NEGOTIATE_REPLY_SIZE as usize,
        Smb2Command::SessionSetup => SMB2_SESSION_SETUP_REPLY_SIZE as usize,
        Smb2Command::Logoff => SMB2_LOGOFF_REPLY_SIZE as usize,
        Smb2Command::TreeConnect => SMB2_TREE_CONNECT_REPLY_SIZE as usize,
        Smb2Command::TreeDisconnect => SMB2_TREE_DISCONNECT_REPLY_SIZE as usize,
        Smb2Command::Create => SMB2_CREATE_REPLY_SIZE as usize,
        Smb2Command::Close => SMB2_CLOSE_REPLY_SIZE as usize,
        Smb2Command::Flush => SMB2_FLUSH_REPLY_SIZE as usize,
        Smb2Command::Read => SMB2_READ_REPLY_SIZE as usize,
        Smb2Command::Write => SMB2_WRITE_REPLY_SIZE as usize,
        Smb2Command::Lock => SMB2_LOCK_REPLY_SIZE as usize,
        Smb2Command::Ioctl => SMB2_IOCTL_REPLY_SIZE as usize,
        Smb2Command::Cancel => 0,
        Smb2Command::Echo => SMB2_ECHO_REPLY_SIZE as usize,
        Smb2Command::QueryDirectory => SMB2_QUERY_DIRECTORY_REPLY_SIZE as usize,
        Smb2Command::ChangeNotify => SMB2_CHANGE_NOTIFY_REPLY_SIZE as usize,
        Smb2Command::QueryInfo => SMB2_QUERY_INFO_REPLY_SIZE as usize,
        Smb2Command::SetInfo => SMB2_SET_INFO_REPLY_SIZE as usize,
        Smb2Command::OplockBreak => 2,
    };
    FixedSizes { request, reply }
}

/// Returns the fixed reply size, using the error payload size for error responses.
pub const fn smb2_get_fixed_reply_size(context: &Context, command: Smb2Command) -> usize {
    if smb2_is_error_response(context) {
        (SMB2_ERROR_REPLY_SIZE & 0xfffe) as usize
    } else {
        smb2_get_fixed_sizes(command).reply
    }
}

/// Returns the fixed request size for a command.
pub const fn smb2_get_fixed_request_size(command: Smb2Command) -> usize {
    smb2_get_fixed_sizes(command).request
}

/// Returns the fixed payload size for the selected server/client direction.
pub const fn smb2_get_fixed_size(command: Smb2Command, is_server: bool) -> usize {
    let sizes = smb2_get_fixed_sizes(command);
    if is_server {
        sizes.request
    } else {
        sizes.reply
    }
}

/// Returns the handler table entry for a command.
pub fn smb2_payload_handler(command: Smb2Command) -> Option<&'static PayloadHandler> {
    PAYLOAD_HANDLERS
        .iter()
        .find(|handler| handler.command == command)
}

/// Processes fixed reply payloads through migrated Rust command processors.
pub fn smb2_process_reply_payload_fixed(context: &Context, pdu: &Pdu) -> PduResult<()> {
    process_fixed_payload(context, pdu, false)
}

/// Processes variable reply payloads through migrated Rust command processors.
pub fn smb2_process_reply_payload_variable(context: &Context, pdu: &Pdu) -> PduResult<()> {
    process_variable_payload(context, pdu, false)
}

/// Processes fixed request payloads through migrated Rust command processors.
pub fn smb2_process_request_payload_fixed(context: &Context, pdu: &Pdu) -> PduResult<()> {
    process_fixed_payload(context, pdu, true)
}

/// Processes variable request payloads through migrated Rust command processors.
pub fn smb2_process_request_payload_variable(context: &Context, pdu: &Pdu) -> PduResult<()> {
    process_variable_payload(context, pdu, true)
}

/// Skeleton dispatcher for fixed payload processing.
pub fn smb2_process_payload_fixed(context: &Context, pdu: &Pdu, is_server: bool) -> PduResult<()> {
    if is_server {
        smb2_process_request_payload_fixed(context, pdu)
    } else {
        smb2_process_reply_payload_fixed(context, pdu)
    }
}

/// Skeleton dispatcher for variable payload processing.
pub fn smb2_process_payload_variable(
    context: &Context,
    pdu: &Pdu,
    is_server: bool,
) -> PduResult<()> {
    if is_server {
        smb2_process_request_payload_variable(context, pdu)
    } else {
        smb2_process_reply_payload_variable(context, pdu)
    }
}

/// Removes expired PDUs from outqueue and waitqueue using a Unix timestamp deadline.
pub fn smb2_timeout_pdus(context: &mut Context, now: i64) {
    context
        .outqueue
        .retain(|pdu| pdu.timeout.is_none_or(|deadline| deadline >= now));
    context
        .waitqueue
        .retain(|pdu| pdu.timeout.is_none_or(|deadline| deadline >= now));
}

fn process_fixed_payload(context: &Context, pdu: &Pdu, is_request: bool) -> PduResult<()> {
    let Some(command) = Smb2Command::from_raw(pdu.header.command) else {
        return Err(PduError::UnknownCommand);
    };
    let fixed = fixed_payload_bytes(pdu, command, is_request)?;
    let pdu_size = pdu_packet_size(pdu)?;
    let next_command = next_command_limit(pdu);

    match (command, is_request) {
        (Smb2Command::Echo, true) => {
            smb2_process_echo_request_fixed(&fixed).map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Echo, false) => {
            smb2_process_echo_fixed(&fixed).map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Flush, true) => {
            smb2_process_flush_request_fixed(&fixed).map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Flush, false) => {
            smb2_process_flush_fixed(&fixed).map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Logoff, true) => {
            smb2_process_logoff_request_fixed(&fixed).map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Logoff, false) => {
            smb2_process_logoff_fixed(&fixed).map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Close, true) => {
            crate::lib::smb2_cmd_close::smb2_process_close_request_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Close, false) => {
            crate::lib::smb2_cmd_close::smb2_process_close_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::TreeConnect, true) => {
            let mut tree_pdu =
                crate::lib::smb2_cmd_tree_connect::Smb2TreeConnectPdu::new_tree_connect();
            crate::lib::smb2_cmd_tree_connect::smb2_process_tree_connect_request_fixed(
                &mut tree_pdu,
                &fixed,
            )
            .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::TreeConnect, false) => {
            let mut tree_context = crate::lib::smb2_cmd_tree_connect::Smb2TreeConnectContext::new();
            let mut tree_pdu =
                crate::lib::smb2_cmd_tree_connect::Smb2TreeConnectPdu::new_tree_connect();
            crate::lib::smb2_cmd_tree_connect::smb2_process_tree_connect_fixed(
                &mut tree_context,
                &mut tree_pdu,
                &fixed,
                pdu.header.tree_id,
            )
            .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::TreeDisconnect, true) => {
            let mut tree_pdu =
                crate::lib::smb2_cmd_tree_disconnect::Smb2TreeDisconnectPdu::new_tree_disconnect();
            crate::lib::smb2_cmd_tree_disconnect::smb2_process_tree_disconnect_request_fixed(
                &mut tree_pdu,
                &fixed,
            )
            .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::TreeDisconnect, false) => {
            let mut tree_context =
                crate::lib::smb2_cmd_tree_disconnect::Smb2TreeDisconnectContext::new();
            let _ = tree_context.connect_tree_id(pdu.header.tree_id);
            let mut tree_pdu =
                crate::lib::smb2_cmd_tree_disconnect::Smb2TreeDisconnectPdu::new_tree_disconnect();
            crate::lib::smb2_cmd_tree_disconnect::smb2_process_tree_disconnect_fixed(
                &mut tree_context,
                &mut tree_pdu,
                &fixed,
                pdu.header.tree_id,
            )
            .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Negotiate, true) => {
            crate::lib::smb2_cmd_negotiate::smb2_process_negotiate_request_fixed(&fixed, pdu_size)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Negotiate, false) => {
            crate::lib::smb2_cmd_negotiate::smb2_process_negotiate_fixed(&fixed, pdu_size)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::SessionSetup, true) => {
            crate::lib::smb2_cmd_session_setup::Smb2SessionSetupRequest::decode_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::SessionSetup, false) => {
            crate::lib::smb2_cmd_session_setup::Smb2SessionSetupReply::decode_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Create, true) => {
            crate::lib::smb2_cmd_create::decode_create_request_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Create, false) => {
            crate::lib::smb2_cmd_create::decode_create_reply_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Read, true) => {
            crate::lib::smb2_cmd_read::Smb2ReadRequest::process_request_fixed(&fixed, u32::MAX)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Read, false) => {
            crate::lib::smb2_cmd_read::Smb2ReadReply::process_reply_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Write, true) => {
            crate::lib::smb2_cmd_write::smb2_process_write_request_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Write, false) => {
            crate::lib::smb2_cmd_write::smb2_process_write_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::QueryInfo, true) => {
            crate::lib::smb2_cmd_query_info::smb2_process_query_info_request_fixed(
                &fixed, pdu_size,
            )
            .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::QueryInfo, false) => {
            crate::lib::smb2_cmd_query_info::smb2_process_query_info_fixed(
                &fixed,
                pdu_size,
                next_command,
            )
            .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::SetInfo, true) => {
            crate::lib::smb2_cmd_set_info::smb2_process_set_info_request_fixed(&fixed, pdu_size)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::SetInfo, false) => {
            crate::lib::smb2_cmd_set_info::smb2_process_set_info_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Ioctl, true) => {
            crate::lib::smb2_cmd_ioctl::IoctlRequest::decode_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Ioctl, false) => {
            crate::lib::smb2_cmd_ioctl::IoctlReply::decode_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Cancel, _)
        | (Smb2Command::Lock, _)
        | (Smb2Command::QueryDirectory, _)
        | (Smb2Command::ChangeNotify, _)
        | (Smb2Command::OplockBreak, _) => preserve_raw_payload(&fixed)?,
    }

    let _ = context;
    Ok(())
}

fn process_variable_payload(_context: &Context, pdu: &Pdu, is_request: bool) -> PduResult<()> {
    let Some(command) = Smb2Command::from_raw(pdu.header.command) else {
        return Err(PduError::UnknownCommand);
    };
    let fixed = fixed_payload_bytes(pdu, command, is_request)?;
    let variable = variable_payload_bytes(pdu, command, is_request)?;
    let pdu_size = pdu_packet_size(pdu)?;

    match (command, is_request) {
        (Smb2Command::Negotiate, true) => {
            let (mut req, _) =
                crate::lib::smb2_cmd_negotiate::smb2_process_negotiate_request_fixed(
                    &fixed, pdu_size,
                )
                .map_err(|_| PduError::OutOfBounds)?;
            crate::lib::smb2_cmd_negotiate::smb2_process_negotiate_request_variable(
                &mut req,
                &variable,
                read_fixed_u16(&fixed, 2)?,
                read_fixed_u16(&fixed, 32)?,
            )
            .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Negotiate, false) => {
            let (mut rep, _) =
                crate::lib::smb2_cmd_negotiate::smb2_process_negotiate_fixed(&fixed, pdu_size)
                    .map_err(|_| PduError::OutOfBounds)?;
            crate::lib::smb2_cmd_negotiate::smb2_process_negotiate_variable(
                &mut rep,
                &variable,
                read_fixed_u16(&fixed, 6)?,
            )
            .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::SessionSetup, true) => {
            let mut req =
                crate::lib::smb2_cmd_session_setup::Smb2SessionSetupRequest::decode_fixed(&fixed)
                    .map_err(|_| PduError::OutOfBounds)?;
            req.attach_security_buffer(variable_prefix(&variable, read_fixed_u16(&fixed, 14)?)?);
        }
        (Smb2Command::SessionSetup, false) => {
            let mut rep =
                crate::lib::smb2_cmd_session_setup::Smb2SessionSetupReply::decode_fixed(&fixed)
                    .map_err(|_| PduError::OutOfBounds)?;
            let full = pdu_packet_bytes(pdu)?;
            rep.attach_variable_from_pdu(&full, read_fixed_u16(&fixed, 6)?)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::TreeConnect, true) => {
            let mut tree_pdu =
                crate::lib::smb2_cmd_tree_connect::Smb2TreeConnectPdu::new_tree_connect();
            crate::lib::smb2_cmd_tree_connect::smb2_process_tree_connect_request_fixed(
                &mut tree_pdu,
                &fixed,
            )
            .map_err(|_| PduError::OutOfBounds)?;
            crate::lib::smb2_cmd_tree_connect::smb2_process_tree_connect_request_variable(
                &mut tree_pdu,
                &variable,
            )
            .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Create, true) => {
            let (req, _) = crate::lib::smb2_cmd_create::decode_create_request_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
            crate::lib::smb2_cmd_create::decode_create_request_variable(&req, &variable)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Create, false) => {
            let (rep, _) = crate::lib::smb2_cmd_create::decode_create_reply_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
            crate::lib::smb2_cmd_create::decode_create_reply_variable(&rep, &variable)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Read, true) => {
            let (mut req, _) =
                crate::lib::smb2_cmd_read::Smb2ReadRequest::process_request_fixed(&fixed, u32::MAX)
                    .map_err(|_| PduError::OutOfBounds)?;
            req.process_request_variable(&variable)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Read, false) => {
            let (mut rep, _) =
                crate::lib::smb2_cmd_read::Smb2ReadReply::process_reply_fixed(&fixed)
                    .map_err(|_| PduError::OutOfBounds)?;
            rep.process_reply_variable(&variable)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Write, true) => {
            let req = crate::lib::smb2_cmd_write::smb2_process_write_request_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
            crate::lib::smb2_cmd_write::smb2_process_write_request_variable(&req, &variable)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::QueryInfo, true) => {
            let (mut req, _) =
                crate::lib::smb2_cmd_query_info::smb2_process_query_info_request_fixed(
                    &fixed, pdu_size,
                )
                .map_err(|_| PduError::OutOfBounds)?;
            crate::lib::smb2_cmd_query_info::smb2_process_query_info_request_variable(
                &mut req, &variable,
            )
            .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::QueryInfo, false) => {
            let (mut rep, _) = crate::lib::smb2_cmd_query_info::smb2_process_query_info_fixed(
                &fixed,
                pdu_size,
                next_command_limit(pdu),
            )
            .map_err(|_| PduError::OutOfBounds)?;
            crate::lib::smb2_cmd_query_info::smb2_process_query_info_variable(
                &mut rep, 0, 0, &variable, true,
            )
            .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::SetInfo, true) => {
            let (mut req, _) = crate::lib::smb2_cmd_set_info::smb2_process_set_info_request_fixed(
                &fixed, pdu_size,
            )
            .map_err(|_| PduError::OutOfBounds)?;
            crate::lib::smb2_cmd_set_info::smb2_process_set_info_request_variable(
                &mut req, &variable, false,
            )
            .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Ioctl, true) => {
            let mut req = crate::lib::smb2_cmd_ioctl::IoctlRequest::decode_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
            req.decode_input(&variable, false)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Ioctl, false) => {
            let mut rep = crate::lib::smb2_cmd_ioctl::IoctlReply::decode_fixed(&fixed)
                .map_err(|_| PduError::OutOfBounds)?;
            rep.decode_output(&variable, false)
                .map_err(|_| PduError::OutOfBounds)?;
        }
        (Smb2Command::Close, _)
        | (Smb2Command::TreeDisconnect, _)
        | (Smb2Command::Flush, _)
        | (Smb2Command::Write, false)
        | (Smb2Command::Logoff, _)
        | (Smb2Command::Echo, _)
        | (Smb2Command::SetInfo, false) => return no_variable_payload(&variable),
        (Smb2Command::TreeConnect, false) => preserve_raw_payload(&variable)?,
        (Smb2Command::Cancel, _)
        | (Smb2Command::Lock, _)
        | (Smb2Command::QueryDirectory, _)
        | (Smb2Command::ChangeNotify, _)
        | (Smb2Command::OplockBreak, _) => preserve_raw_payload(&variable)?,
    }

    Ok(())
}

fn no_variable_payload(variable: &[u8]) -> PduResult<()> {
    preserve_raw_payload(variable)
}

fn preserve_raw_payload(_payload: &[u8]) -> PduResult<()> {
    // Generic PDUs do not carry command-specific state; retaining these bytes in
    // the vector-backed PDU is the lossless representation until typed state is
    // available at a higher layer.
    Ok(())
}

fn fixed_payload_bytes(pdu: &Pdu, command: Smb2Command, is_request: bool) -> PduResult<Vec<u8>> {
    let payload = payload_bytes(pdu)?;
    let fixed_len = fixed_payload_len(command, is_request);
    let fixed = payload.get(..fixed_len).ok_or(PduError::OutOfBounds)?;
    Ok(fixed.to_vec())
}

fn variable_payload_bytes(pdu: &Pdu, command: Smb2Command, is_request: bool) -> PduResult<Vec<u8>> {
    let payload = payload_bytes(pdu)?;
    let fixed_len = fixed_payload_len(command, is_request);
    let variable = payload.get(fixed_len..).ok_or(PduError::OutOfBounds)?;
    Ok(variable.to_vec())
}

fn fixed_payload_len(command: Smb2Command, is_request: bool) -> usize {
    let sizes = smb2_get_fixed_sizes(command);
    let size = if is_request {
        sizes.request
    } else {
        sizes.reply
    };
    size & !1
}

fn pdu_packet_size(pdu: &Pdu) -> PduResult<usize> {
    payload_bytes(pdu).map(|payload| SMB2_HEADER_SIZE + payload.len())
}

fn pdu_packet_bytes(pdu: &Pdu) -> PduResult<Vec<u8>> {
    let payload = payload_bytes(pdu)?;
    let mut packet = Vec::with_capacity(SMB2_HEADER_SIZE + payload.len());
    if first_vector_is_header(&pdu.out) {
        packet.extend_from_slice(&pdu.out.vectors[0].buf[..SMB2_HEADER_SIZE]);
    } else {
        let mut header = vec![0; SMB2_HEADER_SIZE];
        smb2_encode_header_bytes(&mut header, &pdu.header)?;
        packet.extend_from_slice(&header);
    }
    packet.extend_from_slice(&payload);
    Ok(packet)
}

fn next_command_limit(pdu: &Pdu) -> Option<usize> {
    usize::try_from(pdu.header.next_command)
        .ok()
        .filter(|value| *value != 0)
}

fn payload_bytes(pdu: &Pdu) -> PduResult<Vec<u8>> {
    if !pdu.input.vectors.is_empty() {
        return Ok(join_vectors(&pdu.input, 0));
    }

    if pdu.out.vectors.is_empty() {
        return Err(PduError::MissingPdu);
    }

    let start = usize::from(first_vector_is_header(&pdu.out));
    Ok(join_vectors(&pdu.out, start))
}

fn join_vectors(vectors: &IoVectors, start: usize) -> Vec<u8> {
    let len = vectors
        .vectors
        .iter()
        .skip(start)
        .map(|iov| iov.buf.len())
        .sum();
    let mut out = Vec::with_capacity(len);
    for iov in vectors.vectors.iter().skip(start) {
        out.extend_from_slice(&iov.buf);
    }
    out
}

fn read_fixed_u16(fixed: &[u8], offset: usize) -> PduResult<u16> {
    fixed_bytes::<2>(fixed, offset).map(u16::from_le_bytes)
}

fn variable_prefix(variable: &[u8], len: u16) -> PduResult<&[u8]> {
    variable
        .get(..usize::from(len))
        .ok_or(PduError::OutOfBounds)
}

fn encode_queued_pdu(
    context: &mut Context,
    pdu: &mut Pdu,
    prev_compound_mid: &mut u64,
) -> PduResult<()> {
    if context.is_server() {
        pdu.header.flags |= SMB2_FLAGS_SERVER_TO_REDIR;
    } else {
        pdu.prev_compound_mid = *prev_compound_mid;
    }

    ensure_header_vector(pdu);
    let Some(first) = pdu.out.vectors.first_mut() else {
        return Err(PduError::MissingPdu);
    };
    smb2_encode_header(context, &mut first.buf, &mut pdu.header)?;
    pdu.out.total_size = vectors_total_len(&pdu.out);
    *prev_compound_mid = pdu.header.message_id;
    if let Some(next) = pdu.next_compound.as_deref_mut() {
        encode_queued_pdu(context, next, prev_compound_mid)?;
    }
    Ok(())
}

fn ensure_header_vector(pdu: &mut Pdu) {
    if pdu.out.vectors.is_empty() {
        pdu.out.vectors.push(IoVec {
            buf: vec![0; SMB2_HEADER_SIZE],
        });
        pdu.out.total_size = vectors_total_len(&pdu.out);
        return;
    }

    if first_vector_is_header(&pdu.out) {
        let Some(first) = pdu.out.vectors.first_mut() else {
            return;
        };
        if first.buf.len() < SMB2_HEADER_SIZE {
            first.buf.resize(SMB2_HEADER_SIZE, 0);
        }
    } else {
        pdu.out.vectors.insert(
            0,
            IoVec {
                buf: vec![0; SMB2_HEADER_SIZE],
            },
        );
    }
    pdu.out.total_size = vectors_total_len(&pdu.out);
}

fn first_vector_is_header(vectors: &IoVectors) -> bool {
    let Some(first) = vectors.vectors.first() else {
        return false;
    };
    first.buf.len() >= SMB2_HEADER_SIZE
        && matches!(
            fixed_bytes::<4>(&first.buf, 0),
            Ok(protocol_id) if protocol_id == SMB2_PROTOCOL_ID || protocol_id == SMB1_PROTOCOL_ID
        )
}

fn smb2_tree_id(context: &Context) -> Option<u32> {
    context.tree_ids.first().copied()
}

fn credit_request_response(context: &Context) -> u16 {
    let requested = MAX_CREDITS.saturating_sub(context.credits).max(0);
    u16::try_from(requested).map_or(u16::MAX, |value| value)
}

fn vectors_total_len(vectors: &IoVectors) -> usize {
    vectors.vectors.iter().map(|iov| iov.buf.len()).sum()
}

fn fixed_bytes<const N: usize>(buf: &[u8], offset: usize) -> PduResult<[u8; N]> {
    let end = offset.checked_add(N).ok_or(PduError::OutOfBounds)?;
    let Some(bytes) = buf.get(offset..end) else {
        return Err(PduError::OutOfBounds);
    };
    let mut out = [0; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn write_bytes(buf: &mut [u8], offset: usize, bytes: &[u8]) -> PduResult<()> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(PduError::OutOfBounds)?;
    let Some(target) = buf.get_mut(offset..end) else {
        return Err(PduError::OutOfBounds);
    };
    target.copy_from_slice(bytes);
    Ok(())
}
