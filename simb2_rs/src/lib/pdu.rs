//! PDU allocation, queueing, packing, and unpacking migrated from `lib/pdu.c`.

use crate::include::libsmb2_private::{
    Context, IoVec, IoVectors, Smb2Header, SMB2_HEADER_SIZE, SMB2_SIGNATURE_SIZE,
};
use crate::include::smb2::libsmb2::CommandCallback;

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
pub const MAX_CREDITS: i32 = 256;

/// Maximum tree-id nesting tracked by the legacy context.
pub const SMB2_MAX_TREE_NESTING: usize = 16;

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
    Smb2Header {
        protocol_id: SMB2_PROTOCOL_ID,
        struct_size: SMB2_HEADER_STRUCT_SIZE,
        credit_charge: 0,
        status: 0,
        command: command.as_u16(),
        credit_request_response: 0,
        flags: 0,
        next_command: 0,
        message_id: 0,
        process_id: 0xfeff,
        tree_id: 0,
        async_id: 0,
        session_id: 0,
        signature: [0; SMB2_SIGNATURE_SIZE],
    }
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

    let mut header_bytes = vec![0; SMB2_HEADER_SIZE];
    encode_header_bytes_lossless(&mut header_bytes, &header);

    Pdu {
        header,
        out: IoVectors {
            done: 0,
            total_size: SMB2_HEADER_SIZE,
            vectors: vec![IoVec { buf: header_bytes }],
        },
        input: IoVectors::default(),
        callback,
        compound: false,
        timeout: None,
    }
}

/// Pads an I/O vector list to the next 64-bit boundary using zero bytes.
pub fn smb2_pad_to_64bit(vectors: &mut IoVectors) -> usize {
    let len = vectors_total_len(vectors);
    let pad = (8 - (len & 0x07)) & 0x07;
    if pad > 0 {
        vectors.vectors.push(IoVec { buf: vec![0; pad] });
        vectors.total_size = len + pad;
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

/// Queues a PDU in the outgoing context queue after encoding its header vector.
pub fn smb2_queue_pdu(context: &mut Context, mut pdu: Pdu) {
    if let Some(first) = pdu.out.vectors.first_mut() {
        if first.buf.len() < SMB2_HEADER_SIZE {
            first.buf.resize(SMB2_HEADER_SIZE, 0);
        }
        let _result = smb2_encode_header_bytes(&mut first.buf, &pdu.header);
    }
    context.outqueue.push(pdu);
}

/// Returns the next compound PDU placeholder, if the skeleton has one.
pub const fn smb2_get_compound_pdu(_pdu: &Pdu) -> Option<&Pdu> {
    None
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
    context
        .waitqueue
        .iter()
        .find(|pdu| pdu.header.message_id == message_id)
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

/// Returns placeholder fixed request/reply sizes for a command.
pub const fn smb2_get_fixed_sizes(command: Smb2Command) -> FixedSizes {
    let request = match command {
        Smb2Command::OplockBreak => 2,
        Smb2Command::Cancel => 4,
        _ => 0,
    };
    let reply = match command {
        Smb2Command::OplockBreak => 2,
        Smb2Command::Cancel => 0,
        _ => 0,
    };
    FixedSizes { request, reply }
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

/// Skeleton for fixed reply payload processing.
pub fn smb2_process_reply_payload_fixed(context: &Context, pdu: &Pdu) -> PduResult<()> {
    process_payload_stub(context, pdu)
}

/// Skeleton for variable reply payload processing.
pub fn smb2_process_reply_payload_variable(context: &Context, pdu: &Pdu) -> PduResult<()> {
    process_payload_stub(context, pdu)
}

/// Skeleton for fixed request payload processing.
pub fn smb2_process_request_payload_fixed(context: &Context, pdu: &Pdu) -> PduResult<()> {
    process_payload_stub(context, pdu)
}

/// Skeleton for variable request payload processing.
pub fn smb2_process_request_payload_variable(context: &Context, pdu: &Pdu) -> PduResult<()> {
    process_payload_stub(context, pdu)
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

fn process_payload_stub(_context: &Context, pdu: &Pdu) -> PduResult<()> {
    if Smb2Command::from_raw(pdu.header.command).is_some() {
        Ok(())
    } else {
        Err(PduError::MissingPdu)
    }
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

fn encode_header_bytes_lossless(buf: &mut [u8], header: &Smb2Header) {
    if buf.len() < SMB2_HEADER_SIZE {
        return;
    }
    buf[0..4].copy_from_slice(&header.protocol_id);
    buf[4..6].copy_from_slice(&header.struct_size.to_le_bytes());
    buf[6..8].copy_from_slice(&header.credit_charge.to_le_bytes());
    buf[8..12].copy_from_slice(&header.status.to_le_bytes());
    buf[12..14].copy_from_slice(&header.command.to_le_bytes());
    buf[14..16].copy_from_slice(&header.credit_request_response.to_le_bytes());
    buf[16..20].copy_from_slice(&header.flags.to_le_bytes());
    buf[20..24].copy_from_slice(&header.next_command.to_le_bytes());
    buf[24..32].copy_from_slice(&header.message_id.to_le_bytes());
    if header.flags & SMB2_FLAGS_ASYNC_COMMAND != 0 {
        buf[32..40].copy_from_slice(&header.async_id.to_le_bytes());
    } else {
        buf[32..36].copy_from_slice(&header.process_id.to_le_bytes());
        buf[36..40].copy_from_slice(&header.tree_id.to_le_bytes());
    }
    buf[40..48].copy_from_slice(&header.session_id.to_le_bytes());
    buf[48..64].copy_from_slice(&header.signature);
}
