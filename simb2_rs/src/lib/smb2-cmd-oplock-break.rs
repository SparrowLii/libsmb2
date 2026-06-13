//! OPLOCK_BREAK command pack/unpack skeleton migrated from `lib/smb2-cmd-oplock-break.c`.

use crate::include::libsmb2_private::{IoVec, IoVectors, Pdu, Smb2Header, SMB2_SIGNATURE_SIZE};
use crate::include::smb2::libsmb2::{CommandCallback, ErrorCode, Result};
use crate::include::smb2::smb2::{Command, SMB2_PROTOCOL_ID};

/// Size of an SMB2 file identifier in bytes.
pub const SMB2_FD_SIZE: usize = 16;
/// Size of an SMB2 lease key in bytes.
pub const SMB2_LEASE_KEY_SIZE: usize = 16;

/// Oplock level indicating no oplock is held.
pub const SMB2_OPLOCK_LEVEL_NONE: u8 = 0x00;
/// Oplock level for level-II shared caching.
pub const SMB2_OPLOCK_LEVEL_II: u8 = 0x01;
/// Oplock level for exclusive caching.
pub const SMB2_OPLOCK_LEVEL_EXCLUSIVE: u8 = 0x08;

/// Lease state indicating no lease is held.
pub const SMB2_LEASE_NONE: u32 = 0x00;
/// Lease state bit for read caching.
pub const SMB2_LEASE_READ_CACHING: u32 = 0x01;
/// Lease state bit for handle caching.
pub const SMB2_LEASE_HANDLE_CACHING: u32 = 0x02;
/// Lease state bit for write caching.
pub const SMB2_LEASE_WRITE_CACHING: u32 = 0x04;

/// Fixed `StructureSize` for oplock break notifications.
pub const SMB2_OPLOCK_BREAK_NOTIFICATION_SIZE: u16 = 24;
/// Fixed `StructureSize` for oplock break acknowledgements.
pub const SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE: u16 = 24;
/// Fixed `StructureSize` for oplock break replies.
pub const SMB2_OPLOCK_BREAK_REPLY_SIZE: u16 = 24;
/// Fixed `StructureSize` for lease break notifications.
pub const SMB2_LEASE_BREAK_NOTIFICATION_SIZE: u16 = 44;
/// Fixed `StructureSize` for lease break acknowledgements.
pub const SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE: u16 = 36;
/// Fixed `StructureSize` for lease break replies.
pub const SMB2_LEASE_BREAK_REPLY_SIZE: u16 = 36;

const OPLOCK_BREAK_WIRE_SIZE: usize = (SMB2_OPLOCK_BREAK_REPLY_SIZE & 0xfffe) as usize;
const LEASE_BREAK_ACKNOWLEDGE_WIRE_SIZE: usize =
    (SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE & 0xfffe) as usize;
const LEASE_BREAK_REPLY_WIRE_SIZE: usize = (SMB2_LEASE_BREAK_REPLY_SIZE & 0xfffe) as usize;
const LEASE_BREAK_NOTIFICATION_WIRE_SIZE: usize =
    (SMB2_LEASE_BREAK_NOTIFICATION_SIZE & 0xfffe) as usize;
const EINVAL: i32 = -22;
const ASYNC_NOTIFICATION_MESSAGE_ID: u64 = u64::MAX;

/// Break payload type mirrored from the `SMB2_BREAK_TYPE_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Smb2BreakType {
    /// Server oplock break notification.
    OplockNotification = 0x01,
    /// Server oplock break response.
    OplockResponse = 0x02,
    /// Client oplock break acknowledgement.
    OplockAcknowledge = 0x03,
    /// Server lease break notification.
    LeaseNotification = 0x04,
    /// Server lease break response.
    LeaseResponse = 0x05,
    /// Client lease break acknowledgement.
    LeaseAcknowledge = 0x06,
}

/// SMB2 file identifier used by oplock break messages.
pub type Smb2FileId = [u8; SMB2_FD_SIZE];

/// SMB2 lease key used by lease break messages.
pub type Smb2LeaseKey = [u8; SMB2_LEASE_KEY_SIZE];

/// Rust representation shared by oplock break notification, reply, and acknowledgement bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2OplockBreakBody {
    /// Oplock level carried at fixed-body offset 2.
    pub oplock_level: u8,
    /// File identifier carried at fixed-body offset 8.
    pub file_id: Smb2FileId,
}

impl Smb2OplockBreakBody {
    /// Creates an oplock break body skeleton.
    #[must_use]
    pub const fn new(oplock_level: u8, file_id: Smb2FileId) -> Self {
        Self {
            oplock_level,
            file_id,
        }
    }

    /// Encodes the fixed oplock break body with the requested SMB2 structure size.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the fixed buffer cannot contain the C field layout.
    pub fn encode_fixed(&self, structure_size: u16) -> Result<Vec<u8>> {
        let mut buf = vec![0; OPLOCK_BREAK_WIRE_SIZE];
        put_u16(&mut buf, 0, structure_size)?;
        put_u8(&mut buf, 2, self.oplock_level)?;
        put_bytes(&mut buf, 8, &self.file_id)?;
        Ok(buf)
    }

    /// Decodes an oplock break body after the fixed structure size has been validated.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if `buf` is too short for the oplock field layout.
    pub fn decode_fixed(buf: &[u8]) -> Result<Self> {
        let mut file_id = [0; SMB2_FD_SIZE];
        file_id.copy_from_slice(get_bytes(buf, 8, SMB2_FD_SIZE)?);
        Ok(Self {
            oplock_level: get_u8(buf, 2)?,
            file_id,
        })
    }

    /// Decodes an oplock break variable body after the two-byte structure size has been consumed.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if `variable` is too short for the legacy `-2` offsets.
    pub fn decode_variable(variable: &[u8]) -> Result<Self> {
        let mut file_id = [0; SMB2_FD_SIZE];
        file_id.copy_from_slice(get_bytes(variable, 6, SMB2_FD_SIZE)?);
        Ok(Self {
            oplock_level: get_u8(variable, 0)?,
            file_id,
        })
    }
}

/// Rust counterpart of `struct smb2_oplock_break_acknowledgement`.
pub type Smb2OplockBreakAcknowledgement = Smb2OplockBreakBody;
/// Rust counterpart of `struct smb2_oplock_break_reply`.
pub type Smb2OplockBreakReply = Smb2OplockBreakBody;
/// Rust counterpart of `struct smb2_oplock_break_notification`.
pub type Smb2OplockBreakNotification = Smb2OplockBreakBody;

/// Rust representation shared by lease break acknowledgement and reply bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2LeaseBreakBody {
    /// Lease break flags.
    pub flags: u32,
    /// Lease key identifying the lease being broken.
    pub lease_key: Smb2LeaseKey,
    /// Lease state requested or confirmed by the peer.
    pub lease_state: u32,
    /// Lease duration field preserved from the C structure.
    pub lease_duration: u64,
}

impl Smb2LeaseBreakBody {
    /// Creates a lease break acknowledgement or reply body skeleton.
    #[must_use]
    pub const fn new(
        flags: u32,
        lease_key: Smb2LeaseKey,
        lease_state: u32,
        lease_duration: u64,
    ) -> Self {
        Self {
            flags,
            lease_key,
            lease_state,
            lease_duration,
        }
    }

    /// Encodes the fixed lease break acknowledgement or reply body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the fixed buffer cannot contain the C field layout.
    pub fn encode_fixed(&self, structure_size: u16) -> Result<Vec<u8>> {
        let wire_size = if structure_size == SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE {
            LEASE_BREAK_ACKNOWLEDGE_WIRE_SIZE
        } else {
            LEASE_BREAK_REPLY_WIRE_SIZE
        };
        let mut buf = vec![0; wire_size];
        put_u16(&mut buf, 0, structure_size)?;
        put_u32(&mut buf, 4, self.flags)?;
        put_bytes(&mut buf, 8, &self.lease_key)?;
        put_u32(&mut buf, 24, self.lease_state)?;
        put_u64(&mut buf, 28, self.lease_duration)?;
        Ok(buf)
    }

    /// Decodes a fixed lease break acknowledgement or reply body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if `buf` is too short for the lease break layout.
    pub fn decode_fixed(buf: &[u8]) -> Result<Self> {
        let mut lease_key = [0; SMB2_LEASE_KEY_SIZE];
        lease_key.copy_from_slice(get_bytes(buf, 8, SMB2_LEASE_KEY_SIZE)?);
        Ok(Self {
            flags: get_u32(buf, 4)?,
            lease_key,
            lease_state: get_u32(buf, 24)?,
            lease_duration: get_u64(buf, 28)?,
        })
    }

    /// Decodes a lease break variable body after the two-byte structure size has been consumed.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if `variable` is too short for the legacy `-2` offsets.
    pub fn decode_variable(variable: &[u8]) -> Result<Self> {
        let mut lease_key = [0; SMB2_LEASE_KEY_SIZE];
        lease_key.copy_from_slice(get_bytes(variable, 6, SMB2_LEASE_KEY_SIZE)?);
        Ok(Self {
            flags: get_u32(variable, 2)?,
            lease_key,
            lease_state: get_u32(variable, 22)?,
            lease_duration: get_u64(variable, 26)?,
        })
    }
}

/// Rust counterpart of `struct smb2_lease_break_acknowledgement`.
pub type Smb2LeaseBreakAcknowledgement = Smb2LeaseBreakBody;
/// Rust counterpart of `struct smb2_lease_break_reply`.
pub type Smb2LeaseBreakReply = Smb2LeaseBreakBody;

/// Rust counterpart of `struct smb2_lease_break_notification`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2LeaseBreakNotification {
    /// New lease epoch supplied by the server.
    pub new_epoch: u16,
    /// Lease break flags.
    pub flags: u32,
    /// Lease key identifying the lease being broken.
    pub lease_key: Smb2LeaseKey,
    /// Current lease state before the break.
    pub current_lease_state: u32,
    /// New lease state requested by the break.
    pub new_lease_state: u32,
    /// Server-provided break reason.
    pub break_reason: u32,
    /// Access mask hint associated with the break.
    pub access_mask_hint: u32,
    /// Share mask hint associated with the break.
    pub share_mask_hint: u32,
}

impl Smb2LeaseBreakNotification {
    /// Encodes the fixed lease break notification body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the fixed buffer cannot contain the C field layout.
    pub fn encode_fixed(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0; LEASE_BREAK_NOTIFICATION_WIRE_SIZE];
        put_u16(&mut buf, 0, SMB2_LEASE_BREAK_NOTIFICATION_SIZE)?;
        put_u16(&mut buf, 2, self.new_epoch)?;
        put_u32(&mut buf, 4, self.flags)?;
        put_bytes(&mut buf, 8, &self.lease_key)?;
        put_u32(&mut buf, 24, self.current_lease_state)?;
        put_u32(&mut buf, 28, self.new_lease_state)?;
        put_u32(&mut buf, 32, self.break_reason)?;
        put_u32(&mut buf, 36, self.access_mask_hint)?;
        put_u32(&mut buf, 40, self.share_mask_hint)?;
        Ok(buf)
    }

    /// Decodes a fixed lease break notification body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if `buf` is too short for the notification layout.
    pub fn decode_fixed(buf: &[u8]) -> Result<Self> {
        let mut lease_key = [0; SMB2_LEASE_KEY_SIZE];
        lease_key.copy_from_slice(get_bytes(buf, 8, SMB2_LEASE_KEY_SIZE)?);
        Ok(Self {
            new_epoch: get_u16(buf, 2)?,
            flags: get_u32(buf, 4)?,
            lease_key,
            current_lease_state: get_u32(buf, 24)?,
            new_lease_state: get_u32(buf, 28)?,
            break_reason: get_u32(buf, 32)?,
            access_mask_hint: get_u32(buf, 36)?,
            share_mask_hint: get_u32(buf, 40)?,
        })
    }

    /// Decodes a lease break notification after the two-byte structure size has been consumed.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if `variable` is too short for the legacy `-2` offsets.
    pub fn decode_variable(variable: &[u8]) -> Result<Self> {
        let mut lease_key = [0; SMB2_LEASE_KEY_SIZE];
        lease_key.copy_from_slice(get_bytes(variable, 6, SMB2_LEASE_KEY_SIZE)?);
        Ok(Self {
            new_epoch: get_u16(variable, 0)?,
            flags: get_u32(variable, 2)?,
            lease_key,
            current_lease_state: get_u32(variable, 22)?,
            new_lease_state: get_u32(variable, 26)?,
            break_reason: get_u32(variable, 30)?,
            access_mask_hint: get_u32(variable, 34)?,
            share_mask_hint: get_u32(variable, 38)?,
        })
    }
}

/// Decoded oplock or lease break reply/notification payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smb2OplockOrLeaseBreakReplyLock {
    /// Oplock break notification payload.
    OplockNotification(Smb2OplockBreakNotification),
    /// Oplock break response payload.
    OplockResponse(Smb2OplockBreakReply),
    /// Lease break notification payload.
    LeaseNotification(Smb2LeaseBreakNotification),
    /// Lease break response payload.
    LeaseResponse(Smb2LeaseBreakReply),
}

/// Rust counterpart of `struct smb2_oplock_or_lease_break_reply`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2OplockOrLeaseBreakReply {
    /// Structure size read by the fixed reply processor.
    pub struct_size: u16,
    /// Break type selected by the variable reply processor.
    pub break_type: Option<Smb2BreakType>,
    /// Decoded reply or notification body once variable processing has run.
    pub lock: Option<Smb2OplockOrLeaseBreakReplyLock>,
}

impl Smb2OplockOrLeaseBreakReply {
    /// Creates a reply skeleton from a fixed structure size.
    #[must_use]
    pub const fn new(struct_size: u16) -> Self {
        Self {
            struct_size,
            break_type: None,
            lock: None,
        }
    }
}

/// Decoded oplock or lease break request payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smb2OplockOrLeaseBreakRequestLock {
    /// Oplock break acknowledgement payload.
    OplockAcknowledge(Smb2OplockBreakAcknowledgement),
    /// Lease break acknowledgement payload.
    LeaseAcknowledge(Smb2LeaseBreakAcknowledgement),
}

/// Rust counterpart of `struct smb2_oplock_or_lease_break_request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2OplockOrLeaseBreakRequest {
    /// Structure size read by the fixed request processor.
    pub struct_size: u16,
    /// Break type selected by the variable request processor.
    pub break_type: Option<Smb2BreakType>,
    /// Decoded request body once variable processing has run.
    pub lock: Option<Smb2OplockOrLeaseBreakRequestLock>,
}

impl Smb2OplockOrLeaseBreakRequest {
    /// Creates a request skeleton from a fixed structure size.
    #[must_use]
    pub const fn new(struct_size: u16) -> Self {
        Self {
            struct_size,
            break_type: None,
            lock: None,
        }
    }
}

/// Builds an OPLOCK_BREAK acknowledgement PDU skeleton matching `smb2_cmd_oplock_break_async`.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if fixed acknowledgement encoding fails.
pub fn smb2_cmd_oplock_break_async(
    req: &Smb2OplockBreakAcknowledgement,
    callback: Option<CommandCallback>,
) -> Result<Pdu> {
    let fixed = req.encode_fixed(SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE)?;
    Ok(pdu_from_fixed(fixed, callback))
}

/// Builds an OPLOCK_BREAK reply PDU skeleton matching `smb2_cmd_oplock_break_reply_async`.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if fixed reply encoding fails.
pub fn smb2_cmd_oplock_break_reply_async(
    rep: &Smb2OplockBreakReply,
    callback: Option<CommandCallback>,
) -> Result<Pdu> {
    let fixed = rep.encode_fixed(SMB2_OPLOCK_BREAK_REPLY_SIZE)?;
    Ok(pdu_from_fixed(fixed, callback))
}

/// Builds an OPLOCK_BREAK notification PDU skeleton matching `smb2_cmd_oplock_break_notification_async`.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if fixed notification encoding fails.
pub fn smb2_cmd_oplock_break_notification_async(
    rep: &Smb2OplockBreakNotification,
    callback: Option<CommandCallback>,
) -> Result<Pdu> {
    let fixed = rep.encode_fixed(SMB2_OPLOCK_BREAK_NOTIFICATION_SIZE)?;
    Ok(pdu_from_fixed(fixed, callback))
}

/// Builds a lease break acknowledgement PDU skeleton matching `smb2_cmd_lease_break_async`.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if fixed acknowledgement encoding fails.
pub fn smb2_cmd_lease_break_async(
    req: &Smb2LeaseBreakAcknowledgement,
    callback: Option<CommandCallback>,
) -> Result<Pdu> {
    let fixed = req.encode_fixed(SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE)?;
    Ok(pdu_from_fixed(fixed, callback))
}

/// Builds a lease break reply PDU skeleton matching `smb2_cmd_lease_break_reply_async`.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if fixed reply encoding fails.
pub fn smb2_cmd_lease_break_reply_async(
    rep: &Smb2LeaseBreakReply,
    callback: Option<CommandCallback>,
) -> Result<Pdu> {
    let fixed = rep.encode_fixed(SMB2_LEASE_BREAK_REPLY_SIZE)?;
    Ok(pdu_from_fixed(fixed, callback))
}

/// Builds a lease break notification PDU skeleton matching `smb2_cmd_lease_break_notification_async`.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if fixed notification encoding fails.
pub fn smb2_cmd_lease_break_notification_async(
    req: &Smb2LeaseBreakNotification,
    callback: Option<CommandCallback>,
) -> Result<Pdu> {
    let fixed = req.encode_fixed()?;
    Ok(pdu_from_fixed(fixed, callback))
}

/// Processes the fixed reply/notification structure size and returns the remaining body length.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` when `fixed` has an unexpected structure size.
pub fn smb2_process_oplock_break_fixed(
    fixed: &[u8],
) -> Result<(Smb2OplockOrLeaseBreakReply, usize)> {
    let struct_size = get_u16(fixed, 0)?;
    match struct_size {
        SMB2_OPLOCK_BREAK_REPLY_SIZE
        | SMB2_LEASE_BREAK_NOTIFICATION_SIZE
        | SMB2_LEASE_BREAK_REPLY_SIZE => Ok((
            Smb2OplockOrLeaseBreakReply::new(struct_size),
            usize::from(struct_size.saturating_sub(2)),
        )),
        _ => Err(ErrorCode(EINVAL)),
    }
}

/// Processes reply/notification fields after fixed-size validation.
///
/// `message_id` follows the C distinction where `u64::MAX` denotes an async
/// oplock notification and any other value denotes an oplock response.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `variable` does not match the stored structure size.
pub fn smb2_process_oplock_break_variable(
    rep: &mut Smb2OplockOrLeaseBreakReply,
    variable: &[u8],
    message_id: u64,
) -> Result<()> {
    match rep.struct_size {
        SMB2_OPLOCK_BREAK_NOTIFICATION_SIZE => {
            let body = Smb2OplockBreakBody::decode_variable(variable)?;
            if message_id == ASYNC_NOTIFICATION_MESSAGE_ID {
                rep.break_type = Some(Smb2BreakType::OplockNotification);
                rep.lock = Some(Smb2OplockOrLeaseBreakReplyLock::OplockNotification(body));
            } else {
                rep.break_type = Some(Smb2BreakType::OplockResponse);
                rep.lock = Some(Smb2OplockOrLeaseBreakReplyLock::OplockResponse(body));
            }
            Ok(())
        }
        SMB2_LEASE_BREAK_NOTIFICATION_SIZE => {
            rep.break_type = Some(Smb2BreakType::LeaseNotification);
            rep.lock = Some(Smb2OplockOrLeaseBreakReplyLock::LeaseNotification(
                Smb2LeaseBreakNotification::decode_variable(variable)?,
            ));
            Ok(())
        }
        SMB2_LEASE_BREAK_REPLY_SIZE => {
            rep.break_type = Some(Smb2BreakType::LeaseResponse);
            rep.lock = Some(Smb2OplockOrLeaseBreakReplyLock::LeaseResponse(
                Smb2LeaseBreakBody::decode_variable(variable)?,
            ));
            Ok(())
        }
        _ => Err(ErrorCode(EINVAL)),
    }
}

/// Processes the fixed acknowledgement structure size and returns the remaining body length.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` when `fixed` has an unexpected acknowledgement size.
pub fn smb2_process_oplock_break_request_fixed(
    fixed: &[u8],
) -> Result<(Smb2OplockOrLeaseBreakRequest, usize)> {
    let struct_size = get_u16(fixed, 0)?;
    match struct_size {
        SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE | SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE => Ok((
            Smb2OplockOrLeaseBreakRequest::new(struct_size),
            usize::from(struct_size.saturating_sub(2)),
        )),
        _ => Err(ErrorCode(EINVAL)),
    }
}

/// Processes acknowledgement fields after fixed-size validation.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if `variable` does not match the stored structure size.
pub fn smb2_process_oplock_break_request_variable(
    req: &mut Smb2OplockOrLeaseBreakRequest,
    variable: &[u8],
) -> Result<()> {
    match req.struct_size {
        SMB2_OPLOCK_BREAK_ACKNOWLEDGE_SIZE => {
            req.break_type = Some(Smb2BreakType::OplockAcknowledge);
            req.lock = Some(Smb2OplockOrLeaseBreakRequestLock::OplockAcknowledge(
                Smb2OplockBreakBody::decode_variable(variable)?,
            ));
            Ok(())
        }
        SMB2_LEASE_BREAK_ACKNOWLEDGE_SIZE => {
            req.break_type = Some(Smb2BreakType::LeaseAcknowledge);
            req.lock = Some(Smb2OplockOrLeaseBreakRequestLock::LeaseAcknowledge(
                Smb2LeaseBreakBody::decode_variable(variable)?,
            ));
            Ok(())
        }
        _ => Err(ErrorCode(EINVAL)),
    }
}

fn pdu_from_fixed(fixed: Vec<u8>, callback: Option<CommandCallback>) -> Pdu {
    Pdu {
        header: oplock_break_header(),
        out: iovectors_from_fixed(fixed),
        input: IoVectors::default(),
        callback,
        compound: false,
        timeout: None,
    }
}

fn oplock_break_header() -> Smb2Header {
    Smb2Header {
        protocol_id: SMB2_PROTOCOL_ID,
        struct_size: 64,
        credit_charge: 0,
        status: 0,
        command: Command::OplockBreak as u16,
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

fn iovectors_from_fixed(buf: Vec<u8>) -> IoVectors {
    IoVectors {
        done: 0,
        total_size: buf.len(),
        vectors: vec![IoVec { buf }],
    }
}

fn put_u8(buf: &mut [u8], offset: usize, value: u8) -> Result<()> {
    match buf.get_mut(offset) {
        Some(dst) => {
            *dst = value;
            Ok(())
        }
        None => Err(ErrorCode(EINVAL)),
    }
}

fn put_u16(buf: &mut [u8], offset: usize, value: u16) -> Result<()> {
    put_bytes(buf, offset, &value.to_le_bytes())
}

fn put_u32(buf: &mut [u8], offset: usize, value: u32) -> Result<()> {
    put_bytes(buf, offset, &value.to_le_bytes())
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) -> Result<()> {
    put_bytes(buf, offset, &value.to_le_bytes())
}

fn put_bytes(buf: &mut [u8], offset: usize, value: &[u8]) -> Result<()> {
    let Some(end) = offset.checked_add(value.len()) else {
        return Err(ErrorCode(EINVAL));
    };
    match buf.get_mut(offset..end) {
        Some(dst) if dst.len() == value.len() => {
            dst.copy_from_slice(value);
            Ok(())
        }
        _ => Err(ErrorCode(EINVAL)),
    }
}

fn get_u8(buf: &[u8], offset: usize) -> Result<u8> {
    buf.get(offset).copied().ok_or(ErrorCode(EINVAL))
}

fn get_u16(buf: &[u8], offset: usize) -> Result<u16> {
    let bytes = get_bytes(buf, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn get_u32(buf: &[u8], offset: usize) -> Result<u32> {
    let bytes = get_bytes(buf, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn get_u64(buf: &[u8], offset: usize) -> Result<u64> {
    let bytes = get_bytes(buf, offset, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn get_bytes(buf: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    let Some(end) = offset.checked_add(len) else {
        return Err(ErrorCode(EINVAL));
    };
    match buf.get(offset..end) {
        Some(src) if src.len() == len => Ok(src),
        _ => Err(ErrorCode(EINVAL)),
    }
}
