//! ERROR response pack/unpack skeleton migrated from `lib/smb2-cmd-error.c`.

use crate::include::libsmb2_private::{IoVec, IoVectors, Pdu, Smb2Header};
use crate::include::smb2::libsmb2::{CommandCallback, ErrorCode, Result};

/// Fixed `ERROR` reply structure size from `SMB2_ERROR_REPLY_SIZE`.
pub const SMB2_ERROR_REPLY_SIZE: u16 = 9;

const ERROR_REPLY_FIXED_WIRE_SIZE: usize = (SMB2_ERROR_REPLY_SIZE & 0xfffe) as usize;
const EINVAL: i32 = -22;

/// Rust-owned representation of `struct smb2_error_reply`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Smb2ErrorReply {
    /// Number of SMB2 error contexts carried by the reply.
    pub error_context_count: u8,
    /// Length in bytes of the variable error data following the fixed body.
    pub byte_count: u32,
    /// Optional variable error data referenced by the legacy C reply.
    pub error_data: Vec<u8>,
}

impl Smb2ErrorReply {
    /// Creates an ERROR reply skeleton with no variable error data.
    #[must_use]
    pub const fn new(error_context_count: u8, byte_count: u32) -> Self {
        Self {
            error_context_count,
            byte_count,
            error_data: Vec::new(),
        }
    }

    /// Returns a copy of this reply with owned variable error data attached.
    #[must_use]
    pub fn with_error_data(mut self, error_data: Vec<u8>) -> Self {
        self.error_data = error_data;
        self
    }

    /// Encodes the fixed ERROR reply body.
    ///
    /// The legacy C encoder writes only the fixed fields; variable error data is
    /// represented by [`Smb2ErrorReply::error_data`] but not serialized here.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if a fixed-field offset falls outside the buffer.
    pub fn encode_fixed(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0; ERROR_REPLY_FIXED_WIRE_SIZE];
        put_u16(&mut buf, 0, SMB2_ERROR_REPLY_SIZE)?;
        put_u8(&mut buf, 2, self.error_context_count)?;
        put_u32(&mut buf, 4, self.byte_count)?;
        Ok(buf)
    }

    /// Decodes the fixed ERROR reply body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` when the buffer length or structure size does not
    /// match the fixed ERROR reply body expected by the legacy decoder.
    pub fn decode_fixed(buf: &[u8]) -> Result<Self> {
        validate_fixed_size(buf)?;

        Ok(Self {
            error_context_count: get_u8(buf, 2)?,
            byte_count: get_u32(buf, 4)?,
            error_data: Vec::new(),
        })
    }

    /// Attaches the variable ERROR reply data that follows the fixed body.
    pub fn set_error_data(&mut self, error_data: &[u8]) {
        self.error_data.clear();
        self.error_data.extend_from_slice(error_data);
    }
}

/// Decoded payload kind produced by ERROR reply processors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Smb2ErrorPayload {
    /// Fixed ERROR reply payload, without variable error data attached.
    Fixed(Smb2ErrorReply),
    /// ERROR reply payload after variable error data has been associated.
    Variable(Smb2ErrorReply),
}

/// Builds an ERROR reply PDU skeleton matching `smb2_cmd_error_reply_async`.
///
/// # Errors
///
/// Returns an error if fixed ERROR reply encoding fails.
pub fn smb2_cmd_error_reply_async(
    rep: &Smb2ErrorReply,
    causing_command: u8,
    status: u32,
    callback: Option<CommandCallback>,
) -> Result<Pdu> {
    let out = iovectors_from_reply(rep, rep.encode_fixed()?);
    Ok(Pdu::from_parts(
        error_reply_header(causing_command, status),
        out,
        callback,
    ))
}

/// Encodes the fixed ERROR reply body, mirroring `smb2_encode_error_reply`.
///
/// # Errors
///
/// Returns an error if fixed ERROR reply encoding fails.
pub fn smb2_encode_error_reply(rep: &Smb2ErrorReply) -> Result<Vec<u8>> {
    rep.encode_fixed()
}

/// Processes a fixed ERROR reply body and returns the decoded payload skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the fixed body size or structure size is invalid.
pub fn smb2_process_error_fixed(buf: &[u8]) -> Result<Smb2ErrorPayload> {
    Smb2ErrorReply::decode_fixed(buf).map(Smb2ErrorPayload::Fixed)
}

/// Attaches variable ERROR reply bytes to a decoded ERROR reply skeleton.
#[must_use]
pub fn smb2_process_error_variable(mut rep: Smb2ErrorReply, error_data: &[u8]) -> Smb2ErrorPayload {
    rep.set_error_data(error_data);
    Smb2ErrorPayload::Variable(rep)
}

fn error_reply_header(causing_command: u8, status: u32) -> Smb2Header {
    Smb2Header {
        credit_charge: 0,
        status,
        command: u16::from(causing_command),
        credit_request_response: 0,
        flags: 0,
        next_command: 0,
        message_id: 0,
        process_id: 0,
        tree_id: 0,
        async_id: 0,
        session_id: 0,
        ..Smb2Header::default()
    }
}

fn iovectors_from_reply(rep: &Smb2ErrorReply, fixed: Vec<u8>) -> IoVectors {
    let mut vectors = vec![IoVec { buf: fixed }];
    if !rep.error_data.is_empty() {
        vectors.push(IoVec {
            buf: rep.error_data.clone(),
        });
    }
    let total_size = vectors.iter().map(IoVec::len).sum();
    IoVectors {
        done: 0,
        total_size,
        vectors,
    }
}

fn validate_fixed_size(buf: &[u8]) -> Result<()> {
    if buf.len() != ERROR_REPLY_FIXED_WIRE_SIZE || get_u16(buf, 0)? != SMB2_ERROR_REPLY_SIZE {
        return Err(ErrorCode(EINVAL));
    }
    Ok(())
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

fn put_bytes(buf: &mut [u8], offset: usize, value: &[u8]) -> Result<()> {
    match buf.get_mut(offset..offset.saturating_add(value.len())) {
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

fn get_bytes(buf: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    match buf.get(offset..offset.saturating_add(len)) {
        Some(src) if src.len() == len => Ok(src),
        _ => Err(ErrorCode(EINVAL)),
    }
}
