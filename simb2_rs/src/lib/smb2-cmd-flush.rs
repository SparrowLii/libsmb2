//! FLUSH command pack/unpack skeleton migrated from `lib/smb2-cmd-flush.c`.

use crate::include::libsmb2_private::{IoVec, IoVectors, Pdu, Smb2Header, SMB2_SIGNATURE_SIZE};
use crate::include::smb2::libsmb2::{CommandCallback, ErrorCode, Result};
use crate::include::smb2::smb2::{Command, SMB2_PROTOCOL_ID};

/// Size of an SMB2 file identifier in bytes.
pub const SMB2_FD_SIZE: usize = 16;
/// Fixed `FLUSH` request structure size from `SMB2_FLUSH_REQUEST_SIZE`.
pub const SMB2_FLUSH_REQUEST_SIZE: u16 = 24;
/// Fixed `FLUSH` reply structure size from `SMB2_FLUSH_REPLY_SIZE`.
pub const SMB2_FLUSH_REPLY_SIZE: u16 = 4;

const FLUSH_REQUEST_WIRE_SIZE: usize = (SMB2_FLUSH_REQUEST_SIZE & 0xfffe) as usize;
const FLUSH_REPLY_WIRE_SIZE: usize = (SMB2_FLUSH_REPLY_SIZE & 0xfffe) as usize;
const EINVAL: i32 = -22;

/// Rust representation of `struct smb2_flush_request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2FlushRequest {
    /// Raw SMB2 file id copied at offset 8 in the fixed request body.
    pub file_id: [u8; SMB2_FD_SIZE],
}

impl Smb2FlushRequest {
    /// Creates a FLUSH request skeleton for the supplied SMB2 file id.
    #[must_use]
    pub fn new(file_id: [u8; SMB2_FD_SIZE]) -> Self {
        Self { file_id }
    }

    /// Encodes the fixed FLUSH request body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the fixed-size skeleton buffer cannot accept
    /// a field at the legacy C offset.
    pub fn encode_fixed(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0; FLUSH_REQUEST_WIRE_SIZE];
        put_u16(&mut buf, 0, SMB2_FLUSH_REQUEST_SIZE)?;
        put_bytes(&mut buf, 8, &self.file_id)?;
        Ok(buf)
    }

    /// Decodes the fixed FLUSH request body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` when `buf` does not match the fixed request size.
    pub fn decode_fixed(buf: &[u8]) -> Result<Self> {
        validate_fixed_size(buf, SMB2_FLUSH_REQUEST_SIZE, FLUSH_REQUEST_WIRE_SIZE)?;

        let mut file_id = [0; SMB2_FD_SIZE];
        file_id.copy_from_slice(get_bytes(buf, 8, SMB2_FD_SIZE)?);

        Ok(Self { file_id })
    }
}

/// Rust representation of the fixed `FLUSH` reply body.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Smb2FlushReply;

impl Smb2FlushReply {
    /// Creates an empty FLUSH reply skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Encodes the fixed FLUSH reply body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the fixed-size skeleton buffer cannot accept
    /// a field at the legacy C offset.
    pub fn encode_fixed(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0; FLUSH_REPLY_WIRE_SIZE];
        put_u16(&mut buf, 0, SMB2_FLUSH_REPLY_SIZE)?;
        Ok(buf)
    }

    /// Decodes the fixed FLUSH reply body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` when `buf` does not match the fixed reply size.
    pub fn decode_fixed(buf: &[u8]) -> Result<Self> {
        validate_fixed_size(buf, SMB2_FLUSH_REPLY_SIZE, FLUSH_REPLY_WIRE_SIZE)?;
        Ok(Self)
    }
}

/// Decoded payload kind produced by the FLUSH fixed-body processors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smb2FlushPayload {
    /// Fixed FLUSH request payload.
    Request(Smb2FlushRequest),
    /// Fixed FLUSH reply payload.
    Reply(Smb2FlushReply),
}

/// Builds a FLUSH request PDU skeleton matching `smb2_cmd_flush_async`.
///
/// # Errors
///
/// Returns an error if fixed request encoding fails.
pub fn smb2_cmd_flush_async(
    req: &Smb2FlushRequest,
    callback: Option<CommandCallback>,
) -> Result<Pdu> {
    let out = iovectors_from_fixed(req.encode_fixed()?);
    Ok(Pdu {
        header: flush_header(),
        out,
        input: IoVectors::default(),
        callback,
        compound: false,
        timeout: None,
    })
}

/// Builds a FLUSH reply PDU skeleton matching `smb2_cmd_flush_reply_async`.
///
/// # Errors
///
/// Returns an error if fixed reply encoding fails.
pub fn smb2_cmd_flush_reply_async(callback: Option<CommandCallback>) -> Result<Pdu> {
    let out = iovectors_from_fixed(Smb2FlushReply::new().encode_fixed()?);
    Ok(Pdu {
        header: flush_header(),
        out,
        input: IoVectors::default(),
        callback,
        compound: false,
        timeout: None,
    })
}

/// Processes a fixed FLUSH reply body and returns the decoded payload skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the fixed body size or structure size is invalid.
pub fn smb2_process_flush_fixed(buf: &[u8]) -> Result<Smb2FlushPayload> {
    Smb2FlushReply::decode_fixed(buf).map(Smb2FlushPayload::Reply)
}

/// Processes a fixed FLUSH request body and returns the decoded payload skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the fixed body size or structure size is invalid.
pub fn smb2_process_flush_request_fixed(buf: &[u8]) -> Result<Smb2FlushPayload> {
    Smb2FlushRequest::decode_fixed(buf).map(Smb2FlushPayload::Request)
}

fn flush_header() -> Smb2Header {
    Smb2Header {
        protocol_id: SMB2_PROTOCOL_ID,
        struct_size: 64,
        credit_charge: 0,
        status: 0,
        command: Command::Flush as u16,
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

fn validate_fixed_size(buf: &[u8], expected_struct_size: u16, expected_len: usize) -> Result<()> {
    if buf.len() != expected_len || get_u16(buf, 0)? != expected_struct_size {
        return Err(ErrorCode(EINVAL));
    }
    Ok(())
}

fn put_u16(buf: &mut [u8], offset: usize, value: u16) -> Result<()> {
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

fn get_u16(buf: &[u8], offset: usize) -> Result<u16> {
    let bytes = get_bytes(buf, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn get_bytes(buf: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    match buf.get(offset..offset.saturating_add(len)) {
        Some(src) if src.len() == len => Ok(src),
        _ => Err(ErrorCode(EINVAL)),
    }
}
