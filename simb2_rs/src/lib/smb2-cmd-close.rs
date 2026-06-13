//! CLOSE command pack/unpack skeleton migrated from `lib/smb2-cmd-close.c`.

use crate::include::libsmb2_private::{IoVec, IoVectors, Pdu, Smb2Header, SMB2_SIGNATURE_SIZE};
use crate::include::smb2::libsmb2::{CommandCallback, ErrorCode, Result};
use crate::include::smb2::smb2::{Command, SMB2_PROTOCOL_ID};

/// Size of an SMB2 file identifier in bytes.
pub const SMB2_FD_SIZE: usize = 16;
/// Fixed `CLOSE` request structure size from `SMB2_CLOSE_REQUEST_SIZE`.
pub const SMB2_CLOSE_REQUEST_SIZE: u16 = 24;
/// Fixed `CLOSE` reply structure size from `SMB2_CLOSE_REPLY_SIZE`.
pub const SMB2_CLOSE_REPLY_SIZE: u16 = 60;

const CLOSE_REQUEST_WIRE_SIZE: usize = (SMB2_CLOSE_REQUEST_SIZE & 0xfffe) as usize;
const CLOSE_REPLY_WIRE_SIZE: usize = (SMB2_CLOSE_REPLY_SIZE & 0xfffe) as usize;
const EINVAL: i32 = -22;

/// Rust representation of `struct smb2_close_request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2CloseRequest {
    /// CLOSE request flags.
    pub flags: u16,
    /// Raw SMB2 file id copied at offset 8 in the fixed request body.
    pub file_id: [u8; SMB2_FD_SIZE],
}

impl Smb2CloseRequest {
    /// Creates a CLOSE request skeleton for the supplied SMB2 file id.
    #[must_use]
    pub fn new(flags: u16, file_id: [u8; SMB2_FD_SIZE]) -> Self {
        Self { flags, file_id }
    }

    /// Encodes the fixed CLOSE request body.
    ///
    /// # Errors
    ///
    /// This skeleton currently returns only infallible fixed-size encoding results.
    pub fn encode_fixed(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0; CLOSE_REQUEST_WIRE_SIZE];
        put_u16(&mut buf, 0, SMB2_CLOSE_REQUEST_SIZE)?;
        put_u16(&mut buf, 2, self.flags)?;
        put_bytes(&mut buf, 8, &self.file_id)?;
        Ok(buf)
    }

    /// Decodes the fixed CLOSE request body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` when `buf` does not match the fixed request size.
    pub fn decode_fixed(buf: &[u8]) -> Result<Self> {
        validate_fixed_size(buf, SMB2_CLOSE_REQUEST_SIZE, CLOSE_REQUEST_WIRE_SIZE)?;

        let mut file_id = [0; SMB2_FD_SIZE];
        file_id.copy_from_slice(get_bytes(buf, 8, SMB2_FD_SIZE)?);

        Ok(Self {
            flags: get_u16(buf, 2)?,
            file_id,
        })
    }
}

/// Rust representation of `struct smb2_close_reply`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Smb2CloseReply {
    /// CLOSE reply flags.
    pub flags: u16,
    /// File creation time in SMB2 timestamp units.
    pub creation_time: u64,
    /// Last access time in SMB2 timestamp units.
    pub last_access_time: u64,
    /// Last write time in SMB2 timestamp units.
    pub last_write_time: u64,
    /// Last metadata change time in SMB2 timestamp units.
    pub change_time: u64,
    /// Allocated file size in bytes.
    pub allocation_size: u64,
    /// End-of-file position in bytes.
    pub end_of_file: u64,
    /// SMB2 file attribute bitmask.
    pub file_attributes: u32,
}

impl Smb2CloseReply {
    /// Encodes the fixed CLOSE reply body.
    ///
    /// # Errors
    ///
    /// This skeleton currently returns only infallible fixed-size encoding results.
    pub fn encode_fixed(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0; CLOSE_REPLY_WIRE_SIZE];
        put_u16(&mut buf, 0, SMB2_CLOSE_REPLY_SIZE)?;
        put_u16(&mut buf, 2, self.flags)?;
        put_u64(&mut buf, 8, self.creation_time)?;
        put_u64(&mut buf, 16, self.last_access_time)?;
        put_u64(&mut buf, 24, self.last_write_time)?;
        put_u64(&mut buf, 32, self.change_time)?;
        put_u64(&mut buf, 40, self.allocation_size)?;
        put_u64(&mut buf, 48, self.end_of_file)?;
        put_u32(&mut buf, 56, self.file_attributes)?;
        Ok(buf)
    }

    /// Decodes the fixed CLOSE reply body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` when `buf` does not match the fixed reply size.
    pub fn decode_fixed(buf: &[u8]) -> Result<Self> {
        validate_fixed_size(buf, SMB2_CLOSE_REPLY_SIZE, CLOSE_REPLY_WIRE_SIZE)?;

        Ok(Self {
            flags: get_u16(buf, 2)?,
            creation_time: get_u64(buf, 8)?,
            last_access_time: get_u64(buf, 16)?,
            last_write_time: get_u64(buf, 24)?,
            change_time: get_u64(buf, 32)?,
            allocation_size: get_u64(buf, 40)?,
            end_of_file: get_u64(buf, 48)?,
            file_attributes: get_u32(buf, 56)?,
        })
    }
}

/// Decoded payload kind produced by the CLOSE fixed-body processors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smb2ClosePayload {
    /// Fixed CLOSE request payload.
    Request(Smb2CloseRequest),
    /// Fixed CLOSE reply payload.
    Reply(Smb2CloseReply),
}

/// Builds a CLOSE request PDU skeleton matching `smb2_cmd_close_async`.
///
/// # Errors
///
/// Returns an error if fixed request encoding fails.
pub fn smb2_cmd_close_async(
    req: &Smb2CloseRequest,
    callback: Option<CommandCallback>,
) -> Result<Pdu> {
    let out = iovectors_from_fixed(req.encode_fixed()?);
    Ok(Pdu {
        header: close_header(),
        out,
        input: IoVectors::default(),
        callback,
        compound: false,
        timeout: None,
    })
}

/// Builds a CLOSE reply PDU skeleton matching `smb2_cmd_close_reply_async`.
///
/// # Errors
///
/// Returns an error if fixed reply encoding fails.
pub fn smb2_cmd_close_reply_async(
    rep: &Smb2CloseReply,
    callback: Option<CommandCallback>,
) -> Result<Pdu> {
    let out = iovectors_from_fixed(rep.encode_fixed()?);
    Ok(Pdu {
        header: close_header(),
        out,
        input: IoVectors::default(),
        callback,
        compound: false,
        timeout: None,
    })
}

/// Processes a fixed CLOSE reply body and returns the decoded payload skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the fixed body size or structure size is invalid.
pub fn smb2_process_close_fixed(buf: &[u8]) -> Result<Smb2ClosePayload> {
    Smb2CloseReply::decode_fixed(buf).map(Smb2ClosePayload::Reply)
}

/// Processes a fixed CLOSE request body and returns the decoded payload skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the fixed body size or structure size is invalid.
pub fn smb2_process_close_request_fixed(buf: &[u8]) -> Result<Smb2ClosePayload> {
    Smb2CloseRequest::decode_fixed(buf).map(Smb2ClosePayload::Request)
}

fn close_header() -> Smb2Header {
    Smb2Header {
        protocol_id: SMB2_PROTOCOL_ID,
        struct_size: 64,
        credit_charge: 0,
        status: 0,
        command: Command::Close as u16,
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

fn put_u32(buf: &mut [u8], offset: usize, value: u32) -> Result<()> {
    put_bytes(buf, offset, &value.to_le_bytes())
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) -> Result<()> {
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
    match buf.get(offset..offset.saturating_add(len)) {
        Some(src) if src.len() == len => Ok(src),
        _ => Err(ErrorCode(EINVAL)),
    }
}
