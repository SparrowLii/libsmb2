//! LOGOFF command pack/unpack skeleton migrated from `lib/smb2-cmd-logoff.c`.

use crate::include::libsmb2_private::{IoVec, IoVectors, Pdu, Smb2Header, SMB2_SIGNATURE_SIZE};
use crate::include::smb2::libsmb2::{CommandCallback, ErrorCode, Result};
use crate::include::smb2::smb2::{Command, SMB2_PROTOCOL_ID};

/// SMB2 command number used by LOGOFF PDUs.
pub const SMB2_LOGOFF: u16 = Command::Logoff as u16;

/// Fixed LOGOFF request structure size from `SMB2_LOGOFF_REQUEST_SIZE`.
pub const SMB2_LOGOFF_REQUEST_SIZE: u16 = 4;

/// Fixed LOGOFF reply structure size from `SMB2_LOGOFF_REPLY_SIZE`.
pub const SMB2_LOGOFF_REPLY_SIZE: u16 = 4;

const LOGOFF_REQUEST_WIRE_SIZE: usize = (SMB2_LOGOFF_REQUEST_SIZE & 0xfffe) as usize;
const LOGOFF_REPLY_WIRE_SIZE: usize = (SMB2_LOGOFF_REPLY_SIZE & 0xfffe) as usize;
const EINVAL: i32 = -22;

/// Rust representation of `struct smb2_logoff_request`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Smb2LogoffRequest {
    /// Reserved field carried at fixed payload offset 2.
    pub reserved: u16,
}

impl Smb2LogoffRequest {
    /// Creates a LOGOFF request skeleton with the reserved field cleared.
    #[must_use]
    pub const fn new() -> Self {
        Self { reserved: 0 }
    }

    /// Creates a LOGOFF request skeleton with an explicit reserved field.
    #[must_use]
    pub const fn with_reserved(reserved: u16) -> Self {
        Self { reserved }
    }

    /// Encodes the fixed LOGOFF request body matching `smb2_encode_logoff_request`.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if fixed-size buffer writes would exceed the buffer.
    pub fn encode_fixed(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0; LOGOFF_REQUEST_WIRE_SIZE];
        put_u16(&mut buf, 0, SMB2_LOGOFF_REQUEST_SIZE)?;
        put_u16(&mut buf, 2, self.reserved)?;
        Ok(buf)
    }

    /// Decodes the fixed LOGOFF request body handled by `smb2_process_logoff_request_fixed`.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` when `buf` does not match the fixed request size.
    pub fn decode_fixed(buf: &[u8]) -> Result<Self> {
        validate_fixed_size(buf, SMB2_LOGOFF_REQUEST_SIZE, LOGOFF_REQUEST_WIRE_SIZE)?;
        Ok(Self {
            reserved: get_u16(buf, 2)?,
        })
    }
}

/// Rust representation of the fixed LOGOFF reply payload.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Smb2LogoffReply {
    /// Reserved field carried at fixed payload offset 2.
    pub reserved: u16,
}

impl Smb2LogoffReply {
    /// Creates a LOGOFF reply skeleton with the reserved field cleared.
    #[must_use]
    pub const fn new() -> Self {
        Self { reserved: 0 }
    }

    /// Creates a LOGOFF reply skeleton with an explicit reserved field.
    #[must_use]
    pub const fn with_reserved(reserved: u16) -> Self {
        Self { reserved }
    }

    /// Encodes the fixed LOGOFF reply body matching `smb2_encode_logoff_reply`.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if fixed-size buffer writes would exceed the buffer.
    pub fn encode_fixed(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0; LOGOFF_REPLY_WIRE_SIZE];
        put_u16(&mut buf, 0, SMB2_LOGOFF_REPLY_SIZE)?;
        put_u16(&mut buf, 2, self.reserved)?;
        Ok(buf)
    }

    /// Decodes the fixed LOGOFF reply body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` when `buf` does not match the fixed reply size.
    pub fn decode_fixed(buf: &[u8]) -> Result<Self> {
        validate_fixed_size(buf, SMB2_LOGOFF_REPLY_SIZE, LOGOFF_REPLY_WIRE_SIZE)?;
        Ok(Self {
            reserved: get_u16(buf, 2)?,
        })
    }
}

/// Decoded payload kind produced by the LOGOFF fixed-body processors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smb2LogoffPayload {
    /// Fixed LOGOFF request payload.
    Request(Smb2LogoffRequest),
    /// Fixed LOGOFF reply payload.
    Reply(Smb2LogoffReply),
}

/// Builds a LOGOFF request PDU skeleton matching `smb2_cmd_logoff_async`.
///
/// # Errors
///
/// Returns an error if fixed request encoding fails.
pub fn smb2_cmd_logoff_async(callback: Option<CommandCallback>) -> Result<Pdu> {
    let request = Smb2LogoffRequest::new();
    let out = iovectors_from_fixed(request.encode_fixed()?);
    Ok(Pdu {
        header: logoff_header(),
        out,
        input: IoVectors::default(),
        callback,
        compound: false,
        timeout: None,
    })
}

/// Builds a LOGOFF reply PDU skeleton matching `smb2_cmd_logoff_reply_async`.
///
/// # Errors
///
/// Returns an error if fixed reply encoding fails.
pub fn smb2_cmd_logoff_reply_async(callback: Option<CommandCallback>) -> Result<Pdu> {
    let reply = Smb2LogoffReply::new();
    let out = iovectors_from_fixed(reply.encode_fixed()?);
    Ok(Pdu {
        header: logoff_header(),
        out,
        input: IoVectors::default(),
        callback,
        compound: false,
        timeout: None,
    })
}

/// Encodes the fixed LOGOFF request body.
///
/// # Errors
///
/// Returns an error if fixed request encoding fails.
pub fn smb2_encode_logoff_request(req: &Smb2LogoffRequest) -> Result<Vec<u8>> {
    req.encode_fixed()
}

/// Encodes the fixed LOGOFF reply body.
///
/// # Errors
///
/// Returns an error if fixed reply encoding fails.
pub fn smb2_encode_logoff_reply(rep: &Smb2LogoffReply) -> Result<Vec<u8>> {
    rep.encode_fixed()
}

/// Processes a fixed LOGOFF reply body and returns the decoded payload skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the fixed body size or structure size is invalid.
pub fn smb2_process_logoff_fixed(buf: &[u8]) -> Result<Smb2LogoffPayload> {
    Smb2LogoffReply::decode_fixed(buf).map(Smb2LogoffPayload::Reply)
}

/// Processes a fixed LOGOFF request body and returns the decoded payload skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the fixed body size or structure size is invalid.
pub fn smb2_process_logoff_request_fixed(buf: &[u8]) -> Result<Smb2LogoffPayload> {
    Smb2LogoffRequest::decode_fixed(buf).map(Smb2LogoffPayload::Request)
}

fn logoff_header() -> Smb2Header {
    Smb2Header {
        protocol_id: SMB2_PROTOCOL_ID,
        struct_size: 64,
        credit_charge: 0,
        status: 0,
        command: SMB2_LOGOFF,
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
        Some(bytes) if bytes.len() == len => Ok(bytes),
        _ => Err(ErrorCode(EINVAL)),
    }
}
