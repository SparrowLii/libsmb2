//! ECHO command pack/unpack skeleton migrated from `lib/smb2-cmd-echo.c`.

use crate::include::libsmb2_private::{IoVec, IoVectors, Pdu, Smb2Header, SMB2_SIGNATURE_SIZE};
use crate::include::smb2::libsmb2::{CommandCallback, ErrorCode, Result};
use crate::include::smb2::smb2::{Command, SMB2_PROTOCOL_ID};

/// Fixed `ECHO` request structure size from `SMB2_ECHO_REQUEST_SIZE`.
pub const SMB2_ECHO_REQUEST_SIZE: u16 = 4;
/// Fixed `ECHO` reply structure size from `SMB2_ECHO_REPLY_SIZE`.
pub const SMB2_ECHO_REPLY_SIZE: u16 = 4;

const ECHO_REQUEST_WIRE_SIZE: usize = (SMB2_ECHO_REQUEST_SIZE & 0xfffe) as usize;
const ECHO_REPLY_WIRE_SIZE: usize = (SMB2_ECHO_REPLY_SIZE & 0xfffe) as usize;
const EINVAL: i32 = -22;

/// Rust representation of `struct smb2_echo_request`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Smb2EchoRequest;

impl Smb2EchoRequest {
    /// Creates an empty ECHO request skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Encodes the fixed ECHO request body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the fixed-size output buffer cannot be written.
    pub fn encode_fixed(&self) -> Result<Vec<u8>> {
        encode_echo_fixed(SMB2_ECHO_REQUEST_SIZE, ECHO_REQUEST_WIRE_SIZE)
    }

    /// Decodes the fixed ECHO request body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` when `buf` does not match the fixed request size.
    pub fn decode_fixed(buf: &[u8]) -> Result<Self> {
        validate_fixed_size(buf, SMB2_ECHO_REQUEST_SIZE, ECHO_REQUEST_WIRE_SIZE)?;
        Ok(Self)
    }
}

/// Rust representation of the fixed ECHO reply body.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Smb2EchoReply;

impl Smb2EchoReply {
    /// Creates an empty ECHO reply skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Encodes the fixed ECHO reply body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` if the fixed-size output buffer cannot be written.
    pub fn encode_fixed(&self) -> Result<Vec<u8>> {
        encode_echo_fixed(SMB2_ECHO_REPLY_SIZE, ECHO_REPLY_WIRE_SIZE)
    }

    /// Decodes the fixed ECHO reply body.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode(-22)` when `buf` does not match the fixed reply size.
    pub fn decode_fixed(buf: &[u8]) -> Result<Self> {
        validate_fixed_size(buf, SMB2_ECHO_REPLY_SIZE, ECHO_REPLY_WIRE_SIZE)?;
        Ok(Self)
    }
}

/// Decoded payload kind produced by the ECHO fixed-body processors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smb2EchoPayload {
    /// Fixed ECHO request payload.
    Request(Smb2EchoRequest),
    /// Fixed ECHO reply payload.
    Reply(Smb2EchoReply),
}

/// Builds an ECHO request PDU skeleton matching `smb2_cmd_echo_async`.
///
/// # Errors
///
/// Returns an error if fixed request encoding fails.
pub fn smb2_cmd_echo_async(callback: Option<CommandCallback>) -> Result<Pdu> {
    let req = Smb2EchoRequest::new();
    let out = iovectors_from_fixed(req.encode_fixed()?);
    Ok(Pdu {
        header: echo_header(),
        out,
        input: IoVectors::default(),
        callback,
        compound: false,
        timeout: None,
    })
}

/// Builds an ECHO reply PDU skeleton matching `smb2_cmd_echo_reply_async`.
///
/// # Errors
///
/// Returns an error if fixed reply encoding fails.
pub fn smb2_cmd_echo_reply_async(callback: Option<CommandCallback>) -> Result<Pdu> {
    let rep = Smb2EchoReply::new();
    let out = iovectors_from_fixed(rep.encode_fixed()?);
    Ok(Pdu {
        header: echo_header(),
        out,
        input: IoVectors::default(),
        callback,
        compound: false,
        timeout: None,
    })
}

/// Processes a fixed ECHO reply body and returns the decoded payload skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the fixed body size or structure size is invalid.
pub fn smb2_process_echo_fixed(buf: &[u8]) -> Result<Smb2EchoPayload> {
    Smb2EchoReply::decode_fixed(buf).map(Smb2EchoPayload::Reply)
}

/// Processes a fixed ECHO request body and returns the decoded payload skeleton.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` if the fixed body size or structure size is invalid.
pub fn smb2_process_echo_request_fixed(buf: &[u8]) -> Result<Smb2EchoPayload> {
    Smb2EchoRequest::decode_fixed(buf).map(Smb2EchoPayload::Request)
}

fn echo_header() -> Smb2Header {
    Smb2Header {
        protocol_id: SMB2_PROTOCOL_ID,
        struct_size: 64,
        credit_charge: 0,
        status: 0,
        command: Command::Echo as u16,
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

fn encode_echo_fixed(struct_size: u16, wire_size: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0; wire_size];
    put_u16(&mut buf, 0, struct_size)?;
    Ok(buf)
}

fn validate_fixed_size(buf: &[u8], expected_struct_size: u16, expected_len: usize) -> Result<()> {
    if buf.len() != expected_len || get_u16(buf, 0)? != expected_struct_size {
        return Err(ErrorCode(EINVAL));
    }
    Ok(())
}

fn put_u16(buf: &mut [u8], offset: usize, value: u16) -> Result<()> {
    match buf.get_mut(offset..offset.saturating_add(2)) {
        Some(dst) if dst.len() == 2 => {
            dst.copy_from_slice(&value.to_le_bytes());
            Ok(())
        }
        _ => Err(ErrorCode(EINVAL)),
    }
}

fn get_u16(buf: &[u8], offset: usize) -> Result<u16> {
    match buf.get(offset..offset.saturating_add(2)) {
        Some(src) if src.len() == 2 => Ok(u16::from_le_bytes([src[0], src[1]])),
        _ => Err(ErrorCode(EINVAL)),
    }
}
