//! SESSION_SETUP command pack/unpack skeleton migrated from `lib/smb2-cmd-session-setup.c`.

use crate::include::libsmb2_private::SMB2_HEADER_SIZE;
use crate::include::smb2::smb2::Command;

/// Session setup request fixed structure size from `SMB2_SESSION_SETUP_REQUEST_SIZE`.
pub const SMB2_SESSION_SETUP_REQUEST_SIZE: u16 = 25;
/// Session setup reply fixed structure size from `SMB2_SESSION_SETUP_REPLY_SIZE`.
pub const SMB2_SESSION_SETUP_REPLY_SIZE: u16 = 9;

/// Session setup request flag for binding an existing session.
pub const SMB2_SESSION_FLAG_BINDING: u8 = 0x01;
/// Session setup capability flag for DFS support.
pub const SMB2_GLOBAL_CAP_DFS: u32 = 0x0000_0001;
/// Reserved session setup capability bit kept for C header parity.
pub const SMB2_GLOBAL_CAP_UNUSED1: u32 = 0x0000_0002;
/// Reserved session setup capability bit kept for C header parity.
pub const SMB2_GLOBAL_CAP_UNUSED2: u32 = 0x0000_0004;
/// Reserved session setup capability bit kept for C header parity.
pub const SMB2_GLOBAL_CAP_UNUSED4: u32 = 0x0000_0008;

/// Reply flag indicating the authenticated user is a guest.
pub const SMB2_SESSION_FLAG_IS_GUEST: u16 = 0x0001;
/// Reply flag indicating an anonymous/null session.
pub const SMB2_SESSION_FLAG_IS_NULL: u16 = 0x0002;
/// Reply flag indicating the session requires encrypted data.
pub const SMB2_SESSION_FLAG_IS_ENCRYPT_DATA: u16 = 0x0004;

const REQUEST_FIXED_LEN: usize = (SMB2_SESSION_SETUP_REQUEST_SIZE as usize) & 0xfffe;
const REPLY_FIXED_LEN: usize = (SMB2_SESSION_SETUP_REPLY_SIZE as usize) & 0xfffe;

/// Error returned by SESSION_SETUP skeleton encoders and decoders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionSetupError {
    /// A security buffer is too large to fit in the SMB2 16-bit length fields.
    SecurityBufferTooLarge { len: usize },
    /// The fixed command payload length did not match the SMB2 structure size.
    UnexpectedFixedSize { expected: usize, actual: usize },
    /// The variable security buffer range points beyond the available PDU bytes.
    SecurityBufferOutOfBounds {
        offset: usize,
        len: usize,
        total: usize,
    },
    /// The security buffer offset overlaps the fixed SESSION_SETUP payload.
    SecurityBufferOverlapsFixedPart { offset: usize, minimum: usize },
}

impl core::fmt::Display for SessionSetupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SecurityBufferTooLarge { len } => {
                write!(f, "session setup security buffer is too large: {len} bytes")
            }
            Self::UnexpectedFixedSize { expected, actual } => {
                write!(f, "unexpected session setup fixed size: expected {expected}, got {actual}")
            }
            Self::SecurityBufferOutOfBounds { offset, len, total } => write!(
                f,
                "session setup security buffer range {offset}..{} exceeds PDU size {total}",
                offset.saturating_add(*len)
            ),
            Self::SecurityBufferOverlapsFixedPart { offset, minimum } => write!(
                f,
                "session setup security buffer offset {offset} overlaps fixed payload ending at {minimum}"
            ),
        }
    }
}

impl std::error::Error for SessionSetupError {}

/// Owned Rust equivalent of `struct smb2_session_setup_request`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Smb2SessionSetupRequest {
    /// Request flags, such as `SMB2_SESSION_FLAG_BINDING`.
    pub flags: u8,
    /// Requested SMB2 security mode.
    pub security_mode: u8,
    /// Client capability flags.
    pub capabilities: u32,
    /// Session setup channel value.
    pub channel: u32,
    /// Previous session id used for reauthentication or binding.
    pub previous_session_id: u64,
    /// Opaque authentication token carried as the variable security buffer.
    pub security_buffer: Vec<u8>,
}

impl Smb2SessionSetupRequest {
    /// Creates a request skeleton with the supplied fixed fields and security buffer.
    pub fn new(
        flags: u8,
        security_mode: u8,
        capabilities: u32,
        channel: u32,
        previous_session_id: u64,
        security_buffer: Vec<u8>,
    ) -> Self {
        Self {
            flags,
            security_mode,
            capabilities,
            channel,
            previous_session_id,
            security_buffer,
        }
    }

    /// Returns the 16-bit security buffer length used by the SMB2 wire format.
    ///
    /// # Errors
    ///
    /// Returns `SessionSetupError::SecurityBufferTooLarge` when the buffer cannot be
    /// represented in the C wire field.
    pub fn security_buffer_length(&self) -> Result<u16, SessionSetupError> {
        u16::try_from(self.security_buffer.len()).map_err(|_| {
            SessionSetupError::SecurityBufferTooLarge {
                len: self.security_buffer.len(),
            }
        })
    }

    /// Encodes the fixed request payload corresponding to `smb2_encode_session_setup_request`.
    ///
    /// # Errors
    ///
    /// Returns an error when `security_buffer` is too large for the SMB2 request field.
    pub fn encode_fixed(&self) -> Result<Vec<u8>, SessionSetupError> {
        let mut fixed = vec![0_u8; REQUEST_FIXED_LEN];
        put_u16(&mut fixed, 0, SMB2_SESSION_SETUP_REQUEST_SIZE);
        fixed[2] = self.flags;
        fixed[3] = self.security_mode;
        put_u32(&mut fixed, 4, self.capabilities);
        put_u32(&mut fixed, 8, self.channel);
        put_u16(&mut fixed, 12, (SMB2_HEADER_SIZE + 24) as u16);
        put_u16(&mut fixed, 14, self.security_buffer_length()?);
        put_u64(&mut fixed, 16, self.previous_session_id);
        Ok(fixed)
    }

    /// Decodes the fixed request payload corresponding to `smb2_process_session_setup_request_fixed`.
    ///
    /// The returned request has an empty variable buffer; call
    /// `attach_security_buffer` with the variable bytes to mirror the C variable phase.
    ///
    /// # Errors
    ///
    /// Returns an error when `fixed` is not the expected SESSION_SETUP request fixed size.
    pub fn decode_fixed(fixed: &[u8]) -> Result<Self, SessionSetupError> {
        ensure_fixed_size(
            fixed,
            SMB2_SESSION_SETUP_REQUEST_SIZE as usize,
            REQUEST_FIXED_LEN,
        )?;
        Ok(Self {
            flags: fixed[2],
            security_mode: fixed[3],
            capabilities: read_u32(fixed, 4),
            channel: read_u32(fixed, 8),
            previous_session_id: read_u64(fixed, 16),
            security_buffer: Vec::new(),
        })
    }

    /// Attaches the variable security buffer corresponding to `smb2_process_session_setup_request_variable`.
    pub fn attach_security_buffer(&mut self, security_buffer: &[u8]) {
        self.security_buffer.clear();
        self.security_buffer.extend_from_slice(security_buffer);
    }
}

/// Owned Rust equivalent of `struct smb2_session_setup_reply`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Smb2SessionSetupReply {
    /// Server session flags.
    pub session_flags: u16,
    /// Absolute security buffer offset from the SMB2 header start.
    pub security_buffer_offset: u16,
    /// Opaque authentication token carried as the variable security buffer.
    pub security_buffer: Vec<u8>,
}

impl Smb2SessionSetupReply {
    /// Creates a reply skeleton with the supplied flags and security buffer.
    pub fn new(session_flags: u16, security_buffer: Vec<u8>) -> Self {
        Self {
            session_flags,
            security_buffer_offset: 0,
            security_buffer,
        }
    }

    /// Returns the 16-bit security buffer length used by the SMB2 wire format.
    ///
    /// # Errors
    ///
    /// Returns `SessionSetupError::SecurityBufferTooLarge` when the buffer cannot be
    /// represented in the C wire field.
    pub fn security_buffer_length(&self) -> Result<u16, SessionSetupError> {
        u16::try_from(self.security_buffer.len()).map_err(|_| {
            SessionSetupError::SecurityBufferTooLarge {
                len: self.security_buffer.len(),
            }
        })
    }

    /// Encodes the fixed reply payload corresponding to `smb2_encode_session_setup_reply`.
    ///
    /// # Errors
    ///
    /// Returns an error when `security_buffer` is too large for the SMB2 reply field.
    pub fn encode_fixed(&mut self) -> Result<Vec<u8>, SessionSetupError> {
        let fixed_len = pad_to_32bit(REPLY_FIXED_LEN);
        let mut fixed = vec![0_u8; fixed_len];
        self.security_buffer_offset = (SMB2_HEADER_SIZE + fixed_len) as u16;
        put_u16(&mut fixed, 0, SMB2_SESSION_SETUP_REPLY_SIZE);
        put_u16(&mut fixed, 2, self.session_flags);
        put_u16(&mut fixed, 4, self.security_buffer_offset);
        put_u16(&mut fixed, 6, self.security_buffer_length()?);
        Ok(fixed)
    }

    /// Decodes the fixed reply payload corresponding to `smb2_process_session_setup_fixed`.
    ///
    /// The returned reply has an empty variable buffer; call `attach_variable_from_pdu`
    /// to mirror the C variable phase.
    ///
    /// # Errors
    ///
    /// Returns an error when `fixed` is not the expected SESSION_SETUP reply fixed size.
    pub fn decode_fixed(fixed: &[u8]) -> Result<Self, SessionSetupError> {
        ensure_fixed_size(
            fixed,
            SMB2_SESSION_SETUP_REPLY_SIZE as usize,
            REPLY_FIXED_LEN,
        )?;
        Ok(Self {
            session_flags: read_u16(fixed, 2),
            security_buffer_offset: read_u16(fixed, 4),
            security_buffer: Vec::new(),
        })
    }

    /// Attaches a reply variable buffer using the offset and length encoded in the fixed payload.
    ///
    /// # Errors
    ///
    /// Returns an error when the encoded range overlaps the fixed reply or exceeds `pdu`.
    pub fn attach_variable_from_pdu(
        &mut self,
        pdu: &[u8],
        security_buffer_length: u16,
    ) -> Result<(), SessionSetupError> {
        if security_buffer_length == 0 {
            self.security_buffer.clear();
            return Ok(());
        }

        let offset = usize::from(self.security_buffer_offset);
        let len = usize::from(security_buffer_length);
        let minimum = SMB2_HEADER_SIZE + REPLY_FIXED_LEN;
        if offset < minimum {
            return Err(SessionSetupError::SecurityBufferOverlapsFixedPart { offset, minimum });
        }

        let end = offset
            .checked_add(len)
            .filter(|end| *end <= pdu.len())
            .ok_or(SessionSetupError::SecurityBufferOutOfBounds {
                offset,
                len,
                total: pdu.len(),
            })?;
        self.security_buffer.clear();
        self.security_buffer.extend_from_slice(&pdu[offset..end]);
        Ok(())
    }
}

/// Minimal owned PDU skeleton produced by SESSION_SETUP command builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2SessionSetupPdu {
    /// SMB2 command id for this skeleton PDU.
    pub command: Command,
    /// Fixed command payload bytes.
    pub fixed: Vec<u8>,
    /// Variable security buffer bytes.
    pub security_buffer: Vec<u8>,
}

impl Smb2SessionSetupPdu {
    /// Returns the concatenated fixed and variable payload bytes.
    pub fn payload_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(self.fixed.len() + self.security_buffer.len());
        payload.extend_from_slice(&self.fixed);
        payload.extend_from_slice(&self.security_buffer);
        payload
    }
}

/// Builds a request PDU skeleton corresponding to `smb2_cmd_session_setup_async`.
///
/// # Errors
///
/// Returns an error when request fields cannot be represented in the SMB2 wire format.
pub fn smb2_cmd_session_setup_async(
    req: &Smb2SessionSetupRequest,
) -> Result<Smb2SessionSetupPdu, SessionSetupError> {
    Ok(Smb2SessionSetupPdu {
        command: Command::SessionSetup,
        fixed: req.encode_fixed()?,
        security_buffer: req.security_buffer.clone(),
    })
}

/// Builds a reply PDU skeleton corresponding to `smb2_cmd_session_setup_reply_async`.
///
/// # Errors
///
/// Returns an error when reply fields cannot be represented in the SMB2 wire format.
pub fn smb2_cmd_session_setup_reply_async(
    rep: &mut Smb2SessionSetupReply,
) -> Result<Smb2SessionSetupPdu, SessionSetupError> {
    let mut security_buffer = rep.security_buffer.clone();
    security_buffer.resize(pad_to_32bit(security_buffer.len()), 0);
    Ok(Smb2SessionSetupPdu {
        command: Command::SessionSetup,
        fixed: rep.encode_fixed()?,
        security_buffer,
    })
}

fn ensure_fixed_size(
    fixed: &[u8],
    structure_size: usize,
    expected_len: usize,
) -> Result<(), SessionSetupError> {
    if fixed.len() != expected_len {
        return Err(SessionSetupError::UnexpectedFixedSize {
            expected: expected_len,
            actual: fixed.len(),
        });
    }

    if usize::from(read_u16(fixed, 0)) != structure_size {
        return Err(SessionSetupError::UnexpectedFixedSize {
            expected: expected_len,
            actual: fixed.len(),
        });
    }
    Ok(())
}

fn pad_to_32bit(len: usize) -> usize {
    (len + 3) & !3
}

fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn read_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ])
}
