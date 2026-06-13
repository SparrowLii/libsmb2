//! NTLMSSP authentication helpers migrated from `lib/ntlmssp.c`.
//!
//! This module mirrors the responsibilities and naming of the legacy C file so
//! future migration work has stable Rust types to fill in. The cryptographic
//! NTLMv1/NTLMv2, SPNEGO wrapping, and SMB2 context integration logic is not
//! implemented here yet.

/// Length in bytes of the SMB2 exported session key used by NTLMSSP.
pub const SMB2_KEY_SIZE: usize = 16;

/// NTLMSSP signature prefix used by all raw NTLMSSP messages.
pub const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// NTLMSSP negotiate message type.
pub const NEGOTIATE_MESSAGE: u32 = 1;

/// NTLMSSP challenge message type.
pub const CHALLENGE_MESSAGE: u32 = 2;

/// NTLMSSP authenticate message type.
pub const AUTHENTICATION_MESSAGE: u32 = 3;

/// NTLMSSP 56-bit encryption negotiation flag.
pub const NTLMSSP_NEGOTIATE_56: u32 = 0x8000_0000;

/// NTLMSSP key exchange negotiation flag.
pub const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;

/// NTLMSSP 128-bit encryption negotiation flag.
pub const NTLMSSP_NEGOTIATE_128: u32 = 0x2000_0000;

/// NTLMSSP version negotiation flag.
pub const NTLMSSP_NEGOTIATE_VERSION: u32 = 0x0200_0000;

/// NTLMSSP target-info negotiation flag.
pub const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;

/// NTLMSSP extended session security negotiation flag.
pub const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;

/// NTLMSSP server target-type flag.
pub const NTLMSSP_TARGET_TYPE_SERVER: u32 = 0x0002_0000;

/// NTLMSSP always-sign negotiation flag.
pub const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;

/// NTLMSSP anonymous negotiation flag.
pub const NTLMSSP_NEGOTIATE_ANONYMOUS: u32 = 0x0000_0800;

/// NTLMSSP NTLM negotiation flag.
pub const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;

/// NTLMSSP sealing negotiation flag.
pub const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x0000_0020;

/// NTLMSSP signing negotiation flag.
pub const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x0000_0010;

/// NTLMSSP request-target negotiation flag.
pub const NTLMSSP_REQUEST_TARGET: u32 = 0x0000_0004;

/// NTLMSSP OEM negotiation flag.
pub const NTLMSSP_NEGOTIATE_OEM: u32 = 0x0000_0002;

/// NTLMSSP Unicode negotiation flag.
pub const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;

/// Result type used by NTLMSSP skeleton APIs.
pub type NtlmResult<T> = core::result::Result<T, NtlmError>;

/// Errors returned by NTLMSSP skeleton helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NtlmError {
    /// The supplied message does not contain a valid NTLMSSP header.
    InvalidMessage,
    /// The supplied buffer is too short for the requested field.
    BufferTooShort,
    /// The requested operation depends on protocol logic not migrated yet.
    ProtocolLogicNotImplemented,
}

/// NTLMSSP negotiation state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum NtlmState {
    /// No exchange has started.
    #[default]
    Initial,
    /// Negotiate message sent.
    Negotiated,
    /// Challenge received.
    Challenged,
    /// Authentication completed.
    Authenticated,
}

/// Parsed NTLMSSP message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NtlmMessageType {
    /// NTLMSSP `NEGOTIATE_MESSAGE`.
    Negotiate,
    /// NTLMSSP `CHALLENGE_MESSAGE`.
    Challenge,
    /// NTLMSSP `AUTHENTICATION_MESSAGE`.
    Authenticate,
    /// A message type not recognized by this skeleton.
    Unknown(u32),
}

impl From<u32> for NtlmMessageType {
    fn from(value: u32) -> Self {
        match value {
            NEGOTIATE_MESSAGE => Self::Negotiate,
            CHALLENGE_MESSAGE => Self::Challenge,
            AUTHENTICATION_MESSAGE => Self::Authenticate,
            other => Self::Unknown(other),
        }
    }
}

/// Security buffer descriptor used by NTLMSSP field headers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SecurityBuffer {
    /// Current field length in bytes.
    pub length: u16,
    /// Allocated field length in bytes.
    pub allocated: u16,
    /// Offset from the start of the NTLMSSP message.
    pub offset: u32,
}

impl SecurityBuffer {
    /// Creates a new security buffer descriptor.
    #[must_use]
    pub const fn new(length: u16, allocated: u16, offset: u32) -> Self {
        Self {
            length,
            allocated,
            offset,
        }
    }

    /// Parses a little-endian security buffer descriptor from `input`.
    ///
    /// # Errors
    ///
    /// Returns [`NtlmError::BufferTooShort`] when fewer than 8 bytes are available.
    pub fn from_le_bytes(input: &[u8]) -> NtlmResult<Self> {
        let Some(length_bytes) = input.get(0..2) else {
            return Err(NtlmError::BufferTooShort);
        };
        let Some(allocated_bytes) = input.get(2..4) else {
            return Err(NtlmError::BufferTooShort);
        };
        let Some(offset_bytes) = input.get(4..8) else {
            return Err(NtlmError::BufferTooShort);
        };

        Ok(Self {
            length: u16::from_le_bytes([length_bytes[0], length_bytes[1]]),
            allocated: u16::from_le_bytes([allocated_bytes[0], allocated_bytes[1]]),
            offset: u32::from_le_bytes([
                offset_bytes[0],
                offset_bytes[1],
                offset_bytes[2],
                offset_bytes[3],
            ]),
        })
    }
}

/// Raw NTLMSSP blob produced or consumed during an authentication exchange.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NtlmBlob {
    bytes: Vec<u8>,
    wrapped: bool,
}

impl NtlmBlob {
    /// Creates an empty NTLMSSP blob.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            wrapped: false,
        }
    }

    /// Creates a blob from existing bytes and a SPNEGO wrapping marker.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>, wrapped: bool) -> Self {
        Self { bytes, wrapped }
    }

    /// Returns the raw bytes for this blob.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns whether the blob was or should be wrapped in SPNEGO.
    #[must_use]
    pub const fn is_wrapped(&self) -> bool {
        self.wrapped
    }

    /// Consumes the blob and returns the raw bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Configuration values corresponding to `ntlmssp_init_context` inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NtlmAuthConfig {
    /// Optional user name for the NTLMSSP exchange.
    pub user: Option<String>,
    /// Optional password or `ntlm:` password hash string.
    pub password: Option<String>,
    /// Optional authentication domain.
    pub domain: Option<String>,
    /// Optional workstation name.
    pub workstation: Option<String>,
    /// Optional fixed 8-byte client challenge.
    pub client_challenge: Option<[u8; 8]>,
}

/// Mutable NTLMSSP authentication data migrated from `struct auth_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthData {
    buffer: Vec<u8>,
    ntlm_buffer: Vec<u8>,
    neg_result: i32,
    user: Option<String>,
    domain: Option<String>,
    password: Option<String>,
    workstation: Option<String>,
    target_name: Option<String>,
    client_challenge: Option<[u8; 8]>,
    server_challenge: [u8; 8],
    target_info: Vec<u8>,
    spnego_wrap: bool,
    state: NtlmState,
    wintime: u64,
    exported_session_key: [u8; SMB2_KEY_SIZE],
}

impl AuthData {
    /// Creates a new NTLMSSP authentication context.
    #[must_use]
    pub fn init_context(config: NtlmAuthConfig) -> Self {
        Self {
            buffer: Vec::new(),
            ntlm_buffer: Vec::new(),
            neg_result: 0,
            user: config.user,
            domain: config.domain,
            password: config.password,
            workstation: config.workstation,
            target_name: None,
            client_challenge: config.client_challenge,
            server_challenge: [0; 8],
            target_info: Vec::new(),
            spnego_wrap: false,
            state: NtlmState::Initial,
            wintime: 0,
            exported_session_key: [0; SMB2_KEY_SIZE],
        }
    }

    /// Clears transient buffers while preserving credentials and negotiated state.
    pub fn destroy_context(&mut self) {
        self.buffer.clear();
        self.ntlm_buffer.clear();
        self.target_info.clear();
        self.target_name = None;
        self.exported_session_key = [0; SMB2_KEY_SIZE];
        self.state = NtlmState::Initial;
    }

    /// Replaces the password associated with this context.
    pub fn set_password(&mut self, password: Option<String>) {
        self.password = password;
    }

    /// Replaces the domain associated with this context.
    pub fn set_domain(&mut self, domain: Option<String>) {
        self.domain = domain;
    }

    /// Enables or disables SPNEGO wrapping for generated blobs.
    pub fn set_spnego_wrapping(&mut self, wrap: bool) {
        self.spnego_wrap = wrap;
    }

    /// Returns whether SPNEGO wrapping is enabled for this context.
    #[must_use]
    pub const fn spnego_wrapping(&self) -> bool {
        self.spnego_wrap
    }

    /// Returns whether authentication has completed successfully.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        matches!(self.state, NtlmState::Authenticated)
    }

    /// Returns the current NTLMSSP exchange state.
    #[must_use]
    pub const fn state(&self) -> NtlmState {
        self.state
    }

    /// Returns the most recent negotiate result value.
    #[must_use]
    pub const fn neg_result(&self) -> i32 {
        self.neg_result
    }

    /// Returns the user name stored in this context.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Returns the domain stored in this context.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Returns the workstation stored in this context.
    #[must_use]
    pub fn workstation(&self) -> Option<&str> {
        self.workstation.as_deref()
    }

    /// Returns the decoded target name from a challenge message, when present.
    #[must_use]
    pub fn target_name(&self) -> Option<&str> {
        self.target_name.as_deref()
    }

    /// Appends bytes to the current output buffer.
    pub fn encoder(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Returns the current raw output buffer.
    #[must_use]
    pub fn output_buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Returns a copy of the exported session key.
    #[must_use]
    pub const fn session_key(&self) -> [u8; SMB2_KEY_SIZE] {
        self.exported_session_key
    }

    /// Stores challenge data for a later authenticate-message migration step.
    ///
    /// # Errors
    ///
    /// Returns [`NtlmError::InvalidMessage`] if `input` is not a raw NTLMSSP
    /// challenge message.
    pub fn decode_challenge_message(&mut self, input: &[u8]) -> NtlmResult<()> {
        if get_message_type(input)? != NtlmMessageType::Challenge {
            return Err(NtlmError::InvalidMessage);
        }

        self.ntlm_buffer.clear();
        self.ntlm_buffer.extend_from_slice(input);
        if let Some(challenge) = input.get(24..32) {
            self.server_challenge.copy_from_slice(challenge);
        }
        self.state = NtlmState::Challenged;
        Ok(())
    }

    /// Builds the NTLMSSP negotiate-message skeleton.
    ///
    /// # Errors
    ///
    /// This skeleton currently has no fallible path, but returns [`NtlmResult`]
    /// to match the legacy C function shape for future protocol migration.
    pub fn encode_ntlm_negotiate_message(&mut self) -> NtlmResult<NtlmBlob> {
        self.buffer.clear();
        self.encoder(NTLMSSP_SIGNATURE);
        self.encoder(&NEGOTIATE_MESSAGE.to_le_bytes());

        let flags = NTLMSSP_NEGOTIATE_128
            | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NTLMSSP_NEGOTIATE_NTLM
            | NTLMSSP_NEGOTIATE_SEAL
            | NTLMSSP_REQUEST_TARGET
            | NTLMSSP_NEGOTIATE_OEM
            | NTLMSSP_NEGOTIATE_UNICODE;
        self.encoder(&flags.to_le_bytes());
        self.buffer.resize(32, 0);
        self.state = NtlmState::Negotiated;

        Ok(NtlmBlob::from_bytes(self.buffer.clone(), self.spnego_wrap))
    }

    /// Placeholder for NTLMSSP authenticate-message generation.
    ///
    /// # Errors
    ///
    /// Always returns [`NtlmError::ProtocolLogicNotImplemented`] until NTLMv2
    /// response generation and key derivation are migrated.
    pub const fn encode_ntlm_auth(&self) -> NtlmResult<NtlmBlob> {
        Err(NtlmError::ProtocolLogicNotImplemented)
    }

    /// Placeholder for server challenge-message generation.
    ///
    /// # Errors
    ///
    /// Always returns [`NtlmError::ProtocolLogicNotImplemented`] until the
    /// server-side target-info construction is migrated.
    pub const fn encode_ntlm_challenge(&self) -> NtlmResult<NtlmBlob> {
        Err(NtlmError::ProtocolLogicNotImplemented)
    }

    /// Placeholder matching `ntlmssp_generate_blob` from the C implementation.
    ///
    /// # Errors
    ///
    /// Returns [`NtlmError::ProtocolLogicNotImplemented`] for all exchanges
    /// except an initial client negotiate-message skeleton.
    pub fn generate_blob(&mut self, input: Option<&[u8]>) -> NtlmResult<NtlmBlob> {
        match input {
            None => self.encode_ntlm_negotiate_message(),
            Some(_) => Err(NtlmError::ProtocolLogicNotImplemented),
        }
    }

    /// Placeholder matching `ntlmssp_authenticate_blob` from the C implementation.
    ///
    /// # Errors
    ///
    /// Always returns [`NtlmError::ProtocolLogicNotImplemented`] until server-side
    /// NT proof verification is migrated.
    pub const fn authenticate_blob(&self, _input: &[u8]) -> NtlmResult<()> {
        Err(NtlmError::ProtocolLogicNotImplemented)
    }
}

/// Returns the raw NTLMSSP message type from an unwrapped NTLMSSP buffer.
///
/// # Errors
///
/// Returns [`NtlmError::BufferTooShort`] when `buffer` is shorter than the
/// NTLMSSP header and [`NtlmError::InvalidMessage`] when the signature is not
/// present.
pub fn get_message_type(buffer: &[u8]) -> NtlmResult<NtlmMessageType> {
    if buffer.len() < 12 {
        return Err(NtlmError::BufferTooShort);
    }
    if buffer.get(0..8) != Some(NTLMSSP_SIGNATURE.as_slice()) {
        return Err(NtlmError::InvalidMessage);
    }

    let Some(message_type) = buffer.get(8..12) else {
        return Err(NtlmError::BufferTooShort);
    };

    Ok(u32::from_le_bytes([
        message_type[0],
        message_type[1],
        message_type[2],
        message_type[3],
    ])
    .into())
}

/// Extracts a security-buffer-described byte field from an NTLMSSP message.
///
/// # Errors
///
/// Returns [`NtlmError::BufferTooShort`] if the descriptor or described field is
/// outside `input`.
pub fn get_field(input: &[u8], descriptor_offset: usize) -> NtlmResult<&[u8]> {
    let descriptor_end = descriptor_offset.saturating_add(8);
    let Some(descriptor_bytes) = input.get(descriptor_offset..descriptor_end) else {
        return Err(NtlmError::BufferTooShort);
    };
    let descriptor = SecurityBuffer::from_le_bytes(descriptor_bytes)?;
    let field_start = descriptor.offset as usize;
    let field_end = field_start.saturating_add(descriptor.length as usize);

    input
        .get(field_start..field_end)
        .ok_or(NtlmError::BufferTooShort)
}
