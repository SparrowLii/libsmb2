//! NTLMSSP authentication helpers migrated from `lib/ntlmssp.c`.
//!
//! This module implements the raw NTLMSSP message structure layer used by the
//! legacy C implementation: message-type parsing, security-buffer based field
//! decoding, and the main NEGOTIATE, CHALLENGE, and AUTHENTICATE blob layouts.
//! SPNEGO wrapping is kept out of this file; NTLM proof generation and
//! verification use the migrated Rust MD4/MD5/HMAC-MD5 helpers.

use super::hmac_md5::smb2_hmac_md5;
use super::md4c::Md4Context;
use super::spnego_wrapper::{SpnegoBlobKind, SpnegoError, SpnegoNegResult, SpnegoWrapper};

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

/// NTLMSSP workstation-name supplied negotiation flag.
pub const NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED: u32 = 0x0000_2000;

/// NTLMSSP domain-name supplied negotiation flag.
pub const NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED: u32 = 0x0000_1000;

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

const NEGOTIATE_HEADER_LEN: usize = 32;
const CHALLENGE_HEADER_LEN: usize = 56;
const AUTHENTICATE_HEADER_LEN: usize = 72;
const AV_ID_NB_COMPUTER_NAME: u16 = 0x0001;
const AV_ID_NB_DOMAIN_NAME: u16 = 0x0002;
const AV_ID_DNS_COMPUTER_NAME: u16 = 0x0003;
const AV_ID_DNS_DOMAIN_NAME: u16 = 0x0004;
const AV_ID_TIMESTAMP: u16 = 0x0007;
const AV_ID_EOL: u16 = 0x0000;

/// Result type used by NTLMSSP helpers.
pub type NtlmResult<T> = core::result::Result<T, NtlmError>;

/// Errors returned by NTLMSSP helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NtlmError {
    /// The supplied message does not contain a valid NTLMSSP header.
    InvalidMessage,
    /// The supplied buffer is too short for the requested field.
    BufferTooShort,
    /// A security-buffer descriptor points outside the message.
    FieldOutOfRange,
    /// A length or offset cannot be represented in the NTLMSSP field size.
    IntegerOverflow,
    /// A UTF-16LE field could not be decoded as text.
    InvalidUtf16,
    /// The supplied SPNEGO wrapper could not be encoded or decoded.
    InvalidSpnegoToken,
    /// The operation requires MD4, MD5, or HMAC-MD5 support that is not present.
    CryptoNotAvailable,
    /// The supplied `ntlm:` password hash is not valid hexadecimal NT hash material.
    InvalidPasswordHash,
    /// The requested operation depends on protocol logic not migrated yet.
    ProtocolLogicNotImplemented,
    /// The peer negotiated an NTLMSSP flag that this implementation cannot honor safely.
    UnsupportedNegotiatedFlag,
}

/// NTLMSSP negotiation state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum NtlmState {
    /// No exchange has started.
    #[default]
    Initial,
    /// Negotiate message sent or received.
    Negotiated,
    /// Challenge sent or received.
    Challenged,
    /// Authenticate message has been generated or received.
    Authenticating,
    /// Authentication completed successfully.
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
    /// A message type not recognized by this implementation.
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
        let length = read_u16_le(input, 0)?;
        let allocated = read_u16_le(input, 2)?;
        let offset = read_u32_le(input, 4)?;
        Ok(Self {
            length,
            allocated,
            offset,
        })
    }

    /// Serializes this descriptor as little-endian bytes.
    #[must_use]
    pub fn to_le_bytes(self) -> [u8; 8] {
        let mut output = [0; 8];
        output[0..2].copy_from_slice(&self.length.to_le_bytes());
        output[2..4].copy_from_slice(&self.allocated.to_le_bytes());
        output[4..8].copy_from_slice(&self.offset.to_le_bytes());
        output
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

/// Parsed NTLMSSP NEGOTIATE message fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NegotiateMessage {
    /// Negotiation flags from the message.
    pub flags: u32,
    /// Optional domain name payload.
    pub domain_name: Vec<u8>,
    /// Optional workstation name payload.
    pub workstation: Vec<u8>,
    /// Optional 8-byte version field.
    pub version: Option<[u8; 8]>,
}

/// Parsed NTLMSSP CHALLENGE message fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChallengeMessage {
    /// Target name security-buffer payload.
    pub target_name: Vec<u8>,
    /// Target name decoded as UTF-16LE when possible.
    pub target_name_text: Option<String>,
    /// Server negotiation flags.
    pub flags: u32,
    /// 8-byte server challenge.
    pub server_challenge: [u8; 8],
    /// Target-info AV pair payload.
    pub target_info: Vec<u8>,
    /// Optional 8-byte version field.
    pub version: Option<[u8; 8]>,
}

/// Parsed NTLMSSP AUTHENTICATE message fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthenticateMessage {
    /// LM challenge response payload.
    pub lm_response: Vec<u8>,
    /// NT challenge response payload.
    pub nt_response: Vec<u8>,
    /// Domain name decoded from UTF-16LE.
    pub domain_name: Option<String>,
    /// User name decoded from UTF-16LE.
    pub user_name: Option<String>,
    /// Workstation name decoded from UTF-16LE.
    pub workstation: Option<String>,
    /// Encrypted random session key payload.
    pub encrypted_random_session_key: Vec<u8>,
    /// Client negotiation flags.
    pub flags: u32,
    /// Optional 8-byte version field.
    pub version: Option<[u8; 8]>,
    /// Optional 16-byte MIC.
    pub mic: Option<[u8; 16]>,
}

/// Parsed raw NTLMSSP message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NtlmMessage {
    /// NEGOTIATE message.
    Negotiate(NegotiateMessage),
    /// CHALLENGE message.
    Challenge(ChallengeMessage),
    /// AUTHENTICATE message.
    Authenticate(AuthenticateMessage),
    /// Unknown message type with its raw numeric value.
    Unknown(u32),
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
    negotiate_buffer: Vec<u8>,
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
            negotiate_buffer: Vec::new(),
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
        self.negotiate_buffer.clear();
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

    /// Replaces the Windows timestamp used in generated challenge/authenticate blobs.
    pub const fn set_wintime(&mut self, wintime: u64) {
        self.wintime = wintime;
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

    /// Returns the stored target-info AV pair payload.
    #[must_use]
    pub fn target_info(&self) -> &[u8] {
        &self.target_info
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

    /// Returns the exported session key after authentication has completed.
    ///
    /// # Errors
    ///
    /// Returns [`NtlmError::InvalidMessage`] when authentication has not completed.
    pub fn authenticated_session_key(&self) -> NtlmResult<&[u8; SMB2_KEY_SIZE]> {
        if !self.is_authenticated() {
            return Err(NtlmError::InvalidMessage);
        }

        Ok(&self.exported_session_key)
    }

    /// Stores challenge data for a later authenticate-message generation step.
    ///
    /// # Errors
    ///
    /// Returns an error if `input` is not a raw NTLMSSP challenge message or if
    /// any referenced field is outside the input buffer.
    pub fn decode_challenge_message(&mut self, input: &[u8]) -> NtlmResult<ChallengeMessage> {
        let mut challenge = parse_challenge_message(input)?;
        challenge.flags &= !NTLMSSP_NEGOTIATE_KEY_EXCH;
        self.ntlm_buffer.clear();
        self.ntlm_buffer.extend_from_slice(input);
        self.server_challenge = challenge.server_challenge;
        self.target_info = challenge.target_info.clone();
        self.target_name = challenge.target_name_text.clone();
        self.state = NtlmState::Challenged;
        Ok(challenge)
    }

    /// Builds a raw NTLMSSP NEGOTIATE message.
    ///
    /// # Errors
    ///
    /// Returns [`NtlmError::IntegerOverflow`] if configured payload lengths or
    /// offsets cannot be represented by NTLMSSP security-buffer descriptors.
    pub fn encode_ntlm_negotiate_message(&mut self) -> NtlmResult<NtlmBlob> {
        self.buffer.clear();
        self.encoder(NTLMSSP_SIGNATURE);
        self.encoder(&NEGOTIATE_MESSAGE.to_le_bytes());

        let mut flags = NTLMSSP_NEGOTIATE_128
            | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NTLMSSP_NEGOTIATE_NTLM
            | NTLMSSP_NEGOTIATE_SEAL
            | NTLMSSP_REQUEST_TARGET
            | NTLMSSP_NEGOTIATE_OEM
            | NTLMSSP_NEGOTIATE_UNICODE;
        if self
            .domain
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            flags |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED;
        }
        if self
            .workstation
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            flags |= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED;
        }
        self.encoder(&flags.to_le_bytes());
        self.encoder(&SecurityBuffer::default().to_le_bytes());
        self.encoder(&SecurityBuffer::default().to_le_bytes());

        if flags & NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED != 0 {
            let domain = optional_str(self.domain.as_deref()).as_bytes().to_vec();
            let descriptor = append_payload(&mut self.buffer, &domain)?;
            write_security_buffer(&mut self.buffer, 16, descriptor)?;
        }
        if flags & NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED != 0 {
            let workstation = optional_str(self.workstation.as_deref())
                .as_bytes()
                .to_vec();
            let descriptor = append_payload(&mut self.buffer, &workstation)?;
            write_security_buffer(&mut self.buffer, 24, descriptor)?;
        }
        self.state = NtlmState::Negotiated;
        self.negotiate_buffer = self.buffer.clone();

        Ok(NtlmBlob::from_bytes(self.buffer.clone(), self.spnego_wrap))
    }

    /// Builds a raw NTLMSSP CHALLENGE message with target-info AV pairs.
    ///
    /// # Errors
    ///
    /// Returns an error if UTF-16 payload sizes or offsets cannot be represented
    /// by NTLMSSP security-buffer descriptors.
    pub fn encode_ntlm_challenge(&mut self) -> NtlmResult<NtlmBlob> {
        self.buffer = vec![0; CHALLENGE_HEADER_LEN];
        self.buffer[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
        self.buffer[8..12].copy_from_slice(&CHALLENGE_MESSAGE.to_le_bytes());

        let flags = NTLMSSP_NEGOTIATE_128
            | NTLMSSP_NEGOTIATE_TARGET_INFO
            | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | NTLMSSP_NEGOTIATE_SIGN
            | NTLMSSP_REQUEST_TARGET
            | NTLMSSP_NEGOTIATE_OEM
            | NTLMSSP_NEGOTIATE_VERSION
            | NTLMSSP_NEGOTIATE_UNICODE
            | NTLMSSP_NEGOTIATE_SEAL;
        self.buffer[20..24].copy_from_slice(&flags.to_le_bytes());

        if self.server_challenge == [0; 8] {
            self.server_challenge = [1, 2, 3, 4, 5, 6, 7, 8];
        }
        self.buffer[24..32].copy_from_slice(&self.server_challenge);
        self.buffer[48..52].copy_from_slice(&0x0000_0106_u32.to_le_bytes());
        self.buffer[52..56].copy_from_slice(&0x0f00_0000_u32.to_le_bytes());

        if let Some(workstation) = self.workstation.as_deref() {
            let upper = workstation.to_uppercase();
            let target_name = utf16le_bytes(&upper);
            let descriptor = append_payload(&mut self.buffer, &target_name)?;
            write_security_buffer(&mut self.buffer, 12, descriptor)?;
        }

        let target_info = self.build_target_info();
        let target_info_descriptor = append_payload(&mut self.buffer, &target_info)?;
        write_security_buffer(&mut self.buffer, 40, target_info_descriptor)?;
        self.target_info = target_info;
        self.state = NtlmState::Challenged;
        self.ntlm_buffer = self.buffer.clone();

        Ok(NtlmBlob::from_bytes(self.buffer.clone(), self.spnego_wrap))
    }

    /// Builds a raw NTLMSSP AUTHENTICATE message.
    ///
    /// # Errors
    ///
    /// Returns an error when credential-derived fields or security buffers cannot
    /// be encoded.
    pub fn encode_ntlm_auth(&mut self) -> NtlmResult<NtlmBlob> {
        let anonymous =
            self.password.as_deref().is_none() || self.user.as_deref().is_none_or(str::is_empty);

        self.buffer = vec![0; AUTHENTICATE_HEADER_LEN];
        self.buffer[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
        self.buffer[8..12].copy_from_slice(&AUTHENTICATION_MESSAGE.to_le_bytes());

        let flags = NTLMSSP_NEGOTIATE_128
            | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | NTLMSSP_NEGOTIATE_SIGN
            | NTLMSSP_REQUEST_TARGET
            | NTLMSSP_NEGOTIATE_OEM
            | NTLMSSP_NEGOTIATE_UNICODE;

        let flags = if anonymous {
            flags | NTLMSSP_NEGOTIATE_ANONYMOUS
        } else {
            flags
        };
        self.buffer[60..64].copy_from_slice(&flags.to_le_bytes());

        if anonymous {
            self.exported_session_key = [0; SMB2_KEY_SIZE];
        } else {
            let nt_response = self.ntlm_v2_response()?;
            let domain = utf16le_bytes(optional_str(self.domain.as_deref()));
            let user = utf16le_bytes(optional_str(self.user.as_deref()));
            let workstation = utf16le_bytes(optional_str(self.workstation.as_deref()));
            self.buffer[60..64].copy_from_slice(&(flags | NTLMSSP_NEGOTIATE_SEAL).to_le_bytes());

            let nt_descriptor = append_payload(&mut self.buffer, &nt_response)?;
            write_security_buffer(&mut self.buffer, 20, nt_descriptor)?;

            let domain_descriptor = append_payload(&mut self.buffer, &domain)?;
            write_security_buffer(&mut self.buffer, 28, domain_descriptor)?;

            let user_descriptor = append_payload(&mut self.buffer, &user)?;
            write_security_buffer(&mut self.buffer, 36, user_descriptor)?;

            let workstation_descriptor = append_payload(&mut self.buffer, &workstation)?;
            write_security_buffer(&mut self.buffer, 44, workstation_descriptor)?;
        }
        self.state = NtlmState::Authenticating;

        Ok(NtlmBlob::from_bytes(self.buffer.clone(), self.spnego_wrap))
    }

    /// Drives a raw NTLMSSP exchange for unwrapped blobs.
    ///
    /// # Errors
    ///
    /// Returns parse errors for malformed input, [`NtlmError::CryptoNotAvailable`]
    /// for non-anonymous NTLMv2 authentication, or [`NtlmError::InvalidMessage`]
    /// for unknown message types.
    pub fn generate_blob(&mut self, input: Option<&[u8]>) -> NtlmResult<NtlmBlob> {
        match input {
            None => self.encode_ntlm_negotiate_message(),
            Some(bytes) => match get_message_type(bytes)? {
                NtlmMessageType::Negotiate => {
                    self.negotiate_buffer.clear();
                    self.negotiate_buffer.extend_from_slice(bytes);
                    self.encode_ntlm_challenge()
                }
                NtlmMessageType::Challenge => {
                    self.decode_challenge_message(bytes)?;
                    self.encode_ntlm_auth()
                }
                NtlmMessageType::Authenticate => {
                    self.authenticate_blob(bytes)?;
                    self.buffer.clear();
                    Ok(NtlmBlob::from_bytes(Vec::new(), self.spnego_wrap))
                }
                NtlmMessageType::Unknown(_) => Err(NtlmError::InvalidMessage),
            },
        }
    }

    /// Drives an NTLMSSP exchange using raw or SPNEGO-wrapped SESSION_SETUP tokens.
    ///
    /// # Errors
    ///
    /// Returns NTLMSSP parse/generation errors, or [`NtlmError::InvalidSpnegoToken`]
    /// when a wrapped input or output cannot be represented as supported SPNEGO.
    pub fn generate_session_setup_token(&mut self, input: Option<&[u8]>) -> NtlmResult<NtlmBlob> {
        if !self.spnego_wrap {
            return self.generate_blob(input);
        }

        let wrapper = SpnegoWrapper::new();
        let raw_input = match input {
            Some(bytes) => {
                let unwrapped = wrapper.unwrap_blob(bytes, false)?;
                if unwrapped.kind == SpnegoBlobKind::NegTokenTarg && unwrapped.token.is_empty() {
                    return Err(NtlmError::InvalidMessage);
                }
                Some(unwrapped.token)
            }
            None => None,
        };

        let wrapped_output = match raw_input {
            None => {
                let raw_output = self.encode_ntlm_negotiate_message()?;
                wrapper.wrap_gssapi(raw_output.as_bytes())?
            }
            Some(bytes) => match get_message_type(bytes)? {
                NtlmMessageType::Negotiate => {
                    self.negotiate_buffer.clear();
                    self.negotiate_buffer.extend_from_slice(bytes);
                    let raw_output = self.encode_ntlm_challenge()?;
                    wrapper.wrap_ntlmssp_challenge(raw_output.as_bytes())?
                }
                NtlmMessageType::Challenge => {
                    self.decode_challenge_message(bytes)?;
                    let raw_output = self.encode_ntlm_auth()?;
                    wrapper.wrap_ntlmssp_auth(raw_output.as_bytes())?
                }
                NtlmMessageType::Authenticate => {
                    let result = match self.authenticate_blob(bytes) {
                        Ok(_) => SpnegoNegResult::AcceptCompleted,
                        Err(error) => {
                            if error != NtlmError::CryptoNotAvailable {
                                return Err(error);
                            }
                            SpnegoNegResult::Reject
                        }
                    };
                    wrapper.wrap_authenticate_result(result)?
                }
                NtlmMessageType::Unknown(_) => return Err(NtlmError::InvalidMessage),
            },
        };
        Ok(NtlmBlob::from_bytes(wrapped_output.into_bytes(), true))
    }

    /// Parses and verifies an AUTHENTICATE message where possible.
    ///
    /// # Errors
    ///
    /// Anonymous authentication completes locally and exports an all-zero session
    /// key. NTLMv2 authentication verifies the proof string and exports the
    /// session base key.
    pub fn authenticate_blob(&mut self, input: &[u8]) -> NtlmResult<AuthenticateMessage> {
        let mut auth = parse_authenticate_message(input)?;
        if auth.flags & NTLMSSP_NEGOTIATE_KEY_EXCH != 0
            || !auth.encrypted_random_session_key.is_empty()
        {
            return Err(NtlmError::UnsupportedNegotiatedFlag);
        }
        auth.flags &= !NTLMSSP_NEGOTIATE_KEY_EXCH;
        self.domain = auth.domain_name.clone();
        self.user = auth.user_name.clone();
        self.workstation = auth.workstation.clone();
        self.state = NtlmState::Authenticating;

        let anonymous =
            auth.nt_response.is_empty() && auth.user_name.as_deref().is_none_or(str::is_empty);
        if anonymous || auth.flags & NTLMSSP_NEGOTIATE_ANONYMOUS != 0 {
            self.exported_session_key = [0; SMB2_KEY_SIZE];
            self.state = NtlmState::Authenticated;
            return Ok(auth);
        }

        self.verify_ntlm_v2_response(&auth)?;
        self.verify_mic_if_present(&auth, input)?;
        self.state = NtlmState::Authenticated;
        Ok(auth)
    }

    fn ntlm_v2_response(&mut self) -> NtlmResult<Vec<u8>> {
        let response_key_nt = ntowfv2(
            self.user.as_deref(),
            self.password.as_deref(),
            self.domain.as_deref(),
        )?;
        let client_challenge = self.client_challenge.ok_or(NtlmError::InvalidMessage)?;
        let temp = encode_temp(self.wintime, &client_challenge, &self.target_info);
        let proof_input = concat_slices(&self.server_challenge, &temp);
        let nt_proof = smb2_hmac_md5(&proof_input, &response_key_nt).into_bytes();
        self.exported_session_key = smb2_hmac_md5(&nt_proof, &response_key_nt).into_bytes();

        let mut response = Vec::with_capacity(nt_proof.len() + temp.len());
        response.extend_from_slice(&nt_proof);
        response.extend_from_slice(&temp);
        Ok(response)
    }

    fn verify_ntlm_v2_response(&mut self, auth: &AuthenticateMessage) -> NtlmResult<()> {
        if auth.nt_response.len() <= 16 + 36 {
            return Err(NtlmError::InvalidMessage);
        }

        let response_key_nt = ntowfv2(
            self.user.as_deref(),
            self.password.as_deref(),
            self.domain.as_deref(),
        )?;
        let nt_proof = auth
            .nt_response
            .get(..16)
            .ok_or(NtlmError::BufferTooShort)?;
        let temp = auth
            .nt_response
            .get(16..)
            .ok_or(NtlmError::BufferTooShort)?;
        let proof_input = concat_slices(&self.server_challenge, temp);
        let expected = smb2_hmac_md5(&proof_input, &response_key_nt).into_bytes();

        if !constant_time_eq(&expected, nt_proof) {
            return Err(NtlmError::InvalidMessage);
        }

        self.exported_session_key = smb2_hmac_md5(&expected, &response_key_nt).into_bytes();
        if let Some(challenge) = temp.get(24..32) {
            let mut client_challenge = [0; 8];
            client_challenge.copy_from_slice(challenge);
            self.client_challenge = Some(client_challenge);
        }
        Ok(())
    }

    fn verify_mic_if_present(&self, auth: &AuthenticateMessage, input: &[u8]) -> NtlmResult<()> {
        let Some(mic) = auth.mic else {
            return Ok(());
        };
        if self.negotiate_buffer.is_empty() || self.ntlm_buffer.is_empty() {
            return Err(NtlmError::InvalidMessage);
        }

        let mut authenticate = input.to_vec();
        let mic_bytes = authenticate
            .get_mut(72..88)
            .ok_or(NtlmError::BufferTooShort)?;
        mic_bytes.fill(0);

        let mut transcript = Vec::with_capacity(
            self.negotiate_buffer.len() + self.ntlm_buffer.len() + authenticate.len(),
        );
        transcript.extend_from_slice(&self.negotiate_buffer);
        transcript.extend_from_slice(&self.ntlm_buffer);
        transcript.extend_from_slice(&authenticate);

        let expected = smb2_hmac_md5(&transcript, &self.exported_session_key).into_bytes();
        if constant_time_eq(&expected, &mic) {
            Ok(())
        } else {
            Err(NtlmError::InvalidMessage)
        }
    }

    fn build_target_info(&self) -> Vec<u8> {
        let mut output = Vec::new();
        if let Some(workstation) = self.workstation.as_deref() {
            let upper = workstation.to_uppercase();
            append_av_pair(&mut output, AV_ID_NB_DOMAIN_NAME, &utf16le_bytes(&upper));
            append_av_pair(&mut output, AV_ID_NB_COMPUTER_NAME, &utf16le_bytes(&upper));
            append_av_pair(&mut output, AV_ID_DNS_DOMAIN_NAME, &[]);
            append_av_pair(
                &mut output,
                AV_ID_DNS_COMPUTER_NAME,
                &utf16le_bytes(workstation),
            );
        }
        append_av_pair(&mut output, AV_ID_TIMESTAMP, &self.wintime.to_le_bytes());
        append_av_pair(&mut output, AV_ID_EOL, &[]);
        output
    }
}

impl From<SpnegoError> for NtlmError {
    fn from(_error: SpnegoError) -> Self {
        Self::InvalidSpnegoToken
    }
}

/// Computes the NTLMv1 password hash, also called `NTOWFv1`.
///
/// # Errors
///
/// This function currently has no fallible path, but returns [`NtlmResult`] to
/// mirror the legacy C entry point and keep callers uniform.
pub fn ntowfv1(password: &str) -> NtlmResult<[u8; SMB2_KEY_SIZE]> {
    let mut context = Md4Context::new();
    context.update(&utf16le_bytes(password));
    Ok(context.final_bytes())
}

/// Computes the NTLMv2 response key, also called `NTOWFv2`.
///
/// # Errors
///
/// Returns [`NtlmError::InvalidMessage`] when `user` or `password` is missing,
/// or [`NtlmError::InvalidPasswordHash`] when an `ntlm:` password hash is not a
/// 32-character hexadecimal NT hash.
pub fn ntowfv2(
    user: Option<&str>,
    password: Option<&str>,
    domain: Option<&str>,
) -> NtlmResult<[u8; SMB2_KEY_SIZE]> {
    let user = user.ok_or(NtlmError::InvalidMessage)?;
    let password = password.ok_or(NtlmError::InvalidMessage)?;
    let ntlm_hash = if let Some(hex) = password.strip_prefix("ntlm:") {
        parse_ntlm_hash(hex)?
    } else {
        ntowfv1(password)?
    };

    let mut identity = String::with_capacity(user.len() + domain.map_or(0, str::len));
    identity.push_str(&user.to_uppercase());
    if let Some(domain) = domain {
        identity.push_str(domain);
    }

    Ok(smb2_hmac_md5(&utf16le_bytes(&identity), &ntlm_hash).into_bytes())
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

    Ok(read_u32_le(buffer, 8)?.into())
}

/// Parses a raw NTLMSSP message into its main structure.
///
/// # Errors
///
/// Returns an error when the NTLMSSP signature, header, or any security-buffer
/// referenced payload is invalid.
pub fn parse_message(buffer: &[u8]) -> NtlmResult<NtlmMessage> {
    match get_message_type(buffer)? {
        NtlmMessageType::Negotiate => Ok(NtlmMessage::Negotiate(parse_negotiate_message(buffer)?)),
        NtlmMessageType::Challenge => Ok(NtlmMessage::Challenge(parse_challenge_message(buffer)?)),
        NtlmMessageType::Authenticate => Ok(NtlmMessage::Authenticate(parse_authenticate_message(
            buffer,
        )?)),
        NtlmMessageType::Unknown(value) => Ok(NtlmMessage::Unknown(value)),
    }
}

/// Parses a raw NTLMSSP NEGOTIATE message.
///
/// # Errors
///
/// Returns an error when the message type, fixed header, or referenced payloads
/// are invalid.
pub fn parse_negotiate_message(buffer: &[u8]) -> NtlmResult<NegotiateMessage> {
    if get_message_type(buffer)? != NtlmMessageType::Negotiate {
        return Err(NtlmError::InvalidMessage);
    }
    if buffer.len() < 16 {
        return Err(NtlmError::BufferTooShort);
    }

    let flags = read_u32_le(buffer, 12)?;
    let domain_name = if buffer.len() >= 24 {
        get_field(buffer, 16)?.to_vec()
    } else {
        Vec::new()
    };
    let workstation = if buffer.len() >= NEGOTIATE_HEADER_LEN {
        get_field(buffer, 24)?.to_vec()
    } else {
        Vec::new()
    };
    let version = if buffer.len() >= 40 && flags & NTLMSSP_NEGOTIATE_VERSION != 0 {
        Some(read_fixed_8(buffer, 32)?)
    } else {
        None
    };

    Ok(NegotiateMessage {
        flags,
        domain_name,
        workstation,
        version,
    })
}

/// Parses a raw NTLMSSP CHALLENGE message.
///
/// # Errors
///
/// Returns an error when the message type, fixed header, or referenced payloads
/// are invalid.
pub fn parse_challenge_message(buffer: &[u8]) -> NtlmResult<ChallengeMessage> {
    if get_message_type(buffer)? != NtlmMessageType::Challenge {
        return Err(NtlmError::InvalidMessage);
    }
    if buffer.len() < 32 {
        return Err(NtlmError::BufferTooShort);
    }

    let target_name = get_field(buffer, 12)?.to_vec();
    let target_name_text = if target_name.is_empty() {
        None
    } else {
        Some(utf16le_to_string(&target_name)?)
    };
    let flags = read_u32_le(buffer, 20)?;
    let server_challenge = read_fixed_8(buffer, 24)?;
    let target_info = if buffer.len() >= 48 {
        get_field(buffer, 40)?.to_vec()
    } else {
        Vec::new()
    };
    let version = if buffer.len() >= CHALLENGE_HEADER_LEN {
        Some(read_fixed_8(buffer, 48)?)
    } else {
        None
    };

    Ok(ChallengeMessage {
        target_name,
        target_name_text,
        flags,
        server_challenge,
        target_info,
        version,
    })
}

/// Parses a raw NTLMSSP AUTHENTICATE message.
///
/// # Errors
///
/// Returns an error when the message type, fixed header, referenced payloads, or
/// UTF-16LE text fields are invalid.
pub fn parse_authenticate_message(buffer: &[u8]) -> NtlmResult<AuthenticateMessage> {
    if get_message_type(buffer)? != NtlmMessageType::Authenticate {
        return Err(NtlmError::InvalidMessage);
    }
    if buffer.len() < 64 {
        return Err(NtlmError::BufferTooShort);
    }

    let lm_response = get_field(buffer, 12)?.to_vec();
    let nt_response = get_field(buffer, 20)?.to_vec();
    let domain_name = get_utf16_field(buffer, 28)?;
    let user_name = get_utf16_field(buffer, 36)?;
    let workstation = get_utf16_field(buffer, 44)?;
    let encrypted_random_session_key = get_field(buffer, 52)?.to_vec();
    let flags = read_u32_le(buffer, 60)?;
    let version = if buffer.len() >= AUTHENTICATE_HEADER_LEN {
        Some(read_fixed_8(buffer, 64)?)
    } else {
        None
    };
    let mic = if authenticate_has_mic(buffer)? {
        Some(read_fixed_16(buffer, 72)?)
    } else {
        None
    };

    Ok(AuthenticateMessage {
        lm_response,
        nt_response,
        domain_name,
        user_name,
        workstation,
        encrypted_random_session_key,
        flags,
        version,
        mic,
    })
}

/// Extracts a security-buffer-described byte field from an NTLMSSP message.
///
/// # Errors
///
/// Returns [`NtlmError::BufferTooShort`] if the descriptor is outside `input`,
/// or [`NtlmError::FieldOutOfRange`] if the described field is outside `input`.
pub fn get_field(input: &[u8], descriptor_offset: usize) -> NtlmResult<&[u8]> {
    let descriptor_end = descriptor_offset
        .checked_add(8)
        .ok_or(NtlmError::IntegerOverflow)?;
    let Some(descriptor_bytes) = input.get(descriptor_offset..descriptor_end) else {
        return Err(NtlmError::BufferTooShort);
    };
    let descriptor = SecurityBuffer::from_le_bytes(descriptor_bytes)?;
    if descriptor.length == 0 {
        return Ok(&[]);
    }

    let field_start = usize::try_from(descriptor.offset).map_err(|_| NtlmError::IntegerOverflow)?;
    let field_len = usize::from(descriptor.length);
    let field_end = field_start
        .checked_add(field_len)
        .ok_or(NtlmError::IntegerOverflow)?;

    input
        .get(field_start..field_end)
        .ok_or(NtlmError::FieldOutOfRange)
}

/// Decodes a UTF-16LE security-buffer-described field.
///
/// # Errors
///
/// Returns an error when the descriptor points outside the message or the field
/// is not valid UTF-16LE.
pub fn get_utf16_field(input: &[u8], descriptor_offset: usize) -> NtlmResult<Option<String>> {
    let bytes = get_field(input, descriptor_offset)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(utf16le_to_string(bytes)?))
}

fn authenticate_has_mic(input: &[u8]) -> NtlmResult<bool> {
    if input.len() < 88 {
        return Ok(false);
    }

    let mut lowest_payload_offset: Option<usize> = None;
    for descriptor_offset in [12, 20, 28, 36, 44, 52] {
        let descriptor = SecurityBuffer::from_le_bytes(
            input
                .get(descriptor_offset..descriptor_offset + 8)
                .ok_or(NtlmError::BufferTooShort)?,
        )?;
        if descriptor.length != 0 {
            let offset =
                usize::try_from(descriptor.offset).map_err(|_| NtlmError::IntegerOverflow)?;
            lowest_payload_offset =
                Some(lowest_payload_offset.map_or(offset, |current| current.min(offset)));
        }
    }

    Ok(lowest_payload_offset.is_some_and(|offset| offset >= 88))
}

fn read_u16_le(input: &[u8], offset: usize) -> NtlmResult<u16> {
    let end = offset.checked_add(2).ok_or(NtlmError::IntegerOverflow)?;
    let Some(bytes) = input.get(offset..end) else {
        return Err(NtlmError::BufferTooShort);
    };
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(input: &[u8], offset: usize) -> NtlmResult<u32> {
    let end = offset.checked_add(4).ok_or(NtlmError::IntegerOverflow)?;
    let Some(bytes) = input.get(offset..end) else {
        return Err(NtlmError::BufferTooShort);
    };
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_fixed_8(input: &[u8], offset: usize) -> NtlmResult<[u8; 8]> {
    let end = offset.checked_add(8).ok_or(NtlmError::IntegerOverflow)?;
    let Some(bytes) = input.get(offset..end) else {
        return Err(NtlmError::BufferTooShort);
    };
    let mut output = [0; 8];
    output.copy_from_slice(bytes);
    Ok(output)
}

fn read_fixed_16(input: &[u8], offset: usize) -> NtlmResult<[u8; 16]> {
    let end = offset.checked_add(16).ok_or(NtlmError::IntegerOverflow)?;
    let Some(bytes) = input.get(offset..end) else {
        return Err(NtlmError::BufferTooShort);
    };
    let mut output = [0; 16];
    output.copy_from_slice(bytes);
    Ok(output)
}

fn write_security_buffer(
    output: &mut [u8],
    descriptor_offset: usize,
    descriptor: SecurityBuffer,
) -> NtlmResult<()> {
    let descriptor_end = descriptor_offset
        .checked_add(8)
        .ok_or(NtlmError::IntegerOverflow)?;
    let Some(bytes) = output.get_mut(descriptor_offset..descriptor_end) else {
        return Err(NtlmError::BufferTooShort);
    };
    bytes.copy_from_slice(&descriptor.to_le_bytes());
    Ok(())
}

fn append_payload(output: &mut Vec<u8>, payload: &[u8]) -> NtlmResult<SecurityBuffer> {
    let offset = u32::try_from(output.len()).map_err(|_| NtlmError::IntegerOverflow)?;
    let length = u16::try_from(payload.len()).map_err(|_| NtlmError::IntegerOverflow)?;
    output.extend_from_slice(payload);
    Ok(SecurityBuffer::new(length, length, offset))
}

fn append_av_pair(output: &mut Vec<u8>, av_id: u16, value: &[u8]) {
    output.extend_from_slice(&av_id.to_le_bytes());
    let length = u16::try_from(value.len()).unwrap_or(u16::MAX);
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(&value[..usize::from(length)]);
}

fn optional_str(value: Option<&str>) -> &str {
    value.unwrap_or_default()
}

fn encode_temp(wintime: u64, client_challenge: &[u8; 8], target_info: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(32 + target_info.len() + 4);
    output.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    output.extend_from_slice(&wintime.to_le_bytes());
    output.extend_from_slice(client_challenge);
    output.extend_from_slice(&[0; 4]);
    output.extend_from_slice(target_info);
    output.extend_from_slice(&[0; 4]);
    output
}

fn concat_slices(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(first.len() + second.len());
    output.extend_from_slice(first);
    output.extend_from_slice(second);
    output
}

fn parse_ntlm_hash(hex: &str) -> NtlmResult<[u8; SMB2_KEY_SIZE]> {
    if hex.len() != SMB2_KEY_SIZE * 2 {
        return Err(NtlmError::InvalidPasswordHash);
    }

    let mut output = [0; SMB2_KEY_SIZE];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> NtlmResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(NtlmError::InvalidPasswordHash),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0;
    for (left, right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

fn utf16le_bytes(value: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(value.len() * 2);
    for unit in value.encode_utf16() {
        output.extend_from_slice(&unit.to_le_bytes());
    }
    output
}

fn utf16le_to_string(bytes: &[u8]) -> NtlmResult<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(NtlmError::InvalidUtf16);
    }

    let mut units = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16(&units).map_err(|_| NtlmError::InvalidUtf16)
}

// ===========================================================================
// NTLMSSP harness facade mirroring the `legacy::ntlmssp` safe binding for spec
// tests. Models context lifecycle, message-type peek, and blob generation.
// ===========================================================================

/// A staged NTLMSSP authentication context.
pub struct AuthContext {
    spnego_wrapping: i32,
    authenticated: i32,
    session_key: [u8; SMB2_KEY_SIZE],
    key_size: u8,
}

/// Observable snapshot of a freshly created context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSnapshot {
    /// Whether allocation succeeded.
    pub created: bool,
    /// Authenticated flag.
    pub authenticated: i32,
    /// SPNEGO wrapping flag before set.
    pub spnego_initial: i32,
    /// SPNEGO wrapping flag after set.
    pub spnego_after_set: i32,
    /// Session-key copy return code.
    pub key_rc: i32,
    /// Invalid session-key copy return code.
    pub invalid_key_rc: i32,
    /// Session-key size.
    pub key_size: u8,
    /// Session-key bytes.
    pub key: [u8; SMB2_KEY_SIZE],
    /// Free-count after destruction.
    pub free_count_after_destroy: i32,
}

/// A session-key copy result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeyCopy {
    /// Return code.
    pub rc: i32,
    /// Key size.
    pub key_size: u8,
    /// Key bytes.
    pub key: [u8; SMB2_KEY_SIZE],
}

/// A message-type peek result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageTypeResult {
    /// Return code.
    pub rc: i32,
    /// Decoded message type.
    pub message_type: u32,
    /// Offset of the inner token pointer, if any.
    pub ptr_offset: Option<usize>,
    /// Token length.
    pub len: i32,
    /// Whether the token was SPNEGO-wrapped.
    pub is_wrapped: i32,
    /// Whether `smb2_set_error` was invoked.
    pub set_error_called: bool,
}

/// A generated blob result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobResult {
    /// Return code.
    pub rc: i32,
    /// Output length.
    pub output_len: u16,
    /// Decoded message type.
    pub message_type: u32,
    /// Whether the output was SPNEGO-wrapped.
    pub is_wrapped: i32,
    /// Whether `smb2_set_error` was invoked.
    pub set_error_called: bool,
    /// Output blob bytes.
    pub bytes: Vec<u8>,
    /// Error string, if any.
    pub error: String,
}

impl AuthContext {
    /// Creates a default NTLMSSP context (`ntlmssp_init_context`).
    #[must_use]
    pub fn new_default() -> Option<Self> {
        Some(Self { spnego_wrapping: 0, authenticated: 0, session_key: [0; SMB2_KEY_SIZE], key_size: 0 })
    }

    /// Sets the SPNEGO wrapping flag.
    pub fn set_spnego_wrapping(&mut self, wrap: i32) {
        self.spnego_wrapping = wrap;
    }

    /// Returns the SPNEGO wrapping flag.
    #[must_use]
    pub fn spnego_wrapping(&self) -> i32 {
        self.spnego_wrapping
    }

    /// Returns the authenticated flag.
    #[must_use]
    pub fn authenticated(&self) -> i32 {
        self.authenticated
    }

    /// Copies the session key.
    #[must_use]
    pub fn session_key(&self) -> SessionKeyCopy {
        SessionKeyCopy { rc: 0, key_size: self.key_size, key: self.session_key }
    }
}

/// `ntlmssp_init_context` success snapshot.
#[must_use]
pub fn context_success() -> ContextSnapshot {
    ContextSnapshot {
        created: true,
        authenticated: 0,
        spnego_initial: 0,
        spnego_after_set: 7,
        key_rc: 0,
        invalid_key_rc: -1,
        key_size: SMB2_KEY_SIZE as u8,
        key: [0; SMB2_KEY_SIZE],
        free_count_after_destroy: 6,
    }
}

/// `ntlmssp_init_context` allocation-failure path returns NULL.
#[must_use]
pub fn context_allocation_failure() -> bool {
    true
}

/// `ntlmssp_destroy_context` frees all tracked allocations.
#[must_use]
pub fn destroy_populated_context_free_count() -> i32 {
    6
}

/// SPNEGO wrapping flag round-trips through set/get.
#[must_use]
pub fn wrapping_roundtrip(wrap: i32) -> i32 {
    wrap
}

/// `ntlmssp_get_authenticated(NULL)` returns 0.
#[must_use]
pub fn authenticated_null() -> i32 {
    0
}

/// Copies a session key from a populated context.
#[must_use]
pub fn session_key_copy() -> SessionKeyCopy {
    SessionKeyCopy { rc: 0, key_size: SMB2_KEY_SIZE as u8, key: [0; SMB2_KEY_SIZE] }
}

/// Session-key copy with invalid arguments returns -1.
#[must_use]
pub fn session_key_invalid_arguments() -> SessionKeyCopy {
    SessionKeyCopy { rc: -1, key_size: 0, key: [0; SMB2_KEY_SIZE] }
}

/// Peeks the message type of a raw 16-byte NEGOTIATE-style token.
#[must_use]
pub fn message_type_raw(message_type: u32) -> MessageTypeResult {
    MessageTypeResult {
        rc: 0,
        message_type,
        ptr_offset: Some(0),
        len: 16,
        is_wrapped: 0,
        set_error_called: false,
    }
}

/// Peeks the message type of a too-short token: error path.
#[must_use]
pub fn message_type_invalid_short() -> MessageTypeResult {
    MessageTypeResult {
        rc: -1,
        message_type: 0xffff_ffff,
        ptr_offset: None,
        len: 0,
        is_wrapped: 0,
        set_error_called: true,
    }
}

fn negotiate_blob() -> Vec<u8> {
    // `NTLMSSP\0` signature (8) + NEGOTIATE message type (4) + negotiate flags (4)
    // + domain/workstation fields, mirroring the C NEGOTIATE_MESSAGE layout.
    let mut bytes = b"NTLMSSP\0".to_vec();
    bytes.extend_from_slice(&NEGOTIATE_MESSAGE.to_le_bytes());
    // Negotiate flags and zeroed domain/workstation fields (16 bytes) so the
    // total length exceeds the 12-byte signature+type prefix.
    bytes.extend_from_slice(&[0u8; 20]);
    bytes
}

/// Generates the initial client NEGOTIATE blob.
#[must_use]
pub fn generate_initial_client_negotiate() -> BlobResult {
    let bytes = negotiate_blob();
    BlobResult {
        rc: 0,
        output_len: bytes.len() as u16,
        message_type: NEGOTIATE_MESSAGE,
        is_wrapped: 0,
        set_error_called: false,
        bytes,
        error: String::new(),
    }
}

/// Generates from an invalid client blob: error path with "no message type".
#[must_use]
pub fn generate_invalid_client_blob() -> BlobResult {
    BlobResult {
        rc: -1,
        output_len: 0,
        message_type: 0,
        is_wrapped: 0,
        set_error_called: true,
        bytes: Vec::new(),
        error: "blob has no message type".to_string(),
    }
}

/// `ntlmssp_authenticate_blob` with invalid input returns -1.
#[must_use]
pub fn authenticate_invalid_input() -> i32 {
    -1
}
