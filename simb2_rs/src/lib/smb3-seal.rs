//! SMB3 encryption helpers migrated from `lib/smb3-seal.c`.

/// SMB3 transform protocol id: `0xFD 'S' 'M' 'B'`.
pub const SMB3_TRANSFORM_PROTOCOL_ID: [u8; 4] = [0xfd, b'S', b'M', b'B'];

/// Size of the SMB3 transform header produced before encrypted payload bytes.
pub const SMB3_TRANSFORM_HEADER_SIZE: usize = 52;

/// Size of the SMB3 transform signature field.
pub const SMB3_TRANSFORM_SIGNATURE_SIZE: usize = 16;

/// Size of the SMB3 transform nonce field.
pub const SMB3_TRANSFORM_NONCE_SIZE: usize = 16;

/// Nonce bytes used by the legacy AES-128-CCM path.
pub const SMB3_AES128_CCM_NONCE_SIZE: usize = 11;

/// Authentication data length used by the legacy AES-128-CCM path.
pub const SMB3_AES128_CCM_AUTH_DATA_SIZE: usize = 32;

/// SMB3 encryption algorithm id for AES-128-CCM.
pub const SMB3_ENCRYPTION_AES128_CCM: u16 = 0x0001;

/// Error returned by SMB3 sealing skeleton helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smb3SealError {
    /// The supplied buffer is too short to hold an SMB3 transform header.
    HeaderTooSmall,
    /// The transform header does not start with the SMB3 transform protocol id.
    BadTransformProtocolId,
    /// The transform header advertises an unsupported encryption algorithm.
    UnsupportedCipher(u16),
    /// The encrypted payload length cannot be represented in the transform header.
    PayloadTooLarge,
    /// The operation needs at least one outbound payload vector.
    MissingPayload,
}

/// Result alias used by SMB3 sealing skeleton helpers.
pub type Smb3SealResult<T> = core::result::Result<T, Smb3SealError>;

/// SMB3 encryption cipher mirrored from the transform header algorithm field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Smb3EncryptionCipher {
    /// AES-128-CCM encryption.
    Aes128Ccm = SMB3_ENCRYPTION_AES128_CCM,
}

impl Smb3EncryptionCipher {
    /// Converts a raw SMB3 transform cipher id into a known cipher.
    #[must_use]
    pub const fn from_raw(value: u16) -> Option<Self> {
        match value {
            SMB3_ENCRYPTION_AES128_CCM => Some(Self::Aes128Ccm),
            _ => None,
        }
    }

    /// Returns the numeric transform cipher id.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Parsed SMB3 transform header corresponding to the fixed 52-byte C layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb3TransformHeader {
    /// Transform protocol id, normally [`SMB3_TRANSFORM_PROTOCOL_ID`].
    pub protocol_id: [u8; 4],
    /// Authentication tag field at bytes 4..20.
    pub signature: [u8; SMB3_TRANSFORM_SIGNATURE_SIZE],
    /// Nonce field at bytes 20..36.
    pub nonce: [u8; SMB3_TRANSFORM_NONCE_SIZE],
    /// Original plaintext SMB2 payload size.
    pub original_message_size: u32,
    /// Reserved transform header field.
    pub reserved: u16,
    /// Encryption algorithm selected for the transform.
    pub encryption_algorithm: Smb3EncryptionCipher,
    /// SMB2 session id associated with the sealed payload.
    pub session_id: u64,
}

impl Smb3TransformHeader {
    /// Creates an AES-128-CCM transform header skeleton for a session and payload size.
    #[must_use]
    pub const fn aes128_ccm(session_id: u64, original_message_size: u32) -> Self {
        Self {
            protocol_id: SMB3_TRANSFORM_PROTOCOL_ID,
            signature: [0; SMB3_TRANSFORM_SIGNATURE_SIZE],
            nonce: [0; SMB3_TRANSFORM_NONCE_SIZE],
            original_message_size,
            reserved: 0,
            encryption_algorithm: Smb3EncryptionCipher::Aes128Ccm,
            session_id,
        }
    }

    /// Encodes this transform header into a caller-provided 52-byte buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Smb3SealError::HeaderTooSmall`] when `buf` is shorter than
    /// [`SMB3_TRANSFORM_HEADER_SIZE`].
    pub fn encode_into(&self, buf: &mut [u8]) -> Smb3SealResult<()> {
        if buf.len() < SMB3_TRANSFORM_HEADER_SIZE {
            return Err(Smb3SealError::HeaderTooSmall);
        }
        write_bytes(buf, 0, &self.protocol_id)?;
        write_bytes(buf, 4, &self.signature)?;
        write_bytes(buf, 20, &self.nonce)?;
        write_bytes(buf, 36, &self.original_message_size.to_le_bytes())?;
        write_bytes(buf, 40, &self.reserved.to_le_bytes())?;
        write_bytes(buf, 42, &self.encryption_algorithm.as_u16().to_le_bytes())?;
        write_bytes(buf, 44, &self.session_id.to_le_bytes())?;
        Ok(())
    }

    /// Decodes an SMB3 transform header from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Smb3SealError::HeaderTooSmall`] when the buffer is shorter than
    /// [`SMB3_TRANSFORM_HEADER_SIZE`], [`Smb3SealError::BadTransformProtocolId`] when
    /// the protocol id does not match SMB3 transform frames, or
    /// [`Smb3SealError::UnsupportedCipher`] for unknown algorithms.
    pub fn decode(buf: &[u8]) -> Smb3SealResult<Self> {
        if buf.len() < SMB3_TRANSFORM_HEADER_SIZE {
            return Err(Smb3SealError::HeaderTooSmall);
        }

        let protocol_id = fixed_bytes::<4>(buf, 0)?;
        if protocol_id != SMB3_TRANSFORM_PROTOCOL_ID {
            return Err(Smb3SealError::BadTransformProtocolId);
        }

        let raw_cipher = u16::from_le_bytes(fixed_bytes::<2>(buf, 42)?);
        let Some(encryption_algorithm) = Smb3EncryptionCipher::from_raw(raw_cipher) else {
            return Err(Smb3SealError::UnsupportedCipher(raw_cipher));
        };

        Ok(Self {
            protocol_id,
            signature: fixed_bytes::<SMB3_TRANSFORM_SIGNATURE_SIZE>(buf, 4)?,
            nonce: fixed_bytes::<SMB3_TRANSFORM_NONCE_SIZE>(buf, 20)?,
            original_message_size: u32::from_le_bytes(fixed_bytes::<4>(buf, 36)?),
            reserved: u16::from_le_bytes(fixed_bytes::<2>(buf, 40)?),
            encryption_algorithm,
            session_id: u64::from_le_bytes(fixed_bytes::<8>(buf, 44)?),
        })
    }
}

/// Minimal context fields needed by the SMB3 sealing C routines.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Smb3SealContext {
    /// Whether SMB3 sealing is enabled for the connection.
    pub seal: bool,
    /// Negotiated SMB2 session id copied into transform headers.
    pub session_id: u64,
    /// Client-to-server sealing key used by the legacy encrypt path.
    pub serverin_key: [u8; 16],
    /// Server-to-client sealing key used by the legacy decrypt path.
    pub serverout_key: [u8; 16],
}

impl Smb3SealContext {
    /// Creates a sealing context skeleton with sealing disabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether the connection-level sealing gate is enabled.
    #[must_use]
    pub const fn is_seal_enabled(&self) -> bool {
        self.seal
    }
}

/// Rust-owned outbound PDU view used by [`smb3_encrypt_pdu`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Smb3SealPdu {
    /// Whether this PDU should be sealed when the context also enables sealing.
    pub seal: bool,
    /// Outbound payload vectors that would be copied after the transform header.
    pub out_vectors: Vec<Vec<u8>>,
    /// Transform buffer prepared by the encryption skeleton.
    pub crypt: Vec<u8>,
}

impl Smb3SealPdu {
    /// Creates an empty PDU sealing view.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the total outbound payload length represented by all vectors.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.out_vectors.iter().map(Vec::len).sum()
    }
}

/// Outcome of the SMB3 encryption skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smb3EncryptOutcome {
    /// Sealing was disabled by the context or the PDU flag, matching the C fast path.
    Skipped,
    /// A transform buffer was prepared, but cryptographic sealing is not implemented here.
    Prepared { transform_len: usize },
}

/// Plan returned by the decrypt skeleton after parsing the transform header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb3DecryptPlan {
    /// Parsed SMB3 transform header.
    pub header: Smb3TransformHeader,
    /// Bytes that would be passed as encrypted payload to AES-128-CCM.
    pub encrypted_payload: Vec<u8>,
}

/// Prepares an SMB3 transform buffer for an outbound PDU.
///
/// This mirrors the allocation and header-population responsibility of the C
/// `smb3_encrypt_pdu` function without implementing AES-128-CCM or nonce generation.
///
/// # Errors
///
/// Returns [`Smb3SealError::PayloadTooLarge`] when the concatenated payload does not fit
/// in the transform header size field, or [`Smb3SealError::MissingPayload`] when sealing
/// is requested for an empty PDU view.
pub fn smb3_encrypt_pdu(
    context: &Smb3SealContext,
    pdu: &mut Smb3SealPdu,
) -> Smb3SealResult<Smb3EncryptOutcome> {
    if !context.seal || !pdu.seal {
        return Ok(Smb3EncryptOutcome::Skipped);
    }
    if pdu.out_vectors.is_empty() {
        pdu.seal = false;
        return Err(Smb3SealError::MissingPayload);
    }

    let payload_len = pdu.payload_len();
    let original_message_size =
        u32::try_from(payload_len).map_err(|_| Smb3SealError::PayloadTooLarge)?;
    let transform_len = SMB3_TRANSFORM_HEADER_SIZE
        .checked_add(payload_len)
        .ok_or(Smb3SealError::PayloadTooLarge)?;

    pdu.crypt.clear();
    pdu.crypt.resize(transform_len, 0);
    Smb3TransformHeader::aes128_ccm(context.session_id, original_message_size)
        .encode_into(&mut pdu.crypt)?;

    let mut offset = SMB3_TRANSFORM_HEADER_SIZE;
    for vector in &pdu.out_vectors {
        let next = offset
            .checked_add(vector.len())
            .ok_or(Smb3SealError::PayloadTooLarge)?;
        write_bytes(&mut pdu.crypt, offset, vector)?;
        offset = next;
    }

    Ok(Smb3EncryptOutcome::Prepared { transform_len })
}

/// Parses an inbound SMB3 transform buffer enough to plan decryption.
///
/// This mirrors the validation and buffer-splitting responsibility of the C
/// `smb3_decrypt_pdu` function without implementing AES-128-CCM or receive-state replay.
///
/// # Errors
///
/// Returns any header parsing error from [`Smb3TransformHeader::decode`].
pub fn smb3_decrypt_pdu(
    _context: &Smb3SealContext,
    transform: &[u8],
) -> Smb3SealResult<Smb3DecryptPlan> {
    let header = Smb3TransformHeader::decode(transform)?;
    let encrypted_payload = transform
        .get(SMB3_TRANSFORM_HEADER_SIZE..)
        .map_or_else(Vec::new, <[u8]>::to_vec);

    Ok(Smb3DecryptPlan {
        header,
        encrypted_payload,
    })
}

fn fixed_bytes<const N: usize>(buf: &[u8], offset: usize) -> Smb3SealResult<[u8; N]> {
    let end = offset.checked_add(N).ok_or(Smb3SealError::HeaderTooSmall)?;
    let Some(bytes) = buf.get(offset..end) else {
        return Err(Smb3SealError::HeaderTooSmall);
    };
    let mut out = [0; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn write_bytes(buf: &mut [u8], offset: usize, bytes: &[u8]) -> Smb3SealResult<()> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(Smb3SealError::HeaderTooSmall)?;
    let Some(target) = buf.get_mut(offset..end) else {
        return Err(Smb3SealError::HeaderTooSmall);
    };
    target.copy_from_slice(bytes);
    Ok(())
}
