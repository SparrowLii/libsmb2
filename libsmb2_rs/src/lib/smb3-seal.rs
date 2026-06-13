//! SMB3 encryption helpers migrated from `lib/smb3-seal.c`.

use super::aes128ccm::{
    Aes128BlockEncrypt, Aes128Ccm, Aes128CcmError, Aes128CcmKey, Aes128CcmParams, CcmTag,
    ReferenceAes128BlockEncryptor,
};
use super::smb2_signing::SessionDerivedKeys;

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

/// SMB3 encryption algorithm id for AES-128-GCM.
pub const SMB3_ENCRYPTION_AES128_GCM: u16 = 0x0002;

/// SMB3 encryption algorithm ids defined by the protocol constants known to this module.
pub const SMB3_KNOWN_ENCRYPTION_CIPHERS: [u16; 2] =
    [SMB3_ENCRYPTION_AES128_CCM, SMB3_ENCRYPTION_AES128_GCM];

/// SMB3 encryption ciphers backed by crypto helpers in this module.
pub const SMB3_SUPPORTED_ENCRYPTION_CIPHERS: [Smb3EncryptionCipher; 1] =
    [Smb3EncryptionCipher::Aes128Ccm];

/// Error returned by SMB3 sealing helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smb3SealError {
    /// The supplied buffer is too short to hold an SMB3 transform header.
    HeaderTooSmall,
    /// The transform header does not start with the SMB3 transform protocol id.
    BadTransformProtocolId,
    /// The transform header advertises a cipher without a local crypto helper.
    UnavailableCipher(u16),
    /// The encrypted payload length cannot be represented in the transform header.
    PayloadTooLarge,
    /// The operation needs at least one outbound payload vector.
    MissingPayload,
    /// The nonce supplied for AES-128-CCM does not match the SMB3 legacy nonce size.
    InvalidNonceLength,
    /// The operation requires a non-zero SMB3 AES-128-CCM nonce.
    MissingNonce,
    /// The SMB3 transform nonce has already been used for this session.
    DuplicateNonce,
    /// The local SMB3 transform nonce sequence cannot be advanced further.
    NonceExhausted,
    /// The transform session id does not match the available decrypt context session id.
    SessionIdMismatch,
    /// The SMB3 transform header contains non-zero reserved bytes.
    InvalidTransformReserved,
    /// The SMB3 transform nonce has non-zero bytes outside the AES-128-CCM nonce prefix.
    InvalidTransformNoncePadding,
    /// The sealing key material is empty or all zeroes.
    InvalidSealingKey,
    /// The transform payload length does not match the original message size field.
    PayloadLengthMismatch,
    /// AES-128-CCM failed while sealing or unsealing the payload.
    Aes128Ccm(Aes128CcmError),
}

impl From<Aes128CcmError> for Smb3SealError {
    fn from(value: Aes128CcmError) -> Self {
        Self::Aes128Ccm(value)
    }
}

/// Result alias used by SMB3 sealing helpers.
pub type Smb3SealResult<T> = core::result::Result<T, Smb3SealError>;

/// SMB3 encryption cipher mirrored from the transform header algorithm field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Smb3EncryptionCipher {
    /// AES-128-CCM encryption.
    Aes128Ccm = SMB3_ENCRYPTION_AES128_CCM,
}

impl Smb3EncryptionCipher {
    /// Converts a raw SMB3 transform cipher id into a cipher supported by this module.
    #[must_use]
    pub const fn from_raw(value: u16) -> Option<Self> {
        match value {
            SMB3_ENCRYPTION_AES128_CCM => Some(Self::Aes128Ccm),
            _ => None,
        }
    }

    /// Returns whether a raw SMB3 cipher id is safe to negotiate with the available helpers.
    #[must_use]
    pub const fn is_supported_raw(value: u16) -> bool {
        matches!(value, SMB3_ENCRYPTION_AES128_CCM)
    }

    /// Returns the numeric transform cipher id.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Filters a negotiated raw SMB3 encryption cipher list to ciphers this module can seal.
#[must_use]
pub fn smb3_sanitize_encryption_ciphers(raw_ciphers: &[u16]) -> Vec<Smb3EncryptionCipher> {
    raw_ciphers
        .iter()
        .filter_map(|cipher| Smb3EncryptionCipher::from_raw(*cipher))
        .collect()
}

/// Selects the first negotiated SMB3 encryption cipher backed by local crypto helpers.
#[must_use]
pub fn smb3_select_encryption_cipher(raw_ciphers: &[u16]) -> Option<Smb3EncryptionCipher> {
    raw_ciphers
        .iter()
        .find_map(|cipher| Smb3EncryptionCipher::from_raw(*cipher))
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
    /// Creates an AES-128-CCM transform header for a session and payload size.
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
    /// [`Smb3SealError::UnavailableCipher`] when the selected algorithm is not backed by
    /// this module's crypto helpers.
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
            return Err(Smb3SealError::UnavailableCipher(raw_cipher));
        };

        let reserved = u16::from_le_bytes(fixed_bytes::<2>(buf, 40)?);
        if reserved != 0 {
            return Err(Smb3SealError::InvalidTransformReserved);
        }
        let nonce = fixed_bytes::<SMB3_TRANSFORM_NONCE_SIZE>(buf, 20)?;
        validate_transform_nonce_padding(&nonce)?;

        Ok(Self {
            protocol_id,
            signature: fixed_bytes::<SMB3_TRANSFORM_SIGNATURE_SIZE>(buf, 4)?,
            nonce,
            original_message_size: u32::from_le_bytes(fixed_bytes::<4>(buf, 36)?),
            reserved,
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
    /// Caller-provided AES-128-CCM nonce used by the default encrypt path.
    pub aes128_ccm_nonce: [u8; SMB3_AES128_CCM_NONCE_SIZE],
    /// SMB3 transform nonces already emitted for this local session.
    pub used_outbound_nonces: Vec<[u8; SMB3_TRANSFORM_NONCE_SIZE]>,
    /// SMB3 transform nonces already accepted for this remote session.
    pub seen_inbound_nonces: Vec<(u64, [u8; SMB3_TRANSFORM_NONCE_SIZE])>,
}

impl Smb3SealContext {
    /// Creates a sealing context with sealing disabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether the connection-level sealing gate is enabled.
    #[must_use]
    pub const fn is_seal_enabled(&self) -> bool {
        self.seal
    }

    /// Creates sealing state from derived session key metadata.
    #[must_use]
    pub const fn from_session_keys(
        seal: bool,
        session_id: u64,
        keys: SessionDerivedKeys,
        aes128_ccm_nonce: [u8; SMB3_AES128_CCM_NONCE_SIZE],
    ) -> Self {
        Self {
            seal,
            session_id,
            serverin_key: keys.serverin_key,
            serverout_key: keys.serverout_key,
            aes128_ccm_nonce,
            used_outbound_nonces: Vec::new(),
            seen_inbound_nonces: Vec::new(),
        }
    }

    fn next_encrypt_nonce(&mut self) -> Smb3SealResult<[u8; SMB3_AES128_CCM_NONCE_SIZE]> {
        if self.aes128_ccm_nonce == [0; SMB3_AES128_CCM_NONCE_SIZE] {
            advance_aes128_ccm_nonce(&mut self.aes128_ccm_nonce)?;
        }
        let nonce = self.aes128_ccm_nonce;
        advance_aes128_ccm_nonce(&mut self.aes128_ccm_nonce)?;
        Ok(nonce)
    }

    fn record_outbound_nonce(&mut self, nonce: [u8; SMB3_TRANSFORM_NONCE_SIZE]) {
        self.used_outbound_nonces.push(nonce);
    }

    fn has_outbound_nonce(&self, nonce: &[u8; SMB3_TRANSFORM_NONCE_SIZE]) -> bool {
        self.used_outbound_nonces
            .iter()
            .any(|used_nonce| used_nonce == nonce)
    }

    fn record_inbound_nonce(&mut self, session_id: u64, nonce: [u8; SMB3_TRANSFORM_NONCE_SIZE]) {
        self.seen_inbound_nonces.push((session_id, nonce));
    }

    fn has_inbound_nonce(&self, session_id: u64, nonce: &[u8; SMB3_TRANSFORM_NONCE_SIZE]) -> bool {
        self.seen_inbound_nonces
            .iter()
            .any(|(seen_session_id, seen_nonce)| {
                *seen_session_id == session_id && seen_nonce == nonce
            })
    }
}

/// Rust-owned outbound PDU view used by [`smb3_encrypt_pdu`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Smb3SealPdu {
    /// Whether this PDU should be sealed when the context also enables sealing.
    pub seal: bool,
    /// Outbound payload vectors that would be copied after the transform header.
    pub out_vectors: Vec<Vec<u8>>,
    /// Transform buffer prepared by encryption.
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

/// Outcome of SMB3 encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smb3EncryptOutcome {
    /// Sealing was disabled by the context or the PDU flag, matching the C fast path.
    Skipped,
    /// A transform buffer was prepared and the payload was sealed.
    Sealed { transform_len: usize },
}

/// Plan returned by decrypt after parsing the transform header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb3DecryptPlan {
    /// Parsed SMB3 transform header.
    pub header: Smb3TransformHeader,
    /// Bytes that would be passed as encrypted payload to AES-128-CCM.
    pub encrypted_payload: Vec<u8>,
}

/// Prepares an SMB3 transform buffer for an outbound PDU.
///
/// This mirrors the allocation, header-population, and AES-128-CCM sealing responsibility of the C
/// `smb3_encrypt_pdu` function. A missing all-zero context nonce is replaced with the next local
/// sequence nonce, and every emitted transform nonce is tracked to prevent local reuse.
///
/// # Errors
///
/// Returns [`Smb3SealError::PayloadTooLarge`] when the concatenated payload does not fit
/// in the transform header size field, or [`Smb3SealError::MissingPayload`] when sealing
/// is requested for an empty PDU view.
pub fn smb3_encrypt_pdu(
    context: &mut Smb3SealContext,
    pdu: &mut Smb3SealPdu,
) -> Smb3SealResult<Smb3EncryptOutcome> {
    if !context.seal || !pdu.seal {
        return Ok(Smb3EncryptOutcome::Skipped);
    }
    if pdu.out_vectors.is_empty() {
        pdu.seal = false;
        return Err(Smb3SealError::MissingPayload);
    }
    let nonce = context.next_encrypt_nonce()?;
    smb3_encrypt_pdu_with(context, pdu, &nonce, &ReferenceAes128BlockEncryptor)
}

/// Seals an outbound PDU using a caller-supplied AES-128 block encryptor and CCM nonce.
///
/// `nonce` is copied into the first 11 bytes of the 16-byte SMB3 transform nonce field, matching
/// the legacy C AES-128-CCM path that calls CCM with `&header[20], 11` and authenticates
/// `&header[20], 32`. The context rejects all-zero or previously used outbound transform nonces.
///
/// # Errors
///
/// Returns [`Smb3SealError::InvalidNonceLength`] when `nonce` is not 11 bytes, payload/header
/// sizing errors from this module, or [`Smb3SealError::Aes128Ccm`] for CCM validation,
/// authentication, or missing AES backend failures.
pub fn smb3_encrypt_pdu_with<E>(
    context: &mut Smb3SealContext,
    pdu: &mut Smb3SealPdu,
    nonce: &[u8],
    encryptor: &E,
) -> Smb3SealResult<Smb3EncryptOutcome>
where
    E: Aes128BlockEncrypt,
{
    if !context.seal || !pdu.seal {
        return Ok(Smb3EncryptOutcome::Skipped);
    }
    if pdu.out_vectors.is_empty() {
        pdu.seal = false;
        return Err(Smb3SealError::MissingPayload);
    }
    if nonce.len() != SMB3_AES128_CCM_NONCE_SIZE {
        return Err(Smb3SealError::InvalidNonceLength);
    }
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(Smb3SealError::MissingNonce);
    }
    validate_sealing_key(&context.serverin_key)?;

    let payload_len = pdu.payload_len();
    let original_message_size =
        u32::try_from(payload_len).map_err(|_| Smb3SealError::PayloadTooLarge)?;
    let transform_len = SMB3_TRANSFORM_HEADER_SIZE
        .checked_add(payload_len)
        .ok_or(Smb3SealError::PayloadTooLarge)?;

    pdu.crypt.clear();
    pdu.crypt.resize(transform_len, 0);
    let mut header = Smb3TransformHeader::aes128_ccm(context.session_id, original_message_size);
    header.nonce[..SMB3_AES128_CCM_NONCE_SIZE].copy_from_slice(nonce);
    if context.has_outbound_nonce(&header.nonce) {
        return Err(Smb3SealError::DuplicateNonce);
    }
    header.encode_into(&mut pdu.crypt)?;

    let mut offset = SMB3_TRANSFORM_HEADER_SIZE;
    for vector in &pdu.out_vectors {
        let next = offset
            .checked_add(vector.len())
            .ok_or(Smb3SealError::PayloadTooLarge)?;
        write_bytes(&mut pdu.crypt, offset, vector)?;
        offset = next;
    }

    let aad = fixed_bytes::<SMB3_AES128_CCM_AUTH_DATA_SIZE>(&pdu.crypt, 20)?;
    let nonce = fixed_bytes::<SMB3_AES128_CCM_NONCE_SIZE>(&pdu.crypt, 20)?;
    let ccm = Aes128Ccm::new(Aes128CcmKey::new(context.serverin_key));
    let tag = ccm.encrypt_in_place_with(
        Aes128CcmParams::new(&nonce, &aad, 16),
        &mut pdu.crypt[SMB3_TRANSFORM_HEADER_SIZE..],
        encryptor,
    )?;
    write_bytes(&mut pdu.crypt, 4, tag.as_bytes())?;
    context.record_outbound_nonce(header.nonce);

    Ok(Smb3EncryptOutcome::Sealed { transform_len })
}

/// Parses an inbound SMB3 transform buffer enough to plan decryption.
///
/// This mirrors the validation, buffer-splitting, and AES-128-CCM decryption responsibility of the
/// C `smb3_decrypt_pdu` function. The local context rejects duplicate transform nonces per session;
/// the returned `encrypted_payload` field contains the authenticated plaintext payload.
///
/// # Errors
///
/// Returns any header parsing error from [`Smb3TransformHeader::decode`] or
/// [`Smb3SealError::SessionIdMismatch`] when the context has a session id and it differs from the
/// transform header session id.
pub fn smb3_decrypt_pdu(
    context: &mut Smb3SealContext,
    transform: &[u8],
) -> Smb3SealResult<Smb3DecryptPlan> {
    let header = Smb3TransformHeader::decode(transform)?;
    let encrypted_payload =
        smb3_decrypt_pdu_with(context, transform, &ReferenceAes128BlockEncryptor)?;

    Ok(Smb3DecryptPlan {
        header,
        encrypted_payload,
    })
}

/// Decrypts and authenticates an inbound SMB3 AES-128-CCM transform buffer.
///
/// This mirrors the AES-CCM portion of the legacy C `smb3_decrypt_pdu` and records successfully
/// authenticated transform nonces so replays are rejected per session.
///
/// # Errors
///
/// Returns transform header errors, [`Smb3SealError::SessionIdMismatch`] when the context has a
/// session id and it differs from the transform header session id,
/// [`Smb3SealError::PayloadLengthMismatch`] when the payload size differs from the header's
/// original-message-size field, [`Smb3SealError::InvalidNonceLength`] when the transform nonce is
/// not usable as an SMB3 AES-128-CCM nonce, or [`Smb3SealError::Aes128Ccm`] when CCM
/// validation/authentication fails.
pub fn smb3_decrypt_pdu_with<E>(
    context: &mut Smb3SealContext,
    transform: &[u8],
    encryptor: &E,
) -> Smb3SealResult<Vec<u8>>
where
    E: Aes128BlockEncrypt,
{
    let header = Smb3TransformHeader::decode(transform)?;
    if context.session_id != 0 && header.session_id != context.session_id {
        return Err(Smb3SealError::SessionIdMismatch);
    }
    let payload = transform
        .get(SMB3_TRANSFORM_HEADER_SIZE..)
        .ok_or(Smb3SealError::HeaderTooSmall)?;
    if payload.len() != header.original_message_size as usize {
        return Err(Smb3SealError::PayloadLengthMismatch);
    }

    let aad = fixed_bytes::<SMB3_AES128_CCM_AUTH_DATA_SIZE>(transform, 20)?;
    let nonce = header
        .nonce
        .get(..SMB3_AES128_CCM_NONCE_SIZE)
        .ok_or(Smb3SealError::InvalidNonceLength)?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(Smb3SealError::MissingNonce);
    }
    validate_sealing_key(&context.serverout_key)?;
    if context.has_inbound_nonce(header.session_id, &header.nonce) {
        return Err(Smb3SealError::DuplicateNonce);
    }
    let tag = CcmTag::new(header.signature);
    let mut plaintext = payload.to_vec();
    let ccm = Aes128Ccm::new(Aes128CcmKey::new(context.serverout_key));
    ccm.decrypt_in_place_with(
        Aes128CcmParams::new(nonce, &aad, 16),
        &mut plaintext,
        &tag,
        encryptor,
    )?;
    context.record_inbound_nonce(header.session_id, header.nonce);
    Ok(plaintext)
}

fn advance_aes128_ccm_nonce(nonce: &mut [u8; SMB3_AES128_CCM_NONCE_SIZE]) -> Smb3SealResult<()> {
    for byte in nonce {
        let (advanced, overflowed) = byte.overflowing_add(1);
        *byte = advanced;
        if !overflowed {
            return Ok(());
        }
    }
    Err(Smb3SealError::NonceExhausted)
}

fn validate_transform_nonce_padding(nonce: &[u8; SMB3_TRANSFORM_NONCE_SIZE]) -> Smb3SealResult<()> {
    if nonce[SMB3_AES128_CCM_NONCE_SIZE..]
        .iter()
        .any(|byte| *byte != 0)
    {
        Err(Smb3SealError::InvalidTransformNoncePadding)
    } else {
        Ok(())
    }
}

fn validate_sealing_key(key: &[u8; 16]) -> Smb3SealResult<()> {
    if key.iter().all(|byte| *byte == 0) {
        Err(Smb3SealError::InvalidSealingKey)
    } else {
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::super::aes128ccm::MissingAes128BlockEncryptor;
    use super::*;

    fn context() -> Smb3SealContext {
        Smb3SealContext {
            seal: true,
            session_id: 0x1122_3344_5566_7788,
            serverin_key: [0x11; 16],
            serverout_key: [0x11; 16],
            aes128_ccm_nonce: [0; SMB3_AES128_CCM_NONCE_SIZE],
            used_outbound_nonces: Vec::new(),
            seen_inbound_nonces: Vec::new(),
        }
    }

    fn encoded_header() -> [u8; SMB3_TRANSFORM_HEADER_SIZE] {
        let mut header = Smb3TransformHeader::aes128_ccm(0x1122_3344_5566_7788, 4);
        header.nonce[..SMB3_AES128_CCM_NONCE_SIZE]
            .copy_from_slice(&[1; SMB3_AES128_CCM_NONCE_SIZE]);
        header.signature = [0xaa; SMB3_TRANSFORM_SIGNATURE_SIZE];

        let mut bytes = [0_u8; SMB3_TRANSFORM_HEADER_SIZE];
        header.encode_into(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn transform_decode_rejects_gcm_and_bad_header_parameters() {
        let mut header = encoded_header();
        header[42..44].copy_from_slice(&SMB3_ENCRYPTION_AES128_GCM.to_le_bytes());
        assert_eq!(
            Smb3TransformHeader::decode(&header),
            Err(Smb3SealError::UnavailableCipher(SMB3_ENCRYPTION_AES128_GCM))
        );

        let mut header = encoded_header();
        header[40] = 1;
        assert_eq!(
            Smb3TransformHeader::decode(&header),
            Err(Smb3SealError::InvalidTransformReserved)
        );

        let mut header = encoded_header();
        header[20 + SMB3_AES128_CCM_NONCE_SIZE] = 1;
        assert_eq!(
            Smb3TransformHeader::decode(&header),
            Err(Smb3SealError::InvalidTransformNoncePadding)
        );
    }

    #[test]
    fn encrypt_validates_key_nonce_and_missing_backend() {
        let mut context = context();
        let mut pdu = Smb3SealPdu {
            seal: true,
            out_vectors: vec![b"payload".to_vec()],
            crypt: Vec::new(),
        };

        assert_eq!(
            smb3_encrypt_pdu_with(
                &mut context,
                &mut pdu,
                &[0; SMB3_AES128_CCM_NONCE_SIZE],
                &ReferenceAes128BlockEncryptor
            ),
            Err(Smb3SealError::MissingNonce)
        );

        context.serverin_key = [0; 16];
        assert_eq!(
            smb3_encrypt_pdu_with(
                &mut context,
                &mut pdu,
                &[1; SMB3_AES128_CCM_NONCE_SIZE],
                &ReferenceAes128BlockEncryptor
            ),
            Err(Smb3SealError::InvalidSealingKey)
        );

        context.serverin_key = [0x11; 16];
        assert_eq!(
            smb3_encrypt_pdu_with(
                &mut context,
                &mut pdu,
                &[2; SMB3_AES128_CCM_NONCE_SIZE],
                &MissingAes128BlockEncryptor
            ),
            Err(Smb3SealError::Aes128Ccm(
                Aes128CcmError::CryptoNotImplemented
            ))
        );
    }

    #[test]
    fn encrypt_decrypt_round_trip_and_reject_duplicate_nonce() {
        let mut enc_context = context();
        let mut pdu = Smb3SealPdu {
            seal: true,
            out_vectors: vec![b"payload".to_vec()],
            crypt: Vec::new(),
        };
        let nonce = [7; SMB3_AES128_CCM_NONCE_SIZE];
        assert_eq!(
            smb3_encrypt_pdu_with(
                &mut enc_context,
                &mut pdu,
                &nonce,
                &ReferenceAes128BlockEncryptor
            ),
            Ok(Smb3EncryptOutcome::Sealed {
                transform_len: SMB3_TRANSFORM_HEADER_SIZE + b"payload".len()
            })
        );

        let mut dec_context = context();
        let plaintext =
            smb3_decrypt_pdu_with(&mut dec_context, &pdu.crypt, &ReferenceAes128BlockEncryptor)
                .unwrap();
        assert_eq!(plaintext, b"payload");
        assert_eq!(
            smb3_decrypt_pdu_with(&mut dec_context, &pdu.crypt, &ReferenceAes128BlockEncryptor),
            Err(Smb3SealError::DuplicateNonce)
        );
    }
}
