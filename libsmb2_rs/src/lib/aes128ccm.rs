//! AES-128 CCM helpers migrated from `lib/aes128ccm.c`.

/// Size in bytes of an AES-128 key.
pub const AES128_KEY_LEN: usize = 16;

/// Size in bytes of the AES block processed by CCM.
pub const AES_BLOCK_LEN: usize = 16;

/// AES-128 key material used by the CCM helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes128CcmKey(pub [u8; AES128_KEY_LEN]);

impl Aes128CcmKey {
    /// Creates a new AES-128 CCM key wrapper.
    #[must_use]
    pub const fn new(bytes: [u8; AES128_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AES128_KEY_LEN] {
        &self.0
    }
}

/// AES-CCM authentication tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CcmTag(pub [u8; 16]);

impl CcmTag {
    /// Creates a new CCM authentication tag wrapper.
    #[must_use]
    pub const fn new(bytes: [u8; AES_BLOCK_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw authentication tag bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AES_BLOCK_LEN] {
        &self.0
    }
}

/// Validation errors for AES-128 CCM parameter skeletons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aes128CcmError {
    /// The nonce length cannot be encoded by the CCM counter block layout.
    InvalidNonceLength,
    /// The requested authentication tag length is not valid for CCM.
    InvalidTagLength,
    /// The payload length cannot be represented by this migration skeleton.
    PayloadTooLong,
    /// The AAD length cannot be represented by the short AAD encoding used here.
    AadTooLong,
    /// The CCM counter value cannot be represented by the nonce-derived length field.
    CounterTooLarge,
    /// The cryptographic AES-128 CCM body has not been migrated yet.
    CryptoNotImplemented,
    /// The provided authentication tag does not match the plaintext and AAD.
    AuthenticationFailed,
}

/// AES-128 single-block encryption hook required by CCM.
///
/// The legacy C implementation calls `AES128_ECB_encrypt` from `lib/aes.c`. This migration keeps
/// the AES block dependency local so callers can supply an already-migrated backend without this
/// file changing the AES modules or Cargo dependencies.
pub trait Aes128BlockEncrypt {
    /// Encrypts one 16-byte block with `key`.
    ///
    /// # Errors
    ///
    /// Returns [`Aes128CcmError::CryptoNotImplemented`] or another CCM error when no AES-128 block
    /// backend is available.
    fn encrypt_block(
        &self,
        key: &Aes128CcmKey,
        block: [u8; AES_BLOCK_LEN],
    ) -> Result<[u8; AES_BLOCK_LEN], Aes128CcmError>;
}

/// AES hook that reports the missing cross-file AES block dependency.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MissingAes128BlockEncryptor;

impl Aes128BlockEncrypt for MissingAes128BlockEncryptor {
    fn encrypt_block(
        &self,
        _key: &Aes128CcmKey,
        _block: [u8; AES_BLOCK_LEN],
    ) -> Result<[u8; AES_BLOCK_LEN], Aes128CcmError> {
        Err(Aes128CcmError::CryptoNotImplemented)
    }
}

/// AES hook backed by the migrated reference AES-128 ECB encryptor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReferenceAes128BlockEncryptor;

impl Aes128BlockEncrypt for ReferenceAes128BlockEncryptor {
    fn encrypt_block(
        &self,
        key: &Aes128CcmKey,
        block: [u8; AES_BLOCK_LEN],
    ) -> Result<[u8; AES_BLOCK_LEN], Aes128CcmError> {
        let encrypted = super::aes::aes128_ecb_encrypt_with_backend(
            super::aes::AesBlock::new(block),
            super::aes::Aes128Key::new(*key.as_bytes()),
            super::aes::AesBackend::Reference,
        )
        .map_err(|_| Aes128CcmError::CryptoNotImplemented)?;
        Ok(encrypted.into_bytes())
    }
}

/// Borrowed AES-128 CCM inputs that correspond to the C `aad`, `p`, and `m` buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes128CcmParams<'a> {
    /// CCM nonce buffer passed as `nonce`/`nlen` in the C implementation.
    pub nonce: &'a [u8],
    /// Additional authenticated data passed as `aad`/`alen` in the C implementation.
    pub aad: &'a [u8],
    /// Requested authentication tag length, equivalent to the C `mlen` argument.
    pub tag_len: usize,
}

impl<'a> Aes128CcmParams<'a> {
    /// Creates borrowed AES-128 CCM parameters.
    #[must_use]
    pub const fn new(nonce: &'a [u8], aad: &'a [u8], tag_len: usize) -> Self {
        Self {
            nonce,
            aad,
            tag_len,
        }
    }
}

/// Stateful AES-128 CCM helper matching the role of `lib/aes128ccm.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes128Ccm {
    key: Aes128CcmKey,
}

impl Aes128Ccm {
    /// Creates an AES-128 CCM helper for the supplied key.
    #[must_use]
    pub const fn new(key: Aes128CcmKey) -> Self {
        Self { key }
    }

    /// Returns the AES-128 key associated with this CCM helper.
    #[must_use]
    pub const fn key(&self) -> &Aes128CcmKey {
        &self.key
    }

    /// Builds the CCM B0 authentication block header used by `aes_ccm_generate_b0`.
    ///
    /// # Errors
    ///
    /// Returns [`Aes128CcmError::InvalidNonceLength`] if the nonce cannot fit the CCM block
    /// layout, [`Aes128CcmError::InvalidTagLength`] if `tag_len` is outside the CCM range, or
    /// [`Aes128CcmError::PayloadTooLong`] if `payload_len` cannot be encoded in the nonce-derived
    /// CCM length field.
    pub fn generate_b0(
        nonce: &[u8],
        aad_len: usize,
        payload_len: usize,
        tag_len: usize,
    ) -> Result<[u8; AES_BLOCK_LEN], Aes128CcmError> {
        validate_nonce_len(nonce.len())?;
        validate_tag_len(tag_len)?;
        validate_payload_len(nonce.len(), payload_len)?;

        let mut block = [0_u8; AES_BLOCK_LEN];
        let q = length_field_len(nonce.len());
        if aad_len != 0 {
            block[0] |= 0x40;
        }
        block[0] |= (((tag_len - 2) / 2) << 3) as u8 & 0x38;
        block[0] |= ((q - 1) & 0x07) as u8;
        block[1..1 + nonce.len()].copy_from_slice(nonce);
        encode_length(payload_len, q, &mut block)?;
        Ok(block)
    }

    /// Encrypts a payload in place and returns the CCM authentication tag.
    ///
    /// This mirrors the public C `aes128ccm_encrypt` entry point using the reference AES backend.
    ///
    /// # Errors
    ///
    /// Returns validation errors for invalid CCM parameters or AES backend failures.
    pub fn encrypt_in_place(
        &self,
        params: Aes128CcmParams<'_>,
        payload: &mut [u8],
    ) -> Result<CcmTag, Aes128CcmError> {
        self.encrypt_in_place_with(params, payload, &ReferenceAes128BlockEncryptor)
    }

    /// Encrypts a payload in place using a caller-supplied AES-128 block encryptor.
    ///
    /// # Errors
    ///
    /// Returns validation errors for invalid CCM parameters, [`Aes128CcmError::AadTooLong`] for
    /// unsupported AAD encoding, [`Aes128CcmError::CounterTooLarge`] if the CTR counter cannot be
    /// encoded, or any error returned by `encryptor`.
    pub fn encrypt_in_place_with<E>(
        &self,
        params: Aes128CcmParams<'_>,
        payload: &mut [u8],
        encryptor: &E,
    ) -> Result<CcmTag, Aes128CcmError>
    where
        E: Aes128BlockEncrypt,
    {
        validate_params(params, payload.len())?;
        let mut tag = self.generate_t(params, payload, encryptor)?;
        let s0 = self.generate_s(params.nonce, 0, encryptor)?;
        xor_prefix(&mut tag, &s0, params.tag_len);
        self.crypt_in_place(params.nonce, payload, encryptor)?;
        Ok(CcmTag(tag))
    }

    /// Decrypts a payload in place and verifies the supplied CCM authentication tag.
    ///
    /// This mirrors the public C `aes128ccm_decrypt` entry point using the reference AES backend.
    ///
    /// # Errors
    ///
    /// Returns validation errors for invalid CCM parameters,
    /// [`Aes128CcmError::AuthenticationFailed`] when authentication rejects the tag, or AES backend
    /// failures.
    pub fn decrypt_in_place(
        &self,
        params: Aes128CcmParams<'_>,
        payload: &mut [u8],
        tag: &CcmTag,
    ) -> Result<(), Aes128CcmError> {
        self.decrypt_in_place_with(params, payload, tag, &ReferenceAes128BlockEncryptor)
    }

    /// Decrypts a payload in place and verifies `tag` using a supplied AES-128 block encryptor.
    ///
    /// # Errors
    ///
    /// Returns validation errors for invalid CCM parameters, any error returned by `encryptor`, or
    /// [`Aes128CcmError::AuthenticationFailed`] when the computed tag differs from `tag`.
    pub fn decrypt_in_place_with<E>(
        &self,
        params: Aes128CcmParams<'_>,
        payload: &mut [u8],
        tag: &CcmTag,
        encryptor: &E,
    ) -> Result<(), Aes128CcmError>
    where
        E: Aes128BlockEncrypt,
    {
        validate_params(params, payload.len())?;
        self.crypt_in_place(params.nonce, payload, encryptor)?;
        let mut expected = self.generate_t(params, payload, encryptor)?;
        let s0 = self.generate_s(params.nonce, 0, encryptor)?;
        xor_prefix(&mut expected, &s0, params.tag_len);

        if tag_matches(&expected, tag.as_bytes(), params.tag_len) {
            Ok(())
        } else {
            Err(Aes128CcmError::AuthenticationFailed)
        }
    }

    fn generate_t<E>(
        &self,
        params: Aes128CcmParams<'_>,
        payload: &[u8],
        encryptor: &E,
    ) -> Result<[u8; AES_BLOCK_LEN], Aes128CcmError>
    where
        E: Aes128BlockEncrypt,
    {
        let b0 = Self::generate_b0(
            params.nonce,
            params.aad.len(),
            payload.len(),
            params.tag_len,
        )?;
        let mut y = encryptor.encrypt_block(&self.key, b0)?;

        if !params.aad.is_empty() {
            y = self.mac_aad(params.aad, y, encryptor)?;
        }

        for chunk in payload.chunks(AES_BLOCK_LEN) {
            let mut block = [0_u8; AES_BLOCK_LEN];
            block[..chunk.len()].copy_from_slice(chunk);
            xor_block(&mut block, &y);
            y = encryptor.encrypt_block(&self.key, block)?;
        }

        Ok(y)
    }

    fn mac_aad<E>(
        &self,
        aad: &[u8],
        mut y: [u8; AES_BLOCK_LEN],
        encryptor: &E,
    ) -> Result<[u8; AES_BLOCK_LEN], Aes128CcmError>
    where
        E: Aes128BlockEncrypt,
    {
        let aad_len = u16::try_from(aad.len()).map_err(|_| Aes128CcmError::AadTooLong)?;
        let mut offset = 0;
        let mut block = [0_u8; AES_BLOCK_LEN];
        block[..2].copy_from_slice(&aad_len.to_be_bytes());
        let first_len = aad.len().min(14);
        block[2..2 + first_len].copy_from_slice(&aad[..first_len]);
        offset += first_len;
        xor_block(&mut block, &y);
        y = encryptor.encrypt_block(&self.key, block)?;

        while offset < aad.len() {
            let remaining = aad.len() - offset;
            let chunk_len = remaining.min(AES_BLOCK_LEN);
            let mut block = [0_u8; AES_BLOCK_LEN];
            block[..chunk_len].copy_from_slice(&aad[offset..offset + chunk_len]);
            offset += chunk_len;
            xor_block(&mut block, &y);
            y = encryptor.encrypt_block(&self.key, block)?;
        }

        Ok(y)
    }

    fn crypt_in_place<E>(
        &self,
        nonce: &[u8],
        payload: &mut [u8],
        encryptor: &E,
    ) -> Result<(), Aes128CcmError>
    where
        E: Aes128BlockEncrypt,
    {
        for (index, chunk) in payload.chunks_mut(AES_BLOCK_LEN).enumerate() {
            let counter = index
                .checked_add(1)
                .ok_or(Aes128CcmError::CounterTooLarge)?;
            let s = self.generate_s(nonce, counter, encryptor)?;
            xor_prefix(chunk, &s, chunk.len());
        }
        Ok(())
    }

    fn generate_s<E>(
        &self,
        nonce: &[u8],
        counter: usize,
        encryptor: &E,
    ) -> Result<[u8; AES_BLOCK_LEN], Aes128CcmError>
    where
        E: Aes128BlockEncrypt,
    {
        validate_nonce_len(nonce.len())?;
        let q = length_field_len(nonce.len());
        validate_counter(q, counter)?;
        let mut block = [0_u8; AES_BLOCK_LEN];
        block[0] |= ((q - 1) & 0x07) as u8;
        block[1..1 + nonce.len()].copy_from_slice(nonce);
        encode_length(counter, q, &mut block)?;
        encryptor.encrypt_block(&self.key, block)
    }
}

fn validate_params(params: Aes128CcmParams<'_>, payload_len: usize) -> Result<(), Aes128CcmError> {
    validate_nonce_len(params.nonce.len())?;
    validate_tag_len(params.tag_len)?;
    validate_payload_len(params.nonce.len(), payload_len)?;
    if params.aad.len() > u16::MAX as usize {
        return Err(Aes128CcmError::AadTooLong);
    }
    Ok(())
}

fn validate_nonce_len(nonce_len: usize) -> Result<(), Aes128CcmError> {
    if (7..=13).contains(&nonce_len) {
        Ok(())
    } else {
        Err(Aes128CcmError::InvalidNonceLength)
    }
}

fn validate_tag_len(tag_len: usize) -> Result<(), Aes128CcmError> {
    if (4..=16).contains(&tag_len) && tag_len.is_multiple_of(2) {
        Ok(())
    } else {
        Err(Aes128CcmError::InvalidTagLength)
    }
}

fn validate_payload_len(nonce_len: usize, payload_len: usize) -> Result<(), Aes128CcmError> {
    let q = length_field_len(nonce_len);
    if q >= core::mem::size_of::<usize>() {
        return Ok(());
    }
    let Some(limit) = 1_usize.checked_shl((q * 8) as u32) else {
        return Ok(());
    };
    if payload_len < limit {
        Ok(())
    } else {
        Err(Aes128CcmError::PayloadTooLong)
    }
}

fn validate_counter(field_len: usize, counter: usize) -> Result<(), Aes128CcmError> {
    if field_len >= core::mem::size_of::<usize>() {
        return Ok(());
    }
    let Some(limit) = 1_usize.checked_shl((field_len * 8) as u32) else {
        return Ok(());
    };
    if counter < limit {
        Ok(())
    } else {
        Err(Aes128CcmError::CounterTooLarge)
    }
}

const fn length_field_len(nonce_len: usize) -> usize {
    AES_BLOCK_LEN - 1 - nonce_len
}

fn encode_length(
    value: usize,
    field_len: usize,
    block: &mut [u8; AES_BLOCK_LEN],
) -> Result<(), Aes128CcmError> {
    if field_len < core::mem::size_of::<usize>() {
        let Some(limit) = 1_usize.checked_shl((field_len * 8) as u32) else {
            return Err(Aes128CcmError::PayloadTooLong);
        };
        if value >= limit {
            return Err(Aes128CcmError::PayloadTooLong);
        }
    }

    for i in 0..field_len {
        let shift = (field_len - 1 - i) * 8;
        block[AES_BLOCK_LEN - field_len + i] = ((value >> shift) & 0xff) as u8;
    }
    Ok(())
}

fn xor_block(block: &mut [u8; AES_BLOCK_LEN], y: &[u8; AES_BLOCK_LEN]) {
    for (target, source) in block.iter_mut().zip(y.iter()) {
        *target ^= *source;
    }
}

fn xor_prefix(target: &mut [u8], source: &[u8; AES_BLOCK_LEN], len: usize) {
    for (target_byte, source_byte) in target.iter_mut().zip(source.iter()).take(len) {
        *target_byte ^= *source_byte;
    }
}

fn tag_matches(expected: &[u8; AES_BLOCK_LEN], actual: &[u8; AES_BLOCK_LEN], len: usize) -> bool {
    let mut diff = 0_u8;
    for (expected_byte, actual_byte) in expected.iter().zip(actual.iter()).take(len) {
        diff |= expected_byte ^ actual_byte;
    }
    diff == 0
}
