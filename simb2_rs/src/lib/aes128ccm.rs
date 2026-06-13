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
    /// The cryptographic AES-128 CCM body has not been migrated yet.
    CryptoNotImplemented,
    /// The provided authentication tag does not match the plaintext and AAD.
    AuthenticationFailed,
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
    /// [`Aes128CcmError::PayloadTooLong`] if `payload_len` cannot be encoded in the mirrored
    /// four-byte payload length field.
    pub fn generate_b0(
        nonce: &[u8],
        aad_len: usize,
        payload_len: usize,
        tag_len: usize,
    ) -> Result<[u8; AES_BLOCK_LEN], Aes128CcmError> {
        validate_nonce_len(nonce.len())?;
        validate_tag_len(tag_len)?;

        let payload_len = u32::try_from(payload_len).map_err(|_| Aes128CcmError::PayloadTooLong)?;
        let mut block = [0_u8; AES_BLOCK_LEN];
        if aad_len != 0 {
            block[0] |= 0x40;
        }
        block[0] |= (((tag_len - 2) / 2) << 3) as u8 & 0x38;
        block[0] |= ((AES_BLOCK_LEN - nonce.len() - 1) & 0x07) as u8;
        block[1..1 + nonce.len()].copy_from_slice(nonce);
        block[12..AES_BLOCK_LEN].copy_from_slice(&payload_len.to_be_bytes());
        Ok(block)
    }

    /// Encrypts a payload in place and returns the CCM authentication tag.
    ///
    /// This mirrors the public C `aes128ccm_encrypt` entry point. The AES block transform and
    /// counter-mode body are intentionally left as future migration work.
    ///
    /// # Errors
    ///
    /// Returns validation errors for invalid CCM parameters, or
    /// [`Aes128CcmError::CryptoNotImplemented`] until the AES-128 CCM algorithm is migrated.
    pub fn encrypt_in_place(
        &self,
        params: Aes128CcmParams<'_>,
        payload: &mut [u8],
    ) -> Result<CcmTag, Aes128CcmError> {
        Self::generate_b0(
            params.nonce,
            params.aad.len(),
            payload.len(),
            params.tag_len,
        )?;
        Err(Aes128CcmError::CryptoNotImplemented)
    }

    /// Decrypts a payload in place and verifies the supplied CCM authentication tag.
    ///
    /// This mirrors the public C `aes128ccm_decrypt` entry point. The AES block transform and
    /// tag comparison path are intentionally left as future migration work.
    ///
    /// # Errors
    ///
    /// Returns validation errors for invalid CCM parameters,
    /// [`Aes128CcmError::AuthenticationFailed`] when a migrated implementation rejects the tag,
    /// or [`Aes128CcmError::CryptoNotImplemented`] until the algorithm is migrated.
    pub fn decrypt_in_place(
        &self,
        params: Aes128CcmParams<'_>,
        payload: &mut [u8],
        tag: &CcmTag,
    ) -> Result<(), Aes128CcmError> {
        Self::generate_b0(
            params.nonce,
            params.aad.len(),
            payload.len(),
            params.tag_len,
        )?;
        let _ = (payload, tag);
        Err(Aes128CcmError::CryptoNotImplemented)
    }
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
