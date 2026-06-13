//! HMAC-MD5 helpers migrated from `lib/hmac-md5.c`.

/// MD5 digest length used by HMAC-MD5.
pub const HMAC_MD5_DIGEST_LEN: usize = 16;

/// MD5 block length used by the HMAC inner and outer pads.
pub const HMAC_MD5_BLOCK_LEN: usize = 64;

const HMAC_MD5_IPAD: u8 = 0x36;
const HMAC_MD5_OPAD: u8 = 0x5c;

/// Fixed-size HMAC-MD5 digest buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HmacMd5Digest {
    bytes: [u8; HMAC_MD5_DIGEST_LEN],
}

impl HmacMd5Digest {
    /// Creates a digest wrapper from raw digest bytes.
    #[must_use]
    pub const fn new(bytes: [u8; HMAC_MD5_DIGEST_LEN]) -> Self {
        Self { bytes }
    }

    /// Creates a zero-filled digest placeholder for the migration skeleton.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self::new([0; HMAC_MD5_DIGEST_LEN])
    }

    /// Returns the digest as a borrowed byte slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HMAC_MD5_DIGEST_LEN] {
        &self.bytes
    }

    /// Consumes the wrapper and returns the raw digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; HMAC_MD5_DIGEST_LEN] {
        self.bytes
    }
}

impl Default for HmacMd5Digest {
    fn default() -> Self {
        Self::zeroed()
    }
}

/// Prepared inner and outer HMAC-MD5 pad buffers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacMd5Pads {
    inner: [u8; HMAC_MD5_BLOCK_LEN],
    outer: [u8; HMAC_MD5_BLOCK_LEN],
}

impl HmacMd5Pads {
    /// Builds the inner and outer pad buffers from key material that is at most one MD5 block.
    ///
    /// Keys longer than [`HMAC_MD5_BLOCK_LEN`] require the MD5 key-folding pass described by
    /// RFC 2104 before this step. This migration skeleton records that requirement in
    /// [`HmacMd5Context`] and does not perform the MD5 compression itself.
    #[must_use]
    pub fn from_block_sized_key(key: &[u8]) -> Self {
        let mut inner = [0; HMAC_MD5_BLOCK_LEN];
        let mut outer = [0; HMAC_MD5_BLOCK_LEN];
        let key_len = key.len().min(HMAC_MD5_BLOCK_LEN);

        inner[..key_len].copy_from_slice(&key[..key_len]);
        outer[..key_len].copy_from_slice(&key[..key_len]);

        for byte in &mut inner {
            *byte ^= HMAC_MD5_IPAD;
        }

        for byte in &mut outer {
            *byte ^= HMAC_MD5_OPAD;
        }

        Self { inner, outer }
    }

    /// Returns the prepared inner pad bytes.
    #[must_use]
    pub const fn inner(&self) -> &[u8; HMAC_MD5_BLOCK_LEN] {
        &self.inner
    }

    /// Returns the prepared outer pad bytes.
    #[must_use]
    pub const fn outer(&self) -> &[u8; HMAC_MD5_BLOCK_LEN] {
        &self.outer
    }
}

impl Default for HmacMd5Pads {
    fn default() -> Self {
        Self::from_block_sized_key(&[])
    }
}

/// Key preparation state for an HMAC-MD5 operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacMd5KeyState {
    /// The key fit in one MD5 block and can be copied directly into the pads.
    BlockSized,
    /// The key exceeded one MD5 block and must first be folded to an MD5 digest.
    NeedsMd5Fold,
}

/// Migration skeleton for the C `smb2_hmac_md5` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacMd5Context {
    pads: HmacMd5Pads,
    key_state: HmacMd5KeyState,
    key_len: usize,
    text_len: usize,
}

impl HmacMd5Context {
    /// Creates a new HMAC-MD5 context skeleton for the provided authentication key.
    ///
    /// The legacy C implementation folds keys longer than 64 bytes with MD5 before building the
    /// pads. This skeleton does not implement that hash pass; callers can inspect
    /// [`Self::key_state`] to detect that the fold is still required.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let key_state = if key.len() > HMAC_MD5_BLOCK_LEN {
            HmacMd5KeyState::NeedsMd5Fold
        } else {
            HmacMd5KeyState::BlockSized
        };

        Self {
            pads: HmacMd5Pads::from_block_sized_key(key),
            key_state,
            key_len: key.len(),
            text_len: 0,
        }
    }

    /// Records additional text bytes for the HMAC-MD5 data stream.
    pub fn update(&mut self, text: &[u8]) {
        self.text_len = self.text_len.saturating_add(text.len());
    }

    /// Finishes the migration skeleton and returns a zero-filled digest placeholder.
    ///
    /// The complete MD5 inner and outer hash passes are intentionally not implemented here yet.
    #[must_use]
    pub const fn finalize(&self) -> HmacMd5Digest {
        HmacMd5Digest::zeroed()
    }

    /// Returns the prepared HMAC-MD5 pads.
    #[must_use]
    pub const fn pads(&self) -> &HmacMd5Pads {
        &self.pads
    }

    /// Returns the key preparation state.
    #[must_use]
    pub const fn key_state(&self) -> HmacMd5KeyState {
        self.key_state
    }

    /// Returns the original key length supplied to the context.
    #[must_use]
    pub const fn key_len(&self) -> usize {
        self.key_len
    }

    /// Returns the total text length recorded by [`Self::update`].
    #[must_use]
    pub const fn text_len(&self) -> usize {
        self.text_len
    }
}

/// One-shot skeleton corresponding to the C `smb2_hmac_md5` function.
///
/// This records the same input roles as the C API: text stream, authentication key, and caller
/// digest output. It currently returns a zero-filled digest placeholder instead of computing the
/// MD5 inner and outer passes.
#[must_use]
pub fn smb2_hmac_md5(text: &[u8], key: &[u8]) -> HmacMd5Digest {
    let mut context = HmacMd5Context::new(key);
    context.update(text);
    context.finalize()
}
