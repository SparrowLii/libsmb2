//! HMAC helpers migrated from `lib/hmac.c`.

/// Maximum SHA message block size used by the unified SHA/HMAC interface.
pub const USHA_MAX_MESSAGE_BLOCK_SIZE: usize = 128;

/// Maximum digest size accepted by the C HMAC interface.
pub const USHA_MAX_HASH_SIZE: usize = 64;

/// SHA algorithm selector used by the HMAC helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShaVersion {
    /// SHA-1, corresponding to `SHA1` in `sha.h`.
    Sha1,
    /// SHA-224, corresponding to `SHA224` in `sha.h`.
    Sha224,
    /// SHA-256, corresponding to `SHA256` in `sha.h`.
    Sha256,
    /// SHA-384, corresponding to `SHA384` in `sha.h`.
    Sha384,
    /// SHA-512, corresponding to `SHA512` in `sha.h`.
    Sha512,
}

impl ShaVersion {
    /// Returns the SHA message block size in bytes for this algorithm.
    #[must_use]
    pub const fn block_size(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha224 | Self::Sha256 => 64,
            Self::Sha384 | Self::Sha512 => 128,
        }
    }

    /// Returns the SHA digest size in bytes for this algorithm.
    #[must_use]
    pub const fn hash_size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Returns the SHA digest size in bits for this algorithm.
    #[must_use]
    pub const fn hash_size_bits(self) -> usize {
        self.hash_size() * 8
    }
}

/// Error values corresponding to the C SHA/HMAC return codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacError {
    /// A null pointer was supplied to the C API; retained as a Rust API equivalent.
    Null,
    /// The input stream is too long for the selected SHA variant.
    InputTooLong,
    /// The operation was called after finalization.
    State,
    /// A parameter is outside the accepted range.
    BadParam,
}

/// Result alias for HMAC helper operations.
pub type HmacResult<T> = Result<T, HmacError>;

/// HMAC output buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacDigest(pub Vec<u8>);

impl HmacDigest {
    /// Creates an all-zero digest buffer sized for the selected SHA algorithm.
    #[must_use]
    pub fn zeroed(which_sha: ShaVersion) -> Self {
        Self(vec![0; which_sha.hash_size()])
    }

    /// Returns the digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Minimal unified SHA state placeholder used by the HMAC migration skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UshaContext {
    which_sha: ShaVersion,
    input_len: usize,
    final_bits: Option<(u8, usize)>,
    finalized: bool,
}

impl UshaContext {
    /// Creates a new placeholder USHA context for the selected SHA algorithm.
    #[must_use]
    pub const fn new(which_sha: ShaVersion) -> Self {
        Self {
            which_sha,
            input_len: 0,
            final_bits: None,
            finalized: false,
        }
    }

    /// Resets this placeholder USHA context to the selected algorithm.
    pub fn reset(&mut self, which_sha: ShaVersion) {
        *self = Self::new(which_sha);
    }

    /// Records additional input bytes for the placeholder SHA pass.
    ///
    /// # Errors
    ///
    /// Returns [`HmacError::State`] if input is added after final bits or a result.
    pub fn input(&mut self, bytes: &[u8]) -> HmacResult<()> {
        if self.final_bits.is_some() || self.finalized {
            return Err(HmacError::State);
        }

        self.input_len = self
            .input_len
            .checked_add(bytes.len())
            .ok_or(HmacError::InputTooLong)?;
        Ok(())
    }

    /// Records final message bits for the placeholder SHA pass.
    ///
    /// # Errors
    ///
    /// Returns [`HmacError::BadParam`] when `bitcount` is not in `1..=7`, or
    /// [`HmacError::State`] if the context was already finalized.
    pub fn final_bits(&mut self, bits: u8, bitcount: usize) -> HmacResult<()> {
        if !(1..=7).contains(&bitcount) {
            return Err(HmacError::BadParam);
        }
        if self.final_bits.is_some() || self.finalized {
            return Err(HmacError::State);
        }

        self.final_bits = Some((bits, bitcount));
        Ok(())
    }

    /// Produces a zeroed digest buffer sized for this context's SHA algorithm.
    ///
    /// This is a migration skeleton and does not compute SHA compression rounds.
    pub fn result(&mut self) -> HmacDigest {
        self.finalized = true;
        HmacDigest::zeroed(self.which_sha)
    }
}

/// HMAC context matching the state carried by `HMACContext` in `sha.h`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacContext {
    which_sha: ShaVersion,
    hash_size: usize,
    block_size: usize,
    sha_context: UshaContext,
    k_opad: [u8; USHA_MAX_MESSAGE_BLOCK_SIZE],
}

impl HmacContext {
    /// Creates and resets an HMAC context for the selected SHA algorithm and key.
    ///
    /// # Errors
    ///
    /// Returns an error if the placeholder inner SHA pass rejects the derived pad.
    pub fn new(which_sha: ShaVersion, key: &[u8]) -> HmacResult<Self> {
        let mut ctx = Self {
            which_sha,
            hash_size: which_sha.hash_size(),
            block_size: which_sha.block_size(),
            sha_context: UshaContext::new(which_sha),
            k_opad: [0; USHA_MAX_MESSAGE_BLOCK_SIZE],
        };
        ctx.reset(which_sha, key)?;
        Ok(ctx)
    }

    /// Resets this context for a new HMAC computation.
    ///
    /// The pad setup follows `hmacReset` from `lib/hmac.c`. Long keys are represented
    /// by a zeroed digest-sized placeholder because full SHA hashing is out of scope.
    ///
    /// # Errors
    ///
    /// Returns an error if the placeholder inner SHA pass rejects the derived pad.
    pub fn reset(&mut self, which_sha: ShaVersion, key: &[u8]) -> HmacResult<()> {
        let block_size = which_sha.block_size();
        let hash_size = which_sha.hash_size();
        let mut k_ipad = [0u8; USHA_MAX_MESSAGE_BLOCK_SIZE];
        let mut tempkey = [0u8; USHA_MAX_HASH_SIZE];

        self.which_sha = which_sha;
        self.hash_size = hash_size;
        self.block_size = block_size;
        self.k_opad = [0; USHA_MAX_MESSAGE_BLOCK_SIZE];
        self.sha_context.reset(which_sha);

        let key = if key.len() > block_size {
            &tempkey[..hash_size]
        } else {
            key
        };

        for (idx, key_byte) in key.iter().copied().enumerate() {
            k_ipad[idx] = key_byte ^ 0x36;
            self.k_opad[idx] = key_byte ^ 0x5c;
        }
        for (ipad, opad) in k_ipad[key.len()..block_size]
            .iter_mut()
            .zip(self.k_opad[key.len()..block_size].iter_mut())
        {
            *ipad = 0x36;
            *opad = 0x5c;
        }

        tempkey.fill(0);
        self.sha_context.input(&k_ipad[..block_size])
    }

    /// Adds message bytes to the inner HMAC pass.
    ///
    /// # Errors
    ///
    /// Returns [`HmacError::State`] if called after final bits or result generation.
    pub fn input(&mut self, text: &[u8]) -> HmacResult<()> {
        self.sha_context.input(text)
    }

    /// Adds final message bits to the inner HMAC pass.
    ///
    /// # Errors
    ///
    /// Returns [`HmacError::BadParam`] when `bitcount` is not in `1..=7`, or
    /// [`HmacError::State`] if the context was already finalized.
    pub fn final_bits(&mut self, bits: u8, bitcount: usize) -> HmacResult<()> {
        self.sha_context.final_bits(bits, bitcount)
    }

    /// Finishes the placeholder HMAC computation and returns a digest-sized buffer.
    ///
    /// This preserves the two-pass control flow from `hmacResult` without implementing
    /// the underlying SHA digest logic.
    ///
    /// # Errors
    ///
    /// Returns an error if the placeholder outer SHA pass rejects its inputs.
    pub fn result(&mut self) -> HmacResult<HmacDigest> {
        let inner_digest = self.sha_context.result();

        self.sha_context.reset(self.which_sha);
        self.sha_context.input(&self.k_opad[..self.block_size])?;
        self.sha_context
            .input(&inner_digest.as_bytes()[..self.hash_size])?;

        Ok(self.sha_context.result())
    }
}

/// Computes a placeholder HMAC digest for a complete message buffer.
///
/// # Errors
///
/// Returns an error if context setup, input, or finalization rejects the supplied data.
pub fn hmac(which_sha: ShaVersion, text: &[u8], key: &[u8]) -> HmacResult<HmacDigest> {
    let mut ctx = HmacContext::new(which_sha, key)?;
    ctx.input(text)?;
    ctx.result()
}
