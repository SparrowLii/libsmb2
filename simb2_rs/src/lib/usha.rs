//! Unified SHA digest helpers migrated from `lib/usha.c`.
//!
//! The legacy C file dispatches USHA calls to the selected SHA implementation.
//! This Rust module keeps the same responsibility and API shape while the
//! algorithm-specific SHA implementations are still migration skeletons.

/// Largest SHA message block accepted by the unified SHA interface.
pub const USHA_MAX_MESSAGE_BLOCK_SIZE: usize = SHA512_MESSAGE_BLOCK_SIZE;

/// Largest digest buffer accepted by the unified SHA interface.
pub const USHA_MAX_HASH_SIZE: usize = SHA512_HASH_SIZE;

/// Largest digest size in bits accepted by the unified SHA interface.
pub const USHA_MAX_HASH_SIZE_BITS: usize = SHA512_HASH_SIZE_BITS;

/// SHA-1 message block size in bytes.
pub const SHA1_MESSAGE_BLOCK_SIZE: usize = 64;

/// SHA-224 message block size in bytes.
pub const SHA224_MESSAGE_BLOCK_SIZE: usize = 64;

/// SHA-256 message block size in bytes.
pub const SHA256_MESSAGE_BLOCK_SIZE: usize = 64;

/// SHA-384 message block size in bytes.
pub const SHA384_MESSAGE_BLOCK_SIZE: usize = 128;

/// SHA-512 message block size in bytes.
pub const SHA512_MESSAGE_BLOCK_SIZE: usize = 128;

/// SHA-1 digest size in bytes.
pub const SHA1_HASH_SIZE: usize = 20;

/// SHA-224 digest size in bytes.
pub const SHA224_HASH_SIZE: usize = 28;

/// SHA-256 digest size in bytes.
pub const SHA256_HASH_SIZE: usize = 32;

/// SHA-384 digest size in bytes.
pub const SHA384_HASH_SIZE: usize = 48;

/// SHA-512 digest size in bytes.
pub const SHA512_HASH_SIZE: usize = 64;

/// SHA-1 digest size in bits.
pub const SHA1_HASH_SIZE_BITS: usize = 160;

/// SHA-224 digest size in bits.
pub const SHA224_HASH_SIZE_BITS: usize = 224;

/// SHA-256 digest size in bits.
pub const SHA256_HASH_SIZE_BITS: usize = 256;

/// SHA-384 digest size in bits.
pub const SHA384_HASH_SIZE_BITS: usize = 384;

/// SHA-512 digest size in bits.
pub const SHA512_HASH_SIZE_BITS: usize = 512;

/// SHA version selector corresponding to C `enum SHAversion`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SHAversion {
    /// SHA-1 selection.
    SHA1,
    /// SHA-224 selection.
    SHA224,
    /// SHA-256 selection.
    SHA256,
    /// SHA-384 selection.
    SHA384,
    /// SHA-512 selection.
    SHA512,
}

/// Result codes corresponding to the C `sha*` return values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShaErrorCode {
    /// Operation completed successfully.
    ShaSuccess,
    /// A required pointer or buffer was absent in the C API.
    ShaNull,
    /// Input length exceeded the selected SHA implementation limits.
    ShaInputTooLong,
    /// The context is not in a state that can accept the requested operation.
    ShaStateError,
    /// A parameter was outside the range accepted by the C API.
    ShaBadParam,
}

/// Minimal SHA state retained by this migration skeleton.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShaContextState {
    message_block: [u8; USHA_MAX_MESSAGE_BLOCK_SIZE],
    message_block_index: usize,
    byte_count: usize,
    final_bits: Option<(u8, usize)>,
    computed: bool,
    corrupted: Option<ShaErrorCode>,
}

impl Default for ShaContextState {
    fn default() -> Self {
        Self {
            message_block: [0; USHA_MAX_MESSAGE_BLOCK_SIZE],
            message_block_index: 0,
            byte_count: 0,
            final_bits: None,
            computed: false,
            corrupted: None,
        }
    }
}

impl ShaContextState {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn input(&mut self, bytes: &[u8]) -> ShaErrorCode {
        if self.computed || self.final_bits.is_some() {
            self.corrupted = Some(ShaErrorCode::ShaStateError);
            return ShaErrorCode::ShaStateError;
        }

        if self.byte_count.checked_add(bytes.len()).is_none() {
            self.corrupted = Some(ShaErrorCode::ShaInputTooLong);
            return ShaErrorCode::ShaInputTooLong;
        }

        for byte in bytes {
            self.message_block[self.message_block_index] = *byte;
            self.message_block_index = (self.message_block_index + 1) % USHA_MAX_MESSAGE_BLOCK_SIZE;
        }
        self.byte_count += bytes.len();
        ShaErrorCode::ShaSuccess
    }

    fn final_bits(&mut self, bits: u8, bitcount: usize) -> ShaErrorCode {
        if !(1..=7).contains(&bitcount) {
            self.corrupted = Some(ShaErrorCode::ShaBadParam);
            return ShaErrorCode::ShaBadParam;
        }

        if self.computed || self.final_bits.is_some() {
            self.corrupted = Some(ShaErrorCode::ShaStateError);
            return ShaErrorCode::ShaStateError;
        }

        self.final_bits = Some((bits, bitcount));
        ShaErrorCode::ShaSuccess
    }
}

/// Per-algorithm storage for a unified SHA context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UshaContextData {
    /// SHA-1 context storage.
    Sha1(ShaContextState),
    /// SHA-224 context storage.
    Sha224(ShaContextState),
    /// SHA-256 context storage.
    Sha256(ShaContextState),
    /// SHA-384 context storage.
    Sha384(ShaContextState),
    /// SHA-512 context storage.
    Sha512(ShaContextState),
}

impl UshaContextData {
    fn new(which_sha: SHAversion) -> Self {
        match which_sha {
            SHAversion::SHA1 => Self::Sha1(ShaContextState::default()),
            SHAversion::SHA224 => Self::Sha224(ShaContextState::default()),
            SHAversion::SHA256 => Self::Sha256(ShaContextState::default()),
            SHAversion::SHA384 => Self::Sha384(ShaContextState::default()),
            SHAversion::SHA512 => Self::Sha512(ShaContextState::default()),
        }
    }

    fn state_mut(&mut self) -> &mut ShaContextState {
        match self {
            Self::Sha1(state)
            | Self::Sha224(state)
            | Self::Sha256(state)
            | Self::Sha384(state)
            | Self::Sha512(state) => state,
        }
    }
}

/// Unified SHA context corresponding to C `USHAContext`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct USHAContext {
    which_sha: SHAversion,
    ctx: UshaContextData,
}

impl Default for USHAContext {
    fn default() -> Self {
        Self::new(SHAversion::SHA256)
    }
}

impl USHAContext {
    /// Creates a unified SHA context for the selected SHA version.
    pub fn new(which_sha: SHAversion) -> Self {
        Self {
            which_sha,
            ctx: UshaContextData::new(which_sha),
        }
    }

    /// Returns the SHA version currently selected by this context.
    pub fn which_sha(&self) -> SHAversion {
        self.which_sha
    }

    /// Resets this context to compute a new message digest.
    pub fn reset(&mut self, which_sha: SHAversion) -> ShaErrorCode {
        self.which_sha = which_sha;
        self.ctx = UshaContextData::new(which_sha);
        self.ctx.state_mut().reset();
        ShaErrorCode::ShaSuccess
    }

    /// Accepts the next portion of message bytes for this context.
    pub fn input(&mut self, bytes: &[u8]) -> ShaErrorCode {
        self.ctx.state_mut().input(bytes)
    }

    /// Adds final message bits in the upper portion of `bits`.
    pub fn final_bits(&mut self, bits: u8, bitcount: usize) -> ShaErrorCode {
        self.ctx.state_mut().final_bits(bits, bitcount)
    }

    /// Writes the message digest into `message_digest` when hashing is available.
    ///
    /// This migration skeleton does not implement the underlying SHA algorithms;
    /// callers receive `ShaStateError` instead of a placeholder digest.
    pub fn result(&mut self, message_digest: &mut [u8; USHA_MAX_HASH_SIZE]) -> ShaErrorCode {
        let _ = message_digest;
        self.ctx.state_mut().corrupted = Some(ShaErrorCode::ShaStateError);
        ShaErrorCode::ShaStateError
    }
}

/// Initializes a unified SHA context, mirroring C `USHAReset`.
#[allow(non_snake_case)]
pub fn USHAReset(ctx: &mut USHAContext, which_sha: SHAversion) -> ShaErrorCode {
    ctx.reset(which_sha)
}

/// Accepts message bytes, mirroring C `USHAInput`.
#[allow(non_snake_case)]
pub fn USHAInput(ctx: &mut USHAContext, bytes: &[u8]) -> ShaErrorCode {
    ctx.input(bytes)
}

/// Adds final message bits, mirroring C `USHAFinalBits`.
#[allow(non_snake_case)]
pub fn USHAFinalBits(ctx: &mut USHAContext, bits: u8, bitcount: usize) -> ShaErrorCode {
    ctx.final_bits(bits, bitcount)
}

/// Returns a digest for the selected SHA version, mirroring C `USHAResult`.
///
/// The hashing backend is not implemented in this skeleton, so this currently
/// returns `ShaStateError` without writing a digest.
#[allow(non_snake_case)]
pub fn USHAResult(
    ctx: &mut USHAContext,
    message_digest: &mut [u8; USHA_MAX_HASH_SIZE],
) -> ShaErrorCode {
    ctx.result(message_digest)
}

/// Returns the message block size for the selected SHA version.
#[allow(non_snake_case)]
pub fn USHABlockSize(which_sha: SHAversion) -> usize {
    match which_sha {
        SHAversion::SHA1 => SHA1_MESSAGE_BLOCK_SIZE,
        SHAversion::SHA224 => SHA224_MESSAGE_BLOCK_SIZE,
        SHAversion::SHA256 => SHA256_MESSAGE_BLOCK_SIZE,
        SHAversion::SHA384 => SHA384_MESSAGE_BLOCK_SIZE,
        SHAversion::SHA512 => SHA512_MESSAGE_BLOCK_SIZE,
    }
}

/// Returns the digest size in bytes for the selected SHA version.
#[allow(non_snake_case)]
pub fn USHAHashSize(which_sha: SHAversion) -> usize {
    match which_sha {
        SHAversion::SHA1 => SHA1_HASH_SIZE,
        SHAversion::SHA224 => SHA224_HASH_SIZE,
        SHAversion::SHA256 => SHA256_HASH_SIZE,
        SHAversion::SHA384 => SHA384_HASH_SIZE,
        SHAversion::SHA512 => SHA512_HASH_SIZE,
    }
}

/// Returns the digest size in bits for the selected SHA version.
#[allow(non_snake_case)]
pub fn USHAHashSizeBits(which_sha: SHAversion) -> usize {
    match which_sha {
        SHAversion::SHA1 => SHA1_HASH_SIZE_BITS,
        SHAversion::SHA224 => SHA224_HASH_SIZE_BITS,
        SHAversion::SHA256 => SHA256_HASH_SIZE_BITS,
        SHAversion::SHA384 => SHA384_HASH_SIZE_BITS,
        SHAversion::SHA512 => SHA512_HASH_SIZE_BITS,
    }
}
