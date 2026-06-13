//! Unified SHA digest helpers migrated from `lib/usha.c`.

use super::{sha1, sha224_256, sha384_512};

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

/// Per-algorithm storage for a unified SHA context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UshaContextData {
    /// SHA-1 context storage.
    Sha1(sha1::Sha1Context),
    /// SHA-224 context storage.
    Sha224(sha224_256::Sha224Context),
    /// SHA-256 context storage.
    Sha256(sha224_256::Sha256Context),
    /// SHA-384 context storage.
    Sha384(sha384_512::Sha384Context),
    /// SHA-512 context storage.
    Sha512(sha384_512::Sha512Context),
}

impl UshaContextData {
    fn new(which_sha: SHAversion) -> Self {
        match which_sha {
            SHAversion::SHA1 => Self::Sha1(sha1::Sha1Context::new()),
            SHAversion::SHA224 => Self::Sha224(sha224_256::Sha256Context::new_sha224()),
            SHAversion::SHA256 => Self::Sha256(sha224_256::Sha256Context::new_sha256()),
            SHAversion::SHA384 => Self::Sha384(sha384_512::Sha512Context::new_sha384()),
            SHAversion::SHA512 => Self::Sha512(sha384_512::Sha512Context::new_sha512()),
        }
    }

    fn input(&mut self, bytes: &[u8]) -> ShaErrorCode {
        match self {
            Self::Sha1(ctx) => map_sha1(ctx.input(bytes)),
            Self::Sha224(ctx) => map_sha224_256(ctx.sha224_input(bytes)),
            Self::Sha256(ctx) => map_sha224_256(ctx.sha256_input(bytes)),
            Self::Sha384(ctx) => map_sha384_512(ctx.input(bytes)),
            Self::Sha512(ctx) => map_sha384_512(ctx.input(bytes)),
        }
    }

    fn final_bits(&mut self, bits: u8, bitcount: usize) -> ShaErrorCode {
        if !(1..=7).contains(&bitcount) {
            return ShaErrorCode::ShaBadParam;
        }

        match self {
            Self::Sha1(ctx) => map_sha1(ctx.final_bits(bits, bitcount)),
            Self::Sha224(ctx) => map_sha224_256(ctx.sha224_final_bits(bits, bitcount)),
            Self::Sha256(ctx) => map_sha224_256(ctx.sha256_final_bits(bits, bitcount)),
            Self::Sha384(ctx) => map_sha384_512(ctx.final_bits(bits, bitcount)),
            Self::Sha512(ctx) => map_sha384_512(ctx.final_bits(bits, bitcount)),
        }
    }

    fn result(&mut self, message_digest: &mut [u8; USHA_MAX_HASH_SIZE]) -> ShaErrorCode {
        match self {
            Self::Sha1(ctx) => match ctx.result() {
                Ok(digest) => {
                    message_digest[..SHA1_HASH_SIZE].copy_from_slice(&digest);
                    ShaErrorCode::ShaSuccess
                }
                Err(error) => map_sha1::<()>(Err(error)),
            },
            Self::Sha224(ctx) => match ctx.sha224_result() {
                Ok(digest) => {
                    message_digest[..SHA224_HASH_SIZE].copy_from_slice(&digest);
                    ShaErrorCode::ShaSuccess
                }
                Err(error) => map_sha224_256(error),
            },
            Self::Sha256(ctx) => match ctx.sha256_result() {
                Ok(digest) => {
                    message_digest[..SHA256_HASH_SIZE].copy_from_slice(&digest);
                    ShaErrorCode::ShaSuccess
                }
                Err(error) => map_sha224_256(error),
            },
            Self::Sha384(ctx) => {
                let mut digest = [0u8; SHA384_HASH_SIZE];
                match ctx.result(&mut digest) {
                    Ok(()) => {
                        message_digest[..SHA384_HASH_SIZE].copy_from_slice(&digest);
                        ShaErrorCode::ShaSuccess
                    }
                    Err(error) => map_sha384_512::<()>(Err(error)),
                }
            }
            Self::Sha512(ctx) => {
                let mut digest = [0u8; SHA512_HASH_SIZE];
                match ctx.result(&mut digest) {
                    Ok(()) => {
                        message_digest[..SHA512_HASH_SIZE].copy_from_slice(&digest);
                        ShaErrorCode::ShaSuccess
                    }
                    Err(error) => map_sha384_512::<()>(Err(error)),
                }
            }
        }
    }
}

fn map_sha1<T>(result: sha1::Sha1Result<T>) -> ShaErrorCode {
    match result {
        Ok(_) => ShaErrorCode::ShaSuccess,
        Err(sha1::Sha1Error::Null) => ShaErrorCode::ShaNull,
        Err(sha1::Sha1Error::InputTooLong) => ShaErrorCode::ShaInputTooLong,
        Err(sha1::Sha1Error::StateError) => ShaErrorCode::ShaStateError,
        Err(sha1::Sha1Error::BadParam) => ShaErrorCode::ShaBadParam,
    }
}

fn map_sha224_256(error: sha224_256::ShaError) -> ShaErrorCode {
    match error {
        sha224_256::ShaError::Success => ShaErrorCode::ShaSuccess,
        sha224_256::ShaError::Null => ShaErrorCode::ShaNull,
        sha224_256::ShaError::State => ShaErrorCode::ShaStateError,
    }
}

fn map_sha384_512<T>(result: sha384_512::Result<T>) -> ShaErrorCode {
    match result {
        Ok(_) => ShaErrorCode::ShaSuccess,
        Err(sha384_512::Sha384512Error::InputTooLong) => ShaErrorCode::ShaInputTooLong,
        Err(sha384_512::Sha384512Error::StateError) => ShaErrorCode::ShaStateError,
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
        ShaErrorCode::ShaSuccess
    }

    /// Accepts the next portion of message bytes for this context.
    pub fn input(&mut self, bytes: &[u8]) -> ShaErrorCode {
        self.ctx.input(bytes)
    }

    /// Adds final message bits in the upper portion of `bits`.
    pub fn final_bits(&mut self, bits: u8, bitcount: usize) -> ShaErrorCode {
        self.ctx.final_bits(bits, bitcount)
    }

    /// Writes the message digest into `message_digest`.
    pub fn result(&mut self, message_digest: &mut [u8; USHA_MAX_HASH_SIZE]) -> ShaErrorCode {
        self.ctx.result(message_digest)
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
