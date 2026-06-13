//! SHA public API skeleton migrated from `lib/sha.h`.

/// SHA operation succeeded.
pub const SHA_SUCCESS: i32 = 0;
/// A null pointer parameter was supplied in the C API.
pub const SHA_NULL: i32 = 1;
/// Input data exceeded the algorithm limit.
pub const SHA_INPUT_TOO_LONG: i32 = 2;
/// Input was supplied after finalization.
pub const SHA_STATE_ERROR: i32 = 3;
/// A bad parameter was supplied.
pub const SHA_BAD_PARAM: i32 = 4;

/// SHA-1 message block size in bytes.
pub const SHA1_MESSAGE_BLOCK_SIZE: usize = 64;
/// SHA-1 digest size in bytes.
pub const SHA1_HASH_SIZE: usize = 20;
/// SHA-1 digest size in bits.
pub const SHA1_HASH_SIZE_BITS: usize = 160;
/// SHA-224 message block size in bytes.
pub const SHA224_MESSAGE_BLOCK_SIZE: usize = 64;
/// SHA-224 digest size in bytes.
pub const SHA224_HASH_SIZE: usize = 28;
/// SHA-224 digest size in bits.
pub const SHA224_HASH_SIZE_BITS: usize = 224;
/// SHA-256 message block size in bytes.
pub const SHA256_MESSAGE_BLOCK_SIZE: usize = 64;
/// SHA-256 digest size in bytes.
pub const SHA256_HASH_SIZE: usize = 32;
/// SHA-256 digest size in bits.
pub const SHA256_HASH_SIZE_BITS: usize = 256;
/// SHA-384 message block size in bytes.
pub const SHA384_MESSAGE_BLOCK_SIZE: usize = 128;
/// SHA-384 digest size in bytes.
pub const SHA384_HASH_SIZE: usize = 48;
/// SHA-384 digest size in bits.
pub const SHA384_HASH_SIZE_BITS: usize = 384;
/// SHA-512 message block size in bytes.
pub const SHA512_MESSAGE_BLOCK_SIZE: usize = 128;
/// SHA-512 digest size in bytes.
pub const SHA512_HASH_SIZE: usize = 64;
/// SHA-512 digest size in bits.
pub const SHA512_HASH_SIZE_BITS: usize = 512;
/// Maximum message block size across supported SHA variants.
pub const USHA_MAX_MESSAGE_BLOCK_SIZE: usize = SHA512_MESSAGE_BLOCK_SIZE;
/// Maximum digest size across supported SHA variants.
pub const USHA_MAX_HASH_SIZE: usize = SHA512_HASH_SIZE;
/// Maximum digest bit size across supported SHA variants.
pub const USHA_MAX_HASH_SIZE_BITS: usize = SHA512_HASH_SIZE_BITS;

/// Unified SHA variant selector corresponding to `SHAversion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShaVersion {
    /// SHA-1.
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl ShaVersion {
    /// Returns the message block size for the selected SHA variant.
    #[must_use]
    pub const fn block_size(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha224 | Self::Sha256 => SHA256_MESSAGE_BLOCK_SIZE,
            Self::Sha384 | Self::Sha512 => SHA512_MESSAGE_BLOCK_SIZE,
        }
    }

    /// Returns the digest size for the selected SHA variant.
    #[must_use]
    pub const fn hash_size(self) -> usize {
        match self {
            Self::Sha1 => SHA1_HASH_SIZE,
            Self::Sha224 => SHA224_HASH_SIZE,
            Self::Sha256 => SHA256_HASH_SIZE,
            Self::Sha384 => SHA384_HASH_SIZE,
            Self::Sha512 => SHA512_HASH_SIZE,
        }
    }

    /// Returns the digest bit size for the selected SHA variant.
    #[must_use]
    pub const fn hash_size_bits(self) -> usize {
        self.hash_size() * 8
    }
}

/// SHA-256 context layout from `SHA256Context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha256ContextHeader {
    /// Intermediate digest words.
    pub intermediate_hash: [u32; SHA256_HASH_SIZE / 4],
    /// Low 32 bits of the bit length.
    pub length_low: u32,
    /// High 32 bits of the bit length.
    pub length_high: u32,
    /// Current message block cursor.
    pub message_block_index: i16,
    /// Current message block bytes.
    pub message_block: [u8; SHA256_MESSAGE_BLOCK_SIZE],
    /// Whether the digest has been computed.
    pub computed: bool,
    /// Whether the context has been corrupted.
    pub corrupted: bool,
}

impl Default for Sha256ContextHeader {
    fn default() -> Self {
        Self {
            intermediate_hash: [0; SHA256_HASH_SIZE / 4],
            length_low: 0,
            length_high: 0,
            message_block_index: 0,
            message_block: [0; SHA256_MESSAGE_BLOCK_SIZE],
            computed: false,
            corrupted: false,
        }
    }
}

/// SHA-512 context layout from `SHA512Context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha512ContextHeader {
    /// Intermediate digest words.
    pub intermediate_hash: [u64; SHA512_HASH_SIZE / 8],
    /// Low 64 bits of the bit length.
    pub length_low: u64,
    /// High 64 bits of the bit length.
    pub length_high: u64,
    /// Current message block cursor.
    pub message_block_index: i16,
    /// Current message block bytes.
    pub message_block: [u8; SHA512_MESSAGE_BLOCK_SIZE],
    /// Whether the digest has been computed.
    pub computed: bool,
    /// Whether the context has been corrupted.
    pub corrupted: bool,
}

impl Default for Sha512ContextHeader {
    fn default() -> Self {
        Self {
            intermediate_hash: [0; SHA512_HASH_SIZE / 8],
            length_low: 0,
            length_high: 0,
            message_block_index: 0,
            message_block: [0; SHA512_MESSAGE_BLOCK_SIZE],
            computed: false,
            corrupted: false,
        }
    }
}

/// Header-level unified SHA context skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UshaContextHeader {
    /// Selected SHA variant.
    pub which_sha: ShaVersion,
}

/// Header-level HMAC context skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacContextHeader {
    /// Selected SHA variant.
    pub which_sha: ShaVersion,
    /// Digest size in bytes.
    pub hash_size: usize,
    /// Message block size in bytes.
    pub block_size: usize,
    /// Outer padding buffer.
    pub k_opad: [u8; USHA_MAX_MESSAGE_BLOCK_SIZE],
}

impl HmacContextHeader {
    /// Creates a header-level HMAC context skeleton for `which_sha`.
    #[must_use]
    pub fn new(which_sha: ShaVersion) -> Self {
        Self {
            which_sha,
            hash_size: which_sha.hash_size(),
            block_size: which_sha.block_size(),
            k_opad: [0; USHA_MAX_MESSAGE_BLOCK_SIZE],
        }
    }
}
