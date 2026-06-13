//! AES helpers migrated from `lib/aes.c`.

use core::fmt;

/// AES-128 key size in bytes.
pub const AES128_KEY_LEN: usize = 16;

/// AES block size in bytes.
pub const AES128_BLOCK_LEN: usize = 16;

/// AES-128 block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesBlock(pub [u8; AES128_BLOCK_LEN]);

impl AesBlock {
    /// Creates an AES block from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; AES128_BLOCK_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the block as raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AES128_BLOCK_LEN] {
        &self.0
    }

    /// Consumes the block and returns its raw bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; AES128_BLOCK_LEN] {
        self.0
    }
}

/// AES-128 key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes128Key(pub [u8; AES128_KEY_LEN]);

impl Aes128Key {
    /// Creates AES-128 key material from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; AES128_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the key as raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AES128_KEY_LEN] {
        &self.0
    }

    /// Consumes the key and returns its raw bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; AES128_KEY_LEN] {
        self.0
    }
}

/// Backend selected by the `lib/aes.c` dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesBackend {
    /// Apple CommonCrypto backend corresponding to `lib/aes_apple.c`.
    Apple,
    /// Portable reference backend corresponding to `lib/aes_reference.c`.
    Reference,
}

impl AesBackend {
    /// Returns the backend selected by the original C preprocessor branch.
    #[must_use]
    pub const fn platform_default() -> Self {
        if cfg!(target_vendor = "apple") {
            Self::Apple
        } else {
            Self::Reference
        }
    }
}

/// Errors returned by AES migration skeleton entry points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesError {
    /// The selected backend has not been migrated to Rust yet.
    BackendNotImplemented(AesBackend),
}

impl fmt::Display for AesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendNotImplemented(backend) => {
                write!(formatter, "AES backend {backend:?} is not implemented")
            }
        }
    }
}

impl std::error::Error for AesError {}

/// AES-128 ECB encryptor state mirroring the `AES128_ECB_encrypt` inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes128Ecb {
    key: Aes128Key,
    backend: AesBackend,
}

impl Aes128Ecb {
    /// Creates an AES-128 ECB encryptor with an explicit backend.
    #[must_use]
    pub const fn new(key: Aes128Key, backend: AesBackend) -> Self {
        Self { key, backend }
    }

    /// Creates an AES-128 ECB encryptor using the platform backend selected by `lib/aes.c`.
    #[must_use]
    pub const fn platform_default(key: Aes128Key) -> Self {
        Self::new(key, AesBackend::platform_default())
    }

    /// Returns the configured AES-128 key material.
    #[must_use]
    pub const fn key(&self) -> Aes128Key {
        self.key
    }

    /// Returns the configured backend.
    #[must_use]
    pub const fn backend(&self) -> AesBackend {
        self.backend
    }

    /// Encrypts one AES block using the configured backend.
    ///
    /// This is a migration skeleton for `AES128_ECB_encrypt`; backend-specific encryption logic
    /// still belongs in the Rust counterparts of `lib/aes_apple.c` and `lib/aes_reference.c`.
    ///
    /// # Errors
    ///
    /// Returns [`AesError::BackendNotImplemented`] until the selected backend is migrated.
    pub fn encrypt_block(&self, input: AesBlock) -> Result<AesBlock, AesError> {
        aes128_ecb_encrypt_with_backend(input, self.key, self.backend)
    }
}

/// Encrypts one AES block using the platform backend selected by `lib/aes.c`.
///
/// This function mirrors the role of the C `AES128_ECB_encrypt` dispatcher without implementing
/// the backend encryption algorithm yet.
///
/// # Errors
///
/// Returns [`AesError::BackendNotImplemented`] until the platform backend is migrated.
pub fn aes128_ecb_encrypt(input: AesBlock, key: Aes128Key) -> Result<AesBlock, AesError> {
    aes128_ecb_encrypt_with_backend(input, key, AesBackend::platform_default())
}

/// Encrypts one AES block using an explicit backend.
///
/// This is the Rust dispatcher corresponding to `AES128_ECB_encrypt` in `lib/aes.c`.
///
/// # Errors
///
/// Returns [`AesError::BackendNotImplemented`] until the selected backend is migrated.
pub fn aes128_ecb_encrypt_with_backend(
    input: AesBlock,
    key: Aes128Key,
    backend: AesBackend,
) -> Result<AesBlock, AesError> {
    match backend {
        AesBackend::Apple => aes128_ecb_encrypt_apple(input, key),
        AesBackend::Reference => aes128_ecb_encrypt_reference(input, key),
    }
}

fn aes128_ecb_encrypt_apple(_input: AesBlock, _key: Aes128Key) -> Result<AesBlock, AesError> {
    Err(AesError::BackendNotImplemented(AesBackend::Apple))
}

fn aes128_ecb_encrypt_reference(_input: AesBlock, _key: Aes128Key) -> Result<AesBlock, AesError> {
    Err(AesError::BackendNotImplemented(AesBackend::Reference))
}
