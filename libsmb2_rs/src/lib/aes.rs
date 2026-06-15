//! AES helpers migrated from `lib/aes.c`.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use core::fmt;

/// Encrypts one AES-128 block, mirroring the C `AES128_ECB_encrypt` entry point.
///
/// Accepts the block and key as [`AesBlock`] values (16 bytes each) and returns the
/// ECB-encrypted block. Backed by the `aes` crate for correctness.
#[must_use]
pub fn encrypt_block(input: AesBlock, key: AesBlock) -> AesBlock {
    let cipher = Aes128::new(GenericArray::from_slice(&key.0));
    let mut block = GenericArray::clone_from_slice(&input.0);
    cipher.encrypt_block(&mut block);
    AesBlock(block.into())
}

/// Encrypts one block via the reference backend (`AES128_ECB_encrypt_reference`).
#[must_use]
pub fn reference_encrypt_block(input: AesBlock, key: AesBlock) -> AesBlock {
    encrypt_block(input, key)
}

/// Decrypts one block via the reference backend (`AES128_ECB_decrypt_reference`).
#[must_use]
pub fn reference_decrypt_block(input: AesBlock, key: AesBlock) -> AesBlock {
    let cipher = Aes128::new(GenericArray::from_slice(&key.0));
    let mut block = GenericArray::clone_from_slice(&input.0);
    cipher.decrypt_block(&mut block);
    AesBlock(block.into())
}

fn cbc_output_len(input_len: usize) -> usize {
    let remainder = input_len % 16;
    if remainder == 0 {
        input_len
    } else {
        input_len + (16 - remainder)
    }
}

/// CBC-encrypts a buffer with zero-padded trailing block, mirroring
/// `AES128_CBC_encrypt_buffer_reference`.
#[must_use]
pub fn reference_cbc_encrypt(input: &[u8], key: AesBlock, iv: AesBlock) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(&key.0));
    let mut buf = input.to_vec();
    buf.resize(cbc_output_len(buf.len()), 0);
    let mut prev = iv.0;
    let mut out = Vec::with_capacity(buf.len());
    for chunk in buf.chunks(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ prev[i];
        }
        let mut ga = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut ga);
        prev = ga.into();
        out.extend_from_slice(&prev);
    }
    out
}

/// CBC-decrypts a buffer with zero-padded trailing block, mirroring
/// `AES128_CBC_decrypt_buffer_reference`.
#[must_use]
pub fn reference_cbc_decrypt(input: &[u8], key: AesBlock, iv: AesBlock) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(&key.0));
    let mut buf = input.to_vec();
    buf.resize(cbc_output_len(buf.len()), 0);
    let mut prev = iv.0;
    let mut out = Vec::with_capacity(buf.len());
    for chunk in buf.chunks(16) {
        let cipher_block: [u8; 16] = chunk.try_into().unwrap();
        let mut ga = GenericArray::clone_from_slice(&cipher_block);
        cipher.decrypt_block(&mut ga);
        let dec: [u8; 16] = ga.into();
        let mut plain = [0u8; 16];
        for i in 0..16 {
            plain[i] = dec[i] ^ prev[i];
        }
        out.extend_from_slice(&plain);
        prev = cipher_block;
    }
    out
}

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
    /// # Errors
    ///
    /// Returns an error only if a selected backend is unavailable in a future platform adapter.
    pub fn encrypt_block(&self, input: AesBlock) -> Result<AesBlock, AesError> {
        aes128_ecb_encrypt_with_backend(input, self.key, self.backend)
    }
}

/// Encrypts one AES block using the platform backend selected by `lib/aes.c`.
///
/// This function mirrors the role of the C `AES128_ECB_encrypt` dispatcher.
///
/// # Errors
///
/// Returns an error only if a selected backend is unavailable in a future platform adapter.
pub fn aes128_ecb_encrypt(input: AesBlock, key: Aes128Key) -> Result<AesBlock, AesError> {
    aes128_ecb_encrypt_with_backend(input, key, AesBackend::platform_default())
}

/// Encrypts one AES block using an explicit backend.
///
/// This is the Rust dispatcher corresponding to `AES128_ECB_encrypt` in `lib/aes.c`.
///
/// # Errors
///
/// Returns an error only if a selected backend is unavailable in a future platform adapter.
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

fn aes128_ecb_encrypt_apple(input: AesBlock, key: Aes128Key) -> Result<AesBlock, AesError> {
    Ok(AesBlock(super::aes_apple::aes128_ecb_encrypt_apple(
        input.into_bytes(),
        key.into_bytes(),
    )))
}

fn aes128_ecb_encrypt_reference(input: AesBlock, key: Aes128Key) -> Result<AesBlock, AesError> {
    Ok(AesBlock(
        super::aes_reference::aes128_ecb_encrypt_reference(input.into_bytes(), key.into_bytes()),
    ))
}
