//! Apple CommonCrypto AES adapter migrated from `lib/aes_apple.c`.
//!
//! The legacy C file provides the Apple-specific AES-128 ECB encryption entry
//! point used behind the generic AES helper. This Rust module mirrors the public
//! shape and input constraints without binding CommonCrypto directly. Until a
//! platform CommonCrypto binding is introduced, it falls back to the reference AES implementation.

/// AES-128 key length accepted by the Apple CommonCrypto adapter.
pub const AES128_KEY_LEN: usize = 16;

/// AES-128 block size processed by the Apple CommonCrypto adapter.
pub const AES128_BLOCK_SIZE: usize = 16;

/// Fixed-size AES-128 key passed to `AES128_ECB_encrypt_apple` in C.
pub type Aes128Key = [u8; AES128_KEY_LEN];

/// Fixed-size AES-128 input or output block processed by the Apple adapter.
pub type Aes128Block = [u8; AES128_BLOCK_SIZE];

/// Result of an AES-128 ECB encryption request through the Apple adapter shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes128EcbEncryption {
    /// Input block that would be passed to CommonCrypto.
    pub input: Aes128Block,
    /// Key material that would be passed to CommonCrypto.
    pub key: Aes128Key,
    /// Encrypted output block.
    pub output: Aes128Block,
    /// Whether the Rust implementation used a native Apple CommonCrypto backend.
    pub backend_available: bool,
}

impl Aes128EcbEncryption {
    /// Creates an encryption result for the Apple AES-128 ECB path.
    ///
    /// The C implementation has no way to report CommonCrypto setup failures to its caller.
    /// Rust currently preserves the Apple adapter shape and uses the reference backend.
    #[must_use]
    pub fn new(input: Aes128Block, key: Aes128Key) -> Self {
        let output = super::aes_reference::aes128_ecb_encrypt_reference(input, key);
        Self {
            input,
            key,
            output,
            backend_available: false,
        }
    }

    /// Returns the encrypted block.
    #[must_use]
    pub const fn output(&self) -> Aes128Block {
        self.output
    }
}

/// Apple AES-128 ECB adapter state matching `lib/aes_apple.c` responsibilities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AppleAes128Ecb;

impl AppleAes128Ecb {
    /// Creates an Apple AES-128 ECB adapter skeleton.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Encrypts one AES-128 block with one AES-128 key through the Apple path.
    ///
    /// This mirrors `AES128_ECB_encrypt_apple` from C. It validates the fixed
    /// block/key shape at the type level and returns a placeholder result without
    /// invoking CommonCrypto or performing AES encryption.
    #[must_use]
    pub fn encrypt_block(&self, input: Aes128Block, key: Aes128Key) -> Aes128EcbEncryption {
        let _ = self;
        Aes128EcbEncryption::new(input, key)
    }
}

/// Mirrors the C `AES128_ECB_encrypt_apple` entry point as a Rust skeleton.
///
/// The function name follows Rust naming conventions while preserving the C
/// function's semantics: one fixed AES-128 block, one fixed AES-128 key, and one
/// fixed output block. The returned block is a placeholder until an Apple
/// CommonCrypto backend is introduced; until then it returns reference AES output.
#[must_use]
pub fn aes128_ecb_encrypt_apple(input: Aes128Block, key: Aes128Key) -> Aes128Block {
    AppleAes128Ecb::new().encrypt_block(input, key).output()
}
