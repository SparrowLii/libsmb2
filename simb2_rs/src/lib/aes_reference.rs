//! Reference AES implementation migrated from `lib/aes_reference.c`.
//!
//! The legacy C file owns the AES-128 reference backend used by ECB and CBC
//! callers. This Rust module mirrors that surface as migration-safe data
//! structures and method skeletons. It intentionally does not implement the AES
//! round transformations yet.

/// Number of columns comprising an AES state matrix.
pub const NB: usize = 4;

/// Number of 32-bit words in an AES-128 key.
pub const NK: usize = 4;

/// AES-128 key length in bytes.
pub const KEY_LEN: usize = 16;

/// AES block length in bytes.
pub const BLOCK_LEN: usize = KEY_LEN;

/// Number of AES-128 cipher rounds.
pub const NR: usize = 10;

/// Expanded AES-128 round-key length used by the C reference implementation.
pub const ROUND_KEY_LEN: usize = NB * (NR + 1) * 4;

/// AES state matrix mirrored from `smb2_state_t` in the C reference file.
pub type Smb2State = [[u8; NB]; NB];

/// AES-128 block used by the ECB and CBC reference helpers.
pub type AesBlock = [u8; BLOCK_LEN];

/// AES-128 key used by the reference implementation.
pub type Aes128Key = [u8; KEY_LEN];

/// Expanded AES-128 round key buffer.
pub type RoundKey = [u8; ROUND_KEY_LEN];

/// Result alias used by AES reference skeleton helpers.
pub type AesReferenceResult<T> = core::result::Result<T, AesReferenceError>;

/// Error type for AES reference skeleton helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesReferenceError {
    /// The output buffer is smaller than the required output length.
    OutputTooSmall {
        /// Required output length in bytes.
        required: usize,
        /// Actual output length in bytes.
        actual: usize,
    },
}

/// AES-128 reference context containing the expanded round-key buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes128Reference {
    /// Expanded round-key material mirrored from the C `roundKey` buffer.
    pub round_key: RoundKey,
}

impl Aes128Reference {
    /// Creates an AES-128 reference context from a fixed-size key.
    ///
    /// This skeleton records the original key in the first round-key block and
    /// leaves the rest of the expansion zeroed until `smb2_KeyExpansion` is fully
    /// migrated.
    #[must_use]
    pub fn new(key: &Aes128Key) -> Self {
        let mut round_key = [0; ROUND_KEY_LEN];
        round_key[..KEY_LEN].copy_from_slice(key);
        Self { round_key }
    }

    /// Mirrors `smb2_KeyExpansion` and returns the current round-key buffer.
    ///
    /// The complete AES key schedule is intentionally not implemented yet.
    #[must_use]
    pub const fn round_key(&self) -> &RoundKey {
        &self.round_key
    }

    /// Mirrors `smb2_Cipher` for one AES block.
    ///
    /// The full AES cipher rounds are intentionally not implemented. The method
    /// returns the input block unchanged so callers can wire buffer ownership and
    /// sizing before the cryptographic backend is migrated.
    #[must_use]
    pub const fn cipher_block(&self, input: &AesBlock) -> AesBlock {
        let _ = self;
        *input
    }

    /// Mirrors `smb2_InvCipher` for one AES block.
    ///
    /// The full AES inverse cipher rounds are intentionally not implemented. The
    /// method returns the input block unchanged as a migration placeholder.
    #[must_use]
    pub const fn inv_cipher_block(&self, input: &AesBlock) -> AesBlock {
        let _ = self;
        *input
    }
}

/// Direction of an ECB reference operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcbMode {
    /// Encrypt one block, mirroring `AES128_ECB_encrypt_reference`.
    Encrypt,
    /// Decrypt one block, mirroring `AES128_ECB_decrypt_reference`.
    Decrypt,
}

/// Summary of a single-block ECB reference operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcbOperation {
    /// Operation direction.
    pub mode: EcbMode,
    /// Input block copied from the legacy `input` pointer.
    pub input: AesBlock,
    /// AES-128 key copied from the legacy `key` pointer.
    pub key: Aes128Key,
    /// Placeholder output block produced by the skeleton operation.
    pub output: AesBlock,
}

impl EcbOperation {
    /// Creates an ECB encryption operation skeleton.
    #[must_use]
    pub fn encrypt(input: AesBlock, key: Aes128Key) -> Self {
        let output = Aes128Reference::new(&key).cipher_block(&input);
        Self {
            mode: EcbMode::Encrypt,
            input,
            key,
            output,
        }
    }

    /// Creates an ECB decryption operation skeleton.
    #[must_use]
    pub fn decrypt(input: AesBlock, key: Aes128Key) -> Self {
        let output = Aes128Reference::new(&key).inv_cipher_block(&input);
        Self {
            mode: EcbMode::Decrypt,
            input,
            key,
            output,
        }
    }
}

/// Direction of a CBC reference buffer operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CbcMode {
    /// Encrypt a buffer, mirroring `AES128_CBC_encrypt_buffer_reference`.
    Encrypt,
    /// Decrypt a buffer, mirroring `AES128_CBC_decrypt_buffer_reference`.
    Decrypt,
}

/// Summary of a CBC reference buffer operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbcOperation {
    /// Operation direction.
    pub mode: CbcMode,
    /// Number of source bytes requested by the caller.
    pub input_len: usize,
    /// Output length after applying the C reference's trailing zero-padded block.
    pub output_len: usize,
    /// Initial IV supplied by the caller.
    pub iv: AesBlock,
}

impl CbcOperation {
    /// Computes the output length used by the CBC C reference helper.
    ///
    /// Non-full trailing input is rounded up by one zero-padded AES block.
    #[must_use]
    pub const fn padded_len(input_len: usize) -> usize {
        let remainder = input_len % BLOCK_LEN;
        if remainder == 0 {
            input_len
        } else {
            input_len + (BLOCK_LEN - remainder)
        }
    }

    /// Creates a CBC operation summary.
    #[must_use]
    pub const fn new(mode: CbcMode, input_len: usize, iv: AesBlock) -> Self {
        Self {
            mode,
            input_len,
            output_len: Self::padded_len(input_len),
            iv,
        }
    }
}

/// Mirrors `AES128_ECB_encrypt_reference` for one fixed-size block.
///
/// This skeleton validates ownership and buffer shape through fixed-size arrays,
/// but intentionally does not perform AES encryption.
#[must_use]
pub fn aes128_ecb_encrypt_reference(input: AesBlock, key: Aes128Key) -> AesBlock {
    EcbOperation::encrypt(input, key).output
}

/// Mirrors `AES128_ECB_decrypt_reference` for one fixed-size block.
///
/// This skeleton validates ownership and buffer shape through fixed-size arrays,
/// but intentionally does not perform AES decryption.
#[must_use]
pub fn aes128_ecb_decrypt_reference(input: AesBlock, key: Aes128Key) -> AesBlock {
    EcbOperation::decrypt(input, key).output
}

/// Mirrors `AES128_CBC_encrypt_buffer_reference` for a caller-provided buffer.
///
/// The skeleton copies input bytes and applies the same zero-padding shape as the
/// C reference for a trailing partial block, but it does not perform CBC XOR or
/// AES block encryption.
///
/// # Errors
///
/// Returns [`AesReferenceError::OutputTooSmall`] when `output` cannot hold the
/// zero-padded CBC result.
pub fn aes128_cbc_encrypt_buffer_reference(
    output: &mut [u8],
    input: &[u8],
    key: &Aes128Key,
    iv: &AesBlock,
) -> AesReferenceResult<CbcOperation> {
    let operation = CbcOperation::new(CbcMode::Encrypt, input.len(), *iv);
    copy_padded_buffer(output, input, operation.output_len)?;
    let _ = Aes128Reference::new(key);
    Ok(operation)
}

/// Mirrors `AES128_CBC_decrypt_buffer_reference` for a caller-provided buffer.
///
/// The skeleton copies input bytes and applies the same zero-padding shape as the
/// C reference for a trailing partial block, but it does not perform CBC XOR or
/// AES block decryption.
///
/// # Errors
///
/// Returns [`AesReferenceError::OutputTooSmall`] when `output` cannot hold the
/// zero-padded CBC result.
pub fn aes128_cbc_decrypt_buffer_reference(
    output: &mut [u8],
    input: &[u8],
    key: &Aes128Key,
    iv: &AesBlock,
) -> AesReferenceResult<CbcOperation> {
    let operation = CbcOperation::new(CbcMode::Decrypt, input.len(), *iv);
    copy_padded_buffer(output, input, operation.output_len)?;
    let _ = Aes128Reference::new(key);
    Ok(operation)
}

fn copy_padded_buffer(
    output: &mut [u8],
    input: &[u8],
    required_len: usize,
) -> AesReferenceResult<()> {
    if output.len() < required_len {
        return Err(AesReferenceError::OutputTooSmall {
            required: required_len,
            actual: output.len(),
        });
    }

    let (target, _) = output.split_at_mut(required_len);
    let (copied, padding) = target.split_at_mut(input.len());
    copied.copy_from_slice(input);
    padding.fill(0);
    Ok(())
}
