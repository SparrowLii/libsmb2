//! Reference AES implementation migrated from `lib/aes_reference.c`.
//!
//! The legacy C file owns the AES-128 reference backend used by ECB and CBC
//! callers. This Rust module mirrors that surface as migration-safe data
//! structures and method skeletons. It intentionally does not implement the AES
//! round transformations for AES-128 ECB encryption.

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

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 11] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

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
    /// This expands the key using the same AES-128 schedule as `smb2_KeyExpansion`.
    #[must_use]
    pub fn new(key: &Aes128Key) -> Self {
        let round_key = expand_key(key);
        Self { round_key }
    }

    /// Mirrors `smb2_KeyExpansion` and returns the current round-key buffer.
    ///
    /// The returned bytes match the C reference `roundKey` layout.
    #[must_use]
    pub const fn round_key(&self) -> &RoundKey {
        &self.round_key
    }

    /// Mirrors `smb2_Cipher` for one AES block.
    #[must_use]
    pub fn cipher_block(&self, input: &AesBlock) -> AesBlock {
        cipher_block(input, &self.round_key)
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
/// This validates ownership and buffer shape through fixed-size arrays and performs AES-128 ECB.
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

fn expand_key(key: &Aes128Key) -> RoundKey {
    let mut round_key = [0; ROUND_KEY_LEN];
    round_key[..KEY_LEN].copy_from_slice(key);

    let mut i = NK;
    while i < NB * (NR + 1) {
        let mut temp = [
            round_key[(i - 1) * 4],
            round_key[(i - 1) * 4 + 1],
            round_key[(i - 1) * 4 + 2],
            round_key[(i - 1) * 4 + 3],
        ];

        if i.is_multiple_of(NK) {
            temp.rotate_left(1);
            for byte in &mut temp {
                *byte = SBOX[usize::from(*byte)];
            }
            temp[0] ^= RCON[i / NK];
        }

        for j in 0..4 {
            round_key[i * 4 + j] = round_key[(i - NK) * 4 + j] ^ temp[j];
        }
        i += 1;
    }

    round_key
}

fn cipher_block(input: &AesBlock, round_key: &RoundKey) -> AesBlock {
    let mut state = block_to_state(input);
    add_round_key(&mut state, round_key, 0);

    for round in 1..NR {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, round_key, round);
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, round_key, NR);

    state_to_block(&state)
}

fn block_to_state(block: &AesBlock) -> Smb2State {
    let mut state = [[0; NB]; NB];
    for column in 0..NB {
        for row in 0..NB {
            state[column][row] = block[column * NB + row];
        }
    }
    state
}

fn state_to_block(state: &Smb2State) -> AesBlock {
    let mut block = [0; BLOCK_LEN];
    for column in 0..NB {
        for row in 0..NB {
            block[column * NB + row] = state[column][row];
        }
    }
    block
}

fn add_round_key(state: &mut Smb2State, round_key: &RoundKey, round: usize) {
    let offset = round * NB * 4;
    for column in 0..NB {
        for row in 0..NB {
            state[column][row] ^= round_key[offset + column * NB + row];
        }
    }
}

fn sub_bytes(state: &mut Smb2State) {
    for column in 0..NB {
        for row in 0..NB {
            state[column][row] = SBOX[usize::from(state[column][row])];
        }
    }
}

fn shift_rows(state: &mut Smb2State) {
    for row in 1..NB {
        let mut shifted = [0; NB];
        for column in 0..NB {
            shifted[column] = state[(column + row) % NB][row];
        }
        for column in 0..NB {
            state[column][row] = shifted[column];
        }
    }
}

fn mix_columns(state: &mut Smb2State) {
    for column in state {
        let original = *column;
        column[0] = xtime(original[0] ^ original[1]) ^ original[1] ^ original[2] ^ original[3];
        column[1] = xtime(original[1] ^ original[2]) ^ original[0] ^ original[2] ^ original[3];
        column[2] = xtime(original[2] ^ original[3]) ^ original[0] ^ original[1] ^ original[3];
        column[3] = xtime(original[3] ^ original[0]) ^ original[0] ^ original[1] ^ original[2];
    }
}

const fn xtime(value: u8) -> u8 {
    (value << 1) ^ (((value >> 7) & 1) * 0x1b)
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

// ---------------------------------------------------------------------------
// C-parity facade mirroring the safe `legacy::aes_reference` binding used by
// the spec tests. `RefAesBlock` here is a 16-byte newtype, distinct from the
// module's `[u8; 16]` type alias used by the lower-level helpers.
// ---------------------------------------------------------------------------

/// 16-byte AES block newtype matching the safe-binding shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefAesBlock(pub [u8; 16]);

/// `USE_AES128_CBC` default value (CBC declarations disabled by default).
#[must_use]
pub fn default_cbc_value() -> i32 { 0 }

/// CBC reference declarations are disabled by default.
#[must_use]
pub fn default_cbc_declarations_enabled() -> bool { false }

/// External ECB declaration value when ECB is disabled.
#[must_use]
pub fn external_ecb_value_when_disabled() -> i32 { 0 }

/// External ECB declarations are disabled when the ECB switch is off.
#[must_use]
pub fn external_ecb_declarations_enabled_when_disabled() -> bool { false }

/// Reference ECB single-block encryption.
#[must_use]
pub fn ecb_encrypt_block(input: RefAesBlock, key: RefAesBlock) -> RefAesBlock {
    RefAesBlock(aes128_ecb_encrypt_reference(input.0, key.0))
}

/// Reference ECB single-block decryption.
#[must_use]
pub fn ecb_decrypt_block(input: RefAesBlock, key: RefAesBlock) -> RefAesBlock {
    RefAesBlock(super::aes::reference_decrypt_block(super::aes::AesBlock(input.0), super::aes::AesBlock(key.0)).0)
}

/// Reference CBC buffer encryption with zero-padded tail.
#[must_use]
pub fn cbc_encrypt(input: &[u8], key: RefAesBlock, iv: RefAesBlock) -> Vec<u8> {
    super::aes::reference_cbc_encrypt(input, super::aes::AesBlock(key.0), super::aes::AesBlock(iv.0))
}

/// Reference CBC buffer decryption with zero-padded tail.
#[must_use]
pub fn cbc_decrypt(input: &[u8], key: RefAesBlock, iv: RefAesBlock) -> Vec<u8> {
    super::aes::reference_cbc_decrypt(input, super::aes::AesBlock(key.0), super::aes::AesBlock(iv.0))
}
