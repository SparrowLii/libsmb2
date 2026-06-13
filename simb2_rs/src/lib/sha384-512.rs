//! SHA-384 and SHA-512 helpers migrated from `lib/sha384-512.c`.

/// Size in bytes of one SHA-384 message block.
pub const SHA384_MESSAGE_BLOCK_SIZE: usize = 128;

/// Size in bytes of a SHA-384 message digest.
pub const SHA384_HASH_SIZE: usize = 48;

/// Size in bits of a SHA-384 message digest.
pub const SHA384_HASH_SIZE_BITS: usize = 384;

/// Size in bytes of one SHA-512 message block.
pub const SHA512_MESSAGE_BLOCK_SIZE: usize = 128;

/// Size in bytes of a SHA-512 message digest.
pub const SHA512_HASH_SIZE: usize = 64;

/// Size in bits of a SHA-512 message digest.
pub const SHA512_HASH_SIZE_BITS: usize = 512;

const SHA384_H0: [u64; SHA512_HASH_SIZE / 8] = [
    0xCBBB_9D5D_C105_9ED8,
    0x629A_292A_367C_D507,
    0x9159_015A_3070_DD17,
    0x152F_ECD8_F70E_5939,
    0x6733_2667_FFC0_0B31,
    0x8EB4_4A87_6858_1511,
    0xDB0C_2E0D_64F9_8FA7,
    0x47B5_481D_BEFA_4FA4,
];

const SHA512_H0: [u64; SHA512_HASH_SIZE / 8] = [
    0x6A09_E667_F3BC_C908,
    0xBB67_AE85_84CA_A73B,
    0x3C6E_F372_FE94_F82B,
    0xA54F_F53A_5F1D_36F1,
    0x510E_527F_ADE6_82D1,
    0x9B05_688C_2B3E_6C1F,
    0x1F83_D9AB_FB41_BD6B,
    0x5BE0_CD19_137E_2179,
];

const FINAL_BITS_MASKS: [u8; 8] = [0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE];
const FINAL_BITS_MARK: [u8; 8] = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];

/// SHA-384 or SHA-512 variant used by a [`Sha512Context`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Sha384512Variant {
    /// SHA-384 using the SHA-512 block function and a 384-bit result.
    Sha384,
    /// SHA-512 using the SHA-512 block function and a 512-bit result.
    Sha512,
}

impl Sha384512Variant {
    /// Returns the digest size in bytes for this variant.
    #[must_use]
    pub const fn hash_size(self) -> usize {
        match self {
            Self::Sha384 => SHA384_HASH_SIZE,
            Self::Sha512 => SHA512_HASH_SIZE,
        }
    }

    /// Returns the digest size in bits for this variant.
    #[must_use]
    pub const fn hash_size_bits(self) -> usize {
        match self {
            Self::Sha384 => SHA384_HASH_SIZE_BITS,
            Self::Sha512 => SHA512_HASH_SIZE_BITS,
        }
    }

    const fn initial_hash(self) -> [u64; SHA512_HASH_SIZE / 8] {
        match self {
            Self::Sha384 => SHA384_H0,
            Self::Sha512 => SHA512_H0,
        }
    }
}

/// Error codes corresponding to the legacy SHA return values.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Sha384512Error {
    /// Input data is too long to be represented by the SHA-384/SHA-512 length field.
    InputTooLong,
    /// Input was supplied after final bits or a result had already been requested.
    StateError,
    /// The requested operation requires the compression routine, which is not implemented here.
    AlgorithmNotImplemented,
}

/// Result type used by SHA-384/SHA-512 skeleton operations.
pub type Result<T> = core::result::Result<T, Sha384512Error>;

/// Context information for SHA-512 and SHA-384 hashing operations.
///
/// The layout mirrors the legacy `SHA512Context`: intermediate hash words,
/// a 128-bit bit length, a 1024-bit message block, and computed/corrupted
/// state flags. This module intentionally stops at the migration skeleton and
/// does not implement the SHA-512 compression rounds.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Sha512Context {
    variant: Sha384512Variant,
    intermediate_hash: [u64; SHA512_HASH_SIZE / 8],
    length_low: u64,
    length_high: u64,
    message_block_index: usize,
    message_block: [u8; SHA512_MESSAGE_BLOCK_SIZE],
    computed: bool,
    corrupted: Option<Sha384512Error>,
}

/// SHA-384 uses the same context shape as SHA-512 with different initial hash words.
pub type Sha384Context = Sha512Context;

impl Default for Sha512Context {
    fn default() -> Self {
        Self::new_sha512()
    }
}

impl Sha512Context {
    /// Creates a SHA-384 context initialized with the SHA-384 initial hash words.
    #[must_use]
    pub fn new_sha384() -> Self {
        Self::with_variant(Sha384512Variant::Sha384)
    }

    /// Creates a SHA-512 context initialized with the SHA-512 initial hash words.
    #[must_use]
    pub fn new_sha512() -> Self {
        Self::with_variant(Sha384512Variant::Sha512)
    }

    /// Returns the SHA variant selected for this context.
    #[must_use]
    pub const fn variant(&self) -> Sha384512Variant {
        self.variant
    }

    /// Returns the legacy 1024-bit message block buffer.
    #[must_use]
    pub const fn message_block(&self) -> &[u8; SHA512_MESSAGE_BLOCK_SIZE] {
        &self.message_block
    }

    /// Returns the current message block write index.
    #[must_use]
    pub const fn message_block_index(&self) -> usize {
        self.message_block_index
    }

    /// Returns the accumulated message length as `(high, low)` 64-bit words.
    #[must_use]
    pub const fn bit_length(&self) -> (u64, u64) {
        (self.length_high, self.length_low)
    }

    /// Returns whether finalization has been requested.
    #[must_use]
    pub const fn is_computed(&self) -> bool {
        self.computed
    }

    /// Returns the stored corruption/state error, if any.
    #[must_use]
    pub const fn corrupted(&self) -> Option<Sha384512Error> {
        self.corrupted
    }

    /// Resets the context for a new SHA-384 digest.
    pub fn reset_sha384(&mut self) {
        self.reset_with_variant(Sha384512Variant::Sha384);
    }

    /// Resets the context for a new SHA-512 digest.
    pub fn reset_sha512(&mut self) {
        self.reset_with_variant(Sha384512Variant::Sha512);
    }

    /// Accepts the next bytes of a SHA-384/SHA-512 message.
    ///
    /// # Errors
    ///
    /// Returns [`Sha384512Error::StateError`] if called after finalization,
    /// [`Sha384512Error::InputTooLong`] if the 128-bit length overflows, or
    /// [`Sha384512Error::AlgorithmNotImplemented`] when a full message block
    /// would need to be compressed.
    pub fn input(&mut self, message: &[u8]) -> Result<()> {
        if message.is_empty() {
            return Ok(());
        }

        self.ensure_update_allowed()?;

        for &byte in message {
            self.message_block[self.message_block_index] = byte;
            self.message_block_index += 1;
            self.add_length(8)?;

            if self.message_block_index == SHA512_MESSAGE_BLOCK_SIZE {
                self.process_message_block()?;
            }
        }

        Ok(())
    }

    /// Adds one to seven final message bits from the upper portion of `message_bits`.
    ///
    /// # Errors
    ///
    /// Returns [`Sha384512Error::StateError`] if `length` is not in `1..=7` or
    /// finalization already occurred. Returns [`Sha384512Error::InputTooLong`]
    /// if the 128-bit bit length overflows.
    pub fn final_bits(&mut self, message_bits: u8, length: usize) -> Result<()> {
        if length == 0 {
            return Ok(());
        }

        if length >= 8 {
            return self.mark_corrupted(Sha384512Error::StateError);
        }

        self.ensure_update_allowed()?;
        self.add_length(length as u64)?;
        let pad_byte = (message_bits & FINAL_BITS_MASKS[length]) | FINAL_BITS_MARK[length];
        self.finalize(pad_byte)
    }

    /// Finalizes and writes the digest bytes into `digest`.
    ///
    /// # Errors
    ///
    /// Returns [`Sha384512Error::StateError`] when `digest` is smaller than this
    /// variant's digest size. Returns [`Sha384512Error::AlgorithmNotImplemented`]
    /// because the SHA-512 compression and padding routines are intentionally
    /// left as migration skeletons.
    pub fn result(&mut self, digest: &mut [u8]) -> Result<()> {
        let hash_size = self.variant.hash_size();
        if digest.len() < hash_size {
            return self.mark_corrupted(Sha384512Error::StateError);
        }

        if let Some(error) = self.corrupted {
            return Err(error);
        }

        if !self.computed {
            self.finalize(0x80)?;
        }

        for (index, output) in digest.iter_mut().take(hash_size).enumerate() {
            let word = self.intermediate_hash[index / 8];
            *output = (word >> (8 * (7 - (index % 8)))) as u8;
        }

        Ok(())
    }

    fn with_variant(variant: Sha384512Variant) -> Self {
        Self {
            variant,
            intermediate_hash: variant.initial_hash(),
            length_low: 0,
            length_high: 0,
            message_block_index: 0,
            message_block: [0; SHA512_MESSAGE_BLOCK_SIZE],
            computed: false,
            corrupted: None,
        }
    }

    fn reset_with_variant(&mut self, variant: Sha384512Variant) {
        *self = Self::with_variant(variant);
    }

    fn ensure_update_allowed(&mut self) -> Result<()> {
        if self.computed {
            return self.mark_corrupted(Sha384512Error::StateError);
        }

        if let Some(error) = self.corrupted {
            return Err(error);
        }

        Ok(())
    }

    fn add_length(&mut self, bits: u64) -> Result<()> {
        let (new_low, overflowed_low) = self.length_low.overflowing_add(bits);
        let (new_high, overflowed_high) =
            self.length_high.overflowing_add(u64::from(overflowed_low));

        if overflowed_high {
            return self.mark_corrupted(Sha384512Error::InputTooLong);
        }

        self.length_low = new_low;
        self.length_high = new_high;
        Ok(())
    }

    fn finalize(&mut self, pad_byte: u8) -> Result<()> {
        self.pad_message(pad_byte)?;
        self.message_block.fill(0);
        self.length_low = 0;
        self.length_high = 0;
        self.computed = true;
        Ok(())
    }

    fn pad_message(&mut self, pad_byte: u8) -> Result<()> {
        if self.message_block_index >= SHA512_MESSAGE_BLOCK_SIZE {
            return self.mark_corrupted(Sha384512Error::StateError);
        }

        self.message_block[self.message_block_index] = pad_byte;
        self.message_block_index += 1;

        self.process_message_block()
    }

    fn process_message_block(&mut self) -> Result<()> {
        self.message_block_index = 0;
        self.mark_corrupted(Sha384512Error::AlgorithmNotImplemented)
    }

    fn mark_corrupted<T>(&mut self, error: Sha384512Error) -> Result<T> {
        self.corrupted = Some(error);
        Err(error)
    }
}

/// Creates and resets a SHA-384 context.
#[must_use]
pub fn sha384_reset() -> Sha384Context {
    Sha512Context::new_sha384()
}

/// Feeds bytes into a SHA-384 context.
///
/// # Errors
///
/// Returns the same errors as [`Sha512Context::input`].
pub fn sha384_input(context: &mut Sha384Context, message: &[u8]) -> Result<()> {
    context.input(message)
}

/// Adds final bits to a SHA-384 context.
///
/// # Errors
///
/// Returns the same errors as [`Sha512Context::final_bits`].
pub fn sha384_final_bits(
    context: &mut Sha384Context,
    message_bits: u8,
    length: usize,
) -> Result<()> {
    context.final_bits(message_bits, length)
}

/// Finalizes a SHA-384 context and writes a digest skeleton.
///
/// # Errors
///
/// Returns the same errors as [`Sha512Context::result`].
pub fn sha384_result(context: &mut Sha384Context, digest: &mut [u8]) -> Result<()> {
    context.result(digest)
}

/// Creates and resets a SHA-512 context.
#[must_use]
pub fn sha512_reset() -> Sha512Context {
    Sha512Context::new_sha512()
}

/// Feeds bytes into a SHA-512 context.
///
/// # Errors
///
/// Returns the same errors as [`Sha512Context::input`].
pub fn sha512_input(context: &mut Sha512Context, message: &[u8]) -> Result<()> {
    context.input(message)
}

/// Adds final bits to a SHA-512 context.
///
/// # Errors
///
/// Returns the same errors as [`Sha512Context::final_bits`].
pub fn sha512_final_bits(
    context: &mut Sha512Context,
    message_bits: u8,
    length: usize,
) -> Result<()> {
    context.final_bits(message_bits, length)
}

/// Finalizes a SHA-512 context and writes a digest skeleton.
///
/// # Errors
///
/// Returns the same errors as [`Sha512Context::result`].
pub fn sha512_result(context: &mut Sha512Context, digest: &mut [u8]) -> Result<()> {
    context.result(digest)
}
