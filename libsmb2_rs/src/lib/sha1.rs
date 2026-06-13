//! SHA-1 helpers migrated from `lib/sha1.c`.

/// Number of bytes in one SHA-1 message block.
pub const SHA1_MESSAGE_BLOCK_SIZE: usize = 64;

/// Number of bytes in a SHA-1 message digest.
pub const SHA1_HASH_SIZE: usize = 20;

/// Number of bits in a SHA-1 message digest.
pub const SHA1_HASH_SIZE_BITS: usize = 160;

const SHA1_INITIAL_HASH: [u32; SHA1_HASH_SIZE / 4] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

const FINAL_BIT_MASKS: [u8; 8] = [0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE];
const FINAL_MARK_BITS: [u8; 8] = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];

/// SHA-1 operation result codes corresponding to the legacy `sha*` constants.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Sha1Error {
    /// The caller passed an invalid null parameter in the C API.
    Null,
    /// The accumulated input length overflowed the SHA-1 64-bit length field.
    InputTooLong,
    /// Input was provided after finalization or result calculation.
    StateError,
    /// The caller passed a bad parameter value.
    BadParam,
}

/// Result type used by SHA-1 context methods.
pub type Sha1Result<T> = Result<T, Sha1Error>;

/// Context information for an in-progress SHA-1 hashing operation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Sha1Context {
    intermediate_hash: [u32; SHA1_HASH_SIZE / 4],
    length_low: u32,
    length_high: u32,
    message_block_index: usize,
    message_block: [u8; SHA1_MESSAGE_BLOCK_SIZE],
    computed: bool,
    corrupted: Option<Sha1Error>,
}

impl Sha1Context {
    /// Creates a SHA-1 context initialized for a new digest calculation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            intermediate_hash: SHA1_INITIAL_HASH,
            length_low: 0,
            length_high: 0,
            message_block_index: 0,
            message_block: [0; SHA1_MESSAGE_BLOCK_SIZE],
            computed: false,
            corrupted: None,
        }
    }

    /// Resets this context in preparation for computing a new SHA-1 digest.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Adds the next byte-aligned portion of the message to this context.
    ///
    /// # Errors
    ///
    /// Returns [`Sha1Error::StateError`] if the context has already been
    /// finalized, or [`Sha1Error::InputTooLong`] if the bit length overflows the
    /// SHA-1 length field. If the context is already corrupted, the stored error
    /// is returned.
    pub fn input(&mut self, message: &[u8]) -> Sha1Result<()> {
        if message.is_empty() {
            return Ok(());
        }

        if self.computed {
            self.corrupted = Some(Sha1Error::StateError);
            return Err(Sha1Error::StateError);
        }

        if let Some(error) = self.corrupted {
            return Err(error);
        }

        for byte in message {
            self.message_block[self.message_block_index] = *byte;
            self.message_block_index += 1;

            self.add_length(8)?;

            if self.message_block_index == SHA1_MESSAGE_BLOCK_SIZE {
                self.process_message_block();
            }
        }

        Ok(())
    }

    /// Adds the final non-byte-aligned message bits to this context.
    ///
    /// The bits are read from the upper portion of `message_bits`, matching the
    /// legacy C `SHA1FinalBits` contract.
    ///
    /// # Errors
    ///
    /// Returns [`Sha1Error::StateError`] when called after finalization or with a
    /// bit count greater than seven, and returns [`Sha1Error::InputTooLong`] if
    /// the length field overflows. If the context is already corrupted, the
    /// stored error is returned.
    pub fn final_bits(&mut self, message_bits: u8, bit_count: usize) -> Sha1Result<()> {
        if bit_count == 0 {
            return Ok(());
        }

        if self.computed || bit_count >= 8 {
            self.corrupted = Some(Sha1Error::StateError);
            return Err(Sha1Error::StateError);
        }

        if let Some(error) = self.corrupted {
            return Err(error);
        }

        self.add_length(bit_count as u32)?;
        let pad_byte = (message_bits & FINAL_BIT_MASKS[bit_count]) | FINAL_MARK_BITS[bit_count];
        self.finalize(pad_byte);

        Ok(())
    }

    /// Returns the current 160-bit digest buffer for this context.
    ///
    /// # Errors
    ///
    /// Returns the stored [`Sha1Error`] if the context has entered a corrupted
    /// state.
    pub fn result(&mut self) -> Sha1Result<[u8; SHA1_HASH_SIZE]> {
        if let Some(error) = self.corrupted {
            return Err(error);
        }

        if !self.computed {
            self.finalize(0x80);
        }

        let mut digest = [0; SHA1_HASH_SIZE];
        for (index, output) in digest.iter_mut().enumerate() {
            let word = self.intermediate_hash[index >> 2];
            *output = (word >> (8 * (3 - (index & 0x03)))) as u8;
        }

        Ok(digest)
    }

    /// Returns whether this context has been finalized.
    #[must_use]
    pub fn is_computed(&self) -> bool {
        self.computed
    }

    /// Returns the stored corruption state, if any.
    #[must_use]
    pub fn corrupted(&self) -> Option<Sha1Error> {
        self.corrupted
    }

    /// Returns the current message length split into high and low 32-bit words.
    #[must_use]
    pub fn length_words(&self) -> (u32, u32) {
        (self.length_high, self.length_low)
    }

    fn add_length(&mut self, length: u32) -> Sha1Result<()> {
        let previous_low = self.length_low;
        self.length_low = self.length_low.wrapping_add(length);

        if self.length_low < previous_low {
            self.length_high = self.length_high.wrapping_add(1);
            if self.length_high == 0 {
                self.corrupted = Some(Sha1Error::InputTooLong);
                return Err(Sha1Error::InputTooLong);
            }
        }

        Ok(())
    }

    fn finalize(&mut self, pad_byte: u8) {
        self.pad_message(pad_byte);
        self.message_block = [0; SHA1_MESSAGE_BLOCK_SIZE];
        self.length_low = 0;
        self.length_high = 0;
        self.computed = true;
    }

    fn pad_message(&mut self, pad_byte: u8) {
        if self.message_block_index >= SHA1_MESSAGE_BLOCK_SIZE - 8 {
            self.message_block[self.message_block_index] = pad_byte;
            self.message_block_index += 1;

            while self.message_block_index < SHA1_MESSAGE_BLOCK_SIZE {
                self.message_block[self.message_block_index] = 0;
                self.message_block_index += 1;
            }

            self.process_message_block();
        } else {
            self.message_block[self.message_block_index] = pad_byte;
            self.message_block_index += 1;
        }

        while self.message_block_index < SHA1_MESSAGE_BLOCK_SIZE - 8 {
            self.message_block[self.message_block_index] = 0;
            self.message_block_index += 1;
        }

        self.message_block[56] = (self.length_high >> 24) as u8;
        self.message_block[57] = (self.length_high >> 16) as u8;
        self.message_block[58] = (self.length_high >> 8) as u8;
        self.message_block[59] = self.length_high as u8;
        self.message_block[60] = (self.length_low >> 24) as u8;
        self.message_block[61] = (self.length_low >> 16) as u8;
        self.message_block[62] = (self.length_low >> 8) as u8;
        self.message_block[63] = self.length_low as u8;

        self.process_message_block();
    }

    fn process_message_block(&mut self) {
        const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];

        let mut w = [0u32; 80];
        for (word, bytes) in w[..16].iter_mut().zip(self.message_block.chunks_exact(4)) {
            *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }

        let mut a = self.intermediate_hash[0];
        let mut b = self.intermediate_hash[1];
        let mut c = self.intermediate_hash[2];
        let mut d = self.intermediate_hash[3];
        let mut e = self.intermediate_hash[4];

        for (t, word) in w.iter().enumerate() {
            let (f, k) = match t {
                0..=19 => (((b & c) ^ ((!b) & d)), K[0]),
                20..=39 => (b ^ c ^ d, K[1]),
                40..=59 => (((b & c) ^ (b & d) ^ (c & d)), K[2]),
                _ => (b ^ c ^ d, K[3]),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(*word)
                .wrapping_add(k);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.intermediate_hash[0] = self.intermediate_hash[0].wrapping_add(a);
        self.intermediate_hash[1] = self.intermediate_hash[1].wrapping_add(b);
        self.intermediate_hash[2] = self.intermediate_hash[2].wrapping_add(c);
        self.intermediate_hash[3] = self.intermediate_hash[3].wrapping_add(d);
        self.intermediate_hash[4] = self.intermediate_hash[4].wrapping_add(e);
        self.message_block_index = 0;
    }
}

impl Default for Sha1Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Rust counterpart of the C `SHA1Reset` function.
pub fn sha1_reset(context: &mut Sha1Context) {
    context.reset();
}

/// Rust counterpart of the C `SHA1Input` function.
///
/// # Errors
///
/// Returns the same errors as [`Sha1Context::input`].
pub fn sha1_input(context: &mut Sha1Context, message: &[u8]) -> Sha1Result<()> {
    context.input(message)
}

/// Rust counterpart of the C `SHA1FinalBits` function.
///
/// # Errors
///
/// Returns the same errors as [`Sha1Context::final_bits`].
pub fn sha1_final_bits(
    context: &mut Sha1Context,
    message_bits: u8,
    bit_count: usize,
) -> Sha1Result<()> {
    context.final_bits(message_bits, bit_count)
}

/// Rust counterpart of the C `SHA1Result` function.
///
/// # Errors
///
/// Returns the same errors as [`Sha1Context::result`].
pub fn sha1_result(context: &mut Sha1Context) -> Sha1Result<[u8; SHA1_HASH_SIZE]> {
    context.result()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_known_vector() {
        let mut ctx = Sha1Context::new();
        assert_eq!(ctx.input(b"abc"), Ok(()));
        assert_eq!(
            ctx.result(),
            Ok([
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ])
        );
    }
}
