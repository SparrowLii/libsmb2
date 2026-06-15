//! SHA-224 and SHA-256 helpers migrated from `lib/sha224-256.c`.

/// Size in bytes of a SHA-224 message digest.
pub const SHA224_HASH_SIZE: usize = 28;

/// Size in bytes of a SHA-256 message digest.
pub const SHA256_HASH_SIZE: usize = 32;

/// Size in bytes of one SHA-224/SHA-256 message block.
pub const SHA256_MESSAGE_BLOCK_SIZE: usize = 64;

const SHA256_INITIAL_HASH: [u32; SHA256_HASH_SIZE / 4] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const SHA224_INITIAL_HASH: [u32; SHA256_HASH_SIZE / 4] = [
    0xC105_9ED8,
    0x367C_D507,
    0x3070_DD17,
    0xF70E_5939,
    0xFFC0_0B31,
    0x6858_1511,
    0x64F9_8FA7,
    0xBEFA_4FA4,
];

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Error status corresponding to the legacy SHA error codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShaError {
    /// Operation completed successfully.
    Success,
    /// A required context or message pointer was null in the C API.
    Null,
    /// The context state does not allow the requested operation.
    State,
}

/// Hash variant handled by the shared SHA-224/SHA-256 context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sha224256Variant {
    /// SHA-224 using the FIPS-180-2 Change Notice 1 initial hash values.
    Sha224,
    /// SHA-256 using the FIPS-180-2 section 5.3.2 initial hash values.
    Sha256,
}

impl Sha224256Variant {
    /// Returns the digest size in bytes for this variant.
    #[must_use]
    pub const fn hash_size(self) -> usize {
        match self {
            Self::Sha224 => SHA224_HASH_SIZE,
            Self::Sha256 => SHA256_HASH_SIZE,
        }
    }

    const fn initial_hash(self) -> [u32; SHA256_HASH_SIZE / 4] {
        match self {
            Self::Sha224 => SHA224_INITIAL_HASH,
            Self::Sha256 => SHA256_INITIAL_HASH,
        }
    }
}

/// Shared context for SHA-224 and SHA-256 message processing.
///
/// The field names follow Rust style while preserving the roles of the C
/// `SHA256Context` members: message length, partial block, intermediate hash,
/// computed flag, and corruption status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sha256Context {
    variant: Sha224256Variant,
    length_low: u32,
    length_high: u32,
    message_block_index: usize,
    message_block: [u8; SHA256_MESSAGE_BLOCK_SIZE],
    intermediate_hash: [u32; SHA256_HASH_SIZE / 4],
    computed: bool,
    corrupted: ShaError,
}

/// SHA-224 uses the same context layout as SHA-256 with different initial hash
/// values and a shorter result length.
pub type Sha224Context = Sha256Context;

impl Default for Sha256Context {
    fn default() -> Self {
        Self::new_sha256()
    }
}

impl Sha256Context {
    /// Creates a new SHA-224 context initialized for a fresh digest.
    #[must_use]
    pub fn new_sha224() -> Self {
        Self::new(Sha224256Variant::Sha224)
    }

    /// Creates a new SHA-256 context initialized for a fresh digest.
    #[must_use]
    pub fn new_sha256() -> Self {
        Self::new(Sha224256Variant::Sha256)
    }

    /// Returns the digest variant this context is configured for.
    #[must_use]
    pub const fn variant(&self) -> Sha224256Variant {
        self.variant
    }

    /// Returns whether the context has been finalized.
    #[must_use]
    pub const fn is_computed(&self) -> bool {
        self.computed
    }

    /// Returns the current corruption status for the context.
    #[must_use]
    pub const fn corrupted(&self) -> ShaError {
        self.corrupted
    }

    /// Returns `(length_high, length_low)` of the processed bit count.
    #[must_use]
    pub const fn length_words(&self) -> (u32, u32) {
        (self.length_high, self.length_low)
    }

    /// Returns the current message block index.
    #[must_use]
    pub const fn message_block_index(&self) -> usize {
        self.message_block_index
    }

    /// Overwrites the computed flag (observation hook for the C `Computed` field).
    pub fn set_computed_flag(&mut self, computed: bool) {
        self.computed = computed;
    }

    /// Overwrites the corruption state (observation hook for the C `Corrupted` field).
    pub fn set_corrupted_state(&mut self, corrupted: ShaError) {
        self.corrupted = corrupted;
    }

    /// Resets this context for computing a new SHA-224 digest.
    pub fn sha224_reset(&mut self) -> ShaError {
        self.reset(Sha224256Variant::Sha224)
    }

    /// Resets this context for computing a new SHA-256 digest.
    pub fn sha256_reset(&mut self) -> ShaError {
        self.reset(Sha224256Variant::Sha256)
    }

    /// Adds the next octets of a SHA-224 message.
    ///
    /// This mirrors `SHA224Input` by sharing the SHA-256 input path.
    pub fn sha224_input(&mut self, message: &[u8]) -> ShaError {
        self.sha256_input(message)
    }

    /// Adds the next octets of a SHA-256 message.
    ///
    /// The method preserves the legacy state transitions and length accounting.
    pub fn sha256_input(&mut self, message: &[u8]) -> ShaError {
        if message.is_empty() {
            return ShaError::Success;
        }

        if self.computed {
            self.corrupted = ShaError::State;
            return ShaError::State;
        }

        if self.corrupted != ShaError::Success {
            return self.corrupted;
        }

        for byte in message {
            self.message_block[self.message_block_index] = *byte;
            self.message_block_index += 1;

            if self.add_length(8) != ShaError::Success {
                return self.corrupted;
            }

            if self.message_block_index == SHA256_MESSAGE_BLOCK_SIZE {
                self.process_message_block();
            }
        }

        ShaError::Success
    }

    /// Adds final bits of a SHA-224 message.
    ///
    /// `length` is the number of high-order bits in `message_bits`, from 1 to 7.
    pub fn sha224_final_bits(&mut self, message_bits: u8, length: usize) -> ShaError {
        self.sha256_final_bits(message_bits, length)
    }

    /// Adds final bits of a SHA-256 message.
    ///
    /// `length` is the number of high-order bits in `message_bits`, from 1 to 7.
    pub fn sha256_final_bits(&mut self, message_bits: u8, length: usize) -> ShaError {
        const MASKS: [u8; 8] = [0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE];
        const MARK_BITS: [u8; 8] = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];

        if length == 0 {
            return ShaError::Success;
        }

        if self.computed || length >= 8 {
            self.corrupted = ShaError::State;
            return ShaError::State;
        }

        if self.corrupted != ShaError::Success {
            return self.corrupted;
        }

        if self.add_length(length as u32) != ShaError::Success {
            return self.corrupted;
        }

        self.finalize((message_bits & MASKS[length]) | MARK_BITS[length]);
        ShaError::Success
    }

    /// Returns the SHA-224 digest bytes for the current context.
    ///
    /// The returned bytes contain the complete SHA-224 digest.
    pub fn sha224_result(&mut self) -> Result<[u8; SHA224_HASH_SIZE], ShaError> {
        let mut digest = [0; SHA224_HASH_SIZE];
        self.result_into(&mut digest)?;
        Ok(digest)
    }

    /// Returns the SHA-256 digest bytes for the current context.
    ///
    /// The returned bytes contain the complete SHA-256 digest.
    pub fn sha256_result(&mut self) -> Result<[u8; SHA256_HASH_SIZE], ShaError> {
        let mut digest = [0; SHA256_HASH_SIZE];
        self.result_into(&mut digest)?;
        Ok(digest)
    }

    /// Writes the digest bytes for this context's variant into `message_digest`.
    ///
    /// # Errors
    ///
    /// Returns `ShaError::State` when `message_digest` is not the size required
    /// by the configured variant, or returns the context's corruption status.
    pub fn result_into(&mut self, message_digest: &mut [u8]) -> Result<(), ShaError> {
        let hash_size = self.variant.hash_size();
        if message_digest.len() != hash_size {
            self.corrupted = ShaError::State;
            return Err(ShaError::State);
        }

        if self.corrupted != ShaError::Success {
            return Err(self.corrupted);
        }

        if !self.computed {
            self.finalize(0x80);
        }

        for (index, byte) in message_digest.iter_mut().enumerate() {
            *byte = (self.intermediate_hash[index >> 2] >> (8 * (3 - (index & 0x03)))) as u8;
        }

        Ok(())
    }

    fn new(variant: Sha224256Variant) -> Self {
        Self {
            variant,
            length_low: 0,
            length_high: 0,
            message_block_index: 0,
            message_block: [0; SHA256_MESSAGE_BLOCK_SIZE],
            intermediate_hash: variant.initial_hash(),
            computed: false,
            corrupted: ShaError::Success,
        }
    }

    fn reset(&mut self, variant: Sha224256Variant) -> ShaError {
        *self = Self::new(variant);
        ShaError::Success
    }

    fn add_length(&mut self, length: u32) -> ShaError {
        let previous = self.length_low;
        self.length_low = self.length_low.wrapping_add(length);
        if self.length_low < previous {
            self.length_high = self.length_high.wrapping_add(1);
            if self.length_high == 0 {
                self.corrupted = ShaError::State;
                return ShaError::State;
            }
        }
        ShaError::Success
    }

    fn finalize(&mut self, pad_byte: u8) {
        self.pad_message(pad_byte);
        self.message_block = [0; SHA256_MESSAGE_BLOCK_SIZE];
        self.length_low = 0;
        self.length_high = 0;
        self.computed = true;
    }

    fn pad_message(&mut self, pad_byte: u8) {
        if self.message_block_index < SHA256_MESSAGE_BLOCK_SIZE {
            self.message_block[self.message_block_index] = pad_byte;
            self.message_block_index += 1;
        }

        if self.message_block_index > SHA256_MESSAGE_BLOCK_SIZE - 8 {
            self.message_block[self.message_block_index..].fill(0);
            self.process_message_block();
        }

        self.message_block[self.message_block_index..SHA256_MESSAGE_BLOCK_SIZE - 8].fill(0);
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
        let mut w = [0u32; 64];
        for (word, bytes) in w[..16].iter_mut().zip(self.message_block.chunks_exact(4)) {
            *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for t in 16..64 {
            let sigma1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
            let sigma0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            w[t] = sigma1
                .wrapping_add(w[t - 7])
                .wrapping_add(sigma0)
                .wrapping_add(w[t - 16]);
        }

        let mut a = self.intermediate_hash[0];
        let mut b = self.intermediate_hash[1];
        let mut c = self.intermediate_hash[2];
        let mut d = self.intermediate_hash[3];
        let mut e = self.intermediate_hash[4];
        let mut f = self.intermediate_hash[5];
        let mut g = self.intermediate_hash[6];
        let mut h = self.intermediate_hash[7];

        for (&k, &word) in SHA256_K.iter().zip(w.iter()) {
            let temp1 = h
                .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                .wrapping_add((e & f) ^ ((!e) & g))
                .wrapping_add(k)
                .wrapping_add(word);
            let temp2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.intermediate_hash[0] = self.intermediate_hash[0].wrapping_add(a);
        self.intermediate_hash[1] = self.intermediate_hash[1].wrapping_add(b);
        self.intermediate_hash[2] = self.intermediate_hash[2].wrapping_add(c);
        self.intermediate_hash[3] = self.intermediate_hash[3].wrapping_add(d);
        self.intermediate_hash[4] = self.intermediate_hash[4].wrapping_add(e);
        self.intermediate_hash[5] = self.intermediate_hash[5].wrapping_add(f);
        self.intermediate_hash[6] = self.intermediate_hash[6].wrapping_add(g);
        self.intermediate_hash[7] = self.intermediate_hash[7].wrapping_add(h);
        self.message_block_index = 0;
    }
}

/// Resets a context for SHA-224, mirroring `SHA224Reset`.
pub fn sha224_reset(context: &mut Sha224Context) -> ShaError {
    context.sha224_reset()
}

/// Adds message octets for SHA-224, mirroring `SHA224Input`.
pub fn sha224_input(context: &mut Sha224Context, message: &[u8]) -> ShaError {
    context.sha224_input(message)
}

/// Adds final message bits for SHA-224, mirroring `SHA224FinalBits`.
pub fn sha224_final_bits(context: &mut Sha224Context, message_bits: u8, length: usize) -> ShaError {
    context.sha224_final_bits(message_bits, length)
}

/// Returns the current SHA-224 result, mirroring `SHA224Result`.
///
/// # Errors
///
/// Returns the context's corruption status when finalization cannot proceed.
pub fn sha224_result(context: &mut Sha224Context) -> Result<[u8; SHA224_HASH_SIZE], ShaError> {
    context.sha224_result()
}

/// Resets a context for SHA-256, mirroring `SHA256Reset`.
pub fn sha256_reset(context: &mut Sha256Context) -> ShaError {
    context.sha256_reset()
}

/// Adds message octets for SHA-256, mirroring `SHA256Input`.
pub fn sha256_input(context: &mut Sha256Context, message: &[u8]) -> ShaError {
    context.sha256_input(message)
}

/// Adds final message bits for SHA-256, mirroring `SHA256FinalBits`.
pub fn sha256_final_bits(context: &mut Sha256Context, message_bits: u8, length: usize) -> ShaError {
    context.sha256_final_bits(message_bits, length)
}

/// Returns the current SHA-256 result, mirroring `SHA256Result`.
///
/// # Errors
///
/// Returns the context's corruption status when finalization cannot proceed.
pub fn sha256_result(context: &mut Sha256Context) -> Result<[u8; SHA256_HASH_SIZE], ShaError> {
    context.sha256_result()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha224_known_vector() {
        let mut ctx = Sha256Context::new_sha224();
        assert_eq!(ctx.sha224_input(b"abc"), ShaError::Success);
        assert_eq!(
            ctx.sha224_result(),
            Ok([
                0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
                0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
            ])
        );
    }

    #[test]
    fn sha256_known_vector() {
        let mut ctx = Sha256Context::new_sha256();
        assert_eq!(ctx.sha256_input(b"abc"), ShaError::Success);
        assert_eq!(
            ctx.sha256_result(),
            Ok([
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ])
        );
    }
}
