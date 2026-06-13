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

const SHA512_K: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
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
}

/// Result type used by SHA-384/SHA-512 operations.
pub type Result<T> = core::result::Result<T, Sha384512Error>;

/// Context information for SHA-512 and SHA-384 hashing operations.
///
/// The layout mirrors the legacy `SHA512Context`: intermediate hash words,
/// a 128-bit bit length, a 1024-bit message block, and computed/corrupted
/// state flags.
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
    /// Returns [`Sha384512Error::StateError`] if called after finalization, or
    /// [`Sha384512Error::InputTooLong`] if the 128-bit length overflows.
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
                self.process_message_block();
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
    /// variant's digest size.
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
        self.pad_message(pad_byte);
        self.message_block.fill(0);
        self.length_low = 0;
        self.length_high = 0;
        self.computed = true;
        Ok(())
    }

    fn pad_message(&mut self, pad_byte: u8) {
        self.message_block[self.message_block_index] = pad_byte;
        self.message_block_index += 1;

        if self.message_block_index > SHA512_MESSAGE_BLOCK_SIZE - 16 {
            self.message_block[self.message_block_index..].fill(0);
            self.process_message_block();
        }

        self.message_block[self.message_block_index..SHA512_MESSAGE_BLOCK_SIZE - 16].fill(0);
        self.message_block[112..120].copy_from_slice(&self.length_high.to_be_bytes());
        self.message_block[120..128].copy_from_slice(&self.length_low.to_be_bytes());
        self.process_message_block();
    }

    fn process_message_block(&mut self) {
        let mut w = [0u64; 80];
        for (word, bytes) in w[..16].iter_mut().zip(self.message_block.chunks_exact(8)) {
            *word = u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
        }
        for t in 16..80 {
            let sigma1 = w[t - 2].rotate_right(19) ^ w[t - 2].rotate_right(61) ^ (w[t - 2] >> 6);
            let sigma0 = w[t - 15].rotate_right(1) ^ w[t - 15].rotate_right(8) ^ (w[t - 15] >> 7);
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

        for (&k, &word) in SHA512_K.iter().zip(w.iter()) {
            let temp1 = h
                .wrapping_add(e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41))
                .wrapping_add((e & f) ^ ((!e) & g))
                .wrapping_add(k)
                .wrapping_add(word);
            let temp2 = (a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39))
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

/// Finalizes a SHA-384 context and writes a digest.
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

/// Finalizes a SHA-512 context and writes a digest.
///
/// # Errors
///
/// Returns the same errors as [`Sha512Context::result`].
pub fn sha512_result(context: &mut Sha512Context, digest: &mut [u8]) -> Result<()> {
    context.result(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha384_known_vector() {
        let mut ctx = Sha512Context::new_sha384();
        let mut digest = [0u8; SHA384_HASH_SIZE];
        assert_eq!(ctx.input(b"abc"), Ok(()));
        assert_eq!(ctx.result(&mut digest), Ok(()));
        assert_eq!(
            digest,
            [
                0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6,
                0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a,
                0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba,
                0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
            ]
        );
    }

    #[test]
    fn sha512_known_vector() {
        let mut ctx = Sha512Context::new_sha512();
        let mut digest = [0u8; SHA512_HASH_SIZE];
        assert_eq!(ctx.input(b"abc"), Ok(()));
        assert_eq!(ctx.result(&mut digest), Ok(()));
        assert_eq!(
            digest,
            [
                0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
                0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
                0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
                0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
                0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
            ]
        );
    }
}
