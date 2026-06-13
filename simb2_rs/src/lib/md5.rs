//! MD5 helpers migrated from `lib/md5.c`.
//!
//! This module mirrors the data shape and public operations of the legacy C
//! implementation. The compression rounds are intentionally left as a skeleton
//! for a later migration step.

/// Number of bytes in an MD5 digest.
pub const MD5_DIGEST_LENGTH: usize = 16;

/// Number of bytes processed by one MD5 compression block.
pub const MD5_BLOCK_LENGTH: usize = 64;

/// Number of 32-bit words in one MD5 compression block.
pub const MD5_BLOCK_WORDS: usize = 16;

/// Byte type used by the legacy `md5byte` aliases.
pub type Md5Byte = u8;

/// 32-bit word type used by the legacy `UWORD32` aliases.
pub type Uword32 = u32;

/// Fixed-size output buffer produced by MD5 finalization.
pub type Md5Digest = [Md5Byte; MD5_DIGEST_LENGTH];

const INITIAL_BUF: [Uword32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// Streaming MD5 context corresponding to `struct MD5Context` in `lib/md5.c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Md5Context {
    buf: [Uword32; 4],
    bytes: [Uword32; 2],
    input: [Uword32; MD5_BLOCK_WORDS],
    input_len: usize,
}

impl Md5Context {
    /// Creates a new context with the same initial state as `MD5Init`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: INITIAL_BUF,
            bytes: [0, 0],
            input: [0; MD5_BLOCK_WORDS],
            input_len: 0,
        }
    }

    /// Resets the context to the same state established by `MD5Init`.
    pub fn init(&mut self) {
        self.buf = INITIAL_BUF;
        self.bytes = [0, 0];
        self.input = [0; MD5_BLOCK_WORDS];
        self.input_len = 0;
    }

    /// Records additional input bytes using the shape of `MD5Update`.
    ///
    /// This skeleton updates byte counters and stages trailing block data, but
    /// it does not yet run the MD5 compression transform.
    pub fn update(&mut self, data: &[Md5Byte]) {
        self.add_byte_count(data.len());

        for byte in data {
            let word_index = self.input_len / 4;
            let shift = (self.input_len % 4) * 8;
            self.input[word_index] &= !(0xff_u32 << shift);
            self.input[word_index] |= Uword32::from(*byte) << shift;

            self.input_len += 1;
            if self.input_len == MD5_BLOCK_LENGTH {
                md5_transform(&mut self.buf, &self.input);
                self.input = [0; MD5_BLOCK_WORDS];
                self.input_len = 0;
            }
        }
    }

    /// Finalizes the context using the shape of `MD5Final` and returns a digest buffer.
    ///
    /// The returned digest is currently a placeholder because the compression
    /// rounds have not been migrated. The context is cleared after finalization,
    /// matching the C implementation's sensitivity cleanup step.
    #[must_use]
    pub fn finalize(&mut self) -> Md5Digest {
        let digest = [0; MD5_DIGEST_LENGTH];
        self.clear();
        digest
    }

    /// Finalizes the context into a caller-provided digest buffer.
    ///
    /// This mirrors the output-buffer style of `MD5Final` while keeping Rust's
    /// fixed-size array safety. The digest contents are placeholders until the
    /// full transform is migrated.
    pub fn finalize_into(&mut self, digest: &mut Md5Digest) {
        let finalized = self.finalize();
        for (target, source) in digest.iter_mut().zip(finalized) {
            *target = source;
        }
    }

    /// Returns the four-word MD5 accumulator corresponding to `ctx->buf`.
    #[must_use]
    pub fn buf(&self) -> &[Uword32; 4] {
        &self.buf
    }

    /// Returns the low and high 32-bit byte counters corresponding to `ctx->bytes`.
    #[must_use]
    pub fn bytes(&self) -> &[Uword32; 2] {
        &self.bytes
    }

    /// Returns the staged input block words corresponding to `ctx->in`.
    #[must_use]
    pub fn input(&self) -> &[Uword32; MD5_BLOCK_WORDS] {
        &self.input
    }

    /// Returns the number of staged bytes currently held in the input block.
    #[must_use]
    pub fn input_len(&self) -> usize {
        self.input_len
    }

    fn add_byte_count(&mut self, len: usize) {
        let len_low = len as Uword32;
        let len_high = (len >> 32) as Uword32;
        let (low, carry) = self.bytes[0].overflowing_add(len_low);

        self.bytes[0] = low;
        self.bytes[1] = self.bytes[1]
            .wrapping_add(len_high)
            .wrapping_add(Uword32::from(carry));
    }

    fn clear(&mut self) {
        self.buf = [0; 4];
        self.bytes = [0; 2];
        self.input = [0; MD5_BLOCK_WORDS];
        self.input_len = 0;
    }
}

impl Default for Md5Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Applies the legacy `byteSwap` endian adjustment to a word slice.
///
/// On little-endian targets this is a no-op, matching the C macro. On
/// big-endian targets each word is converted from little-endian byte order.
pub fn byte_swap(words: &mut [Uword32]) {
    #[cfg(target_endian = "big")]
    {
        for word in words {
            *word = word.swap_bytes();
        }
    }

    #[cfg(target_endian = "little")]
    {
        let _ = words;
    }
}

/// Initializes an MD5 context, corresponding to `MD5Init`.
pub fn md5_init(ctx: &mut Md5Context) {
    ctx.init();
}

/// Updates an MD5 context with additional bytes, corresponding to `MD5Update`.
///
/// This skeleton records byte counts and staged block words without performing
/// the complete MD5 compression logic.
pub fn md5_update(ctx: &mut Md5Context, data: &[Md5Byte]) {
    ctx.update(data);
}

/// Finalizes an MD5 context into `digest`, corresponding to `MD5Final`.
///
/// The output is a placeholder until the full MD5 transform is migrated.
pub fn md5_final(digest: &mut Md5Digest, ctx: &mut Md5Context) {
    ctx.finalize_into(digest);
}

/// Applies one MD5 compression block, corresponding to `MD5Transform`.
///
/// This is intentionally a no-op skeleton; the 64 MD5 step rounds from the C
/// source have not been migrated yet.
pub fn md5_transform(buf: &mut [Uword32; 4], input: &[Uword32; MD5_BLOCK_WORDS]) {
    let _ = (buf, input);
}
