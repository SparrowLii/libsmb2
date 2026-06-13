//! MD5 helpers migrated from `lib/md5.c`.
//!
//! This module mirrors the data shape and public operations of the legacy C
//! implementation and provides the full MD5 compression flow.

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
    /// The context is cleared after finalization, matching the C implementation's
    /// sensitivity cleanup step.
    #[must_use]
    pub fn finalize(&mut self) -> Md5Digest {
        let bytes = self.bytes;
        let count = (bytes[0] & 0x3f) as usize;
        let pad_len = if count < 56 { 56 - count } else { 120 - count };
        let mut padding = [0_u8; MD5_BLOCK_LENGTH];
        padding[0] = 0x80;

        self.update(&padding[..pad_len]);

        let bit_count = [
            bytes[0].wrapping_shl(3),
            bytes[1].wrapping_shl(3) | (bytes[0] >> 29),
        ];
        let mut length = [0_u8; 8];
        length[..4].copy_from_slice(&bit_count[0].to_le_bytes());
        length[4..].copy_from_slice(&bit_count[1].to_le_bytes());
        self.update(&length);

        let mut digest = [0; MD5_DIGEST_LENGTH];
        for (chunk, word) in digest.chunks_mut(4).zip(self.buf) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }

        self.clear();
        digest
    }

    /// Finalizes the context into a caller-provided digest buffer.
    ///
    /// This mirrors the output-buffer style of `MD5Final` while keeping Rust's
    /// fixed-size array safety.
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
pub fn md5_update(ctx: &mut Md5Context, data: &[Md5Byte]) {
    ctx.update(data);
}

/// Finalizes an MD5 context into `digest`, corresponding to `MD5Final`.
///
pub fn md5_final(digest: &mut Md5Digest, ctx: &mut Md5Context) {
    ctx.finalize_into(digest);
}

/// Applies one MD5 compression block, corresponding to `MD5Transform`.
///
pub fn md5_transform(buf: &mut [Uword32; 4], input: &[Uword32; MD5_BLOCK_WORDS]) {
    let mut a = buf[0];
    let mut b = buf[1];
    let mut c = buf[2];
    let mut d = buf[3];

    md5_step(f1, &mut a, b, c, d, input[0].wrapping_add(0xd76a_a478), 7);
    md5_step(f1, &mut d, a, b, c, input[1].wrapping_add(0xe8c7_b756), 12);
    md5_step(f1, &mut c, d, a, b, input[2].wrapping_add(0x2420_70db), 17);
    md5_step(f1, &mut b, c, d, a, input[3].wrapping_add(0xc1bd_ceee), 22);
    md5_step(f1, &mut a, b, c, d, input[4].wrapping_add(0xf57c_0faf), 7);
    md5_step(f1, &mut d, a, b, c, input[5].wrapping_add(0x4787_c62a), 12);
    md5_step(f1, &mut c, d, a, b, input[6].wrapping_add(0xa830_4613), 17);
    md5_step(f1, &mut b, c, d, a, input[7].wrapping_add(0xfd46_9501), 22);
    md5_step(f1, &mut a, b, c, d, input[8].wrapping_add(0x6980_98d8), 7);
    md5_step(f1, &mut d, a, b, c, input[9].wrapping_add(0x8b44_f7af), 12);
    md5_step(f1, &mut c, d, a, b, input[10].wrapping_add(0xffff_5bb1), 17);
    md5_step(f1, &mut b, c, d, a, input[11].wrapping_add(0x895c_d7be), 22);
    md5_step(f1, &mut a, b, c, d, input[12].wrapping_add(0x6b90_1122), 7);
    md5_step(f1, &mut d, a, b, c, input[13].wrapping_add(0xfd98_7193), 12);
    md5_step(f1, &mut c, d, a, b, input[14].wrapping_add(0xa679_438e), 17);
    md5_step(f1, &mut b, c, d, a, input[15].wrapping_add(0x49b4_0821), 22);

    md5_step(f2, &mut a, b, c, d, input[1].wrapping_add(0xf61e_2562), 5);
    md5_step(f2, &mut d, a, b, c, input[6].wrapping_add(0xc040_b340), 9);
    md5_step(f2, &mut c, d, a, b, input[11].wrapping_add(0x265e_5a51), 14);
    md5_step(f2, &mut b, c, d, a, input[0].wrapping_add(0xe9b6_c7aa), 20);
    md5_step(f2, &mut a, b, c, d, input[5].wrapping_add(0xd62f_105d), 5);
    md5_step(f2, &mut d, a, b, c, input[10].wrapping_add(0x0244_1453), 9);
    md5_step(f2, &mut c, d, a, b, input[15].wrapping_add(0xd8a1_e681), 14);
    md5_step(f2, &mut b, c, d, a, input[4].wrapping_add(0xe7d3_fbc8), 20);
    md5_step(f2, &mut a, b, c, d, input[9].wrapping_add(0x21e1_cde6), 5);
    md5_step(f2, &mut d, a, b, c, input[14].wrapping_add(0xc337_07d6), 9);
    md5_step(f2, &mut c, d, a, b, input[3].wrapping_add(0xf4d5_0d87), 14);
    md5_step(f2, &mut b, c, d, a, input[8].wrapping_add(0x455a_14ed), 20);
    md5_step(f2, &mut a, b, c, d, input[13].wrapping_add(0xa9e3_e905), 5);
    md5_step(f2, &mut d, a, b, c, input[2].wrapping_add(0xfcef_a3f8), 9);
    md5_step(f2, &mut c, d, a, b, input[7].wrapping_add(0x676f_02d9), 14);
    md5_step(f2, &mut b, c, d, a, input[12].wrapping_add(0x8d2a_4c8a), 20);

    md5_step(f3, &mut a, b, c, d, input[5].wrapping_add(0xfffa_3942), 4);
    md5_step(f3, &mut d, a, b, c, input[8].wrapping_add(0x8771_f681), 11);
    md5_step(f3, &mut c, d, a, b, input[11].wrapping_add(0x6d9d_6122), 16);
    md5_step(f3, &mut b, c, d, a, input[14].wrapping_add(0xfde5_380c), 23);
    md5_step(f3, &mut a, b, c, d, input[1].wrapping_add(0xa4be_ea44), 4);
    md5_step(f3, &mut d, a, b, c, input[4].wrapping_add(0x4bde_cfa9), 11);
    md5_step(f3, &mut c, d, a, b, input[7].wrapping_add(0xf6bb_4b60), 16);
    md5_step(f3, &mut b, c, d, a, input[10].wrapping_add(0xbebf_bc70), 23);
    md5_step(f3, &mut a, b, c, d, input[13].wrapping_add(0x289b_7ec6), 4);
    md5_step(f3, &mut d, a, b, c, input[0].wrapping_add(0xeaa1_27fa), 11);
    md5_step(f3, &mut c, d, a, b, input[3].wrapping_add(0xd4ef_3085), 16);
    md5_step(f3, &mut b, c, d, a, input[6].wrapping_add(0x0488_1d05), 23);
    md5_step(f3, &mut a, b, c, d, input[9].wrapping_add(0xd9d4_d039), 4);
    md5_step(f3, &mut d, a, b, c, input[12].wrapping_add(0xe6db_99e5), 11);
    md5_step(f3, &mut c, d, a, b, input[15].wrapping_add(0x1fa2_7cf8), 16);
    md5_step(f3, &mut b, c, d, a, input[2].wrapping_add(0xc4ac_5665), 23);

    md5_step(f4, &mut a, b, c, d, input[0].wrapping_add(0xf429_2244), 6);
    md5_step(f4, &mut d, a, b, c, input[7].wrapping_add(0x432a_ff97), 10);
    md5_step(f4, &mut c, d, a, b, input[14].wrapping_add(0xab94_23a7), 15);
    md5_step(f4, &mut b, c, d, a, input[5].wrapping_add(0xfc93_a039), 21);
    md5_step(f4, &mut a, b, c, d, input[12].wrapping_add(0x655b_59c3), 6);
    md5_step(f4, &mut d, a, b, c, input[3].wrapping_add(0x8f0c_cc92), 10);
    md5_step(f4, &mut c, d, a, b, input[10].wrapping_add(0xffef_f47d), 15);
    md5_step(f4, &mut b, c, d, a, input[1].wrapping_add(0x8584_5dd1), 21);
    md5_step(f4, &mut a, b, c, d, input[8].wrapping_add(0x6fa8_7e4f), 6);
    md5_step(f4, &mut d, a, b, c, input[15].wrapping_add(0xfe2c_e6e0), 10);
    md5_step(f4, &mut c, d, a, b, input[6].wrapping_add(0xa301_4314), 15);
    md5_step(f4, &mut b, c, d, a, input[13].wrapping_add(0x4e08_11a1), 21);
    md5_step(f4, &mut a, b, c, d, input[4].wrapping_add(0xf753_7e82), 6);
    md5_step(f4, &mut d, a, b, c, input[11].wrapping_add(0xbd3a_f235), 10);
    md5_step(f4, &mut c, d, a, b, input[2].wrapping_add(0x2ad7_d2bb), 15);
    md5_step(f4, &mut b, c, d, a, input[9].wrapping_add(0xeb86_d391), 21);

    buf[0] = buf[0].wrapping_add(a);
    buf[1] = buf[1].wrapping_add(b);
    buf[2] = buf[2].wrapping_add(c);
    buf[3] = buf[3].wrapping_add(d);
}

const fn f1(x: Uword32, y: Uword32, z: Uword32) -> Uword32 {
    z ^ (x & (y ^ z))
}

const fn f2(x: Uword32, y: Uword32, z: Uword32) -> Uword32 {
    f1(z, x, y)
}

const fn f3(x: Uword32, y: Uword32, z: Uword32) -> Uword32 {
    x ^ y ^ z
}

const fn f4(x: Uword32, y: Uword32, z: Uword32) -> Uword32 {
    y ^ (x | !z)
}

fn md5_step(
    func: impl Fn(Uword32, Uword32, Uword32) -> Uword32,
    word: &mut Uword32,
    x: Uword32,
    y: Uword32,
    z: Uword32,
    input: Uword32,
    shift: u32,
) {
    *word = word
        .wrapping_add(func(x, y, z))
        .wrapping_add(input)
        .rotate_left(shift)
        .wrapping_add(x);
}
