//! MD4 helpers migrated from `lib/md4c.c`.
//!
//! This module mirrors the structure and public lifecycle of the original C
//! implementation while providing the full MD4 compression algorithm.

const MD4_DIGEST_LEN: usize = 16;
const MD4_BLOCK_LEN: usize = 64;
const MD4_STATE_WORDS: usize = 4;
const MD4_COUNT_WORDS: usize = 2;

const MD4_INITIAL_STATE: [u32; MD4_STATE_WORDS] =
    [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

const PADDING: [u8; MD4_BLOCK_LEN] = {
    let mut padding = [0_u8; MD4_BLOCK_LEN];
    padding[0] = 0x80;
    padding
};

const S11: u32 = 3;
const S12: u32 = 7;
const S13: u32 = 11;
const S14: u32 = 19;
const S21: u32 = 3;
const S22: u32 = 5;
const S23: u32 = 9;
const S24: u32 = 13;
const S31: u32 = 3;
const S32: u32 = 9;
const S33: u32 = 11;
const S34: u32 = 15;

/// Byte length of an MD4 digest.
pub const DIGEST_LEN: usize = MD4_DIGEST_LEN;

/// Byte length of an MD4 input block.
pub const BLOCK_LEN: usize = MD4_BLOCK_LEN;

/// Rust counterpart of the C `MD4_CTX` structure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Md4Context {
    /// Current ABCD state words.
    pub state: [u32; MD4_STATE_WORDS],
    /// Number of processed bits, stored as two little-endian words.
    pub count: [u32; MD4_COUNT_WORDS],
    /// Pending input bytes that have not filled a complete MD4 block.
    pub buffer: [u8; MD4_BLOCK_LEN],
}

impl Default for Md4Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Md4Context {
    /// Creates a new context with the MD4 initial state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: MD4_INITIAL_STATE,
            count: [0; MD4_COUNT_WORDS],
            buffer: [0; MD4_BLOCK_LEN],
        }
    }

    /// Resets this context to the same state produced by C `MD4Init`.
    pub fn init(&mut self) {
        self.state = MD4_INITIAL_STATE;
        self.count = [0; MD4_COUNT_WORDS];
        self.buffer = [0; MD4_BLOCK_LEN];
    }

    /// Updates the context with input bytes, following the C `MD4Update` shape.
    pub fn update(&mut self, input: &[u8]) {
        let mut index = ((self.count[0] >> 3) & 0x3f) as usize;
        self.add_input_bits(input.len());

        let part_len = MD4_BLOCK_LEN - index;
        let mut input_index = 0;

        if input.len() >= part_len {
            self.buffer[index..index + part_len].copy_from_slice(&input[..part_len]);
            md4_transform(&mut self.state, &self.buffer);

            input_index = part_len;
            while input_index + (MD4_BLOCK_LEN - 1) < input.len() {
                let mut block = [0_u8; MD4_BLOCK_LEN];
                block.copy_from_slice(&input[input_index..input_index + MD4_BLOCK_LEN]);
                md4_transform(&mut self.state, &block);
                input_index += MD4_BLOCK_LEN;
            }

            index = 0;
        }

        let remaining = input.len() - input_index;
        self.buffer[index..index + remaining].copy_from_slice(&input[input_index..]);
    }

    /// Finalizes this context and returns the current digest bytes.
    ///
    /// This mirrors the C `MD4Final` control flow and zeroizes the context after
    /// producing output.
    #[must_use]
    pub fn final_bytes(&mut self) -> [u8; MD4_DIGEST_LEN] {
        let bits = encode_words(&self.count, MD4_COUNT_WORDS * 4);
        let index = ((self.count[0] >> 3) & 0x3f) as usize;
        let pad_len = if index < 56 { 56 - index } else { 120 - index };

        self.update(&PADDING[..pad_len]);
        self.update(&bits);

        let digest_vec = encode_words(&self.state, MD4_DIGEST_LEN);
        let mut digest = [0_u8; MD4_DIGEST_LEN];
        digest.copy_from_slice(&digest_vec);
        self.zeroize();
        digest
    }

    /// Clears all state, count, and buffered data from this context.
    pub fn zeroize(&mut self) {
        self.state = [0; MD4_STATE_WORDS];
        self.count = [0; MD4_COUNT_WORDS];
        self.buffer = [0; MD4_BLOCK_LEN];
    }

    fn add_input_bits(&mut self, input_len: usize) {
        let input_bits = (input_len as u32).wrapping_shl(3);
        let old_low = self.count[0];
        self.count[0] = self.count[0].wrapping_add(input_bits);
        if self.count[0] < old_low {
            self.count[1] = self.count[1].wrapping_add(1);
        }
        self.count[1] = self.count[1].wrapping_add((input_len as u32) >> 29);
    }
}

/// Creates a fresh MD4 context, matching the C `MD4Init` entry point.
#[must_use]
pub fn md4_init() -> Md4Context {
    Md4Context::new()
}

/// Updates an MD4 context with additional input, matching C `MD4Update`.
pub fn md4_update(context: &mut Md4Context, input: &[u8]) {
    context.update(input);
}

/// Finalizes an MD4 context into a 16-byte digest, matching C `MD4Final`.
///
#[must_use]
pub fn md4_final(context: &mut Md4Context) -> [u8; MD4_DIGEST_LEN] {
    context.final_bytes()
}

fn md4_transform(state: &mut [u32; MD4_STATE_WORDS], block: &[u8; MD4_BLOCK_LEN]) {
    let mut x = [0_u32; 16];
    decode_words(&mut x, block, MD4_BLOCK_LEN);

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    ff(&mut a, b, c, d, x[0], S11);
    ff(&mut d, a, b, c, x[1], S12);
    ff(&mut c, d, a, b, x[2], S13);
    ff(&mut b, c, d, a, x[3], S14);
    ff(&mut a, b, c, d, x[4], S11);
    ff(&mut d, a, b, c, x[5], S12);
    ff(&mut c, d, a, b, x[6], S13);
    ff(&mut b, c, d, a, x[7], S14);
    ff(&mut a, b, c, d, x[8], S11);
    ff(&mut d, a, b, c, x[9], S12);
    ff(&mut c, d, a, b, x[10], S13);
    ff(&mut b, c, d, a, x[11], S14);
    ff(&mut a, b, c, d, x[12], S11);
    ff(&mut d, a, b, c, x[13], S12);
    ff(&mut c, d, a, b, x[14], S13);
    ff(&mut b, c, d, a, x[15], S14);

    gg(&mut a, b, c, d, x[0], S21);
    gg(&mut d, a, b, c, x[4], S22);
    gg(&mut c, d, a, b, x[8], S23);
    gg(&mut b, c, d, a, x[12], S24);
    gg(&mut a, b, c, d, x[1], S21);
    gg(&mut d, a, b, c, x[5], S22);
    gg(&mut c, d, a, b, x[9], S23);
    gg(&mut b, c, d, a, x[13], S24);
    gg(&mut a, b, c, d, x[2], S21);
    gg(&mut d, a, b, c, x[6], S22);
    gg(&mut c, d, a, b, x[10], S23);
    gg(&mut b, c, d, a, x[14], S24);
    gg(&mut a, b, c, d, x[3], S21);
    gg(&mut d, a, b, c, x[7], S22);
    gg(&mut c, d, a, b, x[11], S23);
    gg(&mut b, c, d, a, x[15], S24);

    hh(&mut a, b, c, d, x[0], S31);
    hh(&mut d, a, b, c, x[8], S32);
    hh(&mut c, d, a, b, x[4], S33);
    hh(&mut b, c, d, a, x[12], S34);
    hh(&mut a, b, c, d, x[2], S31);
    hh(&mut d, a, b, c, x[10], S32);
    hh(&mut c, d, a, b, x[6], S33);
    hh(&mut b, c, d, a, x[14], S34);
    hh(&mut a, b, c, d, x[1], S31);
    hh(&mut d, a, b, c, x[9], S32);
    hh(&mut c, d, a, b, x[5], S33);
    hh(&mut b, c, d, a, x[13], S34);
    hh(&mut a, b, c, d, x[3], S31);
    hh(&mut d, a, b, c, x[11], S32);
    hh(&mut c, d, a, b, x[7], S33);
    hh(&mut b, c, d, a, x[15], S34);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

const fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

const fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

const fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn ff(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
    *a = a.wrapping_add(f(b, c, d)).wrapping_add(x).rotate_left(s);
}

fn gg(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
    *a = a
        .wrapping_add(g(b, c, d))
        .wrapping_add(x)
        .wrapping_add(0x5a82_7999)
        .rotate_left(s);
}

fn hh(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
    *a = a
        .wrapping_add(h(b, c, d))
        .wrapping_add(x)
        .wrapping_add(0x6ed9_eba1)
        .rotate_left(s);
}

fn encode_words(input: &[u32], len: usize) -> Vec<u8> {
    let mut output = vec![0_u8; len];
    for (word, chunk) in input.iter().zip(output.chunks_mut(4)) {
        let bytes = word.to_le_bytes();
        let copy_len = chunk.len();
        chunk.copy_from_slice(&bytes[..copy_len]);
    }
    output
}

fn decode_words(output: &mut [u32], input: &[u8], len: usize) {
    for (word, chunk) in output.iter_mut().zip(input[..len].chunks(4)) {
        let mut bytes = [0_u8; 4];
        bytes[..chunk.len()].copy_from_slice(chunk);
        *word = u32::from_le_bytes(bytes);
    }
}

// ---------------------------------------------------------------------------
// Snapshot-style API mirroring the C `MD4_CTX` observation surface used by the
// spec tests (matches the safe binding shape).
// ---------------------------------------------------------------------------

/// Observable snapshot of an `MD4_CTX`'s internal state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextSnapshot {
    /// Current ABCD state words (`ctx->state`).
    pub state: [u32; 4],
    /// Processed-bit counter (`ctx->count`).
    pub count: [u32; 2],
    /// Pending input buffer (`ctx->buffer`).
    pub buffer: [u8; 64],
}

impl ContextSnapshot {
    fn from_context(ctx: &Md4Context) -> Self {
        Self {
            state: ctx.state,
            count: ctx.count,
            buffer: ctx.buffer,
        }
    }

    /// Returns true if all context storage is zeroed (post-finalization cleanup).
    #[must_use]
    pub fn is_zeroed(&self) -> bool {
        self.state == [0; 4] && self.count == [0; 2] && self.buffer == [0; 64]
    }
}

/// Returns the `(state, count, buffer)` element counts of the context layout.
#[must_use]
pub fn context_layout() -> (usize, usize, usize) {
    (4, 2, 64)
}

/// Returns a snapshot of a freshly initialized context (`MD4Init`).
#[must_use]
pub fn initial_context() -> ContextSnapshot {
    ContextSnapshot::from_context(&Md4Context::new())
}

/// Returns a snapshot after a single `MD4Update` over `input`.
#[must_use]
pub fn snapshot_after_update(input: &[u8]) -> ContextSnapshot {
    let mut ctx = Md4Context::new();
    ctx.update(input);
    ContextSnapshot::from_context(&ctx)
}

/// Returns the digest and the post-finalization (zeroed) context snapshot.
#[must_use]
pub fn digest_with_final_context(input: &[u8]) -> ([u8; 16], ContextSnapshot) {
    let mut ctx = Md4Context::new();
    ctx.update(input);
    let digest = ctx.final_bytes();
    (digest, ContextSnapshot::from_context(&ctx))
}

/// Computes the MD4 digest of `input` in one shot.
#[must_use]
pub fn digest(input: &[u8]) -> [u8; 16] {
    let mut ctx = Md4Context::new();
    ctx.update(input);
    ctx.final_bytes()
}
