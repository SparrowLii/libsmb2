//! MD4 helpers migrated from `lib/md4c.c`.
//!
//! This module mirrors the structure and public lifecycle of the original C
//! implementation without providing the full MD4 compression algorithm yet.

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
    ///
    /// This is a migration skeleton: it tracks bit counts and staging buffers,
    /// but the compression transform is intentionally a no-op until the full
    /// hash algorithm is ported.
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
    /// producing output. Because the transform is still a skeleton, the returned
    /// bytes are not a complete MD4 digest yet.
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
/// The current Rust transform is a skeleton and does not yet compute the full
/// MD4 digest.
#[must_use]
pub fn md4_final(context: &mut Md4Context) -> [u8; MD4_DIGEST_LEN] {
    context.final_bytes()
}

fn md4_transform(state: &mut [u32; MD4_STATE_WORDS], block: &[u8; MD4_BLOCK_LEN]) {
    let mut decoded = [0_u32; 16];
    decode_words(&mut decoded, block, MD4_BLOCK_LEN);
    let schedule = [S11, S12, S13, S14, S21, S22, S23, S24, S31, S32, S33, S34];

    let _ = (state, decoded, schedule);
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
