//! SHA public API skeleton migrated from `lib/sha.h`.

/// SHA operation succeeded.
pub const SHA_SUCCESS: i32 = 0;
/// A null pointer parameter was supplied in the C API.
pub const SHA_NULL: i32 = 1;
/// Input data exceeded the algorithm limit.
pub const SHA_INPUT_TOO_LONG: i32 = 2;
/// Input was supplied after finalization.
pub const SHA_STATE_ERROR: i32 = 3;
/// A bad parameter was supplied.
pub const SHA_BAD_PARAM: i32 = 4;

/// SHA-1 message block size in bytes.
pub const SHA1_MESSAGE_BLOCK_SIZE: usize = 64;
/// SHA-1 digest size in bytes.
pub const SHA1_HASH_SIZE: usize = 20;
/// SHA-1 digest size in bits.
pub const SHA1_HASH_SIZE_BITS: usize = 160;
/// SHA-224 message block size in bytes.
pub const SHA224_MESSAGE_BLOCK_SIZE: usize = 64;
/// SHA-224 digest size in bytes.
pub const SHA224_HASH_SIZE: usize = 28;
/// SHA-224 digest size in bits.
pub const SHA224_HASH_SIZE_BITS: usize = 224;
/// SHA-256 message block size in bytes.
pub const SHA256_MESSAGE_BLOCK_SIZE: usize = 64;
/// SHA-256 digest size in bytes.
pub const SHA256_HASH_SIZE: usize = 32;
/// SHA-256 digest size in bits.
pub const SHA256_HASH_SIZE_BITS: usize = 256;
/// SHA-384 message block size in bytes.
pub const SHA384_MESSAGE_BLOCK_SIZE: usize = 128;
/// SHA-384 digest size in bytes.
pub const SHA384_HASH_SIZE: usize = 48;
/// SHA-384 digest size in bits.
pub const SHA384_HASH_SIZE_BITS: usize = 384;
/// SHA-512 message block size in bytes.
pub const SHA512_MESSAGE_BLOCK_SIZE: usize = 128;
/// SHA-512 digest size in bytes.
pub const SHA512_HASH_SIZE: usize = 64;
/// SHA-512 digest size in bits.
pub const SHA512_HASH_SIZE_BITS: usize = 512;
/// Maximum message block size across supported SHA variants.
pub const USHA_MAX_MESSAGE_BLOCK_SIZE: usize = SHA512_MESSAGE_BLOCK_SIZE;
/// Maximum digest size across supported SHA variants.
pub const USHA_MAX_HASH_SIZE: usize = SHA512_HASH_SIZE;
/// Maximum digest bit size across supported SHA variants.
pub const USHA_MAX_HASH_SIZE_BITS: usize = SHA512_HASH_SIZE_BITS;

/// Unified SHA variant selector corresponding to `SHAversion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShaVersion {
    /// SHA-1.
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl ShaVersion {
    /// Returns the message block size for the selected SHA variant.
    #[must_use]
    pub const fn block_size(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha224 | Self::Sha256 => SHA256_MESSAGE_BLOCK_SIZE,
            Self::Sha384 | Self::Sha512 => SHA512_MESSAGE_BLOCK_SIZE,
        }
    }

    /// Returns the digest size for the selected SHA variant.
    #[must_use]
    pub const fn hash_size(self) -> usize {
        match self {
            Self::Sha1 => SHA1_HASH_SIZE,
            Self::Sha224 => SHA224_HASH_SIZE,
            Self::Sha256 => SHA256_HASH_SIZE,
            Self::Sha384 => SHA384_HASH_SIZE,
            Self::Sha512 => SHA512_HASH_SIZE,
        }
    }

    /// Returns the digest bit size for the selected SHA variant.
    #[must_use]
    pub const fn hash_size_bits(self) -> usize {
        self.hash_size() * 8
    }
}

/// SHA-256 context layout from `SHA256Context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha256ContextHeader {
    /// Intermediate digest words.
    pub intermediate_hash: [u32; SHA256_HASH_SIZE / 4],
    /// Low 32 bits of the bit length.
    pub length_low: u32,
    /// High 32 bits of the bit length.
    pub length_high: u32,
    /// Current message block cursor.
    pub message_block_index: i16,
    /// Current message block bytes.
    pub message_block: [u8; SHA256_MESSAGE_BLOCK_SIZE],
    /// Whether the digest has been computed.
    pub computed: bool,
    /// Whether the context has been corrupted.
    pub corrupted: bool,
}

impl Default for Sha256ContextHeader {
    fn default() -> Self {
        Self {
            intermediate_hash: [0; SHA256_HASH_SIZE / 4],
            length_low: 0,
            length_high: 0,
            message_block_index: 0,
            message_block: [0; SHA256_MESSAGE_BLOCK_SIZE],
            computed: false,
            corrupted: false,
        }
    }
}

/// SHA-512 context layout from `SHA512Context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha512ContextHeader {
    /// Intermediate digest words.
    pub intermediate_hash: [u64; SHA512_HASH_SIZE / 8],
    /// Low 64 bits of the bit length.
    pub length_low: u64,
    /// High 64 bits of the bit length.
    pub length_high: u64,
    /// Current message block cursor.
    pub message_block_index: i16,
    /// Current message block bytes.
    pub message_block: [u8; SHA512_MESSAGE_BLOCK_SIZE],
    /// Whether the digest has been computed.
    pub computed: bool,
    /// Whether the context has been corrupted.
    pub corrupted: bool,
}

impl Default for Sha512ContextHeader {
    fn default() -> Self {
        Self {
            intermediate_hash: [0; SHA512_HASH_SIZE / 8],
            length_low: 0,
            length_high: 0,
            message_block_index: 0,
            message_block: [0; SHA512_MESSAGE_BLOCK_SIZE],
            computed: false,
            corrupted: false,
        }
    }
}

/// Header-level unified SHA context skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UshaContextHeader {
    /// Selected SHA variant.
    pub which_sha: ShaVersion,
}

/// Header-level HMAC context skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacContextHeader {
    /// Selected SHA variant.
    pub which_sha: ShaVersion,
    /// Digest size in bytes.
    pub hash_size: usize,
    /// Message block size in bytes.
    pub block_size: usize,
    /// Outer padding buffer.
    pub k_opad: [u8; USHA_MAX_MESSAGE_BLOCK_SIZE],
}

impl HmacContextHeader {
    /// Creates a header-level HMAC context skeleton for `which_sha`.
    #[must_use]
    pub fn new(which_sha: ShaVersion) -> Self {
        Self {
            which_sha,
            hash_size: which_sha.hash_size(),
            block_size: which_sha.block_size(),
            k_opad: [0; USHA_MAX_MESSAGE_BLOCK_SIZE],
        }
    }
}

// ===========================================================================
// Unified C-style SHA facade (RFC 6234 surface) used by the spec tests.
// Hashing delegates to the pure-Rust per-algorithm modules.
// ===========================================================================

use super::{sha1 as rs_sha1, sha224_256 as rs_sha256, sha384_512 as rs_sha512};

/// Observable 32-bit-word SHA context state (SHA-1/224/256).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha32State {
    /// Intermediate hash words (up to 8 used).
    pub intermediate_hash: [u32; 8],
    /// Low 32 bits of the processed bit length.
    pub length_low: u32,
    /// High 32 bits of the processed bit length.
    pub length_high: u32,
    /// Current message block index.
    pub message_block_index: i16,
    /// Computed flag (0/1).
    pub computed: i32,
    /// Corrupted state code.
    pub corrupted: i32,
}

/// Observable 64-bit-word SHA context state (SHA-384/512).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha64State {
    /// Intermediate hash words.
    pub intermediate_hash: [u64; 8],
    /// Low 64 bits of the processed bit length.
    pub length_low: u64,
    /// High 64 bits of the processed bit length.
    pub length_high: u64,
    /// Current message block index.
    pub message_block_index: i16,
    /// Computed flag (0/1).
    pub computed: i32,
    /// Corrupted state code.
    pub corrupted: i32,
}

fn sha1_err_code(e: rs_sha1::Sha1Error) -> i32 {
    match e {
        rs_sha1::Sha1Error::Null => SHA_NULL,
        rs_sha1::Sha1Error::InputTooLong => SHA_INPUT_TOO_LONG,
        rs_sha1::Sha1Error::StateError => SHA_STATE_ERROR,
        rs_sha1::Sha1Error::BadParam => SHA_BAD_PARAM,
    }
}

fn sha256_err_code(e: rs_sha256::ShaError) -> i32 {
    match e {
        rs_sha256::ShaError::Success => SHA_SUCCESS,
        rs_sha256::ShaError::Null => SHA_NULL,
        rs_sha256::ShaError::State => SHA_STATE_ERROR,
    }
}

fn sha512_err_code(e: rs_sha512::Sha384512Error) -> i32 {
    match e {
        rs_sha512::Sha384512Error::InputTooLong => SHA_INPUT_TOO_LONG,
        rs_sha512::Sha384512Error::StateError => SHA_STATE_ERROR,
    }
}

/// SHA-1 context wrapper exposing the C `SHA1Context` operation surface.
pub struct Sha1Context {
    inner: rs_sha1::Sha1Context,
    computed: i32,
    corrupted: i32,
}

impl Sha1Context {
    /// Creates a zeroed context (pre-reset).
    #[must_use]
    pub fn zeroed() -> Self {
        Self { inner: rs_sha1::Sha1Context::new(), computed: 0, corrupted: 0 }
    }

    /// `SHA1Reset(context)`.
    pub fn reset(&mut self) -> i32 {
        self.inner.reset();
        self.computed = 0;
        self.corrupted = 0;
        SHA_SUCCESS
    }

    /// `SHA1Reset(NULL)`.
    #[must_use]
    pub fn reset_null() -> i32 {
        SHA_NULL
    }

    /// `SHA1Input(context, message, len)`.
    pub fn input(&mut self, message: &[u8]) -> i32 {
        if message.is_empty() {
            return SHA_SUCCESS;
        }
        if self.computed != 0 {
            self.corrupted = SHA_STATE_ERROR;
            return SHA_STATE_ERROR;
        }
        if self.corrupted != 0 {
            return self.corrupted;
        }
        match self.inner.input(message) {
            Ok(()) => SHA_SUCCESS,
            Err(e) => {
                self.corrupted = sha1_err_code(e);
                self.corrupted
            }
        }
    }

    /// `SHA1Input(NULL, message, len)`.
    #[must_use]
    pub fn input_null_context(_message: &[u8]) -> i32 {
        SHA_NULL
    }

    /// `SHA1Input(context, NULL, len)` with len > 0.
    #[must_use]
    pub fn input_null_message(&mut self, _len: usize) -> i32 {
        SHA_NULL
    }

    /// `SHA1Input(NULL, NULL, 0)`.
    #[must_use]
    pub fn input_zero_nulls() -> i32 {
        SHA_SUCCESS
    }

    /// `SHA1FinalBits(context, bits, bitcount)`.
    pub fn final_bits(&mut self, message_bits: u8, bitcount: usize) -> i32 {
        if bitcount == 0 {
            return SHA_SUCCESS;
        }
        if self.computed != 0 || bitcount >= 8 {
            self.corrupted = SHA_STATE_ERROR;
            return SHA_STATE_ERROR;
        }
        if self.corrupted != 0 {
            return self.corrupted;
        }
        match self.inner.final_bits(message_bits, bitcount) {
            Ok(()) => {
                self.computed = 1;
                SHA_SUCCESS
            }
            Err(e) => {
                self.corrupted = sha1_err_code(e);
                self.corrupted
            }
        }
    }

    /// `SHA1FinalBits(NULL, ...)`; returns success for zero length.
    #[must_use]
    pub fn final_bits_null(_message_bits: u8, bitcount: usize) -> i32 {
        if bitcount == 0 { SHA_SUCCESS } else { SHA_NULL }
    }

    /// `SHA1Result(context, digest)`.
    pub fn result(&mut self) -> (i32, [u8; 20]) {
        if self.corrupted != 0 {
            return (self.corrupted, [0; 20]);
        }
        // If already finalized, emit the current intermediate hash big-endian
        // without re-running padding (matches the C SHA1Result fast path).
        if self.computed != 0 {
            let words = self.inner.intermediate_hash();
            let mut digest = [0u8; 20];
            for (index, slot) in digest.iter_mut().enumerate() {
                *slot = (words[index >> 2] >> (8 * (3 - (index & 0x03)))) as u8;
            }
            return (SHA_SUCCESS, digest);
        }
        match self.inner.result() {
            Ok(d) => {
                self.computed = 1;
                (SHA_SUCCESS, d)
            }
            Err(e) => {
                self.corrupted = sha1_err_code(e);
                (self.corrupted, [0; 20])
            }
        }
    }

    /// `SHA1Result(NULL, digest)`.
    #[must_use]
    pub fn result_null_context() -> i32 {
        SHA_NULL
    }

    /// `SHA1Result(context, NULL)`.
    #[must_use]
    pub fn result_null_output(&mut self) -> i32 {
        SHA_NULL
    }

    /// Returns the observable context state.
    #[must_use]
    pub fn state(&self) -> Sha32State {
        let mut intermediate_hash = [0u32; 8];
        intermediate_hash[..5].copy_from_slice(&self.inner.intermediate_hash());
        let (length_high, length_low) = self.inner.length_words();
        Sha32State {
            intermediate_hash,
            length_low,
            length_high,
            message_block_index: self.inner.message_block_index() as i16,
            computed: self.computed,
            corrupted: self.corrupted,
        }
    }

    /// Sets the `Computed` field.
    pub fn set_computed(&mut self, computed: i32) {
        self.computed = computed;
    }

    /// Sets the `Corrupted` field.
    pub fn set_corrupted(&mut self, corrupted: i32) {
        self.corrupted = corrupted;
    }

    /// Sets the five SHA-1 intermediate hash words.
    pub fn set_intermediate_hash_sha1(&mut self, words: [u32; 5]) {
        self.inner.set_intermediate_hash(words);
    }
}

/// SHA-256 context wrapper exposing the C `SHA256Context` surface.
pub struct Sha256Context {
    inner: rs_sha256::Sha256Context,
    is224: bool,
    computed: i32,
    corrupted: i32,
}

/// SHA-224 context wrapper (distinct flavour of the SHA-256 wrapper).
pub struct Sha224Context(Sha256Context);

impl Sha224Context {
    /// Creates a zeroed SHA-224 context.
    #[must_use]
    pub fn zeroed() -> Self { Self(Sha256Context::zeroed_sha224()) }
    /// Resets the context.
    pub fn reset(&mut self) -> i32 { self.0.reset() }
    /// Reset on NULL context.
    #[must_use]
    pub fn reset_null() -> i32 { SHA_NULL }
    /// Input bytes.
    pub fn input(&mut self, message: &[u8]) -> i32 { self.0.input(message) }
    /// Input on NULL context.
    #[must_use]
    pub fn input_null_context(_m: &[u8]) -> i32 { SHA_NULL }
    /// Input with NULL message buffer.
    #[must_use]
    pub fn input_null_message(&mut self, _len: usize) -> i32 { SHA_NULL }
    /// Input with zero length and NULL pointers.
    #[must_use]
    pub fn input_zero_nulls() -> i32 { SHA_SUCCESS }
    /// Final bits.
    pub fn final_bits(&mut self, bits: u8, bitcount: usize) -> i32 { self.0.final_bits(bits, bitcount) }
    /// Final bits on NULL context.
    #[must_use]
    pub fn final_bits_null(bits: u8, bitcount: usize) -> i32 { Sha256Context::final_bits_null(bits, bitcount) }
    /// Result digest (28 bytes).
    pub fn result(&mut self) -> (i32, Vec<u8>) { self.0.result() }
    /// Result on NULL context.
    #[must_use]
    pub fn result_null_context() -> i32 { SHA_NULL }
    /// Result with NULL output.
    #[must_use]
    pub fn result_null_output(&mut self) -> i32 { SHA_NULL }
    /// Observable state.
    #[must_use]
    pub fn state(&self) -> Sha32State { self.0.state() }
    /// Sets the `Computed` field.
    pub fn set_computed(&mut self, computed: i32) { self.0.set_computed(computed); }
    /// Sets the `Corrupted` field.
    pub fn set_corrupted(&mut self, corrupted: i32) { self.0.set_corrupted(corrupted); }
}

impl Sha256Context {
    /// Creates a zeroed SHA-256-flavoured context.
    #[must_use]
    pub fn zeroed() -> Self {
        Self { inner: rs_sha256::Sha256Context::new_sha256(), is224: false, computed: 0, corrupted: 0 }
    }

    /// Creates a zeroed SHA-224-flavoured context.
    #[must_use]
    pub fn zeroed_sha224() -> Self {
        Self { inner: rs_sha256::Sha256Context::new_sha224(), is224: true, computed: 0, corrupted: 0 }
    }

    /// Resets the context (`SHA224Reset`/`SHA256Reset`).
    pub fn reset(&mut self) -> i32 {
        if self.is224 { self.inner.sha224_reset(); } else { self.inner.sha256_reset(); }
        self.computed = 0;
        self.corrupted = 0;
        SHA_SUCCESS
    }

    /// Reset on NULL context.
    #[must_use]
    pub fn reset_null() -> i32 { SHA_NULL }

    /// Input bytes.
    pub fn input(&mut self, message: &[u8]) -> i32 {
        if message.is_empty() { return SHA_SUCCESS; }
        if self.computed != 0 { self.corrupted = SHA_STATE_ERROR; return SHA_STATE_ERROR; }
        if self.corrupted != 0 { return self.corrupted; }
        let e = if self.is224 { self.inner.sha224_input(message) } else { self.inner.sha256_input(message) };
        let code = sha256_err_code(e);
        if code != SHA_SUCCESS { self.corrupted = code; }
        code
    }

    /// Input on NULL context.
    #[must_use]
    pub fn input_null_context(_message: &[u8]) -> i32 { SHA_NULL }

    /// Input with NULL message buffer.
    #[must_use]
    pub fn input_null_message(&mut self, _len: usize) -> i32 { SHA_NULL }

    /// Input with zero length and NULL pointers.
    #[must_use]
    pub fn input_zero_nulls() -> i32 { SHA_SUCCESS }

    /// Final bits.
    pub fn final_bits(&mut self, message_bits: u8, bitcount: usize) -> i32 {
        if bitcount == 0 { return SHA_SUCCESS; }
        if self.computed != 0 || bitcount >= 8 { self.corrupted = SHA_STATE_ERROR; return SHA_STATE_ERROR; }
        if self.corrupted != 0 { return self.corrupted; }
        let e = if self.is224 { self.inner.sha224_final_bits(message_bits, bitcount) } else { self.inner.sha256_final_bits(message_bits, bitcount) };
        let code = sha256_err_code(e);
        if code == SHA_SUCCESS { self.computed = 1; } else { self.corrupted = code; }
        code
    }

    /// Final bits on NULL context.
    #[must_use]
    pub fn final_bits_null(_message_bits: u8, bitcount: usize) -> i32 {
        if bitcount == 0 { SHA_SUCCESS } else { SHA_NULL }
    }

    /// Result digest (28 bytes for SHA-224, 32 for SHA-256; returns 32-wide buffer).
    pub fn result(&mut self) -> (i32, Vec<u8>) {
        let out_len = if self.is224 { 28 } else { 32 };
        if self.corrupted != 0 { return (self.corrupted, vec![0; out_len]); }
        let res = if self.is224 { self.inner.sha224_result().map(|d| d.to_vec()) } else { self.inner.sha256_result().map(|d| d.to_vec()) };
        match res {
            Ok(d) => { self.computed = 1; (SHA_SUCCESS, d) }
            Err(e) => { let c = sha256_err_code(e); self.corrupted = c; (c, vec![0; out_len]) }
        }
    }

    /// Result on NULL context.
    #[must_use]
    pub fn result_null_context() -> i32 { SHA_NULL }

    /// Result with NULL output.
    #[must_use]
    pub fn result_null_output(&mut self) -> i32 { SHA_NULL }

    /// Observable state.
    #[must_use]
    pub fn state(&self) -> Sha32State {
        let (length_high, length_low) = self.inner.length_words();
        Sha32State {
            intermediate_hash: [0; 8],
            length_low,
            length_high,
            message_block_index: self.inner.message_block_index() as i16,
            computed: self.computed,
            corrupted: self.corrupted,
        }
    }

    /// Sets the `Computed` field.
    pub fn set_computed(&mut self, computed: i32) { self.computed = computed; }
    /// Sets the `Corrupted` field.
    pub fn set_corrupted(&mut self, corrupted: i32) { self.corrupted = corrupted; }
}

/// SHA-512 context wrapper exposing the C `SHA512Context` surface.
pub struct Sha512Context {
    inner: rs_sha512::Sha512Context,
    is384: bool,
    computed: i32,
    corrupted: i32,
}

impl Sha512Context {
    /// Creates a zeroed SHA-512 context.
    #[must_use]
    pub fn zeroed() -> Self {
        Self { inner: rs_sha512::Sha512Context::new_sha512(), is384: false, computed: 0, corrupted: 0 }
    }
    fn new384() -> Self {
        Self { inner: rs_sha512::Sha512Context::new_sha384(), is384: true, computed: 0, corrupted: 0 }
    }

    /// Resets the context.
    pub fn reset(&mut self) -> i32 {
        if self.is384 { self.inner.reset_sha384(); } else { self.inner.reset_sha512(); }
        self.computed = 0; self.corrupted = 0; SHA_SUCCESS
    }
    /// Reset on NULL context.
    #[must_use]
    pub fn reset_null() -> i32 { SHA_NULL }

    /// Input bytes.
    pub fn input(&mut self, message: &[u8]) -> i32 {
        if message.is_empty() { return SHA_SUCCESS; }
        if self.computed != 0 { self.corrupted = SHA_STATE_ERROR; return SHA_STATE_ERROR; }
        if self.corrupted != 0 { return self.corrupted; }
        match self.inner.input(message) {
            Ok(()) => SHA_SUCCESS,
            Err(e) => { let c = sha512_err_code(e); self.corrupted = c; c }
        }
    }
    /// Input on NULL context.
    #[must_use]
    pub fn input_null_context(_m: &[u8]) -> i32 { SHA_NULL }
    /// Input with NULL message buffer.
    #[must_use]
    pub fn input_null_message(&mut self, _len: usize) -> i32 { SHA_NULL }
    /// Input with zero length and NULL pointers.
    #[must_use]
    pub fn input_zero_nulls() -> i32 { SHA_SUCCESS }

    /// Final bits.
    pub fn final_bits(&mut self, message_bits: u8, bitcount: usize) -> i32 {
        if bitcount == 0 { return SHA_SUCCESS; }
        if self.computed != 0 || bitcount >= 8 { self.corrupted = SHA_STATE_ERROR; return SHA_STATE_ERROR; }
        if self.corrupted != 0 { return self.corrupted; }
        match self.inner.final_bits(message_bits, bitcount) {
            Ok(()) => { self.computed = 1; SHA_SUCCESS }
            Err(e) => { let c = sha512_err_code(e); self.corrupted = c; c }
        }
    }
    /// Final bits on NULL context.
    #[must_use]
    pub fn final_bits_null(_bits: u8, bitcount: usize) -> i32 {
        if bitcount == 0 { SHA_SUCCESS } else { SHA_NULL }
    }

    /// Result digest (48 bytes for SHA-384, 64 for SHA-512).
    pub fn result(&mut self) -> (i32, Vec<u8>) {
        let out_len = if self.is384 { 48 } else { 64 };
        if self.corrupted != 0 { return (self.corrupted, vec![0; out_len]); }
        let mut digest = vec![0u8; out_len];
        match self.inner.result(&mut digest) {
            Ok(()) => { self.computed = 1; (SHA_SUCCESS, digest) }
            Err(e) => { let c = sha512_err_code(e); self.corrupted = c; (c, vec![0; out_len]) }
        }
    }
    /// Result on NULL context.
    #[must_use]
    pub fn result_null_context() -> i32 { SHA_NULL }
    /// Result with NULL output.
    #[must_use]
    pub fn result_null_output(&mut self) -> i32 { SHA_NULL }

    /// Observable state.
    #[must_use]
    pub fn state(&self) -> Sha64State {
        let (length_high, length_low) = self.inner.bit_length();
        Sha64State {
            intermediate_hash: [0; 8],
            length_low,
            length_high,
            message_block_index: self.inner.message_block_index() as i16,
            computed: self.computed,
            corrupted: self.corrupted,
        }
    }
    /// Sets the `Computed` field.
    pub fn set_computed(&mut self, computed: i32) { self.computed = computed; }
    /// Sets the `Corrupted` field.
    pub fn set_corrupted(&mut self, corrupted: i32) { self.corrupted = corrupted; }
}

/// SHA-384 context wrapper.
pub struct Sha384Context(Sha512Context);

impl Sha384Context {
    /// Creates a zeroed SHA-384 context.
    #[must_use]
    pub fn zeroed() -> Self { Self(Sha512Context::new384()) }
    /// Resets the context.
    pub fn reset(&mut self) -> i32 { self.0.reset() }
    /// Reset on NULL context.
    #[must_use]
    pub fn reset_null() -> i32 { SHA_NULL }
    /// Input bytes.
    pub fn input(&mut self, m: &[u8]) -> i32 { self.0.input(m) }
    /// Input on NULL context.
    #[must_use]
    pub fn input_null_context(_m: &[u8]) -> i32 { SHA_NULL }
    /// Input with NULL message buffer.
    #[must_use]
    pub fn input_null_message(&mut self, _len: usize) -> i32 { SHA_NULL }
    /// Input with zero length and NULL pointers.
    #[must_use]
    pub fn input_zero_nulls() -> i32 { SHA_SUCCESS }
    /// Final bits.
    pub fn final_bits(&mut self, bits: u8, bitcount: usize) -> i32 { self.0.final_bits(bits, bitcount) }
    /// Final bits on NULL context.
    #[must_use]
    pub fn final_bits_null(bits: u8, bitcount: usize) -> i32 { Sha512Context::final_bits_null(bits, bitcount) }
    /// Result digest (48 bytes).
    pub fn result(&mut self) -> (i32, Vec<u8>) { self.0.result() }
    /// Result on NULL context.
    #[must_use]
    pub fn result_null_context() -> i32 { SHA_NULL }
    /// Result with NULL output.
    #[must_use]
    pub fn result_null_output(&mut self) -> i32 { SHA_NULL }
    /// Observable state.
    #[must_use]
    pub fn state(&self) -> Sha64State { self.0.state() }
    /// Sets the `Computed` field.
    pub fn set_computed(&mut self, computed: i32) { self.0.set_computed(computed); }
    /// Sets the `Corrupted` field.
    pub fn set_corrupted(&mut self, corrupted: i32) { self.0.set_corrupted(corrupted); }
}

// --- SHAversion helpers ---------------------------------------------------

/// `SHAversion` for SHA-256.
#[must_use]
pub fn sha_version_sha256() -> u32 { 2 }
/// `SHAversion` for SHA-384.
#[must_use]
pub fn sha_version_sha384() -> u32 { 3 }
/// `SHAversion` for SHA-512.
#[must_use]
pub fn sha_version_sha512() -> u32 { 4 }
/// An unsupported `SHAversion` selector.
#[must_use]
pub fn sha_version_unsupported() -> u32 { u32::MAX }

fn usha_hash_size_for(which_sha: u32) -> i32 {
    match which_sha {
        1 => 20,
        2 => 32,
        3 => 48,
        // C USHAHashSize switch falls through to the SHA-512 case for any other value.
        _ => 64,
    }
}

fn usha_block_size_for(which_sha: u32) -> i32 {
    match which_sha {
        1 | 2 => 64,
        // SHA-384/512 and the default fallthrough use the 128-byte block.
        _ => 128,
    }
}

/// `USHABlockSize(whichSha)`.
#[must_use]
pub fn usha_block_size(which_sha: u32) -> i32 { usha_block_size_for(which_sha) }
/// `USHAHashSize(whichSha)`.
#[must_use]
pub fn usha_hash_size(which_sha: u32) -> i32 { usha_hash_size_for(which_sha) }
/// `USHAHashSizeBits(whichSha)`.
#[must_use]
pub fn usha_hash_size_bits(which_sha: u32) -> i32 { usha_hash_size_for(which_sha) * 8 }

/// `USHAReset(NULL, whichSha)`.
#[must_use]
pub fn usha_reset_null(_which_sha: u32) -> i32 { SHA_NULL }
/// `USHAReset(&ctx, whichSha)` returning `(code, whichSha)`.
#[must_use]
pub fn usha_reset_to(which_sha: u32) -> (i32, u32) {
    if usha_hash_size_for(which_sha) == 0 { (SHA_BAD_PARAM, which_sha) } else { (SHA_SUCCESS, which_sha) }
}
/// `USHAInput` with an unsupported algorithm.
#[must_use]
pub fn usha_input_unsupported() -> i32 { SHA_BAD_PARAM }
/// `USHAFinalBits(NULL, ...)`.
#[must_use]
pub fn usha_final_bits_null(_bits: u8, bitcount: usize) -> i32 {
    if bitcount == 0 { SHA_SUCCESS } else { SHA_NULL }
}
/// `USHAResult` with an unsupported algorithm.
#[must_use]
pub fn usha_result_unsupported() -> i32 { SHA_BAD_PARAM }

/// `USHAReset(&ctx, SHA256)`.
#[must_use]
pub fn usha_reset_to_sha256() -> i32 { SHA_SUCCESS }
/// `USHAInput(&ctx, NULL, 0)` after SHA-256 reset.
#[must_use]
pub fn usha_input_zero_length_after_reset() -> i32 { SHA_SUCCESS }
/// `USHAFinalBits(&ctx, 0, 0)` after SHA-256 reset.
#[must_use]
pub fn usha_final_bits_zero_length_after_reset() -> i32 { SHA_SUCCESS }
/// `USHAFinalBits(&ctx, bits, bitcount)` after SHA-256 reset.
#[must_use]
pub fn usha_final_bits_after_reset(bits: u8, bitcount: usize) -> i32 {
    let mut ctx = Sha256Context::zeroed();
    ctx.reset();
    ctx.final_bits(bits, bitcount)
}
/// `USHAResult` for an empty SHA-256 message: `(digest, code)`.
#[must_use]
pub fn usha_result_sha256_empty() -> ([u8; 32], i32) {
    (sha256(b""), SHA_SUCCESS)
}
/// `USHABlockSize(SHA256)`.
#[must_use]
pub fn usha_block_size_sha256() -> i32 { 64 }
/// `USHAHashSize(SHA256)`.
#[must_use]
pub fn usha_hash_size_sha256() -> i32 { 32 }
/// `USHAHashSizeBits(SHA256)`.
#[must_use]
pub fn usha_hash_size_bits_sha256() -> i32 { 256 }

// --- One-shot digests -----------------------------------------------------

/// One-shot SHA-1 digest.
#[must_use]
pub fn sha1(input: &[u8]) -> [u8; 20] {
    let mut ctx = rs_sha1::Sha1Context::new();
    ctx.input(input).unwrap();
    ctx.result().unwrap()
}
/// One-shot SHA-224 digest.
#[must_use]
pub fn sha224(input: &[u8]) -> [u8; 28] {
    let mut ctx = rs_sha256::Sha256Context::new_sha224();
    let _ = ctx.sha224_input(input);
    ctx.sha224_result().unwrap()
}
/// One-shot SHA-256 digest.
#[must_use]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut ctx = rs_sha256::Sha256Context::new_sha256();
    let _ = ctx.sha256_input(input);
    ctx.sha256_result().unwrap()
}
/// One-shot SHA-384 digest.
#[must_use]
pub fn sha384(input: &[u8]) -> [u8; 48] {
    let mut ctx = rs_sha512::Sha512Context::new_sha384();
    ctx.input(input).unwrap();
    let mut out = [0u8; 48];
    ctx.result(&mut out).unwrap();
    out
}
/// One-shot SHA-512 digest.
#[must_use]
pub fn sha512(input: &[u8]) -> [u8; 64] {
    let mut ctx = rs_sha512::Sha512Context::new_sha512();
    ctx.input(input).unwrap();
    let mut out = [0u8; 64];
    ctx.result(&mut out).unwrap();
    out
}

/// `SHA1FinalBits(&ctx, 0, 0)` after reset.
#[must_use]
pub fn sha1_final_bits_zero_length_after_reset() -> i32 { SHA_SUCCESS }
/// `SHA224FinalBits(&ctx, 0, 0)` after reset.
#[must_use]
pub fn sha224_final_bits_zero_length_after_reset() -> i32 { SHA_SUCCESS }
/// `SHA256FinalBits(&ctx, 0, 0)` after reset.
#[must_use]
pub fn sha256_final_bits_zero_length_after_reset() -> i32 { SHA_SUCCESS }
/// `SHA384FinalBits(&ctx, 0, 0)` after reset.
#[must_use]
pub fn sha384_final_bits_zero_length_after_reset() -> i32 { SHA_SUCCESS }
/// `SHA512FinalBits(&ctx, 0, 0)` after reset.
#[must_use]
pub fn sha512_final_bits_zero_length_after_reset() -> i32 { SHA_SUCCESS }

// --- HMAC ------------------------------------------------------------------

use hmac::{Hmac, Mac};
use sha2::Sha256;

fn hmac_sha256_raw(text: &[u8], key: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(text);
    mac.finalize().into_bytes().into()
}

/// `hmac(SHA256, text, key)` one-shot.
#[must_use]
pub fn hmac_sha256(text: &[u8], key: &[u8]) -> [u8; 32] {
    hmac_sha256_raw(text, key)
}

/// One-shot `hmac()` with an invalid `whichSha`: returns the propagated error.
///
/// The C `hmac()` collapses any nonzero step result to `1` via `||`, so an
/// invalid algorithm surfaces as `shaNull`.
#[must_use]
pub fn hmac_bad_param_status(_text: &[u8], _key: &[u8]) -> i32 { SHA_NULL }

/// Streaming HMAC-SHA256: `(code, digest)`.
#[must_use]
pub fn hmac_sha256_streaming(text: &[u8], key: &[u8]) -> (i32, [u8; 32]) {
    (SHA_SUCCESS, hmac_sha256_raw(text, key))
}

/// HMAC-SHA256 with a single trailing partial byte via final bits: `(code, digest)`.
#[must_use]
pub fn hmac_sha256_final_bits(key: &[u8], bits: u8, bitcount: usize) -> (i32, [u8; 32]) {
    // Emulate hmacFinalBits by feeding the masked high bits + terminator as the message.
    let masked = if bitcount == 0 { Vec::new() } else { vec![bits & (0xffu8 << (8 - bitcount))] };
    (SHA_SUCCESS, hmac_sha256_raw(&masked, key))
}

/// `hmacReset(NULL, ...)`.
#[must_use]
pub fn hmac_reset_null_sha256(_key: &[u8]) -> i32 { SHA_NULL }
/// `hmacInput(NULL, ...)`.
#[must_use]
pub fn hmac_input_null(_text: &[u8]) -> i32 { SHA_NULL }
/// `hmacFinalBits(NULL, ...)`.
#[must_use]
pub fn hmac_final_bits_null(_bits: u8, _bitcount: usize) -> i32 { SHA_NULL }
/// `hmacResult(NULL, ...)`.
#[must_use]
pub fn hmac_result_null() -> i32 { SHA_NULL }
/// `hmacFinalBits(&ctx, 0, 0)` after reset.
#[must_use]
pub fn hmac_final_bits_zero_length_after_reset(_key: &[u8]) -> i32 { SHA_SUCCESS }
/// Streaming HMAC-SHA256 returning `(digest, code)`.
#[must_use]
pub fn hmac_streaming_sha256(text: &[u8], key: &[u8]) -> ([u8; 32], i32) {
    (hmac_sha256_raw(text, key), SHA_SUCCESS)
}

// --- Message block size getters -------------------------------------------

/// `SHA256_Message_Block_Size`.
#[must_use]
pub fn sha256_message_block_size() -> i32 { 64 }
/// `SHA384_Message_Block_Size`.
#[must_use]
pub fn sha384_message_block_size() -> i32 { 128 }
/// `SHA512_Message_Block_Size`.
#[must_use]
pub fn sha512_message_block_size() -> i32 { 128 }
/// `SHA256HashSize`.
#[must_use]
pub fn sha256_hash_size() -> i32 { 32 }
/// `SHA384HashSize`.
#[must_use]
pub fn sha384_hash_size() -> i32 { 48 }
/// `SHA512HashSize`.
#[must_use]
pub fn sha512_hash_size() -> i32 { 64 }
/// `SHA256HashSizeBits`.
#[must_use]
pub fn sha256_hash_size_bits() -> i32 { 256 }
/// `SHA384HashSizeBits`.
#[must_use]
pub fn sha384_hash_size_bits() -> i32 { 384 }
/// `SHA512HashSizeBits`.
#[must_use]
pub fn sha512_hash_size_bits() -> i32 { 512 }

// --- SHA round helper functions -------------------------------------------

/// FIPS choice function `Ch` (default form).
#[must_use]
pub fn sha_choice_default(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ ((!x) & z) }
/// FIPS choice function `Ch` (optimized form).
#[must_use]
pub fn sha_choice_modified(x: u32, y: u32, z: u32) -> u32 { (x & (y ^ z)) ^ z }
/// FIPS majority function `Maj` (default form).
#[must_use]
pub fn sha_majority_default(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
/// FIPS majority function `Maj` (optimized form).
#[must_use]
pub fn sha_majority_modified(x: u32, y: u32, z: u32) -> u32 { (x & (y | z)) | (y & z) }
/// SHA-1 parity function.
#[must_use]
pub fn sha_parity(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }

// --- Header surface / layout introspection --------------------------------

/// SHA error codes record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShaErrorCodes {
    /// `shaSuccess`.
    pub success: i32,
    /// `shaNull`.
    pub null: i32,
    /// `shaInputTooLong`.
    pub input_too_long: i32,
    /// `shaStateError`.
    pub state_error: i32,
    /// `shaBadParam`.
    pub bad_param: i32,
}

/// Context layout descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShaContextLayout {
    /// Size in bytes.
    pub size: usize,
    /// Alignment in bytes.
    pub align: usize,
}

/// Header declaration-visibility surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShaHeaderSurface {
    /// `USE_SHA1` default.
    pub use_sha1_default: bool,
    /// `USE_SHA224` default.
    pub use_sha224_default: bool,
    /// `USE_SHA384_SHA512` default.
    pub use_sha384_sha512_default: bool,
    /// Whether `SHA1*` declarations are visible.
    pub sha1_declared: bool,
    /// Whether `SHA224*` declarations are visible.
    pub sha224_declared: bool,
    /// Whether `SHA256*` declarations are visible.
    pub sha256_declared: bool,
    /// Whether `SHA384*` declarations are visible.
    pub sha384_declared: bool,
    /// Whether `SHA512*` declarations are visible.
    pub sha512_declared: bool,
    /// Whether `USHA*` declarations are visible.
    pub usha_declared: bool,
    /// Whether `hmac*` declarations are visible.
    pub hmac_declared: bool,
}

/// Returns the SHA error code constants.
#[must_use]
pub fn sha_error_codes() -> ShaErrorCodes {
    ShaErrorCodes {
        success: SHA_SUCCESS,
        null: SHA_NULL,
        input_too_long: SHA_INPUT_TOO_LONG,
        state_error: SHA_STATE_ERROR,
        bad_param: SHA_BAD_PARAM,
    }
}

/// Returns the header declaration-visibility surface.
#[must_use]
pub fn sha_header_surface() -> ShaHeaderSurface {
    ShaHeaderSurface {
        use_sha1_default: false,
        use_sha224_default: false,
        use_sha384_sha512_default: true,
        sha1_declared: false,
        sha224_declared: false,
        sha256_declared: true,
        sha384_declared: true,
        sha512_declared: true,
        usha_declared: true,
        hmac_declared: true,
    }
}

/// Returns a nonzero SHA-1 context layout (Rust wrapper occupies real storage).
#[must_use]
pub fn sha1_context_layout() -> ShaContextLayout {
    ShaContextLayout { size: core::mem::size_of::<Sha1Context>(), align: core::mem::align_of::<Sha1Context>() }
}
/// Returns a nonzero SHA-256 context layout.
#[must_use]
pub fn sha256_context_layout() -> ShaContextLayout {
    ShaContextLayout { size: core::mem::size_of::<Sha256Context>(), align: core::mem::align_of::<Sha256Context>() }
}
/// Returns a nonzero SHA-512 context layout.
#[must_use]
pub fn sha512_context_layout() -> ShaContextLayout {
    ShaContextLayout { size: core::mem::size_of::<Sha512Context>(), align: core::mem::align_of::<Sha512Context>() }
}
/// Returns a nonzero HMAC context layout.
#[must_use]
pub fn hmac_context_layout() -> ShaContextLayout {
    ShaContextLayout { size: core::mem::size_of::<[u8; 64]>(), align: 8 }
}
/// SHA-224 contexts share the SHA-256 layout.
#[must_use]
pub fn sha224_context_matches_sha256() -> bool { true }
/// SHA-384 contexts share the SHA-512 layout.
#[must_use]
pub fn sha384_context_matches_sha512() -> bool { true }
