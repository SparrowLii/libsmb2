mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub const SHA_SUCCESS: i32 = ffi::shaSuccess as i32;
pub const SHA_NULL: i32 = ffi::shaNull as i32;
pub const SHA_STATE_ERROR: i32 = ffi::shaStateError as i32;
pub const SHA_BAD_PARAM: i32 = ffi::shaBadParam as i32;

fn assert_success(code: i32) {
    assert_eq!(code, SHA_SUCCESS);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha32State {
    pub intermediate_hash: [u32; 8],
    pub length_low: u32,
    pub length_high: u32,
    pub message_block_index: i16,
    pub computed: i32,
    pub corrupted: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha64State {
    pub intermediate_hash: [u64; 8],
    pub length_low: u64,
    pub length_high: u64,
    pub message_block_index: i16,
    pub computed: i32,
    pub corrupted: i32,
}

pub fn sha_version_sha256() -> u32 {
    ffi::SHAversion_SHA256
}

pub fn sha_version_sha384() -> u32 {
    ffi::SHAversion_SHA384
}

pub fn sha_version_sha512() -> u32 {
    ffi::SHAversion_SHA512
}

pub fn sha_version_unsupported() -> u32 {
    u32::MAX
}

pub fn usha_reset_null(which_sha: u32) -> i32 {
    unsafe { ffi::USHAReset(std::ptr::null_mut(), which_sha) }
}

pub fn usha_reset_to(which_sha: u32) -> (i32, u32) {
    let mut context = unsafe { std::mem::zeroed::<ffi::USHAContext>() };
    let code = unsafe { ffi::USHAReset(&mut context, which_sha) };
    (code, context.whichSha)
}

pub fn usha_input_unsupported() -> i32 {
    let mut context = unsafe { std::mem::zeroed::<ffi::USHAContext>() };
    context.whichSha = sha_version_unsupported();
    unsafe { ffi::USHAInput(&mut context, std::ptr::null(), 0) }
}

pub fn usha_final_bits_null(bits: u8, bitcount: usize) -> i32 {
    unsafe { ffi::USHAFinalBits(std::ptr::null_mut(), bits, bitcount) }
}

pub fn usha_result_unsupported() -> i32 {
    let mut context = unsafe { std::mem::zeroed::<ffi::USHAContext>() };
    let mut output = [0; 64];
    context.whichSha = sha_version_unsupported();
    unsafe { ffi::USHAResult(&mut context, output.as_mut_ptr()) }
}

pub fn usha_block_size(which_sha: u32) -> i32 {
    unsafe { ffi::USHABlockSize(which_sha) }
}

pub fn usha_hash_size(which_sha: u32) -> i32 {
    unsafe { ffi::USHAHashSize(which_sha) }
}

pub fn usha_hash_size_bits(which_sha: u32) -> i32 {
    unsafe { ffi::USHAHashSizeBits(which_sha) }
}

pub fn sha256_message_block_size() -> i32 {
    ffi::SHA256_Message_Block_Size as i32
}

pub fn sha384_message_block_size() -> i32 {
    ffi::SHA384_Message_Block_Size as i32
}

pub fn sha512_message_block_size() -> i32 {
    ffi::SHA512_Message_Block_Size as i32
}

pub fn sha256_hash_size() -> i32 {
    ffi::SHA256HashSize as i32
}

pub fn sha384_hash_size() -> i32 {
    ffi::SHA384HashSize as i32
}

pub fn sha512_hash_size() -> i32 {
    ffi::SHA512HashSize as i32
}

pub fn sha256_hash_size_bits() -> i32 {
    ffi::SHA256HashSizeBits as i32
}

pub fn sha384_hash_size_bits() -> i32 {
    ffi::SHA384HashSizeBits as i32
}

pub fn sha512_hash_size_bits() -> i32 {
    ffi::SHA512HashSizeBits as i32
}

pub fn hmac_sha256_streaming(text: &[u8], key: &[u8]) -> (i32, [u8; 32]) {
    let mut context = unsafe { std::mem::zeroed::<ffi::HMACContext>() };
    let mut output = [0; 64];

    let code = unsafe {
        let mut code = ffi::hmacReset(
            &mut context,
            ffi::SHAversion_SHA256,
            key.as_ptr(),
            key.len(),
        );
        if code == SHA_SUCCESS {
            code = ffi::hmacInput(&mut context, text.as_ptr(), text.len());
        }
        if code == SHA_SUCCESS {
            code = ffi::hmacResult(&mut context, output.as_mut_ptr());
        }
        code
    };

    (code, output[..32].try_into().unwrap())
}

pub fn hmac_bad_param_status(text: &[u8], key: &[u8]) -> i32 {
    let mut output = [0; 64];
    unsafe {
        ffi::hmac(
            999,
            text.as_ptr(),
            text.len(),
            key.as_ptr(),
            key.len(),
            output.as_mut_ptr(),
        )
    }
}

pub fn hmac_sha256_final_bits(key: &[u8], bits: u8, bitcount: usize) -> (i32, [u8; 32]) {
    let mut context = unsafe { std::mem::zeroed::<ffi::HMACContext>() };
    let mut output = [0; 64];

    let code = unsafe {
        let mut code = ffi::hmacReset(
            &mut context,
            ffi::SHAversion_SHA256,
            key.as_ptr(),
            key.len(),
        );
        if code == SHA_SUCCESS {
            code = ffi::hmacFinalBits(&mut context, bits, bitcount);
        }
        if code == SHA_SUCCESS {
            code = ffi::hmacResult(&mut context, output.as_mut_ptr());
        }
        code
    };

    (code, output[..32].try_into().unwrap())
}

pub fn hmac_reset_null_sha256(key: &[u8]) -> i32 {
    unsafe {
        ffi::hmacReset(
            std::ptr::null_mut(),
            ffi::SHAversion_SHA256,
            key.as_ptr(),
            key.len(),
        )
    }
}

pub fn hmac_input_null(text: &[u8]) -> i32 {
    unsafe { ffi::hmacInput(std::ptr::null_mut(), text.as_ptr(), text.len()) }
}

pub fn hmac_final_bits_null(bits: u8, bitcount: usize) -> i32 {
    unsafe { ffi::hmacFinalBits(std::ptr::null_mut(), bits, bitcount) }
}

pub fn hmac_result_null() -> i32 {
    let mut output = [0; 64];
    unsafe { ffi::hmacResult(std::ptr::null_mut(), output.as_mut_ptr()) }
}

pub struct Sha1Context {
    raw: ffi::SHA1Context,
}

impl Sha1Context {
    pub fn zeroed() -> Self {
        Self {
            raw: unsafe { std::mem::zeroed() },
        }
    }

    pub fn reset(&mut self) -> i32 {
        unsafe { ffi::SHA1Reset(&mut self.raw) }
    }

    pub fn reset_null() -> i32 {
        unsafe { ffi::SHA1Reset(std::ptr::null_mut()) }
    }

    pub fn input(&mut self, input: &[u8]) -> i32 {
        unsafe { ffi::SHA1Input(&mut self.raw, input.as_ptr(), input.len()) }
    }

    pub fn input_null_context(input: &[u8]) -> i32 {
        unsafe { ffi::SHA1Input(std::ptr::null_mut(), input.as_ptr(), input.len()) }
    }

    pub fn input_null_message(&mut self, len: usize) -> i32 {
        unsafe { ffi::SHA1Input(&mut self.raw, std::ptr::null(), len) }
    }

    pub fn input_zero_nulls() -> i32 {
        unsafe { ffi::SHA1Input(std::ptr::null_mut(), std::ptr::null(), 0) }
    }

    pub fn final_bits(&mut self, bits: u8, bitcount: usize) -> i32 {
        unsafe { ffi::SHA1FinalBits(&mut self.raw, bits, bitcount) }
    }

    pub fn final_bits_null(bits: u8, bitcount: usize) -> i32 {
        unsafe { ffi::SHA1FinalBits(std::ptr::null_mut(), bits, bitcount) }
    }

    pub fn result(&mut self) -> (i32, [u8; 20]) {
        let mut output = [0; 20];
        let code = unsafe { ffi::SHA1Result(&mut self.raw, output.as_mut_ptr()) };
        (code, output)
    }

    pub fn result_null_context() -> i32 {
        let mut output = [0; 20];
        unsafe { ffi::SHA1Result(std::ptr::null_mut(), output.as_mut_ptr()) }
    }

    pub fn result_null_output(&mut self) -> i32 {
        unsafe { ffi::SHA1Result(&mut self.raw, std::ptr::null_mut()) }
    }

    pub fn state(&self) -> Sha32State {
        let mut intermediate_hash = [0; 8];
        intermediate_hash[..5].copy_from_slice(&self.raw.Intermediate_Hash);
        Sha32State {
            intermediate_hash,
            length_low: self.raw.Length_Low,
            length_high: self.raw.Length_High,
            message_block_index: self.raw.Message_Block_Index,
            computed: self.raw.Computed,
            corrupted: self.raw.Corrupted,
        }
    }

    pub fn set_computed(&mut self, computed: i32) {
        self.raw.Computed = computed;
    }

    pub fn set_corrupted(&mut self, corrupted: i32) {
        self.raw.Corrupted = corrupted;
    }

    pub fn set_intermediate_hash_sha1(&mut self, words: [u32; 5]) {
        self.raw.Intermediate_Hash = words;
    }
}

macro_rules! sha32_context {
    ($name:ident, $raw:ty, $reset:ident, $input:ident, $final_bits:ident, $result:ident, $out:expr, $hash_words:expr) => {
        pub struct $name {
            raw: $raw,
        }

        impl $name {
            pub fn zeroed() -> Self {
                Self {
                    raw: unsafe { std::mem::zeroed() },
                }
            }

            pub fn reset(&mut self) -> i32 {
                unsafe { ffi::$reset(&mut self.raw) }
            }

            pub fn reset_null() -> i32 {
                unsafe { ffi::$reset(std::ptr::null_mut()) }
            }

            pub fn input(&mut self, input: &[u8]) -> i32 {
                unsafe { ffi::$input(&mut self.raw, input.as_ptr(), input.len()) }
            }

            pub fn input_null_context(input: &[u8]) -> i32 {
                unsafe { ffi::$input(std::ptr::null_mut(), input.as_ptr(), input.len()) }
            }

            pub fn input_null_message(&mut self, len: usize) -> i32 {
                unsafe { ffi::$input(&mut self.raw, std::ptr::null(), len) }
            }

            pub fn input_zero_nulls() -> i32 {
                unsafe { ffi::$input(std::ptr::null_mut(), std::ptr::null(), 0) }
            }

            pub fn final_bits(&mut self, bits: u8, bitcount: usize) -> i32 {
                unsafe { ffi::$final_bits(&mut self.raw, bits, bitcount) }
            }

            pub fn final_bits_null(bits: u8, bitcount: usize) -> i32 {
                unsafe { ffi::$final_bits(std::ptr::null_mut(), bits, bitcount) }
            }

            pub fn result(&mut self) -> (i32, [u8; $out]) {
                let mut output = [0; $out];
                let code = unsafe { ffi::$result(&mut self.raw, output.as_mut_ptr()) };
                (code, output)
            }

            pub fn result_null_context() -> i32 {
                let mut output = [0; $out];
                unsafe { ffi::$result(std::ptr::null_mut(), output.as_mut_ptr()) }
            }

            pub fn result_null_output(&mut self) -> i32 {
                unsafe { ffi::$result(&mut self.raw, std::ptr::null_mut()) }
            }

            pub fn state(&self) -> Sha32State {
                let mut intermediate_hash = [0; 8];
                intermediate_hash[..$hash_words].copy_from_slice(&self.raw.Intermediate_Hash);
                Sha32State {
                    intermediate_hash,
                    length_low: self.raw.Length_Low,
                    length_high: self.raw.Length_High,
                    message_block_index: self.raw.Message_Block_Index,
                    computed: self.raw.Computed,
                    corrupted: self.raw.Corrupted,
                }
            }

            pub fn set_computed(&mut self, computed: i32) {
                self.raw.Computed = computed;
            }

            pub fn set_corrupted(&mut self, corrupted: i32) {
                self.raw.Corrupted = corrupted;
            }
        }
    };
}

macro_rules! sha64_context {
    ($name:ident, $raw:ty, $reset:ident, $input:ident, $final_bits:ident, $result:ident, $out:expr) => {
        pub struct $name {
            raw: $raw,
        }

        impl $name {
            pub fn zeroed() -> Self {
                Self {
                    raw: unsafe { std::mem::zeroed() },
                }
            }

            pub fn reset(&mut self) -> i32 {
                unsafe { ffi::$reset(&mut self.raw) }
            }

            pub fn reset_null() -> i32 {
                unsafe { ffi::$reset(std::ptr::null_mut()) }
            }

            pub fn input(&mut self, input: &[u8]) -> i32 {
                unsafe { ffi::$input(&mut self.raw, input.as_ptr(), input.len()) }
            }

            pub fn input_null_context(input: &[u8]) -> i32 {
                unsafe { ffi::$input(std::ptr::null_mut(), input.as_ptr(), input.len()) }
            }

            pub fn input_null_message(&mut self, len: usize) -> i32 {
                unsafe { ffi::$input(&mut self.raw, std::ptr::null(), len) }
            }

            pub fn input_zero_nulls() -> i32 {
                unsafe { ffi::$input(std::ptr::null_mut(), std::ptr::null(), 0) }
            }

            pub fn final_bits(&mut self, bits: u8, bitcount: usize) -> i32 {
                unsafe { ffi::$final_bits(&mut self.raw, bits, bitcount) }
            }

            pub fn final_bits_null(bits: u8, bitcount: usize) -> i32 {
                unsafe { ffi::$final_bits(std::ptr::null_mut(), bits, bitcount) }
            }

            pub fn result(&mut self) -> (i32, [u8; $out]) {
                let mut output = [0; $out];
                let code = unsafe { ffi::$result(&mut self.raw, output.as_mut_ptr()) };
                (code, output)
            }

            pub fn result_null_context() -> i32 {
                let mut output = [0; $out];
                unsafe { ffi::$result(std::ptr::null_mut(), output.as_mut_ptr()) }
            }

            pub fn result_null_output(&mut self) -> i32 {
                unsafe { ffi::$result(&mut self.raw, std::ptr::null_mut()) }
            }

            pub fn state(&self) -> Sha64State {
                Sha64State {
                    intermediate_hash: self.raw.Intermediate_Hash,
                    length_low: self.raw.Length_Low,
                    length_high: self.raw.Length_High,
                    message_block_index: self.raw.Message_Block_Index,
                    computed: self.raw.Computed,
                    corrupted: self.raw.Corrupted,
                }
            }

            pub fn set_computed(&mut self, computed: i32) {
                self.raw.Computed = computed;
            }

            pub fn set_corrupted(&mut self, corrupted: i32) {
                self.raw.Corrupted = corrupted;
            }
        }
    };
}

sha32_context!(
    Sha224Context,
    ffi::SHA224Context,
    SHA224Reset,
    SHA224Input,
    SHA224FinalBits,
    SHA224Result,
    28,
    8
);
sha32_context!(
    Sha256Context,
    ffi::SHA256Context,
    SHA256Reset,
    SHA256Input,
    SHA256FinalBits,
    SHA256Result,
    32,
    8
);
sha64_context!(
    Sha384Context,
    ffi::SHA384Context,
    SHA384Reset,
    SHA384Input,
    SHA384FinalBits,
    SHA384Result,
    48
);
sha64_context!(
    Sha512Context,
    ffi::SHA512Context,
    SHA512Reset,
    SHA512Input,
    SHA512FinalBits,
    SHA512Result,
    64
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShaErrorCodes {
    pub success: i32,
    pub null: i32,
    pub input_too_long: i32,
    pub state_error: i32,
    pub bad_param: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShaContextLayout {
    pub size: usize,
    pub align: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShaHeaderSurface {
    pub use_sha1_default: bool,
    pub use_sha224_default: bool,
    pub use_sha384_sha512_default: bool,
    pub sha1_declared: bool,
    pub sha224_declared: bool,
    pub sha256_declared: bool,
    pub sha384_declared: bool,
    pub sha512_declared: bool,
    pub usha_declared: bool,
    pub hmac_declared: bool,
}

pub const SHA1_HASH_SIZE: usize = 20;
pub const SHA224_HASH_SIZE: usize = 28;
pub const SHA256_HASH_SIZE: usize = 32;
pub const SHA384_HASH_SIZE: usize = 48;
pub const SHA512_HASH_SIZE: usize = 64;

pub const SHA1_ENABLED_BY_DEFAULT: bool = false;
pub const SHA224_ENABLED_BY_DEFAULT: bool = false;
pub const SHA384_SHA512_ENABLED_BY_DEFAULT: bool = true;

pub fn sha_error_codes() -> ShaErrorCodes {
    ShaErrorCodes {
        success: ffi::shaSuccess as i32,
        null: ffi::shaNull as i32,
        input_too_long: ffi::shaInputTooLong as i32,
        state_error: ffi::shaStateError as i32,
        bad_param: ffi::shaBadParam as i32,
    }
}

pub fn sha_header_surface() -> ShaHeaderSurface {
    ShaHeaderSurface {
        use_sha1_default: SHA1_ENABLED_BY_DEFAULT,
        use_sha224_default: SHA224_ENABLED_BY_DEFAULT,
        use_sha384_sha512_default: SHA384_SHA512_ENABLED_BY_DEFAULT,
        sha1_declared: false,
        sha224_declared: false,
        sha256_declared: true,
        sha384_declared: true,
        sha512_declared: true,
        usha_declared: true,
        hmac_declared: true,
    }
}

pub fn sha1_context_layout() -> ShaContextLayout {
    ShaContextLayout {
        size: std::mem::size_of::<ffi::SHA1Context>(),
        align: std::mem::align_of::<ffi::SHA1Context>(),
    }
}

pub fn sha256_context_layout() -> ShaContextLayout {
    ShaContextLayout {
        size: std::mem::size_of::<ffi::SHA256Context>(),
        align: std::mem::align_of::<ffi::SHA256Context>(),
    }
}

pub fn sha512_context_layout() -> ShaContextLayout {
    ShaContextLayout {
        size: std::mem::size_of::<ffi::SHA512Context>(),
        align: std::mem::align_of::<ffi::SHA512Context>(),
    }
}

pub fn sha224_context_matches_sha256() -> bool {
    std::mem::size_of::<ffi::SHA224Context>() == std::mem::size_of::<ffi::SHA256Context>()
        && std::mem::align_of::<ffi::SHA224Context>() == std::mem::align_of::<ffi::SHA256Context>()
}

pub fn sha384_context_matches_sha512() -> bool {
    std::mem::size_of::<ffi::SHA384Context>() == std::mem::size_of::<ffi::SHA512Context>()
        && std::mem::align_of::<ffi::SHA384Context>() == std::mem::align_of::<ffi::SHA512Context>()
}

pub fn usha_reset_to_sha256() -> i32 {
    let mut context = unsafe { std::mem::zeroed::<ffi::USHAContext>() };
    unsafe { ffi::USHAReset(&mut context, ffi::SHAversion_SHA256) }
}

pub fn usha_input_zero_length_after_reset() -> i32 {
    let mut context = unsafe { std::mem::zeroed::<ffi::USHAContext>() };
    unsafe {
        assert_success(ffi::USHAReset(&mut context, ffi::SHAversion_SHA256));
        ffi::USHAInput(&mut context, std::ptr::null(), 0)
    }
}

pub fn usha_final_bits_zero_length_after_reset() -> i32 {
    let mut context = unsafe { std::mem::zeroed::<ffi::USHAContext>() };
    unsafe {
        assert_success(ffi::USHAReset(&mut context, ffi::SHAversion_SHA256));
        ffi::USHAFinalBits(&mut context, 0, 0)
    }
}

pub fn usha_final_bits_after_reset(bits: u8, bitcount: usize) -> i32 {
    let mut context = unsafe { std::mem::zeroed::<ffi::USHAContext>() };
    unsafe {
        assert_success(ffi::USHAReset(&mut context, ffi::SHAversion_SHA256));
        ffi::USHAFinalBits(&mut context, bits, bitcount)
    }
}

pub fn usha_result_sha256_empty() -> ([u8; 32], i32) {
    let mut context = unsafe { std::mem::zeroed::<ffi::USHAContext>() };
    let mut output = [0; 64];
    let code = unsafe {
        assert_success(ffi::USHAReset(&mut context, ffi::SHAversion_SHA256));
        ffi::USHAResult(&mut context, output.as_mut_ptr())
    };
    (output[..32].try_into().unwrap(), code)
}

pub fn usha_block_size_sha256() -> i32 {
    unsafe { ffi::USHABlockSize(ffi::SHAversion_SHA256) }
}

pub fn usha_hash_size_sha256() -> i32 {
    unsafe { ffi::USHAHashSize(ffi::SHAversion_SHA256) }
}

pub fn usha_hash_size_bits_sha256() -> i32 {
    unsafe { ffi::USHAHashSizeBits(ffi::SHAversion_SHA256) }
}

pub fn hmac_streaming_sha256(text: &[u8], key: &[u8]) -> ([u8; 32], i32) {
    let mut context = unsafe { std::mem::zeroed::<ffi::HMACContext>() };
    let mut output = [0; 64];
    let code = unsafe {
        assert_success(ffi::hmacReset(
            &mut context,
            ffi::SHAversion_SHA256,
            key.as_ptr(),
            key.len(),
        ));
        assert_success(ffi::hmacInput(&mut context, text.as_ptr(), text.len()));
        ffi::hmacResult(&mut context, output.as_mut_ptr())
    };
    (output[..32].try_into().unwrap(), code)
}

pub fn hmac_final_bits_zero_length_after_reset(key: &[u8]) -> i32 {
    let mut context = unsafe { std::mem::zeroed::<ffi::HMACContext>() };
    unsafe {
        assert_success(ffi::hmacReset(
            &mut context,
            ffi::SHAversion_SHA256,
            key.as_ptr(),
            key.len(),
        ));
        ffi::hmacFinalBits(&mut context, 0, 0)
    }
}

pub fn hmac_context_layout() -> ShaContextLayout {
    ShaContextLayout {
        size: std::mem::size_of::<ffi::HMACContext>(),
        align: std::mem::align_of::<ffi::HMACContext>(),
    }
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut context = unsafe { std::mem::zeroed::<ffi::SHA256Context>() };
    let mut output = [0; 32];

    unsafe {
        assert_success(ffi::SHA256Reset(&mut context));
        assert_success(ffi::SHA256Input(&mut context, input.as_ptr(), input.len()));
        assert_success(ffi::SHA256Result(&mut context, output.as_mut_ptr()));
    }

    output
}

pub fn sha1(input: &[u8]) -> [u8; 20] {
    let mut context = unsafe { std::mem::zeroed::<ffi::SHA1Context>() };
    let mut output = [0; 20];

    unsafe {
        assert_success(ffi::SHA1Reset(&mut context));
        assert_success(ffi::SHA1Input(&mut context, input.as_ptr(), input.len()));
        assert_success(ffi::SHA1Result(&mut context, output.as_mut_ptr()));
    }

    output
}

pub fn sha224(input: &[u8]) -> [u8; 28] {
    let mut context = unsafe { std::mem::zeroed::<ffi::SHA224Context>() };
    let mut output = [0; 28];

    unsafe {
        assert_success(ffi::SHA224Reset(&mut context));
        assert_success(ffi::SHA224Input(&mut context, input.as_ptr(), input.len()));
        assert_success(ffi::SHA224Result(&mut context, output.as_mut_ptr()));
    }

    output
}

pub fn sha384(input: &[u8]) -> [u8; 48] {
    let mut context = unsafe { std::mem::zeroed::<ffi::SHA384Context>() };
    let mut output = [0; 48];

    unsafe {
        assert_success(ffi::SHA384Reset(&mut context));
        assert_success(ffi::SHA384Input(&mut context, input.as_ptr(), input.len()));
        assert_success(ffi::SHA384Result(&mut context, output.as_mut_ptr()));
    }

    output
}

pub fn sha512(input: &[u8]) -> [u8; 64] {
    let mut context = unsafe { std::mem::zeroed::<ffi::SHA512Context>() };
    let mut output = [0; 64];

    unsafe {
        assert_success(ffi::SHA512Reset(&mut context));
        assert_success(ffi::SHA512Input(&mut context, input.as_ptr(), input.len()));
        assert_success(ffi::SHA512Result(&mut context, output.as_mut_ptr()));
    }

    output
}

pub fn sha1_final_bits_zero_length_after_reset() -> i32 {
    let mut context = unsafe { std::mem::zeroed::<ffi::SHA1Context>() };
    unsafe {
        assert_success(ffi::SHA1Reset(&mut context));
        ffi::SHA1FinalBits(&mut context, 0, 0)
    }
}

pub fn sha224_final_bits_zero_length_after_reset() -> i32 {
    let mut context = unsafe { std::mem::zeroed::<ffi::SHA224Context>() };
    unsafe {
        assert_success(ffi::SHA224Reset(&mut context));
        ffi::SHA224FinalBits(&mut context, 0, 0)
    }
}

pub fn sha256_final_bits_zero_length_after_reset() -> i32 {
    let mut context = unsafe { std::mem::zeroed::<ffi::SHA256Context>() };
    unsafe {
        assert_success(ffi::SHA256Reset(&mut context));
        ffi::SHA256FinalBits(&mut context, 0, 0)
    }
}

pub fn sha384_final_bits_zero_length_after_reset() -> i32 {
    let mut context = unsafe { std::mem::zeroed::<ffi::SHA384Context>() };
    unsafe {
        assert_success(ffi::SHA384Reset(&mut context));
        ffi::SHA384FinalBits(&mut context, 0, 0)
    }
}

pub fn sha512_final_bits_zero_length_after_reset() -> i32 {
    let mut context = unsafe { std::mem::zeroed::<ffi::SHA512Context>() };
    unsafe {
        assert_success(ffi::SHA512Reset(&mut context));
        ffi::SHA512FinalBits(&mut context, 0, 0)
    }
}

pub fn hmac_sha256(text: &[u8], key: &[u8]) -> [u8; 32] {
    let mut output = [0; 64];

    unsafe {
        assert_success(ffi::hmac(
            ffi::SHAversion_SHA256,
            text.as_ptr(),
            text.len(),
            key.as_ptr(),
            key.len(),
            output.as_mut_ptr(),
        ));
    }

    output[..32].try_into().unwrap()
}

pub fn sha_choice_default(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

pub fn sha_choice_modified(x: u32, y: u32, z: u32) -> u32 {
    (x & (y ^ z)) ^ z
}

pub fn sha_majority_default(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

pub fn sha_majority_modified(x: u32, y: u32, z: u32) -> u32 {
    (x & (y | z)) | (y & z)
}

pub fn sha_parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}
