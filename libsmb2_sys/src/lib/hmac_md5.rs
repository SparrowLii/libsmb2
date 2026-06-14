mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub const HMAC_MD5_UWORD32_DEFINED: bool = true;
pub const HMAC_MD5_UWORD32_BITS: u32 = u32::BITS;
pub const HMAC_MD5_WORDS_BIGENDIAN_VALUE: i32 = 1;

pub fn hmac_md5_words_bigendian_defined(
    byte_order_big_endian: bool,
    xbox_360_platform: bool,
) -> bool {
    byte_order_big_endian || xbox_360_platform
}

pub fn digest(text: &[u8], key: &[u8]) -> [u8; 16] {
    let mut output = [0; 16];
    let text_len = i32::try_from(text.len()).expect("HMAC-MD5 text length exceeds int range");
    let key_len = u32::try_from(key.len()).expect("HMAC-MD5 key length exceeds unsigned int range");

    unsafe {
        ffi::smb2_hmac_md5(
            text.as_ptr().cast_mut(),
            text_len,
            key.as_ptr().cast_mut(),
            key_len,
            output.as_mut_ptr(),
        )
    };

    output
}
