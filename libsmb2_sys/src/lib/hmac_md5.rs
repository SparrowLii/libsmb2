mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
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
