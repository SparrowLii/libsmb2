mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesBlock(pub [u8; 16]);

pub fn encrypt_block(input: AesBlock, key: AesBlock) -> AesBlock {
    let mut input = input.0;
    let key = key.0;
    let mut output = [0; 16];

    unsafe { ffi::AES128_ECB_encrypt(input.as_mut_ptr(), key.as_ptr(), output.as_mut_ptr()) };

    AesBlock(output)
}
