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

pub fn default_cbc_value() -> i32 {
    unsafe { ffi::aes_reference_ffi_default_cbc_value() }
}

pub fn default_cbc_declarations_enabled() -> bool {
    unsafe { ffi::aes_reference_ffi_default_cbc_declarations_enabled() != 0 }
}

pub fn external_ecb_value_when_disabled() -> i32 {
    unsafe { ffi::aes_reference_ffi_external_ecb_value() }
}

pub fn external_ecb_declarations_enabled_when_disabled() -> bool {
    unsafe { ffi::aes_reference_ffi_external_ecb_declarations_enabled() != 0 }
}

pub fn ecb_encrypt_block(input: AesBlock, key: AesBlock) -> AesBlock {
    let mut input = input.0;
    let key = key.0;
    let mut output = [0; 16];
    unsafe {
        ffi::AES128_ECB_encrypt_reference(input.as_mut_ptr(), key.as_ptr(), output.as_mut_ptr())
    };
    AesBlock(output)
}

pub fn ecb_decrypt_block(input: AesBlock, key: AesBlock) -> AesBlock {
    let mut input = input.0;
    let key = key.0;
    let mut output = [0; 16];
    unsafe {
        ffi::AES128_ECB_decrypt_reference(input.as_mut_ptr(), key.as_ptr(), output.as_mut_ptr())
    };
    AesBlock(output)
}

pub fn cbc_encrypt(input: &[u8], key: AesBlock, iv: AesBlock) -> Vec<u8> {
    let output_len = input.len().next_multiple_of(16);
    let mut input = input.to_vec();
    input.resize(output_len, 0);
    let mut output = vec![0; output_len];
    let key = key.0;
    let mut iv = iv.0;
    unsafe {
        ffi::AES128_CBC_encrypt_buffer_reference(
            output.as_mut_ptr(),
            input.as_mut_ptr(),
            input.len() as u32,
            key.as_ptr(),
            iv.as_mut_ptr(),
        )
    };
    output
}

pub fn cbc_decrypt(input: &[u8], key: AesBlock, iv: AesBlock) -> Vec<u8> {
    let output_len = input.len().next_multiple_of(16);
    let mut input = input.to_vec();
    input.resize(output_len, 0);
    let mut output = vec![0; output_len];
    let key = key.0;
    let mut iv = iv.0;
    unsafe {
        ffi::AES128_CBC_decrypt_buffer_reference(
            output.as_mut_ptr(),
            input.as_mut_ptr(),
            input.len() as u32,
            key.as_ptr(),
            iv.as_mut_ptr(),
        )
    };
    output
}
