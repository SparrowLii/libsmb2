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

pub fn reference_encrypt_block(input: AesBlock, key: AesBlock) -> AesBlock {
    let mut input = input.0;
    let key = key.0;
    let mut output = [0; 16];

    unsafe {
        ffi::AES128_ECB_encrypt_reference(input.as_mut_ptr(), key.as_ptr(), output.as_mut_ptr())
    };

    AesBlock(output)
}

pub fn reference_decrypt_block(input: AesBlock, key: AesBlock) -> AesBlock {
    let mut input = input.0;
    let key = key.0;
    let mut output = [0; 16];

    unsafe {
        ffi::AES128_ECB_decrypt_reference(input.as_mut_ptr(), key.as_ptr(), output.as_mut_ptr())
    };

    AesBlock(output)
}

pub fn reference_cbc_encrypt(input: &[u8], key: AesBlock, iv: AesBlock) -> Vec<u8> {
    let mut input = input.to_vec();
    let key = key.0;
    let mut iv = iv.0;
    let mut output = vec![0; cbc_output_len(input.len())];

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

pub fn reference_cbc_decrypt(input: &[u8], key: AesBlock, iv: AesBlock) -> Vec<u8> {
    let mut input = input.to_vec();
    let key = key.0;
    let mut iv = iv.0;
    let mut output = vec![0; cbc_output_len(input.len())];

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

fn cbc_output_len(input_len: usize) -> usize {
    let remainder = input_len % 16;
    if remainder == 0 {
        input_len
    } else {
        input_len + (16 - remainder)
    }
}
