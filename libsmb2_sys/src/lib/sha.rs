mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

fn assert_success(code: i32) {
    assert_eq!(code, ffi::shaSuccess as i32);
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
