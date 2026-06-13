mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub fn digest(input: &[u8]) -> [u8; 16] {
    let mut context = unsafe { std::mem::zeroed::<ffi::MD5Context>() };
    let len = u32::try_from(input.len()).expect("MD5 input length exceeds unsigned int range");
    let mut output = [0; 16];

    unsafe {
        ffi::MD5Init(&mut context);
        ffi::MD5Update(&mut context, input.as_ptr(), len);
        ffi::MD5Final(output.as_mut_ptr(), &mut context);
    }

    output
}
