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
    let mut context = unsafe { std::mem::zeroed::<ffi::MD4_CTX>() };
    let mut data = input.to_vec();
    let len = u32::try_from(data.len()).expect("MD4 input length exceeds unsigned int range");
    let mut output = [0; 16];

    unsafe {
        ffi::MD4Init(&mut context);
        ffi::MD4Update(&mut context, data.as_mut_ptr(), len);
        ffi::MD4Final(output.as_mut_ptr(), &mut context);
    }

    output
}
