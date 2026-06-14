mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextSnapshot {
    pub buf: [u32; 4],
    pub bytes: [u32; 2],
    pub input: [u32; 16],
}

impl ContextSnapshot {
    fn from_context(context: &ffi::MD5Context) -> Self {
        Self {
            buf: context.buf,
            bytes: context.bytes,
            input: context.in_,
        }
    }

    pub fn buffered_bytes(&self) -> Vec<u8> {
        let len = (self.bytes[0] & 0x3f) as usize;
        let mut bytes = Vec::with_capacity(64);
        for word in self.input {
            bytes.extend_from_slice(&word.to_ne_bytes());
        }
        bytes.truncate(len);
        bytes
    }

    pub fn is_zeroed(&self) -> bool {
        self.buf == [0; 4] && self.bytes == [0; 2] && self.input == [0; 16]
    }
}

pub fn words_bigendian_enabled() -> bool {
    cfg!(target_endian = "big")
}

pub fn context_layout() -> (usize, usize, usize) {
    (4, 2, 16)
}

pub fn initial_context() -> ContextSnapshot {
    let mut context = unsafe { std::mem::zeroed::<ffi::MD5Context>() };

    unsafe {
        ffi::MD5Init(&mut context);
    }

    ContextSnapshot::from_context(&context)
}

pub fn snapshot_after_update(input: &[u8]) -> ContextSnapshot {
    let mut context = unsafe { std::mem::zeroed::<ffi::MD5Context>() };
    let len = u32::try_from(input.len()).expect("MD5 input length exceeds unsigned int range");

    unsafe {
        ffi::MD5Init(&mut context);
        ffi::MD5Update(&mut context, input.as_ptr(), len);
    }

    ContextSnapshot::from_context(&context)
}

pub fn digest_with_final_context(input: &[u8]) -> ([u8; 16], ContextSnapshot) {
    let mut context = unsafe { std::mem::zeroed::<ffi::MD5Context>() };
    let len = u32::try_from(input.len()).expect("MD5 input length exceeds unsigned int range");
    let mut output = [0; 16];

    unsafe {
        ffi::MD5Init(&mut context);
        ffi::MD5Update(&mut context, input.as_ptr(), len);
        ffi::MD5Final(output.as_mut_ptr(), &mut context);
    }

    (output, ContextSnapshot::from_context(&context))
}

pub fn transform(mut state: [u32; 4], block: [u32; 16]) -> [u32; 4] {
    unsafe {
        ffi::MD5Transform(state.as_mut_ptr(), block.as_ptr());
    }

    state
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
