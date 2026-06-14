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
    pub state: [u32; 4],
    pub count: [u32; 2],
    pub buffer: [u8; 64],
}

impl ContextSnapshot {
    fn from_context(context: &ffi::MD4_CTX) -> Self {
        Self {
            state: context.state,
            count: context.count,
            buffer: context.buffer,
        }
    }

    pub fn is_zeroed(&self) -> bool {
        self.state == [0; 4] && self.count == [0; 2] && self.buffer == [0; 64]
    }
}

pub fn context_layout() -> (usize, usize, usize) {
    (4, 2, 64)
}

pub fn initial_context() -> ContextSnapshot {
    let mut context = unsafe { std::mem::zeroed::<ffi::MD4_CTX>() };

    unsafe {
        ffi::MD4Init(&mut context);
    }

    ContextSnapshot::from_context(&context)
}

pub fn snapshot_after_update(input: &[u8]) -> ContextSnapshot {
    let mut context = unsafe { std::mem::zeroed::<ffi::MD4_CTX>() };
    let mut data = input.to_vec();
    let len = u32::try_from(data.len()).expect("MD4 input length exceeds unsigned int range");

    unsafe {
        ffi::MD4Init(&mut context);
        ffi::MD4Update(&mut context, data.as_mut_ptr(), len);
    }

    ContextSnapshot::from_context(&context)
}

pub fn digest_with_final_context(input: &[u8]) -> ([u8; 16], ContextSnapshot) {
    let mut context = unsafe { std::mem::zeroed::<ffi::MD4_CTX>() };
    let mut data = input.to_vec();
    let len = u32::try_from(data.len()).expect("MD4 input length exceeds unsigned int range");
    let mut output = [0; 16];

    unsafe {
        ffi::MD4Init(&mut context);
        ffi::MD4Update(&mut context, data.as_mut_ptr(), len);
        ffi::MD4Final(output.as_mut_ptr(), &mut context);
    }

    (output, ContextSnapshot::from_context(&context))
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
