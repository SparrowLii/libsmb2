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
#[repr(u32)]
pub enum BerType {
    Integer = ffi::ber_type_t_BER_INTEGER,
    OctetString = ffi::ber_type_t_BER_OCTET_STRING,
    Null = ffi::ber_type_t_BER_NULL,
    ObjectId = ffi::ber_type_t_BER_OBJECT_ID,
    Counter = ffi::ber_type_t_BER_COUNTER,
    Unsigned = ffi::ber_type_t_BER_UNSIGNED,
    Counter64 = ffi::ber_type_t_BER_COUNTER64,
    Integer64 = ffi::ber_type_t_BER_INTEGER64,
    Unsigned64 = ffi::ber_type_t_BER_UNSIGNED64,
    Struct = 0x30,
}

impl BerType {
    fn raw(self) -> ffi::ber_type_t {
        self as ffi::ber_type_t
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidValue {
    pub elements: Vec<u32>,
}

pub struct Decoder {
    src: Vec<u8>,
    ctx: ffi::asn1ber_context,
}

impl Decoder {
    pub fn new(src: &[u8]) -> Self {
        let mut src = src.to_vec();
        let ctx = ffi::asn1ber_context {
            src: src.as_mut_ptr(),
            src_count: src.len() as i32,
            src_tail: 0,
            dst: std::ptr::null_mut(),
            dst_size: 0,
            dst_head: 0,
            last_error: 0,
        };
        Self { src, ctx }
    }

    fn refresh(&mut self) {
        self.ctx.src = self.src.as_mut_ptr();
    }

    pub fn last_error(&self) -> i32 {
        self.ctx.last_error
    }

    pub fn decode_length(&mut self) -> Result<u32, i32> {
        self.refresh();
        let mut len = 0;
        let status = unsafe { ffi::asn1ber_length_from_ber(&mut self.ctx, &mut len) };
        self.status_with_value(status, len)
    }

    pub fn decode_typecode(&mut self) -> Result<u32, i32> {
        self.refresh();
        let mut ty = 0;
        let status = unsafe { ffi::ber_typecode_from_ber(&mut self.ctx, &mut ty) };
        self.status_with_value(status, ty as u32)
    }

    pub fn decode_typelen(&mut self) -> Result<(u32, u32), i32> {
        self.refresh();
        let mut ty = 0;
        let mut len = 0;
        let status = unsafe { ffi::ber_typelen_from_ber(&mut self.ctx, &mut ty, &mut len) };
        self.status(status).map(|()| (ty as u32, len))
    }

    pub fn decode_request(&mut self) -> Result<(u32, u32), i32> {
        self.refresh();
        let mut ty = 0;
        let mut len = 0;
        let status = unsafe { ffi::asn1ber_request_from_ber(&mut self.ctx, &mut ty, &mut len) };
        self.status(status).map(|()| (ty as u32, len))
    }

    pub fn decode_struct_len(&mut self) -> Result<u32, i32> {
        self.refresh();
        let mut len = 0;
        let status = unsafe { ffi::asn1ber_struct_from_ber(&mut self.ctx, &mut len) };
        self.status_with_value(status, len)
    }

    pub fn decode_null_len(&mut self) -> Result<u32, i32> {
        self.refresh();
        let mut len = 0;
        let status = unsafe { ffi::asn1ber_null_from_ber(&mut self.ctx, &mut len) };
        self.status_with_value(status, len)
    }

    pub fn decode_int32(&mut self) -> Result<i32, i32> {
        self.refresh();
        let mut val = 0;
        let status = unsafe { ffi::asn1ber_int32_from_ber(&mut self.ctx, &mut val) };
        self.status_with_value(status, val)
    }

    pub fn decode_uint32(&mut self) -> Result<u32, i32> {
        self.refresh();
        let mut val = 0;
        let status = unsafe { ffi::asn1ber_uint32_from_ber(&mut self.ctx, &mut val) };
        self.status_with_value(status, val)
    }

    pub fn decode_int64(&mut self) -> Result<i64, i32> {
        self.refresh();
        let mut val = 0;
        let status = unsafe { ffi::asn1ber_int64_from_ber(&mut self.ctx, &mut val) };
        self.status_with_value(status, val)
    }

    pub fn decode_uint64(&mut self) -> Result<u64, i32> {
        self.refresh();
        let mut val = 0;
        let status = unsafe { ffi::asn1ber_uint64_from_ber(&mut self.ctx, &mut val) };
        self.status_with_value(status, val)
    }

    pub fn decode_oid(&mut self) -> Result<OidValue, i32> {
        self.refresh();
        let mut oid = ffi::asn1ber_oid_value {
            length: 0,
            elements: [0; 32],
        };
        let status = unsafe { ffi::asn1ber_oid_from_ber(&mut self.ctx, &mut oid) };
        self.status(status)?;
        Ok(OidValue {
            elements: oid.elements[..oid.length as usize].to_vec(),
        })
    }

    pub fn decode_bytes(&mut self, max_len: usize) -> Result<(Vec<u8>, u32), i32> {
        self.refresh();
        let mut val = vec![0; max_len];
        let mut len = 0;
        let status = unsafe {
            ffi::asn1ber_bytes_from_ber(&mut self.ctx, val.as_mut_ptr(), max_len as u32, &mut len)
        };
        self.status(status)?;
        Ok((val, len))
    }

    pub fn decode_string(&mut self, max_len: usize) -> Result<(String, u32), i32> {
        self.refresh();
        let mut val = vec![0_u8; max_len];
        let mut len = 0;
        let status = unsafe {
            ffi::asn1ber_string_from_ber(
                &mut self.ctx,
                val.as_mut_ptr().cast::<i8>(),
                max_len as u32,
                &mut len,
            )
        };
        self.status(status)?;
        Ok((
            String::from_utf8_lossy(&val[..len as usize]).into_owned(),
            len,
        ))
    }

    fn status(&self, status: i32) -> Result<(), i32> {
        if status == 0 {
            Ok(())
        } else {
            Err(self.ctx.last_error)
        }
    }

    fn status_with_value<T>(&self, status: i32, value: T) -> Result<T, i32> {
        self.status(status).map(|()| value)
    }
}

pub struct Encoder {
    dst: Vec<u8>,
    ctx: ffi::asn1ber_context,
}

impl Encoder {
    pub fn with_capacity(capacity: usize) -> Self {
        let mut dst = vec![0; capacity];
        let ctx = ffi::asn1ber_context {
            src: std::ptr::null_mut(),
            src_count: 0,
            src_tail: 0,
            dst: dst.as_mut_ptr(),
            dst_size: dst.len() as i32,
            dst_head: 0,
            last_error: 0,
        };
        Self { dst, ctx }
    }

    fn refresh(&mut self) {
        self.ctx.dst = self.dst.as_mut_ptr();
        self.ctx.dst_size = self.dst.len() as i32;
    }

    pub fn bytes(&self) -> &[u8] {
        &self.dst[..self.ctx.dst_head as usize]
    }

    pub fn last_error(&self) -> i32 {
        self.ctx.last_error
    }

    pub fn save_out_state(&mut self) -> Result<i32, i32> {
        self.refresh();
        let mut out_pos = 0;
        let status = unsafe { ffi::asn1ber_save_out_state(&mut self.ctx, &mut out_pos) };
        self.status_with_value(status, out_pos)
    }

    pub fn reserve_length(&mut self, len: u32) -> Result<(), i32> {
        self.refresh();
        let status = unsafe { ffi::asn1ber_ber_reserve_length(&mut self.ctx, len) };
        self.status(status)
    }

    pub fn annotate_length(&mut self, out_pos: i32, reserved: i32) -> Result<(), i32> {
        self.refresh();
        let status = unsafe { ffi::asn1ber_annotate_length(&mut self.ctx, out_pos, reserved) };
        self.status(status)
    }

    pub fn encode_length(&mut self, len: u32) -> Result<u32, i32> {
        self.refresh();
        let mut lenout = 0;
        let status = unsafe { ffi::asn1ber_ber_from_length(&mut self.ctx, len, &mut lenout) };
        self.status_with_value(status, lenout)
    }

    pub fn encode_typecode(&mut self, ty: BerType) -> Result<(), i32> {
        self.refresh();
        let status = unsafe { ffi::asn1ber_ber_from_typecode(&mut self.ctx, ty.raw()) };
        self.status(status)
    }

    pub fn encode_typelen(&mut self, ty: BerType, len: u32) -> Result<u32, i32> {
        self.refresh();
        let mut lenout = 0;
        let status =
            unsafe { ffi::asn1ber_ber_from_typelen(&mut self.ctx, ty.raw(), len, &mut lenout) };
        self.status_with_value(status, lenout)
    }

    pub fn encode_int32(&mut self, ty: BerType, val: i32) -> Result<(), i32> {
        self.refresh();
        let status = unsafe { ffi::asn1ber_ber_from_int32(&mut self.ctx, ty.raw(), val) };
        self.status(status)
    }

    pub fn encode_uint32(&mut self, ty: BerType, val: u32) -> Result<(), i32> {
        self.refresh();
        let status = unsafe { ffi::asn1ber_ber_from_uint32(&mut self.ctx, ty.raw(), val) };
        self.status(status)
    }

    pub fn encode_int64(&mut self, ty: BerType, val: i64) -> Result<(), i32> {
        self.refresh();
        let status = unsafe { ffi::asn1ber_ber_from_int64(&mut self.ctx, ty.raw(), val) };
        self.status(status)
    }

    pub fn encode_uint64(&mut self, ty: BerType, val: u64) -> Result<(), i32> {
        self.refresh();
        let status = unsafe { ffi::asn1ber_ber_from_uint64(&mut self.ctx, ty.raw(), val) };
        self.status(status)
    }

    pub fn encode_oid(&mut self, oid: &OidValue) -> Result<(), i32> {
        self.refresh();
        let mut raw = ffi::asn1ber_oid_value {
            length: oid.elements.len() as i32,
            elements: [0; 32],
        };
        raw.elements[..oid.elements.len()].copy_from_slice(&oid.elements);
        let status = unsafe { ffi::asn1ber_ber_from_oid(&mut self.ctx, &raw) };
        self.status(status)
    }

    pub fn encode_bytes(&mut self, ty: BerType, val: &[u8]) -> Result<(), i32> {
        self.refresh();
        let status = unsafe {
            ffi::asn1ber_ber_from_bytes(&mut self.ctx, ty.raw(), val.as_ptr(), val.len() as u32)
        };
        self.status(status)
    }

    pub fn encode_string(&mut self, val: &str) -> Result<(), i32> {
        self.refresh();
        let status = unsafe {
            ffi::asn1ber_ber_from_string(&mut self.ctx, val.as_ptr().cast::<i8>(), val.len() as u32)
        };
        self.status(status)
    }

    fn status(&self, status: i32) -> Result<(), i32> {
        if status == 0 {
            Ok(())
        } else {
            Err(self.ctx.last_error)
        }
    }

    fn status_with_value<T>(&self, status: i32, value: T) -> Result<T, i32> {
        self.status(status).map(|()| value)
    }
}
