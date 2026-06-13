mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub fn be16_to_host(value: u16) -> u16 {
    unsafe { ffi::portable_endian_ffi_be16toh(value) }
}

pub fn host_to_be16(value: u16) -> u16 {
    unsafe { ffi::portable_endian_ffi_htobe16(value) }
}

pub fn host_to_le16(value: u16) -> u16 {
    unsafe { ffi::portable_endian_ffi_htole16(value) }
}

pub fn le16_to_host(value: u16) -> u16 {
    unsafe { ffi::portable_endian_ffi_le16toh(value) }
}

pub fn be32_to_host(value: u32) -> u32 {
    unsafe { ffi::portable_endian_ffi_be32toh(value) }
}

pub fn host_to_be32(value: u32) -> u32 {
    unsafe { ffi::portable_endian_ffi_htobe32(value) }
}

pub fn host_to_le32(value: u32) -> u32 {
    unsafe { ffi::portable_endian_ffi_htole32(value) }
}

pub fn le32_to_host(value: u32) -> u32 {
    unsafe { ffi::portable_endian_ffi_le32toh(value) }
}

pub fn be64_to_host(value: u64) -> u64 {
    unsafe { ffi::portable_endian_ffi_be64toh(value) }
}

pub fn host_to_be64(value: u64) -> u64 {
    unsafe { ffi::portable_endian_ffi_htobe64(value) }
}

pub fn host_to_le64(value: u64) -> u64 {
    unsafe { ffi::portable_endian_ffi_htole64(value) }
}

pub fn le64_to_host(value: u64) -> u64 {
    unsafe { ffi::portable_endian_ffi_le64toh(value) }
}
