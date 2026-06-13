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
pub enum RecvState {
    Spl,
    Header,
    Fixed,
    Variable,
    Pad,
    Transform,
    Unknown,
}

impl RecvState {
    fn as_ffi(self) -> ffi::libsmb2_private_ffi_recv_state_t {
        match self {
            Self::Spl => ffi::libsmb2_private_ffi_recv_state_t_LIBSMB2_PRIVATE_FFI_RECV_SPL,
            Self::Header => ffi::libsmb2_private_ffi_recv_state_t_LIBSMB2_PRIVATE_FFI_RECV_HEADER,
            Self::Fixed => ffi::libsmb2_private_ffi_recv_state_t_LIBSMB2_PRIVATE_FFI_RECV_FIXED,
            Self::Variable => {
                ffi::libsmb2_private_ffi_recv_state_t_LIBSMB2_PRIVATE_FFI_RECV_VARIABLE
            }
            Self::Pad => ffi::libsmb2_private_ffi_recv_state_t_LIBSMB2_PRIVATE_FFI_RECV_PAD,
            Self::Transform => ffi::libsmb2_private_ffi_recv_state_t_LIBSMB2_PRIVATE_FFI_RECV_TRFM,
            Self::Unknown => ffi::libsmb2_private_ffi_recv_state_t_LIBSMB2_PRIVATE_FFI_RECV_UNKNOWN,
        }
    }

    pub fn value(self) -> Option<i32> {
        let mut out = 0;
        let status = unsafe { ffi::libsmb2_private_ffi_recv_state_value(self.as_ffi(), &mut out) };
        (status == 0).then_some(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateConstants {
    pub max_error_size: u32,
    pub spl_size: u32,
    pub header_size: u32,
    pub signature_size: u32,
    pub key_size: u32,
    pub max_vectors: u32,
    pub max_tree_nesting: u32,
    pub max_credits: u32,
    pub salt_size: u32,
    pub max_pdu_size: u32,
    pub preauth_hash_size: u32,
}

pub fn private_constants() -> PrivateConstants {
    PrivateConstants {
        max_error_size: unsafe { ffi::libsmb2_private_ffi_max_error_size() },
        spl_size: unsafe { ffi::libsmb2_private_ffi_spl_size() },
        header_size: unsafe { ffi::libsmb2_private_ffi_header_size() },
        signature_size: unsafe { ffi::libsmb2_private_ffi_signature_size() },
        key_size: unsafe { ffi::libsmb2_private_ffi_key_size() },
        max_vectors: unsafe { ffi::libsmb2_private_ffi_max_vectors() },
        max_tree_nesting: unsafe { ffi::libsmb2_private_ffi_max_tree_nesting() },
        max_credits: unsafe { ffi::libsmb2_private_ffi_max_credits() },
        salt_size: unsafe { ffi::libsmb2_private_ffi_salt_size() },
        max_pdu_size: unsafe { ffi::libsmb2_private_ffi_max_pdu_size() },
        preauth_hash_size: unsafe { ffi::libsmb2_private_ffi_preauth_hash_size() },
    }
}

pub fn pad_to_32bit(len: u32) -> u32 {
    unsafe { ffi::libsmb2_private_ffi_pad_to_32bit(len) }
}

pub fn pad_to_64bit(len: u32) -> u32 {
    unsafe { ffi::libsmb2_private_ffi_pad_to_64bit(len) }
}

pub fn sizeof_smb2_header() -> usize {
    unsafe { ffi::libsmb2_private_ffi_sizeof_smb2_header() }
}

pub fn sizeof_smb2_io_vectors() -> usize {
    unsafe { ffi::libsmb2_private_ffi_sizeof_smb2_io_vectors() }
}

pub fn sizeof_smb2_context() -> usize {
    unsafe { ffi::libsmb2_private_ffi_sizeof_smb2_context() }
}

pub fn sizeof_smb2_pdu() -> usize {
    unsafe { ffi::libsmb2_private_ffi_sizeof_smb2_pdu() }
}

pub fn sizeof_smb2dir() -> usize {
    unsafe { ffi::libsmb2_private_ffi_sizeof_smb2dir() }
}
