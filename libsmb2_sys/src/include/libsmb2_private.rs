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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextLayout {
    pub error_string_len: usize,
    pub header_len: usize,
    pub tree_id_len: usize,
    pub signing_key_len: usize,
    pub serverin_key_len: usize,
    pub serverout_key_len: usize,
    pub salt_len: usize,
    pub has_connect_cb_data: bool,
    pub has_io_vectors: bool,
    pub has_owning_server: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PduLayout {
    pub hdr_len: usize,
    pub has_header: bool,
    pub has_out_vectors: bool,
    pub has_in_vectors: bool,
    pub has_payload: bool,
    pub has_free_payload: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoVectorsLayout {
    pub iov_len: usize,
    pub has_num_done: bool,
    pub has_total_size: bool,
    pub has_niov: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderLayout {
    pub protocol_id_len: usize,
    pub signature_len: usize,
    pub has_async_id: bool,
    pub has_process_id: bool,
    pub has_tree_id: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncCallbackDataLayout {
    pub has_is_finished: bool,
    pub has_status: bool,
    pub has_ptr: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryLayout {
    pub has_internal_next: bool,
    pub has_internal_dirent: bool,
    pub has_entries: bool,
    pub has_current_entry: bool,
    pub has_index: bool,
}

fn ffi_size_to_bool(value: usize) -> bool {
    value != 0
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

pub fn min_i32(a: i32, b: i32) -> i32 {
    unsafe { ffi::libsmb2_private_ffi_min_i32(a, b) }
}

pub fn discard_const_addr<T>(ptr: *const T) -> usize {
    unsafe { ffi::libsmb2_private_ffi_discard_const_ptr(ptr.cast()) as usize }
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

pub fn context_layout() -> ContextLayout {
    let layout = unsafe { ffi::libsmb2_private_ffi_context_layout() };
    ContextLayout {
        error_string_len: layout.error_string_len,
        header_len: layout.header_len,
        tree_id_len: layout.tree_id_len,
        signing_key_len: layout.signing_key_len,
        serverin_key_len: layout.serverin_key_len,
        serverout_key_len: layout.serverout_key_len,
        salt_len: layout.salt_len,
        has_connect_cb_data: ffi_size_to_bool(layout.has_connect_cb_data),
        has_io_vectors: ffi_size_to_bool(layout.has_io_vectors),
        has_owning_server: ffi_size_to_bool(layout.has_owning_server),
    }
}

pub fn pdu_layout() -> PduLayout {
    let layout = unsafe { ffi::libsmb2_private_ffi_pdu_layout() };
    PduLayout {
        hdr_len: layout.hdr_len,
        has_header: ffi_size_to_bool(layout.has_header),
        has_out_vectors: ffi_size_to_bool(layout.has_out_vectors),
        has_in_vectors: ffi_size_to_bool(layout.has_in_vectors),
        has_payload: ffi_size_to_bool(layout.has_payload),
        has_free_payload: ffi_size_to_bool(layout.has_free_payload),
    }
}

pub fn io_vectors_layout() -> IoVectorsLayout {
    let layout = unsafe { ffi::libsmb2_private_ffi_io_vectors_layout() };
    IoVectorsLayout {
        iov_len: layout.iov_len,
        has_num_done: ffi_size_to_bool(layout.has_num_done),
        has_total_size: ffi_size_to_bool(layout.has_total_size),
        has_niov: ffi_size_to_bool(layout.has_niov),
    }
}

pub fn header_layout() -> HeaderLayout {
    let layout = unsafe { ffi::libsmb2_private_ffi_header_layout() };
    HeaderLayout {
        protocol_id_len: layout.protocol_id_len,
        signature_len: layout.signature_len,
        has_async_id: ffi_size_to_bool(layout.has_async_id),
        has_process_id: ffi_size_to_bool(layout.has_process_id),
        has_tree_id: ffi_size_to_bool(layout.has_tree_id),
    }
}

pub fn sync_cb_data_layout() -> SyncCallbackDataLayout {
    let layout = unsafe { ffi::libsmb2_private_ffi_sync_cb_data_layout() };
    SyncCallbackDataLayout {
        has_is_finished: ffi_size_to_bool(layout.has_is_finished),
        has_status: ffi_size_to_bool(layout.has_status),
        has_ptr: ffi_size_to_bool(layout.has_ptr),
    }
}

pub fn directory_layout() -> DirectoryLayout {
    let layout = unsafe { ffi::libsmb2_private_ffi_dir_layout() };
    DirectoryLayout {
        has_internal_next: ffi_size_to_bool(layout.has_internal_next),
        has_internal_dirent: ffi_size_to_bool(layout.has_internal_dirent),
        has_entries: ffi_size_to_bool(layout.has_entries),
        has_current_entry: ffi_size_to_bool(layout.has_current_entry),
        has_index: ffi_size_to_bool(layout.has_index),
    }
}

pub fn tree_id_for_current_index(tree_id_cur: i32, value: u32) -> u32 {
    unsafe { ffi::libsmb2_private_ffi_tree_id_for_cur(tree_id_cur, value) }
}

pub fn is_server_for_owning_server(has_owning_server: bool) -> bool {
    unsafe {
        ffi::libsmb2_private_ffi_is_server_for_owning_server(i32::from(has_owning_server)) != 0
    }
}
