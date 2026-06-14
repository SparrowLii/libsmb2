#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum libsmb2_private_ffi_recv_state_t {
    LIBSMB2_PRIVATE_FFI_RECV_SPL = 0,
    LIBSMB2_PRIVATE_FFI_RECV_HEADER = 1,
    LIBSMB2_PRIVATE_FFI_RECV_FIXED = 2,
    LIBSMB2_PRIVATE_FFI_RECV_VARIABLE = 3,
    LIBSMB2_PRIVATE_FFI_RECV_PAD = 4,
    LIBSMB2_PRIVATE_FFI_RECV_TRFM = 5,
    LIBSMB2_PRIVATE_FFI_RECV_UNKNOWN = 6,
} libsmb2_private_ffi_recv_state_t;

typedef struct libsmb2_private_ffi_context_layout_t {
    size_t error_string_len;
    size_t header_len;
    size_t tree_id_len;
    size_t signing_key_len;
    size_t serverin_key_len;
    size_t serverout_key_len;
    size_t salt_len;
    size_t has_connecting_fds;
    size_t has_addrinfos;
    size_t has_security_mode;
    size_t has_connect_cb_data;
    size_t has_tree_id_cur;
    size_t has_outqueue;
    size_t has_waitqueue;
    size_t has_io_vectors;
    size_t has_recv_state;
    size_t has_error_string;
    size_t has_owning_server;
} libsmb2_private_ffi_context_layout_t;

typedef struct libsmb2_private_ffi_pdu_layout_t {
    size_t hdr_len;
    size_t has_header;
    size_t has_out_vectors;
    size_t has_in_vectors;
    size_t has_payload;
    size_t has_free_payload;
} libsmb2_private_ffi_pdu_layout_t;

typedef struct libsmb2_private_ffi_io_vectors_layout_t {
    size_t iov_len;
    size_t has_num_done;
    size_t has_total_size;
    size_t has_niov;
} libsmb2_private_ffi_io_vectors_layout_t;

typedef struct libsmb2_private_ffi_header_layout_t {
    size_t protocol_id_len;
    size_t signature_len;
    size_t has_async_id;
    size_t has_process_id;
    size_t has_tree_id;
} libsmb2_private_ffi_header_layout_t;

typedef struct libsmb2_private_ffi_sync_cb_data_layout_t {
    size_t has_is_finished;
    size_t has_status;
    size_t has_ptr;
} libsmb2_private_ffi_sync_cb_data_layout_t;

typedef struct libsmb2_private_ffi_dir_layout_t {
    size_t has_internal_next;
    size_t has_internal_dirent;
    size_t has_entries;
    size_t has_current_entry;
    size_t has_index;
} libsmb2_private_ffi_dir_layout_t;

uint32_t libsmb2_private_ffi_max_error_size(void);
int32_t libsmb2_private_ffi_min_i32(int32_t a, int32_t b);
uintptr_t libsmb2_private_ffi_discard_const_ptr(const void* ptr);
uint32_t libsmb2_private_ffi_pad_to_32bit(uint32_t len);
uint32_t libsmb2_private_ffi_pad_to_64bit(uint32_t len);
uint32_t libsmb2_private_ffi_spl_size(void);
uint32_t libsmb2_private_ffi_header_size(void);
uint32_t libsmb2_private_ffi_signature_size(void);
uint32_t libsmb2_private_ffi_key_size(void);
uint32_t libsmb2_private_ffi_max_vectors(void);
uint32_t libsmb2_private_ffi_max_tree_nesting(void);
uint32_t libsmb2_private_ffi_max_credits(void);
uint32_t libsmb2_private_ffi_salt_size(void);
uint32_t libsmb2_private_ffi_max_pdu_size(void);
uint32_t libsmb2_private_ffi_preauth_hash_size(void);
size_t libsmb2_private_ffi_sizeof_smb2_header(void);
size_t libsmb2_private_ffi_sizeof_smb2_io_vectors(void);
size_t libsmb2_private_ffi_sizeof_smb2_context(void);
size_t libsmb2_private_ffi_sizeof_smb2_pdu(void);
size_t libsmb2_private_ffi_sizeof_smb2dir(void);
libsmb2_private_ffi_context_layout_t libsmb2_private_ffi_context_layout(void);
libsmb2_private_ffi_pdu_layout_t libsmb2_private_ffi_pdu_layout(void);
libsmb2_private_ffi_io_vectors_layout_t libsmb2_private_ffi_io_vectors_layout(void);
libsmb2_private_ffi_header_layout_t libsmb2_private_ffi_header_layout(void);
libsmb2_private_ffi_sync_cb_data_layout_t libsmb2_private_ffi_sync_cb_data_layout(void);
libsmb2_private_ffi_dir_layout_t libsmb2_private_ffi_dir_layout(void);
uint32_t libsmb2_private_ffi_tree_id_for_cur(int tree_id_cur, uint32_t value);
int libsmb2_private_ffi_is_server_for_owning_server(int has_owning_server);
int libsmb2_private_ffi_recv_state_value(libsmb2_private_ffi_recv_state_t state, int* out);

#ifdef __cplusplus
}
#endif
