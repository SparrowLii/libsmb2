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

uint32_t libsmb2_private_ffi_max_error_size(void);
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
int libsmb2_private_ffi_recv_state_value(libsmb2_private_ffi_recv_state_t state, int* out);

#ifdef __cplusplus
}
#endif
