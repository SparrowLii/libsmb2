#include "libsmb2_private_ffi.h"

#define HAVE_STDINT_H 1
#define HAVE_TIME_H 1
#include <time.h>

#include "smb2/smb2.h"
#include "compat.h"
#include "smb2/libsmb2.h"
#include "libsmb2-private.h"

uint32_t libsmb2_private_ffi_max_error_size(void) { return MAX_ERROR_SIZE; }
uint32_t libsmb2_private_ffi_pad_to_32bit(uint32_t len) { return PAD_TO_32BIT(len); }
uint32_t libsmb2_private_ffi_pad_to_64bit(uint32_t len) { return PAD_TO_64BIT(len); }
uint32_t libsmb2_private_ffi_spl_size(void) { return SMB2_SPL_SIZE; }
uint32_t libsmb2_private_ffi_header_size(void) { return SMB2_HEADER_SIZE; }
uint32_t libsmb2_private_ffi_signature_size(void) { return SMB2_SIGNATURE_SIZE; }
uint32_t libsmb2_private_ffi_key_size(void) { return SMB2_KEY_SIZE; }
uint32_t libsmb2_private_ffi_max_vectors(void) { return SMB2_MAX_VECTORS; }
uint32_t libsmb2_private_ffi_max_tree_nesting(void) { return SMB2_MAX_TREE_NESTING; }
uint32_t libsmb2_private_ffi_max_credits(void) { return MAX_CREDITS; }
uint32_t libsmb2_private_ffi_salt_size(void) { return SMB2_SALT_SIZE; }
uint32_t libsmb2_private_ffi_max_pdu_size(void) { return SMB2_MAX_PDU_SIZE; }
uint32_t libsmb2_private_ffi_preauth_hash_size(void) { return SMB2_PREAUTH_HASH_SIZE; }
size_t libsmb2_private_ffi_sizeof_smb2_header(void) { return sizeof(struct smb2_header); }
size_t libsmb2_private_ffi_sizeof_smb2_io_vectors(void) { return sizeof(struct smb2_io_vectors); }
size_t libsmb2_private_ffi_sizeof_smb2_context(void) { return sizeof(struct smb2_context); }
size_t libsmb2_private_ffi_sizeof_smb2_pdu(void) { return sizeof(struct smb2_pdu); }
size_t libsmb2_private_ffi_sizeof_smb2dir(void) { return sizeof(struct smb2dir); }

int libsmb2_private_ffi_recv_state_value(libsmb2_private_ffi_recv_state_t state, int* out) {
    if (out == NULL) {
        return -1;
    }

    switch (state) {
    case LIBSMB2_PRIVATE_FFI_RECV_SPL:
        *out = SMB2_RECV_SPL;
        return 0;
    case LIBSMB2_PRIVATE_FFI_RECV_HEADER:
        *out = SMB2_RECV_HEADER;
        return 0;
    case LIBSMB2_PRIVATE_FFI_RECV_FIXED:
        *out = SMB2_RECV_FIXED;
        return 0;
    case LIBSMB2_PRIVATE_FFI_RECV_VARIABLE:
        *out = SMB2_RECV_VARIABLE;
        return 0;
    case LIBSMB2_PRIVATE_FFI_RECV_PAD:
        *out = SMB2_RECV_PAD;
        return 0;
    case LIBSMB2_PRIVATE_FFI_RECV_TRFM:
        *out = SMB2_RECV_TRFM;
        return 0;
    case LIBSMB2_PRIVATE_FFI_RECV_UNKNOWN:
        *out = SMB2_RECV_UNKNOWN;
        return 0;
    default:
        return -2;
    }
}
