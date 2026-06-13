#include "libsmb2_private_ffi.h"

#define HAVE_STDINT_H 1
#define HAVE_TIME_H 1
#include <time.h>

#include "smb2/smb2.h"
#include "compat.h"
#include "smb2/libsmb2.h"
#include "libsmb2-private.h"

uint32_t libsmb2_private_ffi_max_error_size(void) { return MAX_ERROR_SIZE; }
int32_t libsmb2_private_ffi_min_i32(int32_t a, int32_t b) { return MIN(a, b); }
uintptr_t libsmb2_private_ffi_discard_const_ptr(const void* ptr) { return (uintptr_t)discard_const(ptr); }
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

libsmb2_private_ffi_context_layout_t libsmb2_private_ffi_context_layout(void) {
    struct smb2_context ctx;
    return (libsmb2_private_ffi_context_layout_t){
        sizeof(ctx.error_string),
        sizeof(ctx.header),
        sizeof(ctx.tree_id) / sizeof(ctx.tree_id[0]),
        sizeof(ctx.signing_key),
        sizeof(ctx.serverin_key),
        sizeof(ctx.serverout_key),
        sizeof(ctx.salt),
        sizeof(ctx.connect_cb_data) > 0,
        sizeof(ctx.in) > 0,
        sizeof(ctx.owning_server) > 0,
    };
}

libsmb2_private_ffi_pdu_layout_t libsmb2_private_ffi_pdu_layout(void) {
    struct smb2_pdu pdu;
    return (libsmb2_private_ffi_pdu_layout_t){
        sizeof(pdu.hdr),
        sizeof(pdu.header) > 0,
        sizeof(pdu.out) > 0,
        sizeof(pdu.in) > 0,
        sizeof(pdu.payload) > 0,
        sizeof(pdu.free_payload) > 0,
    };
}

libsmb2_private_ffi_io_vectors_layout_t libsmb2_private_ffi_io_vectors_layout(void) {
    struct smb2_io_vectors vectors;
    return (libsmb2_private_ffi_io_vectors_layout_t){
        sizeof(vectors.iov) / sizeof(vectors.iov[0]),
        sizeof(vectors.num_done) > 0,
        sizeof(vectors.total_size) > 0,
        sizeof(vectors.niov) > 0,
    };
}

libsmb2_private_ffi_header_layout_t libsmb2_private_ffi_header_layout(void) {
    struct smb2_header header;
    return (libsmb2_private_ffi_header_layout_t){
        sizeof(header.protocol_id),
        sizeof(header.signature),
        sizeof(header.async.async_id) > 0,
        sizeof(header.sync.process_id) > 0,
        sizeof(header.sync.tree_id) > 0,
    };
}

libsmb2_private_ffi_sync_cb_data_layout_t libsmb2_private_ffi_sync_cb_data_layout(void) {
    struct sync_cb_data data;
    return (libsmb2_private_ffi_sync_cb_data_layout_t){
        sizeof(data.is_finished) > 0,
        sizeof(data.status) > 0,
        sizeof(data.ptr) > 0,
    };
}

libsmb2_private_ffi_dir_layout_t libsmb2_private_ffi_dir_layout(void) {
    struct smb2_dirent_internal internal;
    struct smb2dir dir;
    return (libsmb2_private_ffi_dir_layout_t){
        sizeof(internal.next) > 0,
        sizeof(internal.dirent) > 0,
        sizeof(dir.entries) > 0,
        sizeof(dir.current_entry) > 0,
        sizeof(dir.index) > 0,
    };
}

uint32_t libsmb2_private_ffi_tree_id_for_cur(int tree_id_cur, uint32_t value) {
    struct smb2_context ctx;
    struct smb2_context *ctxp = &ctx;
    ctx.tree_id_cur = tree_id_cur;
    ctx.tree_id[0] = value;
    return smb2_tree_id(ctxp);
}

int libsmb2_private_ffi_is_server_for_owning_server(int has_owning_server) {
    struct smb2_context ctx;
    ctx.owning_server = has_owning_server ? (struct smb2_server*)&ctx : NULL;
    return smb2_is_server(&ctx) ? 1 : 0;
}

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
