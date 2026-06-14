#ifndef LIBSMB2_SYS_SPNEGO_WRAPPER_FFI_H
#define LIBSMB2_SYS_SPNEGO_WRAPPER_FFI_H

#include <stddef.h>
#include <stdint.h>

#define SPNEGO_FFI_MAX_BLOB 768
#define SPNEGO_FFI_MAX_ERROR 128

struct spnego_ffi_blob_result {
        int rc;
        int has_blob;
        int set_error_called;
        uint32_t mechanisms;
        size_t token_offset;
        size_t token_len;
        size_t len;
        uint8_t bytes[SPNEGO_FFI_MAX_BLOB];
        char error[SPNEGO_FFI_MAX_ERROR];
};

struct spnego_ffi_blob_result spnego_ffi_create_negotiate_reply(int allow_ntlmssp,
                                                                int fail_alloc);
struct spnego_ffi_blob_result spnego_ffi_wrap_gssapi(const uint8_t *token,
                                                     int token_len,
                                                     int fail_alloc);
struct spnego_ffi_blob_result spnego_ffi_wrap_ntlmssp_challenge(const uint8_t *token,
                                                                int token_len,
                                                                int fail_alloc);
struct spnego_ffi_blob_result spnego_ffi_wrap_ntlmssp_auth(const uint8_t *token,
                                                           int token_len,
                                                           int fail_alloc);
struct spnego_ffi_blob_result spnego_ffi_wrap_authenticate_result(int authorized_ok,
                                                                  int fail_alloc);
struct spnego_ffi_blob_result spnego_ffi_unwrap_gssapi(const uint8_t *spnego,
                                                       int spnego_len,
                                                       int suppress_errors);
struct spnego_ffi_blob_result spnego_ffi_unwrap_blob(const uint8_t *spnego,
                                                     int spnego_len,
                                                     int suppress_errors,
                                                     int null_token);
struct spnego_ffi_blob_result spnego_ffi_unwrap_targ(const uint8_t *spnego,
                                                     int spnego_len);

#endif
