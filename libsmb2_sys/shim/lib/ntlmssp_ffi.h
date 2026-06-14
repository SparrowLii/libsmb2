#ifndef LIBSMB2_SYS_NTLMSSP_FFI_H
#define LIBSMB2_SYS_NTLMSSP_FFI_H

#include <stddef.h>
#include <stdint.h>

#define NTLMSSP_FFI_MAX_BLOB 256
#define NTLMSSP_FFI_MAX_ERROR 128
#define NTLMSSP_FFI_KEY_SIZE 16

struct auth_data;

struct ntlmssp_ffi_context_result {
        int created;
        int authenticated;
        int spnego_initial;
        int spnego_after_set;
        int key_rc;
        int invalid_key_rc;
        uint8_t key_size;
        uint8_t key[NTLMSSP_FFI_KEY_SIZE];
        int free_count_after_destroy;
};

struct ntlmssp_ffi_key_result {
        int rc;
        uint8_t key_size;
        uint8_t key[NTLMSSP_FFI_KEY_SIZE];
};

struct ntlmssp_ffi_message_result {
        int rc;
        uint32_t message_type;
        size_t ptr_offset;
        int len;
        int is_wrapped;
        int set_error_called;
};

struct ntlmssp_ffi_blob_result {
        int rc;
        uint16_t output_len;
        uint32_t message_type;
        int is_wrapped;
        int set_error_called;
        size_t len;
        uint8_t bytes[NTLMSSP_FFI_MAX_BLOB];
        char error[NTLMSSP_FFI_MAX_ERROR];
};

struct auth_data *ntlmssp_ffi_context_new_default(void);
void ntlmssp_ffi_context_destroy(struct auth_data *auth);
void ntlmssp_ffi_context_set_spnego_wrapping(struct auth_data *auth, int wrap);
int ntlmssp_ffi_context_get_spnego_wrapping(struct auth_data *auth);
int ntlmssp_ffi_context_get_authenticated(struct auth_data *auth);
struct ntlmssp_ffi_key_result ntlmssp_ffi_context_get_session_key(struct auth_data *auth);

struct ntlmssp_ffi_context_result ntlmssp_ffi_context_success(void);
int ntlmssp_ffi_context_allocation_failure(void);
int ntlmssp_ffi_destroy_populated_context_free_count(void);
int ntlmssp_ffi_wrapping_roundtrip(int wrap);
int ntlmssp_ffi_authenticated_null(void);
struct ntlmssp_ffi_key_result ntlmssp_ffi_session_key_copy(void);
struct ntlmssp_ffi_key_result ntlmssp_ffi_session_key_invalid_arguments(void);
struct ntlmssp_ffi_message_result ntlmssp_ffi_message_type_raw(uint32_t message_type);
struct ntlmssp_ffi_message_result ntlmssp_ffi_message_type_invalid_short(void);
struct ntlmssp_ffi_blob_result ntlmssp_ffi_generate_initial_client_negotiate(void);
struct ntlmssp_ffi_blob_result ntlmssp_ffi_generate_invalid_client_blob(void);
int ntlmssp_ffi_authenticate_invalid_input(void);

#endif
