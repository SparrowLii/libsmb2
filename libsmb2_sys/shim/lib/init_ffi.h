#ifndef LIBSMB2_SYS_INIT_FFI_H
#define LIBSMB2_SYS_INIT_FFI_H

#include <stddef.h>
#include <stdint.h>

struct smb2_context;
typedef struct smb2_context init_ffi_context;

init_ffi_context *init_ffi_context_new(void);
void init_ffi_context_free(init_ffi_context *smb2);
const char *init_ffi_get_error(const init_ffi_context *smb2);
int init_ffi_get_nterror(const init_ffi_context *smb2);
void init_ffi_set_nterror(init_ffi_context *smb2, int nterror);
void init_ffi_set_client_guid(init_ffi_context *smb2, const uint8_t *guid);
const uint8_t *init_ffi_get_client_guid(const init_ffi_context *smb2);
uint16_t init_ffi_get_dialect(const init_ffi_context *smb2);
void init_ffi_set_dialect(init_ffi_context *smb2, uint16_t dialect);
void init_ffi_set_security_mode(init_ffi_context *smb2, uint16_t security_mode);
uint16_t init_ffi_get_security_mode(const init_ffi_context *smb2);
void init_ffi_set_password_from_file(init_ffi_context *smb2);
const char *init_ffi_get_password(const init_ffi_context *smb2);
void init_ffi_set_user(init_ffi_context *smb2, const char *user);
const char *init_ffi_get_user(const init_ffi_context *smb2);
void init_ffi_set_password(init_ffi_context *smb2, const char *password);
void init_ffi_set_domain(init_ffi_context *smb2, const char *domain);
const char *init_ffi_get_domain(const init_ffi_context *smb2);
void init_ffi_set_workstation(init_ffi_context *smb2, const char *workstation);
const char *init_ffi_get_workstation(const init_ffi_context *smb2);
void init_ffi_set_server(init_ffi_context *smb2, const char *server);
void init_ffi_set_opaque(init_ffi_context *smb2, void *opaque);
void *init_ffi_get_opaque(const init_ffi_context *smb2);
void init_ffi_set_seal(init_ffi_context *smb2, int val);
int init_ffi_get_seal(const init_ffi_context *smb2);
void init_ffi_set_sign(init_ffi_context *smb2, int val);
int init_ffi_get_sign(const init_ffi_context *smb2);
int init_ffi_context_active(const init_ffi_context *smb2);
int init_ffi_iovector_free_probe(void);
int init_ffi_iovector_add_probe(size_t *total_size);
int init_ffi_iovector_overflow_probe(void);
void init_ffi_set_error_literal(init_ffi_context *smb2, const char *error_string);
int init_ffi_error_callback_probe(init_ffi_context *smb2);
void init_ffi_set_nterror_with_error(init_ffi_context *smb2, int nterror, const char *error_string);
void init_ffi_set_authentication(init_ffi_context *smb2, int val);
int init_ffi_get_authentication(const init_ffi_context *smb2);
void init_ffi_set_timeout(init_ffi_context *smb2, int seconds);
int init_ffi_get_timeout(const init_ffi_context *smb2);
void init_ffi_set_version(init_ffi_context *smb2, int version);
int init_ffi_get_version(const init_ffi_context *smb2);
void init_ffi_get_libversion(uint8_t *major, uint8_t *minor, uint8_t *patch);
void init_ffi_set_passthrough(init_ffi_context *smb2, int passthrough);
int init_ffi_get_passthrough(init_ffi_context *smb2);
int init_ffi_oplock_callback_probe(init_ffi_context *smb2);
int init_ffi_delegate_credentials_unavailable(init_ffi_context *in, init_ffi_context *out);
void init_ffi_set_max_read_size(init_ffi_context *smb2, uint32_t max_read_size);
uint32_t init_ffi_get_max_read_size(const init_ffi_context *smb2);
void init_ffi_set_max_write_size(init_ffi_context *smb2, uint32_t max_write_size);
uint32_t init_ffi_get_max_write_size(const init_ffi_context *smb2);

typedef struct init_ffi_file_handle init_ffi_file_handle;
init_ffi_file_handle *init_ffi_file_handle_from_id(const uint8_t *file_id);
void init_ffi_file_handle_free(init_ffi_file_handle *fh);
const uint8_t *init_ffi_file_handle_get_id(const init_ffi_file_handle *fh);

struct init_ffi_url_snapshot {
        char domain[64];
        char user[64];
        char server[64];
        char share[64];
        char path[128];
};

struct init_ffi_context_defaults {
        int allocated;
        int fd;
        int sec;
        int version;
        int ndr;
        int active;
};

int init_ffi_parse_url_snapshot(const char *url,
                                struct init_ffi_url_snapshot *snapshot);
const char *init_ffi_parse_url_error(const char *url);
int init_ffi_parse_url_query_snapshot(int *seal, int *version, int *sec,
                                      int *timeout);
const char *init_ffi_parse_url_bad_query_error(void);
int init_ffi_destroy_parsed_url_probe(void);
int init_ffi_destroy_null_url_probe(void);
struct init_ffi_context_defaults init_ffi_real_context_defaults(void);
int init_ffi_init_context_allocation_failure_probe(void);
int init_ffi_destroy_active_context_probe(void);
int init_ffi_destroy_null_context_probe(void);
int init_ffi_active_contexts_probe(void);
int init_ffi_real_context_active_probe(void);

#endif
