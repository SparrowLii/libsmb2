#include "ntlmssp_ffi.h"

#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_TIME_H 1
#define STDC_HEADERS 1
#define _U_ __attribute__((unused))

#include "smb2/smb2.h"
#include "smb2/libsmb2.h"
#include "smb2/libsmb2-raw.h"
#include "libsmb2-private.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ntlmssp_ffi_fail_next_calloc;
static int ntlmssp_ffi_free_count;
static int ntlmssp_ffi_set_error_called;

static const char ntlmssp_ffi_user[] = "user";
static const char ntlmssp_ffi_password[] = "password";
static const char ntlmssp_ffi_domain[] = "domain";
static const char ntlmssp_ffi_workstation[] = "workstation";
static const char ntlmssp_ffi_challenge[8] = {'1', '2', '3', '4', '5', '6', '7', '8'};

static void *ntlmssp_ffi_malloc(size_t size)
{
        return malloc(size);
}

static void *ntlmssp_ffi_calloc(size_t nmemb, size_t size)
{
        if (ntlmssp_ffi_fail_next_calloc > 0) {
                ntlmssp_ffi_fail_next_calloc--;
                return NULL;
        }
        return calloc(nmemb, size);
}

static char *ntlmssp_ffi_strdup(const char *value)
{
        size_t len;
        char *copy;

        if (!value) {
                return NULL;
        }
        len = strlen(value) + 1;
        copy = ntlmssp_ffi_malloc(len);
        if (!copy) {
                return NULL;
        }
        memcpy(copy, value, len);
        return copy;
}

static void ntlmssp_ffi_free(void *ptr)
{
        if (ptr) {
                ntlmssp_ffi_free_count++;
        }
        free(ptr);
}

static void ntlmssp_ffi_set_error(struct smb2_context *smb2,
                                  const char *error_string, ...)
{
        va_list ap;

        ntlmssp_ffi_set_error_called = 1;
        if (!smb2) {
                return;
        }
        va_start(ap, error_string);
        vsnprintf(smb2->error_string, sizeof(smb2->error_string), error_string, ap);
        va_end(ap);
}

static void ntlmssp_ffi_replace_string(const char **slot, const char *value)
{
        if (*slot) {
                ntlmssp_ffi_free((void *)*slot);
                *slot = NULL;
        }
        if (value) {
                *slot = ntlmssp_ffi_strdup(value);
        }
}

static void ntlmssp_ffi_set_user(struct smb2_context *smb2, const char *user)
{
        if (smb2) {
                ntlmssp_ffi_replace_string(&smb2->user, user);
        }
}

static void ntlmssp_ffi_set_domain(struct smb2_context *smb2, const char *domain)
{
        if (smb2) {
                ntlmssp_ffi_replace_string(&smb2->domain, domain);
        }
}

static void ntlmssp_ffi_set_workstation(struct smb2_context *smb2, const char *workstation)
{
        if (smb2) {
                ntlmssp_ffi_replace_string(&smb2->workstation, workstation);
        }
}

static void ntlmssp_ffi_set_password(struct smb2_context *smb2, const char *password)
{
        if (smb2) {
                ntlmssp_ffi_replace_string(&smb2->password, password);
        }
}

static void ntlmssp_ffi_set_password_from_file(struct smb2_context *smb2 _U_)
{
}

static int ntlmssp_ffi_spnego_unwrap_blob(struct smb2_context *smb2 _U_,
                                          const uint8_t *spnego,
                                          int spnego_len,
                                          int suppress_errors,
                                          uint8_t **token,
                                          uint32_t *mechanisms)
{
        if (mechanisms) {
                *mechanisms = 0;
        }
        if (token) {
                *token = NULL;
        }
        if (spnego && spnego_len >= 12 && !memcmp(spnego, "NTLMSSP", 7)) {
                if (token) {
                        *token = (uint8_t *)spnego;
                }
                return spnego_len;
        }
        if (!suppress_errors) {
                ntlmssp_ffi_set_error(smb2, "invalid NTLMSSP blob");
        }
        return -1;
}

static int ntlmssp_ffi_spnego_wrap_fail(struct smb2_context *smb2 _U_,
                                        const uint8_t *token _U_,
                                        int token_len _U_,
                                        void **blob _U_)
{
        return -1;
}

static int ntlmssp_ffi_spnego_wrap_auth_result_fail(struct smb2_context *smb2 _U_,
                                                    int authorized_ok _U_,
                                                    void **blob _U_)
{
        return -1;
}

#define malloc ntlmssp_ffi_malloc
#define calloc ntlmssp_ffi_calloc
#define strdup ntlmssp_ffi_strdup
#define free ntlmssp_ffi_free
#define smb2_set_error ntlmssp_ffi_set_error
#define smb2_set_user ntlmssp_ffi_set_user
#define smb2_set_domain ntlmssp_ffi_set_domain
#define smb2_set_workstation ntlmssp_ffi_set_workstation
#define smb2_set_password ntlmssp_ffi_set_password
#define smb2_set_password_from_file ntlmssp_ffi_set_password_from_file
#define smb2_spnego_unwrap_blob ntlmssp_ffi_spnego_unwrap_blob
#define smb2_spnego_wrap_gssapi ntlmssp_ffi_spnego_wrap_fail
#define smb2_spnego_wrap_ntlmssp_challenge ntlmssp_ffi_spnego_wrap_fail
#define smb2_spnego_wrap_ntlmssp_auth ntlmssp_ffi_spnego_wrap_fail
#define smb2_spnego_wrap_authenticate_result ntlmssp_ffi_spnego_wrap_auth_result_fail
#define ntlmssp_init_context ntlmssp_ffi_real_init_context
#define ntlmssp_destroy_context ntlmssp_ffi_real_destroy_context
#define ntlmssp_set_spnego_wrapping ntlmssp_ffi_real_set_spnego_wrapping
#define ntlmssp_get_spnego_wrapping ntlmssp_ffi_real_get_spnego_wrapping
#define ntlmssp_get_message_type ntlmssp_ffi_real_get_message_type
#define ntlmssp_generate_blob ntlmssp_ffi_real_generate_blob
#define ntlmssp_authenticate_blob ntlmssp_ffi_real_authenticate_blob
#define ntlmssp_get_authenticated ntlmssp_ffi_real_get_authenticated
#define ntlmssp_get_session_key ntlmssp_ffi_real_get_session_key
#include "ntlmssp.c"
#undef malloc
#undef calloc
#undef strdup
#undef free
#undef smb2_set_error
#undef smb2_set_user
#undef smb2_set_domain
#undef smb2_set_workstation
#undef smb2_set_password
#undef smb2_set_password_from_file
#undef smb2_spnego_unwrap_blob
#undef smb2_spnego_wrap_gssapi
#undef smb2_spnego_wrap_ntlmssp_challenge
#undef smb2_spnego_wrap_ntlmssp_auth
#undef smb2_spnego_wrap_authenticate_result
#undef ntlmssp_init_context
#undef ntlmssp_destroy_context
#undef ntlmssp_set_spnego_wrapping
#undef ntlmssp_get_spnego_wrapping
#undef ntlmssp_get_message_type
#undef ntlmssp_generate_blob
#undef ntlmssp_authenticate_blob
#undef ntlmssp_get_authenticated
#undef ntlmssp_get_session_key

static struct smb2_context ntlmssp_ffi_context(void)
{
        struct smb2_context smb2;
        memset(&smb2, 0, sizeof(smb2));
        return smb2;
}

static struct ntlmssp_ffi_key_result ntlmssp_ffi_empty_key_result(void)
{
        struct ntlmssp_ffi_key_result result;
        memset(&result, 0, sizeof(result));
        result.rc = -1;
        return result;
}

static void ntlmssp_ffi_write_u32le(uint8_t *buf, size_t offset, uint32_t value)
{
        buf[offset + 0] = (uint8_t)(value & 0xff);
        buf[offset + 1] = (uint8_t)((value >> 8) & 0xff);
        buf[offset + 2] = (uint8_t)((value >> 16) & 0xff);
        buf[offset + 3] = (uint8_t)((value >> 24) & 0xff);
}

struct auth_data *ntlmssp_ffi_context_new_default(void)
{
        return ntlmssp_ffi_real_init_context(ntlmssp_ffi_user,
                                             ntlmssp_ffi_password,
                                             ntlmssp_ffi_domain,
                                             ntlmssp_ffi_workstation,
                                             ntlmssp_ffi_challenge);
}

void ntlmssp_ffi_context_destroy(struct auth_data *auth)
{
        ntlmssp_ffi_real_destroy_context(auth);
}

void ntlmssp_ffi_context_set_spnego_wrapping(struct auth_data *auth, int wrap)
{
        ntlmssp_ffi_real_set_spnego_wrapping(auth, wrap);
}

int ntlmssp_ffi_context_get_spnego_wrapping(struct auth_data *auth)
{
        return ntlmssp_ffi_real_get_spnego_wrapping(auth);
}

int ntlmssp_ffi_context_get_authenticated(struct auth_data *auth)
{
        return ntlmssp_ffi_real_get_authenticated(auth);
}

struct ntlmssp_ffi_key_result ntlmssp_ffi_context_get_session_key(struct auth_data *auth)
{
        struct ntlmssp_ffi_key_result result = ntlmssp_ffi_empty_key_result();
        uint8_t *key = NULL;
        uint8_t key_size = 0;

        result.rc = ntlmssp_ffi_real_get_session_key(auth, &key, &key_size);
        result.key_size = key_size;
        if (result.rc == 0 && key) {
                size_t len = key_size;
                if (len > sizeof(result.key)) {
                        len = sizeof(result.key);
                }
                memcpy(result.key, key, len);
                ntlmssp_ffi_free(key);
        }
        return result;
}

struct ntlmssp_ffi_context_result ntlmssp_ffi_context_success(void)
{
        struct ntlmssp_ffi_context_result result;
        struct auth_data *auth;
        struct ntlmssp_ffi_key_result key;
        int free_before_destroy;

        memset(&result, 0, sizeof(result));
        ntlmssp_ffi_free_count = 0;
        auth = ntlmssp_ffi_context_new_default();
        result.created = auth != NULL;
        if (!auth) {
                return result;
        }
        result.authenticated = ntlmssp_ffi_real_get_authenticated(auth);
        result.spnego_initial = ntlmssp_ffi_real_get_spnego_wrapping(auth);
        ntlmssp_ffi_real_set_spnego_wrapping(auth, 7);
        result.spnego_after_set = ntlmssp_ffi_real_get_spnego_wrapping(auth);
        key = ntlmssp_ffi_context_get_session_key(auth);
        result.key_rc = key.rc;
        result.key_size = key.key_size;
        memcpy(result.key, key.key, sizeof(result.key));
        result.invalid_key_rc = ntlmssp_ffi_real_get_session_key(NULL, NULL, NULL);
        free_before_destroy = ntlmssp_ffi_free_count;
        ntlmssp_ffi_real_destroy_context(auth);
        result.free_count_after_destroy = ntlmssp_ffi_free_count - free_before_destroy;
        return result;
}

int ntlmssp_ffi_context_allocation_failure(void)
{
        struct auth_data *auth;

        ntlmssp_ffi_fail_next_calloc = 1;
        auth = ntlmssp_ffi_context_new_default();
        return auth == NULL;
}

int ntlmssp_ffi_destroy_populated_context_free_count(void)
{
        struct auth_data *auth;
        int free_before_destroy;

        ntlmssp_ffi_free_count = 0;
        auth = ntlmssp_ffi_context_new_default();
        if (!auth) {
                return 0;
        }
        free_before_destroy = ntlmssp_ffi_free_count;
        ntlmssp_ffi_real_destroy_context(auth);
        return ntlmssp_ffi_free_count - free_before_destroy;
}

int ntlmssp_ffi_wrapping_roundtrip(int wrap)
{
        struct auth_data *auth = ntlmssp_ffi_context_new_default();
        int observed = -1;

        if (!auth) {
                return -1;
        }
        ntlmssp_ffi_real_set_spnego_wrapping(auth, wrap);
        observed = ntlmssp_ffi_real_get_spnego_wrapping(auth);
        ntlmssp_ffi_real_destroy_context(auth);
        return observed;
}

int ntlmssp_ffi_authenticated_null(void)
{
        return ntlmssp_ffi_real_get_authenticated(NULL);
}

struct ntlmssp_ffi_key_result ntlmssp_ffi_session_key_copy(void)
{
        struct auth_data *auth = ntlmssp_ffi_context_new_default();
        struct ntlmssp_ffi_key_result result = ntlmssp_ffi_empty_key_result();

        if (!auth) {
                return result;
        }
        result = ntlmssp_ffi_context_get_session_key(auth);
        ntlmssp_ffi_real_destroy_context(auth);
        return result;
}

struct ntlmssp_ffi_key_result ntlmssp_ffi_session_key_invalid_arguments(void)
{
        struct ntlmssp_ffi_key_result result = ntlmssp_ffi_empty_key_result();
        result.rc = ntlmssp_ffi_real_get_session_key(NULL, NULL, NULL);
        return result;
}

struct ntlmssp_ffi_message_result ntlmssp_ffi_message_type_raw(uint32_t message_type)
{
        struct ntlmssp_ffi_message_result result;
        struct smb2_context smb2 = ntlmssp_ffi_context();
        uint8_t buffer[16];
        uint8_t *ptr = NULL;

        memset(&result, 0, sizeof(result));
        memset(buffer, 0, sizeof(buffer));
        memcpy(buffer, "NTLMSSP", 7);
        ntlmssp_ffi_write_u32le(buffer, 8, message_type);
        result.message_type = 0xffffffffu;
        result.is_wrapped = -1;
        ntlmssp_ffi_set_error_called = 0;
        result.rc = ntlmssp_ffi_real_get_message_type(&smb2, buffer, sizeof(buffer), 0,
                                                      &result.message_type,
                                                      &ptr,
                                                      &result.len,
                                                      &result.is_wrapped);
        result.ptr_offset = ptr ? (size_t)(ptr - buffer) : (size_t)-1;
        result.set_error_called = ntlmssp_ffi_set_error_called;
        return result;
}

struct ntlmssp_ffi_message_result ntlmssp_ffi_message_type_invalid_short(void)
{
        struct ntlmssp_ffi_message_result result;
        struct smb2_context smb2 = ntlmssp_ffi_context();
        uint8_t buffer[4] = {'N', 'T', 'L', 'M'};
        uint8_t *ptr = (uint8_t *)1;

        memset(&result, 0, sizeof(result));
        result.message_type = 0;
        result.len = 99;
        result.is_wrapped = -1;
        ntlmssp_ffi_set_error_called = 0;
        result.rc = ntlmssp_ffi_real_get_message_type(&smb2, buffer, sizeof(buffer), 0,
                                                      &result.message_type,
                                                      &ptr,
                                                      &result.len,
                                                      &result.is_wrapped);
        result.ptr_offset = ptr ? 1 : (size_t)-1;
        result.set_error_called = ntlmssp_ffi_set_error_called;
        return result;
}

struct ntlmssp_ffi_blob_result ntlmssp_ffi_generate_initial_client_negotiate(void)
{
        struct ntlmssp_ffi_blob_result result;
        struct smb2_context smb2 = ntlmssp_ffi_context();
        struct auth_data *auth = ntlmssp_ffi_context_new_default();
        uint8_t *output = NULL;
        uint16_t output_len = 0;

        memset(&result, 0, sizeof(result));
        result.message_type = 0xffffffffu;
        if (!auth) {
                result.rc = -1;
                return result;
        }
        ntlmssp_ffi_set_error_called = 0;
        result.rc = ntlmssp_ffi_real_generate_blob(NULL, &smb2, 0, auth,
                                                   NULL, 0,
                                                   &output, &output_len);
        result.output_len = output_len;
        if (result.rc == 0 && output && output_len > 0) {
                result.len = output_len;
                if (result.len > sizeof(result.bytes)) {
                        result.len = sizeof(result.bytes);
                }
                memcpy(result.bytes, output, result.len);
                (void)ntlmssp_ffi_real_get_message_type(&smb2, output, output_len, 0,
                                                        &result.message_type,
                                                        NULL, NULL,
                                                        &result.is_wrapped);
        }
        result.set_error_called = ntlmssp_ffi_set_error_called;
        snprintf(result.error, sizeof(result.error), "%s", smb2.error_string);
        ntlmssp_ffi_real_destroy_context(auth);
        return result;
}

struct ntlmssp_ffi_blob_result ntlmssp_ffi_generate_invalid_client_blob(void)
{
        struct ntlmssp_ffi_blob_result result;
        struct smb2_context smb2 = ntlmssp_ffi_context();
        struct auth_data *auth = ntlmssp_ffi_context_new_default();
        uint8_t bad[12] = {'b', 'a', 'd'};
        uint8_t *output = NULL;
        uint16_t output_len = 0;

        memset(&result, 0, sizeof(result));
        if (!auth) {
                result.rc = -1;
                return result;
        }
        ntlmssp_ffi_set_error_called = 0;
        result.rc = ntlmssp_ffi_real_generate_blob(NULL, &smb2, 0, auth,
                                                   bad, sizeof(bad),
                                                   &output, &output_len);
        result.output_len = output_len;
        result.set_error_called = ntlmssp_ffi_set_error_called;
        snprintf(result.error, sizeof(result.error), "%s", smb2.error_string);
        ntlmssp_ffi_real_destroy_context(auth);
        return result;
}

int ntlmssp_ffi_authenticate_invalid_input(void)
{
        struct smb2_context smb2 = ntlmssp_ffi_context();
        struct auth_data *auth = ntlmssp_ffi_context_new_default();
        uint8_t bad[12] = {'b', 'a', 'd'};
        int rc;

        if (!auth) {
                return -2;
        }
        rc = ntlmssp_ffi_real_authenticate_blob(NULL, &smb2, auth, bad, sizeof(bad));
        ntlmssp_ffi_real_destroy_context(auth);
        return rc;
}
