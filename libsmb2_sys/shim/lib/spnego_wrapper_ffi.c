#include "spnego_wrapper_ffi.h"

#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_TYPES_H 1
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

static int spnego_ffi_fail_next_calloc;
static int spnego_ffi_set_error_called;

static void *spnego_ffi_calloc(size_t nmemb, size_t size)
{
        if (spnego_ffi_fail_next_calloc > 0) {
                spnego_ffi_fail_next_calloc--;
                return NULL;
        }
        return calloc(nmemb, size);
}

static void spnego_ffi_set_error(struct smb2_context *smb2,
                                 const char *error_string, ...)
{
        va_list ap;

        spnego_ffi_set_error_called = 1;
        if (!smb2) {
                return;
        }
        va_start(ap, error_string);
        vsnprintf(smb2->error_string, sizeof(smb2->error_string), error_string, ap);
        va_end(ap);
}

#define calloc spnego_ffi_calloc
#define smb2_set_error spnego_ffi_set_error
#define smb2_spnego_create_negotiate_reply_blob spnego_ffi_real_create_negotiate_reply_blob
#define smb2_spnego_wrap_gssapi spnego_ffi_real_wrap_gssapi
#define smb2_spnego_wrap_ntlmssp_challenge spnego_ffi_real_wrap_ntlmssp_challenge
#define smb2_spnego_wrap_ntlmssp_auth spnego_ffi_real_wrap_ntlmssp_auth
#define smb2_spnego_wrap_authenticate_result spnego_ffi_real_wrap_authenticate_result
#define smb2_spnego_unwrap_targ spnego_ffi_real_unwrap_targ
#define smb2_spnego_unwrap_gssapi spnego_ffi_real_unwrap_gssapi
#define smb2_spnego_unwrap_blob spnego_ffi_real_unwrap_blob
#include "spnego-wrapper.c"
#undef calloc
#undef smb2_set_error
#undef smb2_spnego_create_negotiate_reply_blob
#undef smb2_spnego_wrap_gssapi
#undef smb2_spnego_wrap_ntlmssp_challenge
#undef smb2_spnego_wrap_ntlmssp_auth
#undef smb2_spnego_wrap_authenticate_result
#undef smb2_spnego_unwrap_targ
#undef smb2_spnego_unwrap_gssapi
#undef smb2_spnego_unwrap_blob

static struct spnego_ffi_blob_result spnego_ffi_empty_result(void)
{
        struct spnego_ffi_blob_result result;
        memset(&result, 0, sizeof(result));
        return result;
}

static struct smb2_context spnego_ffi_context(void)
{
        struct smb2_context smb2;
        memset(&smb2, 0, sizeof(smb2));
        return smb2;
}

static void spnego_ffi_finish(struct spnego_ffi_blob_result *result,
                              const struct smb2_context *smb2)
{
        snprintf(result->error, sizeof(result->error), "%s", smb2->error_string);
        result->set_error_called = spnego_ffi_set_error_called || result->error[0] != '\0';
}

static void spnego_ffi_copy_blob(struct spnego_ffi_blob_result *result,
                                 const uint8_t *blob)
{
        if (!blob || result->rc <= 0) {
                return;
        }
        result->has_blob = 1;
        result->len = (size_t)result->rc;
        if (result->len > sizeof(result->bytes)) {
                result->len = sizeof(result->bytes);
        }
        memcpy(result->bytes, blob, result->len);
}

struct spnego_ffi_blob_result spnego_ffi_create_negotiate_reply(int allow_ntlmssp,
                                                                int fail_alloc)
{
        struct spnego_ffi_blob_result result = spnego_ffi_empty_result();
        struct smb2_context smb2 = spnego_ffi_context();
        void *blob = NULL;

        spnego_ffi_set_error_called = 0;
        spnego_ffi_fail_next_calloc = fail_alloc ? 1 : 0;
        result.rc = spnego_ffi_real_create_negotiate_reply_blob(&smb2, allow_ntlmssp, &blob);
        spnego_ffi_copy_blob(&result, blob);
        free(blob);
        spnego_ffi_finish(&result, &smb2);
        return result;
}

struct spnego_ffi_blob_result spnego_ffi_wrap_gssapi(const uint8_t *token,
                                                     int token_len,
                                                     int fail_alloc)
{
        struct spnego_ffi_blob_result result = spnego_ffi_empty_result();
        struct smb2_context smb2 = spnego_ffi_context();
        void *blob = NULL;

        spnego_ffi_set_error_called = 0;
        spnego_ffi_fail_next_calloc = fail_alloc ? 1 : 0;
        result.rc = spnego_ffi_real_wrap_gssapi(&smb2, token, token_len, &blob);
        spnego_ffi_copy_blob(&result, blob);
        free(blob);
        spnego_ffi_finish(&result, &smb2);
        return result;
}

struct spnego_ffi_blob_result spnego_ffi_wrap_ntlmssp_challenge(const uint8_t *token,
                                                                int token_len,
                                                                int fail_alloc)
{
        struct spnego_ffi_blob_result result = spnego_ffi_empty_result();
        struct smb2_context smb2 = spnego_ffi_context();
        void *blob = NULL;

        spnego_ffi_set_error_called = 0;
        spnego_ffi_fail_next_calloc = fail_alloc ? 1 : 0;
        result.rc = spnego_ffi_real_wrap_ntlmssp_challenge(&smb2, token, token_len, &blob);
        spnego_ffi_copy_blob(&result, blob);
        free(blob);
        spnego_ffi_finish(&result, &smb2);
        return result;
}

struct spnego_ffi_blob_result spnego_ffi_wrap_ntlmssp_auth(const uint8_t *token,
                                                           int token_len,
                                                           int fail_alloc)
{
        struct spnego_ffi_blob_result result = spnego_ffi_empty_result();
        struct smb2_context smb2 = spnego_ffi_context();
        void *blob = NULL;

        spnego_ffi_set_error_called = 0;
        spnego_ffi_fail_next_calloc = fail_alloc ? 1 : 0;
        result.rc = spnego_ffi_real_wrap_ntlmssp_auth(&smb2, token, token_len, &blob);
        spnego_ffi_copy_blob(&result, blob);
        free(blob);
        spnego_ffi_finish(&result, &smb2);
        return result;
}

struct spnego_ffi_blob_result spnego_ffi_wrap_authenticate_result(int authorized_ok,
                                                                  int fail_alloc)
{
        struct spnego_ffi_blob_result result = spnego_ffi_empty_result();
        struct smb2_context smb2 = spnego_ffi_context();
        void *blob = NULL;

        spnego_ffi_set_error_called = 0;
        spnego_ffi_fail_next_calloc = fail_alloc ? 1 : 0;
        result.rc = spnego_ffi_real_wrap_authenticate_result(&smb2, authorized_ok, &blob);
        spnego_ffi_copy_blob(&result, blob);
        free(blob);
        spnego_ffi_finish(&result, &smb2);
        return result;
}

struct spnego_ffi_blob_result spnego_ffi_unwrap_gssapi(const uint8_t *spnego,
                                                       int spnego_len,
                                                       int suppress_errors)
{
        struct spnego_ffi_blob_result result = spnego_ffi_empty_result();
        struct smb2_context smb2 = spnego_ffi_context();
        uint8_t *token = NULL;
        uint32_t mechanisms = 0;

        spnego_ffi_set_error_called = 0;
        result.rc = spnego_ffi_real_unwrap_gssapi(&smb2, spnego, spnego_len,
                                                  suppress_errors, &token, &mechanisms);
        result.mechanisms = mechanisms;
        if (token && spnego && token >= spnego && token <= spnego + spnego_len) {
                result.token_offset = (size_t)(token - spnego);
                result.token_len = result.rc > 0 ? (size_t)result.rc : 0;
        }
        spnego_ffi_finish(&result, &smb2);
        return result;
}

struct spnego_ffi_blob_result spnego_ffi_unwrap_blob(const uint8_t *spnego,
                                                     int spnego_len,
                                                     int suppress_errors,
                                                     int null_token)
{
        struct spnego_ffi_blob_result result = spnego_ffi_empty_result();
        struct smb2_context smb2 = spnego_ffi_context();
        uint8_t *token = (uint8_t *)0x1;
        uint8_t **token_arg = null_token ? NULL : &token;
        uint32_t mechanisms = 0;

        spnego_ffi_set_error_called = 0;
        result.rc = spnego_ffi_real_unwrap_blob(&smb2, spnego, spnego_len,
                                                suppress_errors, token_arg, &mechanisms);
        result.mechanisms = mechanisms;
        if (!token) {
                result.token_offset = (size_t)-1;
        } else if (spnego && token >= spnego && token <= spnego + spnego_len) {
                result.token_offset = (size_t)(token - spnego);
                result.token_len = result.rc > 0 ? (size_t)result.rc : 0;
        }
        spnego_ffi_finish(&result, &smb2);
        return result;
}

struct spnego_ffi_blob_result spnego_ffi_unwrap_targ(const uint8_t *spnego,
                                                     int spnego_len)
{
        struct spnego_ffi_blob_result result = spnego_ffi_empty_result();
        struct smb2_context smb2 = spnego_ffi_context();
        uint8_t *token = NULL;
        uint32_t mechanisms = 0;

        spnego_ffi_set_error_called = 0;
        result.rc = spnego_ffi_real_unwrap_targ(&smb2, spnego, spnego_len, &token, &mechanisms);
        result.mechanisms = mechanisms;
        if (token && spnego && token >= spnego && token <= spnego + spnego_len) {
                result.token_offset = (size_t)(token - spnego);
                result.token_len = result.rc > 0 ? (size_t)result.rc : 0;
        }
        spnego_ffi_finish(&result, &smb2);
        return result;
}
