#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc_ffi.h"

struct smb2_context;

void smb2_set_error(struct smb2_context *smb2, const char *error_string, ...)
{
    (void)smb2;
    (void)error_string;

    va_list ap;
    va_start(ap, error_string);
    va_end(ap);
}

static int alloc_ffi_fail_next_calloc;
static int alloc_ffi_set_error_called;
static char alloc_ffi_set_error_message[128];

static void *alloc_ffi_forced_calloc(size_t nmemb, size_t size)
{
    if (alloc_ffi_fail_next_calloc > 0) {
        alloc_ffi_fail_next_calloc--;
        return NULL;
    }

    return calloc(nmemb, size);
}

void alloc_ffi_forced_set_error(struct smb2_context *smb2, const char *error_string, ...)
{
    (void)smb2;

    va_list ap;
    va_start(ap, error_string);
    vsnprintf(alloc_ffi_set_error_message, sizeof(alloc_ffi_set_error_message), error_string, ap);
    va_end(ap);
    alloc_ffi_set_error_called = 1;
}

#define calloc alloc_ffi_forced_calloc
#define smb2_alloc_init alloc_ffi_forced_smb2_alloc_init
#define smb2_alloc_data alloc_ffi_forced_smb2_alloc_data
#define smb2_free_data alloc_ffi_forced_smb2_free_data
#define smb2_set_error alloc_ffi_forced_set_error
#include "alloc.c"
#undef calloc
#undef smb2_alloc_init
#undef smb2_alloc_data
#undef smb2_free_data
#undef smb2_set_error

int alloc_ffi_forced_init_failure_returns_null(size_t size)
{
    alloc_ffi_fail_next_calloc = 1;

    return alloc_ffi_forced_smb2_alloc_init(NULL, size) == NULL;
}

struct alloc_ffi_child_failure_result alloc_ffi_forced_child_failure(size_t child_size)
{
    struct alloc_ffi_child_failure_result result;
    void *memctx;
    void *child;

    memset(&result, 0, sizeof(result));
    memset(alloc_ffi_set_error_message, 0, sizeof(alloc_ffi_set_error_message));
    alloc_ffi_set_error_called = 0;
    alloc_ffi_fail_next_calloc = 0;

    memctx = alloc_ffi_forced_smb2_alloc_init(NULL, 8);
    if (memctx == NULL) {
        return result;
    }

    alloc_ffi_fail_next_calloc = 1;
    child = alloc_ffi_forced_smb2_alloc_data((struct smb2_context *)&result, memctx, child_size);

    result.returned_null = child == NULL;
    result.set_error_called = alloc_ffi_set_error_called;
    snprintf(result.message, sizeof(result.message), "%s", alloc_ffi_set_error_message);

    alloc_ffi_forced_smb2_free_data(NULL, memctx);
    return result;
}
