#include "asprintf_ffi.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define vasprintf asprintf_ffi_system_vasprintf
#define asprintf asprintf_ffi_system_asprintf
#include <stdio.h>
#undef asprintf
#undef vasprintf

static int asprintf_ffi_force_malloc_failure;

static void *asprintf_ffi_malloc_maybe_fail(size_t size) {
    if (asprintf_ffi_force_malloc_failure) {
        return NULL;
    }
    return malloc(size);
}

#define __AROS__ 1
#define malloc asprintf_ffi_malloc_maybe_fail
#define inline
#include "asprintf.h"
#undef inline
#undef malloc

static int call_alloc_fail_vasprintf(char **strp, const char *format, ...) {
    int rc;
    va_list ap;
    va_start(ap, format);
    rc = vasprintf(strp, format, ap);
    va_end(ap);
    return rc;
}

int asprintf_ffi_vasprintf_forced_alloc_failure(char **strp) {
    char *allocated = malloc(4);
    if (allocated == NULL) {
        return -2;
    }
    memcpy(allocated, "old", 4);
    *strp = allocated;
    asprintf_ffi_force_malloc_failure = 1;
    int rc = call_alloc_fail_vasprintf(strp, "%d", 7);
    asprintf_ffi_force_malloc_failure = 0;
    return rc;
}
