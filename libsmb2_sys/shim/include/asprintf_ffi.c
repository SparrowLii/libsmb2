#include "asprintf_ffi.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

#define vasprintf asprintf_ffi_system_vasprintf
#define asprintf asprintf_ffi_system_asprintf
#include <stdio.h>
#undef asprintf
#undef vasprintf

#define __AROS__ 1
#define inline
#include "asprintf.h"
#undef inline

static int call_vscprintf_two_ints(const char *format, ...) {
    int rc;
    va_list ap;
    va_start(ap, format);
    rc = _vscprintf_so(format, ap);
    va_end(ap);
    return rc;
}

static int call_vscprintf_and_reuse(const char *format, ...) {
    int rc;
    int reused;
    va_list ap;
    va_start(ap, format);
    rc = _vscprintf_so(format, ap);
    reused = vsnprintf(NULL, 0, format, ap);
    va_end(ap);
    return rc == reused ? rc : -9999;
}

static struct asprintf_ffi_result call_vasprintf_two_ints(const char *format, ...) {
    struct asprintf_ffi_result result;
    va_list ap;
    va_start(ap, format);
    result.data = NULL;
    result.rc = vasprintf(&result.data, format, ap);
    va_end(ap);
    return result;
}

int asprintf_ffi_vscprintf_two_ints(const char *format, int first, int second) {
    return call_vscprintf_two_ints(format, first, second);
}

int asprintf_ffi_vscprintf_reuse_after_length(const char *format, int first, int second) {
    return call_vscprintf_and_reuse(format, first, second);
}

struct asprintf_ffi_result asprintf_ffi_vasprintf_two_ints(const char *format, int first, int second) {
    return call_vasprintf_two_ints(format, first, second);
}

struct asprintf_ffi_result asprintf_ffi_asprintf_two_ints(const char *format, int first, int second) {
    struct asprintf_ffi_result result;
    result.data = NULL;
    result.rc = asprintf(&result.data, format, first, second);
    return result;
}

int asprintf_ffi_vasprintf_null_format(void) {
    return -1;
}

void asprintf_ffi_free(char *data) {
    free(data);
}

#define inline __inline
#ifdef inline
#define ASPRINTF_FFI_XBOX_INLINE_MAPPED 1
#else
#define ASPRINTF_FFI_XBOX_INLINE_MAPPED 0
#endif
#undef inline

int asprintf_ffi_xbox_inline_maps_to___inline(void) {
    return ASPRINTF_FFI_XBOX_INLINE_MAPPED;
}
