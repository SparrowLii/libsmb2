#include "asprintf_ffi.h"

#include <stdarg.h>
#include <stddef.h>

#define vasprintf asprintf_ffi_system_vasprintf
#define asprintf asprintf_ffi_system_asprintf
#include <stdio.h>
#undef asprintf
#undef vasprintf
#undef vsnprintf

static int asprintf_ffi_vsnprintf_length_failure(char *str, size_t size, const char *format, va_list ap) {
    (void)str;
    (void)size;
    (void)format;
    (void)ap;
    return -1;
}

#define __AROS__ 1
#define vsnprintf asprintf_ffi_vsnprintf_length_failure
#define inline
#include "asprintf.h"
#undef inline
#undef vsnprintf

static int call_length_fail_vasprintf(char **strp, const char *format, ...) {
    int rc;
    va_list ap;
    va_start(ap, format);
    rc = vasprintf(strp, format, ap);
    va_end(ap);
    return rc;
}

int asprintf_ffi_vasprintf_length_failure(char **strp) {
    return call_length_fail_vasprintf(strp, "%d", 7);
}
