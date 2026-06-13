#include "asprintf_ffi.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

#define vasprintf asprintf_ffi_system_vasprintf
#define asprintf asprintf_ffi_system_asprintf
#include <stdio.h>
#undef asprintf
#undef vasprintf
#undef vsnprintf

static int asprintf_ffi_final_fail_free_count;

static int asprintf_ffi_vsnprintf_final_failure(char *str, size_t size, const char *format, va_list ap) {
    (void)size;
    (void)format;
    (void)ap;
    return str == NULL ? 4 : -1;
}

static void asprintf_ffi_tracking_free(void *ptr) {
    asprintf_ffi_final_fail_free_count++;
    free(ptr);
}

#define __AROS__ 1
#define vsnprintf asprintf_ffi_vsnprintf_final_failure
#define free asprintf_ffi_tracking_free
#define inline
#include "asprintf.h"
#undef inline
#undef free
#undef vsnprintf

static int call_format_fail_vasprintf(char **strp, const char *format, ...) {
    int rc;
    va_list ap;
    va_start(ap, format);
    rc = vasprintf(strp, format, ap);
    va_end(ap);
    return rc;
}

struct asprintf_ffi_format_failure_result asprintf_ffi_vasprintf_forced_format_failure(void) {
    struct asprintf_ffi_format_failure_result result;
    char *str = NULL;
    asprintf_ffi_final_fail_free_count = 0;
    result.rc = call_format_fail_vasprintf(&str, "%d", 7);
    result.free_count = asprintf_ffi_final_fail_free_count;
    return result;
}
