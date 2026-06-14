#include "unicode_fault_ffi.h"

#include <stddef.h>
#include <stdlib.h>

static int unicode_ffi_fail_after = -1;

static void *unicode_ffi_fault_malloc(size_t size)
{
        if (unicode_ffi_fail_after == 0) {
                return NULL;
        }
        if (unicode_ffi_fail_after > 0) {
                unicode_ffi_fail_after--;
        }
        return malloc(size);
}

#define malloc unicode_ffi_fault_malloc
#define smb2_utf8_to_utf16 unicode_ffi_fault_utf8_to_utf16
#define smb2_utf16_to_utf8 unicode_ffi_fault_utf16_to_utf8
#include "../../../lib/unicode.c"
#undef smb2_utf16_to_utf8
#undef smb2_utf8_to_utf16
#undef malloc

int unicode_ffi_utf8_to_utf16_alloc_failure(void)
{
        struct smb2_utf16 *result;

        unicode_ffi_fail_after = 0;
        result = unicode_ffi_fault_utf8_to_utf16("ok");
        unicode_ffi_fail_after = -1;
        if (result != NULL) {
                free(result);
                return 0;
        }
        return 1;
}

int unicode_ffi_utf16_to_utf8_alloc_failure(void)
{
        uint16_t input[] = {0x004f, 0x004b};
        const char *result;

        unicode_ffi_fail_after = 0;
        result = unicode_ffi_fault_utf16_to_utf8(input, 2);
        unicode_ffi_fail_after = -1;
        if (result != NULL) {
                free((void *)result);
                return 0;
        }
        return 1;
}
