#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct asprintf_ffi_result {
    int rc;
    char *data;
};

struct asprintf_ffi_format_failure_result {
    int rc;
    int free_count;
};

int asprintf_ffi_vscprintf_two_ints(const char *format, int first, int second);
int asprintf_ffi_vscprintf_reuse_after_length(const char *format, int first, int second);
struct asprintf_ffi_result asprintf_ffi_vasprintf_two_ints(const char *format, int first, int second);
struct asprintf_ffi_result asprintf_ffi_asprintf_two_ints(const char *format, int first, int second);
int asprintf_ffi_vasprintf_null_format(void);
int asprintf_ffi_vasprintf_length_failure(char **strp);
int asprintf_ffi_vasprintf_forced_alloc_failure(char **strp);
struct asprintf_ffi_format_failure_result asprintf_ffi_vasprintf_forced_format_failure(void);
void asprintf_ffi_free(char *data);
int asprintf_ffi_xbox_inline_maps_to___inline(void);

#ifdef __cplusplus
}
#endif
