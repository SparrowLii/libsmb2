#ifndef LIBSMB2_SYS_UNICODE_FAULT_FFI_H
#define LIBSMB2_SYS_UNICODE_FAULT_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

int unicode_ffi_utf8_to_utf16_alloc_failure(void);
int unicode_ffi_utf16_to_utf8_alloc_failure(void);

#ifdef __cplusplus
}
#endif

#endif
