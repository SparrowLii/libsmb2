#include <stddef.h>

struct alloc_ffi_child_failure_result {
    int returned_null;
    int set_error_called;
    char message[128];
};

int alloc_ffi_forced_init_failure_returns_null(size_t size);
struct alloc_ffi_child_failure_result alloc_ffi_forced_child_failure(size_t child_size);
