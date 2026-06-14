#ifndef LIBSMB2_SYS_COMPAT_FFI_H
#define LIBSMB2_SYS_COMPAT_FFI_H

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct compat_ffi_addrinfo_snapshot {
        int ai_family;
        size_t ai_addrlen;
        int ai_next_is_null;
        unsigned short port_host_order;
        unsigned int addr_host_order;
};

struct compat_ffi_iovec_input {
        const unsigned char *ptr;
        size_t len;
};

struct compat_ffi_poll_snapshot {
        int rc;
        int err;
        short revents;
};

int compat_ffi_resolve_ipv4(const char *node, const char *service,
                            struct compat_ffi_addrinfo_snapshot *snapshot);
ssize_t compat_ffi_writev_to_pipe(const struct compat_ffi_iovec_input *chunks,
                                  size_t count, unsigned char *out,
                                  size_t out_len, size_t *bytes_read,
                                  int *err_out);
ssize_t compat_ffi_readv_from_pipe(const unsigned char *input, size_t input_len,
                                   const size_t *lens, size_t count,
                                   unsigned char *out, size_t out_len,
                                   int *err_out);
int compat_ffi_writev_overflow_sets_einval(void);
int compat_ffi_readv_overflow_sets_einval(void);
int compat_ffi_writev_allocation_failure_returns_minus_one(void);
int compat_ffi_readv_allocation_failure_returns_minus_one(void);
int compat_ffi_strdup_allocation_failure_returns_null(void);
int compat_ffi_poll_readable_pipe(struct compat_ffi_poll_snapshot *snapshot);
int compat_ffi_poll_writable_pipe(struct compat_ffi_poll_snapshot *snapshot);
int compat_ffi_strdup_matches(const char *input, size_t *len_out);

#ifdef __cplusplus
}
#endif

#endif
