#include "compat_ffi.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef SSIZE_MAX
#define SSIZE_MAX ((ssize_t)(((size_t)-1) >> 1))
#endif

#define NEED_GETADDRINFO
#define NEED_FREEADDRINFO
#define NEED_WRITEV
#define NEED_READV
#define NEED_POLL
#define NEED_STRDUP

#define smb2_getaddrinfo compat_ffi_smb2_getaddrinfo
#define smb2_freeaddrinfo compat_ffi_smb2_freeaddrinfo
#define writev compat_ffi_writev
#define readv compat_ffi_readv
#define poll compat_ffi_poll
#define strdup compat_ffi_strdup

#include "../../../lib/compat.c"

int compat_ffi_resolve_ipv4(const char *node, const char *service,
                            struct compat_ffi_addrinfo_snapshot *snapshot)
{
        struct addrinfo *res = NULL;
        struct sockaddr_in *sin;
        int rc;

        if (snapshot == NULL) {
                errno = EINVAL;
                return -1;
        }

        rc = compat_ffi_smb2_getaddrinfo(node, service, NULL, &res);
        if (rc != 0) {
                return rc;
        }
        if (res == NULL || res->ai_addr == NULL) {
                if (res != NULL) {
                        compat_ffi_smb2_freeaddrinfo(res);
                }
                errno = EINVAL;
                return -1;
        }

        sin = (struct sockaddr_in *)res->ai_addr;
        snapshot->ai_family = res->ai_family;
        snapshot->ai_addrlen = res->ai_addrlen;
        snapshot->ai_next_is_null = res->ai_next == NULL;
        snapshot->port_host_order = ntohs(sin->sin_port);
        snapshot->addr_host_order = ntohl(sin->sin_addr.s_addr);

        compat_ffi_smb2_freeaddrinfo(res);
        return 0;
}

ssize_t compat_ffi_writev_to_pipe(const struct compat_ffi_iovec_input *chunks,
                                  size_t count, unsigned char *out,
                                  size_t out_len, size_t *bytes_read,
                                  int *err_out)
{
        struct iovec iov[64];
        int fds[2];
        size_t i;
        ssize_t written;
        ssize_t read_rc;
        int saved_errno;

        if (count > 64) {
                errno = EINVAL;
                if (err_out != NULL) {
                        *err_out = errno;
                }
                return -1;
        }
        if (pipe(fds) != 0) {
                if (err_out != NULL) {
                        *err_out = errno;
                }
                return -1;
        }

        for (i = 0; i < count; i++) {
                iov[i].iov_base = (void *)chunks[i].ptr;
                iov[i].iov_len = chunks[i].len;
        }

        errno = 0;
        written = compat_ffi_writev(fds[1], iov, (int)count);
        saved_errno = errno;
        close(fds[1]);

        read_rc = read(fds[0], out, out_len);
        close(fds[0]);

        if (bytes_read != NULL) {
                *bytes_read = read_rc > 0 ? (size_t)read_rc : 0;
        }
        if (err_out != NULL) {
                *err_out = saved_errno;
        }
        return written;
}

ssize_t compat_ffi_readv_from_pipe(const unsigned char *input, size_t input_len,
                                   const size_t *lens, size_t count,
                                   unsigned char *out, size_t out_len,
                                   int *err_out)
{
        struct iovec iov[64];
        int fds[2];
        size_t i;
        size_t offset = 0;
        ssize_t read_rc;
        int saved_errno;

        if (count > 64) {
                errno = EINVAL;
                if (err_out != NULL) {
                        *err_out = errno;
                }
                return -1;
        }
        for (i = 0; i < count; i++) {
                if (lens[i] > out_len - offset) {
                        errno = EINVAL;
                        if (err_out != NULL) {
                                *err_out = errno;
                        }
                        return -1;
                }
                iov[i].iov_base = out + offset;
                iov[i].iov_len = lens[i];
                offset += lens[i];
        }

        if (pipe(fds) != 0) {
                if (err_out != NULL) {
                        *err_out = errno;
                }
                return -1;
        }
        if (write(fds[1], input, input_len) < 0) {
                saved_errno = errno;
                close(fds[0]);
                close(fds[1]);
                if (err_out != NULL) {
                        *err_out = saved_errno;
                }
                return -1;
        }
        close(fds[1]);

        errno = 0;
        read_rc = compat_ffi_readv(fds[0], iov, (int)count);
        saved_errno = errno;
        close(fds[0]);

        if (err_out != NULL) {
                *err_out = saved_errno;
        }
        return read_rc;
}

int compat_ffi_writev_overflow_sets_einval(void)
{
        struct iovec iov[2];

        iov[0].iov_base = NULL;
        iov[0].iov_len = (size_t)-1;
        iov[1].iov_base = NULL;
        iov[1].iov_len = 1;

        errno = 0;
        return compat_ffi_writev(-1, iov, 2) == -1 && errno == EINVAL;
}

int compat_ffi_readv_overflow_sets_einval(void)
{
        struct iovec iov[2];

        iov[0].iov_base = NULL;
        iov[0].iov_len = (size_t)-1;
        iov[1].iov_base = NULL;
        iov[1].iov_len = 1;

        errno = 0;
        return compat_ffi_readv(-1, iov, 2) == -1 && errno == EINVAL;
}

int compat_ffi_poll_readable_pipe(struct compat_ffi_poll_snapshot *snapshot)
{
        int fds[2];
        struct pollfd pfd;
        char byte = 'x';

        if (snapshot == NULL) {
                errno = EINVAL;
                return -1;
        }
        if (pipe(fds) != 0) {
                return -1;
        }
        if (write(fds[1], &byte, 1) != 1) {
                close(fds[0]);
                close(fds[1]);
                return -1;
        }

        pfd.fd = fds[0];
        pfd.events = POLLIN;
        pfd.revents = (short)0x7fff;
        errno = 0;
        snapshot->rc = compat_ffi_poll(&pfd, 1, 0);
        snapshot->err = errno;
        snapshot->revents = pfd.revents;

        close(fds[0]);
        close(fds[1]);
        return 0;
}

int compat_ffi_poll_writable_pipe(struct compat_ffi_poll_snapshot *snapshot)
{
        int fds[2];
        struct pollfd pfd;

        if (snapshot == NULL) {
                errno = EINVAL;
                return -1;
        }
        if (pipe(fds) != 0) {
                return -1;
        }

        pfd.fd = fds[1];
        pfd.events = POLLOUT;
        pfd.revents = (short)0x7fff;
        errno = 0;
        snapshot->rc = compat_ffi_poll(&pfd, 1, 0);
        snapshot->err = errno;
        snapshot->revents = pfd.revents;

        close(fds[0]);
        close(fds[1]);
        return 0;
}

int compat_ffi_strdup_matches(const char *input, size_t *len_out)
{
        char *copy = compat_ffi_strdup(input);
        int matches;

        if (copy == NULL) {
                return 0;
        }
        matches = strcmp(copy, input) == 0 && copy != input;
        if (len_out != NULL) {
                *len_out = strlen(copy);
        }
        free(copy);
        return matches;
}
