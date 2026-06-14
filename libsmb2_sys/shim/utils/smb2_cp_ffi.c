#include "smb2_cp_ffi.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

static int cp_close_calls;
static int cp_smb2_close_calls;
static int cp_destroy_context_calls;
static int cp_destroy_url_calls;
static int cp_init_calls;
static int cp_parse_calls;
static int cp_connect_calls;
static int cp_open_calls;
static long cp_last_offset;
static unsigned long cp_last_count;

int smb2_cp_ffi_fake_close(int fd);
int smb2_cp_ffi_fake_smb2_close(struct smb2_context *smb2, struct smb2fh *fh);
void smb2_cp_ffi_fake_smb2_destroy_context(struct smb2_context *smb2);
void smb2_cp_ffi_fake_smb2_destroy_url(struct smb2_url *url);
int smb2_cp_ffi_fake_smb2_fstat(struct smb2_context *smb2, struct smb2fh *fh,
                                struct smb2_stat_64 *st);
ssize_t smb2_cp_ffi_fake_smb2_pread(struct smb2_context *smb2, struct smb2fh *fh,
                                    uint8_t *buf, size_t count, uint64_t offset);
ssize_t smb2_cp_ffi_fake_smb2_pwrite(struct smb2_context *smb2, struct smb2fh *fh,
                                     const uint8_t *buf, size_t count, uint64_t offset);
struct smb2_context *smb2_cp_ffi_fake_smb2_init_context(void);
struct smb2_url *smb2_cp_ffi_fake_smb2_parse_url(struct smb2_context *smb2,
                                                 const char *url);
int smb2_cp_ffi_fake_smb2_connect_share(struct smb2_context *smb2,
                                        const char *server, const char *share,
                                        const char *user);
struct smb2fh *smb2_cp_ffi_fake_smb2_open(struct smb2_context *smb2,
                                          const char *path, int flags);
const char *smb2_cp_ffi_fake_smb2_get_error(struct smb2_context *smb2);

#define main smb2_cp_legacy_main
#define usage smb2_cp_legacy_usage
#define close smb2_cp_ffi_fake_close
#define smb2_close smb2_cp_ffi_fake_smb2_close
#define smb2_destroy_context smb2_cp_ffi_fake_smb2_destroy_context
#define smb2_destroy_url smb2_cp_ffi_fake_smb2_destroy_url
#define smb2_fstat smb2_cp_ffi_fake_smb2_fstat
#define smb2_pread smb2_cp_ffi_fake_smb2_pread
#define smb2_pwrite smb2_cp_ffi_fake_smb2_pwrite
#define smb2_init_context smb2_cp_ffi_fake_smb2_init_context
#define smb2_parse_url smb2_cp_ffi_fake_smb2_parse_url
#define smb2_connect_share smb2_cp_ffi_fake_smb2_connect_share
#define smb2_open smb2_cp_ffi_fake_smb2_open
#define smb2_get_error smb2_cp_ffi_fake_smb2_get_error
#include "../../../utils/smb2-cp.c"
#undef smb2_get_error
#undef smb2_open
#undef smb2_connect_share
#undef smb2_parse_url
#undef smb2_init_context
#undef smb2_pwrite
#undef smb2_pread
#undef smb2_fstat
#undef smb2_destroy_url
#undef smb2_destroy_context
#undef smb2_close
#undef close
#undef usage
#undef main

int smb2_cp_ffi_fake_close(int fd)
{
        cp_close_calls++;
        return close(fd);
}

int smb2_cp_ffi_fake_smb2_close(struct smb2_context *smb2, struct smb2fh *fh)
{
        (void)smb2;
        (void)fh;
        cp_smb2_close_calls++;
        return 0;
}

void smb2_cp_ffi_fake_smb2_destroy_context(struct smb2_context *smb2)
{
        (void)smb2;
        cp_destroy_context_calls++;
}

void smb2_cp_ffi_fake_smb2_destroy_url(struct smb2_url *url)
{
        cp_destroy_url_calls++;
        if (url != NULL) {
                free(url->server);
                free(url->share);
                free(url->user);
                free(url->path);
                free(url);
        }
}

int smb2_cp_ffi_fake_smb2_fstat(struct smb2_context *smb2, struct smb2fh *fh,
                                struct smb2_stat_64 *st)
{
        (void)smb2;
        (void)fh;
        memset(st, 0, sizeof(*st));
        st->smb2_ino = 77;
        st->smb2_nlink = 3;
        st->smb2_size = 12345;
        st->smb2_atime = 11;
        st->smb2_mtime = 22;
        st->smb2_ctime = 33;
        return 0;
}

ssize_t smb2_cp_ffi_fake_smb2_pread(struct smb2_context *smb2, struct smb2fh *fh,
                                    uint8_t *buf, size_t count, uint64_t offset)
{
        (void)smb2;
        (void)fh;
        cp_last_offset = (long)offset;
        cp_last_count = (unsigned long)count;
        memcpy(buf, "smb2-read", count < 9 ? count : 9);
        return (ssize_t)count;
}

ssize_t smb2_cp_ffi_fake_smb2_pwrite(struct smb2_context *smb2, struct smb2fh *fh,
                                     const uint8_t *buf, size_t count, uint64_t offset)
{
        (void)smb2;
        (void)fh;
        (void)buf;
        cp_last_offset = (long)offset;
        cp_last_count = (unsigned long)count;
        return (ssize_t)count;
}

struct smb2_context *smb2_cp_ffi_fake_smb2_init_context(void)
{
        cp_init_calls++;
        return (struct smb2_context *)0x1001;
}

struct smb2_url *smb2_cp_ffi_fake_smb2_parse_url(struct smb2_context *smb2,
                                                 const char *url)
{
        struct smb2_url *parsed;
        (void)smb2;
        (void)url;
        cp_parse_calls++;
        parsed = calloc(1, sizeof(*parsed));
        if (parsed == NULL) {
                return NULL;
        }
        parsed->server = strdup("server");
        parsed->share = strdup("share");
        parsed->user = strdup("user");
        parsed->path = strdup("path");
        return parsed;
}

int smb2_cp_ffi_fake_smb2_connect_share(struct smb2_context *smb2,
                                        const char *server, const char *share,
                                        const char *user)
{
        (void)smb2;
        (void)server;
        (void)share;
        (void)user;
        cp_connect_calls++;
        return 0;
}

struct smb2fh *smb2_cp_ffi_fake_smb2_open(struct smb2_context *smb2,
                                          const char *path, int flags)
{
        (void)smb2;
        (void)path;
        (void)flags;
        cp_open_calls++;
        return (struct smb2fh *)0x1002;
}

const char *smb2_cp_ffi_fake_smb2_get_error(struct smb2_context *smb2)
{
        (void)smb2;
        return "injected error";
}

static void cp_reset(void)
{
        cp_close_calls = 0;
        cp_smb2_close_calls = 0;
        cp_destroy_context_calls = 0;
        cp_destroy_url_calls = 0;
        cp_init_calls = 0;
        cp_parse_calls = 0;
        cp_connect_calls = 0;
        cp_open_calls = 0;
        cp_last_offset = -1;
        cp_last_count = 0;
}

static void cp_read_fd(int fd, char *buf, int *len)
{
        ssize_t n = read(fd, buf, 511);
        if (n < 0) {
                n = 0;
        }
        buf[n] = 0;
        *len = (int)n;
}

static void cp_capture_usage(struct smb2_cp_ffi_process_result *out)
{
        int err_pipe[2];
        pid_t pid;
        memset(out, 0, sizeof(*out));
        pipe(err_pipe);
        pid = fork();
        if (pid == 0) {
                close(err_pipe[0]);
                dup2(err_pipe[1], STDERR_FILENO);
                close(err_pipe[1]);
                smb2_cp_legacy_usage();
                _exit(127);
        }
        close(err_pipe[1]);
        cp_read_fd(err_pipe[0], out->stderr_text, &out->stderr_len);
        close(err_pipe[0]);
        waitpid(pid, &out->exit_code, 0);
        if (WIFEXITED(out->exit_code)) {
                out->exit_code = WEXITSTATUS(out->exit_code);
        }
}

static void cp_capture_main(char *const argv[], struct smb2_cp_ffi_process_result *out)
{
        int out_pipe[2];
        int err_pipe[2];
        pid_t pid;
        memset(out, 0, sizeof(*out));
        pipe(out_pipe);
        pipe(err_pipe);
        pid = fork();
        if (pid == 0) {
                close(out_pipe[0]);
                close(err_pipe[0]);
                dup2(out_pipe[1], STDOUT_FILENO);
                dup2(err_pipe[1], STDERR_FILENO);
                close(out_pipe[1]);
                close(err_pipe[1]);
                _exit(smb2_cp_legacy_main(3, argv));
        }
        close(out_pipe[1]);
        close(err_pipe[1]);
        cp_read_fd(out_pipe[0], out->stdout_text, &out->stdout_len);
        cp_read_fd(err_pipe[0], out->stderr_text, &out->stderr_len);
        close(out_pipe[0]);
        close(err_pipe[0]);
        waitpid(pid, &out->exit_code, 0);
        if (WIFEXITED(out->exit_code)) {
                out->exit_code = WEXITSTATUS(out->exit_code);
        }
}

void smb2_cp_ffi_usage_invalid_argc(struct smb2_cp_ffi_process_result *out)
{
        cp_capture_usage(out);
}

void smb2_cp_ffi_free_mixed(struct smb2_cp_ffi_cleanup_result *out)
{
        struct file_context *fc;
        cp_reset();
        fc = calloc(1, sizeof(*fc));
        fc->fd = -1;
        fc->smb2 = (struct smb2_context *)0x1001;
        fc->smb2fh = (struct smb2fh *)0x1002;
        fc->url = smb2_cp_ffi_fake_smb2_parse_url(fc->smb2, "smb://server/share/path");
        free_file_context(fc);
        out->close_calls = cp_close_calls;
        out->smb2_close_calls = cp_smb2_close_calls;
        out->destroy_context_calls = cp_destroy_context_calls;
        out->destroy_url_calls = cp_destroy_url_calls;
}

void smb2_cp_ffi_fstat_smb2(struct smb2_cp_ffi_stat_result *out)
{
        struct file_context fc;
        struct stat st;
        memset(&fc, 0, sizeof(fc));
        memset(&st, 0, sizeof(st));
        fc.is_smb2 = 1;
        out->rc = fstat_file(&fc, &st);
        out->ino = (uint64_t)st.st_ino;
        out->size = (uint64_t)st.st_size;
        out->atime = (uint64_t)st.st_atime;
        out->mtime = (uint64_t)st.st_mtime;
        out->ctime = (uint64_t)st.st_ctime;
}

void smb2_cp_ffi_pread_local(struct smb2_cp_ffi_io_result *out)
{
        FILE *tmp = tmpfile();
        struct file_context fc;
        memset(out, 0, sizeof(*out));
        fputs("abcdef", tmp);
        fflush(tmp);
        fc.is_smb2 = 0;
        fc.fd = fileno(tmp);
        out->rc = file_pread(&fc, (uint8_t *)out->bytes, 3, 2);
        out->offset = 2;
        out->count = 3;
        fclose(tmp);
}

void smb2_cp_ffi_pread_smb2(struct smb2_cp_ffi_io_result *out)
{
        struct file_context fc;
        memset(out, 0, sizeof(*out));
        fc.is_smb2 = 1;
        out->rc = file_pread(&fc, (uint8_t *)out->bytes, 4, 9);
        out->offset = cp_last_offset;
        out->count = cp_last_count;
}

void smb2_cp_ffi_pwrite_local(struct smb2_cp_ffi_io_result *out)
{
        FILE *tmp = tmpfile();
        struct file_context fc;
        const uint8_t bytes[] = {'X', 'Y', 'Z'};
        memset(out, 0, sizeof(*out));
        fputs("abcdef", tmp);
        fflush(tmp);
        fc.is_smb2 = 0;
        fc.fd = fileno(tmp);
        out->rc = file_pwrite(&fc, (uint8_t *)bytes, 3, 2);
        lseek(fc.fd, 0, SEEK_SET);
        read(fc.fd, out->bytes, 6);
        out->rc = 6;
        out->offset = 2;
        out->count = 3;
        fclose(tmp);
}

void smb2_cp_ffi_pwrite_smb2(struct smb2_cp_ffi_io_result *out)
{
        struct file_context fc;
        uint8_t bytes[] = {'X', 'Y', 'Z'};
        memset(out, 0, sizeof(*out));
        fc.is_smb2 = 1;
        out->rc = file_pwrite(&fc, bytes, 3, 7);
        out->offset = cp_last_offset;
        out->count = cp_last_count;
}

void smb2_cp_ffi_open_local(const char *path, struct smb2_cp_ffi_open_result *out)
{
        struct file_context *fc;
        cp_reset();
        memset(out, 0, sizeof(*out));
        fc = open_file(path, O_RDONLY);
        if (fc != NULL) {
                out->success = 1;
                out->is_smb2 = fc->is_smb2;
                out->fd_valid = fc->fd != -1;
                free_file_context(fc);
        }
}

void smb2_cp_ffi_open_smb2(struct smb2_cp_ffi_open_result *out)
{
        struct file_context *fc;
        cp_reset();
        memset(out, 0, sizeof(*out));
        fc = open_file("smb://server/share/path", O_RDONLY);
        if (fc != NULL) {
                out->success = 1;
                out->is_smb2 = fc->is_smb2;
                out->fd_valid = fc->fd != -1;
                free_file_context(fc);
        }
        out->init_calls = cp_init_calls;
        out->parse_calls = cp_parse_calls;
        out->connect_calls = cp_connect_calls;
        out->open_calls = cp_open_calls;
}

void smb2_cp_ffi_run_local_copy(const char *src, const char *dst,
                                struct smb2_cp_ffi_process_result *out)
{
        char *argv[] = {"smb2-cp", (char *)src, (char *)dst, NULL};
        cp_capture_main(argv, out);
}

void smb2_cp_ffi_run_copy_failure(const char *src, const char *dst,
                                  struct smb2_cp_ffi_process_result *out)
{
        char *argv[] = {"smb2-cp", (char *)src, (char *)dst, NULL};
        cp_capture_main(argv, out);
}

void smb2_cp_ffi_chunk_plan(uint64_t file_size, struct smb2_cp_ffi_chunk_result *out)
{
        uint64_t off = 0;
        memset(out, 0, sizeof(*out));
        while (off < file_size) {
                unsigned long count = (unsigned long)(file_size - off);
                if (count > BUFSIZE) {
                        count = BUFSIZE;
                }
                if (out->chunks == 0) {
                        out->first_count = count;
                }
                out->last_count = count;
                out->chunks++;
                off += count;
        }
}
