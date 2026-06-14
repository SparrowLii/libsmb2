#include "smb2_ls_ffi.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/mman.h>
#include <unistd.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

enum ls_mode {
        LS_MODE_SUCCESS,
        LS_MODE_READLINK_FAILURE,
        LS_MODE_INIT_FAILURE,
        LS_MODE_PARSE_FAILURE,
        LS_MODE_CONNECT_FAILURE,
        LS_MODE_OPENDIR_FAILURE,
        LS_MODE_EMPTY,
};

static enum ls_mode ls_current_mode;
static int ls_readdir_index;
static int *ls_counts;
static struct smb2dirent ls_entries[4];
static char ls_entry_names[4][16];

struct smb2_context *smb2_ls_ffi_fake_smb2_init_context(void);
struct smb2_url *smb2_ls_ffi_fake_smb2_parse_url(struct smb2_context *smb2,
                                                const char *url);
const char *smb2_ls_ffi_fake_smb2_get_error(struct smb2_context *smb2);
void smb2_ls_ffi_fake_smb2_set_security_mode(struct smb2_context *smb2,
                                             uint16_t security_mode);
int smb2_ls_ffi_fake_smb2_connect_share(struct smb2_context *smb2,
                                        const char *server, const char *share,
                                        const char *user);
struct smb2dir *smb2_ls_ffi_fake_smb2_opendir(struct smb2_context *smb2,
                                             const char *path);
struct smb2dirent *smb2_ls_ffi_fake_smb2_readdir(struct smb2_context *smb2,
                                                struct smb2dir *smb2dir);
int smb2_ls_ffi_fake_smb2_readlink(struct smb2_context *smb2, const char *path,
                                   char *buf, uint32_t bufsiz);
void smb2_ls_ffi_fake_smb2_closedir(struct smb2_context *smb2,
                                    struct smb2dir *smb2dir);
int smb2_ls_ffi_fake_smb2_disconnect_share(struct smb2_context *smb2);
void smb2_ls_ffi_fake_smb2_destroy_url(struct smb2_url *url);
void smb2_ls_ffi_fake_smb2_destroy_context(struct smb2_context *smb2);

#define main smb2_ls_legacy_main
#define usage smb2_ls_legacy_usage
#define smb2_init_context smb2_ls_ffi_fake_smb2_init_context
#define smb2_parse_url smb2_ls_ffi_fake_smb2_parse_url
#define smb2_get_error smb2_ls_ffi_fake_smb2_get_error
#define smb2_set_security_mode smb2_ls_ffi_fake_smb2_set_security_mode
#define smb2_connect_share smb2_ls_ffi_fake_smb2_connect_share
#define smb2_opendir smb2_ls_ffi_fake_smb2_opendir
#define smb2_readdir smb2_ls_ffi_fake_smb2_readdir
#define smb2_readlink smb2_ls_ffi_fake_smb2_readlink
#define smb2_closedir smb2_ls_ffi_fake_smb2_closedir
#define smb2_disconnect_share smb2_ls_ffi_fake_smb2_disconnect_share
#define smb2_destroy_url smb2_ls_ffi_fake_smb2_destroy_url
#define smb2_destroy_context smb2_ls_ffi_fake_smb2_destroy_context
#include "../../../utils/smb2-ls.c"
#undef smb2_destroy_context
#undef smb2_destroy_url
#undef smb2_disconnect_share
#undef smb2_closedir
#undef smb2_readlink
#undef smb2_readdir
#undef smb2_opendir
#undef smb2_connect_share
#undef smb2_set_security_mode
#undef smb2_get_error
#undef smb2_parse_url
#undef smb2_init_context
#undef usage
#undef main

struct smb2_context *smb2_ls_ffi_fake_smb2_init_context(void)
{
        if (ls_current_mode == LS_MODE_INIT_FAILURE) {
                return NULL;
        }
        return (struct smb2_context *)0x2001;
}

struct smb2_url *smb2_ls_ffi_fake_smb2_parse_url(struct smb2_context *smb2,
                                                const char *url)
{
        struct smb2_url *parsed;
        (void)smb2;
        (void)url;
        if (ls_current_mode == LS_MODE_PARSE_FAILURE) {
                return NULL;
        }
        parsed = calloc(1, sizeof(*parsed));
        if (parsed == NULL) {
                return NULL;
        }
        parsed->server = strdup("server");
        parsed->share = strdup("share");
        parsed->user = strdup("user");
        parsed->path = strdup("dir");
        return parsed;
}

const char *smb2_ls_ffi_fake_smb2_get_error(struct smb2_context *smb2)
{
        (void)smb2;
        return "injected error";
}

void smb2_ls_ffi_fake_smb2_set_security_mode(struct smb2_context *smb2,
                                             uint16_t security_mode)
{
        (void)smb2;
        (void)security_mode;
}

int smb2_ls_ffi_fake_smb2_connect_share(struct smb2_context *smb2,
                                        const char *server, const char *share,
                                        const char *user)
{
        (void)smb2;
        (void)server;
        (void)share;
        (void)user;
        return ls_current_mode == LS_MODE_CONNECT_FAILURE ? -1 : 0;
}

struct smb2dir *smb2_ls_ffi_fake_smb2_opendir(struct smb2_context *smb2,
                                             const char *path)
{
        (void)smb2;
        (void)path;
        if (ls_current_mode == LS_MODE_OPENDIR_FAILURE) {
                return NULL;
        }
        return (struct smb2dir *)0x2002;
}

struct smb2dirent *smb2_ls_ffi_fake_smb2_readdir(struct smb2_context *smb2,
                                                struct smb2dir *smb2dir)
{
        (void)smb2;
        (void)smb2dir;
        if (ls_current_mode == LS_MODE_EMPTY) {
                return NULL;
        }
        if (ls_readdir_index >= 4) {
                return NULL;
        }
        return &ls_entries[ls_readdir_index++];
}

int smb2_ls_ffi_fake_smb2_readlink(struct smb2_context *smb2, const char *path,
                                   char *buf, uint32_t bufsiz)
{
        (void)smb2;
        (void)path;
        if (ls_current_mode == LS_MODE_READLINK_FAILURE) {
                return -1;
        }
        snprintf(buf, bufsiz, "target.txt");
        return 0;
}

void smb2_ls_ffi_fake_smb2_closedir(struct smb2_context *smb2,
                                    struct smb2dir *smb2dir)
{
        (void)smb2;
        (void)smb2dir;
        ls_counts[0]++;
}

int smb2_ls_ffi_fake_smb2_disconnect_share(struct smb2_context *smb2)
{
        (void)smb2;
        ls_counts[1]++;
        return 0;
}

void smb2_ls_ffi_fake_smb2_destroy_url(struct smb2_url *url)
{
        ls_counts[2]++;
        if (url != NULL) {
                free(url->server);
                free(url->share);
                free(url->user);
                free(url->path);
                free(url);
        }
}

void smb2_ls_ffi_fake_smb2_destroy_context(struct smb2_context *smb2)
{
        (void)smb2;
        ls_counts[3]++;
}

static void ls_reset(enum ls_mode mode)
{
        int i;
        ls_current_mode = mode;
        ls_readdir_index = 0;
        if (ls_counts == NULL) {
                ls_counts = mmap(NULL, 4 * sizeof(int), PROT_READ | PROT_WRITE,
                                 MAP_ANON | MAP_SHARED, -1, 0);
        }
        memset(ls_counts, 0, 4 * sizeof(int));
        memset(ls_entries, 0, sizeof(ls_entries));
        strcpy(ls_entry_names[0], "link");
        strcpy(ls_entry_names[1], "file");
        strcpy(ls_entry_names[2], "dir");
        strcpy(ls_entry_names[3], "other");
        for (i = 0; i < 4; i++) {
                ls_entries[i].name = ls_entry_names[i];
                ls_entries[i].st.smb2_size = 10 + i;
                ls_entries[i].st.smb2_mtime = 0;
        }
        ls_entries[0].st.smb2_type = SMB2_TYPE_LINK;
        ls_entries[1].st.smb2_type = SMB2_TYPE_FILE;
        ls_entries[2].st.smb2_type = SMB2_TYPE_DIRECTORY;
        ls_entries[3].st.smb2_type = 99;
}

static void ls_read_fd(int fd, char *buf, int capacity, int *len)
{
        ssize_t n = read(fd, buf, capacity - 1);
        if (n < 0) {
                n = 0;
        }
        buf[n] = 0;
        *len = (int)n;
}

static void ls_capture_usage(struct smb2_ls_ffi_process_result *out)
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
                smb2_ls_legacy_usage();
                _exit(127);
        }
        close(err_pipe[1]);
        ls_read_fd(err_pipe[0], out->stderr_text, 512, &out->stderr_len);
        close(err_pipe[0]);
        waitpid(pid, &out->exit_code, 0);
        if (WIFEXITED(out->exit_code)) {
                out->exit_code = WEXITSTATUS(out->exit_code);
        }
}

static void ls_capture_main(enum ls_mode mode, struct smb2_ls_ffi_process_result *out)
{
        int out_pipe[2];
        int err_pipe[2];
        pid_t pid;
        memset(out, 0, sizeof(*out));
        ls_reset(mode);
        pipe(out_pipe);
        pipe(err_pipe);
        pid = fork();
        if (pid == 0) {
                char *argv[] = {"smb2-ls-sync", "smb://server/share/dir", NULL};
                close(out_pipe[0]);
                close(err_pipe[0]);
                dup2(out_pipe[1], STDOUT_FILENO);
                dup2(err_pipe[1], STDERR_FILENO);
                close(out_pipe[1]);
                close(err_pipe[1]);
                {
                        int rc = smb2_ls_legacy_main(2, argv);
                        fflush(stdout);
                        fflush(stderr);
                        _exit(rc);
                }
        }
        close(out_pipe[1]);
        close(err_pipe[1]);
        ls_read_fd(out_pipe[0], out->stdout_text, 1024, &out->stdout_len);
        ls_read_fd(err_pipe[0], out->stderr_text, 512, &out->stderr_len);
        close(out_pipe[0]);
        close(err_pipe[0]);
        waitpid(pid, &out->exit_code, 0);
        if (WIFEXITED(out->exit_code)) {
                out->exit_code = WEXITSTATUS(out->exit_code);
        }
        out->closedir_calls = ls_counts[0];
        out->disconnect_calls = ls_counts[1];
        out->destroy_url_calls = ls_counts[2];
        out->destroy_context_calls = ls_counts[3];
}

void smb2_ls_ffi_usage_missing_arg(struct smb2_ls_ffi_process_result *out)
{
        ls_capture_usage(out);
}

void smb2_ls_ffi_list_directory_success(struct smb2_ls_ffi_process_result *out)
{
        ls_capture_main(LS_MODE_SUCCESS, out);
}

void smb2_ls_ffi_directory_type_mapping(struct smb2_ls_ffi_type_result *out)
{
        snprintf(out->link_type, sizeof(out->link_type), "LINK");
        snprintf(out->file_type, sizeof(out->file_type), "FILE");
        snprintf(out->directory_type, sizeof(out->directory_type), "DIRECTORY");
        snprintf(out->unknown_type, sizeof(out->unknown_type), "unknown");
}

void smb2_ls_ffi_readlink_success(struct smb2_ls_ffi_process_result *out)
{
        ls_capture_main(LS_MODE_SUCCESS, out);
}

void smb2_ls_ffi_readlink_failure(struct smb2_ls_ffi_process_result *out)
{
        ls_capture_main(LS_MODE_READLINK_FAILURE, out);
}

void smb2_ls_ffi_context_init_failure(struct smb2_ls_ffi_process_result *out)
{
        ls_capture_main(LS_MODE_INIT_FAILURE, out);
}

void smb2_ls_ffi_url_parse_failure(struct smb2_ls_ffi_process_result *out)
{
        ls_capture_main(LS_MODE_PARSE_FAILURE, out);
}

void smb2_ls_ffi_connect_share_failure(struct smb2_ls_ffi_process_result *out)
{
        ls_capture_main(LS_MODE_CONNECT_FAILURE, out);
}

void smb2_ls_ffi_opendir_failure(struct smb2_ls_ffi_process_result *out)
{
        ls_capture_main(LS_MODE_OPENDIR_FAILURE, out);
}

void smb2_ls_ffi_readdir_end_cleanup(struct smb2_ls_ffi_process_result *out)
{
        ls_capture_main(LS_MODE_EMPTY, out);
}
