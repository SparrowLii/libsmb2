#ifndef LIBSMB2_SYS_SMB2_CP_FFI_H
#define LIBSMB2_SYS_SMB2_CP_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct smb2_cp_ffi_process_result {
        int exit_code;
        int stdout_len;
        int stderr_len;
        char stdout_text[512];
        char stderr_text[512];
};

struct smb2_cp_ffi_cleanup_result {
        int close_calls;
        int smb2_close_calls;
        int destroy_context_calls;
        int destroy_url_calls;
};

struct smb2_cp_ffi_stat_result {
        int rc;
        uint64_t ino;
        uint64_t size;
        uint64_t atime;
        uint64_t mtime;
        uint64_t ctime;
};

struct smb2_cp_ffi_io_result {
        long rc;
        long offset;
        unsigned long count;
        char bytes[16];
};

struct smb2_cp_ffi_open_result {
        int success;
        int is_smb2;
        int fd_valid;
        int init_calls;
        int parse_calls;
        int connect_calls;
        int open_calls;
};

struct smb2_cp_ffi_chunk_result {
        unsigned long first_count;
        unsigned long last_count;
        unsigned long chunks;
};

void smb2_cp_ffi_usage_invalid_argc(struct smb2_cp_ffi_process_result *out);
void smb2_cp_ffi_free_mixed(struct smb2_cp_ffi_cleanup_result *out);
void smb2_cp_ffi_fstat_smb2(struct smb2_cp_ffi_stat_result *out);
void smb2_cp_ffi_pread_local(struct smb2_cp_ffi_io_result *out);
void smb2_cp_ffi_pread_smb2(struct smb2_cp_ffi_io_result *out);
void smb2_cp_ffi_pwrite_local(struct smb2_cp_ffi_io_result *out);
void smb2_cp_ffi_pwrite_smb2(struct smb2_cp_ffi_io_result *out);
void smb2_cp_ffi_open_local(const char *path, struct smb2_cp_ffi_open_result *out);
void smb2_cp_ffi_open_smb2(struct smb2_cp_ffi_open_result *out);
void smb2_cp_ffi_run_local_copy(const char *src, const char *dst,
                                struct smb2_cp_ffi_process_result *out);
void smb2_cp_ffi_run_copy_failure(const char *src, const char *dst,
                                  struct smb2_cp_ffi_process_result *out);
void smb2_cp_ffi_chunk_plan(uint64_t file_size, struct smb2_cp_ffi_chunk_result *out);

#ifdef __cplusplus
}
#endif

#endif
