#ifndef LIBSMB2_SYS_SMB2_LS_FFI_H
#define LIBSMB2_SYS_SMB2_LS_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

struct smb2_ls_ffi_process_result {
        int exit_code;
        int stdout_len;
        int stderr_len;
        char stdout_text[1024];
        char stderr_text[512];
        int closedir_calls;
        int disconnect_calls;
        int destroy_url_calls;
        int destroy_context_calls;
};

struct smb2_ls_ffi_type_result {
        char link_type[16];
        char file_type[16];
        char directory_type[16];
        char unknown_type[16];
};

void smb2_ls_ffi_usage_missing_arg(struct smb2_ls_ffi_process_result *out);
void smb2_ls_ffi_list_directory_success(struct smb2_ls_ffi_process_result *out);
void smb2_ls_ffi_directory_type_mapping(struct smb2_ls_ffi_type_result *out);
void smb2_ls_ffi_readlink_success(struct smb2_ls_ffi_process_result *out);
void smb2_ls_ffi_readlink_failure(struct smb2_ls_ffi_process_result *out);
void smb2_ls_ffi_context_init_failure(struct smb2_ls_ffi_process_result *out);
void smb2_ls_ffi_url_parse_failure(struct smb2_ls_ffi_process_result *out);
void smb2_ls_ffi_connect_share_failure(struct smb2_ls_ffi_process_result *out);
void smb2_ls_ffi_opendir_failure(struct smb2_ls_ffi_process_result *out);
void smb2_ls_ffi_readdir_end_cleanup(struct smb2_ls_ffi_process_result *out);

#ifdef __cplusplus
}
#endif

#endif
