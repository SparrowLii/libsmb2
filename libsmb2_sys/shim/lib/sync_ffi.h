#ifndef LIBSMB2_SYS_SYNC_FFI_H
#define LIBSMB2_SYS_SYNC_FFI_H

#define SYNC_FFI_MAX_ERROR 128

enum sync_ffi_operation {
        SYNC_FFI_CONNECT_SHARE = 1,
        SYNC_FFI_DISCONNECT_SHARE = 2,
        SYNC_FFI_OPENDIR = 3,
        SYNC_FFI_OPEN = 4,
        SYNC_FFI_CLOSE = 5,
        SYNC_FFI_FSYNC = 6,
        SYNC_FFI_PREAD = 7,
        SYNC_FFI_PWRITE = 8,
        SYNC_FFI_READ = 9,
        SYNC_FFI_WRITE = 10,
        SYNC_FFI_UNLINK = 11,
        SYNC_FFI_RMDIR = 12,
        SYNC_FFI_MKDIR = 13,
        SYNC_FFI_FSTAT = 14,
        SYNC_FFI_STAT = 15,
        SYNC_FFI_RENAME = 16,
        SYNC_FFI_STATVFS = 17,
        SYNC_FFI_TRUNCATE = 18,
        SYNC_FFI_FTRUNCATE = 19,
        SYNC_FFI_READLINK = 20,
        SYNC_FFI_ECHO = 21,
        SYNC_FFI_NOTIFY_CHANGE = 22,
        SYNC_FFI_SHARE_ENUM = 23
};

struct sync_ffi_result {
        int rc;
        int returned_pointer;
        int callback_status;
        int async_called;
        int wait_service_called;
        char text[64];
        char error[SYNC_FFI_MAX_ERROR];
};

struct sync_ffi_result sync_ffi_run_status(enum sync_ffi_operation operation,
                                           int async_rc,
                                           int callback_status);
struct sync_ffi_result sync_ffi_run_pointer(enum sync_ffi_operation operation,
                                            int async_rc,
                                            int callback_status);
struct sync_ffi_result sync_ffi_run_disconnected(enum sync_ffi_operation operation);

#endif
