#include "sync_ffi.h"

#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_TIME_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_POLL_H 1
#define _U_ __attribute__((unused))

#include "smb2/smb2.h"
#include "smb2/libsmb2.h"
#include "smb2/libsmb2-dcerpc-srvsvc.h"
#include "smb2/libsmb2-raw.h"
#include "libsmb2-private.h"

#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int sync_ffi_async_rc;
static int sync_ffi_callback_status;
static int sync_ffi_async_called;
static int sync_ffi_wait_service_called;
static struct smb2_pdu sync_ffi_pdu;
static struct smb2dir sync_ffi_dir;
static struct smb2_file_notify_change_information sync_ffi_notify;
static struct srvsvc_NetrShareEnum_rep sync_ffi_share_enum;
static char sync_ffi_readlink_text[] = "target-link";
static unsigned char sync_ffi_file_handle_storage[32];

static void sync_ffi_set_error(struct smb2_context *smb2,
                               const char *error_string, ...)
{
        va_list ap;

        if (!smb2) {
                return;
        }
        va_start(ap, error_string);
        vsnprintf(smb2->error_string, sizeof(smb2->error_string), error_string, ap);
        va_end(ap);
}

static int sync_ffi_finish_async(struct smb2_context *smb2,
                                 smb2_command_cb cb,
                                 void *cb_data,
                                 void *command_data)
{
        sync_ffi_async_called++;
        if (sync_ffi_async_rc < 0) {
                return sync_ffi_async_rc;
        }
        cb(smb2, sync_ffi_callback_status, command_data, cb_data);
        return sync_ffi_async_rc;
}

int smb2_connect_share_async(struct smb2_context *smb2, const char *server _U_,
                             const char *share _U_, const char *user _U_,
                             smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_disconnect_share_async(struct smb2_context *smb2,
                                smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

struct smb2_pdu *smb2_opendir_async_pdu(struct smb2_context *smb2,
                                        const char *path _U_, smb2_command_cb cb,
                                        void *cb_data, void (*free_cb)(void *) _U_)
{
        sync_ffi_async_called++;
        if (sync_ffi_async_rc < 0) {
                return NULL;
        }
        cb(smb2, sync_ffi_callback_status, &sync_ffi_dir, cb_data);
        return &sync_ffi_pdu;
}

struct smb2_pdu *smb2_open_async_pdu(struct smb2_context *smb2,
                                     const char *path _U_, int flags _U_,
                                     smb2_command_cb cb, void *cb_data,
                                     void (*free_cb)(void *) _U_)
{
        sync_ffi_async_called++;
        if (sync_ffi_async_rc < 0) {
                return NULL;
        }
        cb(smb2, sync_ffi_callback_status, sync_ffi_file_handle_storage, cb_data);
        return &sync_ffi_pdu;
}

int smb2_close_async(struct smb2_context *smb2, struct smb2fh *fh _U_,
                     smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_fsync_async(struct smb2_context *smb2, struct smb2fh *fh _U_,
                     smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_pread_async(struct smb2_context *smb2, struct smb2fh *fh _U_,
                     uint8_t *buf _U_, uint32_t count _U_, uint64_t offset _U_,
                     smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_pwrite_async(struct smb2_context *smb2, struct smb2fh *fh _U_,
                      const uint8_t *buf _U_, uint32_t count _U_, uint64_t offset _U_,
                      smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_read_async(struct smb2_context *smb2, struct smb2fh *fh _U_,
                    uint8_t *buf _U_, uint32_t count _U_, smb2_command_cb cb,
                    void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_write_async(struct smb2_context *smb2, struct smb2fh *fh _U_,
                     const uint8_t *buf _U_, uint32_t count _U_,
                     smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_unlink_async(struct smb2_context *smb2, const char *path _U_,
                      smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_rmdir_async(struct smb2_context *smb2, const char *path _U_,
                     smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_mkdir_async(struct smb2_context *smb2, const char *path _U_,
                     smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_fstat_async(struct smb2_context *smb2, struct smb2fh *fh _U_,
                     struct smb2_stat_64 *st _U_, smb2_command_cb cb,
                     void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_stat_async(struct smb2_context *smb2, const char *path _U_,
                    struct smb2_stat_64 *st _U_, smb2_command_cb cb,
                    void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_rename_async(struct smb2_context *smb2, const char *oldpath _U_,
                      const char *newpath _U_, smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_statvfs_async(struct smb2_context *smb2, const char *path _U_,
                       struct smb2_statvfs *statvfs _U_, smb2_command_cb cb,
                       void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_truncate_async(struct smb2_context *smb2, const char *path _U_,
                        uint64_t length _U_, smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_ftruncate_async(struct smb2_context *smb2, struct smb2fh *fh _U_,
                         uint64_t length _U_, smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_readlink_async(struct smb2_context *smb2, const char *path _U_,
                        smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, sync_ffi_readlink_text);
}

int smb2_echo_async(struct smb2_context *smb2, smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, NULL);
}

int smb2_notify_change_async(struct smb2_context *smb2, const char *path _U_,
                             uint16_t flags _U_, uint32_t filter _U_, int loop _U_,
                             smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, &sync_ffi_notify);
}

int smb2_share_enum_async(struct smb2_context *smb2, enum SHARE_INFO_enum level _U_,
                          smb2_command_cb cb, void *cb_data)
{
        return sync_ffi_finish_async(smb2, cb, cb_data, &sync_ffi_share_enum);
}

t_socket smb2_get_fd(struct smb2_context *smb2 _U_)
{
        return -1;
}

int smb2_which_events(struct smb2_context *smb2 _U_)
{
        return 0;
}

void smb2_timeout_pdus(struct smb2_context *smb2 _U_)
{
}

int smb2_service(struct smb2_context *smb2 _U_, int revents _U_)
{
        sync_ffi_wait_service_called++;
        return 0;
}

const char *smb2_get_error(struct smb2_context *smb2)
{
        return smb2 ? smb2->error_string : "";
}

void smb2_free_pdu(struct smb2_context *smb2 _U_, struct smb2_pdu *pdu _U_)
{
}

#define smb2_set_error sync_ffi_set_error
#define smb2_connect_share sync_ffi_real_connect_share
#define smb2_disconnect_share sync_ffi_real_disconnect_share
#define smb2_opendir sync_ffi_real_opendir
#define smb2_open sync_ffi_real_open
#define smb2_close sync_ffi_real_close
#define smb2_fsync sync_ffi_real_fsync
#define smb2_pread sync_ffi_real_pread
#define smb2_pwrite sync_ffi_real_pwrite
#define smb2_read sync_ffi_real_read
#define smb2_write sync_ffi_real_write
#define smb2_unlink sync_ffi_real_unlink
#define smb2_rmdir sync_ffi_real_rmdir
#define smb2_mkdir sync_ffi_real_mkdir
#define smb2_fstat sync_ffi_real_fstat
#define smb2_stat sync_ffi_real_stat
#define smb2_rename sync_ffi_real_rename
#define smb2_statvfs sync_ffi_real_statvfs
#define smb2_truncate sync_ffi_real_truncate
#define smb2_ftruncate sync_ffi_real_ftruncate
#define smb2_readlink sync_ffi_real_readlink
#define smb2_echo sync_ffi_real_echo
#define smb2_notify_change sync_ffi_real_notify_change
#define smb2_share_enum_sync sync_ffi_real_share_enum_sync
#include "sync.c"
#undef smb2_set_error
#undef smb2_connect_share
#undef smb2_disconnect_share
#undef smb2_opendir
#undef smb2_open
#undef smb2_close
#undef smb2_fsync
#undef smb2_pread
#undef smb2_pwrite
#undef smb2_read
#undef smb2_write
#undef smb2_unlink
#undef smb2_rmdir
#undef smb2_mkdir
#undef smb2_fstat
#undef smb2_stat
#undef smb2_rename
#undef smb2_statvfs
#undef smb2_truncate
#undef smb2_ftruncate
#undef smb2_readlink
#undef smb2_echo
#undef smb2_notify_change
#undef smb2_share_enum_sync

static struct smb2_context sync_ffi_context(int connected)
{
        struct smb2_context smb2;
        memset(&smb2, 0, sizeof(smb2));
        smb2.fd = connected ? 3 : -1;
        return smb2;
}

static void sync_ffi_reset(int async_rc, int callback_status)
{
        sync_ffi_async_rc = async_rc;
        sync_ffi_callback_status = callback_status;
        sync_ffi_async_called = 0;
        sync_ffi_wait_service_called = 0;
        memset(&sync_ffi_dir, 0, sizeof(sync_ffi_dir));
        memset(&sync_ffi_notify, 0, sizeof(sync_ffi_notify));
        memset(&sync_ffi_share_enum, 0, sizeof(sync_ffi_share_enum));
        memset(&sync_ffi_pdu, 0, sizeof(sync_ffi_pdu));
}

static struct sync_ffi_result sync_ffi_result_from_context(struct smb2_context *smb2,
                                                           int rc,
                                                           int returned_pointer)
{
        struct sync_ffi_result result;
        memset(&result, 0, sizeof(result));
        result.rc = rc;
        result.returned_pointer = returned_pointer;
        result.callback_status = sync_ffi_callback_status;
        result.async_called = sync_ffi_async_called;
        result.wait_service_called = sync_ffi_wait_service_called;
        snprintf(result.error, sizeof(result.error), "%s", smb2->error_string);
        return result;
}

struct sync_ffi_result sync_ffi_run_status(enum sync_ffi_operation operation,
                                           int async_rc,
                                           int callback_status)
{
        struct smb2_context smb2 = sync_ffi_context(1);
        struct smb2fh *fh = (struct smb2fh *)sync_ffi_file_handle_storage;
        uint8_t buf[8] = {0};
        struct smb2_stat_64 st;
        struct smb2_statvfs stvfs;
        int rc = -EINVAL;

        memset(&st, 0, sizeof(st));
        memset(&stvfs, 0, sizeof(stvfs));
        sync_ffi_reset(async_rc, callback_status);

        switch (operation) {
        case SYNC_FFI_CONNECT_SHARE:
                rc = sync_ffi_real_connect_share(&smb2, "server", "share", "user");
                break;
        case SYNC_FFI_DISCONNECT_SHARE:
                rc = sync_ffi_real_disconnect_share(&smb2);
                break;
        case SYNC_FFI_CLOSE:
                rc = sync_ffi_real_close(&smb2, fh);
                break;
        case SYNC_FFI_FSYNC:
                rc = sync_ffi_real_fsync(&smb2, fh);
                break;
        case SYNC_FFI_PREAD:
                rc = sync_ffi_real_pread(&smb2, fh, buf, sizeof(buf), 7);
                break;
        case SYNC_FFI_PWRITE:
                rc = sync_ffi_real_pwrite(&smb2, fh, buf, sizeof(buf), 7);
                break;
        case SYNC_FFI_READ:
                rc = sync_ffi_real_read(&smb2, fh, buf, sizeof(buf));
                break;
        case SYNC_FFI_WRITE:
                rc = sync_ffi_real_write(&smb2, fh, buf, sizeof(buf));
                break;
        case SYNC_FFI_UNLINK:
                rc = sync_ffi_real_unlink(&smb2, "path");
                break;
        case SYNC_FFI_RMDIR:
                rc = sync_ffi_real_rmdir(&smb2, "path");
                break;
        case SYNC_FFI_MKDIR:
                rc = sync_ffi_real_mkdir(&smb2, "path");
                break;
        case SYNC_FFI_FSTAT:
                rc = sync_ffi_real_fstat(&smb2, fh, &st);
                break;
        case SYNC_FFI_STAT:
                rc = sync_ffi_real_stat(&smb2, "path", &st);
                break;
        case SYNC_FFI_RENAME:
                rc = sync_ffi_real_rename(&smb2, "old", "new");
                break;
        case SYNC_FFI_STATVFS:
                rc = sync_ffi_real_statvfs(&smb2, "path", &stvfs);
                break;
        case SYNC_FFI_TRUNCATE:
                rc = sync_ffi_real_truncate(&smb2, "path", 42);
                break;
        case SYNC_FFI_FTRUNCATE:
                rc = sync_ffi_real_ftruncate(&smb2, fh, 42);
                break;
        case SYNC_FFI_READLINK:
                rc = sync_ffi_real_readlink(&smb2, "path", (char *)buf, sizeof(buf));
                break;
        case SYNC_FFI_ECHO:
                rc = sync_ffi_real_echo(&smb2);
                break;
        default:
                break;
        }

        return sync_ffi_result_from_context(&smb2, rc, 0);
}

struct sync_ffi_result sync_ffi_run_pointer(enum sync_ffi_operation operation,
                                            int async_rc,
                                            int callback_status)
{
        struct smb2_context smb2 = sync_ffi_context(1);
        struct sync_ffi_result result;
        void *ptr = NULL;

        sync_ffi_reset(async_rc, callback_status);
        switch (operation) {
        case SYNC_FFI_OPENDIR:
                ptr = sync_ffi_real_opendir(&smb2, "path");
                break;
        case SYNC_FFI_OPEN:
                ptr = sync_ffi_real_open(&smb2, "path", 0);
                break;
        case SYNC_FFI_NOTIFY_CHANGE:
                ptr = sync_ffi_real_notify_change(&smb2, "path", 0, 0);
                break;
        case SYNC_FFI_SHARE_ENUM:
                ptr = sync_ffi_real_share_enum_sync(&smb2, SHARE_INFO_1);
                break;
        default:
                break;
        }
        result = sync_ffi_result_from_context(&smb2, ptr ? callback_status : -1, ptr != NULL);
        return result;
}

struct sync_ffi_result sync_ffi_run_disconnected(enum sync_ffi_operation operation)
{
        struct smb2_context smb2 = sync_ffi_context(0);
        int rc = 0;
        void *ptr = NULL;

        sync_ffi_reset(0, 0);
        if (operation == SYNC_FFI_ECHO) {
                rc = sync_ffi_real_echo(&smb2);
                return sync_ffi_result_from_context(&smb2, rc, 0);
        }
        if (operation == SYNC_FFI_SHARE_ENUM) {
                ptr = sync_ffi_real_share_enum_sync(&smb2, SHARE_INFO_1);
                return sync_ffi_result_from_context(&smb2, ptr ? 0 : -1, ptr != NULL);
        }
        return sync_ffi_result_from_context(&smb2, -EINVAL, 0);
}
