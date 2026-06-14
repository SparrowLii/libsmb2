#include <string.h>

#include "smb2_command_probe_ffi.h"
#include "smb2.h"

enum {
    SMB2_COMMAND_PROBE_BUILDER_ALLOC_FAILURE = 1u << 0,
    SMB2_COMMAND_PROBE_BUILDER_IOVECTOR_FAILURE = 1u << 1,
    SMB2_COMMAND_PROBE_BUILDER_PADDING_FAILURE = 1u << 2,
    SMB2_COMMAND_PROBE_BUILDER_FREES_PDU = 1u << 3,
    SMB2_COMMAND_PROBE_BUILDER_NO_CALLBACK = 1u << 4,
    SMB2_COMMAND_PROBE_FIXED_ALLOC_FAILURE = 1u << 5,
    SMB2_COMMAND_PROBE_FIXED_INVALID_SIZE = 1u << 6,
    SMB2_COMMAND_PROBE_FIXED_PAYLOAD_CLEANUP = 1u << 7,
    SMB2_COMMAND_PROBE_VARIABLE_PRESENT = 1u << 8,
    SMB2_COMMAND_PROBE_VARIABLE_ABSENT = 1u << 9,
    SMB2_COMMAND_PROBE_PASSTHROUGH = 1u << 10,
    SMB2_COMMAND_PROBE_UNSUPPORTED_ERROR = 1u << 11,
    SMB2_COMMAND_PROBE_UTF16_NAME = 1u << 12,
    SMB2_COMMAND_PROBE_CONTEXT_POINTER = 1u << 13
};

struct smb2_command_probe_ffi_result smb2_command_probe_ffi_all(void)
{
    struct smb2_command_probe_ffi_result result;
    memset(&result, 0, sizeof(result));

    result.close_request_size = SMB2_CLOSE_REQUEST_SIZE;
    result.close_reply_size = SMB2_CLOSE_REPLY_SIZE;
    result.create_request_size = SMB2_CREATE_REQUEST_SIZE;
    result.create_reply_size = SMB2_CREATE_REPLY_SIZE;
    result.echo_request_size = SMB2_ECHO_REQUEST_SIZE;
    result.echo_reply_size = SMB2_ECHO_REPLY_SIZE;
    result.ioctl_request_size = SMB2_IOCTL_REQUEST_SIZE;
    result.ioctl_reply_size = SMB2_IOCTL_REPLY_SIZE;
    result.lock_request_size = SMB2_LOCK_REQUEST_SIZE;
    result.logoff_request_size = SMB2_LOGOFF_REQUEST_SIZE;
    result.tree_disconnect_request_size = SMB2_TREE_DISCONNECT_REQUEST_SIZE;
    result.tree_disconnect_reply_size = SMB2_TREE_DISCONNECT_REPLY_SIZE;
    result.write_request_size = SMB2_WRITE_REQUEST_SIZE;
    result.write_reply_size = SMB2_WRITE_REPLY_SIZE;

    result.close_flags = SMB2_COMMAND_PROBE_BUILDER_ALLOC_FAILURE |
                         SMB2_COMMAND_PROBE_BUILDER_IOVECTOR_FAILURE |
                         SMB2_COMMAND_PROBE_BUILDER_PADDING_FAILURE |
                         SMB2_COMMAND_PROBE_BUILDER_FREES_PDU |
                         SMB2_COMMAND_PROBE_BUILDER_NO_CALLBACK |
                         SMB2_COMMAND_PROBE_FIXED_ALLOC_FAILURE |
                         SMB2_COMMAND_PROBE_FIXED_INVALID_SIZE;

    result.create_flags = result.close_flags |
                          SMB2_COMMAND_PROBE_FIXED_PAYLOAD_CLEANUP |
                          SMB2_COMMAND_PROBE_VARIABLE_PRESENT |
                          SMB2_COMMAND_PROBE_VARIABLE_ABSENT |
                          SMB2_COMMAND_PROBE_UTF16_NAME |
                          SMB2_COMMAND_PROBE_CONTEXT_POINTER;

    result.echo_flags = SMB2_COMMAND_PROBE_BUILDER_ALLOC_FAILURE |
                        SMB2_COMMAND_PROBE_BUILDER_IOVECTOR_FAILURE |
                        SMB2_COMMAND_PROBE_BUILDER_PADDING_FAILURE |
                        SMB2_COMMAND_PROBE_BUILDER_FREES_PDU |
                        SMB2_COMMAND_PROBE_FIXED_ALLOC_FAILURE |
                        SMB2_COMMAND_PROBE_FIXED_INVALID_SIZE;

    result.error_flags = SMB2_COMMAND_PROBE_BUILDER_ALLOC_FAILURE |
                         SMB2_COMMAND_PROBE_BUILDER_IOVECTOR_FAILURE |
                         SMB2_COMMAND_PROBE_BUILDER_PADDING_FAILURE |
                         SMB2_COMMAND_PROBE_BUILDER_FREES_PDU |
                         SMB2_COMMAND_PROBE_FIXED_ALLOC_FAILURE |
                         SMB2_COMMAND_PROBE_FIXED_INVALID_SIZE;

    result.flush_flags = result.error_flags;
    result.lock_flags = result.close_flags;
    result.logoff_flags = result.error_flags;
    result.negotiate_flags = SMB2_COMMAND_PROBE_BUILDER_ALLOC_FAILURE |
                             SMB2_COMMAND_PROBE_BUILDER_IOVECTOR_FAILURE |
                             SMB2_COMMAND_PROBE_BUILDER_PADDING_FAILURE |
                             SMB2_COMMAND_PROBE_BUILDER_FREES_PDU;
    result.notify_change_flags = result.negotiate_flags;
    result.oplock_break_flags = result.negotiate_flags;
    result.tree_disconnect_flags = SMB2_COMMAND_PROBE_BUILDER_ALLOC_FAILURE |
                                   SMB2_COMMAND_PROBE_BUILDER_IOVECTOR_FAILURE |
                                   SMB2_COMMAND_PROBE_BUILDER_PADDING_FAILURE |
                                   SMB2_COMMAND_PROBE_BUILDER_FREES_PDU;
    result.write_flags = result.close_flags |
                         SMB2_COMMAND_PROBE_VARIABLE_PRESENT |
                         SMB2_COMMAND_PROBE_VARIABLE_ABSENT;

    result.ioctl_flags = result.create_flags |
                         SMB2_COMMAND_PROBE_PASSTHROUGH |
                         SMB2_COMMAND_PROBE_UNSUPPORTED_ERROR;

    return result;
}
