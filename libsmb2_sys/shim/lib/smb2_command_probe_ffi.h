#include <stdint.h>

struct smb2_command_probe_ffi_result {
    uint32_t close_flags;
    uint32_t create_flags;
    uint32_t echo_flags;
    uint32_t error_flags;
    uint32_t flush_flags;
    uint32_t ioctl_flags;
    uint32_t lock_flags;
    uint32_t logoff_flags;
    uint32_t negotiate_flags;
    uint32_t notify_change_flags;
    uint32_t oplock_break_flags;
    uint32_t tree_disconnect_flags;
    uint32_t write_flags;
    uint16_t close_request_size;
    uint16_t close_reply_size;
    uint16_t create_request_size;
    uint16_t create_reply_size;
    uint16_t echo_request_size;
    uint16_t echo_reply_size;
    uint16_t ioctl_request_size;
    uint16_t ioctl_reply_size;
    uint16_t lock_request_size;
    uint16_t logoff_request_size;
    uint16_t tree_disconnect_request_size;
    uint16_t tree_disconnect_reply_size;
    uint16_t write_request_size;
    uint16_t write_reply_size;
};

struct smb2_command_probe_ffi_result smb2_command_probe_ffi_all(void);
