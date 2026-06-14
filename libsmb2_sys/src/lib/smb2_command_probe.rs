mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub const BUILDER_ALLOC_FAILURE: u32 = 1 << 0;
pub const BUILDER_IOVECTOR_FAILURE: u32 = 1 << 1;
pub const BUILDER_PADDING_FAILURE: u32 = 1 << 2;
pub const BUILDER_FREES_PDU: u32 = 1 << 3;
pub const BUILDER_NO_CALLBACK: u32 = 1 << 4;
pub const FIXED_ALLOC_FAILURE: u32 = 1 << 5;
pub const FIXED_INVALID_SIZE: u32 = 1 << 6;
pub const FIXED_PAYLOAD_CLEANUP: u32 = 1 << 7;
pub const VARIABLE_PRESENT: u32 = 1 << 8;
pub const VARIABLE_ABSENT: u32 = 1 << 9;
pub const PASSTHROUGH: u32 = 1 << 10;
pub const UNSUPPORTED_ERROR: u32 = 1 << 11;
pub const UTF16_NAME: u32 = 1 << 12;
pub const CONTEXT_POINTER: u32 = 1 << 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandProbe {
    pub close_flags: u32,
    pub create_flags: u32,
    pub echo_flags: u32,
    pub error_flags: u32,
    pub flush_flags: u32,
    pub ioctl_flags: u32,
    pub lock_flags: u32,
    pub logoff_flags: u32,
    pub negotiate_flags: u32,
    pub notify_change_flags: u32,
    pub oplock_break_flags: u32,
    pub tree_disconnect_flags: u32,
    pub write_flags: u32,
    pub close_request_size: u16,
    pub close_reply_size: u16,
    pub create_request_size: u16,
    pub create_reply_size: u16,
    pub echo_request_size: u16,
    pub echo_reply_size: u16,
    pub ioctl_request_size: u16,
    pub ioctl_reply_size: u16,
    pub lock_request_size: u16,
    pub logoff_request_size: u16,
    pub tree_disconnect_request_size: u16,
    pub tree_disconnect_reply_size: u16,
    pub write_request_size: u16,
    pub write_reply_size: u16,
}

impl CommandProbe {
    pub fn has(flags: u32, expected: u32) -> bool {
        flags & expected == expected
    }
}

pub fn command_probe() -> CommandProbe {
    let raw = unsafe { ffi::smb2_command_probe_ffi_all() };
    CommandProbe {
        close_flags: raw.close_flags,
        create_flags: raw.create_flags,
        echo_flags: raw.echo_flags,
        error_flags: raw.error_flags,
        flush_flags: raw.flush_flags,
        ioctl_flags: raw.ioctl_flags,
        lock_flags: raw.lock_flags,
        logoff_flags: raw.logoff_flags,
        negotiate_flags: raw.negotiate_flags,
        notify_change_flags: raw.notify_change_flags,
        oplock_break_flags: raw.oplock_break_flags,
        tree_disconnect_flags: raw.tree_disconnect_flags,
        write_flags: raw.write_flags,
        close_request_size: raw.close_request_size,
        close_reply_size: raw.close_reply_size,
        create_request_size: raw.create_request_size,
        create_reply_size: raw.create_reply_size,
        echo_request_size: raw.echo_request_size,
        echo_reply_size: raw.echo_reply_size,
        ioctl_request_size: raw.ioctl_request_size,
        ioctl_reply_size: raw.ioctl_reply_size,
        lock_request_size: raw.lock_request_size,
        logoff_request_size: raw.logoff_request_size,
        tree_disconnect_request_size: raw.tree_disconnect_request_size,
        tree_disconnect_reply_size: raw.tree_disconnect_reply_size,
        write_request_size: raw.write_request_size,
        write_reply_size: raw.write_reply_size,
    }
}
