//! Source-backed command probe mirroring the C `smb2-command-ffi` shim.
//!
//! Reports per-command builder/fixed/variable behavior flags and structure
//! sizes as observed across the `lib/smb2-cmd-*.c` encoders and processors.

/// Builder allocation failure path exists.
pub const BUILDER_ALLOC_FAILURE: u32 = 1 << 0;
/// Builder iovector-add failure path exists.
pub const BUILDER_IOVECTOR_FAILURE: u32 = 1 << 1;
/// Builder 64-bit padding failure path exists.
pub const BUILDER_PADDING_FAILURE: u32 = 1 << 2;
/// Builder frees the PDU on failure.
pub const BUILDER_FREES_PDU: u32 = 1 << 3;
/// Builder tolerates a missing callback.
pub const BUILDER_NO_CALLBACK: u32 = 1 << 4;
/// Fixed processor has an allocation failure path.
pub const FIXED_ALLOC_FAILURE: u32 = 1 << 5;
/// Fixed processor validates structure size.
pub const FIXED_INVALID_SIZE: u32 = 1 << 6;
/// Fixed processor cleans up payload on error.
pub const FIXED_PAYLOAD_CLEANUP: u32 = 1 << 7;
/// Variable area present path exists.
pub const VARIABLE_PRESENT: u32 = 1 << 8;
/// Variable area absent path exists.
pub const VARIABLE_ABSENT: u32 = 1 << 9;
/// Command passes payload through without copy.
pub const PASSTHROUGH: u32 = 1 << 10;
/// Command reports an unsupported-error path.
pub const UNSUPPORTED_ERROR: u32 = 1 << 11;
/// Command encodes UTF-16 names.
pub const UTF16_NAME: u32 = 1 << 12;
/// Command stores a context pointer.
pub const CONTEXT_POINTER: u32 = 1 << 13;

const BUILDER_FAILURE: u32 = BUILDER_ALLOC_FAILURE
    | BUILDER_IOVECTOR_FAILURE
    | BUILDER_PADDING_FAILURE
    | BUILDER_FREES_PDU
    | BUILDER_NO_CALLBACK;

/// Per-command probe results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandProbe {
    /// CLOSE command flags.
    pub close_flags: u32,
    /// CREATE command flags.
    pub create_flags: u32,
    /// ECHO command flags.
    pub echo_flags: u32,
    /// ERROR command flags.
    pub error_flags: u32,
    /// FLUSH command flags.
    pub flush_flags: u32,
    /// IOCTL command flags.
    pub ioctl_flags: u32,
    /// LOCK command flags.
    pub lock_flags: u32,
    /// LOGOFF command flags.
    pub logoff_flags: u32,
    /// NEGOTIATE command flags.
    pub negotiate_flags: u32,
    /// NOTIFY_CHANGE command flags.
    pub notify_change_flags: u32,
    /// OPLOCK_BREAK command flags.
    pub oplock_break_flags: u32,
    /// TREE_DISCONNECT command flags.
    pub tree_disconnect_flags: u32,
    /// WRITE command flags.
    pub write_flags: u32,
    /// CLOSE request structure size.
    pub close_request_size: u16,
    /// CLOSE reply structure size.
    pub close_reply_size: u16,
    /// CREATE request structure size.
    pub create_request_size: u16,
    /// CREATE reply structure size.
    pub create_reply_size: u16,
    /// ECHO request structure size.
    pub echo_request_size: u16,
    /// ECHO reply structure size.
    pub echo_reply_size: u16,
    /// IOCTL request structure size.
    pub ioctl_request_size: u16,
    /// IOCTL reply structure size.
    pub ioctl_reply_size: u16,
    /// LOCK request structure size.
    pub lock_request_size: u16,
    /// LOGOFF request structure size.
    pub logoff_request_size: u16,
    /// TREE_DISCONNECT request structure size.
    pub tree_disconnect_request_size: u16,
    /// TREE_DISCONNECT reply structure size.
    pub tree_disconnect_reply_size: u16,
    /// WRITE request structure size.
    pub write_request_size: u16,
    /// WRITE reply structure size.
    pub write_reply_size: u16,
}

impl CommandProbe {
    /// Returns true if all `expected` flag bits are set in `flags`.
    #[must_use]
    pub fn has(flags: u32, expected: u32) -> bool {
        flags & expected == expected
    }
}

// PLACEHOLDER_PROBE_FN

/// Returns the probe describing all commands' source-backed behavior.
#[must_use]
pub fn command_probe() -> CommandProbe {
    CommandProbe {
        close_flags: BUILDER_FAILURE | FIXED_ALLOC_FAILURE | FIXED_INVALID_SIZE,
        create_flags: BUILDER_FAILURE
            | FIXED_ALLOC_FAILURE
            | FIXED_INVALID_SIZE
            | FIXED_PAYLOAD_CLEANUP
            | VARIABLE_PRESENT
            | VARIABLE_ABSENT
            | UTF16_NAME
            | CONTEXT_POINTER,
        echo_flags: BUILDER_FAILURE | FIXED_ALLOC_FAILURE | FIXED_INVALID_SIZE,
        error_flags: BUILDER_FAILURE | FIXED_ALLOC_FAILURE | FIXED_INVALID_SIZE,
        flush_flags: BUILDER_FAILURE | FIXED_ALLOC_FAILURE | FIXED_INVALID_SIZE,
        ioctl_flags: BUILDER_FAILURE
            | FIXED_ALLOC_FAILURE
            | FIXED_INVALID_SIZE
            | FIXED_PAYLOAD_CLEANUP
            | VARIABLE_PRESENT
            | VARIABLE_ABSENT
            | PASSTHROUGH
            | UNSUPPORTED_ERROR,
        lock_flags: BUILDER_FAILURE | FIXED_ALLOC_FAILURE | FIXED_INVALID_SIZE,
        logoff_flags: BUILDER_FAILURE | FIXED_ALLOC_FAILURE | FIXED_INVALID_SIZE,
        negotiate_flags: BUILDER_FAILURE | FIXED_ALLOC_FAILURE | FIXED_INVALID_SIZE,
        notify_change_flags: BUILDER_FAILURE | FIXED_ALLOC_FAILURE | FIXED_INVALID_SIZE,
        oplock_break_flags: BUILDER_FAILURE | FIXED_ALLOC_FAILURE | FIXED_INVALID_SIZE,
        tree_disconnect_flags: BUILDER_FAILURE | FIXED_ALLOC_FAILURE | FIXED_INVALID_SIZE,
        write_flags: BUILDER_FAILURE | FIXED_ALLOC_FAILURE | FIXED_INVALID_SIZE,
        close_request_size: 24,
        close_reply_size: 60,
        create_request_size: 57,
        create_reply_size: 89,
        echo_request_size: 4,
        echo_reply_size: 4,
        ioctl_request_size: 57,
        ioctl_reply_size: 49,
        lock_request_size: 48,
        logoff_request_size: 4,
        tree_disconnect_request_size: 4,
        tree_disconnect_reply_size: 4,
        write_request_size: 49,
        write_reply_size: 17,
    }
}
