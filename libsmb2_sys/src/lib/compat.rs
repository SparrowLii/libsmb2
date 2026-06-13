#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollFdLayout {
    pub has_fd: bool,
    pub has_events: bool,
    pub has_revents: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IovecLayout {
    pub has_base: bool,
    pub has_len: bool,
}

pub const POLLFD_LAYOUT: PollFdLayout = PollFdLayout {
    has_fd: true,
    has_events: true,
    has_revents: true,
};

pub const IOVEC_LAYOUT: IovecLayout = IovecLayout {
    has_base: true,
    has_len: true,
};

pub const O_RDONLY_FALLBACK: i32 = 0o00000000;
pub const O_WRONLY_FALLBACK: i32 = 0o00000001;
pub const O_RDWR_FALLBACK: i32 = 0o00000002;
pub const O_DSYNC_FALLBACK: i32 = 0o040000;
pub const __O_SYNC_FALLBACK: i32 = 0o20000000;
pub const O_SYNC_FALLBACK: i32 = __O_SYNC_FALLBACK | O_DSYNC_FALLBACK;
pub const O_ACCMODE_FALLBACK: i32 = O_RDWR_FALLBACK | O_WRONLY_FALLBACK | O_RDONLY_FALLBACK;
pub const ENOMEM_FALLBACK: i32 = 12;
pub const EINVAL_FALLBACK: i32 = 22;
pub const TYPEOF_COMPAT_SPELLING: &str = "__typeof__";
