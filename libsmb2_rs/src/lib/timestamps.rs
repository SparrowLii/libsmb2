//! Timestamp conversion helpers migrated from `lib/timestamps.c`.

/// Microseconds per second used by `struct smb2_timeval`.
pub const MICROSECONDS_PER_SECOND: u64 = 1_000_000;

/// Windows FILETIME ticks per second.
pub const WIN_TICKS_PER_SECOND: u64 = 10_000_000;

/// Windows FILETIME ticks per microsecond.
pub const WIN_TICKS_PER_MICROSECOND: u64 = 10;

/// FILETIME tick value for the Unix epoch, matching `lib/timestamps.c`.
pub const UNIX_EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;

/// Rust counterpart of `struct smb2_timeval` from `include/smb2/smb2.h`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Smb2Timeval {
    /// Seconds since the Unix epoch.
    pub tv_sec: i64,

    /// Microseconds within the current second.
    pub tv_usec: i64,
}

impl Smb2Timeval {
    /// Creates a timestamp value with the same fields as `struct smb2_timeval`.
    #[must_use]
    pub const fn new(tv_sec: i64, tv_usec: i64) -> Self {
        Self { tv_sec, tv_usec }
    }

    /// Converts this timestamp to Windows FILETIME ticks.
    #[must_use]
    pub fn to_win_time(self) -> u64 {
        smb2_timeval_to_win(&self)
    }

    /// Converts Windows FILETIME ticks into an SMB2 timeval value.
    #[must_use]
    pub fn from_win_time(smb2_time: u64) -> Self {
        smb2_win_to_timeval(smb2_time)
    }
}

/// Mirrors `smb2_timeval_to_win` from `lib/timestamps.c`.
#[must_use]
pub fn smb2_timeval_to_win(tv: &Smb2Timeval) -> u64 {
    let seconds = i128::from(tv.tv_sec) * i128::from(WIN_TICKS_PER_SECOND);
    let micros = i128::from(tv.tv_usec) * i128::from(WIN_TICKS_PER_MICROSECOND);
    let ticks = seconds + i128::from(UNIX_EPOCH_AS_FILETIME) + micros;

    i128_to_u64_saturating(ticks)
}

/// `timeval_to_windows_time(tv)` mirroring the sys safe binding.
#[must_use]
pub fn timeval_to_windows_time(time: Smb2Timeval) -> u64 {
    smb2_timeval_to_win(&time)
}

/// `windows_time_to_timeval(t)` mirroring the sys safe binding.
#[must_use]
pub fn windows_time_to_timeval(windows_time: u64) -> Smb2Timeval {
    smb2_win_to_timeval(windows_time)
}

/// Mirrors `smb2_win_to_timeval` from `lib/timestamps.c`.
#[must_use]
pub fn smb2_win_to_timeval(smb2_time: u64) -> Smb2Timeval {
    let tv_usec = (smb2_time / WIN_TICKS_PER_MICROSECOND) % MICROSECONDS_PER_SECOND;
    let ticks_since_unix_epoch = i128::from(smb2_time) - i128::from(UNIX_EPOCH_AS_FILETIME);
    let tv_sec = ticks_since_unix_epoch / i128::from(WIN_TICKS_PER_SECOND);

    Smb2Timeval {
        tv_sec: i128_to_i64_saturating(tv_sec),
        tv_usec: u64_to_i64_saturating(tv_usec),
    }
}

fn i128_to_u64_saturating(value: i128) -> u64 {
    if value <= 0 {
        0
    } else if value > i128::from(u64::MAX) {
        u64::MAX
    } else {
        value as u64
    }
}

fn i128_to_i64_saturating(value: i128) -> i64 {
    if value < i128::from(i64::MIN) {
        i64::MIN
    } else if value > i128::from(i64::MAX) {
        i64::MAX
    } else {
        value as i64
    }
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    if value > i64::MAX as u64 {
        i64::MAX
    } else {
        value as i64
    }
}
