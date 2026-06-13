use libsmb2_sys::legacy::timestamps::{self, Smb2Timeval};

// Trace: `lib/timestamps.c:smb2_timeval_to_win`, `include/smb2/libsmb2.h:smb2_timeval_to_win`, `tests/ntlmssp_generate_blob.c:main`
// Spec: smb2_timeval_to_win convert Unix timeval to Windows FILETIME#正常 timeval 转换为 FILETIME
// - **GIVEN** 调用方提供非空 `struct smb2_timeval *tv`，其中 `tv_sec` 表示 Unix epoch 秒数且 `tv_usec` 表示微秒部分
// - **WHEN** 调用 `smb2_timeval_to_win(tv)`
// - **THEN** implementation MUST 返回 `((uint64_t)tv->tv_sec * 10000000) + 116444736000000000 + tv->tv_usec * 10`
#[test]
fn test_timestamps_timeval_filetime() {
    let input = Smb2Timeval {
        seconds: 1_700_000_000,
        microseconds: 123_456,
    };

    assert_eq!(
        timestamps::timeval_to_windows_time(input),
        (1_700_000_000_u64 * 10_000_000) + 116_444_736_000_000_000 + (123_456_u64 * 10)
    );
}

// Trace: `lib/timestamps.c:smb2_win_to_timeval`, `include/smb2/libsmb2.h:smb2_win_to_timeval`
// Spec: smb2_win_to_timeval convert Windows FILETIME to Unix timeval#正常 FILETIME 转换为 timeval
// - **GIVEN** 调用方提供 Windows FILETIME 值 `smb2_time` 和非空可写 `struct smb2_timeval *tv`
// - **WHEN** 调用 `smb2_win_to_timeval(smb2_time, tv)`
// - **THEN** implementation MUST 将 `tv->tv_usec` 设置为 `(smb2_time / 10) % 1000000`，并将 `tv->tv_sec` 设置为 `(smb2_time - 116444736000000000) / 10000000`
#[test]
fn test_timestamps_filetime_timeval() {
    let windows_time =
        116_444_736_000_000_000 + (1_700_000_000_u64 * 10_000_000) + (123_456_u64 * 10);

    assert_eq!(
        timestamps::windows_time_to_timeval(windows_time),
        Smb2Timeval {
            seconds: 1_700_000_000,
            microseconds: 123_456,
        }
    );
}
