mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2Timeval {
    pub seconds: i64,
    pub microseconds: i64,
}

pub fn timeval_to_windows_time(time: Smb2Timeval) -> u64 {
    let mut raw = ffi::smb2_timeval {
        tv_sec: time.seconds,
        tv_usec: time.microseconds,
    };

    unsafe { ffi::smb2_timeval_to_win(&mut raw) }
}

pub fn windows_time_to_timeval(windows_time: u64) -> Smb2Timeval {
    let mut raw = ffi::smb2_timeval {
        tv_sec: 0,
        tv_usec: 0,
    };

    unsafe { ffi::smb2_win_to_timeval(windows_time, &mut raw) };

    Smb2Timeval {
        seconds: raw.tv_sec,
        microseconds: raw.tv_usec,
    }
}
