use std::ffi::CString;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockaddrStorageLayout {
    pub has_family: bool,
    pub min_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrInfoLayout {
    pub has_flags: bool,
    pub has_family: bool,
    pub has_socktype: bool,
    pub has_protocol: bool,
    pub has_addrlen: bool,
    pub has_canonname: bool,
    pub has_addr: bool,
    pub has_next: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseCompatTargets {
    pub winsock_use_winsock: &'static str,
    pub winsock_default: &'static str,
    pub amiga: &'static str,
    pub ps2_iop: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetPidCompatTargets {
    pub windows_target: &'static str,
    pub xbox_value: i32,
    pub ps2_iop_value: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetLoginCompatTargets {
    pub default_status: &'static str,
    pub xbox_status: i32,
    pub pico_status: i32,
    pub writes_buffer: bool,
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

pub const SOCKADDR_STORAGE_LAYOUT: SockaddrStorageLayout = SockaddrStorageLayout {
    has_family: true,
    min_size: 128,
};

pub const ADDRINFO_LAYOUT: AddrInfoLayout = AddrInfoLayout {
    has_flags: true,
    has_family: true,
    has_socktype: true,
    has_protocol: true,
    has_addrlen: true,
    has_canonname: true,
    has_addr: true,
    has_next: true,
};

pub const CLOSE_COMPAT_TARGETS: CloseCompatTargets = CloseCompatTargets {
    winsock_use_winsock: "_close",
    winsock_default: "closesocket",
    amiga: "CloseSocket",
    ps2_iop: "lwip_close",
};

pub const SRANDOM_NON_IOP_DELEGATE: &str = "smb2_srandom";
pub const RANDOM_NON_IOP_DELEGATE: &str = "smb2_random";
pub const PS2_IOP_RANDOM_MULTIPLIER: u32 = 1_103_515_245;
pub const PS2_IOP_RANDOM_INCREMENT: u32 = 12_345;
pub const PS2_IOP_RANDOM_DIVISOR: u32 = 65_536;
pub const PS2_IOP_RANDOM_MODULUS: u32 = 32_768;

pub const GETPID_COMPAT_TARGETS: GetPidCompatTargets = GetPidCompatTargets {
    windows_target: "GetCurrentProcessId",
    xbox_value: 0,
    ps2_iop_value: 27,
};

pub const GETLOGIN_COMPAT_TARGETS: GetLoginCompatTargets = GetLoginCompatTargets {
    default_status: "ENXIO",
    xbox_status: 0,
    pico_status: 1,
    writes_buffer: false,
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
pub const T_SOCKET_DEFAULT_KIND: &str = "int";
pub const SMB2_INVALID_SOCKET_DEFAULT: i32 = -1;
pub const GETADDRINFO_COMPAT_TARGET: &str = "smb2_getaddrinfo";
pub const FREEADDRINFO_COMPAT_TARGET: &str = "smb2_freeaddrinfo";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrInfoSnapshot {
    pub family: i32,
    pub addr_len: usize,
    pub next_is_null: bool,
    pub port: u16,
    pub ipv4_addr: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollSnapshot {
    pub rc: i32,
    pub errno: i32,
    pub revents: i16,
}

pub const AF_INET_FAMILY: i32 = 2;
pub const POLLIN_EVENT: i16 = 0x0001;
pub const POLLOUT_EVENT: i16 = 0x0004;

pub fn smb2_valid_socket_default(sock: i32) -> bool {
    sock >= 0
}

pub fn ps2_iop_random_after_seed(seed: u32) -> u32 {
    let next = seed
        .wrapping_mul(PS2_IOP_RANDOM_MULTIPLIER)
        .wrapping_add(PS2_IOP_RANDOM_INCREMENT);
    (next / PS2_IOP_RANDOM_DIVISOR) % PS2_IOP_RANDOM_MODULUS
}

pub fn resolve_ipv4_addrinfo(node: &str, service: Option<&str>) -> Option<AddrInfoSnapshot> {
    let node = CString::new(node).ok()?;
    let service = match service {
        Some(service) => Some(CString::new(service).ok()?),
        None => None,
    };
    let mut snapshot = ffi::compat_ffi_addrinfo_snapshot {
        ai_family: 0,
        ai_addrlen: 0,
        ai_next_is_null: 0,
        port_host_order: 0,
        addr_host_order: 0,
    };

    let rc = unsafe {
        ffi::compat_ffi_resolve_ipv4(
            node.as_ptr(),
            service
                .as_ref()
                .map_or(std::ptr::null(), |service| service.as_ptr()),
            &mut snapshot,
        )
    };
    (rc == 0).then_some(AddrInfoSnapshot {
        family: snapshot.ai_family,
        addr_len: snapshot.ai_addrlen,
        next_is_null: snapshot.ai_next_is_null != 0,
        port: snapshot.port_host_order,
        ipv4_addr: snapshot.addr_host_order,
    })
}

pub fn writev_to_pipe(chunks: &[&[u8]]) -> Option<(isize, Vec<u8>, i32)> {
    let inputs: Vec<_> = chunks
        .iter()
        .map(|chunk| ffi::compat_ffi_iovec_input {
            ptr: chunk.as_ptr(),
            len: chunk.len(),
        })
        .collect();
    let out_len = chunks.iter().map(|chunk| chunk.len()).sum();
    let mut out = vec![0; out_len];
    let mut bytes_read = 0;
    let mut errno = 0;

    let written = unsafe {
        ffi::compat_ffi_writev_to_pipe(
            inputs.as_ptr(),
            inputs.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut bytes_read,
            &mut errno,
        )
    };
    if written < 0 {
        return None;
    }
    out.truncate(bytes_read);
    Some((written, out, errno))
}

pub fn readv_from_pipe(input: &[u8], lengths: &[usize]) -> Option<(isize, Vec<u8>, i32)> {
    let out_len = lengths.iter().sum();
    let mut out = vec![0; out_len];
    let mut errno = 0;

    let read = unsafe {
        ffi::compat_ffi_readv_from_pipe(
            input.as_ptr(),
            input.len(),
            lengths.as_ptr(),
            lengths.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut errno,
        )
    };
    if read < 0 {
        return None;
    }
    Some((read, out, errno))
}

pub fn writev_overflow_sets_einval() -> bool {
    unsafe { ffi::compat_ffi_writev_overflow_sets_einval() != 0 }
}

pub fn readv_overflow_sets_einval() -> bool {
    unsafe { ffi::compat_ffi_readv_overflow_sets_einval() != 0 }
}

pub fn poll_readable_pipe() -> Option<PollSnapshot> {
    poll_snapshot(ffi::compat_ffi_poll_readable_pipe)
}

pub fn poll_writable_pipe() -> Option<PollSnapshot> {
    poll_snapshot(ffi::compat_ffi_poll_writable_pipe)
}

fn poll_snapshot(
    f: unsafe extern "C" fn(*mut ffi::compat_ffi_poll_snapshot) -> i32,
) -> Option<PollSnapshot> {
    let mut snapshot = ffi::compat_ffi_poll_snapshot {
        rc: 0,
        err: 0,
        revents: 0,
    };
    let rc = unsafe { f(&mut snapshot) };
    (rc == 0).then_some(PollSnapshot {
        rc: snapshot.rc,
        errno: snapshot.err,
        revents: snapshot.revents,
    })
}

pub fn strdup_matches(input: &str) -> Option<usize> {
    let input = CString::new(input).ok()?;
    let mut len = 0;
    let matches = unsafe { ffi::compat_ffi_strdup_matches(input.as_ptr(), &mut len) };
    (matches != 0).then_some(len)
}
