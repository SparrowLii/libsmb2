//! Platform compatibility helpers migrated from `lib/compat.c`.

use std::fmt;
use std::net::Ipv4Addr;
use std::process;

/// Platform socket descriptor abstraction.
pub type Socket = i32;

/// Process identifier returned by the compatibility layer.
pub type ProcessId = u32;

/// Address family value used by the legacy IPv4-only fallback.
pub const AF_INET: i32 = 2;

/// Read readiness event used by the legacy `poll` fallback.
pub const POLLIN: i16 = 0x0001;

/// Urgent read readiness event used by the legacy `poll` fallback.
pub const POLLPRI: i16 = 0x0002;

/// Write readiness event used by the legacy `poll` fallback.
pub const POLLOUT: i16 = 0x0004;

/// Hang-up event used by the legacy `poll` fallback.
pub const POLLHUP: i16 = 0x0010;

/// Error type for compatibility helpers that are still migration skeletons.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompatError {
    /// The caller supplied an invalid argument.
    InvalidInput,
    /// A byte-count calculation exceeded `isize::MAX`.
    LengthOverflow,
    /// The requested platform operation has no Rust implementation yet.
    Unsupported,
    /// The requested address could not be represented by the IPv4 fallback.
    AddressParseFailed,
}

impl fmt::Display for CompatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => f.write_str("invalid compatibility-layer input"),
            Self::LengthOverflow => f.write_str("compatibility-layer byte count overflow"),
            Self::Unsupported => f.write_str("compatibility-layer operation is not implemented"),
            Self::AddressParseFailed => f.write_str("failed to parse compatibility-layer address"),
        }
    }
}

impl std::error::Error for CompatError {}

/// Result type returned by compatibility helpers.
pub type CompatResult<T> = std::result::Result<T, CompatError>;

/// Portable counterpart of C `struct sockaddr_in` for the IPv4 fallback path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockAddrIn {
    /// Address family, normally [`AF_INET`].
    pub family: i32,
    /// IPv4 address in host representation.
    pub address: Ipv4Addr,
    /// TCP or UDP port in host byte order.
    pub port: u16,
}

impl SockAddrIn {
    /// Creates an IPv4 socket address record.
    #[must_use]
    pub fn new(address: Ipv4Addr, port: u16) -> Self {
        Self {
            family: AF_INET,
            address,
            port,
        }
    }
}

/// Rust-owned counterpart of the legacy `struct addrinfo` result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrInfo {
    /// Address family selected for the result.
    pub family: i32,
    /// IPv4 socket address allocated by the fallback.
    pub addr: SockAddrIn,
}

impl AddrInfo {
    /// Creates an address-info record for an IPv4 socket address.
    #[must_use]
    pub fn new(addr: SockAddrIn) -> Self {
        Self {
            family: addr.family,
            addr,
        }
    }

    /// Returns the number of bytes the C fallback would report for `sockaddr_in`.
    #[must_use]
    pub fn addr_len(&self) -> usize {
        16
    }
}

/// Optional address resolution hints mirroring the C `addrinfo` input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrInfoHints {
    /// Desired address family, or `None` when the caller accepts the fallback.
    pub family: Option<i32>,
}

impl AddrInfoHints {
    /// Returns hints for the IPv4-only fallback.
    #[must_use]
    pub fn ipv4() -> Self {
        Self {
            family: Some(AF_INET),
        }
    }
}

impl Default for AddrInfoHints {
    fn default() -> Self {
        Self::ipv4()
    }
}

/// Resolves an IPv4 numeric host and optional service like `smb2_getaddrinfo`.
///
/// This skeleton intentionally does not perform DNS lookups or platform socket
/// calls; it only models the numeric IPv4 fallback present in `compat.c`.
///
/// # Errors
///
/// Returns [`CompatError::AddressParseFailed`] for non-IPv4 nodes or invalid
/// services, and [`CompatError::Unsupported`] for non-IPv4 hints.
pub fn smb2_getaddrinfo(
    node: &str,
    service: Option<&str>,
    hints: Option<AddrInfoHints>,
) -> CompatResult<AddrInfo> {
    if let Some(hints) = hints {
        if hints.family.is_some() && hints.family != Some(AF_INET) {
            return Err(CompatError::Unsupported);
        }
    }

    let address = node
        .parse::<Ipv4Addr>()
        .map_err(|_| CompatError::AddressParseFailed)?;
    let port = match service {
        Some(service) => service
            .parse::<u16>()
            .map_err(|_| CompatError::AddressParseFailed)?,
        None => 0,
    };

    Ok(AddrInfo::new(SockAddrIn::new(address, port)))
}

/// Releases an address-info record produced by [`smb2_getaddrinfo`].
///
/// Rust ownership drops the value directly, so this function exists to mirror
/// the C `smb2_freeaddrinfo` call site shape during migration.
pub fn smb2_freeaddrinfo(_addr_info: AddrInfo) {}

/// Deterministic pseudo-random state used by the migrated `random/srandom` shim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatRandom {
    next: u32,
}

impl CompatRandom {
    /// Creates a pseudo-random generator initialized with the C fallback seed.
    #[must_use]
    pub fn new() -> Self {
        Self { next: 1 }
    }

    /// Seeds the pseudo-random generator like `srandom`.
    pub fn srandom(&mut self, seed: u32) {
        self.next = seed;
    }

    /// Produces a pseudo-random value like the PS2 IOP fallback in `compat.c`.
    #[must_use]
    pub fn random(&mut self) -> u32 {
        self.next = self.next.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        (self.next / 65_536) % 32_768
    }
}

impl Default for CompatRandom {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the current process identifier for platforms with a native process id.
#[must_use]
pub fn getpid() -> ProcessId {
    process::id()
}

/// Models the fallback `getlogin_r` failure for platforms without login names.
///
/// # Errors
///
/// Always returns [`CompatError::Unsupported`] until platform-specific account
/// lookup is migrated.
pub fn getlogin_r(_buf: &mut [u8]) -> CompatResult<usize> {
    Err(CompatError::Unsupported)
}

/// Borrowed byte segment equivalent to the C `struct iovec` input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoVec<'a> {
    /// Bytes referenced by this vector entry.
    pub bytes: &'a [u8],
}

impl<'a> IoVec<'a> {
    /// Creates a borrowed write vector entry.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

/// Mutable byte segment equivalent to the C `struct iovec` read target.
#[derive(Debug, PartialEq, Eq)]
pub struct IoVecMut<'a> {
    /// Writable bytes referenced by this vector entry.
    pub bytes: &'a mut [u8],
}

impl<'a> IoVecMut<'a> {
    /// Creates a borrowed read vector entry.
    #[must_use]
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }
}

/// Returns the total length of write vectors after C `ssize_t` overflow checks.
///
/// # Errors
///
/// Returns [`CompatError::LengthOverflow`] when the total would exceed
/// `isize::MAX`.
pub fn writev_len(vectors: &[IoVec<'_>]) -> CompatResult<usize> {
    vectors.iter().try_fold(0usize, |total, vector| {
        let next = total
            .checked_add(vector.bytes.len())
            .ok_or(CompatError::LengthOverflow)?;
        if next > isize::MAX as usize {
            Err(CompatError::LengthOverflow)
        } else {
            Ok(next)
        }
    })
}

/// Returns the total length of read vectors after C `ssize_t` overflow checks.
///
/// # Errors
///
/// Returns [`CompatError::LengthOverflow`] when the total would exceed
/// `isize::MAX`.
pub fn readv_len(vectors: &[IoVecMut<'_>]) -> CompatResult<usize> {
    vectors.iter().try_fold(0usize, |total, vector| {
        let next = total
            .checked_add(vector.bytes.len())
            .ok_or(CompatError::LengthOverflow)?;
        if next > isize::MAX as usize {
            Err(CompatError::LengthOverflow)
        } else {
            Ok(next)
        }
    })
}

/// Placeholder for the legacy `writev` compatibility shim.
///
/// # Errors
///
/// Validates vector lengths, then returns [`CompatError::Unsupported`] because
/// descriptor writes are not wired in this migration skeleton.
pub fn writev(_fd: Socket, vectors: &[IoVec<'_>]) -> CompatResult<usize> {
    let _total = writev_len(vectors)?;
    Err(CompatError::Unsupported)
}

/// Placeholder for the legacy `readv` compatibility shim.
///
/// # Errors
///
/// Validates vector lengths, then returns [`CompatError::Unsupported`] because
/// descriptor reads are not wired in this migration skeleton.
pub fn readv(_fd: Socket, vectors: &mut [IoVecMut<'_>]) -> CompatResult<usize> {
    let _total = readv_len(vectors)?;
    Err(CompatError::Unsupported)
}

/// Poll event mask used by the fallback `poll` model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PollEvents {
    bits: i16,
}

impl PollEvents {
    /// Creates an event mask from raw C-style bits.
    #[must_use]
    pub fn from_bits(bits: i16) -> Self {
        Self { bits }
    }

    /// Returns an empty event mask.
    #[must_use]
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Returns the raw C-style bits for this mask.
    #[must_use]
    pub fn bits(self) -> i16 {
        self.bits
    }

    /// Returns `true` when all requested event bits are present.
    #[must_use]
    pub fn contains(self, events: i16) -> bool {
        self.bits & events == events
    }

    /// Adds raw event bits to this mask.
    pub fn insert(&mut self, events: i16) {
        self.bits |= events;
    }

    /// Clears all event bits from this mask.
    pub fn clear(&mut self) {
        self.bits = 0;
    }
}

/// Poll descriptor equivalent to C `struct pollfd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollFd {
    /// Socket descriptor to poll.
    pub fd: Socket,
    /// Events requested by the caller.
    pub events: PollEvents,
    /// Events observed by the fallback poll operation.
    pub revents: PollEvents,
}

impl PollFd {
    /// Creates a poll descriptor with empty returned events.
    #[must_use]
    pub fn new(fd: Socket, events: PollEvents) -> Self {
        Self {
            fd,
            events,
            revents: PollEvents::empty(),
        }
    }
}

/// Timeout model accepted by the fallback `poll` skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollTimeout {
    /// Wait indefinitely.
    Infinite,
    /// Return immediately.
    Immediate,
    /// Wait for the given number of milliseconds.
    Milliseconds(u32),
}

impl From<i32> for PollTimeout {
    fn from(value: i32) -> Self {
        if value < 0 {
            Self::Infinite
        } else if value == 0 {
            Self::Immediate
        } else {
            Self::Milliseconds(value as u32)
        }
    }
}

/// Placeholder for the legacy `poll` compatibility shim.
///
/// # Errors
///
/// Clears `revents`, then returns [`CompatError::Unsupported`] unless no file
/// descriptors were supplied.
pub fn poll(fds: &mut [PollFd], _timeout: PollTimeout) -> CompatResult<usize> {
    for fd in fds.iter_mut() {
        fd.revents.clear();
    }

    if fds.is_empty() {
        Ok(0)
    } else {
        Err(CompatError::Unsupported)
    }
}

/// Duplicates a string like the C `strdup` fallback.
#[must_use]
pub fn strdup(value: &str) -> String {
    value.to_owned()
}

/// Converts a big-endian 64-bit integer to host order like `be64toh`.
#[must_use]
pub fn be64toh(value: u64) -> u64 {
    u64::from_be(value)
}
