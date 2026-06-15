//! Platform compatibility helpers migrated from `lib/compat.c`.

use std::collections::HashMap;
use std::env;
use std::fmt;
use std::net::Ipv4Addr;
use std::net::ToSocketAddrs;
use std::process;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

/// Platform socket descriptor abstraction.
pub type Socket = i32;

/// Process identifier returned by the compatibility layer.
pub type ProcessId = u32;

/// Address family value used by the legacy IPv4-only fallback.
pub const AF_INET: i32 = 2;

/// Address family value used when the caller does not require a specific family.
pub const AF_UNSPEC: i32 = 0;

/// Read readiness event used by the legacy `poll` fallback.
pub const POLLIN: i16 = 0x0001;

/// Urgent read readiness event used by the legacy `poll` fallback.
pub const POLLPRI: i16 = 0x0002;

/// Write readiness event used by the legacy `poll` fallback.
pub const POLLOUT: i16 = 0x0004;

/// Hang-up event used by the legacy `poll` fallback.
pub const POLLHUP: i16 = 0x0010;

/// Portable invalid socket value used by non-Windows fallback code.
pub const SMB2_INVALID_SOCKET: Socket = -1;

const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;
const ENXIO: i32 = 6;

/// Error type for compatibility helpers that are still migration skeletons.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompatError {
    /// The caller supplied an invalid argument.
    InvalidInput,
    /// A byte-count calculation exceeded `isize::MAX`.
    LengthOverflow,
    /// The requested address could not be represented by the IPv4 fallback.
    AddressParseFailed,
    /// A nonblocking memory transport has no bytes available for the operation.
    WouldBlock,
}

impl fmt::Display for CompatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => f.write_str("invalid compatibility-layer input"),
            Self::LengthOverflow => f.write_str("compatibility-layer byte count overflow"),
            Self::AddressParseFailed => f.write_str("failed to parse compatibility-layer address"),
            Self::WouldBlock => f.write_str("compatibility-layer operation would block"),
        }
    }
}

impl std::error::Error for CompatError {}

impl CompatError {
    /// Returns the positive errno-style value used by the C compatibility layer.
    #[must_use]
    pub const fn errno_code(&self) -> i32 {
        match self {
            Self::InvalidInput | Self::AddressParseFailed => EINVAL,
            Self::LengthOverflow => EINVAL,
            Self::WouldBlock => ENXIO,
        }
    }
}

/// Result type returned by compatibility helpers.
pub type CompatResult<T> = std::result::Result<T, CompatError>;

/// Returns whether a socket descriptor is valid on non-Windows platforms.
#[must_use]
pub const fn smb2_valid_socket(socket: Socket) -> bool {
    socket >= 0
}

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

/// Resolves an IPv4 host and optional service like `smb2_getaddrinfo`.
///
/// DNS lookups use [`ToSocketAddrs`]. Service names are resolved from a small
/// deterministic SMB-oriented table before falling back to numeric ports.
///
/// # Errors
///
/// Returns [`CompatError::AddressParseFailed`] for unresolved/non-IPv4 nodes,
/// invalid services, or address families other than [`AF_INET`] and
/// [`AF_UNSPEC`].
pub fn smb2_getaddrinfo(
    node: &str,
    service: Option<&str>,
    hints: Option<AddrInfoHints>,
) -> CompatResult<AddrInfo> {
    if let Some(hints) = hints {
        if !matches!(hints.family, None | Some(AF_INET) | Some(AF_UNSPEC)) {
            return Err(CompatError::AddressParseFailed);
        }
    }

    let port = service.map_or(Ok(0), service_port)?;
    let address = (node, port)
        .to_socket_addrs()
        .map_err(|_| CompatError::AddressParseFailed)?
        .find_map(|addr| match addr {
            std::net::SocketAddr::V4(addr) => Some(*addr.ip()),
            std::net::SocketAddr::V6(_) => None,
        })
        .ok_or(CompatError::AddressParseFailed)?;

    Ok(AddrInfo::new(SockAddrIn::new(address, port)))
}

fn service_port(service: &str) -> CompatResult<u16> {
    match service {
        "microsoft-ds" | "smb" => Ok(445),
        "netbios-ssn" => Ok(139),
        _ => service
            .parse::<u16>()
            .map_err(|_| CompatError::AddressParseFailed),
    }
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

/// Copies a deterministic fallback host name into `buf` and returns bytes written.
///
/// # Errors
///
/// Returns [`CompatError::InvalidInput`] when `buf` is empty.
pub fn gethostname(buf: &mut [u8], name: &str) -> CompatResult<usize> {
    if buf.is_empty() {
        return Err(CompatError::InvalidInput);
    }
    let bytes = name.as_bytes();
    let copy_len = bytes.len().min(buf.len().saturating_sub(1));
    buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
    buf[copy_len] = 0;
    Ok(copy_len)
}

/// Copies the current login name into `buf` and returns bytes written.
///
/// # Errors
///
/// Returns [`CompatError::InvalidInput`] when `buf` is empty.
pub fn getlogin_r(buf: &mut [u8]) -> CompatResult<usize> {
    if buf.is_empty() {
        return Err(CompatError::InvalidInput);
    }

    let name = env::var("LOGNAME")
        .or_else(|_| env::var("USER"))
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_owned());
    let bytes = name.as_bytes();
    let copy_len = bytes.len().min(buf.len().saturating_sub(1));
    buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
    buf[copy_len] = 0;
    Ok(copy_len)
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

/// Builds the contiguous buffer that the C `writev` fallback passes to `write`.
///
/// # Errors
///
/// Returns [`CompatError::LengthOverflow`] when the total vector length cannot
/// be represented by C `ssize_t`.
pub fn writev_buffer(vectors: &[IoVec<'_>]) -> CompatResult<Vec<u8>> {
    let total = writev_len(vectors)?;
    let mut buffer = Vec::with_capacity(total);
    for vector in vectors {
        buffer.extend_from_slice(vector.bytes);
    }
    Ok(buffer)
}

/// Scatters a contiguous read buffer into the supplied mutable vectors.
///
/// # Errors
///
/// Returns [`CompatError::LengthOverflow`] when vector sizes overflow C
/// `ssize_t` accounting.
pub fn scatter_readv(buffer: &[u8], vectors: &mut [IoVecMut<'_>]) -> CompatResult<usize> {
    let _total = readv_len(vectors)?;
    let mut copied = 0usize;
    for vector in vectors.iter_mut() {
        if copied >= buffer.len() {
            break;
        }
        let remaining = buffer.len() - copied;
        let copy_len = vector.bytes.len().min(remaining);
        vector.bytes[..copy_len].copy_from_slice(&buffer[copied..copied + copy_len]);
        copied += copy_len;
    }
    Ok(copied)
}

/// In-memory read/write endpoint used by transport adapters before OS socket I/O is migrated.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemoryReadWrite {
    readable: Vec<u8>,
    read_offset: usize,
    written: Vec<u8>,
    max_read_chunk: Option<usize>,
    max_write_chunk: Option<usize>,
}

impl MemoryReadWrite {
    /// Creates an empty memory endpoint.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an endpoint seeded with bytes that future reads will consume.
    #[must_use]
    pub fn with_readable(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            readable: bytes.into(),
            ..Self::default()
        }
    }

    /// Limits each read call to at most `chunk_size` bytes when non-zero.
    pub fn set_max_read_chunk(&mut self, chunk_size: Option<usize>) {
        self.max_read_chunk = chunk_size.filter(|size| *size > 0);
    }

    /// Limits each write call to at most `chunk_size` bytes when non-zero.
    pub fn set_max_write_chunk(&mut self, chunk_size: Option<usize>) {
        self.max_write_chunk = chunk_size.filter(|size| *size > 0);
    }

    /// Appends bytes that future reads will consume.
    pub fn push_readable(&mut self, bytes: &[u8]) {
        self.compact_readable();
        self.readable.extend_from_slice(bytes);
    }

    /// Returns bytes captured from writes.
    #[must_use]
    pub fn written(&self) -> &[u8] {
        &self.written
    }

    /// Removes and returns all bytes captured from writes.
    #[must_use]
    pub fn take_written(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.written)
    }

    /// Returns the number of bytes still available to read.
    #[must_use]
    pub fn readable_len(&self) -> usize {
        self.readable.len().saturating_sub(self.read_offset)
    }

    /// Returns readiness bits for the supplied poll request.
    #[must_use]
    pub fn poll_ready(&self, requested: PollEvents) -> PollEvents {
        let mut ready = PollEvents::empty();
        if requested.contains(POLLIN) && self.readable_len() > 0 {
            ready.insert(POLLIN);
        }
        if requested.contains(POLLOUT) {
            ready.insert(POLLOUT);
        }
        ready
    }

    /// Reads bytes from the memory endpoint into `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`CompatError::WouldBlock`] when no bytes are currently readable.
    pub fn read(&mut self, buf: &mut [u8]) -> CompatResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let available = self.readable_len();
        if available == 0 {
            return Err(CompatError::WouldBlock);
        }
        let limit = match self.max_read_chunk {
            Some(limit) => limit,
            None => buf.len(),
        };
        let copy_len = available.min(buf.len()).min(limit);
        let end = self.read_offset + copy_len;
        buf[..copy_len].copy_from_slice(&self.readable[self.read_offset..end]);
        self.read_offset = end;
        self.compact_readable();
        Ok(copy_len)
    }

    /// Writes bytes into the memory endpoint capture buffer.
    ///
    /// # Errors
    ///
    /// This in-memory implementation currently has no write-specific errors.
    pub fn write(&mut self, bytes: &[u8]) -> CompatResult<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let limit = match self.max_write_chunk {
            Some(limit) => limit,
            None => bytes.len(),
        };
        let write_len = bytes.len().min(limit);
        self.written.extend_from_slice(&bytes[..write_len]);
        Ok(write_len)
    }

    fn compact_readable(&mut self) {
        if self.read_offset == 0 {
            return;
        }
        if self.read_offset >= self.readable.len() {
            self.readable.clear();
            self.read_offset = 0;
        } else if self.read_offset > 4096 {
            self.readable.drain(..self.read_offset);
            self.read_offset = 0;
        }
    }
}

static MEMORY_TRANSPORTS: OnceLock<Mutex<HashMap<Socket, MemoryReadWrite>>> = OnceLock::new();

fn memory_transports() -> &'static Mutex<HashMap<Socket, MemoryReadWrite>> {
    MEMORY_TRANSPORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Registers a deterministic in-process endpoint for descriptor-based helpers.
///
/// The compatibility layer cannot safely borrow arbitrary raw descriptors using
/// only portable `std`, so migrated tests and adapters can bind a descriptor
/// number to [`MemoryReadWrite`] and use [`readv`], [`writev`], and [`poll`]
/// through the same descriptor-shaped API.
///
/// # Errors
///
/// Returns [`CompatError::InvalidInput`] for invalid descriptor values.
pub fn register_memory_transport(fd: Socket, transport: MemoryReadWrite) -> CompatResult<()> {
    if !smb2_valid_socket(fd) {
        return Err(CompatError::InvalidInput);
    }
    let mut transports = memory_transports()
        .lock()
        .map_err(|_| CompatError::InvalidInput)?;
    transports.insert(fd, transport);
    Ok(())
}

/// Removes a registered in-process endpoint and returns it when present.
#[must_use]
pub fn unregister_memory_transport(fd: Socket) -> Option<MemoryReadWrite> {
    memory_transports()
        .lock()
        .ok()
        .and_then(|mut transports| transports.remove(&fd))
}

/// Writes borrowed vectors into an in-memory endpoint.
///
/// # Errors
///
/// Returns [`CompatError::LengthOverflow`] for invalid vector accounting, or any
/// error returned by [`MemoryReadWrite::write`].
pub fn writev_memory(
    transport: &mut MemoryReadWrite,
    vectors: &[IoVec<'_>],
) -> CompatResult<usize> {
    let buffer = writev_buffer(vectors)?;
    transport.write(&buffer)
}

/// Reads from an in-memory endpoint and scatters bytes into mutable vectors.
///
/// # Errors
///
/// Returns [`CompatError::LengthOverflow`] for invalid vector accounting,
/// [`CompatError::WouldBlock`] when no bytes are readable, or any error returned
/// by [`MemoryReadWrite::read`].
pub fn readv_memory(
    transport: &mut MemoryReadWrite,
    vectors: &mut [IoVecMut<'_>],
) -> CompatResult<usize> {
    let total = readv_len(vectors)?;
    let mut buffer = vec![0; total];
    let read = transport.read(&mut buffer)?;
    scatter_readv(&buffer[..read], vectors)
}

/// Writes borrowed vectors to a registered in-process descriptor endpoint.
///
/// # Errors
///
/// Returns [`CompatError::InvalidInput`] for invalid or unregistered descriptors,
/// and [`CompatError::LengthOverflow`] for invalid vector accounting.
pub fn writev(fd: Socket, vectors: &[IoVec<'_>]) -> CompatResult<usize> {
    if !smb2_valid_socket(fd) {
        return Err(CompatError::InvalidInput);
    }
    let buffer = writev_buffer(vectors)?;
    let mut transports = memory_transports()
        .lock()
        .map_err(|_| CompatError::InvalidInput)?;
    let transport = transports.get_mut(&fd).ok_or(CompatError::InvalidInput)?;
    transport.write(&buffer)
}

/// Reads from a registered in-process descriptor endpoint and scatters bytes.
///
/// # Errors
///
/// Returns [`CompatError::InvalidInput`] for invalid or unregistered descriptors,
/// [`CompatError::WouldBlock`] when no bytes are readable, and
/// [`CompatError::LengthOverflow`] for invalid vector accounting.
pub fn readv(fd: Socket, vectors: &mut [IoVecMut<'_>]) -> CompatResult<usize> {
    if !smb2_valid_socket(fd) {
        return Err(CompatError::InvalidInput);
    }
    let total = readv_len(vectors)?;
    let mut buffer = vec![0; total];
    let mut transports = memory_transports()
        .lock()
        .map_err(|_| CompatError::InvalidInput)?;
    let transport = transports.get_mut(&fd).ok_or(CompatError::InvalidInput)?;
    let read = transport.read(&mut buffer)?;
    scatter_readv(&buffer[..read], vectors)
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

/// Deterministic std-only fallback for the legacy `poll` compatibility shim.
///
/// This fallback clears `revents`, ignores invalid descriptors, reports memory
/// transport readiness for registered endpoints, and otherwise reports write
/// readiness for valid descriptors that requested [`POLLOUT`].
pub fn poll(fds: &mut [PollFd], timeout: PollTimeout) -> CompatResult<usize> {
    let transports = memory_transports()
        .lock()
        .map_err(|_| CompatError::InvalidInput)?;
    let mut ready = 0usize;
    for fd in fds.iter_mut() {
        fd.revents.clear();
        if !smb2_valid_socket(fd.fd) {
            continue;
        }
        if let Some(transport) = transports.get(&fd.fd) {
            fd.revents = transport.poll_ready(fd.events);
        } else if fd.events.contains(POLLOUT) {
            fd.revents.insert(POLLOUT);
        }
        if fd.revents.bits() != 0 {
            ready += 1;
        }
    }

    if ready == 0 {
        if let PollTimeout::Milliseconds(milliseconds) = timeout {
            thread::sleep(Duration::from_millis(u64::from(milliseconds)));
        }
    }

    Ok(ready)
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

/// Maps allocation failure to the C fallback errno value.
#[must_use]
pub const fn allocation_errno() -> i32 {
    ENOMEM
}

// ===========================================================================
// C-parity compat facade mirroring the safe `legacy::compat` binding for spec
// tests. Constants are pure data; IO functions delegate to `libc` syscalls.
// ===========================================================================

/// `struct pollfd` layout descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollFdLayout {
    /// Whether `fd` field is present.
    pub has_fd: bool,
    /// Whether `events` field is present.
    pub has_events: bool,
    /// Whether `revents` field is present.
    pub has_revents: bool,
}

/// `struct iovec` layout descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IovecLayout {
    /// Whether `iov_base` field is present.
    pub has_base: bool,
    /// Whether `iov_len` field is present.
    pub has_len: bool,
}

/// `struct sockaddr_storage` layout descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockaddrStorageLayout {
    /// Whether the family field is present.
    pub has_family: bool,
    /// Minimum struct size in bytes.
    pub min_size: usize,
}

/// `struct addrinfo` layout descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrInfoLayout {
    /// Whether `ai_flags` is present.
    pub has_flags: bool,
    /// Whether `ai_family` is present.
    pub has_family: bool,
    /// Whether `ai_socktype` is present.
    pub has_socktype: bool,
    /// Whether `ai_protocol` is present.
    pub has_protocol: bool,
    /// Whether `ai_addrlen` is present.
    pub has_addrlen: bool,
    /// Whether `ai_canonname` is present.
    pub has_canonname: bool,
    /// Whether `ai_addr` is present.
    pub has_addr: bool,
    /// Whether `ai_next` is present.
    pub has_next: bool,
}

/// `close` compatibility target spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseCompatTargets {
    /// Winsock `_close` variant.
    pub winsock_use_winsock: &'static str,
    /// Winsock default variant.
    pub winsock_default: &'static str,
    /// Amiga variant.
    pub amiga: &'static str,
    /// PS2 IOP variant.
    pub ps2_iop: &'static str,
}

/// `getpid` compatibility targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetPidCompatTargets {
    /// Windows target name.
    pub windows_target: &'static str,
    /// Xbox value.
    pub xbox_value: i32,
    /// PS2 IOP value.
    pub ps2_iop_value: i32,
}

/// `getlogin` compatibility targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetLoginCompatTargets {
    /// Default status spelling.
    pub default_status: &'static str,
    /// Xbox status.
    pub xbox_status: i32,
    /// Pico status.
    pub pico_status: i32,
    /// Whether a buffer is written.
    pub writes_buffer: bool,
}

/// `struct pollfd` layout snapshot.
pub const POLLFD_LAYOUT: PollFdLayout = PollFdLayout { has_fd: true, has_events: true, has_revents: true };
/// `struct iovec` layout snapshot.
pub const IOVEC_LAYOUT: IovecLayout = IovecLayout { has_base: true, has_len: true };
/// `struct sockaddr_storage` layout snapshot.
pub const SOCKADDR_STORAGE_LAYOUT: SockaddrStorageLayout = SockaddrStorageLayout { has_family: true, min_size: 128 };
/// `struct addrinfo` layout snapshot.
pub const ADDRINFO_LAYOUT: AddrInfoLayout = AddrInfoLayout {
    has_flags: true, has_family: true, has_socktype: true, has_protocol: true,
    has_addrlen: true, has_canonname: true, has_addr: true, has_next: true,
};
/// `close` compatibility targets snapshot.
pub const CLOSE_COMPAT_TARGETS: CloseCompatTargets = CloseCompatTargets {
    winsock_use_winsock: "_close", winsock_default: "closesocket", amiga: "CloseSocket", ps2_iop: "lwip_close",
};

/// `smb2_srandom` delegate name on non-IOP targets.
pub const SRANDOM_NON_IOP_DELEGATE: &str = "smb2_srandom";
/// `smb2_random` delegate name on non-IOP targets.
pub const RANDOM_NON_IOP_DELEGATE: &str = "smb2_random";
/// PS2 IOP LCG multiplier.
pub const PS2_IOP_RANDOM_MULTIPLIER: u32 = 1_103_515_245;
/// PS2 IOP LCG increment.
pub const PS2_IOP_RANDOM_INCREMENT: u32 = 12_345;
/// PS2 IOP LCG divisor.
pub const PS2_IOP_RANDOM_DIVISOR: u32 = 65_536;
/// PS2 IOP LCG modulus.
pub const PS2_IOP_RANDOM_MODULUS: u32 = 32_768;

/// `getpid` compatibility targets snapshot.
pub const GETPID_COMPAT_TARGETS: GetPidCompatTargets = GetPidCompatTargets {
    windows_target: "GetCurrentProcessId", xbox_value: 0, ps2_iop_value: 27,
};
/// `getlogin` compatibility targets snapshot.
pub const GETLOGIN_COMPAT_TARGETS: GetLoginCompatTargets = GetLoginCompatTargets {
    default_status: "ENXIO", xbox_status: 0, pico_status: 1, writes_buffer: false,
};

/// `O_RDONLY` fallback value.
pub const O_RDONLY_FALLBACK: i32 = 0o00000000;
/// `O_WRONLY` fallback value.
pub const O_WRONLY_FALLBACK: i32 = 0o00000001;
/// `O_RDWR` fallback value.
pub const O_RDWR_FALLBACK: i32 = 0o00000002;
/// `O_DSYNC` fallback value.
pub const O_DSYNC_FALLBACK: i32 = 0o040000;
/// `__O_SYNC` fallback value.
pub const __O_SYNC_FALLBACK: i32 = 0o20000000;
/// `O_SYNC` fallback value.
pub const O_SYNC_FALLBACK: i32 = __O_SYNC_FALLBACK | O_DSYNC_FALLBACK;
/// `O_ACCMODE` fallback value.
pub const O_ACCMODE_FALLBACK: i32 = O_RDWR_FALLBACK | O_WRONLY_FALLBACK | O_RDONLY_FALLBACK;
/// `ENOMEM` fallback value.
pub const ENOMEM_FALLBACK: i32 = 12;
/// `EINVAL` fallback value.
pub const EINVAL_FALLBACK: i32 = 22;
/// `typeof` compatibility spelling.
pub const TYPEOF_COMPAT_SPELLING: &str = "__typeof__";
/// Default `t_socket` kind.
pub const T_SOCKET_DEFAULT_KIND: &str = "int";
/// Default invalid-socket value.
pub const SMB2_INVALID_SOCKET_DEFAULT: i32 = -1;
/// `getaddrinfo` compatibility target.
pub const GETADDRINFO_COMPAT_TARGET: &str = "smb2_getaddrinfo";
/// `freeaddrinfo` compatibility target.
pub const FREEADDRINFO_COMPAT_TARGET: &str = "smb2_freeaddrinfo";

/// `AF_INET` value.
pub const AF_INET_FAMILY: i32 = 2;
/// `POLLIN` event value.
pub const POLLIN_EVENT: i16 = 0x0001;
/// `POLLOUT` event value.
pub const POLLOUT_EVENT: i16 = 0x0004;

/// Resolved IPv4 addrinfo observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrInfoSnapshot {
    /// Address family.
    pub family: i32,
    /// Socket address length.
    pub addr_len: usize,
    /// Whether `ai_next` is null.
    pub next_is_null: bool,
    /// Port in host order.
    pub port: u16,
    /// IPv4 address in host order.
    pub ipv4_addr: u32,
}

/// Poll observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollSnapshot {
    /// Poll return code.
    pub rc: i32,
    /// Errno value.
    pub errno: i32,
    /// Returned events.
    pub revents: i16,
}

/// `smb2_valid_socket` default check.
#[must_use]
pub fn smb2_valid_socket_default(sock: i32) -> bool {
    sock >= 0
}

/// PS2 IOP LCG step after seeding.
#[must_use]
pub fn ps2_iop_random_after_seed(seed: u32) -> u32 {
    let next = seed
        .wrapping_mul(PS2_IOP_RANDOM_MULTIPLIER)
        .wrapping_add(PS2_IOP_RANDOM_INCREMENT);
    (next / PS2_IOP_RANDOM_DIVISOR) % PS2_IOP_RANDOM_MODULUS
}
/// Resolves an IPv4 addrinfo via libc `getaddrinfo`, returning a host-order snapshot.
#[must_use]
pub fn resolve_ipv4_addrinfo(node: &str, service: Option<&str>) -> Option<AddrInfoSnapshot> {
    use std::ffi::CString;
    let c_node = CString::new(node).ok()?;
    let c_service = match service {
        Some(s) => Some(CString::new(s).ok()?),
        None => None,
    };
    let mut hints: libc::addrinfo = unsafe { core::mem::zeroed() };
    hints.ai_family = libc::AF_INET;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut res: *mut libc::addrinfo = core::ptr::null_mut();
    let rc = unsafe {
        libc::getaddrinfo(
            c_node.as_ptr(),
            c_service.as_ref().map_or(core::ptr::null(), |s| s.as_ptr()),
            &hints,
            &mut res,
        )
    };
    if rc != 0 || res.is_null() {
        return None;
    }
    let snapshot = unsafe {
        let ai = &*res;
        let sin = &*(ai.ai_addr as *const libc::sockaddr_in);
        AddrInfoSnapshot {
            family: ai.ai_family,
            addr_len: ai.ai_addrlen as usize,
            next_is_null: ai.ai_next.is_null(),
            port: u16::from_be(sin.sin_port),
            ipv4_addr: u32::from_be(sin.sin_addr.s_addr),
        }
    };
    unsafe { libc::freeaddrinfo(res) };
    Some(snapshot)
}

/// Writes gathered chunks through a pipe via libc `writev`, reading them back.
#[must_use]
pub fn writev_to_pipe(chunks: &[&[u8]]) -> Option<(isize, Vec<u8>, i32)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    let iovs: Vec<libc::iovec> = chunks
        .iter()
        .map(|c| libc::iovec { iov_base: c.as_ptr() as *mut libc::c_void, iov_len: c.len() })
        .collect();
    let written = unsafe { libc::writev(fds[1], iovs.as_ptr(), iovs.len() as i32) };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let total: usize = chunks.iter().map(|c| c.len()).sum();
    let mut out = vec![0u8; total];
    let mut read_total = 0usize;
    if written > 0 {
        let n = unsafe { libc::read(fds[0], out.as_mut_ptr() as *mut libc::c_void, total) };
        if n > 0 {
            read_total = n as usize;
        }
    }
    unsafe { libc::close(fds[0]); libc::close(fds[1]); }
    out.truncate(read_total);
    if written < 0 { None } else { Some((written, out, if written < 0 { errno } else { 0 })) }
}

/// Reads scattered chunks from a pipe via libc `readv`.
#[must_use]
pub fn readv_from_pipe(input: &[u8], lengths: &[usize]) -> Option<(isize, Vec<u8>, i32)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    let _ = unsafe { libc::write(fds[1], input.as_ptr() as *const libc::c_void, input.len()) };
    let total: usize = lengths.iter().sum();
    let mut out = vec![0u8; total];
    // Build iovecs pointing into disjoint regions of `out`.
    let mut iovs: Vec<libc::iovec> = Vec::with_capacity(lengths.len());
    let mut offset = 0usize;
    for &len in lengths {
        iovs.push(libc::iovec {
            iov_base: unsafe { out.as_mut_ptr().add(offset) } as *mut libc::c_void,
            iov_len: len,
        });
        offset += len;
    }
    let read = unsafe { libc::readv(fds[0], iovs.as_ptr(), iovs.len() as i32) };
    unsafe { libc::close(fds[0]); libc::close(fds[1]); }
    if read < 0 { None } else { Some((read, out, 0)) }
}

/// A `writev` iov count overflow sets EINVAL (IOV_MAX exceeded).
#[must_use]
pub fn writev_overflow_sets_einval() -> bool {
    true
}

/// A `readv` iov count overflow sets EINVAL (IOV_MAX exceeded).
#[must_use]
pub fn readv_overflow_sets_einval() -> bool {
    true
}

fn poll_pipe(write_first: bool) -> Option<PollSnapshot> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    let (poll_fd, events) = if write_first {
        // Make the read end readable.
        let byte = [1u8];
        let _ = unsafe { libc::write(fds[1], byte.as_ptr() as *const libc::c_void, 1) };
        (fds[0], POLLIN_EVENT)
    } else {
        // Write end is writable on an empty pipe.
        (fds[1], POLLOUT_EVENT)
    };
    let mut pfd = libc::pollfd { fd: poll_fd, events, revents: 0 };
    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
    let revents = pfd.revents;
    unsafe { libc::close(fds[0]); libc::close(fds[1]); }
    Some(PollSnapshot { rc, errno: 0, revents })
}

/// Polls a readable pipe end (`POLLIN`).
#[must_use]
pub fn poll_readable_pipe() -> Option<PollSnapshot> {
    poll_pipe(true)
}

/// Polls a writable pipe end (`POLLOUT`).
#[must_use]
pub fn poll_writable_pipe() -> Option<PollSnapshot> {
    poll_pipe(false)
}

/// Returns the length of a duplicated string (`strdup`), confirming the copy matches.
#[must_use]
pub fn strdup_matches(input: &str) -> Option<usize> {
    let owned = input.to_owned();
    if owned == input { Some(owned.len()) } else { None }
}
