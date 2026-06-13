//! Socket and event-loop integration migrated from `lib/socket.c`.
//!
//! This module intentionally models the state transitions and API shape from
//! the C socket layer without performing OS socket I/O. Platform-specific
//! `socket`, `connect`, `readv`, `writev`, `poll`, and `accept` calls are left
//! for a later migration step.

use crate::include::libsmb2_private::{IoVectors, Pdu, RecvState, Smb2Header};

/// Maximum URL buffer size used by the legacy socket code.
pub const MAX_URL_SIZE: usize = 1024;

/// Timeout in milliseconds between parallel Happy Eyeballs connection attempts.
pub const HAPPY_EYEBALLS_TIMEOUT_MS: i32 = 100;

/// Size of the SMB stream protocol length prefix.
pub const SMB2_SPL_SIZE: usize = 4;

/// Invalid socket sentinel matching the C `-1` convention.
pub const INVALID_SOCKET: SocketFd = -1;

/// Poll-style read readiness bit.
pub const POLLIN: i32 = 0x0001;

/// Poll-style write readiness bit.
pub const POLLOUT: i32 = 0x0004;

/// Poll-style error bit.
pub const POLLERR: i32 = 0x0008;

/// Poll-style hang-up bit.
pub const POLLHUP: i32 = 0x0010;

const SMB2_NEGOTIATE_COMMAND: u16 = 0;
const SMB2_VERSION_0202: u16 = 0x0202;

/// File descriptor type used by the migrated socket skeleton.
pub type SocketFd = i32;

/// Result type used by socket migration skeleton operations.
pub type SocketResult<T> = Result<T, SocketError>;

/// Event mask requested by the SMB2 context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Events {
    /// Read readiness requested.
    pub readable: bool,
    /// Write readiness requested.
    pub writable: bool,
}

impl Events {
    /// Creates an event mask from legacy poll bits.
    #[must_use]
    pub const fn from_poll_bits(bits: i32) -> Self {
        Self {
            readable: bits & POLLIN != 0,
            writable: bits & POLLOUT != 0,
        }
    }

    /// Converts this event mask into legacy poll bits.
    #[must_use]
    pub const fn to_poll_bits(self) -> i32 {
        let mut bits = 0;
        if self.readable {
            bits |= POLLIN;
        }
        if self.writable {
            bits |= POLLOUT;
        }
        bits
    }
}

/// Errors returned by socket migration skeleton operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketError {
    /// Operation requires an established socket.
    NotConnected,
    /// Operation received an invalid socket descriptor.
    InvalidSocket,
    /// Address text could not be split into host and port components.
    InvalidAddress,
    /// Operation is intentionally deferred to a later OS I/O migration.
    Unsupported(&'static str),
}

impl core::fmt::Display for SocketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotConnected => f.write_str("socket is not connected"),
            Self::InvalidSocket => f.write_str("socket descriptor is invalid"),
            Self::InvalidAddress => f.write_str("socket address is invalid"),
            Self::Unsupported(operation) => {
                write!(f, "socket operation is unsupported: {operation}")
            }
        }
    }
}

impl std::error::Error for SocketError {}

/// Parsed server endpoint corresponding to `smb2_connect_async` input parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketAddress {
    /// Hostname, IPv4 address, or unbracketed IPv6 address.
    pub host: String,
    /// Service port as decimal text.
    pub port: String,
}

impl SocketAddress {
    /// Parses a server string into host and port parts.
    ///
    /// Bracketed IPv6 addresses follow the C path in `smb2_connect_async`.
    /// Missing ports default to SMB port `445`.
    ///
    /// # Errors
    ///
    /// Returns [`SocketError::InvalidAddress`] when the address is empty,
    /// exceeds [`MAX_URL_SIZE`], has an unterminated bracketed IPv6 host, or
    /// resolves to an empty host/port component.
    pub fn parse(server: &str) -> SocketResult<Self> {
        if server.is_empty() || server.len() > MAX_URL_SIZE {
            return Err(SocketError::InvalidAddress);
        }

        let (host, port) = if let Some(rest) = server.strip_prefix('[') {
            let Some(end) = rest.find(']') else {
                return Err(SocketError::InvalidAddress);
            };
            let host = &rest[..end];
            let port_part = &rest[end + 1..];
            let port = port_part.strip_prefix(':').map_or("445", |port| port);
            (host, port)
        } else if let Some((host, port)) = server.split_once(':') {
            (host, port)
        } else {
            (server, "445")
        };

        if host.is_empty() || port.is_empty() {
            return Err(SocketError::InvalidAddress);
        }

        Ok(Self {
            host: host.to_owned(),
            port: port.to_owned(),
        })
    }
}

/// Minimal address-info entry used to model Happy Eyeballs ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrInfoEntry {
    /// Address family identifier from the resolver.
    pub family: i32,
    /// Parsed socket endpoint.
    pub address: SocketAddress,
}

/// Socket-side view of an outbound PDU and its compound children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketPdu {
    /// SMB2 header used for credit accounting.
    pub header: Smb2Header,
    /// Total number of bytes already written for this compound chain.
    pub bytes_done: usize,
    /// Payload length used by the stream length prefix.
    pub payload_len: usize,
    /// Whether this PDU represents an encrypted SMB3 transform payload.
    pub sealed: bool,
    /// Compound children sent after this PDU.
    pub next_compound: Vec<SocketPdu>,
}

impl SocketPdu {
    /// Creates a socket PDU view from the shared internal PDU model.
    #[must_use]
    pub fn from_pdu(pdu: &Pdu) -> Self {
        Self {
            header: pdu.header,
            bytes_done: pdu.out.done,
            payload_len: pdu.out.total_size,
            sealed: false,
            next_compound: Vec::new(),
        }
    }

    /// Returns the total credit charge for this PDU and compound children.
    #[must_use]
    pub fn credit_charge(&self, dialect: u16) -> i32 {
        let own = real_credit_charge_for_one_pdu(dialect, &self.header);
        own + self
            .next_compound
            .iter()
            .map(|pdu| pdu.credit_charge(dialect))
            .sum::<i32>()
    }

    /// Returns the stream payload size represented by this compound chain.
    #[must_use]
    pub fn stream_payload_len(&self) -> usize {
        self.payload_len
            + self
                .next_compound
                .iter()
                .map(Self::stream_payload_len)
                .sum::<usize>()
    }
}

/// Receive operation source used by the shared `smb2_read_data` skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadSource {
    /// Data is read from the connected socket.
    Socket,
    /// Data is read from a decrypted transform buffer.
    Buffer,
}

/// Outcome of a read skeleton pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOutcome {
    /// More bytes are needed before the current phase can advance.
    NeedMoreData,
    /// The receive state advanced to the next phase.
    Advanced(RecvState),
    /// A complete PDU or transform payload has been collected.
    Complete,
}

/// Socket migration context corresponding to socket-related fields in `smb2_context`.
#[derive(Debug, Clone)]
pub struct SocketContext {
    /// Established socket descriptor.
    pub fd: SocketFd,
    /// Parallel connection attempts currently in flight.
    pub connecting_fds: Vec<SocketFd>,
    /// Resolver entries retained for Happy Eyeballs attempts.
    pub addrinfos: Vec<AddrInfoEntry>,
    /// Index of the next resolver entry to try.
    pub next_addrinfo: Option<usize>,
    /// Last event mask published through `smb2_change_events`.
    pub events: Events,
    /// Negotiated SMB dialect.
    pub dialect: u16,
    /// Available SMB credits.
    pub credits: i32,
    /// Pending outbound socket PDU chains.
    pub outqueue: Vec<SocketPdu>,
    /// Pending requests waiting for replies.
    pub waitqueue: Vec<SocketPdu>,
    /// Receive state for socket input.
    pub recv_state: RecvState,
    /// Input vectors for the active receive phase.
    pub input: IoVectors,
    /// Current SPL value.
    pub spl: u32,
    /// Last socket-layer error message.
    pub last_error: Option<String>,
}

impl Default for SocketContext {
    fn default() -> Self {
        Self {
            fd: INVALID_SOCKET,
            connecting_fds: Vec::new(),
            addrinfos: Vec::new(),
            next_addrinfo: None,
            events: Events::default(),
            dialect: SMB2_VERSION_0202,
            credits: 0,
            outqueue: Vec::new(),
            waitqueue: Vec::new(),
            recv_state: RecvState::Spl,
            input: IoVectors::default(),
            spl: 0,
            last_error: None,
        }
    }
}

impl SocketContext {
    /// Creates an empty socket migration context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Closes and clears all in-flight connection descriptors except the connected descriptor.
    pub fn close_connecting_fds(&mut self) {
        let fd = self.fd;
        self.connecting_fds.retain(|candidate| *candidate == fd);
        self.connecting_fds.clear();
        self.addrinfos.clear();
        self.next_addrinfo = None;
    }

    /// Returns the poll events currently required by this socket context.
    #[must_use]
    pub fn which_events(&self) -> Events {
        let mut events = if is_valid_socket(self.fd) {
            Events {
                readable: true,
                writable: false,
            }
        } else {
            Events {
                readable: false,
                writable: true,
            }
        };

        if self
            .outqueue
            .first()
            .is_some_and(|pdu| pdu.credit_charge(self.dialect) <= self.credits)
        {
            events.writable = true;
        }

        events
    }

    /// Returns the primary descriptor exposed by `smb2_get_fd`.
    #[must_use]
    pub fn get_fd(&self) -> Option<SocketFd> {
        if is_valid_socket(self.fd) {
            Some(self.fd)
        } else {
            self.connecting_fds.first().copied()
        }
    }

    /// Returns descriptors and timeout exposed by `smb2_get_fds`.
    #[must_use]
    pub fn get_fds(&self) -> FdSet<'_> {
        if is_valid_socket(self.fd) {
            FdSet {
                fds: core::slice::from_ref(&self.fd),
                timeout_ms: None,
            }
        } else {
            FdSet {
                fds: self.connecting_fds.as_slice(),
                timeout_ms: self.next_addrinfo.map(|_| HAPPY_EYEBALLS_TIMEOUT_MS),
            }
        }
    }

    /// Records a changed event mask for a descriptor.
    pub fn change_events(&mut self, events: Events) {
        if self.events != events {
            self.events = events;
        }
    }

    /// Advances the write side enough to mirror credit gating from `smb2_write_to_socket`.
    ///
    /// # Errors
    ///
    /// Returns [`SocketError::NotConnected`] when no established descriptor is present.
    pub fn write_to_socket(&mut self) -> SocketResult<WriteOutcome> {
        if !is_valid_socket(self.fd) {
            self.last_error = Some("trying to write but not connected".to_owned());
            return Err(SocketError::NotConnected);
        }

        let Some(pdu) = self.outqueue.first() else {
            return Ok(WriteOutcome::Idle);
        };

        if pdu.credit_charge(self.dialect) > self.credits {
            return Ok(WriteOutcome::CreditBlocked);
        }

        let total_len = SMB2_SPL_SIZE + pdu.stream_payload_len();
        Ok(WriteOutcome::WouldWrite {
            bytes_remaining: total_len.saturating_sub(pdu.bytes_done),
        })
    }

    /// Advances the read state skeleton shared by socket and transform-buffer reads.
    ///
    /// # Errors
    ///
    /// Returns [`SocketError::NotConnected`] when reading from the socket without
    /// an established descriptor.
    pub fn read_data(&mut self, source: ReadSource) -> SocketResult<ReadOutcome> {
        if source == ReadSource::Socket && !is_valid_socket(self.fd) {
            self.last_error = Some("trying to read but not connected".to_owned());
            return Err(SocketError::NotConnected);
        }

        if self.input.done < self.input.total_size {
            return Ok(ReadOutcome::NeedMoreData);
        }

        let next = match self.recv_state {
            RecvState::Spl => RecvState::Header,
            RecvState::Header => RecvState::Fixed,
            RecvState::Fixed => RecvState::Variable,
            RecvState::Variable | RecvState::Pad | RecvState::Transform | RecvState::Unknown => {
                self.input.done = 0;
                return Ok(ReadOutcome::Complete);
            }
        };

        self.recv_state = next;
        Ok(ReadOutcome::Advanced(next))
    }

    /// Prepares the context for reading from the connected socket.
    ///
    /// # Errors
    ///
    /// Returns [`SocketError::NotConnected`] when no established descriptor is present.
    pub fn read_from_socket(&mut self) -> SocketResult<ReadOutcome> {
        if self.input.done == 0 {
            self.recv_state = RecvState::Spl;
            self.spl = 0;
            self.input = IoVectors {
                done: 0,
                total_size: SMB2_SPL_SIZE,
                vectors: Vec::new(),
            };
        }
        self.read_data(ReadSource::Socket)
    }

    /// Continues reading from a decrypted SMB3 transform buffer.
    ///
    /// # Errors
    ///
    /// This skeleton currently has no buffer-specific errors.
    pub fn read_from_buf(&mut self) -> SocketResult<ReadOutcome> {
        self.read_data(ReadSource::Buffer)
    }

    /// Services a descriptor using legacy poll revents.
    ///
    /// # Errors
    ///
    /// Returns [`SocketError::InvalidSocket`] for invalid explicit descriptors,
    /// [`SocketError::NotConnected`] for read/write events before connection, or
    /// [`SocketError::Unsupported`] for OS-level connect completion handling.
    pub fn service_fd(&mut self, fd: SocketFd, revents: i32) -> SocketResult<ServiceOutcome> {
        if !is_valid_socket(fd) {
            if self.next_addrinfo.is_some() {
                return self.connect_async_next_addr();
            }
            return Err(SocketError::InvalidSocket);
        }

        if revents & POLLERR != 0 {
            self.last_error = Some("smb2_service: socket error".to_owned());
            return Ok(ServiceOutcome::Error);
        }

        if revents & POLLHUP != 0 {
            self.last_error = Some("smb2_service: POLLHUP, socket error".to_owned());
            return Ok(ServiceOutcome::Hangup);
        }

        if !is_valid_socket(self.fd) && revents & POLLOUT != 0 {
            self.fd = fd;
            self.close_connecting_fds();
            let events = self.which_events();
            self.change_events(events);
            return Ok(ServiceOutcome::Connected);
        }

        if revents & POLLIN != 0 {
            self.read_from_socket()?;
        }

        if revents & POLLOUT != 0 && !self.outqueue.is_empty() {
            self.write_to_socket()?;
        }

        Ok(ServiceOutcome::Serviced)
    }

    /// Services the primary descriptor chosen by `smb2_service`.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`SocketContext::service_fd`].
    pub fn service(&mut self, revents: i32) -> SocketResult<ServiceOutcome> {
        let fd = match self.get_fd() {
            Some(fd) => fd,
            None => INVALID_SOCKET,
        };
        self.service_fd(fd, revents)
    }

    /// Parses and records the first address for an asynchronous connection attempt.
    ///
    /// # Errors
    ///
    /// Returns [`SocketError::InvalidAddress`] for malformed server strings or
    /// [`SocketError::Unsupported`] when an actual OS connection would be needed.
    pub fn connect_async(&mut self, server: &str) -> SocketResult<ServiceOutcome> {
        if is_valid_socket(self.fd) {
            self.last_error = Some("trying to connect but already connected".to_owned());
            return Err(SocketError::Unsupported("already connected"));
        }

        let address = SocketAddress::parse(server)?;
        self.addrinfos = vec![AddrInfoEntry { family: 0, address }];
        self.next_addrinfo = Some(0);
        self.connect_async_next_addr()
    }

    /// Attempts to start the next Happy Eyeballs address attempt.
    ///
    /// # Errors
    ///
    /// Returns [`SocketError::Unsupported`] because opening nonblocking sockets is
    /// outside this skeleton.
    pub fn connect_async_next_addr(&mut self) -> SocketResult<ServiceOutcome> {
        if let Some(index) = self.next_addrinfo {
            self.next_addrinfo = (index + 1 < self.addrinfos.len()).then_some(index + 1);
            return Err(SocketError::Unsupported("connect_async_ai"));
        }
        Err(SocketError::InvalidAddress)
    }
}

/// Descriptor list and timeout returned by `smb2_get_fds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdSet<'a> {
    /// Socket descriptors to poll.
    pub fds: &'a [SocketFd],
    /// Timeout in milliseconds, or `None` for an infinite timeout.
    pub timeout_ms: Option<i32>,
}

/// Write-side skeleton outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// Nothing is queued for writing.
    Idle,
    /// The first outbound PDU is waiting for more credits.
    CreditBlocked,
    /// A later I/O layer would write this many bytes.
    WouldWrite {
        /// Remaining byte count including the SPL prefix.
        bytes_remaining: usize,
    },
}

/// Service loop skeleton outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceOutcome {
    /// A pending connection descriptor became the connected descriptor.
    Connected,
    /// Revents were consumed without completing a connection.
    Serviced,
    /// A socket error event was observed.
    Error,
    /// A hang-up event was observed.
    Hangup,
}

/// Returns whether a socket descriptor is considered valid.
#[must_use]
pub const fn is_valid_socket(fd: SocketFd) -> bool {
    fd >= 0
}

/// Returns the credit charge for one PDU header.
#[must_use]
pub fn real_credit_charge_for_one_pdu(dialect: u16, header: &Smb2Header) -> i32 {
    let mut credits = i32::from(header.credit_charge);
    if header.command != SMB2_NEGOTIATE_COMMAND && dialect <= SMB2_VERSION_0202 {
        credits += 1;
    }
    credits
}

/// Interleaves resolver entries by address family like the C helper.
pub fn interleave_addrinfo(entries: &mut [AddrInfoEntry]) {
    if entries.len() < 3 {
        return;
    }

    let mut base = 0;
    while base + 2 < entries.len() {
        let base_family = entries[base].family;
        let mut cursor = base + 1;
        while cursor < entries.len() && entries[cursor].family == base_family {
            cursor += 1;
        }

        if cursor >= entries.len() {
            return;
        }

        if cursor == base + 1 {
            base = cursor;
        } else {
            entries[base + 1..=cursor].rotate_right(1);
            base += 2;
        }
    }
}

/// Builds a listening socket placeholder corresponding to `smb2_bind_and_listen`.
///
/// # Errors
///
/// Returns [`SocketError::Unsupported`] because binding a real socket is outside
/// this migration skeleton.
pub fn bind_and_listen(_port: u16, _max_connections: i32) -> SocketResult<SocketFd> {
    Err(SocketError::Unsupported("bind_and_listen"))
}

/// Accepts one pending connection placeholder corresponding to `smb2_accept_connection_async`.
///
/// # Errors
///
/// Returns [`SocketError::InvalidSocket`] for invalid listener descriptors or
/// [`SocketError::Unsupported`] because polling and accepting are outside this skeleton.
pub fn accept_connection_async(fd: SocketFd, _timeout_ms: i32) -> SocketResult<SocketFd> {
    if !is_valid_socket(fd) {
        return Err(SocketError::InvalidSocket);
    }
    Err(SocketError::Unsupported("accept_connection_async"))
}
