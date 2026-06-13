//! Socket and event-loop integration migrated from `lib/socket.c`.
//!
//! This module models the state transitions and API shape from the C socket
//! layer while using safe `std::net` TCP streams for local migrated behavior.
//! The public API still exposes legacy integer descriptors, backed internally by
//! an owned TCP registry because portable safe Rust cannot adopt arbitrary OS
//! file descriptors without platform-specific code.

use super::compat::{CompatError, MemoryReadWrite, PollEvents};
use crate::include::libsmb2_private::{IoVectors, Pdu, RecvState, Smb2Header};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

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
/// First deterministic descriptor allocated by the internal TCP registry.
///
/// Registry descriptors are process-local handles, not OS file descriptors, so
/// callers should use [`SocketContext::get_fds`] and [`poll_internal_fd`] rather
/// than passing them to platform `poll(2)` directly.
pub const FIRST_INTERNAL_FD: SocketFd = 10_000;

static NEXT_INTERNAL_FD: AtomicI32 = AtomicI32::new(FIRST_INTERNAL_FD);
static TCP_STREAMS: OnceLock<Mutex<HashMap<SocketFd, TcpStream>>> = OnceLock::new();
static TCP_LISTENERS: OnceLock<Mutex<HashMap<SocketFd, TcpListener>>> = OnceLock::new();

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
    /// Operation reached a boundary that still needs OS socket I/O.
    Unsupported(&'static str),
    /// A nonblocking transport cannot make progress yet.
    WouldBlock,
    /// The injected transport returned a compatibility-layer error.
    Transport(&'static str),
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
            Self::WouldBlock => f.write_str("socket transport operation would block"),
            Self::Transport(operation) => {
                write!(f, "socket transport operation failed: {operation}")
            }
        }
    }
}

impl std::error::Error for SocketError {}

impl From<CompatError> for SocketError {
    fn from(error: CompatError) -> Self {
        match error {
            CompatError::WouldBlock => Self::WouldBlock,
            CompatError::InvalidInput
            | CompatError::LengthOverflow
            | CompatError::AddressParseFailed => Self::Transport("compat"),
        }
    }
}

impl From<io::Error> for SocketError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Self::WouldBlock,
            io::ErrorKind::InvalidInput | io::ErrorKind::AddrNotAvailable => Self::InvalidAddress,
            _ => Self::Transport("tcp"),
        }
    }
}

/// Platform-neutral byte transport used by the socket service loop.
pub trait TransportAdapter {
    /// Reads bytes from `fd` into `buf`.
    ///
    /// # Errors
    ///
    /// Returns a [`SocketError`] when the adapter cannot service the read.
    fn read(&mut self, fd: SocketFd, buf: &mut [u8]) -> SocketResult<usize>;

    /// Writes bytes for `fd` from `buf`.
    ///
    /// # Errors
    ///
    /// Returns a [`SocketError`] when the adapter cannot service the write.
    fn write(&mut self, fd: SocketFd, buf: &[u8]) -> SocketResult<usize>;

    /// Returns currently ready events for `fd` from a requested event mask.
    fn poll_ready(&self, fd: SocketFd, requested: Events) -> SocketResult<Events>;
}

/// In-memory transport adapter for deterministic service-loop tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTransportAdapter {
    fd: SocketFd,
    io: MemoryReadWrite,
}

#[derive(Debug, Default)]
struct StdTcpTransport;

impl TransportAdapter for StdTcpTransport {
    fn read(&mut self, fd: SocketFd, buf: &mut [u8]) -> SocketResult<usize> {
        with_tcp_stream(fd, |stream| stream.read(buf))
    }

    fn write(&mut self, fd: SocketFd, buf: &[u8]) -> SocketResult<usize> {
        with_tcp_stream(fd, |stream| stream.write(buf))
    }

    fn poll_ready(&self, fd: SocketFd, requested: Events) -> SocketResult<Events> {
        poll_internal_fd(fd, requested)
    }
}

impl MemoryTransportAdapter {
    /// Creates an empty memory transport bound to `fd`.
    #[must_use]
    pub fn new(fd: SocketFd) -> Self {
        Self {
            fd,
            io: MemoryReadWrite::new(),
        }
    }

    /// Creates a memory transport seeded with bytes that future reads consume.
    #[must_use]
    pub fn with_readable(fd: SocketFd, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            fd,
            io: MemoryReadWrite::with_readable(bytes),
        }
    }

    /// Returns the descriptor served by this adapter.
    #[must_use]
    pub const fn fd(&self) -> SocketFd {
        self.fd
    }

    /// Appends bytes for future reads.
    pub fn push_readable(&mut self, bytes: &[u8]) {
        self.io.push_readable(bytes);
    }

    /// Returns bytes captured from writes.
    #[must_use]
    pub fn written(&self) -> &[u8] {
        self.io.written()
    }

    /// Removes and returns bytes captured from writes.
    #[must_use]
    pub fn take_written(&mut self) -> Vec<u8> {
        self.io.take_written()
    }

    /// Limits each read call to at most `chunk_size` bytes when non-zero.
    pub fn set_max_read_chunk(&mut self, chunk_size: Option<usize>) {
        self.io.set_max_read_chunk(chunk_size);
    }

    /// Limits each write call to at most `chunk_size` bytes when non-zero.
    pub fn set_max_write_chunk(&mut self, chunk_size: Option<usize>) {
        self.io.set_max_write_chunk(chunk_size);
    }
}

impl TransportAdapter for MemoryTransportAdapter {
    fn read(&mut self, fd: SocketFd, buf: &mut [u8]) -> SocketResult<usize> {
        if fd != self.fd {
            return Err(SocketError::InvalidSocket);
        }
        self.io.read(buf).map_err(SocketError::from)
    }

    fn write(&mut self, fd: SocketFd, buf: &[u8]) -> SocketResult<usize> {
        if fd != self.fd {
            return Err(SocketError::InvalidSocket);
        }
        self.io.write(buf).map_err(SocketError::from)
    }

    fn poll_ready(&self, fd: SocketFd, requested: Events) -> SocketResult<Events> {
        if fd != self.fd {
            return Err(SocketError::InvalidSocket);
        }
        let ready = self
            .io
            .poll_ready(PollEvents::from_bits(requested.to_poll_bits() as i16));
        Ok(Events::from_poll_bits(i32::from(ready.bits())))
    }
}

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
    /// Outbound vector bytes that make up this PDU payload.
    pub vectors: Vec<Vec<u8>>,
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
            vectors: pdu.out.vectors.iter().map(|iov| iov.buf.clone()).collect(),
            bytes_done: pdu.out.done,
            payload_len: pdu.out.total_size,
            sealed: false,
            next_compound: pdu
                .next_compound
                .as_deref()
                .map(|pdu| vec![Self::from_pdu(pdu)])
                .unwrap_or_default(),
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
    /// Synthetic descriptor seed used until real OS socket creation is migrated.
    pub next_fd_seed: SocketFd,
    /// Bytes collected for the current receive phase by an injected transport.
    pub recv_buffer: Vec<u8>,
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
            next_fd_seed: 0,
            recv_buffer: Vec::new(),
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

    /// Adds a resolver entry to the pending connection list.
    pub fn add_addrinfo(&mut self, entry: AddrInfoEntry) {
        self.addrinfos.push(entry);
        if self.next_addrinfo.is_none() {
            self.next_addrinfo = Some(0);
        }
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

    /// Advances the write side, moving a fully sent PDU chain to the wait queue.
    ///
    /// # Errors
    ///
    /// Returns [`SocketError::NotConnected`] when no established descriptor is present.
    pub fn write_to_socket(&mut self) -> SocketResult<WriteOutcome> {
        self.write_to_transport(&mut StdTcpTransport)
    }

    /// Advances the write side using an injected platform-neutral transport.
    ///
    /// # Errors
    ///
    /// Returns [`SocketError::NotConnected`] when no established descriptor is
    /// present, or any error produced by `transport`.
    pub fn write_to_transport<T: TransportAdapter + ?Sized>(
        &mut self,
        transport: &mut T,
    ) -> SocketResult<WriteOutcome> {
        if !is_valid_socket(self.fd) {
            self.last_error = Some("trying to write but not connected".to_owned());
            return Err(SocketError::NotConnected);
        }

        let Some(pdu) = self.outqueue.first() else {
            return Ok(WriteOutcome::Idle);
        };

        let credit_charge = pdu.credit_charge(self.dialect);
        if credit_charge > self.credits {
            return Ok(WriteOutcome::CreditBlocked);
        }

        let total_len = SMB2_SPL_SIZE + pdu.stream_payload_len();
        if pdu.bytes_done >= total_len {
            return self.finish_written_pdu(credit_charge, 0, total_len);
        }

        let frame = encode_socket_pdu_frame(pdu, total_len);
        let bytes_written = transport.write(self.fd, &frame[pdu.bytes_done..])?;
        if bytes_written == 0 {
            return Ok(WriteOutcome::WouldBlock);
        }

        let pdu = &mut self.outqueue[0];
        pdu.bytes_done = pdu.bytes_done.saturating_add(bytes_written).min(total_len);
        if pdu.bytes_done < total_len {
            return Ok(WriteOutcome::Written { bytes_written });
        }

        self.finish_written_pdu(credit_charge, bytes_written, total_len)
    }

    /// Records bytes read by a future transport adapter and advances the current input phase.
    #[must_use]
    pub fn record_read_progress(&mut self, bytes: usize) -> ReadOutcome {
        if self.input.total_size == 0 {
            return ReadOutcome::NeedMoreData;
        }
        self.input.done = self
            .input
            .done
            .saturating_add(bytes)
            .min(self.input.total_size);
        if self.input.done < self.input.total_size {
            ReadOutcome::NeedMoreData
        } else {
            ReadOutcome::Advanced(self.recv_state)
        }
    }

    /// Records concrete bytes read by an injected transport.
    #[must_use]
    pub fn record_read_bytes(&mut self, bytes: &[u8]) -> ReadOutcome {
        self.recv_buffer.extend_from_slice(bytes);
        let outcome = self.record_read_progress(bytes.len());
        if self.recv_state == RecvState::Spl
            && self.input.done >= SMB2_SPL_SIZE
            && self.recv_buffer.len() >= SMB2_SPL_SIZE
        {
            self.spl = u32::from_be_bytes([
                self.recv_buffer[0],
                self.recv_buffer[1],
                self.recv_buffer[2],
                self.recv_buffer[3],
            ]);
        }
        outcome
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
            RecvState::Spl => {
                self.input.done = 0;
                self.input.total_size = 64;
                RecvState::Header
            }
            RecvState::Header => {
                self.input.done = 0;
                self.input.total_size = self.spl.saturating_sub(64) as usize;
                if self.input.total_size == 0 {
                    return Ok(ReadOutcome::Complete);
                }
                RecvState::Fixed
            }
            RecvState::Fixed => {
                self.input.done = 0;
                self.input.total_size = 0;
                RecvState::Variable
            }
            RecvState::Variable | RecvState::Pad | RecvState::Transform | RecvState::Unknown => {
                self.input.done = 0;
                self.input.total_size = 0;
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
        self.read_from_transport(&mut StdTcpTransport)
    }

    /// Reads bytes from an injected transport and advances the receive state.
    ///
    /// # Errors
    ///
    /// Returns [`SocketError::NotConnected`] when no established descriptor is
    /// present, or any error produced by `transport` except
    /// [`SocketError::WouldBlock`], which maps to [`ReadOutcome::NeedMoreData`].
    pub fn read_from_transport<T: TransportAdapter + ?Sized>(
        &mut self,
        transport: &mut T,
    ) -> SocketResult<ReadOutcome> {
        if !is_valid_socket(self.fd) {
            self.last_error = Some("trying to read but not connected".to_owned());
            return Err(SocketError::NotConnected);
        }

        self.prepare_socket_read();
        if self.input.done >= self.input.total_size {
            return self.read_data(ReadSource::Socket);
        }

        let remaining = self.input.total_size.saturating_sub(self.input.done);
        if remaining == 0 {
            return self.read_data(ReadSource::Socket);
        }

        let mut buffer = vec![0; remaining];
        let bytes_read = match transport.read(self.fd, &mut buffer) {
            Ok(bytes_read) => bytes_read,
            Err(SocketError::WouldBlock) => return Ok(ReadOutcome::NeedMoreData),
            Err(error) => return Err(error),
        };
        if bytes_read == 0 {
            return Ok(ReadOutcome::NeedMoreData);
        }
        let outcome = self.record_read_bytes(&buffer[..bytes_read]);
        if matches!(outcome, ReadOutcome::NeedMoreData) {
            Ok(outcome)
        } else {
            self.read_data(ReadSource::Socket)
        }
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
    /// Returns [`SocketError::InvalidSocket`] for invalid explicit descriptors or
    /// [`SocketError::NotConnected`] for read/write events before connection.
    pub fn service_fd(&mut self, fd: SocketFd, revents: i32) -> SocketResult<ServiceOutcome> {
        self.service_fd_with_transport(fd, revents, &mut StdTcpTransport)
    }

    /// Services a descriptor with a platform-neutral transport adapter.
    ///
    /// # Errors
    ///
    /// Returns descriptor, connection, or transport errors produced while
    /// servicing the injected adapter.
    pub fn service_fd_with_transport<T: TransportAdapter + ?Sized>(
        &mut self,
        fd: SocketFd,
        revents: i32,
        transport: &mut T,
    ) -> SocketResult<ServiceOutcome> {
        if !is_valid_socket(fd) {
            if self.next_addrinfo.is_some() {
                return self.connect_async_next_addr();
            }
            return Ok(ServiceOutcome::Serviced);
        }

        if fd != self.fd && !self.connecting_fds.contains(&fd) {
            return Ok(ServiceOutcome::Serviced);
        }

        if revents & POLLERR != 0 {
            if !is_valid_socket(self.fd) && self.next_addrinfo.is_some() {
                self.close_connecting_fd(fd);
                return self.connect_async_next_addr();
            }
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
            self.read_from_transport(transport)?;
        }

        if revents & POLLOUT != 0 && !self.outqueue.is_empty() {
            self.write_to_transport(transport)?;
        }

        let requested = self.which_events();
        let ready = transport.poll_ready(fd, requested)?;
        self.change_events(ready);
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

    /// Services the primary descriptor through an injected transport adapter.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`SocketContext::service_fd_with_transport`].
    pub fn service_with_transport<T: TransportAdapter + ?Sized>(
        &mut self,
        revents: i32,
        transport: &mut T,
    ) -> SocketResult<ServiceOutcome> {
        let fd = match self.get_fd() {
            Some(fd) => fd,
            None => INVALID_SOCKET,
        };
        self.service_fd_with_transport(fd, revents, transport)
    }

    /// Parses and records the first address for an asynchronous connection attempt.
    ///
    /// # Errors
    ///
    /// Returns [`SocketError::InvalidAddress`] for malformed server strings or a
    /// transport error when TCP connection setup fails.
    pub fn connect_async(&mut self, server: &str) -> SocketResult<ServiceOutcome> {
        if is_valid_socket(self.fd) {
            self.last_error = Some("trying to connect but already connected".to_owned());
            return Err(SocketError::InvalidSocket);
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
    /// Returns [`SocketError::InvalidAddress`] if no address candidates remain.
    pub fn connect_async_next_addr(&mut self) -> SocketResult<ServiceOutcome> {
        if let Some(index) = self.next_addrinfo {
            if index >= self.addrinfos.len() {
                self.next_addrinfo = None;
                return Err(SocketError::InvalidAddress);
            }
            let address = self.addrinfos[index].address.clone();
            self.next_addrinfo = (index + 1 < self.addrinfos.len()).then_some(index + 1);
            match connect_tcp_stream(&address) {
                Ok(fd) => {
                    self.fd = fd;
                    self.close_connecting_fds();
                    let events = self.which_events();
                    self.change_events(events);
                    Ok(ServiceOutcome::Connected)
                }
                Err(error) => {
                    self.last_error = Some(error.to_string());
                    if self.next_addrinfo.is_some() {
                        self.connect_async_next_addr()
                    } else {
                        Err(error)
                    }
                }
            }
        } else {
            Err(SocketError::InvalidAddress)
        }
    }

    fn close_connecting_fd(&mut self, fd: SocketFd) {
        self.connecting_fds.retain(|candidate| *candidate != fd);
    }

    fn prepare_socket_read(&mut self) {
        if self.input.done == 0 && self.input.total_size == 0 {
            self.recv_state = RecvState::Spl;
            self.spl = 0;
            self.recv_buffer.clear();
            self.input = IoVectors {
                done: 0,
                total_size: SMB2_SPL_SIZE,
                vectors: Vec::new(),
            };
        }
    }

    fn finish_written_pdu(
        &mut self,
        credit_charge: i32,
        bytes_written: usize,
        total_len: usize,
    ) -> SocketResult<WriteOutcome> {
        let mut pdu = self.outqueue.remove(0);
        pdu.bytes_done = total_len;
        self.credits = self.credits.saturating_sub(credit_charge);
        self.waitqueue.push(pdu);
        let events = self.which_events();
        self.change_events(events);
        Ok(WriteOutcome::Written { bytes_written })
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
    /// The transport accepted no bytes and should be polled again later.
    WouldBlock,
    /// A complete PDU chain was accepted by the socket state machine.
    Written {
        /// Byte count including the SPL prefix.
        bytes_written: usize,
    },
}

fn encode_socket_pdu_frame(pdu: &SocketPdu, total_len: usize) -> Vec<u8> {
    let payload_len = total_len.saturating_sub(SMB2_SPL_SIZE);
    let mut frame = Vec::with_capacity(total_len);
    let spl = (payload_len as u32).to_be_bytes();
    frame.extend_from_slice(&spl);
    append_socket_pdu_payload(pdu, &mut frame);
    frame.resize(total_len, 0);
    frame.truncate(total_len);
    frame
}

fn append_socket_pdu_payload(pdu: &SocketPdu, frame: &mut Vec<u8>) {
    for vector in &pdu.vectors {
        frame.extend_from_slice(vector);
    }
    for pdu in &pdu.next_compound {
        append_socket_pdu_payload(pdu, frame);
    }
}

/// Service loop skeleton outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceOutcome {
    /// A nonblocking connection attempt was started for a descriptor.
    Connecting {
        /// Descriptor to poll for write readiness.
        fd: SocketFd,
    },
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

/// Returns whether a descriptor belongs to the internal TCP registry range.
#[must_use]
pub const fn is_internal_fd(fd: SocketFd) -> bool {
    fd >= FIRST_INTERNAL_FD
}

/// Returns current readiness for an internally registered TCP descriptor.
///
/// This is a deterministic, safe-Rust substitute for polling registry-backed
/// descriptors. Stream readability is checked with non-consuming `peek`; stream
/// writability is considered ready for poll-style progress attempts. Listener
/// readability cannot be tested without accepting a connection in portable safe
/// `std`, so listeners report no readiness here and should be driven through
/// [`accept_connection_async`].
///
/// # Errors
///
/// Returns [`SocketError::InvalidSocket`] when `fd` is not an internal registry
/// stream or listener, or a transport error if the registry check fails.
pub fn poll_internal_fd(fd: SocketFd, requested: Events) -> SocketResult<Events> {
    if !is_internal_fd(fd) {
        return Err(SocketError::InvalidSocket);
    }

    let stream_ready = {
        let mut streams = tcp_streams()
            .lock()
            .map_err(|_| SocketError::Transport("tcp registry"))?;
        if let Some(stream) = streams.get_mut(&fd) {
            let mut ready = Events::default();
            if requested.readable {
                let mut byte = [0_u8; 1];
                match stream.peek(&mut byte) {
                    Ok(_) => ready.readable = true,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(SocketError::from(error)),
                }
            }
            if requested.writable {
                ready.writable = true;
            }
            Some(ready)
        } else {
            None
        }
    };

    if let Some(ready) = stream_ready {
        return Ok(ready);
    }

    with_tcp_listener(fd, |_| Ok(Events::default()))
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

fn tcp_streams() -> &'static Mutex<HashMap<SocketFd, TcpStream>> {
    TCP_STREAMS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn tcp_listeners() -> &'static Mutex<HashMap<SocketFd, TcpListener>> {
    TCP_LISTENERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn allocate_internal_fd() -> SocketResult<SocketFd> {
    loop {
        let current = NEXT_INTERNAL_FD.load(Ordering::Relaxed);
        if !is_internal_fd(current) {
            return Err(SocketError::Transport("tcp registry fd"));
        }
        let next = current
            .checked_add(1)
            .ok_or(SocketError::Transport("tcp registry fd"))?;
        if NEXT_INTERNAL_FD
            .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(current);
        }
    }
}

fn register_tcp_stream(stream: TcpStream) -> SocketResult<SocketFd> {
    stream.set_nonblocking(true).map_err(SocketError::from)?;
    let fd = allocate_internal_fd()?;
    let mut streams = tcp_streams()
        .lock()
        .map_err(|_| SocketError::Transport("tcp registry"))?;
    streams.insert(fd, stream);
    Ok(fd)
}

fn register_tcp_listener(listener: TcpListener) -> SocketResult<SocketFd> {
    listener.set_nonblocking(true).map_err(SocketError::from)?;
    let fd = allocate_internal_fd()?;
    let mut listeners = tcp_listeners()
        .lock()
        .map_err(|_| SocketError::Transport("tcp registry"))?;
    listeners.insert(fd, listener);
    Ok(fd)
}

fn with_tcp_stream<T>(
    fd: SocketFd,
    operation: impl FnOnce(&mut TcpStream) -> io::Result<T>,
) -> SocketResult<T> {
    if !is_valid_socket(fd) {
        return Err(SocketError::InvalidSocket);
    }
    let mut streams = tcp_streams()
        .lock()
        .map_err(|_| SocketError::Transport("tcp registry"))?;
    let stream = streams.get_mut(&fd).ok_or(SocketError::InvalidSocket)?;
    operation(stream).map_err(SocketError::from)
}

fn with_tcp_listener<T>(
    fd: SocketFd,
    operation: impl FnOnce(&TcpListener) -> io::Result<T>,
) -> SocketResult<T> {
    if !is_valid_socket(fd) {
        return Err(SocketError::InvalidSocket);
    }
    let listeners = tcp_listeners()
        .lock()
        .map_err(|_| SocketError::Transport("tcp registry"))?;
    let listener = listeners.get(&fd).ok_or(SocketError::InvalidSocket)?;
    operation(listener).map_err(SocketError::from)
}

fn connect_tcp_stream(address: &SocketAddress) -> SocketResult<SocketFd> {
    let port = address
        .port
        .parse::<u16>()
        .map_err(|_| SocketError::InvalidAddress)?;
    let mut last_error = None;
    for socket_address in (address.host.as_str(), port)
        .to_socket_addrs()
        .map_err(SocketError::from)?
    {
        match TcpStream::connect(socket_address) {
            Ok(stream) => return register_tcp_stream(stream),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.map_or(SocketError::InvalidAddress, SocketError::from))
}

/// Builds a listening socket corresponding to `smb2_bind_and_listen`.
///
/// # Errors
///
/// Returns [`SocketError::InvalidAddress`] if `max_connections` is negative, or
/// a transport error when binding the any-address listener or registering its
/// internal descriptor fails.
///
/// # Backlog limitation
///
/// Safe `std::net::TcpListener::bind` does not expose a portable backlog value.
/// The value is validated for legacy API parity, but the OS default backlog is
/// used for the internal listener.
pub fn bind_and_listen(port: u16, max_connections: i32) -> SocketResult<SocketFd> {
    if max_connections < 0 {
        return Err(SocketError::InvalidAddress);
    }
    let listener = TcpListener::bind(("0.0.0.0", port)).map_err(SocketError::from)?;
    register_tcp_listener(listener)
}

/// Accepts one pending connection corresponding to `smb2_accept_connection_async`.
///
/// # Errors
///
/// Returns [`SocketError::InvalidSocket`] for invalid listener descriptors,
/// [`SocketError::WouldBlock`] when no connection arrives before `timeout_ms`,
/// or a transport error if accepting/registering the stream fails.
pub fn accept_connection_async(fd: SocketFd, timeout_ms: i32) -> SocketResult<SocketFd> {
    if !is_valid_socket(fd) {
        return Err(SocketError::InvalidSocket);
    }
    let deadline = if timeout_ms < 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
    };

    loop {
        let accepted = with_tcp_listener(fd, TcpListener::accept);

        match accepted {
            Ok((stream, _address)) => return register_tcp_stream(stream),
            Err(SocketError::WouldBlock) => {
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Err(SocketError::WouldBlock);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}
