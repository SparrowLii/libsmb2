//! DCERPC transport helpers migrated from `lib/dcerpc.c`.
//!
//! This module mirrors the main data shapes and call boundaries from the C
//! implementation without implementing the full DCERPC/NDR protocol yet.

use std::collections::VecDeque;

/// Maximum number of deferred NDR pointers tracked by a PDU.
pub const MAX_DEFERRED_PTR: usize = 1024;

/// Maximum number of bind acknowledgement results retained by a PDU.
pub const MAX_ACK_RESULTS: usize = 4;

/// Default DCERPC named-pipe transmit buffer size used by the C transport.
pub const NSE_BUF_SIZE: usize = 128 * 1024;

/// DCERPC data representation bit for little-endian NDR payloads.
pub const DCERPC_DR_LITTLE_ENDIAN: u8 = 0x10;

/// DCERPC data representation bit for ASCII character encoding.
pub const DCERPC_DR_ASCII: u8 = 0x00;

/// DCERPC pointer marker used by reference pointers in the C encoder.
pub const RPTR: u64 = 0x5270_7472_7274_7052;

/// DCERPC pointer marker used by unique pointers in the C encoder.
pub const UPTR: u64 = 0x5570_7472_7274_7055;

/// NDR32 transfer syntax UUID.
pub const NDR32_UUID: DceRpcUuid = DceRpcUuid {
    v1: 0x8a88_5d04,
    v2: 0x1ceb,
    v3: 0x11c9,
    v4: [0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60],
};

/// NDR64 transfer syntax UUID.
pub const NDR64_UUID: DceRpcUuid = DceRpcUuid {
    v1: 0x7171_0533,
    v2: 0xbeba,
    v3: 0x4937,
    v4: [0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36],
};

/// NDR32 presentation syntax identifier.
pub const NDR32_SYNTAX: PSyntaxId = PSyntaxId {
    uuid: NDR32_UUID,
    vers: 2,
    vers_minor: 0,
};

/// NDR64 presentation syntax identifier.
pub const NDR64_SYNTAX: PSyntaxId = PSyntaxId {
    uuid: NDR64_UUID,
    vers: 1,
    vers_minor: 0,
};

/// DCERPC bind acknowledgement result: acceptance.
pub const ACK_RESULT_ACCEPTANCE: u16 = 0;

/// DCERPC bind acknowledgement result: user rejection.
pub const ACK_RESULT_USER_REJECTION: u16 = 1;

/// DCERPC bind acknowledgement result: provider rejection.
pub const ACK_RESULT_PROVIDER_REJECTION: u16 = 2;

/// DCERPC bind acknowledgement reason: not specified.
pub const ACK_REASON_REASON_NOT_SPECIFIED: u16 = 0;

/// DCERPC bind acknowledgement reason: abstract syntax unsupported.
pub const ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED: u16 = 1;

/// DCERPC bind acknowledgement reason: transfer syntaxes unsupported.
pub const ACK_REASON_PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED: u16 = 2;

/// DCERPC bind acknowledgement reason: protocol version unsupported.
pub const ACK_REASON_PROTOCOL_VERSION_NOT_SUPPORTED: u16 = 4;

/// DCERPC PDU type values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PduType {
    /// Request PDU.
    Request = 0,
    /// Ping PDU.
    Ping = 1,
    /// Response PDU.
    Response = 2,
    /// Fault PDU.
    Fault = 3,
    /// Working PDU.
    Working = 4,
    /// No-call PDU.
    NoCall = 5,
    /// Reject PDU.
    Reject = 6,
    /// Acknowledgement PDU.
    Ack = 7,
    /// Client cancel PDU.
    ClientCancel = 8,
    /// Fragment acknowledgement PDU.
    FragmentAck = 9,
    /// Cancel acknowledgement PDU.
    CancelAck = 10,
    /// Bind PDU.
    Bind = 11,
    /// Bind acknowledgement PDU.
    BindAck = 12,
    /// Bind negative acknowledgement PDU.
    BindNak = 13,
    /// Alter-context PDU.
    AlterContext = 14,
    /// Alter-context response PDU.
    AlterContextResponse = 15,
    /// Shutdown PDU.
    Shutdown = 17,
    /// Connection-oriented cancel PDU.
    ConnectionOrientedCancel = 18,
    /// Orphaned PDU.
    Orphaned = 19,
}

/// DCERPC packet flags from the common PDU header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PfcFlags(u8);

impl PfcFlags {
    /// First fragment flag.
    pub const FIRST_FRAG: Self = Self(0x01);
    /// Last fragment flag.
    pub const LAST_FRAG: Self = Self(0x02);
    /// Pending cancel flag.
    pub const PENDING_CANCEL: Self = Self(0x04);
    /// Reserved flag bit one.
    pub const RESERVED_1: Self = Self(0x08);
    /// Concurrent multiplexing flag.
    pub const CONC_MPX: Self = Self(0x10);
    /// Did-not-execute flag.
    pub const DID_NOT_EXECUTE: Self = Self(0x20);
    /// Maybe flag.
    pub const MAYBE: Self = Self(0x40);
    /// Object UUID flag.
    pub const OBJECT_UUID: Self = Self(0x80);

    /// Returns empty flags.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns flags containing both first-fragment and last-fragment bits.
    #[must_use]
    pub const fn first_and_last() -> Self {
        Self(Self::FIRST_FRAG.0 | Self::LAST_FRAG.0)
    }

    /// Returns the raw bit representation.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Returns true when all bits from `other` are present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl Default for PfcFlags {
    fn default() -> Self {
        Self::empty()
    }
}

/// DCERPC packet coding direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Decode bytes from the server into Rust-owned structures.
    Decode,
    /// Encode Rust-owned structures into bytes for the server.
    Encode,
    /// Client to server request.
    Request,
    /// Server to client response.
    Response,
}

/// Transfer syntax selected for variable-width NDR words.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TransferSyntax {
    /// NDR32 transfer syntax.
    #[default]
    Ndr32,
    /// NDR64 transfer syntax.
    Ndr64,
}

impl TransferSyntax {
    /// Returns the presentation context identifier used by the C code.
    #[must_use]
    pub const fn context_id(self) -> u8 {
        match self {
            Self::Ndr32 => 0,
            Self::Ndr64 => 1,
        }
    }

    /// Returns the natural pointer-width alignment for this syntax.
    #[must_use]
    pub const fn pointer_alignment(self) -> usize {
        match self {
            Self::Ndr32 => 4,
            Self::Ndr64 => 8,
        }
    }
}

/// NDR pointer flavor used by pointer coders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtrType {
    /// Reference pointer.
    Ref,
    /// Full pointer.
    Full,
    /// Unique pointer.
    Unique,
}

/// Error returned by DCERPC skeleton helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DceRpcError {
    /// The requested operation needs full protocol support that is not migrated yet.
    ProtocolNotImplemented(&'static str),
    /// The PDU type byte is not assigned by the connection-oriented DCERPC protocol.
    InvalidPduType { ptype: u8 },
    /// The PDU type is valid but this local decoder does not parse its body yet.
    UnsupportedPduBody { ptype: PduType },
    /// The authentication verifier trailer is truncated or internally inconsistent.
    InvalidAuthVerifier { needed: usize, available: usize },
    /// The requested buffer access would exceed the backing storage.
    BufferTooSmall { needed: usize, available: usize },
    /// The deferred pointer queue reached the C implementation's fixed limit.
    TooManyDeferredPointers { max: usize },
    /// The response allocation hint exceeded the C implementation's safety limit.
    AllocHintOutOfRange { alloc_hint: u32, max: u32 },
    /// The encoded count cannot be represented by the selected NDR syntax.
    CountOutOfRange { count: usize },
    /// UTF-16 data from the wire is not valid Unicode.
    InvalidUtf16,
    /// A decoded pointer was NULL where the caller required a value.
    NullPointer,
}

/// Convenient result type for DCERPC skeleton helpers.
pub type DceRpcResult<T> = Result<T, DceRpcError>;

/// Byte-level NDR encoder/decoder for the migrated DCERPC helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdrCodec {
    direction: Direction,
    transfer_syntax: TransferSyntax,
    little_endian: bool,
    bytes: Vec<u8>,
    offset: usize,
}

impl NdrCodec {
    /// Creates an encoder using little-endian NDR32 layout.
    #[must_use]
    pub fn encoder() -> Self {
        Self::new(Direction::Encode, TransferSyntax::Ndr32, true, Vec::new())
    }

    /// Creates a decoder over `bytes` using little-endian NDR32 layout.
    #[must_use]
    pub fn decoder(bytes: Vec<u8>) -> Self {
        Self::new(Direction::Decode, TransferSyntax::Ndr32, true, bytes)
    }

    /// Creates a codec with explicit direction, transfer syntax, endian, and storage.
    #[must_use]
    pub const fn new(
        direction: Direction,
        transfer_syntax: TransferSyntax,
        little_endian: bool,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            direction,
            transfer_syntax,
            little_endian,
            bytes,
            offset: 0,
        }
    }

    /// Returns the current byte offset.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Sets the current byte offset used by the next primitive coder.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError::BufferTooSmall`] when a decoder is moved beyond
    /// the backing input. Encoders grow their backing storage to the requested
    /// offset, mirroring sparse writes through the public C-style offset API.
    pub fn set_offset(&mut self, offset: usize) -> DceRpcResult<()> {
        self.offset = offset;
        match self.direction {
            Direction::Decode | Direction::Response => self.ensure_available(0),
            Direction::Encode | Direction::Request => {
                self.ensure_write(0);
                Ok(())
            }
        }
    }

    /// Returns the current coding direction.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Returns the selected NDR transfer syntax.
    #[must_use]
    pub const fn transfer_syntax(&self) -> TransferSyntax {
        self.transfer_syntax
    }

    /// Returns the encoded or decoded backing bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns the backing bytes without consuming the codec.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Aligns the current offset to `alignment`.
    pub fn align(&mut self, alignment: usize) {
        self.offset = align_offset(self.offset, alignment);
        if matches!(self.direction, Direction::Encode | Direction::Request)
            && self.bytes.len() < self.offset
        {
            self.bytes.resize(self.offset, 0);
        }
    }

    /// Aligns to the selected pointer-width boundary.
    pub fn align_3264(&mut self) {
        self.align(self.transfer_syntax.pointer_alignment());
    }

    /// Encodes or decodes an unsigned 8-bit integer.
    pub fn code_u8(&mut self, value: &mut u8) -> DceRpcResult<()> {
        match self.direction {
            Direction::Decode | Direction::Response => {
                self.ensure_available(1)?;
                *value = self.bytes[self.offset];
                self.offset += 1;
            }
            Direction::Encode | Direction::Request => {
                self.ensure_write(1);
                self.bytes[self.offset] = *value;
                self.offset += 1;
            }
        }
        Ok(())
    }

    /// Encodes or decodes an unsigned 16-bit integer with NDR alignment.
    pub fn code_u16(&mut self, value: &mut u16) -> DceRpcResult<()> {
        self.align(2);
        match self.direction {
            Direction::Decode | Direction::Response => {
                self.ensure_available(2)?;
                let bytes = [self.bytes[self.offset], self.bytes[self.offset + 1]];
                *value = if self.little_endian {
                    u16::from_le_bytes(bytes)
                } else {
                    u16::from_be_bytes(bytes)
                };
                self.offset += 2;
            }
            Direction::Encode | Direction::Request => {
                self.ensure_write(2);
                let bytes = if self.little_endian {
                    value.to_le_bytes()
                } else {
                    value.to_be_bytes()
                };
                self.bytes[self.offset..self.offset + 2].copy_from_slice(&bytes);
                self.offset += 2;
            }
        }
        Ok(())
    }

    /// Encodes or decodes an unsigned 32-bit integer with NDR alignment.
    pub fn code_u32(&mut self, value: &mut u32) -> DceRpcResult<()> {
        self.align(4);
        match self.direction {
            Direction::Decode | Direction::Response => {
                self.ensure_available(4)?;
                let bytes = [
                    self.bytes[self.offset],
                    self.bytes[self.offset + 1],
                    self.bytes[self.offset + 2],
                    self.bytes[self.offset + 3],
                ];
                *value = if self.little_endian {
                    u32::from_le_bytes(bytes)
                } else {
                    u32::from_be_bytes(bytes)
                };
                self.offset += 4;
            }
            Direction::Encode | Direction::Request => {
                self.ensure_write(4);
                let bytes = if self.little_endian {
                    value.to_le_bytes()
                } else {
                    value.to_be_bytes()
                };
                self.bytes[self.offset..self.offset + 4].copy_from_slice(&bytes);
                self.offset += 4;
            }
        }
        Ok(())
    }

    /// Encodes or decodes an unsigned 64-bit integer with NDR alignment.
    pub fn code_u64(&mut self, value: &mut u64) -> DceRpcResult<()> {
        self.align(8);
        match self.direction {
            Direction::Decode | Direction::Response => {
                self.ensure_available(8)?;
                let bytes = [
                    self.bytes[self.offset],
                    self.bytes[self.offset + 1],
                    self.bytes[self.offset + 2],
                    self.bytes[self.offset + 3],
                    self.bytes[self.offset + 4],
                    self.bytes[self.offset + 5],
                    self.bytes[self.offset + 6],
                    self.bytes[self.offset + 7],
                ];
                *value = if self.little_endian {
                    u64::from_le_bytes(bytes)
                } else {
                    u64::from_be_bytes(bytes)
                };
                self.offset += 8;
            }
            Direction::Encode | Direction::Request => {
                self.ensure_write(8);
                let bytes = if self.little_endian {
                    value.to_le_bytes()
                } else {
                    value.to_be_bytes()
                };
                self.bytes[self.offset..self.offset + 8].copy_from_slice(&bytes);
                self.offset += 8;
            }
        }
        Ok(())
    }

    /// Encodes or decodes an NDR32/NDR64 variable-width unsigned integer.
    pub fn code_u3264(&mut self, value: &mut u64) -> DceRpcResult<()> {
        match self.transfer_syntax {
            TransferSyntax::Ndr32 => {
                if matches!(self.direction, Direction::Encode | Direction::Request)
                    && *value > u64::from(u32::MAX)
                {
                    return Err(DceRpcError::CountOutOfRange { count: usize::MAX });
                }
                let mut v = *value as u32;
                self.code_u32(&mut v)?;
                *value = u64::from(v);
            }
            TransferSyntax::Ndr64 => self.code_u64(value)?,
        }
        Ok(())
    }

    /// Encodes or decodes an NDR conformance count.
    pub fn code_count(&mut self, value: &mut u64) -> DceRpcResult<()> {
        self.code_u3264(value)
    }

    /// Encodes or decodes raw bytes without extra alignment.
    pub fn code_bytes(&mut self, bytes: &mut Vec<u8>, len: usize) -> DceRpcResult<()> {
        match self.direction {
            Direction::Decode | Direction::Response => {
                self.ensure_available(len)?;
                bytes.clear();
                bytes.extend_from_slice(&self.bytes[self.offset..self.offset + len]);
                self.offset += len;
            }
            Direction::Encode | Direction::Request => {
                if bytes.len() < len {
                    return Err(DceRpcError::BufferTooSmall {
                        needed: len,
                        available: bytes.len(),
                    });
                }
                self.ensure_write(len);
                self.bytes[self.offset..self.offset + len].copy_from_slice(&bytes[..len]);
                self.offset += len;
            }
        }
        Ok(())
    }

    /// Encodes or decodes a UTF-16 conformant varying string.
    pub fn code_utf16(
        &mut self,
        value: &mut DceRpcUtf16,
        nul_terminated: bool,
    ) -> DceRpcResult<()> {
        match self.direction {
            Direction::Encode | Direction::Request => self.encode_utf16(value, nul_terminated),
            Direction::Decode | Direction::Response => self.decode_utf16(value, nul_terminated),
        }
    }

    /// Encodes or decodes a DCERPC UUID.
    pub fn code_uuid(&mut self, uuid: &mut DceRpcUuid) -> DceRpcResult<()> {
        self.code_u32(&mut uuid.v1)?;
        self.code_u16(&mut uuid.v2)?;
        self.code_u16(&mut uuid.v3)?;
        for byte in &mut uuid.v4 {
            self.code_u8(byte)?;
        }
        Ok(())
    }

    /// Encodes or decodes an NDR context handle.
    pub fn code_context_handle(&mut self, handle: &mut NdrContextHandle) -> DceRpcResult<()> {
        self.code_u32(&mut handle.context_handle_attributes)?;
        self.code_uuid(&mut handle.context_handle_uuid)
    }

    /// Encodes or decodes a unique pointer discriminant, returning whether it is non-null.
    pub fn code_unique_pointer_present(&mut self, present: bool) -> DceRpcResult<bool> {
        let mut referent = if present { UPTR } else { 0 };
        self.code_pointer_referent(&mut referent)?;
        Ok(referent != 0)
    }

    /// Encodes or decodes a reference pointer discriminant for nested pointed data.
    pub fn code_ref_pointer(&mut self) -> DceRpcResult<()> {
        let mut referent = RPTR;
        self.code_pointer_referent(&mut referent)
    }

    fn code_pointer_referent(&mut self, referent: &mut u64) -> DceRpcResult<()> {
        match self.transfer_syntax {
            TransferSyntax::Ndr32 => {
                let mut value = *referent as u32;
                self.code_u32(&mut value)?;
                *referent = u64::from(value);
                Ok(())
            }
            TransferSyntax::Ndr64 => self.code_u64(referent),
        }
    }

    fn encode_utf16(&mut self, value: &mut DceRpcUtf16, nul_terminated: bool) -> DceRpcResult<()> {
        let text = value.utf8.as_deref().map_or("", core::convert::identity);
        value.utf16 = text.encode_utf16().collect();
        let mut actual = value.utf16.len();
        if nul_terminated {
            actual = actual.saturating_add(1);
        }
        let mut max = actual;
        if !nul_terminated && (max & 1) != 0 {
            max = max.saturating_add(1);
        }
        value.max_count = usize_to_u32(max)?;
        value.offset = 0;
        value.actual_count = usize_to_u32(actual)?;
        let mut max_count = u64::from(value.max_count);
        let mut offset = u64::from(value.offset);
        let mut actual_count = u64::from(value.actual_count);
        self.code_count(&mut max_count)?;
        self.code_count(&mut offset)?;
        self.code_count(&mut actual_count)?;
        for unit in value.utf16.clone() {
            let mut unit = unit;
            self.code_u16(&mut unit)?;
        }
        if nul_terminated {
            let mut zero = 0u16;
            self.code_u16(&mut zero)?;
        }
        Ok(())
    }

    fn decode_utf16(&mut self, value: &mut DceRpcUtf16, nul_terminated: bool) -> DceRpcResult<()> {
        let mut max_count = 0u64;
        let mut offset = 0u64;
        let mut actual_count = 0u64;
        self.code_count(&mut max_count)?;
        self.code_count(&mut offset)?;
        self.code_count(&mut actual_count)?;
        value.max_count = u64_to_u32(max_count)?;
        value.offset = u64_to_u32(offset)?;
        value.actual_count = u64_to_u32(actual_count)?;
        value.utf16.clear();
        let count = usize::try_from(actual_count)
            .map_err(|_| DceRpcError::CountOutOfRange { count: usize::MAX })?;
        for _ in 0..count {
            let mut unit = 0u16;
            self.code_u16(&mut unit)?;
            value.utf16.push(unit);
        }
        let slice_len = if nul_terminated && value.utf16.last().copied() == Some(0) {
            value.utf16.len().saturating_sub(1)
        } else {
            value.utf16.len()
        };
        let decoded =
            String::from_utf16(&value.utf16[..slice_len]).map_err(|_| DceRpcError::InvalidUtf16)?;
        value.utf8 = Some(decoded);
        Ok(())
    }

    fn ensure_available(&self, len: usize) -> DceRpcResult<()> {
        let needed = self.offset.saturating_add(len);
        if needed > self.bytes.len() {
            Err(DceRpcError::BufferTooSmall {
                needed,
                available: self.bytes.len(),
            })
        } else {
            Ok(())
        }
    }

    fn ensure_write(&mut self, len: usize) {
        let needed = self.offset.saturating_add(len);
        if self.bytes.len() < needed {
            self.bytes.resize(needed, 0);
        }
    }
}

fn usize_to_u32(value: usize) -> DceRpcResult<u32> {
    u32::try_from(value).map_err(|_| DceRpcError::CountOutOfRange { count: value })
}

fn u64_to_u32(value: u64) -> DceRpcResult<u32> {
    u32::try_from(value).map_err(|_| DceRpcError::CountOutOfRange { count: usize::MAX })
}

/// DCERPC UUID layout used by presentation syntax and context handles.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DceRpcUuid {
    /// First UUID component.
    pub v1: u32,
    /// Second UUID component.
    pub v2: u16,
    /// Third UUID component.
    pub v3: u16,
    /// Final eight UUID bytes.
    pub v4: [u8; 8],
}

/// Presentation syntax identifier (`p_syntax_id_t` in the C code).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PSyntaxId {
    /// Syntax UUID.
    pub uuid: DceRpcUuid,
    /// Major syntax version.
    pub vers: u16,
    /// Minor syntax version.
    pub vers_minor: u16,
}

/// NDR context handle payload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NdrContextHandle {
    /// Context-handle attributes.
    pub context_handle_attributes: u32,
    /// Context-handle UUID.
    pub context_handle_uuid: DceRpcUuid,
}

/// UTF-16 string accounting used by the C UTF-16 coders.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DceRpcUtf16 {
    /// UTF-8 view used before encoding or after decoding.
    pub utf8: Option<String>,
    /// UTF-16 units used during staged encoding or decoding.
    pub utf16: Vec<u16>,
    /// Maximum conformant array element count.
    pub max_count: u32,
    /// Conformant-varying array offset.
    pub offset: u32,
    /// Actual conformant-varying array element count.
    pub actual_count: u32,
}

/// Common DCERPC PDU header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceRpcHeader {
    /// RPC major version.
    pub rpc_vers: u8,
    /// RPC minor version.
    pub rpc_vers_minor: u8,
    /// PDU packet type.
    pub ptype: PduType,
    /// PDU flags.
    pub pfc_flags: PfcFlags,
    /// Packed data representation bytes.
    pub packed_drep: [u8; 4],
    /// Fragment length.
    pub frag_length: u16,
    /// Authentication verifier length.
    pub auth_length: u16,
    /// Call identifier.
    pub call_id: u32,
}

impl Default for DceRpcHeader {
    fn default() -> Self {
        Self {
            rpc_vers: 5,
            rpc_vers_minor: 0,
            ptype: PduType::Request,
            pfc_flags: PfcFlags::empty(),
            packed_drep: [DCERPC_DR_LITTLE_ENDIAN, 0, 0, 0],
            frag_length: 0,
            auth_length: 0,
            call_id: 0,
        }
    }
}

impl DceRpcHeader {
    /// Encoded size of a connection-oriented DCERPC common header.
    pub const ENCODED_LEN: usize = 16;

    /// Encodes this common header into standalone bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError`] if primitive NDR encoding fails.
    pub fn to_bytes(&self) -> DceRpcResult<Vec<u8>> {
        let mut header = self.clone();
        let mut codec = NdrCodec::new(
            Direction::Encode,
            TransferSyntax::Ndr32,
            header.is_little_endian(),
            Vec::with_capacity(Self::ENCODED_LEN),
        );
        header.code(&mut codec)?;
        Ok(codec.into_bytes())
    }

    /// Decodes a common DCERPC header from standalone bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError::BufferTooSmall`] when `bytes` is shorter than a
    /// header, or [`DceRpcError::InvalidPduType`] for unknown packet types.
    pub fn from_bytes(bytes: &[u8]) -> DceRpcResult<Self> {
        let mut header = Self::default();
        let mut prefix_codec = NdrCodec::decoder(bytes.to_vec());
        header.code_prefix(&mut prefix_codec)?;

        let mut codec = NdrCodec::new(
            Direction::Decode,
            TransferSyntax::Ndr32,
            header.is_little_endian(),
            bytes.to_vec(),
        );
        codec.set_offset(prefix_codec.offset())?;
        header.code_suffix(&mut codec)?;
        Ok(header)
    }

    fn code(&mut self, codec: &mut NdrCodec) -> DceRpcResult<()> {
        self.code_prefix(codec)?;
        self.code_suffix(codec)
    }

    fn code_prefix(&mut self, codec: &mut NdrCodec) -> DceRpcResult<()> {
        codec.code_u8(&mut self.rpc_vers)?;
        codec.code_u8(&mut self.rpc_vers_minor)?;
        let mut ptype = self.ptype as u8;
        codec.code_u8(&mut ptype)?;
        self.ptype = PduType::try_from(ptype)?;
        let mut flags = self.pfc_flags.bits();
        codec.code_u8(&mut flags)?;
        self.pfc_flags = PfcFlags(flags);
        let mut packed_drep = self.packed_drep.to_vec();
        codec.code_bytes(&mut packed_drep, 4)?;
        self.packed_drep.copy_from_slice(&packed_drep);
        Ok(())
    }

    fn code_suffix(&mut self, codec: &mut NdrCodec) -> DceRpcResult<()> {
        codec.code_u16(&mut self.frag_length)?;
        codec.code_u16(&mut self.auth_length)?;
        codec.code_u32(&mut self.call_id)
    }

    const fn is_little_endian(&self) -> bool {
        (self.packed_drep[0] & DCERPC_DR_LITTLE_ENDIAN) != 0
    }
}

impl TryFrom<u8> for PduType {
    type Error = DceRpcError;

    fn try_from(value: u8) -> DceRpcResult<Self> {
        match value {
            0 => Ok(Self::Request),
            1 => Ok(Self::Ping),
            2 => Ok(Self::Response),
            3 => Ok(Self::Fault),
            4 => Ok(Self::Working),
            5 => Ok(Self::NoCall),
            6 => Ok(Self::Reject),
            7 => Ok(Self::Ack),
            8 => Ok(Self::ClientCancel),
            9 => Ok(Self::FragmentAck),
            10 => Ok(Self::CancelAck),
            11 => Ok(Self::Bind),
            12 => Ok(Self::BindAck),
            13 => Ok(Self::BindNak),
            14 => Ok(Self::AlterContext),
            15 => Ok(Self::AlterContextResponse),
            17 => Ok(Self::Shutdown),
            18 => Ok(Self::ConnectionOrientedCancel),
            19 => Ok(Self::Orphaned),
            _ => Err(DceRpcError::InvalidPduType { ptype: value }),
        }
    }
}

/// Presentation context element used by bind PDUs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PContElem {
    /// Presentation context identifier.
    pub p_cont_id: u16,
    /// Number of transfer syntaxes proposed.
    pub n_transfer_syn: u8,
    /// Reserved alignment byte.
    pub reserved: u8,
    /// Abstract syntax for this context.
    pub abstract_syntax: Option<PSyntaxId>,
    /// Transfer syntaxes proposed for this context.
    pub transfer_syntaxes: Vec<PSyntaxId>,
}

/// Bind PDU body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceRpcBindPdu {
    /// Maximum transmit fragment size.
    pub max_xmit_frag: u16,
    /// Maximum receive fragment size.
    pub max_recv_frag: u16,
    /// Association group identifier.
    pub assoc_group_id: u32,
    /// Presentation context list.
    pub p_cont_elem: Vec<PContElem>,
}

impl Default for DceRpcBindPdu {
    fn default() -> Self {
        Self {
            max_xmit_frag: 32_768,
            max_recv_frag: 32_768,
            assoc_group_id: 0,
            p_cont_elem: Vec::new(),
        }
    }
}

impl DceRpcBindPdu {
    /// Encodes the bind body fields.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError::CountOutOfRange`] when the presentation-context
    /// count cannot be represented on the wire, or a primitive codec error.
    pub fn to_bytes(&self) -> DceRpcResult<Vec<u8>> {
        let mut body = self.clone();
        let mut codec = NdrCodec::encoder();
        body.code(&mut codec)?;
        Ok(codec.into_bytes())
    }

    /// Decodes a bind PDU body.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError`] when the buffer is truncated or structurally
    /// invalid.
    pub fn from_bytes(bytes: &[u8]) -> DceRpcResult<Self> {
        let mut body = Self::default();
        let mut codec = NdrCodec::decoder(bytes.to_vec());
        body.code(&mut codec)?;
        Ok(body)
    }

    /// Returns the number of presentation contexts.
    #[must_use]
    pub fn n_context_elem(&self) -> u8 {
        let len = self.p_cont_elem.len();
        if len > usize::from(u8::MAX) {
            u8::MAX
        } else {
            len as u8
        }
    }

    fn code(&mut self, codec: &mut NdrCodec) -> DceRpcResult<()> {
        codec.code_u16(&mut self.max_xmit_frag)?;
        codec.code_u16(&mut self.max_recv_frag)?;
        codec.code_u32(&mut self.assoc_group_id)?;
        if matches!(codec.direction(), Direction::Encode | Direction::Request)
            && self.p_cont_elem.len() > usize::from(u8::MAX)
        {
            return Err(DceRpcError::CountOutOfRange {
                count: self.p_cont_elem.len(),
            });
        }
        let mut n_context_elem = self.n_context_elem();
        codec.code_u8(&mut n_context_elem)?;
        let mut reserved = 0u8;
        codec.code_u8(&mut reserved)?;
        let mut reserved2 = 0u16;
        codec.code_u16(&mut reserved2)?;

        if matches!(codec.direction(), Direction::Decode | Direction::Response) {
            self.p_cont_elem
                .resize_with(usize::from(n_context_elem), PContElem::default);
        }

        for elem in &mut self.p_cont_elem {
            elem.code(codec)?;
        }
        Ok(())
    }
}

impl PContElem {
    fn code(&mut self, codec: &mut NdrCodec) -> DceRpcResult<()> {
        if matches!(codec.direction(), Direction::Encode | Direction::Request) {
            self.n_transfer_syn = u8::try_from(self.transfer_syntaxes.len()).map_err(|_| {
                DceRpcError::CountOutOfRange {
                    count: self.transfer_syntaxes.len(),
                }
            })?;
        }
        codec.code_u16(&mut self.p_cont_id)?;
        codec.code_u8(&mut self.n_transfer_syn)?;
        codec.code_u8(&mut self.reserved)?;

        let mut abstract_syntax = self.abstract_syntax.unwrap_or_default();
        code_p_syntax_id(codec, &mut abstract_syntax)?;
        self.abstract_syntax = Some(abstract_syntax);

        if matches!(codec.direction(), Direction::Decode | Direction::Response) {
            self.transfer_syntaxes
                .resize(usize::from(self.n_transfer_syn), PSyntaxId::default());
        }

        for syntax in &mut self.transfer_syntaxes {
            code_p_syntax_id(codec, syntax)?;
        }
        Ok(())
    }
}

/// Bind acknowledgement result item.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DceRpcBindContextResult {
    /// Acknowledgement result.
    pub ack_result: u16,
    /// Acknowledgement reason.
    pub ack_reason: u16,
    /// Accepted transfer syntax UUID.
    pub uuid: DceRpcUuid,
    /// Accepted transfer syntax version.
    pub syntax_version: u32,
}

/// Bind acknowledgement PDU body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceRpcBindAckPdu {
    /// Maximum transmit fragment size.
    pub max_xmit_frag: u16,
    /// Maximum receive fragment size.
    pub max_recv_frag: u16,
    /// Association group identifier.
    pub assoc_group_id: u32,
    /// Presentation context results.
    pub results: Vec<DceRpcBindContextResult>,
}

impl Default for DceRpcBindAckPdu {
    fn default() -> Self {
        Self {
            max_xmit_frag: 0,
            max_recv_frag: 0,
            assoc_group_id: 0,
            results: Vec::with_capacity(MAX_ACK_RESULTS),
        }
    }
}

impl DceRpcBindAckPdu {
    /// Encodes the bind acknowledgement body fields.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError::CountOutOfRange`] when too many context results
    /// are represented, or a primitive codec error.
    pub fn to_bytes(&self) -> DceRpcResult<Vec<u8>> {
        let mut body = self.clone();
        let mut codec = NdrCodec::encoder();
        body.code(&mut codec)?;
        Ok(codec.into_bytes())
    }

    /// Decodes a bind acknowledgement PDU body.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError`] when the buffer is truncated or structurally
    /// invalid.
    pub fn from_bytes(bytes: &[u8]) -> DceRpcResult<Self> {
        let mut body = Self::default();
        let mut codec = NdrCodec::decoder(bytes.to_vec());
        body.code(&mut codec)?;
        Ok(body)
    }

    fn code(&mut self, codec: &mut NdrCodec) -> DceRpcResult<()> {
        codec.code_u16(&mut self.max_xmit_frag)?;
        codec.code_u16(&mut self.max_recv_frag)?;
        codec.code_u32(&mut self.assoc_group_id)?;

        let mut secondary_address = Vec::new();
        let mut secondary_address_len = 0u16;
        codec.code_u16(&mut secondary_address_len)?;
        if secondary_address_len != 0 {
            codec.code_bytes(&mut secondary_address, usize::from(secondary_address_len))?;
        }
        codec.align(4);

        let mut n_results = results_len_u8(&self.results)?;
        codec.code_u8(&mut n_results)?;
        let mut reserved = 0u8;
        codec.code_u8(&mut reserved)?;
        let mut reserved2 = 0u16;
        codec.code_u16(&mut reserved2)?;

        if matches!(codec.direction(), Direction::Decode | Direction::Response) {
            self.results
                .resize(usize::from(n_results), DceRpcBindContextResult::default());
        }

        for result in &mut self.results {
            result.code(codec)?;
        }
        Ok(())
    }
}

impl DceRpcBindContextResult {
    fn code(&mut self, codec: &mut NdrCodec) -> DceRpcResult<()> {
        codec.code_u16(&mut self.ack_result)?;
        codec.code_u16(&mut self.ack_reason)?;
        codec.code_uuid(&mut self.uuid)?;
        codec.code_u32(&mut self.syntax_version)
    }
}

/// Request PDU body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DceRpcRequestPdu {
    /// Allocation hint for stub data.
    pub alloc_hint: u32,
    /// Presentation context identifier.
    pub context_id: u16,
    /// Operation number.
    pub opnum: u16,
}

impl DceRpcRequestPdu {
    /// Encoded size of a request PDU body header before stub data.
    pub const ENCODED_LEN: usize = 8;

    /// Encodes the request body fields that precede stub data.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError`] if primitive NDR encoding fails.
    pub fn to_bytes(&self) -> DceRpcResult<Vec<u8>> {
        let mut body = *self;
        let mut codec = NdrCodec::new(
            Direction::Encode,
            TransferSyntax::Ndr32,
            true,
            Vec::with_capacity(Self::ENCODED_LEN),
        );
        body.code(&mut codec)?;
        Ok(codec.into_bytes())
    }

    /// Decodes request body fields that precede stub data.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError::BufferTooSmall`] when `bytes` is shorter than a
    /// request body header.
    pub fn from_bytes(bytes: &[u8]) -> DceRpcResult<Self> {
        let mut body = Self::default();
        let mut codec = NdrCodec::decoder(bytes.to_vec());
        body.code(&mut codec)?;
        Ok(body)
    }

    fn code(&mut self, codec: &mut NdrCodec) -> DceRpcResult<()> {
        codec.code_u32(&mut self.alloc_hint)?;
        codec.code_u16(&mut self.context_id)?;
        codec.code_u16(&mut self.opnum)
    }
}

/// Response PDU body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DceRpcResponsePdu {
    /// Allocation hint for stub data.
    pub alloc_hint: u32,
    /// Presentation context identifier.
    pub context_id: u16,
    /// Cancel count from the response header body.
    pub cancel_count: u8,
    /// Reserved alignment byte.
    pub reserved: u8,
}

impl DceRpcResponsePdu {
    /// Encoded size of a response PDU body header before stub data.
    pub const ENCODED_LEN: usize = 8;

    /// Encodes the response body fields that precede stub data.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError`] if primitive NDR encoding fails.
    pub fn to_bytes(&self) -> DceRpcResult<Vec<u8>> {
        let mut body = *self;
        let mut codec = NdrCodec::new(
            Direction::Encode,
            TransferSyntax::Ndr32,
            true,
            Vec::with_capacity(Self::ENCODED_LEN),
        );
        body.code(&mut codec)?;
        Ok(codec.into_bytes())
    }

    /// Decodes response body fields that precede stub data.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError::BufferTooSmall`] when `bytes` is shorter than a
    /// response body header.
    pub fn from_bytes(bytes: &[u8]) -> DceRpcResult<Self> {
        let mut body = Self::default();
        let mut codec = NdrCodec::decoder(bytes.to_vec());
        body.code(&mut codec)?;
        Ok(body)
    }

    fn code(&mut self, codec: &mut NdrCodec) -> DceRpcResult<()> {
        codec.code_u32(&mut self.alloc_hint)?;
        codec.code_u16(&mut self.context_id)?;
        codec.code_u8(&mut self.cancel_count)?;
        codec.code_u8(&mut self.reserved)
    }
}

/// Parsed DCERPC authentication verifier trailer and its preceding auth padding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DceRpcAuthVerifier {
    /// Padding bytes between stub data and the security trailer.
    pub auth_pad: Vec<u8>,
    /// Authentication service identifier.
    pub auth_type: u8,
    /// Authentication protection level.
    pub auth_level: u8,
    /// Padding byte count recorded in the security trailer.
    pub auth_pad_length: u8,
    /// Reserved security trailer byte.
    pub auth_reserved: u8,
    /// Authentication context identifier.
    pub auth_context_id: u32,
    /// Authentication token bytes whose length is recorded in the common header.
    pub auth_value: Vec<u8>,
}

impl DceRpcAuthVerifier {
    /// Encoded security trailer length without auth padding or auth token bytes.
    pub const SECURITY_TRAILER_LEN: usize = 8;

    fn split_from_fragment(
        fragment: &[u8],
        auth_length: u16,
    ) -> DceRpcResult<(&[u8], Option<Self>)> {
        if auth_length == 0 {
            return Ok((fragment, None));
        }

        let auth_len = usize::from(auth_length);
        let needed = Self::SECURITY_TRAILER_LEN.saturating_add(auth_len);
        if fragment.len() < needed {
            return Err(DceRpcError::InvalidAuthVerifier {
                needed,
                available: fragment.len(),
            });
        }

        let trailer_start = fragment.len() - needed;
        let auth_pad_length = fragment[trailer_start + 2];
        let pad_len = usize::from(auth_pad_length);
        if trailer_start < pad_len {
            return Err(DceRpcError::InvalidAuthVerifier {
                needed: needed.saturating_add(pad_len),
                available: fragment.len(),
            });
        }

        let body_end = trailer_start - pad_len;
        let auth_context_id = u32::from_le_bytes([
            fragment[trailer_start + 4],
            fragment[trailer_start + 5],
            fragment[trailer_start + 6],
            fragment[trailer_start + 7],
        ]);
        let auth_value_start = trailer_start + Self::SECURITY_TRAILER_LEN;

        Ok((
            &fragment[..body_end],
            Some(Self {
                auth_pad: fragment[body_end..trailer_start].to_vec(),
                auth_type: fragment[trailer_start],
                auth_level: fragment[trailer_start + 1],
                auth_pad_length,
                auth_reserved: fragment[trailer_start + 3],
                auth_context_id,
                auth_value: fragment[auth_value_start..].to_vec(),
            }),
        ))
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.auth_pad.clone();
        bytes.push(self.auth_type);
        bytes.push(self.auth_level);
        bytes.push(self.auth_pad_length);
        bytes.push(self.auth_reserved);
        bytes.extend_from_slice(&self.auth_context_id.to_le_bytes());
        bytes.extend_from_slice(&self.auth_value);
        bytes
    }
}

/// PDU body variants mirrored from the C union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DceRpcPduBody {
    /// Bind PDU body.
    Bind(DceRpcBindPdu),
    /// Bind acknowledgement PDU body.
    BindAck(DceRpcBindAckPdu),
    /// Request PDU body.
    Request(DceRpcRequestPdu),
    /// Response PDU body.
    Response(DceRpcResponsePdu),
    /// Valid PDU type whose body is not decoded into structured fields yet.
    Unsupported { ptype: PduType, bytes: Vec<u8> },
}

impl Default for DceRpcPduBody {
    fn default() -> Self {
        Self::Request(DceRpcRequestPdu::default())
    }
}

/// Deferred pointer entry recorded while walking NDR data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceRpcDeferredPointer {
    /// Pointer flavor represented by the queued item.
    pub ptr_type: PtrType,
    /// Human-readable coder name retained until real coder callbacks exist.
    pub coder_name: &'static str,
}

/// DCERPC PDU state used by encoder and decoder skeletons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceRpcPdu {
    /// Common PDU header.
    pub hdr: DceRpcHeader,
    /// PDU body selected by `hdr.ptype`.
    pub body: DceRpcPduBody,
    /// Decode or encode direction.
    pub direction: Direction,
    /// Stub payload storage.
    pub payload: Vec<u8>,
    /// Parsed authentication verifier preserved from authenticated fragments.
    pub auth_verifier: Option<DceRpcAuthVerifier>,
    /// Expected decode payload size.
    pub decode_size: usize,
    /// Whether the current coder is handling top-level data.
    pub top_level: bool,
    /// Next pointer identifier for full pointers.
    pub ptr_id: u64,
    /// Deferred pointers queued during NDR pointer traversal.
    pub ptrs: VecDeque<DceRpcDeferredPointer>,
    /// Whether the coder is in the conformance pass.
    pub is_conformance_run: bool,
    /// Maximum alignment observed during the conformance pass.
    pub max_alignment: usize,
    /// Last `size_is()` value passed through pointer decoding.
    pub size_is: i32,
}

/// Locally prepared DCERPC PDU that has not been sent on any transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceRpcPendingPdu {
    /// Structured PDU representation.
    pub pdu: DceRpcPdu,
    /// Complete encoded DCERPC PDU bytes: common header, body, and stub payload.
    pub encoded: Vec<u8>,
}

/// Locally prepared named-pipe open request state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceRpcPendingOpen {
    /// Named pipe path to open through an SMB2 transport layer.
    pub path: Option<String>,
    /// Abstract syntax that will be bound after the pipe is opened.
    pub syntax: Option<PSyntaxId>,
    /// Next call identifier retained for the bind PDU.
    pub call_id: u32,
}

impl DceRpcPdu {
    /// Creates a PDU skeleton for the requested direction and payload capacity.
    #[must_use]
    pub fn new(call_id: u32, direction: Direction, payload_size: usize) -> Self {
        let hdr = DceRpcHeader {
            call_id,
            ..DceRpcHeader::default()
        };

        Self {
            hdr,
            body: DceRpcPduBody::default(),
            direction,
            payload: vec![0; payload_size],
            auth_verifier: None,
            decode_size: 0,
            top_level: true,
            ptr_id: 0,
            ptrs: VecDeque::new(),
            is_conformance_run: false,
            max_alignment: 1,
            size_is: 0,
        }
    }

    /// Returns a shared view of the PDU payload buffer.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns a mutable view of the PDU payload buffer.
    #[must_use]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.payload
    }

    /// Returns the current coding direction.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Overrides the endian bit used by primitive coders.
    pub fn set_endian(&mut self, little_endian: bool) {
        if little_endian {
            self.hdr.packed_drep[0] |= DCERPC_DR_LITTLE_ENDIAN;
        } else {
            self.hdr.packed_drep[0] &= !DCERPC_DR_LITTLE_ENDIAN;
        }
    }

    /// Returns true when primitive coders should use little-endian layout.
    #[must_use]
    pub const fn is_little_endian(&self) -> bool {
        (self.hdr.packed_drep[0] & DCERPC_DR_LITTLE_ENDIAN) != 0
    }

    /// Stores the `size_is()` value used by pointer-aware array coders.
    pub fn set_size_is(&mut self, size_is: i32) {
        self.size_is = size_is;
    }

    /// Returns the last `size_is()` value used by pointer-aware array coders.
    #[must_use]
    pub const fn size_is(&self) -> i32 {
        self.size_is
    }

    /// Queues a deferred pointer entry without running any protocol coder.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError::TooManyDeferredPointers`] when the queue reaches
    /// [`MAX_DEFERRED_PTR`].
    pub fn add_deferred_pointer(
        &mut self,
        ptr_type: PtrType,
        coder_name: &'static str,
    ) -> DceRpcResult<()> {
        if self.ptrs.len() >= MAX_DEFERRED_PTR {
            return Err(DceRpcError::TooManyDeferredPointers {
                max: MAX_DEFERRED_PTR,
            });
        }

        self.ptrs.push_back(DceRpcDeferredPointer {
            ptr_type,
            coder_name,
        });
        Ok(())
    }

    /// Drains deferred pointer entries in FIFO order.
    #[must_use]
    pub fn drain_deferred_pointers(&mut self) -> Vec<DceRpcDeferredPointer> {
        self.ptrs.drain(..).collect()
    }

    /// Encodes this PDU as common header, selected body, and stub payload.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError`] when the selected body is structurally invalid or
    /// the complete fragment length cannot be represented in the DCERPC header.
    pub fn to_bytes(&self) -> DceRpcResult<Vec<u8>> {
        let body = self.body_to_bytes()?;
        let auth = self
            .auth_verifier
            .as_ref()
            .map(DceRpcAuthVerifier::to_bytes);
        let auth_len = self
            .auth_verifier
            .as_ref()
            .map_or(0, |auth| auth.auth_value.len());
        let frag_length = DceRpcHeader::ENCODED_LEN
            .saturating_add(body.len())
            .saturating_add(self.payload.len())
            .saturating_add(auth.as_ref().map_or(0, Vec::len));
        let frag_length = u16::try_from(frag_length)
            .map_err(|_| DceRpcError::CountOutOfRange { count: frag_length })?;
        let auth_length = u16::try_from(auth_len)
            .map_err(|_| DceRpcError::CountOutOfRange { count: auth_len })?;

        let mut header = self.hdr.clone();
        header.ptype = self.body.ptype();
        header.pfc_flags = PfcFlags::first_and_last();
        header.packed_drep = self.hdr.packed_drep;
        header.frag_length = frag_length;
        header.auth_length = auth_length;

        let mut bytes = header.to_bytes()?;
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&self.payload);
        if let Some(auth) = auth {
            bytes.extend_from_slice(&auth);
        }
        Ok(bytes)
    }

    /// Decodes a complete DCERPC PDU from common header, body, and payload.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError`] when the fragment is truncated or structurally invalid.
    pub fn from_bytes(bytes: &[u8]) -> DceRpcResult<Self> {
        let header = DceRpcHeader::from_bytes(bytes)?;
        if usize::from(header.frag_length) > bytes.len() {
            return Err(DceRpcError::BufferTooSmall {
                needed: usize::from(header.frag_length),
                available: bytes.len(),
            });
        }

        let fragment = &bytes[..usize::from(header.frag_length)];
        let (body_payload, auth_verifier) = DceRpcAuthVerifier::split_from_fragment(
            &fragment[DceRpcHeader::ENCODED_LEN..],
            header.auth_length,
        )?;
        let (body, payload) = DceRpcPduBody::decode(header.ptype, body_payload)?;
        Ok(Self {
            hdr: header,
            body,
            direction: Direction::Decode,
            payload,
            auth_verifier,
            decode_size: 0,
            top_level: true,
            ptr_id: 0,
            ptrs: VecDeque::new(),
            is_conformance_run: false,
            max_alignment: 1,
            size_is: 0,
        })
    }

    fn body_to_bytes(&self) -> DceRpcResult<Vec<u8>> {
        match &self.body {
            DceRpcPduBody::Bind(body) => body.to_bytes(),
            DceRpcPduBody::BindAck(body) => body.to_bytes(),
            DceRpcPduBody::Request(body) => body.to_bytes(),
            DceRpcPduBody::Response(body) => body.to_bytes(),
            DceRpcPduBody::Unsupported { bytes, .. } => Ok(bytes.clone()),
        }
    }
}

impl DceRpcPduBody {
    fn ptype(&self) -> PduType {
        match self {
            Self::Bind(_) => PduType::Bind,
            Self::BindAck(_) => PduType::BindAck,
            Self::Request(_) => PduType::Request,
            Self::Response(_) => PduType::Response,
            Self::Unsupported { ptype, .. } => *ptype,
        }
    }

    fn decode(ptype: PduType, bytes: &[u8]) -> DceRpcResult<(Self, Vec<u8>)> {
        match ptype {
            PduType::Bind => Ok((Self::Bind(DceRpcBindPdu::from_bytes(bytes)?), Vec::new())),
            PduType::BindAck => Ok((
                Self::BindAck(DceRpcBindAckPdu::from_bytes(bytes)?),
                Vec::new(),
            )),
            PduType::Request => {
                if bytes.len() < DceRpcRequestPdu::ENCODED_LEN {
                    return Err(DceRpcError::BufferTooSmall {
                        needed: DceRpcRequestPdu::ENCODED_LEN,
                        available: bytes.len(),
                    });
                }
                let body = DceRpcRequestPdu::from_bytes(&bytes[..DceRpcRequestPdu::ENCODED_LEN])?;
                Ok((
                    Self::Request(body),
                    bytes[DceRpcRequestPdu::ENCODED_LEN..].to_vec(),
                ))
            }
            PduType::Response => {
                if bytes.len() < DceRpcResponsePdu::ENCODED_LEN {
                    return Err(DceRpcError::BufferTooSmall {
                        needed: DceRpcResponsePdu::ENCODED_LEN,
                        available: bytes.len(),
                    });
                }
                let body = DceRpcResponsePdu::from_bytes(&bytes[..DceRpcResponsePdu::ENCODED_LEN])?;
                Ok((
                    Self::Response(body),
                    bytes[DceRpcResponsePdu::ENCODED_LEN..].to_vec(),
                ))
            }
            ptype => Ok((
                Self::Unsupported {
                    ptype,
                    bytes: bytes.to_vec(),
                },
                Vec::new(),
            )),
        }
    }
}

/// DCERPC context state corresponding to `struct dcerpc_context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceRpcContext {
    /// Named pipe path used for the DCERPC transport.
    pub path: Option<String>,
    /// Abstract syntax requested during bind.
    pub syntax: Option<PSyntaxId>,
    /// SMB2 file identifier for the opened named pipe.
    pub file_id: [u8; 16],
    /// Selected transfer syntax.
    pub transfer_syntax: TransferSyntax,
    /// Packed data representation bytes.
    pub packed_drep: [u8; 4],
    /// Next call identifier.
    pub call_id: u32,
}

impl Default for DceRpcContext {
    fn default() -> Self {
        Self {
            path: None,
            syntax: None,
            file_id: [0; 16],
            transfer_syntax: TransferSyntax::default(),
            packed_drep: [DCERPC_DR_LITTLE_ENDIAN, 0, 0, 0],
            call_id: 1,
        }
    }
}

impl DceRpcContext {
    /// Creates a new DCERPC context skeleton.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Prepares context fields for a named-pipe connection.
    pub fn connect_context(&mut self, path: impl Into<String>, syntax: PSyntaxId) {
        self.call_id = 2;
        self.path = Some(path.into());
        self.syntax = Some(syntax);
        self.packed_drep[0] = DCERPC_DR_ASCII | DCERPC_DR_LITTLE_ENDIAN;
    }

    /// Allocates a PDU skeleton and advances the context call id.
    #[must_use]
    pub fn allocate_pdu(&mut self, direction: Direction, payload_size: usize) -> DceRpcPdu {
        let pdu = DceRpcPdu::new(self.call_id, direction, payload_size);
        self.call_id = self.call_id.saturating_add(1);
        pdu
    }

    /// Builds the bind PDU body proposed by the C `dcerpc_bind_async` path.
    #[must_use]
    pub fn build_bind_pdu(&self, prefer: NdrPreference) -> DceRpcBindPdu {
        let mut bind = DceRpcBindPdu::default();
        let syntax = self.syntax;

        if matches!(prefer, NdrPreference::Any | NdrPreference::Ndr32) {
            bind.p_cont_elem.push(PContElem {
                p_cont_id: 0,
                n_transfer_syn: 1,
                reserved: 0,
                abstract_syntax: syntax,
                transfer_syntaxes: vec![NDR32_SYNTAX],
            });
        }

        if matches!(prefer, NdrPreference::Any | NdrPreference::Ndr64) {
            bind.p_cont_elem.push(PContElem {
                p_cont_id: 1,
                n_transfer_syn: 1,
                reserved: 0,
                abstract_syntax: syntax,
                transfer_syntaxes: vec![NDR64_SYNTAX],
            });
        }

        bind
    }

    /// Updates the selected transfer syntax by presentation context id.
    pub fn set_tctx(&mut self, tctx: u8) {
        self.transfer_syntax = if tctx == TransferSyntax::Ndr64.context_id() {
            TransferSyntax::Ndr64
        } else {
            TransferSyntax::Ndr32
        };
    }

    /// Aligns an offset to NDR32 or NDR64 pointer-width boundaries.
    #[must_use]
    pub fn align_3264(&self, offset: usize) -> usize {
        align_offset(offset, self.transfer_syntax.pointer_alignment())
    }

    /// Returns the selected presentation context identifier.
    #[must_use]
    pub const fn tctx_id(&self) -> u8 {
        self.transfer_syntax.context_id()
    }

    /// Prepares the C `dcerpc_open_async` named-pipe state without SMB2 IO.
    #[must_use]
    pub fn open_async(&self) -> DceRpcPendingOpen {
        DceRpcPendingOpen {
            path: self.path.clone(),
            syntax: self.syntax,
            call_id: self.call_id,
        }
    }

    /// Prepares the C `dcerpc_bind_async` PDU without sending it.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError`] if the local bind PDU cannot be encoded. This
    /// method does not perform SMB2 named-pipe IO.
    pub fn bind_async(&mut self) -> DceRpcResult<DceRpcPendingPdu> {
        let mut pdu = self.allocate_pdu(Direction::Request, 0);
        pdu.hdr.packed_drep = self.packed_drep;
        pdu.body = DceRpcPduBody::Bind(self.build_bind_pdu(NdrPreference::Any));
        let encoded = pdu.to_bytes()?;
        Ok(DceRpcPendingPdu { pdu, encoded })
    }

    /// Prepares the C `dcerpc_call_async` request PDU without sending it.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError`] if the local request PDU cannot be encoded. This
    /// method does not perform SMB2 named-pipe IO.
    pub fn call_async(&mut self, opnum: u16) -> DceRpcResult<DceRpcPendingPdu> {
        self.call_async_with_payload(opnum, &[])
    }

    /// Prepares a request PDU with caller-supplied NDR stub payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DceRpcError`] if the local request PDU cannot be encoded.
    pub fn call_async_with_payload(
        &mut self,
        opnum: u16,
        payload: &[u8],
    ) -> DceRpcResult<DceRpcPendingPdu> {
        let mut pdu = self.allocate_pdu(Direction::Request, payload.len());
        pdu.hdr.packed_drep = self.packed_drep;
        pdu.body = DceRpcPduBody::Request(DceRpcRequestPdu {
            alloc_hint: usize_to_u32(payload.len())?,
            context_id: u16::from(self.tctx_id()),
            opnum,
        });
        pdu.payload.copy_from_slice(payload);
        let encoded = pdu.to_bytes()?;
        Ok(DceRpcPendingPdu { pdu, encoded })
    }
}

fn code_p_syntax_id(codec: &mut NdrCodec, syntax: &mut PSyntaxId) -> DceRpcResult<()> {
    codec.code_uuid(&mut syntax.uuid)?;
    codec.code_u16(&mut syntax.vers)?;
    codec.code_u16(&mut syntax.vers_minor)
}

fn results_len_u8(results: &[DceRpcBindContextResult]) -> DceRpcResult<u8> {
    u8::try_from(results.len()).map_err(|_| DceRpcError::CountOutOfRange {
        count: results.len(),
    })
}

/// NDR transfer syntax preference used when constructing bind contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdrPreference {
    /// Offer both NDR32 and NDR64.
    Any,
    /// Offer only NDR32.
    Ndr32,
    /// Offer only NDR64.
    Ndr64,
}

/// Aligns `offset` to `alignment`, mirroring the C bit-mask alignment pattern.
#[must_use]
pub const fn align_offset(offset: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        offset
    } else {
        (offset + (alignment - 1)) & !(alignment - 1)
    }
}

/// Exercises the default unsigned 8-bit NDR coder.
///
/// # Errors
///
/// Returns [`DceRpcError`] if the default primitive coder fails.
pub fn dcerpc_uint8_coder() -> DceRpcResult<()> {
    let mut codec = NdrCodec::encoder();
    let mut value = 0u8;
    codec.code_u8(&mut value)
}

/// Exercises the default unsigned 16-bit NDR coder.
///
/// # Errors
///
/// Returns [`DceRpcError`] if the default primitive coder fails.
pub fn dcerpc_uint16_coder() -> DceRpcResult<()> {
    let mut codec = NdrCodec::encoder();
    let mut value = 0u16;
    codec.code_u16(&mut value)
}

/// Exercises the default unsigned 32-bit NDR coder.
///
/// # Errors
///
/// Returns [`DceRpcError`] if the default primitive coder fails.
pub fn dcerpc_uint32_coder() -> DceRpcResult<()> {
    let mut codec = NdrCodec::encoder();
    let mut value = 0u32;
    codec.code_u32(&mut value)
}

/// Exercises the default unsigned 64-bit NDR coder.
///
/// # Errors
///
/// Returns [`DceRpcError`] if the default primitive coder fails.
pub fn dcerpc_uint64_coder() -> DceRpcResult<()> {
    let mut codec = NdrCodec::encoder();
    let mut value = 0u64;
    codec.code_u64(&mut value)
}

/// Exercises the default variable-width unsigned NDR coder.
///
/// # Errors
///
/// Returns [`DceRpcError`] if the default primitive coder fails.
pub fn dcerpc_uint3264_coder() -> DceRpcResult<()> {
    let mut codec = NdrCodec::encoder();
    let mut value = 0u64;
    codec.code_u3264(&mut value)
}

/// Exercises the default conformance-count NDR coder.
///
/// # Errors
///
/// Returns [`DceRpcError`] if the default count coder fails.
pub fn dcerpc_conformance_coder() -> DceRpcResult<()> {
    let mut codec = NdrCodec::encoder();
    let mut value = 0u64;
    codec.code_count(&mut value)
}

/// Exercises a default NDR pointer discriminant coder while preserving the C name.
///
/// # Errors
///
/// Returns [`DceRpcError`] if the default pointer coder fails.
pub fn dcerpc_ptr_coder(ptr_type: PtrType) -> DceRpcResult<()> {
    let mut codec = NdrCodec::encoder();
    match ptr_type {
        PtrType::Ref => codec.code_ref_pointer(),
        PtrType::Full | PtrType::Unique => {
            codec.code_unique_pointer_present(true)?;
            Ok(())
        }
    }
}

/// Exercises a default zero-length conformant-array count coder.
///
/// # Errors
///
/// Returns [`DceRpcError`] if the default count coder fails.
pub fn dcerpc_carray_coder() -> DceRpcResult<()> {
    let mut codec = NdrCodec::encoder();
    let mut count = 0u64;
    codec.code_count(&mut count)
}

/// Exercises the default UTF-16 string coder with an empty string.
///
/// # Errors
///
/// Returns [`DceRpcError`] if the default UTF-16 coder fails.
pub fn dcerpc_utf16_coder() -> DceRpcResult<()> {
    let mut codec = NdrCodec::encoder();
    let mut value = DceRpcUtf16 {
        utf8: Some(String::new()),
        ..DceRpcUtf16::default()
    };
    codec.code_utf16(&mut value, false)
}

/// Exercises the default NUL-terminated UTF-16 string coder with an empty string.
///
/// # Errors
///
/// Returns [`DceRpcError`] if the default UTF-16 coder fails.
pub fn dcerpc_utf16z_coder() -> DceRpcResult<()> {
    let mut codec = NdrCodec::encoder();
    let mut value = DceRpcUtf16 {
        utf8: Some(String::new()),
        ..DceRpcUtf16::default()
    };
    codec.code_utf16(&mut value, true)
}

/// Exercises the default DCERPC header coder.
///
/// # Errors
///
/// Returns [`DceRpcError`] if the default header coder fails.
pub fn dcerpc_header_coder() -> DceRpcResult<()> {
    DceRpcHeader::default().to_bytes().map(|_| ())
}

/// Exercises the default UUID coder.
///
/// # Errors
///
/// Returns [`DceRpcError`] if the default UUID coder fails.
pub fn dcerpc_uuid_coder() -> DceRpcResult<()> {
    let mut codec = NdrCodec::encoder();
    let mut uuid = DceRpcUuid::default();
    codec.code_uuid(&mut uuid)
}

/// Exercises the default context-handle coder.
///
/// # Errors
///
/// Returns [`DceRpcError`] if the default context-handle coder fails.
pub fn dcerpc_context_handle_coder() -> DceRpcResult<()> {
    let mut codec = NdrCodec::encoder();
    let mut handle = NdrContextHandle::default();
    codec.code_context_handle(&mut handle)
}
