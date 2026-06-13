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
    /// The requested buffer access would exceed the backing storage.
    BufferTooSmall { needed: usize, available: usize },
    /// The deferred pointer queue reached the C implementation's fixed limit.
    TooManyDeferredPointers { max: usize },
    /// The response allocation hint exceeded the C implementation's safety limit.
    AllocHintOutOfRange { alloc_hint: u32, max: u32 },
}

/// Convenient result type for DCERPC skeleton helpers.
pub type DceRpcResult<T> = Result<T, DceRpcError>;

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

    /// Placeholder for the C `dcerpc_open_async` transport path.
    ///
    /// # Errors
    ///
    /// Always returns [`DceRpcError::ProtocolNotImplemented`] until SMB2 IO is
    /// wired to the Rust migration.
    pub fn open_async(&self) -> DceRpcResult<()> {
        Err(DceRpcError::ProtocolNotImplemented("dcerpc_open_async"))
    }

    /// Placeholder for the C `dcerpc_bind_async` transport path.
    ///
    /// # Errors
    ///
    /// Always returns [`DceRpcError::ProtocolNotImplemented`] until SMB2 IO is
    /// wired to the Rust migration.
    pub fn bind_async(&self) -> DceRpcResult<()> {
        Err(DceRpcError::ProtocolNotImplemented("dcerpc_bind_async"))
    }

    /// Placeholder for the C `dcerpc_call_async` transport path.
    ///
    /// # Errors
    ///
    /// Always returns [`DceRpcError::ProtocolNotImplemented`] until SMB2 IO is
    /// wired to the Rust migration.
    pub fn call_async(&self, _opnum: u16) -> DceRpcResult<()> {
        Err(DceRpcError::ProtocolNotImplemented("dcerpc_call_async"))
    }
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

/// Records an unsupported primitive coder boundary.
///
/// # Errors
///
/// Always returns [`DceRpcError::ProtocolNotImplemented`] because this skeleton
/// intentionally does not implement byte-level NDR coding.
pub fn dcerpc_uint8_coder() -> DceRpcResult<()> {
    Err(DceRpcError::ProtocolNotImplemented("dcerpc_uint8_coder"))
}

/// Records an unsupported primitive coder boundary.
///
/// # Errors
///
/// Always returns [`DceRpcError::ProtocolNotImplemented`] because this skeleton
/// intentionally does not implement byte-level NDR coding.
pub fn dcerpc_uint16_coder() -> DceRpcResult<()> {
    Err(DceRpcError::ProtocolNotImplemented("dcerpc_uint16_coder"))
}

/// Records an unsupported primitive coder boundary.
///
/// # Errors
///
/// Always returns [`DceRpcError::ProtocolNotImplemented`] because this skeleton
/// intentionally does not implement byte-level NDR coding.
pub fn dcerpc_uint32_coder() -> DceRpcResult<()> {
    Err(DceRpcError::ProtocolNotImplemented("dcerpc_uint32_coder"))
}

/// Records an unsupported primitive coder boundary.
///
/// # Errors
///
/// Always returns [`DceRpcError::ProtocolNotImplemented`] because this skeleton
/// intentionally does not implement byte-level NDR coding.
pub fn dcerpc_uint64_coder() -> DceRpcResult<()> {
    Err(DceRpcError::ProtocolNotImplemented("dcerpc_uint64_coder"))
}

/// Records an unsupported variable-width primitive coder boundary.
///
/// # Errors
///
/// Always returns [`DceRpcError::ProtocolNotImplemented`] because this skeleton
/// intentionally does not implement byte-level NDR coding.
pub fn dcerpc_uint3264_coder() -> DceRpcResult<()> {
    Err(DceRpcError::ProtocolNotImplemented("dcerpc_uint3264_coder"))
}

/// Records an unsupported conformance coder boundary.
///
/// # Errors
///
/// Always returns [`DceRpcError::ProtocolNotImplemented`] because this skeleton
/// intentionally does not implement byte-level NDR coding.
pub fn dcerpc_conformance_coder() -> DceRpcResult<()> {
    Err(DceRpcError::ProtocolNotImplemented(
        "dcerpc_conformance_coder",
    ))
}

/// Records an unsupported pointer coder boundary while preserving the C name.
///
/// # Errors
///
/// Always returns [`DceRpcError::ProtocolNotImplemented`] because this skeleton
/// intentionally does not implement byte-level NDR coding.
pub fn dcerpc_ptr_coder(_ptr_type: PtrType) -> DceRpcResult<()> {
    Err(DceRpcError::ProtocolNotImplemented("dcerpc_ptr_coder"))
}

/// Records an unsupported conformant-array coder boundary.
///
/// # Errors
///
/// Always returns [`DceRpcError::ProtocolNotImplemented`] because this skeleton
/// intentionally does not implement byte-level NDR coding.
pub fn dcerpc_carray_coder() -> DceRpcResult<()> {
    Err(DceRpcError::ProtocolNotImplemented("dcerpc_carray_coder"))
}

/// Records an unsupported UTF-16 string coder boundary.
///
/// # Errors
///
/// Always returns [`DceRpcError::ProtocolNotImplemented`] because this skeleton
/// intentionally does not implement byte-level NDR coding.
pub fn dcerpc_utf16_coder() -> DceRpcResult<()> {
    Err(DceRpcError::ProtocolNotImplemented("dcerpc_utf16_coder"))
}

/// Records an unsupported NUL-terminated UTF-16 string coder boundary.
///
/// # Errors
///
/// Always returns [`DceRpcError::ProtocolNotImplemented`] because this skeleton
/// intentionally does not implement byte-level NDR coding.
pub fn dcerpc_utf16z_coder() -> DceRpcResult<()> {
    Err(DceRpcError::ProtocolNotImplemented("dcerpc_utf16z_coder"))
}

/// Records an unsupported header coder boundary.
///
/// # Errors
///
/// Always returns [`DceRpcError::ProtocolNotImplemented`] because this skeleton
/// intentionally does not implement byte-level NDR coding.
pub fn dcerpc_header_coder() -> DceRpcResult<()> {
    Err(DceRpcError::ProtocolNotImplemented("dcerpc_header_coder"))
}

/// Records an unsupported UUID coder boundary.
///
/// # Errors
///
/// Always returns [`DceRpcError::ProtocolNotImplemented`] because this skeleton
/// intentionally does not implement byte-level NDR coding.
pub fn dcerpc_uuid_coder() -> DceRpcResult<()> {
    Err(DceRpcError::ProtocolNotImplemented("dcerpc_uuid_coder"))
}

/// Records an unsupported context-handle coder boundary.
///
/// # Errors
///
/// Always returns [`DceRpcError::ProtocolNotImplemented`] because this skeleton
/// intentionally does not implement byte-level NDR coding.
pub fn dcerpc_context_handle_coder() -> DceRpcResult<()> {
    Err(DceRpcError::ProtocolNotImplemented(
        "dcerpc_context_handle_coder",
    ))
}
