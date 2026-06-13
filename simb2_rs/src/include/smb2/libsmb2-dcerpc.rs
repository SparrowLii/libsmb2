//! DCERPC public API skeleton from `include/smb2/libsmb2-dcerpc.h`.
//!
//! The types and functions in this module mirror the public C header boundary.
//! They intentionally do not implement the DCERPC/NDR protocol yet.

use super::libsmb2::{ErrorCode, Result, Smb2Client};

/// DCERPC data-representation flag for big-endian integer encoding.
pub const DCERPC_DR_BIG_ENDIAN: u8 = 0x00;

/// DCERPC data-representation flag for little-endian integer encoding.
pub const DCERPC_DR_LITTLE_ENDIAN: u8 = 0x10;

/// DCERPC data-representation flag for ASCII character encoding.
pub const DCERPC_DR_ASCII: u8 = 0x00;

/// DCERPC data-representation flag for EBCDIC character encoding.
pub const DCERPC_DR_EBCDIC: u8 = 0x01;

/// Direction value used when decoding a staged DCERPC PDU.
pub const DCERPC_DECODE: i32 = 0;

/// Direction value used when encoding a staged DCERPC PDU.
pub const DCERPC_ENCODE: i32 = 1;

const ERROR_FUNCTION_NOT_IMPLEMENTED: i32 = -38;
const ERROR_INVALID_ARGUMENT: i32 = -22;

/// Rust-owned equivalent of the C `struct smb2_iovec` used by DCERPC coders.
pub type Smb2Iovec = crate::include::libsmb2_private::IoVec;

/// Mutable opaque payload passed to staged DCERPC coder functions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DceRpcPayload {
    /// Raw bytes retained until a typed NDR representation is implemented.
    pub bytes: Vec<u8>,
}

/// Encoder/decoder callback shape for a DCERPC object.
pub type DceRpcCoder = fn(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    payload: &mut DceRpcPayload,
) -> Result<()>;

/// Completion callback shape for staged DCERPC asynchronous operations.
pub type DceRpcCallback = Box<dyn FnOnce(&mut DceRpcContext, Result<DceRpcCommandData>) + Send>;

/// NDR pointer flavor selected by `dcerpc_ptr_coder`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PtrType {
    /// Reference pointer (`PTR_REF`).
    Ref = 0,
    /// Unique pointer (`PTR_UNIQUE`).
    Unique = 1,
    /// Full pointer (`PTR_FULL`).
    Full = 2,
}

/// DCERPC UUID layout used by presentation syntaxes and context handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

/// Presentation syntax identifier (`p_syntax_id_t` in the C API).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PSyntaxId {
    /// Interface or transfer-syntax UUID.
    pub uuid: DceRpcUuid,
    /// Major syntax version.
    pub vers: u16,
    /// Minor syntax version.
    pub vers_minor: u16,
}

/// NDR transfer syntax descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NdrTransferSyntax {
    /// Transfer-syntax UUID.
    pub uuid: DceRpcUuid,
    /// Transfer-syntax version.
    pub vers: u16,
}

/// Opaque NDR context handle returned by remote DCERPC services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NdrContextHandle {
    /// Context-handle attributes.
    pub context_handle_attributes: u32,
    /// Context-handle UUID.
    pub context_handle_uuid: DceRpcUuid,
}

/// UTF-16 string accounting used by DCERPC string coders.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DceRpcUtf16 {
    /// Maximum conformant array element count; internal coder bookkeeping.
    pub max_count: u32,
    /// Conformant-varying array offset; internal coder bookkeeping.
    pub offset: u32,
    /// Actual conformant-varying array element count; internal coder bookkeeping.
    pub actual_count: u32,
    /// UTF-16 units retained while protocol coding is staged.
    pub utf16: Vec<u16>,
    /// UTF-8 view supplied by or returned to callers.
    pub utf8: Option<String>,
}

/// Counted byte array used by DCERPC conformant-array helpers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DceRpcCarray {
    /// Maximum number of bytes represented by `data`.
    pub max_count: u32,
    /// Raw array bytes.
    pub data: Vec<u8>,
}

/// LSA presentation syntax identifier placeholder exported by the C API.
pub const LSA_INTERFACE: PSyntaxId = PSyntaxId {
    uuid: DceRpcUuid {
        v1: 0x1234_5778,
        v2: 0x1234,
        v3: 0xabcd,
        v4: [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb],
    },
    vers: 0,
    vers_minor: 0,
};

/// SRVSVC presentation syntax identifier placeholder exported by the C API.
pub const SRVSVC_INTERFACE: PSyntaxId = PSyntaxId {
    uuid: DceRpcUuid {
        v1: 0x4b32_4fc8,
        v2: 0x1670,
        v3: 0x01d3,
        v4: [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88],
    },
    vers: 3,
    vers_minor: 0,
};

/// Data passed to DCERPC completion callbacks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DceRpcCommandData {
    /// Raw command payload retained until typed command data is implemented.
    pub payload: DceRpcPayload,
}

/// DCERPC PDU placeholder corresponding to `struct dcerpc_pdu`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceRpcPdu {
    /// Encode or decode direction associated with this PDU.
    pub direction: i32,
    /// Payload buffer reserved for command data.
    pub payload: DceRpcPayload,
    /// Current `size_is` value used by conformant-array coders.
    pub size_is: i32,
}

impl Default for DceRpcPdu {
    fn default() -> Self {
        Self {
            direction: DCERPC_DECODE,
            payload: DceRpcPayload::default(),
            size_is: 0,
        }
    }
}

/// DCERPC context placeholder corresponding to `struct dcerpc_context`.
#[derive(Debug, Default)]
pub struct DceRpcContext {
    smb2: Option<Smb2Client>,
    error: Option<String>,
    path: Option<String>,
    syntax: Option<PSyntaxId>,
}

impl DceRpcContext {
    /// Creates an empty staged DCERPC context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the named-pipe path selected for this context, if any.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Returns the presentation syntax selected for this context, if any.
    #[must_use]
    pub fn syntax(&self) -> Option<PSyntaxId> {
        self.syntax
    }
}

/// Creates a staged DCERPC context that owns an SMB2 client context.
#[must_use]
pub fn dcerpc_create_context(smb2: Smb2Client) -> DceRpcContext {
    DceRpcContext {
        smb2: Some(smb2),
        ..DceRpcContext::default()
    }
}

/// Releases staged DCERPC-owned command data.
pub fn dcerpc_free_data(_dce: &mut DceRpcContext, _data: DceRpcCommandData) {}

/// Returns the last staged DCERPC error string, if any.
#[must_use]
pub fn dcerpc_get_error(dce: &DceRpcContext) -> Option<&str> {
    dce.error.as_deref()
}

/// Starts connecting a DCERPC context to a named pipe and presentation syntax.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until DCERPC transport binding is implemented.
pub fn dcerpc_connect_context_async(
    dce: &mut DceRpcContext,
    path: &str,
    syntax: PSyntaxId,
    _callback: DceRpcCallback,
) -> Result<()> {
    dce.path = Some(path.to_owned());
    dce.syntax = Some(syntax);
    Err(not_implemented())
}

/// Destroys a staged DCERPC context.
pub fn dcerpc_destroy_context(_dce: DceRpcContext) {}

/// Returns the SMB2 client associated with a DCERPC context, if present.
#[must_use]
pub fn dcerpc_get_smb2_context(dce: &DceRpcContext) -> Option<&Smb2Client> {
    dce.smb2.as_ref()
}

/// Returns the raw payload bytes associated with a DCERPC PDU.
#[must_use]
pub fn dcerpc_get_pdu_payload(pdu: &DceRpcPdu) -> &[u8] {
    &pdu.payload.bytes
}

/// Starts opening the underlying DCERPC named-pipe transport.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until DCERPC transport open is implemented.
pub fn dcerpc_open_async(_dce: &mut DceRpcContext, _callback: DceRpcCallback) -> Result<()> {
    Err(not_implemented())
}

/// Starts a staged DCERPC request/response call.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until DCERPC call transport and NDR coding are implemented.
pub fn dcerpc_call_async(
    _dce: &mut DceRpcContext,
    _opnum: i32,
    _req_coder: DceRpcCoder,
    _req: &mut DceRpcPayload,
    _rep_coder: DceRpcCoder,
    _decode_size: usize,
    _callback: DceRpcCallback,
) -> Result<()> {
    Err(not_implemented())
}

/// Invokes a supplied staged DCERPC coder.
///
/// # Errors
///
/// Propagates the supplied coder's error. Skeleton coders in this module return `ErrorCode(-38)`.
pub fn dcerpc_do_coder(
    ctx: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    ptr: &mut DceRpcPayload,
    coder: DceRpcCoder,
) -> Result<()> {
    coder(ctx, pdu, iov, offset, ptr)
}

/// Encodes or decodes an NDR pointer value.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until NDR pointer coding is implemented.
pub fn dcerpc_ptr_coder(
    _dce: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _ptr: &mut DceRpcPayload,
    _ptr_type: PtrType,
    _coder: DceRpcCoder,
) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes an NDR conformant array.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until NDR array coding is implemented.
pub fn dcerpc_carray_coder(
    _ctx: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _num: usize,
    _ptr: &mut DceRpcPayload,
    _elem_size: usize,
    _coder: DceRpcCoder,
) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes an unsigned 8-bit integer.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until scalar NDR coding is implemented.
pub fn dcerpc_uint8_coder(
    _ctx: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _ptr: &mut u8,
) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes an unsigned 16-bit integer.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until scalar NDR coding is implemented.
pub fn dcerpc_uint16_coder(
    _ctx: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _ptr: &mut u16,
) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes an unsigned 32-bit integer.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until scalar NDR coding is implemented.
pub fn dcerpc_uint32_coder(
    _ctx: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _ptr: &mut u32,
) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes a width-dependent unsigned integer.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until scalar NDR coding is implemented.
pub fn dcerpc_uint3264_coder(
    _ctx: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _ptr: &mut u64,
) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes a conformant-array count.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until NDR conformance coding is implemented.
pub fn dcerpc_conformance_coder(
    _ctx: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _ptr: &mut u32,
) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes a UTF-16 string value.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until NDR UTF-16 coding is implemented.
pub fn dcerpc_utf16_coder(
    _ctx: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _ptr: &mut DceRpcUtf16,
) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes a NUL-terminated UTF-16 string value.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until NDR UTF-16 coding is implemented.
pub fn dcerpc_utf16z_coder(
    _ctx: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _ptr: &mut DceRpcUtf16,
) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes an NDR context handle.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until context-handle coding is implemented.
pub fn dcerpc_context_handle_coder(
    _dce: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _ptr: &mut NdrContextHandle,
) -> Result<()> {
    Err(not_implemented())
}

/// Encodes or decodes a DCERPC UUID.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until UUID coding is implemented.
pub fn dcerpc_uuid_coder(
    _dce: &mut DceRpcContext,
    _pdu: &mut DceRpcPdu,
    _iov: &mut Smb2Iovec,
    _offset: &mut usize,
    _uuid: &mut DceRpcUuid,
) -> Result<()> {
    Err(not_implemented())
}

/// Allocates a staged DCERPC PDU placeholder.
///
/// # Errors
///
/// Returns `ErrorCode(-22)` when `payload_size` is negative.
pub fn dcerpc_allocate_pdu(
    _dce: &mut DceRpcContext,
    direction: i32,
    payload_size: i32,
) -> Result<DceRpcPdu> {
    let payload_len =
        usize::try_from(payload_size).map_err(|_| ErrorCode(ERROR_INVALID_ARGUMENT))?;

    Ok(DceRpcPdu {
        direction,
        payload: DceRpcPayload {
            bytes: vec![0; payload_len],
        },
        size_is: 0,
    })
}

/// Releases a staged DCERPC PDU placeholder.
pub fn dcerpc_free_pdu(_dce: &mut DceRpcContext, _pdu: DceRpcPdu) {}

/// Stores the current `size_is` value used by conformant-array coders.
pub fn dcerpc_set_size_is(pdu: &mut DceRpcPdu, size_is: i32) {
    pdu.size_is = size_is;
}

/// Returns the current `size_is` value used by conformant-array coders.
#[must_use]
pub fn dcerpc_get_size_is(pdu: &DceRpcPdu) -> i32 {
    pdu.size_is
}

fn not_implemented() -> ErrorCode {
    ErrorCode(ERROR_FUNCTION_NOT_IMPLEMENTED)
}
