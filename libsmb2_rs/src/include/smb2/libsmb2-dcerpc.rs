//! DCERPC public API skeleton from `include/smb2/libsmb2-dcerpc.h`.
//!
//! The types and functions in this module mirror the public C header boundary.
//! Transport operations use the safe `Smb2Client` named-pipe adapter boundary;
//! coder helpers delegate to the migrated byte-level NDR codec in `lib/dcerpc.rs`.

use super::libsmb2::{ErrorCode, Result, Smb2Client, Smb2TransportAdapter};
use crate::lib::dcerpc as lib_dcerpc;

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

impl DceRpcPayload {
    /// Creates a payload from encoded DCERPC stub bytes.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
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
    lib_ctx: lib_dcerpc::DceRpcContext,
    state: DceRpcTransportState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum DceRpcTransportState {
    #[default]
    Created,
    Prepared,
    Opened,
    Bound,
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

    /// Returns the SMB2 file id selected for the opened named pipe.
    #[must_use]
    pub fn file_id(&self) -> [u8; 16] {
        self.lib_ctx.file_id
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
/// Returns `ErrorCode(-38)` because this API requires named-pipe transport IO.
/// Use [`dcerpc_connect_context_with_transport_async`] when a transport adapter
/// is available.
pub fn dcerpc_connect_context_async(
    dce: &mut DceRpcContext,
    path: &str,
    syntax: PSyntaxId,
    _callback: DceRpcCallback,
) -> Result<()> {
    prepare_context(dce, path, syntax);
    dce.error = Some("DCERPC named-pipe transport is not implemented for this API".to_owned());
    Err(not_implemented())
}

/// Connects a DCERPC context to a named pipe using an injected SMB2 transport.
///
/// This opens the pipe through [`Smb2Client`], writes a DCERPC bind PDU, and
/// requires the adapter to supply a bind acknowledgement.
///
/// # Errors
///
/// Returns an [`ErrorCode`] if the SMB2 client is missing, the adapter rejects
/// open/read/write, or the DCERPC bind response is malformed.
pub fn dcerpc_connect_context_with_transport_async<T: Smb2TransportAdapter + ?Sized>(
    dce: &mut DceRpcContext,
    path: &str,
    syntax: PSyntaxId,
    transport: &mut T,
    callback: DceRpcCallback,
) -> Result<()> {
    prepare_context(dce, path, syntax);
    dcerpc_open_with_transport(dce, transport)?;
    let bind = dce.lib_ctx.bind_async().map_err(map_dcerpc_error)?;
    let response = write_then_read(dce, &bind.encoded, transport)?;
    apply_bind_response(dce, &response)?;
    callback(
        dce,
        Ok(DceRpcCommandData {
            payload: DceRpcPayload::from_bytes(response),
        }),
    );
    Ok(())
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
/// Returns `ErrorCode(-38)` because this API requires named-pipe transport IO.
/// Use [`dcerpc_open_with_transport`] when a transport adapter is available.
pub fn dcerpc_open_async(dce: &mut DceRpcContext, _callback: DceRpcCallback) -> Result<()> {
    dce.error = Some("DCERPC named-pipe open requires a transport adapter".to_owned());
    Err(not_implemented())
}

/// Opens the underlying named pipe using an injected SMB2 transport.
///
/// # Errors
///
/// Returns an [`ErrorCode`] if no SMB2 client is owned by this context, the path
/// or syntax is missing, or the transport rejects the open.
pub fn dcerpc_open_with_transport<T: Smb2TransportAdapter + ?Sized>(
    dce: &mut DceRpcContext,
    transport: &mut T,
) -> Result<()> {
    let path = dce.path.clone().ok_or(ErrorCode(ERROR_INVALID_ARGUMENT))?;
    if dce.syntax.is_none() {
        dce.error = Some("DCERPC syntax is not set".to_owned());
        return Err(ErrorCode(ERROR_INVALID_ARGUMENT));
    }
    let smb2 = dce.smb2.as_mut().ok_or(ErrorCode(ERROR_INVALID_ARGUMENT))?;
    dce.lib_ctx.file_id = smb2.named_pipe_open_with_transport(&path, transport)?;
    dce.state = DceRpcTransportState::Opened;
    Ok(())
}

/// Starts a staged DCERPC request/response call.
///
/// # Errors
///
/// Returns `ErrorCode(-38)` because this API requires named-pipe transport IO.
/// Use [`dcerpc_call_with_transport_async`] when a transport adapter is available.
pub fn dcerpc_call_async(
    dce: &mut DceRpcContext,
    _opnum: i32,
    _req_coder: DceRpcCoder,
    _req: &mut DceRpcPayload,
    _rep_coder: DceRpcCoder,
    _decode_size: usize,
    _callback: DceRpcCallback,
) -> Result<()> {
    dce.error = Some("DCERPC request dispatch requires a transport adapter".to_owned());
    Err(not_implemented())
}

/// Performs a DCERPC request/response call using an injected SMB2 transport.
///
/// # Errors
///
/// Returns an [`ErrorCode`] if request coding fails, transport IO fails, or the
/// response PDU cannot be decoded by the supplied reply coder.
pub fn dcerpc_call_with_transport_async<T: Smb2TransportAdapter + ?Sized>(
    dce: &mut DceRpcContext,
    opnum: i32,
    req_coder: DceRpcCoder,
    req: &mut DceRpcPayload,
    rep_coder: DceRpcCoder,
    decode_size: usize,
    transport: &mut T,
    callback: DceRpcCallback,
) -> Result<()> {
    if dce.state != DceRpcTransportState::Bound {
        dce.error = Some("DCERPC context is not bound to a named pipe".to_owned());
        return Err(ErrorCode(ERROR_INVALID_ARGUMENT));
    }
    let opnum = u16::try_from(opnum).map_err(|_| ErrorCode(ERROR_INVALID_ARGUMENT))?;
    let mut pdu = dcerpc_allocate_pdu(dce, DCERPC_ENCODE, len_to_i32(req.bytes.len())?)?;
    let mut iov = Smb2Iovec::new(req.bytes.clone());
    let mut offset = 0usize;
    req_coder(dce, &mut pdu, &mut iov, &mut offset, req)?;
    req.bytes = pdu.payload.bytes;

    let request = dce
        .lib_ctx
        .call_async_with_payload(opnum, &req.bytes)
        .map_err(map_dcerpc_error)?;
    let response = write_then_read(dce, &request.encoded, transport)?;
    let mut payload = response_payload(&response)?;
    let mut rep_pdu = dcerpc_allocate_pdu(dce, DCERPC_DECODE, len_to_i32(decode_size)?)?;
    rep_pdu.payload = DceRpcPayload::from_bytes(payload.bytes.clone());
    let mut rep_iov = Smb2Iovec::new(payload.bytes.clone());
    let mut rep_offset = 0usize;
    rep_coder(
        dce,
        &mut rep_pdu,
        &mut rep_iov,
        &mut rep_offset,
        &mut payload,
    )?;
    callback(
        dce,
        Ok(DceRpcCommandData {
            payload: DceRpcPayload::from_bytes(response),
        }),
    );
    Ok(())
}

fn prepare_context(dce: &mut DceRpcContext, path: &str, syntax: PSyntaxId) {
    dce.path = Some(path.to_owned());
    dce.syntax = Some(syntax);
    dce.lib_ctx.connect_context(path, to_lib_syntax(syntax));
    dce.state = DceRpcTransportState::Prepared;
}

fn apply_bind_response(dce: &mut DceRpcContext, bytes: &[u8]) -> Result<()> {
    let pdu = lib_dcerpc::DceRpcPdu::from_bytes(bytes).map_err(map_dcerpc_error)?;
    let lib_dcerpc::DceRpcPduBody::BindAck(ack) = pdu.body else {
        return Err(ErrorCode(ERROR_INVALID_ARGUMENT));
    };
    let accepted = ack
        .results
        .iter()
        .position(|result| result.ack_result == lib_dcerpc::ACK_RESULT_ACCEPTANCE)
        .ok_or(ErrorCode(ERROR_INVALID_ARGUMENT))?;
    dce.lib_ctx
        .set_tctx(u8::try_from(accepted).map_err(|_| ErrorCode(ERROR_INVALID_ARGUMENT))?);
    dce.state = DceRpcTransportState::Bound;
    Ok(())
}

fn response_payload(bytes: &[u8]) -> Result<DceRpcPayload> {
    if bytes.is_empty() {
        return Err(ErrorCode(ERROR_INVALID_ARGUMENT));
    }
    let pdu = lib_dcerpc::DceRpcPdu::from_bytes(bytes).map_err(map_dcerpc_error)?;
    match pdu.body {
        lib_dcerpc::DceRpcPduBody::Response(_) => Ok(DceRpcPayload::from_bytes(pdu.payload)),
        _ => Err(ErrorCode(ERROR_INVALID_ARGUMENT)),
    }
}

fn write_then_read<T: Smb2TransportAdapter + ?Sized>(
    dce: &mut DceRpcContext,
    bytes: &[u8],
    transport: &mut T,
) -> Result<Vec<u8>> {
    let file_id = dce.lib_ctx.file_id;
    let smb2 = dce.smb2.as_mut().ok_or(ErrorCode(ERROR_INVALID_ARGUMENT))?;
    smb2.named_pipe_write_with_transport(file_id, bytes, transport)?;
    let mut response = vec![0; lib_dcerpc::NSE_BUF_SIZE];
    let read = smb2.named_pipe_read_with_transport(file_id, &mut response, transport)?;
    if read == 0 {
        dce.error = Some("DCERPC named-pipe transport returned no response".to_owned());
        return Err(ErrorCode(ERROR_INVALID_ARGUMENT));
    }
    response.truncate(read);
    Ok(response)
}

fn len_to_i32(len: usize) -> Result<i32> {
    i32::try_from(len).map_err(|_| ErrorCode(ERROR_INVALID_ARGUMENT))
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
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    ptr: &mut DceRpcPayload,
    ptr_type: PtrType,
    coder: DceRpcCoder,
) -> Result<()> {
    let mut codec = codec_from_pdu(pdu, iov, *offset)?;
    match ptr_type {
        PtrType::Ref => codec.code_ref_pointer().map_err(map_dcerpc_error)?,
        PtrType::Unique | PtrType::Full => {
            let present = codec
                .code_unique_pointer_present(true)
                .map_err(map_dcerpc_error)?;
            if !present {
                return Err(ErrorCode(ERROR_INVALID_ARGUMENT));
            }
        }
    }
    sync_codec(codec, pdu, iov, offset);
    coder(dce, pdu, iov, offset, ptr)
}

/// Encodes or decodes an NDR conformant array.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until NDR array coding is implemented.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the public C DCERPC conformant-array coder signature"
)]
pub fn dcerpc_carray_coder(
    _ctx: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    num: usize,
    ptr: &mut DceRpcPayload,
    elem_size: usize,
    _coder: DceRpcCoder,
) -> Result<()> {
    let len = num
        .checked_mul(elem_size)
        .ok_or(ErrorCode(ERROR_INVALID_ARGUMENT))?;
    let mut codec = codec_from_pdu(pdu, iov, *offset)?;
    let mut count = u64::try_from(num).map_err(|_| ErrorCode(ERROR_INVALID_ARGUMENT))?;
    codec.code_count(&mut count).map_err(map_dcerpc_error)?;
    codec
        .code_bytes(&mut ptr.bytes, len)
        .map_err(map_dcerpc_error)?;
    sync_codec(codec, pdu, iov, offset);
    Ok(())
}

/// Encodes or decodes an unsigned 8-bit integer.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until scalar NDR coding is implemented.
pub fn dcerpc_uint8_coder(
    _ctx: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    ptr: &mut u8,
) -> Result<()> {
    code_with_codec(pdu, iov, offset, |codec| codec.code_u8(ptr))
}

/// Encodes or decodes an unsigned 16-bit integer.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until scalar NDR coding is implemented.
pub fn dcerpc_uint16_coder(
    _ctx: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    ptr: &mut u16,
) -> Result<()> {
    code_with_codec(pdu, iov, offset, |codec| codec.code_u16(ptr))
}

/// Encodes or decodes an unsigned 32-bit integer.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until scalar NDR coding is implemented.
pub fn dcerpc_uint32_coder(
    _ctx: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    ptr: &mut u32,
) -> Result<()> {
    code_with_codec(pdu, iov, offset, |codec| codec.code_u32(ptr))
}

/// Encodes or decodes a width-dependent unsigned integer.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until scalar NDR coding is implemented.
pub fn dcerpc_uint3264_coder(
    _ctx: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    ptr: &mut u64,
) -> Result<()> {
    code_with_codec(pdu, iov, offset, |codec| codec.code_u3264(ptr))
}

/// Encodes or decodes a conformant-array count.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until NDR conformance coding is implemented.
pub fn dcerpc_conformance_coder(
    _ctx: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    ptr: &mut u32,
) -> Result<()> {
    let mut value = u64::from(*ptr);
    code_with_codec(pdu, iov, offset, |codec| codec.code_count(&mut value))?;
    *ptr = u32::try_from(value).map_err(|_| ErrorCode(ERROR_INVALID_ARGUMENT))?;
    Ok(())
}

/// Encodes or decodes a UTF-16 string value.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until NDR UTF-16 coding is implemented.
pub fn dcerpc_utf16_coder(
    _ctx: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    ptr: &mut DceRpcUtf16,
) -> Result<()> {
    let mut value = to_lib_utf16(ptr);
    code_with_codec(pdu, iov, offset, |codec| {
        codec.code_utf16(&mut value, false)
    })?;
    *ptr = from_lib_utf16(value);
    Ok(())
}

/// Encodes or decodes a NUL-terminated UTF-16 string value.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until NDR UTF-16 coding is implemented.
pub fn dcerpc_utf16z_coder(
    _ctx: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    ptr: &mut DceRpcUtf16,
) -> Result<()> {
    let mut value = to_lib_utf16(ptr);
    code_with_codec(pdu, iov, offset, |codec| codec.code_utf16(&mut value, true))?;
    *ptr = from_lib_utf16(value);
    Ok(())
}

/// Encodes or decodes an NDR context handle.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until context-handle coding is implemented.
pub fn dcerpc_context_handle_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    ptr: &mut NdrContextHandle,
) -> Result<()> {
    let mut value = lib_dcerpc::NdrContextHandle {
        context_handle_attributes: ptr.context_handle_attributes,
        context_handle_uuid: to_lib_uuid(ptr.context_handle_uuid),
    };
    code_with_codec(pdu, iov, offset, |codec| {
        codec.code_context_handle(&mut value)
    })?;
    ptr.context_handle_attributes = value.context_handle_attributes;
    ptr.context_handle_uuid = from_lib_uuid(value.context_handle_uuid);
    Ok(())
}

/// Encodes or decodes a DCERPC UUID.
///
/// # Errors
///
/// Always returns `ErrorCode(-38)` until UUID coding is implemented.
pub fn dcerpc_uuid_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    uuid: &mut DceRpcUuid,
) -> Result<()> {
    let mut value = to_lib_uuid(*uuid);
    code_with_codec(pdu, iov, offset, |codec| codec.code_uuid(&mut value))?;
    *uuid = from_lib_uuid(value);
    Ok(())
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

fn code_with_codec(
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
    code: impl FnOnce(&mut lib_dcerpc::NdrCodec) -> lib_dcerpc::DceRpcResult<()>,
) -> Result<()> {
    let mut codec = codec_from_pdu(pdu, iov, *offset)?;
    code(&mut codec).map_err(map_dcerpc_error)?;
    sync_codec(codec, pdu, iov, offset);
    Ok(())
}

fn codec_from_pdu(pdu: &DceRpcPdu, iov: &Smb2Iovec, offset: usize) -> Result<lib_dcerpc::NdrCodec> {
    let direction = if pdu.direction == DCERPC_ENCODE {
        lib_dcerpc::Direction::Encode
    } else {
        lib_dcerpc::Direction::Decode
    };
    let bytes = if pdu.payload.bytes.is_empty() && !iov.buf.is_empty() {
        iov.buf.clone()
    } else {
        pdu.payload.bytes.clone()
    };
    let mut codec =
        lib_dcerpc::NdrCodec::new(direction, lib_dcerpc::TransferSyntax::Ndr32, true, bytes);
    codec.set_offset(offset).map_err(map_dcerpc_error)?;
    Ok(codec)
}

fn sync_codec(
    codec: lib_dcerpc::NdrCodec,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut usize,
) {
    *offset = codec.offset();
    pdu.payload.bytes = codec.into_bytes();
    iov.buf = pdu.payload.bytes.clone();
}

fn to_lib_utf16(value: &DceRpcUtf16) -> lib_dcerpc::DceRpcUtf16 {
    lib_dcerpc::DceRpcUtf16 {
        utf8: value.utf8.clone(),
        utf16: value.utf16.clone(),
        max_count: value.max_count,
        offset: value.offset,
        actual_count: value.actual_count,
    }
}

fn from_lib_utf16(value: lib_dcerpc::DceRpcUtf16) -> DceRpcUtf16 {
    DceRpcUtf16 {
        max_count: value.max_count,
        offset: value.offset,
        actual_count: value.actual_count,
        utf16: value.utf16,
        utf8: value.utf8,
    }
}

fn to_lib_syntax(value: PSyntaxId) -> lib_dcerpc::PSyntaxId {
    lib_dcerpc::PSyntaxId {
        uuid: to_lib_uuid(value.uuid),
        vers: value.vers,
        vers_minor: value.vers_minor,
    }
}

fn to_lib_uuid(value: DceRpcUuid) -> lib_dcerpc::DceRpcUuid {
    lib_dcerpc::DceRpcUuid {
        v1: value.v1,
        v2: value.v2,
        v3: value.v3,
        v4: value.v4,
    }
}

fn from_lib_uuid(value: lib_dcerpc::DceRpcUuid) -> DceRpcUuid {
    DceRpcUuid {
        v1: value.v1,
        v2: value.v2,
        v3: value.v3,
        v4: value.v4,
    }
}

fn map_dcerpc_error(error: lib_dcerpc::DceRpcError) -> ErrorCode {
    match error {
        lib_dcerpc::DceRpcError::ProtocolNotImplemented(_) => not_implemented(),
        lib_dcerpc::DceRpcError::BufferTooSmall { .. }
        | lib_dcerpc::DceRpcError::TooManyDeferredPointers { .. }
        | lib_dcerpc::DceRpcError::AllocHintOutOfRange { .. }
        | lib_dcerpc::DceRpcError::CountOutOfRange { .. }
        | lib_dcerpc::DceRpcError::InvalidAuthVerifier { .. }
        | lib_dcerpc::DceRpcError::InvalidPduType { .. }
        | lib_dcerpc::DceRpcError::InvalidUtf16
        | lib_dcerpc::DceRpcError::NullPointer
        | lib_dcerpc::DceRpcError::UnsupportedPduBody { .. } => ErrorCode(ERROR_INVALID_ARGUMENT),
    }
}

fn not_implemented() -> ErrorCode {
    ErrorCode(ERROR_FUNCTION_NOT_IMPLEMENTED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::include::smb2::libsmb2::{Smb2Client, Smb2TransportAdapter, Socket};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    struct ScriptedTransport {
        fd: Socket,
        reads: std::collections::VecDeque<Vec<u8>>,
        written: Vec<u8>,
    }

    impl ScriptedTransport {
        fn new(fd: Socket, reads: Vec<Vec<u8>>) -> Self {
            Self {
                fd,
                reads: reads.into(),
                written: Vec::new(),
            }
        }

        fn written(&self) -> &[u8] {
            &self.written
        }
    }

    impl Smb2TransportAdapter for ScriptedTransport {
        fn read(&mut self, fd: Socket, buf: &mut [u8]) -> Result<usize> {
            if fd != self.fd {
                return Err(ErrorCode(ERROR_INVALID_ARGUMENT));
            }
            let Some(bytes) = self.reads.pop_front() else {
                return Ok(0);
            };
            let len = bytes.len().min(buf.len());
            buf[..len].copy_from_slice(&bytes[..len]);
            Ok(len)
        }

        fn write(&mut self, fd: Socket, buf: &[u8]) -> Result<usize> {
            if fd != self.fd {
                return Err(ErrorCode(ERROR_INVALID_ARGUMENT));
            }
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn ready_events(&self, fd: Socket, requested: i32) -> Result<i32> {
            if fd != self.fd {
                return Err(ErrorCode(ERROR_INVALID_ARGUMENT));
            }
            Ok(requested)
        }
    }

    fn frame(message_id: u64, status: i32, payload: &[u8]) -> Vec<u8> {
        let len = 12usize.saturating_add(payload.len());
        let mut bytes = Vec::with_capacity(4 + len);
        bytes.extend_from_slice(&(len as u32).to_be_bytes());
        bytes.extend_from_slice(&message_id.to_be_bytes());
        bytes.extend_from_slice(&status.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn bind_ack() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&32_768u16.to_le_bytes());
        body.extend_from_slice(&32_768u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&[0, 0]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&[0, 0, 0]);
        body.extend_from_slice(&lib_dcerpc::ACK_RESULT_ACCEPTANCE.to_le_bytes());
        body.extend_from_slice(&lib_dcerpc::ACK_REASON_REASON_NOT_SPECIFIED.to_le_bytes());
        body.extend_from_slice(&lib_dcerpc::NDR32_UUID.v1.to_le_bytes());
        body.extend_from_slice(&lib_dcerpc::NDR32_UUID.v2.to_le_bytes());
        body.extend_from_slice(&lib_dcerpc::NDR32_UUID.v3.to_le_bytes());
        body.extend_from_slice(&lib_dcerpc::NDR32_UUID.v4);
        body.extend_from_slice(&2u32.to_le_bytes());

        let mut header = lib_dcerpc::DceRpcHeader {
            ptype: lib_dcerpc::PduType::BindAck,
            pfc_flags: lib_dcerpc::PfcFlags::first_and_last(),
            frag_length: (lib_dcerpc::DceRpcHeader::ENCODED_LEN + body.len()) as u16,
            call_id: 2,
            ..lib_dcerpc::DceRpcHeader::default()
        }
        .to_bytes()
        .expect("bind ack header encodes");
        header.extend_from_slice(&body);
        header
    }

    fn response_pdu(call_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut pdu =
            lib_dcerpc::DceRpcPdu::new(call_id, lib_dcerpc::Direction::Response, payload.len());
        pdu.body = lib_dcerpc::DceRpcPduBody::Response(lib_dcerpc::DceRpcResponsePdu {
            alloc_hint: payload.len() as u32,
            context_id: 0,
            cancel_count: 0,
            reserved: 0,
        });
        pdu.payload.copy_from_slice(payload);
        pdu.to_bytes().expect("response fixture encodes")
    }

    fn identity_coder(
        _dce: &mut DceRpcContext,
        pdu: &mut DceRpcPdu,
        _iov: &mut Smb2Iovec,
        _offset: &mut usize,
        payload: &mut DceRpcPayload,
    ) -> Result<()> {
        if pdu.direction == DCERPC_ENCODE {
            pdu.payload.bytes = payload.bytes.clone();
        } else {
            payload.bytes = pdu.payload.bytes.clone();
        }
        Ok(())
    }

    fn connected_context(reads: Vec<Vec<u8>>) -> (DceRpcContext, ScriptedTransport) {
        let mut smb2 = Smb2Client::new();
        smb2.set_fd(0);
        smb2.connect_share_local("server", "IPC$")
            .expect("local IPC$ connect succeeds");
        (
            dcerpc_create_context(smb2),
            ScriptedTransport::new(0, reads),
        )
    }

    #[test]
    fn transport_state_machine_opens_binds_calls_and_decodes_response() {
        let reply_payload = b"srvsvc-reply";
        let (mut dce, mut transport) = connected_context(vec![
            frame(1, 0, &[]),
            bind_ack(),
            response_pdu(3, reply_payload),
        ]);

        dcerpc_connect_context_with_transport_async(
            &mut dce,
            "srvsvc",
            SRVSVC_INTERFACE,
            &mut transport,
            Box::new(|ctx, result| {
                assert!(result.is_ok());
                assert_eq!(ctx.file_id()[..8], 1u64.to_be_bytes());
            }),
        )
        .expect("bind response is accepted");

        let mut request = DceRpcPayload::from_bytes(b"srvsvc-request".to_vec());
        let call_payload = Arc::new(Mutex::new(Vec::new()));
        let callback_payload = Arc::clone(&call_payload);
        dcerpc_call_with_transport_async(
            &mut dce,
            15,
            identity_coder,
            &mut request,
            identity_coder,
            reply_payload.len(),
            &mut transport,
            Box::new(move |_ctx, result| {
                let data = result.expect("call succeeds");
                *callback_payload.lock().expect("callback payload lock") = data.payload.bytes;
            }),
        )
        .expect("response PDU is decoded");

        assert_eq!(request.bytes, b"srvsvc-request");
        let call_payload = call_payload.lock().expect("callback payload lock");
        assert_eq!(
            response_payload(&call_payload).unwrap().bytes,
            reply_payload
        );
        assert!(!transport.written().is_empty());
    }

    #[test]
    fn transport_connect_rejects_missing_bind_ack() {
        let (mut dce, mut transport) = connected_context(vec![frame(1, 0, &[])]);

        let result = dcerpc_connect_context_with_transport_async(
            &mut dce,
            "lsarpc",
            LSA_INTERFACE,
            &mut transport,
            Box::new(|_, _| panic!("callback must not run on bind failure")),
        );

        assert_eq!(result, Err(ErrorCode(ERROR_INVALID_ARGUMENT)));
    }

    #[test]
    fn transport_call_requires_bound_context() {
        let (mut dce, mut transport) = connected_context(Vec::new());
        prepare_context(&mut dce, "srvsvc", SRVSVC_INTERFACE);
        let mut request = DceRpcPayload::from_bytes(Vec::new());

        let result = dcerpc_call_with_transport_async(
            &mut dce,
            15,
            identity_coder,
            &mut request,
            identity_coder,
            0,
            &mut transport,
            Box::new(|_, _| panic!("callback must not run before bind")),
        );

        assert_eq!(result, Err(ErrorCode(ERROR_INVALID_ARGUMENT)));
    }
}
