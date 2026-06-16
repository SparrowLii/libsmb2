use std::fmt;

pub const DCERPC_DR_BIG_ENDIAN: u8 = 0x00;
pub const DCERPC_DR_LITTLE_ENDIAN: u8 = 0x10;
pub const DCERPC_DR_ASCII: u8 = 0x00;
pub const DCERPC_DR_EBCDIC: u8 = 0x01;
pub const DCERPC_DECODE: i32 = 0;
pub const DCERPC_ENCODE: i32 = 1;

const ERROR_INVALID_ARGUMENT: i32 = -22;
const ERROR_FUNCTION_NOT_IMPLEMENTED: i32 = -38;

/// NDR reference-pointer referent marker (C `RPTR` = "RptrrtpR").
const RPTR: u64 = 0x5270_7472_7274_7052;
/// NDR unique-pointer referent marker (C `UPTR` = "UptrrtpU").
const UPTR: u64 = 0x5570_7472_7274_7055;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceRpcContext {
    smb2_attached: bool,
    error: Option<String>,
    path: Option<String>,
    syntax: Option<PSyntaxId>,
    callback_count: usize,
    call_id: u32,
    tctx_id: i32,
}

impl Default for DceRpcContext {
    fn default() -> Self {
        Self {
            smb2_attached: false,
            error: None,
            path: None,
            syntax: None,
            callback_count: 0,
            call_id: 1,
            tctx_id: 0,
        }
    }
}

impl DceRpcContext {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    #[must_use]
    pub fn syntax(&self) -> Option<PSyntaxId> {
        self.syntax
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DceRpcPdu {
    pub direction: i32,
    pub payload: Vec<u8>,
    pub size_is: i32,
    pub packed_drep: [u8; 4],
    pub is_conformance_run: bool,
    pub suppress_conformance_io: bool,
    /// NDR top-level flag. Mirrors C `pdu->top_level`: when set, a pointer coder
    /// codes its referent object inline and flushes deferred pointers at the end;
    /// when clear (nested), the object is queued for deferred coding.
    pub top_level: bool,
    /// Running maximum field alignment observed during a conformance run.
    pub max_alignment: i32,
    /// Monotonic referent id for `PTR_FULL` pointers (mirrors C `pdu->ptr_id`).
    pub ptr_id: u64,
    /// FIFO of deferred pointer objects awaiting coding at the top-level flush.
    /// Each entry is `(coder, raw object pointer)`, mirroring C's `pdu->ptrs[]`.
    /// The raw pointers reference caller-owned `DceRpcPayload` values that outlive
    /// the single top-level coder invocation that enqueues and flushes them.
    pub deferred: Vec<DeferredPointer>,
}

/// A queued NDR pointer whose referent is coded during the top-level deferred
/// flush. Mirrors C `struct dcerpc_deferred_pointer { coder; ptr }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredPointer {
    pub coder: DceRpcCoder,
    pub ptr: *mut DceRpcPayload,
}


#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Smb2Iovec {
    pub data: Vec<u8>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DceRpcPayload {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceRpcError {
    code: i32,
}

impl DceRpcError {
    #[must_use]
    pub const fn code(&self) -> i32 {
        self.code
    }

    /// Constructs an error with the given status code.
    #[must_use]
    pub const fn with_code(code: i32) -> Self {
        Self { code }
    }
}

impl fmt::Display for DceRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DCERPC error {}", self.code)
    }
}

impl std::error::Error for DceRpcError {}

pub type Result<T> = std::result::Result<T, DceRpcError>;

pub type DceRpcCoder = fn(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    ptr: &mut DceRpcPayload,
) -> i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PtrType {
    Ref = 0,
    Unique = 1,
    Full = 2,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DceRpcUuid {
    pub v1: u32,
    pub v2: u16,
    pub v3: u16,
    pub v4: [u8; 8],
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PSyntaxId {
    pub uuid: DceRpcUuid,
    pub vers: u16,
    pub vers_minor: u16,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct NdrTransferSyntax {
    pub uuid: DceRpcUuid,
    pub vers: u16,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct NdrContextHandle {
    pub context_handle_attributes: u32,
    pub context_handle_uuid: DceRpcUuid,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DceRpcUtf16 {
    pub max_count: u32,
    pub offset: u32,
    pub actual_count: u32,
    pub utf16: Vec<u16>,
    pub utf8: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DceRpcCarray {
    pub max_count: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DceRpcHeader {
    pub version: u8,
    pub packet_type: u8,
    pub packet_flags: u8,
    pub packed_drep: [u8; 4],
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

pub const NDR_TRANSFER_SYNTAX: NdrTransferSyntax = NdrTransferSyntax {
    uuid: DceRpcUuid {
        v1: 0x8a88_5d04,
        v2: 0x1ceb,
        v3: 0x11c9,
        v4: [0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60],
    },
    vers: 2,
};

pub const NDR64_SYNTAX: PSyntaxId = PSyntaxId {
    uuid: DceRpcUuid {
        v1: 0x7171_0533,
        v2: 0xbeba,
        v3: 0x4937,
        v4: [0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36],
    },
    vers: 1,
    vers_minor: 0,
};

pub const LSA_INTERFACE: PSyntaxId = PSyntaxId {
    uuid: DceRpcUuid {
        v1: 0x1234_5778,
        v2: 0x1234,
        v3: 0xabcd,
        v4: [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab],
    },
    vers: 0,
    vers_minor: 0,
};

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

pub type DceRpcCallback = Box<dyn FnOnce(&mut DceRpcContext, i32, DceRpcPayload) + Send>;

#[must_use]
pub fn dcerpc_create_context() -> DceRpcContext {
    DceRpcContext {
        smb2_attached: true,
        ..DceRpcContext::default()
    }
}

pub fn dcerpc_destroy_context(_dce: DceRpcContext) {}

pub fn dcerpc_free_data(_dce: &mut DceRpcContext, _data: DceRpcPayload) {}

#[must_use]
pub fn dcerpc_get_error(dce: &DceRpcContext) -> Option<&str> {
    dce.error.as_deref()
}

#[must_use]
pub fn dcerpc_get_smb2_context(dce: &DceRpcContext) -> bool {
    dce.smb2_attached
}

#[must_use]
pub fn dcerpc_get_pdu_payload(pdu: &DceRpcPdu) -> &[u8] {
    &pdu.payload
}

pub fn dcerpc_connect_context_async(
    dce: &mut DceRpcContext,
    path: &str,
    syntax: PSyntaxId,
    _callback: DceRpcCallback,
) -> Result<()> {
    dce.path = Some(path.to_owned());
    dce.syntax = Some(syntax);
    dce.error = Some("DCERPC connect requires real SMB2 named-pipe transport".to_owned());
    Err(DceRpcError {
        code: ERROR_FUNCTION_NOT_IMPLEMENTED,
    })
}

pub fn dcerpc_open_async(dce: &mut DceRpcContext, _callback: DceRpcCallback) -> Result<()> {
    dce.error = Some("DCERPC open requires real SMB2 named-pipe transport".to_owned());
    Err(DceRpcError {
        code: ERROR_FUNCTION_NOT_IMPLEMENTED,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn dcerpc_call_async(
    dce: &mut DceRpcContext,
    _opnum: i32,
    _req_coder: DceRpcCoder,
    _req: &mut DceRpcPayload,
    _rep_coder: DceRpcCoder,
    _decode_size: usize,
    _callback: DceRpcCallback,
) -> Result<()> {
    dce.error = Some("DCERPC call requires real SMB2 named-pipe transport".to_owned());
    Err(DceRpcError {
        code: ERROR_FUNCTION_NOT_IMPLEMENTED,
    })
}

pub fn dcerpc_invoke_callback(
    dce: &mut DceRpcContext,
    status: i32,
    payload: DceRpcPayload,
    callback: DceRpcCallback,
) {
    dce.callback_count = dce.callback_count.saturating_add(1);
    callback(dce, status, payload);
}

#[must_use]
pub fn dcerpc_callback_count(dce: &DceRpcContext) -> usize {
    dce.callback_count
}

pub fn dcerpc_allocate_pdu(
    dce: &mut DceRpcContext,
    direction: i32,
    payload_size: i32,
) -> Result<DceRpcPdu> {
    let payload_len = usize::try_from(payload_size).map_err(|_| DceRpcError {
        code: ERROR_INVALID_ARGUMENT,
    })?;
    dce.call_id = dce.call_id.saturating_add(1);
    Ok(DceRpcPdu {
        direction,
        payload: vec![0; payload_len],
        size_is: 0,
        packed_drep: [DCERPC_DR_LITTLE_ENDIAN, 0, 0, 0],
        is_conformance_run: false,
        suppress_conformance_io: false,
        top_level: true,
        max_alignment: 1,
        ptr_id: 0,
        deferred: Vec::new(),
    })
}

pub fn dcerpc_free_pdu(_dce: &mut DceRpcContext, _pdu: DceRpcPdu) {}

pub fn dcerpc_set_size_is(pdu: &mut DceRpcPdu, size_is: i32) {
    pdu.size_is = size_is;
}

#[must_use]
pub fn dcerpc_get_size_is(pdu: &DceRpcPdu) -> i32 {
    pdu.size_is
}

pub fn dcerpc_header_coder(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    header: &mut DceRpcHeader,
) -> Result<()> {
    dcerpc_uint8_coder(dce, pdu, iov, offset, &mut header.version)?;
    dcerpc_uint8_coder(dce, pdu, iov, offset, &mut header.packet_type)?;
    dcerpc_uint8_coder(dce, pdu, iov, offset, &mut header.packet_flags)?;
    for byte in &mut header.packed_drep {
        dcerpc_uint8_coder(dce, pdu, iov, offset, byte)?;
    }
    dcerpc_uint16_coder(dce, pdu, iov, offset, &mut header.frag_length)?;
    dcerpc_uint16_coder(dce, pdu, iov, offset, &mut header.auth_length)?;
    dcerpc_uint32_coder(dce, pdu, iov, offset, &mut header.call_id)
}

#[must_use]
pub fn dcerpc_pdu_direction(pdu: &DceRpcPdu) -> i32 {
    pdu.direction
}

#[must_use]
pub fn dcerpc_align_3264(ctx: &DceRpcContext, offset: i32) -> i32 {
    if offset < 0 {
        return offset;
    }
    if ctx.tctx_id != 0 {
        (offset + 7) & !7
    } else {
        (offset + 3) & !3
    }
}

pub fn dcerpc_set_tctx(ctx: &mut DceRpcContext, tctx_id: i32) {
    ctx.tctx_id = tctx_id;
}

#[must_use]
pub fn dcerpc_tctx(ctx: &DceRpcContext) -> i32 {
    ctx.tctx_id
}

pub fn dcerpc_set_endian(pdu: &mut DceRpcPdu, little_endian: i32) {
    if little_endian != 0 {
        pdu.packed_drep[0] |= DCERPC_DR_LITTLE_ENDIAN;
    } else {
        pdu.packed_drep[0] &= !DCERPC_DR_LITTLE_ENDIAN;
    }
}

#[must_use]
pub fn dcerpc_get_cr(pdu: &DceRpcPdu) -> bool {
    pdu.is_conformance_run
}

/// Codes a referenced object using the C two-pass NDR model: a conformance run
/// (computes alignment + emits conformance fields) followed by an alignment of
/// the offset and the data run. Mirrors C `dcerpc_do_coder` (lib/dcerpc.c).
pub fn dcerpc_do_coder(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    ptr: &mut DceRpcPayload,
    coder: DceRpcCoder,
) -> Result<()> {
    pdu.max_alignment = 1;
    pdu.is_conformance_run = true;
    if coder(dce, pdu, iov, offset, ptr) != 0 {
        return Err(DceRpcError { code: -1 });
    }
    let align = pdu.max_alignment.max(1);
    *offset = (*offset + (align - 1)) & !(align - 1);
    pdu.is_conformance_run = false;
    if coder(dce, pdu, iov, offset, ptr) != 0 {
        return Err(DceRpcError { code: -1 });
    }
    Ok(())
}

/// Closure-driven variant of [`dcerpc_do_coder`]. Runs the supplied object coder
/// through the same two-pass conformance/data model, but accepts an `FnMut` so
/// callers (e.g. the C-ABI bridge) can code typed referents that do not fit the
/// byte-only [`DceRpcCoder`] function-pointer signature. The closure observes
/// `pdu.is_conformance_run` to gate writes exactly as the primitive coders do.
pub fn dcerpc_do_coder_with<F>(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    mut coder: F,
) -> Result<()>
where
    F: FnMut(&mut DceRpcContext, &mut DceRpcPdu, &mut Smb2Iovec, &mut i32) -> Result<()>,
{
    pdu.max_alignment = 1;
    pdu.is_conformance_run = true;
    coder(dce, pdu, iov, offset)?;
    let align = pdu.max_alignment.max(1);
    *offset = (*offset + (align - 1)) & !(align - 1);
    pdu.is_conformance_run = false;
    coder(dce, pdu, iov, offset)
}

/// Closure-driven NDR pointer coder mirroring [`dcerpc_ptr_coder`]. Handles the
/// referent id (skipping it for top-level `PTR_REF`), the top-level inline vs
/// nested-deferred decision, and the top-level deferred-pointer flush — but runs
/// the referent object through a caller-supplied `FnMut` so typed referents can
/// be coded. Nested deferral falls back to coding the referent inline at the
/// point of reference (sufficient for the single-level nesting used by the LSA /
/// srvsvc contract coders); deeper deferral still flushes any fn-pointer
/// referents queued by inner [`dcerpc_ptr_coder`] calls.
pub fn dcerpc_ptr_coder_with<F>(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    ptr_present: bool,
    ptr_type: PtrType,
    mut coder: F,
) -> Result<()>
where
    F: FnMut(&mut DceRpcContext, &mut DceRpcPdu, &mut Smb2Iovec, &mut i32) -> Result<()>,
{
    let top_level = pdu.top_level;

    if pdu.is_conformance_run {
        if !(ptr_type == PtrType::Ref && pdu.top_level) {
            let align = if dce.tctx_id != 0 { 8 } else { 4 };
            pdu.max_alignment = pdu.max_alignment.max(align);
        }
        return Ok(());
    }

    let mut code_inline =
        |dce: &mut DceRpcContext, pdu: &mut DceRpcPdu, iov: &mut Smb2Iovec, offset: &mut i32| {
            pdu.top_level = false;
            let r = dcerpc_do_coder_with(dce, pdu, iov, offset, &mut coder);
            pdu.top_level = top_level;
            r
        };

    match ptr_type {
        PtrType::Ref => {
            if pdu.top_level {
                code_inline(dce, pdu, iov, offset)?;
            } else {
                let mut referent = if pdu.direction == DCERPC_DECODE { 0 } else { RPTR };
                dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut referent)?;
                code_inline(dce, pdu, iov, offset)?;
            }
        }
        PtrType::Unique => {
            if pdu.direction == DCERPC_DECODE {
                let mut p = 0u64;
                dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut p)?;
                if p == 0 || !ptr_present {
                    return Ok(());
                }
            } else {
                if !ptr_present {
                    let mut zero = 0u64;
                    dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut zero)?;
                    return Ok(());
                }
                let mut referent = UPTR;
                dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut referent)?;
            }
            code_inline(dce, pdu, iov, offset)?;
        }
        PtrType::Full => {
            if pdu.direction == DCERPC_DECODE {
                let mut p = 0u64;
                dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut p)?;
                if p == 0 || !ptr_present {
                    return Ok(());
                }
            } else {
                if !ptr_present {
                    let mut zero = 0u64;
                    dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut zero)?;
                    return Ok(());
                }
                pdu.ptr_id = pdu.ptr_id.saturating_add(1);
                let mut val = pdu.ptr_id;
                dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut val)?;
            }
            code_inline(dce, pdu, iov, offset)?;
        }
    }

    if pdu.top_level {
        pdu.top_level = false;
        let r = dcerpc_process_deferred_pointers(dce, pdu, iov, offset);
        pdu.top_level = top_level;
        r?;
    }
    Ok(())
}

/// Flushes all queued deferred pointers, coding each referent via the two-pass
/// `dcerpc_do_coder`. Mirrors C `dcerpc_process_deferred_pointers`. New entries
/// enqueued while flushing are processed in FIFO order until the queue drains.
fn dcerpc_process_deferred_pointers(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
) -> Result<()> {
    let mut idx = 0;
    while idx < pdu.deferred.len() {
        let entry = pdu.deferred[idx];
        idx += 1;
        // SAFETY: deferred entries reference caller-owned DceRpcPayload values
        // that outlive the single top-level coder invocation driving this flush.
        let referent = unsafe { &mut *entry.ptr };
        dcerpc_do_coder(dce, pdu, iov, offset, referent, entry.coder)?;
    }
    pdu.deferred.clear();
    Ok(())
}

/// Boxed deferred-referent body. Coded during the top-level deferred flush; may
/// itself enqueue further deferred bodies (matching C's growing `pdu->ptrs`).
type DeferredBody = Box<
    dyn FnMut(&mut DceRpcContext, &mut DceRpcPdu, &mut Smb2Iovec, &mut i32, &mut NdrEngine) -> Result<()>,
>;

/// Closure-capable NDR deferred-pointer engine. Mirrors the C `pdu->ptrs[]`
/// deferred queue, but holds boxed closures so the C-ABI bridge can defer the
/// coding of typed referents (UTF-16 strings, nested structs) that do not fit
/// the byte-only [`DceRpcCoder`] function-pointer signature. Drive a top-level
/// coder via [`NdrEngine::run_top_level`]; inside it, reference pointers with
/// [`NdrEngine::ptr`]. The orchestration (referent ids, top-level inline vs
/// deferred, two-pass conformance, FIFO flush) all lives here in `libsmb2_rs`.
/// Deferred bodies capture only `Copy` raw pointers / owned values, so they are
/// `'static` and the queue carries no borrow of caller data.
#[derive(Default)]
pub struct NdrEngine {
    queue: std::collections::VecDeque<DeferredBody>,
    top_level: bool,
}

impl NdrEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: std::collections::VecDeque::new(),
            top_level: true,
        }
    }

    /// Codes an NDR pointer field. At top level the referent body is coded
    /// inline (PTR_REF emits no referent id); nested pointers emit the referent
    /// id and defer the body to the FIFO queue. `body` codes the referent object
    /// using the supplied engine refs (and may reference further pointers).
    pub fn ptr<F>(
        &mut self,
        dce: &mut DceRpcContext,
        pdu: &mut DceRpcPdu,
        iov: &mut Smb2Iovec,
        offset: &mut i32,
        present: bool,
        ptr_type: PtrType,
        body: F,
    ) -> Result<()>
    where
        F: FnMut(
                &mut DceRpcContext,
                &mut DceRpcPdu,
                &mut Smb2Iovec,
                &mut i32,
                &mut NdrEngine,
            ) -> Result<()>
            + 'static,
    {
        let decode = pdu.direction == DCERPC_DECODE;

        // During a conformance run, a pointer only contributes its alignment and
        // never writes a referent or defers (mirrors C dcerpc_(en|de)code_ptr).
        if pdu.is_conformance_run {
            if !(ptr_type == PtrType::Ref && self.top_level) {
                let align = if dce.tctx_id != 0 { 8 } else { 4 };
                pdu.max_alignment = pdu.max_alignment.max(align);
            }
            return Ok(());
        }

        match ptr_type {
            PtrType::Ref => {
                if !self.top_level {
                    let mut referent = if decode { 0 } else { RPTR };
                    dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut referent)?;
                }
            }
            PtrType::Unique => {
                if decode {
                    let mut p = 0u64;
                    dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut p)?;
                    if p == 0 || !present {
                        return Ok(());
                    }
                } else if present {
                    let mut referent = UPTR;
                    dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut referent)?;
                } else {
                    let mut zero = 0u64;
                    dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut zero)?;
                    return Ok(());
                }
            }
            PtrType::Full => {
                if decode {
                    let mut p = 0u64;
                    dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut p)?;
                    if p == 0 || !present {
                        return Ok(());
                    }
                } else if present {
                    pdu.ptr_id = pdu.ptr_id.saturating_add(1);
                    let mut val = pdu.ptr_id;
                    dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut val)?;
                } else {
                    let mut zero = 0u64;
                    dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut zero)?;
                    return Ok(());
                }
            }
        }

        if self.top_level {
            let saved = self.top_level;
            self.top_level = false;
            let mut body = body;
            let r = self.do_coder(dce, pdu, iov, offset, &mut body);
            self.top_level = saved;
            r?;
        } else {
            self.queue.push_back(Box::new(body));
        }

        // Mirror C `dcerpc_(en|de)code_ptr` `out:`: when this pointer is the
        // top-level one, flush the deferred queue here (FIFO; bodies may enqueue
        // more) before returning, so deferred referents are coded within this
        // pointer's scope rather than at the end of the whole message.
        if self.top_level {
            self.top_level = false;
            let r = self.flush_deferred(dce, pdu, iov, offset);
            self.top_level = true;
            r?;
        }
        Ok(())
    }

    /// Drains the deferred-pointer FIFO, coding each body via the two-pass model.
    /// Bodies may enqueue further deferred pointers (matching C's growing queue).
    fn flush_deferred(
        &mut self,
        dce: &mut DceRpcContext,
        pdu: &mut DceRpcPdu,
        iov: &mut Smb2Iovec,
        offset: &mut i32,
    ) -> Result<()> {
        while let Some(mut deferred) = self.queue.pop_front() {
            self.do_coder(dce, pdu, iov, offset, &mut deferred)?;
        }
        Ok(())
    }

    /// Runs `body` through the C two-pass conformance/data model.
    fn do_coder<F>(
        &mut self,
        dce: &mut DceRpcContext,
        pdu: &mut DceRpcPdu,
        iov: &mut Smb2Iovec,
        offset: &mut i32,
        body: &mut F,
    ) -> Result<()>
    where
        F: FnMut(
                &mut DceRpcContext,
                &mut DceRpcPdu,
                &mut Smb2Iovec,
                &mut i32,
                &mut NdrEngine,
            ) -> Result<()>
            + ?Sized,
    {
        pdu.max_alignment = 1;
        pdu.is_conformance_run = true;
        body(dce, pdu, iov, offset, self)?;
        let align = pdu.max_alignment.max(1);
        *offset = (*offset + (align - 1)) & !(align - 1);
        pdu.is_conformance_run = false;
        body(dce, pdu, iov, offset, self)
    }

    /// Drives a top-level coder body, then flushes deferred referent bodies FIFO
    /// (bodies may enqueue more). Mirrors C top-level inline + deferred flush.
    pub fn run_top_level<F>(
        &mut self,
        dce: &mut DceRpcContext,
        pdu: &mut DceRpcPdu,
        iov: &mut Smb2Iovec,
        offset: &mut i32,
        mut body: F,
    ) -> Result<()>
    where
        F: FnMut(
            &mut DceRpcContext,
            &mut DceRpcPdu,
            &mut Smb2Iovec,
            &mut i32,
            &mut NdrEngine,
        ) -> Result<()>,
    {
        self.top_level = true;
        body(dce, pdu, iov, offset, self)?;
        // Each top-level pointer flushes its own deferred queue (mirroring C's
        // per-pointer `out:`). Any remaining entries (e.g. a top-level body that
        // deferred without going through a top-level pointer) are drained here.
        self.top_level = false;
        self.flush_deferred(dce, pdu, iov, offset)
    }
}

pub fn dcerpc_uint8_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    value: &mut u8,
) -> Result<()> {
    if pdu.is_conformance_run {
        pdu.max_alignment = pdu.max_alignment.max(1);
        return Ok(());
    }
    code_bytes(pdu, iov, offset, &mut [*value])?;
    if pdu.direction == DCERPC_DECODE {
        *value = iov.data[usize::try_from(*offset - 1).map_err(|_| DceRpcError {
            code: ERROR_INVALID_ARGUMENT,
        })?];
    }
    Ok(())
}

pub fn dcerpc_set_uint8(iov: &mut Smb2Iovec, offset: &mut i32, value: u8) -> Result<()> {
    let start = usize::try_from(*offset).map_err(|_| DceRpcError {
        code: ERROR_INVALID_ARGUMENT,
    })?;
    let end = start.checked_add(1).ok_or(DceRpcError {
        code: ERROR_INVALID_ARGUMENT,
    })?;
    if end > iov.data.len() {
        return Err(DceRpcError { code: -1 });
    }
    iov.data[start] = value;
    *offset = i32::try_from(end).map_err(|_| DceRpcError {
        code: ERROR_INVALID_ARGUMENT,
    })?;
    Ok(())
}

pub fn dcerpc_uint64_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    value: &mut u64,
) -> Result<()> {
    if pdu.is_conformance_run {
        pdu.max_alignment = pdu.max_alignment.max(8);
        return Ok(());
    }
    align_offset(offset, 8)?;
    let mut bytes = value.to_le_bytes();
    code_bytes(pdu, iov, offset, &mut bytes)?;
    if pdu.direction == DCERPC_DECODE {
        *value = u64::from_le_bytes(bytes);
    }
    Ok(())
}

pub fn dcerpc_uint16_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    value: &mut u16,
) -> Result<()> {
    if pdu.is_conformance_run {
        pdu.max_alignment = pdu.max_alignment.max(2);
        return Ok(());
    }
    align_offset(offset, 2)?;
    let mut bytes = value.to_le_bytes();
    code_bytes(pdu, iov, offset, &mut bytes)?;
    if pdu.direction == DCERPC_DECODE {
        *value = u16::from_le_bytes(bytes);
    }
    Ok(())
}

pub fn dcerpc_uint32_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    value: &mut u32,
) -> Result<()> {
    if pdu.is_conformance_run {
        pdu.max_alignment = pdu.max_alignment.max(4);
        return Ok(());
    }
    align_offset(offset, 4)?;
    let mut bytes = value.to_le_bytes();
    code_bytes(pdu, iov, offset, &mut bytes)?;
    if pdu.direction == DCERPC_DECODE {
        *value = u32::from_le_bytes(bytes);
    }
    Ok(())
}

pub fn dcerpc_uint3264_coder(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    value: &mut u64,
) -> Result<()> {
    if pdu.is_conformance_run {
        let align = if dce.tctx_id != 0 { 8 } else { 4 };
        pdu.max_alignment = pdu.max_alignment.max(align);
        return Ok(());
    }
    if dce.tctx_id != 0 {
        return dcerpc_uint64_coder(dce, pdu, iov, offset, value);
    }
    let mut narrowed = *value as u32;
    dcerpc_uint32_coder(dce, pdu, iov, offset, &mut narrowed)?;
    *value = u64::from(narrowed);
    Ok(())
}

pub fn dcerpc_conformance_coder(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    value: &mut u32,
) -> Result<()> {
    if !pdu.is_conformance_run {
        return Ok(());
    }
    // Conformance fields are written during the conformance run itself; bypass
    // the data-run gate by coding the scalar directly.
    if dce.tctx_id != 0 {
        let mut wide = u64::from(*value);
        align_offset(offset, 8)?;
        let mut bytes = wide.to_le_bytes();
        code_bytes(pdu, iov, offset, &mut bytes)?;
        if pdu.direction == DCERPC_DECODE {
            wide = u64::from_le_bytes(bytes);
            *value = wide as u32;
        }
    } else {
        align_offset(offset, 4)?;
        let mut bytes = value.to_le_bytes();
        code_bytes(pdu, iov, offset, &mut bytes)?;
        if pdu.direction == DCERPC_DECODE {
            *value = u32::from_le_bytes(bytes);
        }
    }
    Ok(())
}

/// Conformant array coder. Mirrors C `dcerpc_carray_coder`: codes the
/// conformance count, then runs the element `coder` for each of `num` elements.
/// The element payloads are carved from `ptr.data` in `elem_size` chunks.
#[allow(clippy::too_many_arguments)]
pub fn dcerpc_carray_coder(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    num: usize,
    ptr: &mut DceRpcPayload,
    elem_size: usize,
    coder: DceRpcCoder,
) -> Result<()> {
    let mut count = u32::try_from(num).map_err(|_| DceRpcError {
        code: ERROR_INVALID_ARGUMENT,
    })?;
    dcerpc_conformance_coder(dce, pdu, iov, offset, &mut count)?;
    if count as usize != num {
        return Err(DceRpcError { code: -1 });
    }
    if elem_size == 0 {
        return Ok(());
    }
    let needed = num.checked_mul(elem_size).ok_or(DceRpcError {
        code: ERROR_INVALID_ARGUMENT,
    })?;
    if pdu.direction == DCERPC_DECODE {
        if ptr.data.len() < needed {
            ptr.data.resize(needed, 0);
        }
    } else if ptr.data.len() < needed {
        return Err(DceRpcError { code: -1 });
    }
    for index in 0..num {
        let start = index * elem_size;
        let end = start + elem_size;
        let mut element = DceRpcPayload {
            data: ptr.data[start..end].to_vec(),
        };
        if coder(dce, pdu, iov, offset, &mut element) != 0 {
            return Err(DceRpcError { code: -1 });
        }
        let copy = element.data.len().min(elem_size);
        ptr.data[start..start + copy].copy_from_slice(&element.data[..copy]);
    }
    Ok(())
}

pub fn dcerpc_utf16_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    value: &mut DceRpcUtf16,
) -> Result<()> {
    code_utf16(pdu, iov, offset, value, false)
}

pub fn dcerpc_utf16z_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    value: &mut DceRpcUtf16,
) -> Result<()> {
    code_utf16(pdu, iov, offset, value, true)
}

/// Codes the body of a UTF-16(z) string referent (the conformance-aware
/// `dcerpc_(de|en)code_utf16` inner routine). Exposed for the C-ABI bridge so it
/// can drive string referents through the rs engine's closure pointer coder.
pub fn code_utf16_referent(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    value: &mut DceRpcUtf16,
    nul_terminated: bool,
) -> Result<()> {
    code_utf16(pdu, iov, offset, value, nul_terminated)
}

pub fn dcerpc_uuid_coder(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    uuid: &mut DceRpcUuid,
) -> Result<()> {
    dcerpc_uint32_coder(dce, pdu, iov, offset, &mut uuid.v1)?;
    dcerpc_uint16_coder(dce, pdu, iov, offset, &mut uuid.v2)?;
    dcerpc_uint16_coder(dce, pdu, iov, offset, &mut uuid.v3)?;
    for byte in &mut uuid.v4 {
        dcerpc_uint8_coder(dce, pdu, iov, offset, byte)?;
    }
    Ok(())
}

pub fn dcerpc_context_handle_coder(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    handle: &mut NdrContextHandle,
) -> Result<()> {
    dcerpc_uint32_coder(dce, pdu, iov, offset, &mut handle.context_handle_attributes)?;
    dcerpc_uuid_coder(dce, pdu, iov, offset, &mut handle.context_handle_uuid)
}

/// NDR pointer coder. Mirrors C `dcerpc_ptr_coder` (encode + decode unified):
/// - conformance run only updates alignment (skips top-level PTR_REF),
/// - top-level pointers code the referent inline (no referent id for PTR_REF),
/// - nested pointers emit a referent id and defer the referent,
/// - the top-level invocation flushes the deferred queue at the end.
pub fn dcerpc_ptr_coder(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    ptr: &mut DceRpcPayload,
    ptr_type: PtrType,
    coder: DceRpcCoder,
) -> Result<()> {
    let top_level = pdu.top_level;

    if pdu.is_conformance_run {
        if !(ptr_type == PtrType::Ref && pdu.top_level) {
            let align = if dce.tctx_id != 0 { 8 } else { 4 };
            pdu.max_alignment = pdu.max_alignment.max(align);
        }
        return Ok(());
    }

    let ptr_raw: *mut DceRpcPayload = ptr;

    match ptr_type {
        PtrType::Ref => {
            if pdu.top_level {
                pdu.top_level = false;
                let r = dcerpc_do_coder(dce, pdu, iov, offset, ptr, coder);
                pdu.top_level = top_level;
                r?;
            } else {
                let mut referent = if pdu.direction == DCERPC_DECODE {
                    0
                } else {
                    RPTR
                };
                dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut referent)?;
                pdu.deferred.push(DeferredPointer {
                    coder,
                    ptr: ptr_raw,
                });
            }
        }
        PtrType::Unique => {
            if pdu.direction == DCERPC_DECODE {
                let mut p = 0u64;
                dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut p)?;
                if p == 0 {
                    return Ok(());
                }
            } else {
                let mut referent = UPTR;
                dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut referent)?;
            }
            if pdu.top_level {
                pdu.top_level = false;
                let r = dcerpc_do_coder(dce, pdu, iov, offset, ptr, coder);
                pdu.top_level = top_level;
                r?;
            } else {
                pdu.deferred.push(DeferredPointer {
                    coder,
                    ptr: ptr_raw,
                });
            }
        }
        PtrType::Full => {
            if pdu.direction == DCERPC_DECODE {
                // C marks PTR_FULL decode as not implemented.
                let mut p = 0u64;
                dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut p)?;
                return Ok(());
            }
            pdu.ptr_id = pdu.ptr_id.saturating_add(1);
            let mut val = pdu.ptr_id;
            dcerpc_uint3264_coder(dce, pdu, iov, offset, &mut val)?;
            if pdu.top_level {
                pdu.top_level = false;
                let r = dcerpc_do_coder(dce, pdu, iov, offset, ptr, coder);
                pdu.top_level = top_level;
                r?;
            } else {
                pdu.deferred.push(DeferredPointer {
                    coder,
                    ptr: ptr_raw,
                });
            }
        }
    }

    if pdu.top_level {
        pdu.top_level = false;
        let r = dcerpc_process_deferred_pointers(dce, pdu, iov, offset);
        pdu.top_level = top_level;
        r?;
    }
    Ok(())
}

fn align_offset(offset: &mut i32, alignment: i32) -> Result<()> {
    if *offset < 0 || alignment <= 0 {
        return Err(DceRpcError {
            code: ERROR_INVALID_ARGUMENT,
        });
    }
    *offset = (*offset + (alignment - 1)) & !(alignment - 1);
    Ok(())
}

fn code_bytes(
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    bytes: &mut [u8],
) -> Result<()> {
    let start = usize::try_from(*offset).map_err(|_| DceRpcError {
        code: ERROR_INVALID_ARGUMENT,
    })?;
    let end = start.checked_add(bytes.len()).ok_or(DceRpcError {
        code: ERROR_INVALID_ARGUMENT,
    })?;
    match pdu.direction {
        DCERPC_DECODE => {
            if end > iov.data.len() {
                return Err(DceRpcError {
                    code: ERROR_INVALID_ARGUMENT,
                });
            }
            bytes.copy_from_slice(&iov.data[start..end]);
        }
        _ => {
            let old_iov_len = iov.data.len();
            if iov.data.len() < end {
                iov.data.resize(end, 0);
            }
            if pdu.payload.len() < end {
                pdu.payload.resize(end, 0);
            }
            if old_iov_len < start {
                pdu.payload[old_iov_len..start].fill(0);
            }
            iov.data[start..end].copy_from_slice(bytes);
            pdu.payload[start..end].copy_from_slice(bytes);
        }
    }
    *offset = i32::try_from(end).map_err(|_| DceRpcError {
        code: ERROR_INVALID_ARGUMENT,
    })?;
    Ok(())
}

fn code_vec(
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    bytes: &mut Vec<u8>,
    len: usize,
) -> Result<()> {
    if pdu.direction == DCERPC_DECODE {
        let mut out = vec![0; len];
        code_bytes(pdu, iov, offset, &mut out)?;
        *bytes = out;
        return Ok(());
    }
    if bytes.len() < len {
        return Err(DceRpcError {
            code: ERROR_INVALID_ARGUMENT,
        });
    }
    code_bytes(pdu, iov, offset, &mut bytes[..len])
}

/// Codes an NDR conformant+varying UTF-16 string. Conformance-aware to match the
/// C two-pass model (`dcerpc_encode_utf16`/`dcerpc_decode_utf16`):
/// - conformance run writes/reads the `max_count`, `offset`, `actual_count`
///   header (and, on encode, computes the UTF-16 units),
/// - data run writes/reads the UTF-16 code units themselves.
fn code_utf16(
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    value: &mut DceRpcUtf16,
    nul_terminated: bool,
) -> Result<()> {
    match pdu.direction {
        DCERPC_DECODE => {
            if pdu.is_conformance_run {
                // Conformance count fields are uint32s written via the
                // conformance coder, which aligns to 4 (mirrors C set_uint32).
                align_offset(offset, 4)?;
                let mut max_count = [0; 4];
                let mut string_offset = [0; 4];
                let mut actual_count = [0; 4];
                code_bytes(pdu, iov, offset, &mut max_count)?;
                code_bytes(pdu, iov, offset, &mut string_offset)?;
                code_bytes(pdu, iov, offset, &mut actual_count)?;
                value.max_count = u32::from_le_bytes(max_count);
                value.offset = u32::from_le_bytes(string_offset);
                value.actual_count = u32::from_le_bytes(actual_count);
                pdu.max_alignment = pdu.max_alignment.max(2);
                return Ok(());
            }
            value.utf16.clear();
            for _ in 0..value.actual_count {
                let mut unit = [0; 2];
                code_bytes(pdu, iov, offset, &mut unit)?;
                value.utf16.push(u16::from_le_bytes(unit));
            }
            let slice_len = if nul_terminated && value.utf16.last().copied() == Some(0) {
                value.utf16.len().saturating_sub(1)
            } else {
                value.utf16.len()
            };
            value.utf8 =
                Some(
                    String::from_utf16(&value.utf16[..slice_len]).map_err(|_| DceRpcError {
                        code: ERROR_INVALID_ARGUMENT,
                    })?,
                );
        }
        _ => {
            if pdu.is_conformance_run {
                value.utf16 = value
                    .utf8
                    .as_deref()
                    .unwrap_or_default()
                    .encode_utf16()
                    .collect();
                let mut actual = value.utf16.len() + usize::from(nul_terminated);
                value.actual_count = u32::try_from(actual).map_err(|_| DceRpcError {
                    code: ERROR_INVALID_ARGUMENT,
                })?;
                if !nul_terminated && actual % 2 != 0 {
                    actual += 1;
                }
                value.max_count = u32::try_from(actual).map_err(|_| DceRpcError {
                    code: ERROR_INVALID_ARGUMENT,
                })?;
                value.offset = 0;
                // Conformance count fields are uint32s written via the
                // conformance coder, which aligns to 4 (mirrors C set_uint32).
                align_offset(offset, 4)?;
                code_bytes(pdu, iov, offset, &mut value.max_count.to_le_bytes())?;
                code_bytes(pdu, iov, offset, &mut value.offset.to_le_bytes())?;
                code_bytes(pdu, iov, offset, &mut value.actual_count.to_le_bytes())?;
                pdu.max_alignment = pdu.max_alignment.max(2);
                return Ok(());
            }
            for unit in value.utf16.clone() {
                code_bytes(pdu, iov, offset, &mut unit.to_le_bytes())?;
            }
            if nul_terminated {
                code_bytes(pdu, iov, offset, &mut 0u16.to_le_bytes())?;
            }
        }
    }
    Ok(())
}
