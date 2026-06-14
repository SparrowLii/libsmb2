use std::fmt;

pub const DCERPC_DR_BIG_ENDIAN: u8 = 0x00;
pub const DCERPC_DR_LITTLE_ENDIAN: u8 = 0x10;
pub const DCERPC_DR_ASCII: u8 = 0x00;
pub const DCERPC_DR_EBCDIC: u8 = 0x01;
pub const DCERPC_DECODE: i32 = 0;
pub const DCERPC_ENCODE: i32 = 1;

const ERROR_INVALID_ARGUMENT: i32 = -22;
const ERROR_FUNCTION_NOT_IMPLEMENTED: i32 = -38;

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

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the public DCERPC async call boundary"
)]
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

pub fn dcerpc_do_coder(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    ptr: &mut DceRpcPayload,
    coder: DceRpcCoder,
) -> Result<()> {
    if coder(dce, pdu, iov, offset, ptr) != 0 {
        return Err(DceRpcError { code: -1 });
    }
    Ok(())
}

pub fn dcerpc_uint8_coder(
    _dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    value: &mut u8,
) -> Result<()> {
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
    dcerpc_uint32_coder(dce, pdu, iov, offset, value)
}

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the public DCERPC conformant-array coder boundary"
)]
pub fn dcerpc_carray_coder(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    num: usize,
    ptr: &mut DceRpcPayload,
    elem_size: usize,
    _coder: DceRpcCoder,
) -> Result<()> {
    let mut count = u32::try_from(num).map_err(|_| DceRpcError {
        code: ERROR_INVALID_ARGUMENT,
    })?;
    dcerpc_conformance_coder(dce, pdu, iov, offset, &mut count)?;
    if count as usize != num {
        return Err(DceRpcError { code: -1 });
    }
    let len = num.checked_mul(elem_size).ok_or(DceRpcError {
        code: ERROR_INVALID_ARGUMENT,
    })?;
    code_vec(pdu, iov, offset, &mut ptr.data, len)
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

pub fn dcerpc_ptr_coder(
    dce: &mut DceRpcContext,
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    ptr: &mut DceRpcPayload,
    ptr_type: PtrType,
    coder: DceRpcCoder,
) -> Result<()> {
    let mut referent = match ptr_type {
        PtrType::Ref => 0x7274_7052,
        PtrType::Unique | PtrType::Full => 0x7274_7055,
    };
    dcerpc_uint32_coder(dce, pdu, iov, offset, &mut referent)?;
    dcerpc_do_coder(dce, pdu, iov, offset, ptr, coder)
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

fn code_utf16(
    pdu: &mut DceRpcPdu,
    iov: &mut Smb2Iovec,
    offset: &mut i32,
    value: &mut DceRpcUtf16,
    nul_terminated: bool,
) -> Result<()> {
    match pdu.direction {
        DCERPC_DECODE => {
            let mut max_count = [0; 4];
            let mut string_offset = [0; 4];
            let mut actual_count = [0; 4];
            code_bytes(pdu, iov, offset, &mut max_count)?;
            code_bytes(pdu, iov, offset, &mut string_offset)?;
            code_bytes(pdu, iov, offset, &mut actual_count)?;
            value.max_count = u32::from_le_bytes(max_count);
            value.offset = u32::from_le_bytes(string_offset);
            value.actual_count = u32::from_le_bytes(actual_count);
            value.utf16.clear();
            for _ in 0..value.actual_count {
                align_offset(offset, 2)?;
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
            value.utf16 = value
                .utf8
                .as_deref()
                .unwrap_or_default()
                .encode_utf16()
                .collect();
            let actual = value.utf16.len() + usize::from(nul_terminated);
            value.actual_count = u32::try_from(actual).map_err(|_| DceRpcError {
                code: ERROR_INVALID_ARGUMENT,
            })?;
            value.max_count = value.actual_count;
            value.offset = 0;
            code_bytes(pdu, iov, offset, &mut value.max_count.to_le_bytes())?;
            code_bytes(pdu, iov, offset, &mut value.offset.to_le_bytes())?;
            code_bytes(pdu, iov, offset, &mut value.actual_count.to_le_bytes())?;
            for unit in value.utf16.clone() {
                align_offset(offset, 2)?;
                code_bytes(pdu, iov, offset, &mut unit.to_le_bytes())?;
            }
            if nul_terminated {
                align_offset(offset, 2)?;
                code_bytes(pdu, iov, offset, &mut 0u16.to_le_bytes())?;
            }
        }
    }
    Ok(())
}
