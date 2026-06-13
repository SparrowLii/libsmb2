pub const DCERPC_DR_BIG_ENDIAN: u8 = 0x00;
pub const DCERPC_DR_LITTLE_ENDIAN: u8 = 0x10;
pub const DCERPC_DR_ASCII: u8 = 0x00;
pub const DCERPC_DR_EBCDIC: u8 = 0x01;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DceRpcContext;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DceRpcPdu;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Smb2Iovec {
    pub data: Vec<u8>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DceRpcPayload {
    pub data: Vec<u8>,
}

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

pub const NDR_TRANSFER_SYNTAX: NdrTransferSyntax = NdrTransferSyntax {
    uuid: DceRpcUuid {
        v1: 0x8a88_5d04,
        v2: 0x1ceb,
        v3: 0x11c9,
        v4: [0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60],
    },
    vers: 2,
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
