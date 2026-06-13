pub const SRVSVC_NETRSHAREENUM: u32 = 0x0f;
pub const SRVSVC_NETRSHAREGETINFO: u32 = 0x10;

pub const SHARE_TYPE_DISKTREE: u32 = 0;
pub const SHARE_TYPE_PRINTQ: u32 = 1;
pub const SHARE_TYPE_DEVICE: u32 = 2;
pub const SHARE_TYPE_IPC: u32 = 3;

pub const SHARE_TYPE_TEMPORARY: u32 = 0x4000_0000;
pub const SHARE_TYPE_HIDDEN: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ShareInfoLevel {
    ShareInfo0 = 0,
    ShareInfo1 = 1,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DcerpcUtf16 {
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo0 {
    pub netname: DcerpcUtf16,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo0Container {
    pub entries_read: u32,
    pub share_info_0: Vec<SrvsvcShareInfo0>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo1 {
    pub netname: DcerpcUtf16,
    pub share_type: u32,
    pub remark: DcerpcUtf16,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcShareInfo1Container {
    pub entries_read: u32,
    pub share_info_1: Vec<SrvsvcShareInfo1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrvsvcShareEnumUnion {
    Level0(SrvsvcShareInfo0Container),
    Level1(SrvsvcShareInfo1Container),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvsvcShareEnumStruct {
    pub level: u32,
    pub share_info: SrvsvcShareEnumUnion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvsvcNetrShareEnumReq {
    pub server_name: DcerpcUtf16,
    pub ses: SrvsvcShareEnumStruct,
    pub preferred_maximum_length: u32,
    pub resume_handle: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvsvcNetrShareEnumRep {
    pub status: u32,
    pub ses: SrvsvcShareEnumStruct,
    pub total_entries: u32,
    pub resume_handle: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrvsvcShareInfoPayload {
    ShareInfo1(SrvsvcShareInfo1),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvsvcShareInfo {
    pub level: u32,
    pub payload: SrvsvcShareInfoPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvsvcNetrShareGetInfoReq {
    pub server_name: DcerpcUtf16,
    pub netname: DcerpcUtf16,
    pub level: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvsvcNetrShareGetInfoRep {
    pub status: u32,
    pub info_struct: SrvsvcShareInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SrvsvcRep {
    pub status: u32,
}
