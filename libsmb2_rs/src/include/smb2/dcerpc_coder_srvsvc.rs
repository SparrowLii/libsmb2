pub const SRVSVC_NETRSHAREENUM: u32 = 0x0f;
pub const SRVSVC_NETRSHAREGETINFO: u32 = 0x10;

pub const SRVSVC_UUID: [u8; 16] = [
    0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
];
pub const SRVSVC_INTERFACE_MAJOR_VERSION: u16 = 3;
pub const SRVSVC_INTERFACE_MINOR_VERSION: u16 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SrvsvcInterfaceSyntax {
    pub uuid: [u8; 16],
    pub major_version: u16,
    pub minor_version: u16,
}

pub const SRVSVC_INTERFACE: SrvsvcInterfaceSyntax = SrvsvcInterfaceSyntax {
    uuid: SRVSVC_UUID,
    major_version: SRVSVC_INTERFACE_MAJOR_VERSION,
    minor_version: SRVSVC_INTERFACE_MINOR_VERSION,
};

pub const SHARE_TYPE_DISKTREE: u32 = 0;
pub const SHARE_TYPE_PRINTQ: u32 = 1;
pub const SHARE_TYPE_DEVICE: u32 = 2;
pub const SHARE_TYPE_IPC: u32 = 3;

pub const SHARE_TYPE_TEMPORARY: u32 = 0x4000_0000;
pub const SHARE_TYPE_HIDDEN: u32 = 0x8000_0000;
pub const SRVSVC_SHARE_ENUM_PREFERRED_MAXIMUM_LENGTH: u32 = u32::MAX;

const UNIQUE_POINTER_PRESENT: u32 = 0x5570_7455;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrvsvcHarnessError {
    BufferTooSmall,
    InvalidUtf16,
    NullPointer,
    UnsupportedLevel(u32),
}

pub type SrvsvcHarnessResult<T> = Result<T, SrvsvcHarnessError>;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvsvcShareEnumBoundary {
    pub requires_ipc_share: bool,
    pub requires_smb2_transport: bool,
    pub requires_dcerpc_bind: bool,
    pub safe_offline_smoke_available: bool,
    pub reason: &'static str,
}

#[must_use]
pub const fn share_enum_network_boundary() -> SrvsvcShareEnumBoundary {
    SrvsvcShareEnumBoundary {
        requires_ipc_share: true,
        requires_smb2_transport: true,
        requires_dcerpc_bind: true,
        safe_offline_smoke_available: false,
        reason: "smb2_share_enum_async/sync require a live SMB2 IPC$ tree and srvsvc DCERPC bind",
    }
}

#[must_use]
pub fn srvsvc_share_info_0_coder_harness(value: &SrvsvcShareInfo0) -> SrvsvcHarnessResult<Vec<u8>> {
    let mut codec = SrvsvcHarnessCodec::encoder();
    code_share_info_0(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

pub fn srvsvc_share_info_0_decoder_harness(bytes: &[u8]) -> SrvsvcHarnessResult<SrvsvcShareInfo0> {
    let mut value = SrvsvcShareInfo0::default();
    let mut codec = SrvsvcHarnessCodec::decoder(bytes);
    code_share_info_0(&mut codec, &mut value)?;
    Ok(value)
}

#[must_use]
pub fn srvsvc_share_info_0_container_coder_harness(
    value: &SrvsvcShareInfo0Container,
) -> SrvsvcHarnessResult<Vec<u8>> {
    let mut codec = SrvsvcHarnessCodec::encoder();
    code_share_info_0_container(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

pub fn srvsvc_share_info_0_container_decoder_harness(
    bytes: &[u8],
) -> SrvsvcHarnessResult<SrvsvcShareInfo0Container> {
    let mut value = SrvsvcShareInfo0Container::default();
    let mut codec = SrvsvcHarnessCodec::decoder(bytes);
    code_share_info_0_container(&mut codec, &mut value)?;
    Ok(value)
}

#[must_use]
pub fn srvsvc_share_info_1_coder_harness(value: &SrvsvcShareInfo1) -> SrvsvcHarnessResult<Vec<u8>> {
    let mut codec = SrvsvcHarnessCodec::encoder();
    code_share_info_1(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

pub fn srvsvc_share_info_1_decoder_harness(bytes: &[u8]) -> SrvsvcHarnessResult<SrvsvcShareInfo1> {
    let mut value = SrvsvcShareInfo1::default();
    let mut codec = SrvsvcHarnessCodec::decoder(bytes);
    code_share_info_1(&mut codec, &mut value)?;
    Ok(value)
}

#[must_use]
pub fn srvsvc_share_info_1_container_coder_harness(
    value: &SrvsvcShareInfo1Container,
) -> SrvsvcHarnessResult<Vec<u8>> {
    let mut codec = SrvsvcHarnessCodec::encoder();
    code_share_info_1_container(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

pub fn srvsvc_share_info_1_container_decoder_harness(
    bytes: &[u8],
) -> SrvsvcHarnessResult<SrvsvcShareInfo1Container> {
    let mut value = SrvsvcShareInfo1Container::default();
    let mut codec = SrvsvcHarnessCodec::decoder(bytes);
    code_share_info_1_container(&mut codec, &mut value)?;
    Ok(value)
}

#[must_use]
pub fn srvsvc_netr_share_enum_req_coder_harness(
    value: &SrvsvcNetrShareEnumReq,
) -> SrvsvcHarnessResult<Vec<u8>> {
    let mut codec = SrvsvcHarnessCodec::encoder();
    code_netr_share_enum_req(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

pub fn srvsvc_netr_share_enum_req_decoder_harness(
    bytes: &[u8],
) -> SrvsvcHarnessResult<SrvsvcNetrShareEnumReq> {
    let mut value = SrvsvcNetrShareEnumReq {
        server_name: DcerpcUtf16::default(),
        ses: share_enum_struct_for_level(ShareInfoLevel::ShareInfo1),
        preferred_maximum_length: 0,
        resume_handle: 0,
    };
    let mut codec = SrvsvcHarnessCodec::decoder(bytes);
    code_netr_share_enum_req(&mut codec, &mut value)?;
    Ok(value)
}

#[must_use]
pub fn srvsvc_netr_share_enum_rep_coder_harness(
    value: &SrvsvcNetrShareEnumRep,
) -> SrvsvcHarnessResult<Vec<u8>> {
    let mut codec = SrvsvcHarnessCodec::encoder();
    code_netr_share_enum_rep(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

pub fn srvsvc_netr_share_enum_rep_decoder_harness(
    bytes: &[u8],
) -> SrvsvcHarnessResult<SrvsvcNetrShareEnumRep> {
    let mut value = SrvsvcNetrShareEnumRep {
        status: 0,
        ses: share_enum_struct_for_level(ShareInfoLevel::ShareInfo1),
        total_entries: 0,
        resume_handle: 0,
    };
    let mut codec = SrvsvcHarnessCodec::decoder(bytes);
    code_netr_share_enum_rep(&mut codec, &mut value)?;
    Ok(value)
}

#[must_use]
pub fn srvsvc_netr_share_get_info_req_coder_harness(
    value: &SrvsvcNetrShareGetInfoReq,
) -> SrvsvcHarnessResult<Vec<u8>> {
    let mut codec = SrvsvcHarnessCodec::encoder();
    code_netr_share_get_info_req(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

pub fn srvsvc_netr_share_get_info_req_decoder_harness(
    bytes: &[u8],
) -> SrvsvcHarnessResult<SrvsvcNetrShareGetInfoReq> {
    let mut value = SrvsvcNetrShareGetInfoReq::default();
    let mut codec = SrvsvcHarnessCodec::decoder(bytes);
    code_netr_share_get_info_req(&mut codec, &mut value)?;
    Ok(value)
}

#[must_use]
pub fn srvsvc_netr_share_get_info_rep_coder_harness(
    value: &SrvsvcNetrShareGetInfoRep,
) -> SrvsvcHarnessResult<Vec<u8>> {
    let mut codec = SrvsvcHarnessCodec::encoder();
    code_netr_share_get_info_rep(&mut codec, &mut value.clone())?;
    Ok(codec.into_bytes())
}

pub fn srvsvc_netr_share_get_info_rep_decoder_harness(
    bytes: &[u8],
) -> SrvsvcHarnessResult<SrvsvcNetrShareGetInfoRep> {
    let mut value = SrvsvcNetrShareGetInfoRep {
        status: 0,
        info_struct: SrvsvcShareInfo {
            level: 1,
            payload: SrvsvcShareInfoPayload::ShareInfo1(SrvsvcShareInfo1::default()),
        },
    };
    let mut codec = SrvsvcHarnessCodec::decoder(bytes);
    code_netr_share_get_info_rep(&mut codec, &mut value)?;
    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HarnessDirection {
    Encode,
    Decode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SrvsvcHarnessCodec {
    direction: HarnessDirection,
    bytes: Vec<u8>,
    offset: usize,
}

impl SrvsvcHarnessCodec {
    fn encoder() -> Self {
        Self {
            direction: HarnessDirection::Encode,
            bytes: Vec::new(),
            offset: 0,
        }
    }

    fn decoder(bytes: &[u8]) -> Self {
        Self {
            direction: HarnessDirection::Decode,
            bytes: bytes.to_vec(),
            offset: 0,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    fn code_u32(&mut self, value: &mut u32) -> SrvsvcHarnessResult<()> {
        self.align(4);
        match self.direction {
            HarnessDirection::Encode => {
                self.ensure_write(4);
                self.bytes[self.offset..self.offset + 4].copy_from_slice(&value.to_le_bytes());
                self.offset += 4;
            }
            HarnessDirection::Decode => {
                self.ensure_available(4)?;
                *value = u32::from_le_bytes([
                    self.bytes[self.offset],
                    self.bytes[self.offset + 1],
                    self.bytes[self.offset + 2],
                    self.bytes[self.offset + 3],
                ]);
                self.offset += 4;
            }
        }
        Ok(())
    }

    fn code_u16(&mut self, value: &mut u16) -> SrvsvcHarnessResult<()> {
        self.align(2);
        match self.direction {
            HarnessDirection::Encode => {
                self.ensure_write(2);
                self.bytes[self.offset..self.offset + 2].copy_from_slice(&value.to_le_bytes());
                self.offset += 2;
            }
            HarnessDirection::Decode => {
                self.ensure_available(2)?;
                *value = u16::from_le_bytes([self.bytes[self.offset], self.bytes[self.offset + 1]]);
                self.offset += 2;
            }
        }
        Ok(())
    }

    fn code_unique_pointer_present(&mut self, present: bool) -> SrvsvcHarnessResult<bool> {
        let mut referent = if present { UNIQUE_POINTER_PRESENT } else { 0 };
        self.code_u32(&mut referent)?;
        Ok(referent != 0)
    }

    fn code_utf16z(&mut self, value: &mut DcerpcUtf16) -> SrvsvcHarnessResult<()> {
        match self.direction {
            HarnessDirection::Encode => {
                let text = value.value.as_deref().unwrap_or_default();
                let mut units: Vec<u16> = text.encode_utf16().collect();
                units.push(0);
                let mut count = units.len() as u32;
                let mut offset = 0;
                self.code_u32(&mut count)?;
                self.code_u32(&mut offset)?;
                self.code_u32(&mut count)?;
                for unit in &mut units {
                    self.code_u16(unit)?;
                }
            }
            HarnessDirection::Decode => {
                let mut max_count = 0;
                let mut offset = 0;
                let mut actual_count = 0;
                self.code_u32(&mut max_count)?;
                self.code_u32(&mut offset)?;
                self.code_u32(&mut actual_count)?;
                let mut units = Vec::with_capacity(actual_count as usize);
                for _ in 0..actual_count {
                    let mut unit = 0;
                    self.code_u16(&mut unit)?;
                    units.push(unit);
                }
                let text_units = if units.last().copied() == Some(0) {
                    &units[..units.len().saturating_sub(1)]
                } else {
                    &units[..]
                };
                value.value = Some(
                    String::from_utf16(text_units).map_err(|_| SrvsvcHarnessError::InvalidUtf16)?,
                );
            }
        }
        Ok(())
    }

    fn align(&mut self, alignment: usize) {
        self.offset = (self.offset + alignment - 1) & !(alignment - 1);
        if matches!(self.direction, HarnessDirection::Encode) && self.bytes.len() < self.offset {
            self.bytes.resize(self.offset, 0);
        }
    }

    fn ensure_available(&self, len: usize) -> SrvsvcHarnessResult<()> {
        if self.offset.saturating_add(len) > self.bytes.len() {
            Err(SrvsvcHarnessError::BufferTooSmall)
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

fn code_optional_string(
    codec: &mut SrvsvcHarnessCodec,
    value: &mut DcerpcUtf16,
) -> SrvsvcHarnessResult<()> {
    let present = codec.code_unique_pointer_present(value.value.is_some())?;
    if !present {
        value.value = None;
        return Ok(());
    }
    codec.code_utf16z(value)
}

fn code_required_string(
    codec: &mut SrvsvcHarnessCodec,
    value: &mut DcerpcUtf16,
) -> SrvsvcHarnessResult<()> {
    let present = codec.code_unique_pointer_present(true)?;
    if !present {
        return Err(SrvsvcHarnessError::NullPointer);
    }
    codec.code_utf16z(value)
}

fn code_share_info_0(
    codec: &mut SrvsvcHarnessCodec,
    value: &mut SrvsvcShareInfo0,
) -> SrvsvcHarnessResult<()> {
    code_optional_string(codec, &mut value.netname)
}

fn code_share_info_1(
    codec: &mut SrvsvcHarnessCodec,
    value: &mut SrvsvcShareInfo1,
) -> SrvsvcHarnessResult<()> {
    code_optional_string(codec, &mut value.netname)?;
    codec.code_u32(&mut value.share_type)?;
    code_optional_string(codec, &mut value.remark)
}

fn code_share_info_0_container(
    codec: &mut SrvsvcHarnessCodec,
    value: &mut SrvsvcShareInfo0Container,
) -> SrvsvcHarnessResult<()> {
    if matches!(codec.direction, HarnessDirection::Encode) {
        value.entries_read = value.share_info_0.len() as u32;
    }
    codec.code_u32(&mut value.entries_read)?;
    let present = codec.code_unique_pointer_present(value.entries_read != 0)?;
    if !present {
        value.share_info_0.clear();
        return Ok(());
    }
    let mut array_count = value.entries_read;
    codec.code_u32(&mut array_count)?;
    value
        .share_info_0
        .resize_with(array_count as usize, SrvsvcShareInfo0::default);
    for item in &mut value.share_info_0 {
        code_share_info_0(codec, item)?;
    }
    Ok(())
}

fn code_share_info_1_container(
    codec: &mut SrvsvcHarnessCodec,
    value: &mut SrvsvcShareInfo1Container,
) -> SrvsvcHarnessResult<()> {
    if matches!(codec.direction, HarnessDirection::Encode) {
        value.entries_read = value.share_info_1.len() as u32;
    }
    codec.code_u32(&mut value.entries_read)?;
    let present = codec.code_unique_pointer_present(value.entries_read != 0)?;
    if !present {
        value.share_info_1.clear();
        return Ok(());
    }
    let mut array_count = value.entries_read;
    codec.code_u32(&mut array_count)?;
    value
        .share_info_1
        .resize_with(array_count as usize, SrvsvcShareInfo1::default);
    for item in &mut value.share_info_1 {
        code_share_info_1(codec, item)?;
    }
    Ok(())
}

fn code_share_enum_struct(
    codec: &mut SrvsvcHarnessCodec,
    value: &mut SrvsvcShareEnumStruct,
) -> SrvsvcHarnessResult<()> {
    if matches!(codec.direction, HarnessDirection::Decode) {
        codec.code_u32(&mut value.level)?;
        *value = share_enum_struct_for_raw_level(value.level)?;
    } else {
        codec.code_u32(&mut value.level)?;
    }
    code_share_enum_union(codec, value)
}

fn code_share_enum_union(
    codec: &mut SrvsvcHarnessCodec,
    value: &mut SrvsvcShareEnumStruct,
) -> SrvsvcHarnessResult<()> {
    codec.code_u32(&mut value.level)?;
    match &mut value.share_info {
        SrvsvcShareEnumUnion::Level0(container) => code_share_info_0_container(codec, container),
        SrvsvcShareEnumUnion::Level1(container) => code_share_info_1_container(codec, container),
    }
}

fn code_share_info(
    codec: &mut SrvsvcHarnessCodec,
    value: &mut SrvsvcShareInfo,
) -> SrvsvcHarnessResult<()> {
    codec.code_u32(&mut value.level)?;
    if matches!(codec.direction, HarnessDirection::Decode) {
        value.payload = match value.level {
            1 => SrvsvcShareInfoPayload::ShareInfo1(SrvsvcShareInfo1::default()),
            level => return Err(SrvsvcHarnessError::UnsupportedLevel(level)),
        };
    }
    match &mut value.payload {
        SrvsvcShareInfoPayload::ShareInfo1(info) => code_share_info_1(codec, info),
    }
}

fn code_netr_share_enum_req(
    codec: &mut SrvsvcHarnessCodec,
    value: &mut SrvsvcNetrShareEnumReq,
) -> SrvsvcHarnessResult<()> {
    code_optional_string(codec, &mut value.server_name)?;
    code_share_enum_struct(codec, &mut value.ses)?;
    codec.code_u32(&mut value.preferred_maximum_length)?;
    codec.code_u32(&mut value.resume_handle)
}

fn code_netr_share_enum_rep(
    codec: &mut SrvsvcHarnessCodec,
    value: &mut SrvsvcNetrShareEnumRep,
) -> SrvsvcHarnessResult<()> {
    code_share_enum_struct(codec, &mut value.ses)?;
    codec.code_u32(&mut value.total_entries)?;
    codec.code_u32(&mut value.resume_handle)?;
    codec.code_u32(&mut value.status)
}

fn code_netr_share_get_info_req(
    codec: &mut SrvsvcHarnessCodec,
    value: &mut SrvsvcNetrShareGetInfoReq,
) -> SrvsvcHarnessResult<()> {
    code_optional_string(codec, &mut value.server_name)?;
    code_required_string(codec, &mut value.netname)?;
    codec.code_u32(&mut value.level)
}

fn code_netr_share_get_info_rep(
    codec: &mut SrvsvcHarnessCodec,
    value: &mut SrvsvcNetrShareGetInfoRep,
) -> SrvsvcHarnessResult<()> {
    code_share_info(codec, &mut value.info_struct)?;
    codec.code_u32(&mut value.status)
}

fn share_enum_struct_for_level(level: ShareInfoLevel) -> SrvsvcShareEnumStruct {
    match level {
        ShareInfoLevel::ShareInfo0 => SrvsvcShareEnumStruct {
            level: 0,
            share_info: SrvsvcShareEnumUnion::Level0(SrvsvcShareInfo0Container::default()),
        },
        ShareInfoLevel::ShareInfo1 => SrvsvcShareEnumStruct {
            level: 1,
            share_info: SrvsvcShareEnumUnion::Level1(SrvsvcShareInfo1Container::default()),
        },
    }
}

fn share_enum_struct_for_raw_level(level: u32) -> SrvsvcHarnessResult<SrvsvcShareEnumStruct> {
    match level {
        0 => Ok(share_enum_struct_for_level(ShareInfoLevel::ShareInfo0)),
        1 => Ok(share_enum_struct_for_level(ShareInfoLevel::ShareInfo1)),
        level => Err(SrvsvcHarnessError::UnsupportedLevel(level)),
    }
}
