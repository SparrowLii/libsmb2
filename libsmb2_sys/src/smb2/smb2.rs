pub const SMB2_GUID_SIZE: usize = 16;
pub const SMB2_FD_SIZE: usize = 16;
pub const SMB2_LEASE_KEY_SIZE: usize = 16;
pub const SMB2_NEGOTIATE_MAX_DIALECTS: usize = 10;

pub type Smb2Guid = [u8; SMB2_GUID_SIZE];
pub type Smb2FileId = [u8; SMB2_FD_SIZE];
pub type Smb2LeaseKey = [u8; SMB2_LEASE_KEY_SIZE];

pub const SMB2_ERROR_REPLY_SIZE: u16 = 9;
pub const SMB2_NEGOTIATE_REQUEST_SIZE: u16 = 36;
pub const SMB2_NEGOTIATE_REPLY_SIZE: u16 = 65;
pub const SMB2_SESSION_SETUP_REQUEST_SIZE: u16 = 25;
pub const SMB2_SESSION_SETUP_REPLY_SIZE: u16 = 9;
pub const SMB2_TREE_CONNECT_REQUEST_SIZE: u16 = 9;
pub const SMB2_TREE_CONNECT_REPLY_SIZE: u16 = 16;
pub const SMB2_CREATE_REQUEST_SIZE: u16 = 57;
pub const SMB2_CREATE_REPLY_SIZE: u16 = 89;
pub const SMB2_CLOSE_REQUEST_SIZE: u16 = 24;
pub const SMB2_CLOSE_REPLY_SIZE: u16 = 60;
pub const SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE: u16 = 80;
pub const SMB2_READ_REQUEST_SIZE: u16 = 49;
pub const SMB2_READ_REPLY_SIZE: u16 = 17;
pub const SMB2_QUERY_INFO_REQUEST_SIZE: u16 = 41;
pub const SMB2_QUERY_INFO_REPLY_SIZE: u16 = 9;
pub const SMB2_IOCTL_REQUEST_SIZE: u16 = 57;
pub const SMB2_IOCTL_REPLY_SIZE: u16 = 49;
pub const SMB2_CHANGE_NOTIFY_REQUEST_SIZE: u16 = 32;
pub const SMB2_CHANGE_NOTIFY_REPLY_SIZE: u16 = 9;
pub const SMB2_WRITE_REQUEST_SIZE: u16 = 49;
pub const SMB2_WRITE_REPLY_SIZE: u16 = 17;
pub const SMB2_LOCK_ELEMENT_SIZE: u16 = 24;
pub const SMB2_LOCK_REQUEST_SIZE: u16 = 48;

pub const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
pub const SMB2_FLAGS_ASYNC_COMMAND: u32 = 0x0000_0002;
pub const SMB2_FLAGS_RELATED_OPERATIONS: u32 = 0x0000_0004;
pub const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;
pub const SMB2_FLAGS_PRIORITY_MASK: u32 = 0x0000_0070;
pub const SMB2_FLAGS_DFS_OPERATIONS: u32 = 0x1000_0000;
pub const SMB2_FLAGS_REPLAY_OPERATION: u32 = 0x2000_0000;

pub const SMB2_NEGOTIATE_SIGNING_ENABLED: u16 = 0x0001;
pub const SMB2_NEGOTIATE_SIGNING_REQUIRED: u16 = 0x0002;
pub const SMB2_GLOBAL_CAP_DFS: u32 = 0x0000_0001;
pub const SMB2_GLOBAL_CAP_LEASING: u32 = 0x0000_0002;
pub const SMB2_GLOBAL_CAP_LARGE_MTU: u32 = 0x0000_0004;
pub const SMB2_GLOBAL_CAP_MULTI_CHANNEL: u32 = 0x0000_0008;
pub const SMB2_GLOBAL_CAP_PERSISTENT_HANDLES: u32 = 0x0000_0010;
pub const SMB2_GLOBAL_CAP_DIRECTORY_LEASING: u32 = 0x0000_0020;
pub const SMB2_GLOBAL_CAP_ENCRYPTION: u32 = 0x0000_0040;

pub const SMB2_SHARE_TYPE_DISK: u8 = 0x01;
pub const SMB2_SHARE_TYPE_PIPE: u8 = 0x02;
pub const SMB2_SHARE_TYPE_PRINT: u8 = 0x03;
pub const SMB2_OPLOCK_LEVEL_NONE: u8 = 0x00;
pub const SMB2_OPLOCK_LEVEL_II: u8 = 0x01;
pub const SMB2_OPLOCK_LEVEL_EXCLUSIVE: u8 = 0x08;
pub const SMB2_OPLOCK_LEVEL_BATCH: u8 = 0x09;
pub const SMB2_OPLOCK_LEVEL_LEASE: u8 = 0xff;

pub const SMB2_FILE_READ_DATA: u32 = 0x0000_0001;
pub const SMB2_FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const SMB2_FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const SMB2_FILE_EXECUTE: u32 = 0x0000_0020;
pub const SMB2_FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
pub const SMB2_FILE_ADD_FILE: u32 = 0x0000_0002;
pub const SMB2_FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
pub const SMB2_FILE_TRAVERSE: u32 = 0x0000_0020;

pub const SMB2_FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const SMB2_FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub const SMB2_FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
pub const SMB2_FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const SMB2_FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const SMB2_FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

pub const SMB2_FILE_DIRECTORY_INFORMATION: u8 = 0x01;
pub const SMB2_FILE_FULL_DIRECTORY_INFORMATION: u8 = 0x02;
pub const SMB2_FILE_BOTH_DIRECTORY_INFORMATION: u8 = 0x03;
pub const SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 0x25;
pub const SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION: u8 = 0x26;

pub const SMB2_0_INFO_FILE: u8 = 0x01;
pub const SMB2_0_INFO_FILESYSTEM: u8 = 0x02;
pub const SMB2_0_INFO_SECURITY: u8 = 0x03;
pub const SMB2_0_INFO_QUOTA: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Smb2Command {
    Negotiate = 0,
    SessionSetup = 1,
    Logoff = 2,
    TreeConnect = 3,
    TreeDisconnect = 4,
    Create = 5,
    Close = 6,
    Flush = 7,
    Read = 8,
    Write = 9,
    Lock = 10,
    Ioctl = 11,
    Cancel = 12,
    Echo = 13,
    QueryDirectory = 14,
    ChangeNotify = 15,
    QueryInfo = 16,
    SetInfo = 17,
    OplockBreak = 18,
    Smb1Negotiate = 114,
}

impl Smb2Command {
    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Negotiate),
            1 => Some(Self::SessionSetup),
            2 => Some(Self::Logoff),
            3 => Some(Self::TreeConnect),
            4 => Some(Self::TreeDisconnect),
            5 => Some(Self::Create),
            6 => Some(Self::Close),
            7 => Some(Self::Flush),
            8 => Some(Self::Read),
            9 => Some(Self::Write),
            10 => Some(Self::Lock),
            11 => Some(Self::Ioctl),
            12 => Some(Self::Cancel),
            13 => Some(Self::Echo),
            14 => Some(Self::QueryDirectory),
            15 => Some(Self::ChangeNotify),
            16 => Some(Self::QueryInfo),
            17 => Some(Self::SetInfo),
            18 => Some(Self::OplockBreak),
            114 => Some(Self::Smb1Negotiate),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2NegotiateRequest {
    pub dialect_count: u16,
    pub security_mode: u16,
    pub capabilities: u32,
    pub client_guid: Smb2Guid,
    pub negotiate_context_offset: u32,
    pub negotiate_context_count: u16,
    pub dialects: [u16; SMB2_NEGOTIATE_MAX_DIALECTS],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2TreeConnectReply {
    pub share_type: u8,
    pub share_flags: u32,
    pub capabilities: u32,
    pub maximal_access: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2CreateRequest {
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub name: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2CloseRequest {
    pub flags: u16,
    pub file_id: Smb2FileId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2ReadRequest {
    pub flags: u8,
    pub length: u32,
    pub offset: u64,
    pub file_id: Smb2FileId,
    pub minimum_count: u32,
    pub channel: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2QueryInfoRequest {
    pub info_type: u8,
    pub file_info_class: u8,
    pub output_buffer_length: u32,
    pub additional_information: u32,
    pub flags: u32,
    pub file_id: Smb2FileId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2IoctlRequest {
    pub ctl_code: u32,
    pub file_id: Smb2FileId,
    pub input_count: u32,
    pub output_count: u32,
    pub flags: u32,
    pub input: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2ChangeNotifyRequest {
    pub flags: u16,
    pub output_buffer_length: u32,
    pub file_id: Smb2FileId,
    pub completion_filter: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smb2WriteRequest {
    pub length: u32,
    pub offset: u64,
    pub buf: Vec<u8>,
    pub file_id: Smb2FileId,
    pub channel: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Smb2LockElement {
    pub offset: u64,
    pub length: u64,
    pub flags: u32,
}
