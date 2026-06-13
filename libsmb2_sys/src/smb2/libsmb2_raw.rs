pub const SMB2_FD_SIZE: usize = 16;

pub type Smb2FileId = [u8; SMB2_FD_SIZE];

pub const COMPOUND_FILE_ID: Smb2FileId = [0xff; SMB2_FD_SIZE];
