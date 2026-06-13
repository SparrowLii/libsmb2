//! CREATE command pack/unpack skeleton migrated from `lib/smb2-cmd-create.c`.

/// SMB2 packet header size used by CREATE offset calculations.
pub const SMB2_HEADER_SIZE: u16 = 64;

/// Wire structure size for an SMB2 CREATE request.
pub const SMB2_CREATE_REQUEST_SIZE: u16 = 57;

/// Wire structure size for an SMB2 CREATE reply.
pub const SMB2_CREATE_REPLY_SIZE: u16 = 89;

/// Size of an SMB2 file identifier carried by CREATE replies.
pub const SMB2_FD_SIZE: usize = 16;

const fn pad_to_32bit(value: u32) -> u32 {
    (value + 3) & !3
}

const fn pad_to_64bit(value: u32) -> u32 {
    (value + 7) & !7
}

const fn fixed_request_len() -> u32 {
    (SMB2_CREATE_REQUEST_SIZE & 0xfffe) as u32
}

const fn fixed_reply_len() -> u32 {
    (SMB2_CREATE_REPLY_SIZE & 0xfffe) as u32
}

/// Borrowed create-context bytes carried without protocol-specific decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CreateContext<'a> {
    /// Raw create-context payload bytes.
    pub bytes: &'a [u8],
}

impl<'a> CreateContext<'a> {
    /// Creates a raw CREATE context view.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the unpadded context length used in SMB2 headers.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.bytes.len() as u32
    }

    /// Returns true when no context bytes are present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the 64-bit padded context length used for iovec sizing.
    #[must_use]
    pub const fn padded_len(&self) -> u32 {
        pad_to_64bit(self.len())
    }
}

/// Rust-side skeleton for `struct smb2_create_request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2CreateRequest<'a> {
    /// Security flags byte from the fixed CREATE request.
    pub security_flags: u8,
    /// Requested opportunistic lock level.
    pub requested_oplock_level: u8,
    /// Impersonation level requested by the client.
    pub impersonation_level: u32,
    /// SMB create flags field.
    pub smb_create_flags: u64,
    /// Desired access mask.
    pub desired_access: u32,
    /// File attributes requested for create/open.
    pub file_attributes: u32,
    /// Share access mask.
    pub share_access: u32,
    /// Create disposition value.
    pub create_disposition: u32,
    /// Create options mask.
    pub create_options: u32,
    /// UTF-8 path name before UTF-16 wire conversion.
    pub name: Option<&'a str>,
    /// Wire offset of the encoded name.
    pub name_offset: u16,
    /// Encoded name length in bytes.
    pub name_length: u16,
    /// Wire offset of raw create-context bytes.
    pub create_context_offset: u32,
    /// Raw create-context length in bytes.
    pub create_context_length: u32,
    /// Optional raw create-context bytes passed through unchanged.
    pub create_context: Option<CreateContext<'a>>,
}

impl<'a> Smb2CreateRequest<'a> {
    /// Creates an empty CREATE request skeleton with fixed offsets unset.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0,
            smb_create_flags: 0,
            desired_access: 0,
            file_attributes: 0,
            share_access: 0,
            create_disposition: 0,
            create_options: 0,
            name: None,
            name_offset: 0,
            name_length: 0,
            create_context_offset: 0,
            create_context_length: 0,
            create_context: None,
        }
    }

    /// Sets the request name and records the expected UTF-16 byte length.
    #[must_use]
    pub fn with_name(mut self, name: &'a str) -> Self {
        self.name = if name.is_empty() { None } else { Some(name) };
        self.name_length = utf16_wire_len(name);
        self
    }

    /// Sets pass-through create-context bytes.
    #[must_use]
    pub fn with_create_context(mut self, bytes: &'a [u8]) -> Self {
        let context = CreateContext::new(bytes);
        self.create_context_length = context.len();
        self.create_context = if context.is_empty() {
            None
        } else {
            Some(context)
        };
        self
    }

    /// Mirrors `smb2_encode_create_request` offset calculation without encoding bytes.
    #[must_use]
    pub fn with_encoded_offsets(mut self) -> Self {
        self.name_offset = request_name_offset();
        self.create_context_offset = request_create_context_offset(
            self.name_offset,
            self.name_length,
            self.create_context_length,
        );
        self
    }

    /// Returns the variable area byte count requested by the fixed parser.
    #[must_use]
    pub const fn variable_bytes_len(&self) -> u32 {
        request_variable_bytes_len(
            self.name_offset,
            self.name_length,
            self.create_context_offset,
            self.create_context_length,
        )
    }
}

impl<'a> Default for Smb2CreateRequest<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// Rust-side skeleton for `struct smb2_create_reply`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2CreateReply<'a> {
    /// Oplock level returned by the server.
    pub oplock_level: u8,
    /// Reply flags byte.
    pub flags: u8,
    /// Create action result.
    pub create_action: u32,
    /// File creation time in SMB timestamp units.
    pub creation_time: u64,
    /// Last access time in SMB timestamp units.
    pub last_access_time: u64,
    /// Last write time in SMB timestamp units.
    pub last_write_time: u64,
    /// Change time in SMB timestamp units.
    pub change_time: u64,
    /// Allocation size reported by the server.
    pub allocation_size: u64,
    /// End-of-file size reported by the server.
    pub end_of_file: u64,
    /// File attributes reported by the server.
    pub file_attributes: u32,
    /// SMB2 file identifier.
    pub file_id: [u8; SMB2_FD_SIZE],
    /// Wire offset of raw create-context bytes.
    pub create_context_offset: u32,
    /// Raw create-context length in bytes.
    pub create_context_length: u32,
    /// Optional raw create-context bytes passed through unchanged.
    pub create_context: Option<CreateContext<'a>>,
}

impl<'a> Smb2CreateReply<'a> {
    /// Creates an empty CREATE reply skeleton with fixed offsets unset.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            oplock_level: 0,
            flags: 0,
            create_action: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: 0,
            file_id: [0; SMB2_FD_SIZE],
            create_context_offset: 0,
            create_context_length: 0,
            create_context: None,
        }
    }

    /// Sets pass-through create-context bytes.
    #[must_use]
    pub fn with_create_context(mut self, bytes: &'a [u8]) -> Self {
        let context = CreateContext::new(bytes);
        self.create_context_length = context.len();
        self.create_context = if context.is_empty() {
            None
        } else {
            Some(context)
        };
        self
    }

    /// Mirrors `smb2_encode_create_reply` context offset calculation.
    #[must_use]
    pub fn with_encoded_offsets(mut self) -> Self {
        self.create_context_offset = reply_create_context_offset();
        self
    }

    /// Returns the variable area byte count requested by the fixed parser.
    #[must_use]
    pub const fn variable_bytes_len(&self) -> u32 {
        reply_variable_bytes_len(self.create_context_offset, self.create_context_length)
    }
}

impl<'a> Default for Smb2CreateReply<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal PDU placeholder used by CREATE async skeleton functions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2CreatePdu<'a, T> {
    /// SMB2 command code for CREATE.
    pub command: Smb2CreateCommand,
    /// Request or reply payload associated with the PDU.
    pub payload: T,
    /// Optional callback data marker retained by async constructors.
    pub callback_data: Option<&'a [u8]>,
}

/// SMB2 CREATE command identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Smb2CreateCommand {
    /// SMB2 CREATE command, matching command code `0x0005`.
    #[default]
    Create,
}

/// Builds a CREATE request PDU skeleton, mirroring `smb2_cmd_create_async`.
#[must_use]
pub fn smb2_cmd_create_async<'a>(
    request: Smb2CreateRequest<'a>,
    callback_data: Option<&'a [u8]>,
) -> Smb2CreatePdu<'a, Smb2CreateRequest<'a>> {
    Smb2CreatePdu {
        command: Smb2CreateCommand::Create,
        payload: request.with_encoded_offsets(),
        callback_data,
    }
}

/// Builds a CREATE reply PDU skeleton, mirroring `smb2_cmd_create_reply_async`.
#[must_use]
pub fn smb2_cmd_create_reply_async<'a>(
    reply: Smb2CreateReply<'a>,
    callback_data: Option<&'a [u8]>,
) -> Smb2CreatePdu<'a, Smb2CreateReply<'a>> {
    Smb2CreatePdu {
        command: Smb2CreateCommand::Create,
        payload: reply.with_encoded_offsets(),
        callback_data,
    }
}

/// Computes the fixed CREATE request name offset.
#[must_use]
pub const fn request_name_offset() -> u16 {
    pad_to_32bit(SMB2_HEADER_SIZE as u32 + fixed_request_len()) as u16
}

/// Computes the CREATE request create-context offset.
#[must_use]
pub const fn request_create_context_offset(
    name_offset: u16,
    name_length: u16,
    create_context_length: u32,
) -> u32 {
    if create_context_length == 0 {
        0
    } else if name_length == 0 {
        pad_to_64bit(4 + name_offset as u32)
    } else {
        pad_to_64bit(name_length as u32 + name_offset as u32)
    }
}

/// Computes the fixed CREATE reply create-context offset.
#[must_use]
pub const fn reply_create_context_offset() -> u32 {
    pad_to_64bit(SMB2_HEADER_SIZE as u32 + fixed_reply_len())
}

/// Computes bytes needed for a CREATE reply variable area.
#[must_use]
pub const fn reply_variable_bytes_len(
    create_context_offset: u32,
    create_context_length: u32,
) -> u32 {
    if create_context_length == 0 {
        0
    } else {
        create_context_offset - SMB2_HEADER_SIZE as u32 - fixed_reply_len() + create_context_length
    }
}

/// Computes bytes needed for a CREATE request variable area.
#[must_use]
pub const fn request_variable_bytes_len(
    name_offset: u16,
    name_length: u16,
    create_context_offset: u32,
    create_context_length: u32,
) -> u32 {
    if create_context_length == 0 && name_length == 0 {
        0
    } else {
        let mut remaining = name_offset as u32 - SMB2_HEADER_SIZE as u32 - fixed_request_len();
        if create_context_offset > name_offset as u32 {
            remaining += pad_to_64bit(create_context_offset - name_offset as u32);
        } else {
            remaining += name_length as u32;
        }
        remaining + create_context_length
    }
}

/// Computes the current skeleton UTF-16 wire length for a request name.
#[must_use]
pub fn utf16_wire_len(name: &str) -> u16 {
    let byte_len = name.encode_utf16().count().saturating_mul(2);
    if byte_len > u16::MAX as usize {
        u16::MAX
    } else {
        byte_len as u16
    }
}
