//! CREATE command pack/unpack skeleton migrated from `lib/smb2-cmd-create.c`.

/// SMB2 packet header size used by CREATE offset calculations.
pub const SMB2_HEADER_SIZE: u16 = 64;

/// Wire structure size for an SMB2 CREATE request.
pub const SMB2_CREATE_REQUEST_SIZE: u16 = 57;

/// Wire structure size for an SMB2 CREATE reply.
pub const SMB2_CREATE_REPLY_SIZE: u16 = 89;

/// Size of an SMB2 file identifier carried by CREATE replies.
pub const SMB2_FD_SIZE: usize = 16;

/// Error returned by CREATE command fixed/variable encoding and decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smb2CreateError {
    /// A fixed or variable byte buffer is shorter than the SMB2 layout requires.
    BufferTooShort,
    /// The structure-size field does not match the expected SMB2 CREATE shape.
    InvalidStructureSize { expected: u16, actual: u16 },
    /// A calculated or decoded offset points into the fixed CREATE body.
    VariableOverlapsFixed,
    /// A variable range described by offset and length exceeds the supplied bytes.
    VariableOutOfBounds,
    /// A length cannot be represented in the SMB2 wire field.
    LengthOverflow,
}

/// Result type used by CREATE command helpers.
pub type Smb2CreateResult<T> = Result<T, Smb2CreateError>;

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
    /// Encoded fixed and variable output vectors, mirroring C `pdu->out` order.
    pub out: Vec<Vec<u8>>,
}

/// SMB2 CREATE command identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Smb2CreateCommand {
    /// SMB2 CREATE command, matching command code `0x0005`.
    #[default]
    Create,
}

/// Builds a CREATE request PDU skeleton, mirroring `smb2_cmd_create_async`.
pub fn smb2_cmd_create_async<'a>(
    request: Smb2CreateRequest<'a>,
    callback_data: Option<&'a [u8]>,
) -> Smb2CreateResult<Smb2CreatePdu<'a, Smb2CreateRequest<'a>>> {
    let request = request.with_encoded_offsets();
    let out = encode_create_request(&request)?;
    Ok(Smb2CreatePdu {
        command: Smb2CreateCommand::Create,
        payload: request,
        callback_data,
        out,
    })
}

/// Builds a CREATE reply PDU skeleton, mirroring `smb2_cmd_create_reply_async`.
pub fn smb2_cmd_create_reply_async<'a>(
    reply: Smb2CreateReply<'a>,
    callback_data: Option<&'a [u8]>,
) -> Smb2CreateResult<Smb2CreatePdu<'a, Smb2CreateReply<'a>>> {
    let reply = reply.with_encoded_offsets();
    let out = encode_create_reply(&reply)?;
    Ok(Smb2CreatePdu {
        command: Smb2CreateCommand::Create,
        payload: reply,
        callback_data,
        out,
    })
}

/// Encodes CREATE request fixed bytes plus padded name and create-context vectors.
pub fn encode_create_request(request: &Smb2CreateRequest<'_>) -> Smb2CreateResult<Vec<Vec<u8>>> {
    let mut fixed = vec![0; fixed_request_len() as usize];
    write_u16(&mut fixed, 0, SMB2_CREATE_REQUEST_SIZE)?;
    write_u8(&mut fixed, 2, request.security_flags)?;
    write_u8(&mut fixed, 3, request.requested_oplock_level)?;
    write_u32(&mut fixed, 4, request.impersonation_level)?;
    write_u64(&mut fixed, 8, request.smb_create_flags)?;
    write_u32(&mut fixed, 24, request.desired_access)?;
    write_u32(&mut fixed, 28, request.file_attributes)?;
    write_u32(&mut fixed, 32, request.share_access)?;
    write_u32(&mut fixed, 36, request.create_disposition)?;
    write_u32(&mut fixed, 40, request.create_options)?;
    write_u16(&mut fixed, 44, request.name_offset)?;
    write_u16(&mut fixed, 46, request.name_length)?;
    write_u32(&mut fixed, 48, request.create_context_offset)?;
    write_u32(&mut fixed, 52, request.create_context_length)?;

    let mut vectors = vec![fixed];
    vectors.push(encode_create_name_vector(request.name)?);
    if let Some(context) = request.create_context {
        vectors.push(padded_copy(context.bytes, context.padded_len() as usize));
    }
    Ok(vectors)
}

/// Encodes CREATE reply fixed bytes plus optional padded create-context vector.
pub fn encode_create_reply(reply: &Smb2CreateReply<'_>) -> Smb2CreateResult<Vec<Vec<u8>>> {
    let mut fixed = vec![0; fixed_reply_len() as usize];
    write_u16(&mut fixed, 0, SMB2_CREATE_REPLY_SIZE)?;
    write_u8(&mut fixed, 2, reply.oplock_level)?;
    write_u8(&mut fixed, 3, reply.flags)?;
    write_u32(&mut fixed, 4, reply.create_action)?;
    write_u64(&mut fixed, 8, reply.creation_time)?;
    write_u64(&mut fixed, 16, reply.last_access_time)?;
    write_u64(&mut fixed, 24, reply.last_write_time)?;
    write_u64(&mut fixed, 32, reply.change_time)?;
    write_u64(&mut fixed, 40, reply.allocation_size)?;
    write_u64(&mut fixed, 48, reply.end_of_file)?;
    write_u32(&mut fixed, 56, reply.file_attributes)?;
    write_bytes(&mut fixed, 64, &reply.file_id)?;
    write_u32(&mut fixed, 80, reply.create_context_offset)?;
    write_u32(&mut fixed, 84, reply.create_context_length)?;

    let mut vectors = vec![fixed];
    if let Some(context) = reply.create_context {
        vectors.push(padded_copy(context.bytes, context.padded_len() as usize));
    }
    Ok(vectors)
}

/// Decodes the fixed CREATE request and returns expected variable byte count.
pub fn decode_create_request_fixed(
    fixed: &[u8],
) -> Smb2CreateResult<(Smb2CreateRequest<'static>, usize)> {
    validate_fixed(
        fixed,
        SMB2_CREATE_REQUEST_SIZE,
        fixed_request_len() as usize,
    )?;
    let name_offset = read_u16(fixed, 44)?;
    let name_length = read_u16(fixed, 46)?;
    let create_context_offset = read_u32(fixed, 48)?;
    let create_context_length = read_u32(fixed, 52)?;
    validate_request_variable_ranges(
        name_offset,
        name_length,
        create_context_offset,
        create_context_length,
    )?;
    Ok((
        Smb2CreateRequest {
            security_flags: read_u8(fixed, 2)?,
            requested_oplock_level: read_u8(fixed, 3)?,
            impersonation_level: read_u32(fixed, 4)?,
            smb_create_flags: read_u64(fixed, 8)?,
            desired_access: read_u32(fixed, 24)?,
            file_attributes: read_u32(fixed, 28)?,
            share_access: read_u32(fixed, 32)?,
            create_disposition: read_u32(fixed, 36)?,
            create_options: read_u32(fixed, 40)?,
            name: None,
            name_offset,
            name_length,
            create_context_offset,
            create_context_length,
            create_context: None,
        },
        request_variable_bytes_len(
            name_offset,
            name_length,
            create_context_offset,
            create_context_length,
        ) as usize,
    ))
}

/// Decodes the fixed CREATE reply and returns expected variable byte count.
pub fn decode_create_reply_fixed(
    fixed: &[u8],
) -> Smb2CreateResult<(Smb2CreateReply<'static>, usize)> {
    validate_fixed(fixed, SMB2_CREATE_REPLY_SIZE, fixed_reply_len() as usize)?;
    let create_context_offset = read_u32(fixed, 80)?;
    let create_context_length = read_u32(fixed, 84)?;
    if create_context_length > 0
        && create_context_offset < SMB2_HEADER_SIZE as u32 + fixed_reply_len()
    {
        return Err(Smb2CreateError::VariableOverlapsFixed);
    }
    let mut file_id = [0; SMB2_FD_SIZE];
    file_id.copy_from_slice(read_bytes(fixed, 64, SMB2_FD_SIZE)?);
    Ok((
        Smb2CreateReply {
            oplock_level: read_u8(fixed, 2)?,
            flags: read_u8(fixed, 3)?,
            create_action: read_u32(fixed, 4)?,
            creation_time: read_u64(fixed, 8)?,
            last_access_time: read_u64(fixed, 16)?,
            last_write_time: read_u64(fixed, 24)?,
            change_time: read_u64(fixed, 32)?,
            allocation_size: read_u64(fixed, 40)?,
            end_of_file: read_u64(fixed, 48)?,
            file_attributes: read_u32(fixed, 56)?,
            file_id,
            create_context_offset,
            create_context_length,
            create_context: None,
        },
        reply_variable_bytes_len(create_context_offset, create_context_length) as usize,
    ))
}

/// Returns the CREATE request name bytes and create-context bytes from a variable buffer.
pub fn decode_create_request_variable<'a>(
    request: &Smb2CreateRequest<'_>,
    variable: &'a [u8],
) -> Smb2CreateResult<(Option<String>, Option<&'a [u8]>)> {
    let name_offset = request.name_offset as u32 - SMB2_HEADER_SIZE as u32 - fixed_request_len();
    let name = if request.name_length == 0 {
        None
    } else {
        let bytes = checked_range(
            variable,
            name_offset as usize,
            usize::from(request.name_length),
        )?;
        Some(decode_utf16le_lossy(bytes))
    };
    let context = if request.create_context_length == 0 || request.create_context_offset == 0 {
        None
    } else {
        let offset = request.create_context_offset - SMB2_HEADER_SIZE as u32 - fixed_request_len();
        Some(checked_range(
            variable,
            offset as usize,
            request.create_context_length as usize,
        )?)
    };
    Ok((name, context))
}

/// Returns CREATE reply create-context bytes from a variable buffer.
pub fn decode_create_reply_variable<'a>(
    reply: &Smb2CreateReply<'_>,
    variable: &'a [u8],
) -> Smb2CreateResult<Option<&'a [u8]>> {
    if reply.create_context_length == 0 || reply.create_context_offset == 0 {
        return Ok(None);
    }
    let offset = reply.create_context_offset - SMB2_HEADER_SIZE as u32 - fixed_reply_len();
    Ok(Some(checked_range(
        variable,
        offset as usize,
        reply.create_context_length as usize,
    )?))
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

fn encode_create_name_vector(name: Option<&str>) -> Smb2CreateResult<Vec<u8>> {
    let Some(name) = name else {
        return Ok(vec![0; 8]);
    };
    if name.is_empty() {
        return Ok(vec![0; 8]);
    }
    let byte_len = name
        .encode_utf16()
        .count()
        .checked_mul(2)
        .ok_or(Smb2CreateError::LengthOverflow)?;
    let mut out = vec![0; pad_to_64bit(byte_len as u32) as usize];
    for (index, unit) in name.encode_utf16().enumerate() {
        let wire_unit = if unit == 0x002f { 0x005c } else { unit };
        write_u16(&mut out, index * 2, wire_unit)?;
    }
    Ok(out)
}

fn padded_copy(bytes: &[u8], padded_len: usize) -> Vec<u8> {
    let mut out = vec![0; padded_len];
    let copy_len = bytes.len().min(out.len());
    out[..copy_len].copy_from_slice(&bytes[..copy_len]);
    out
}

fn validate_fixed(fixed: &[u8], expected_size: u16, expected_len: usize) -> Smb2CreateResult<()> {
    if fixed.len() != expected_len {
        return Err(Smb2CreateError::BufferTooShort);
    }
    let actual = read_u16(fixed, 0)?;
    if actual != expected_size {
        return Err(Smb2CreateError::InvalidStructureSize {
            expected: expected_size,
            actual,
        });
    }
    Ok(())
}

fn validate_request_variable_ranges(
    name_offset: u16,
    name_length: u16,
    create_context_offset: u32,
    create_context_length: u32,
) -> Smb2CreateResult<()> {
    let minimum = SMB2_HEADER_SIZE as u32 + fixed_request_len();
    if name_length > 0 && u32::from(name_offset) < minimum {
        return Err(Smb2CreateError::VariableOverlapsFixed);
    }
    if create_context_length > 0 && create_context_offset < minimum {
        return Err(Smb2CreateError::VariableOverlapsFixed);
    }
    Ok(())
}

fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
    String::from_utf16_lossy(&units.collect::<Vec<_>>())
}

fn checked_range(input: &[u8], offset: usize, len: usize) -> Smb2CreateResult<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(Smb2CreateError::VariableOutOfBounds)?;
    input
        .get(offset..end)
        .ok_or(Smb2CreateError::VariableOutOfBounds)
}

fn read_u8(input: &[u8], offset: usize) -> Smb2CreateResult<u8> {
    input
        .get(offset)
        .copied()
        .ok_or(Smb2CreateError::BufferTooShort)
}

fn read_u16(input: &[u8], offset: usize) -> Smb2CreateResult<u16> {
    let bytes = read_bytes(input, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Smb2CreateResult<u32> {
    let bytes = read_bytes(input, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(input: &[u8], offset: usize) -> Smb2CreateResult<u64> {
    let bytes = read_bytes(input, offset, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_bytes(input: &[u8], offset: usize, len: usize) -> Smb2CreateResult<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(Smb2CreateError::BufferTooShort)?;
    input
        .get(offset..end)
        .ok_or(Smb2CreateError::BufferTooShort)
}

fn write_u8(output: &mut [u8], offset: usize, value: u8) -> Smb2CreateResult<()> {
    let slot = output
        .get_mut(offset)
        .ok_or(Smb2CreateError::BufferTooShort)?;
    *slot = value;
    Ok(())
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) -> Smb2CreateResult<()> {
    write_bytes(output, offset, &value.to_le_bytes())
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) -> Smb2CreateResult<()> {
    write_bytes(output, offset, &value.to_le_bytes())
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) -> Smb2CreateResult<()> {
    write_bytes(output, offset, &value.to_le_bytes())
}

fn write_bytes(output: &mut [u8], offset: usize, value: &[u8]) -> Smb2CreateResult<()> {
    let end = offset
        .checked_add(value.len())
        .ok_or(Smb2CreateError::BufferTooShort)?;
    let dst = output
        .get_mut(offset..end)
        .ok_or(Smb2CreateError::BufferTooShort)?;
    dst.copy_from_slice(value);
    Ok(())
}
