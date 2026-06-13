//! NEGOTIATE command pack/unpack skeleton migrated from `lib/smb2-cmd-negotiate.c`.

const SMB2_HEADER_SIZE: usize = 64;
const SMB2_GUID_SIZE: usize = 16;
const SMB2_SALT_SIZE: usize = 32;
const SMB2_NEGOTIATE_REQUEST_SIZE: usize = 36;
const SMB2_NEGOTIATE_REPLY_SIZE: usize = 65;
const SMB2_NEGOTIATE_REPLY_FIXED_SIZE: usize = SMB2_NEGOTIATE_REPLY_SIZE & 0xfffe;
const SMB2_NEGOTIATE_MAX_DIALECTS: usize = 16;
const SMB2_VERSION_ANY: u16 = 0x0000;
const SMB2_VERSION_ANY3: u16 = 0x0300;
const SMB2_VERSION_0311: u16 = 0x0311;
const SMB2_PREAUTH_INTEGRITY_CAP: u16 = 0x0001;
const SMB2_ENCRYPTION_CAP: u16 = 0x0002;
const SMB2_COMPRESSION_CAP: u16 = 0x0003;
const SMB2_NETNAME_NEGOTIATE_CONTEXT_ID: u16 = 0x0005;
const SMB2_TRANSPORT_CAP: u16 = 0x0006;
const SMB2_RDMA_TRANSFORM_CAP: u16 = 0x0007;
const SMB2_SIGNING_CAP: u16 = 0x0008;
const SMB2_CONTEXTTYPE_RESERVED: u16 = 0x0100;
const SMB2_HASH_SHA_512: u16 = 0x0001;
const SMB2_ENCRYPTION_AES_128_CCM: u16 = 0x0001;

/// Errors reported by the NEGOTIATE migration skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiateError {
    /// The supplied buffer is shorter than the field being read or written.
    BufferTooShort,
    /// The fixed structure size does not match the SMB2 NEGOTIATE layout.
    UnexpectedStructureSize,
    /// The security buffer points outside the received PDU bytes.
    SecurityBufferOutOfBounds,
    /// The security buffer overlaps with the fixed NEGOTIATE header.
    SecurityBufferOverlapsHeader,
    /// A negotiate context advertises a type not handled by the skeleton.
    UnknownNegotiateContext(u16),
    /// A calculated offset does not fit in the destination field.
    OffsetOutOfRange,
}

/// Result alias used by NEGOTIATE skeleton helpers.
pub type NegotiateResult<T> = Result<T, NegotiateError>;

/// SMB2 dialect revision advertised during negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialectRevision(pub u16);

impl DialectRevision {
    /// Returns true when SMB 3.1.1 negotiate contexts are expected.
    #[must_use]
    pub const fn supports_negotiate_contexts(self) -> bool {
        self.0 == SMB2_VERSION_ANY || self.0 == SMB2_VERSION_ANY3 || self.0 == SMB2_VERSION_0311
    }
}

/// NEGOTIATE context type values used by SMB 3.1.1 negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiateContextType {
    /// Preauth integrity capability context.
    PreauthIntegrity,
    /// Encryption capability context.
    Encryption,
    /// Compression capability context.
    Compression,
    /// Netname negotiate context.
    Netname,
    /// Transport capability context.
    Transport,
    /// RDMA transform capability context.
    RdmaTransform,
    /// Signing capability context.
    Signing,
    /// Reserved context type used by some servers for extensions.
    Reserved,
}

impl NegotiateContextType {
    /// Converts a raw SMB2 negotiate context type into the skeleton enum.
    #[must_use]
    pub const fn from_raw(value: u16) -> Option<Self> {
        match value {
            SMB2_PREAUTH_INTEGRITY_CAP => Some(Self::PreauthIntegrity),
            SMB2_ENCRYPTION_CAP => Some(Self::Encryption),
            SMB2_COMPRESSION_CAP => Some(Self::Compression),
            SMB2_NETNAME_NEGOTIATE_CONTEXT_ID => Some(Self::Netname),
            SMB2_TRANSPORT_CAP => Some(Self::Transport),
            SMB2_RDMA_TRANSFORM_CAP => Some(Self::RdmaTransform),
            SMB2_SIGNING_CAP => Some(Self::Signing),
            SMB2_CONTEXTTYPE_RESERVED => Some(Self::Reserved),
            _ => None,
        }
    }

    /// Returns the raw SMB2 negotiate context type value.
    #[must_use]
    pub const fn as_raw(self) -> u16 {
        match self {
            Self::PreauthIntegrity => SMB2_PREAUTH_INTEGRITY_CAP,
            Self::Encryption => SMB2_ENCRYPTION_CAP,
            Self::Compression => SMB2_COMPRESSION_CAP,
            Self::Netname => SMB2_NETNAME_NEGOTIATE_CONTEXT_ID,
            Self::Transport => SMB2_TRANSPORT_CAP,
            Self::RdmaTransform => SMB2_RDMA_TRANSFORM_CAP,
            Self::Signing => SMB2_SIGNING_CAP,
            Self::Reserved => SMB2_CONTEXTTYPE_RESERVED,
        }
    }
}

/// Rust-owned representation of a NEGOTIATE context record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateContext {
    /// Context discriminator.
    pub context_type: NegotiateContextType,
    /// Context payload bytes following the 8-byte context header.
    pub data: Vec<u8>,
}

/// Rust-owned equivalent of `struct smb2_negotiate_request` fields used here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2NegotiateRequest {
    /// Security mode flags requested by the client.
    pub security_mode: u16,
    /// Capability flags requested by the client.
    pub capabilities: u32,
    /// Client GUID copied into the request fixed part.
    pub client_guid: [u8; SMB2_GUID_SIZE],
    /// Dialects advertised by the client.
    pub dialects: Vec<DialectRevision>,
    /// Offset of SMB 3.1.1 negotiate contexts from the SMB2 header.
    pub negotiate_context_offset: u32,
    /// Parsed or pending SMB 3.1.1 negotiate contexts.
    pub negotiate_contexts: Vec<NegotiateContext>,
}

impl Smb2NegotiateRequest {
    /// Creates a request skeleton from the fields encoded by the C implementation.
    #[must_use]
    pub fn new(
        security_mode: u16,
        capabilities: u32,
        client_guid: [u8; SMB2_GUID_SIZE],
        dialects: Vec<DialectRevision>,
    ) -> Self {
        Self {
            security_mode,
            capabilities,
            client_guid,
            dialects,
            negotiate_context_offset: 0,
            negotiate_contexts: Vec::new(),
        }
    }

    /// Returns whether the request advertises dialect `0x0311`.
    #[must_use]
    pub fn has_smb_0311(&self) -> bool {
        self.dialects
            .iter()
            .take(SMB2_NEGOTIATE_MAX_DIALECTS)
            .any(|dialect| dialect.0 == SMB2_VERSION_0311)
    }
}

/// Rust-owned equivalent of `struct smb2_negotiate_reply` fields used here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2NegotiateReply {
    /// Security mode flags selected by the server.
    pub security_mode: u16,
    /// Dialect selected by the server.
    pub dialect_revision: DialectRevision,
    /// Server GUID copied from the reply fixed part.
    pub server_guid: [u8; SMB2_GUID_SIZE],
    /// Capability flags selected by the server.
    pub capabilities: u32,
    /// Maximum transaction size.
    pub max_transact_size: u32,
    /// Maximum read size.
    pub max_read_size: u32,
    /// Maximum write size.
    pub max_write_size: u32,
    /// Server system time in SMB wire format.
    pub system_time: u64,
    /// Server start time in SMB wire format.
    pub server_start_time: u64,
    /// Security buffer offset from the SMB2 header.
    pub security_buffer_offset: u16,
    /// Security buffer bytes.
    pub security_buffer: Vec<u8>,
    /// Offset of SMB 3.1.1 negotiate contexts from the SMB2 header.
    pub negotiate_context_offset: u32,
    /// Parsed or pending SMB 3.1.1 negotiate contexts.
    pub negotiate_contexts: Vec<NegotiateContext>,
    /// Encryption cipher selected from an encryption context.
    pub cipher: Option<u16>,
}

impl Smb2NegotiateReply {
    /// Creates an empty reply skeleton for fixed-part parsing.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            security_mode: 0,
            dialect_revision: DialectRevision(0),
            server_guid: [0; SMB2_GUID_SIZE],
            capabilities: 0,
            max_transact_size: 0,
            max_read_size: 0,
            max_write_size: 0,
            system_time: 0,
            server_start_time: 0,
            security_buffer_offset: 0,
            security_buffer: Vec::new(),
            negotiate_context_offset: 0,
            negotiate_contexts: Vec::new(),
            cipher: None,
        }
    }
}

/// Outgoing PDU skeleton returned by NEGOTIATE command builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatePdu {
    /// SMB2 command id for NEGOTIATE.
    pub command: u16,
    /// Fixed and variable output buffers in the order the C iovectors are appended.
    pub output_vectors: Vec<Vec<u8>>,
}

impl NegotiatePdu {
    /// Creates a NEGOTIATE PDU skeleton from pre-encoded vectors.
    #[must_use]
    pub fn new(output_vectors: Vec<Vec<u8>>) -> Self {
        Self {
            command: 0,
            output_vectors,
        }
    }
}

/// Encodes the preauth integrity negotiate context skeleton.
#[must_use]
pub fn smb2_encode_preauth_context(salt: &[u8; SMB2_SALT_SIZE]) -> Vec<u8> {
    let data_len = 38usize;
    let mut buf = vec![0; 8 + pad_to_64bit(data_len)];
    write_u16_le(&mut buf, 0, SMB2_PREAUTH_INTEGRITY_CAP);
    write_u16_le(&mut buf, 2, data_len as u16);
    write_u16_le(&mut buf, 8, 1);
    write_u16_le(&mut buf, 10, SMB2_SALT_SIZE as u16);
    write_u16_le(&mut buf, 12, SMB2_HASH_SHA_512);
    buf[14..14 + SMB2_SALT_SIZE].copy_from_slice(salt);
    buf
}

/// Encodes the encryption negotiate context skeleton.
#[must_use]
pub fn smb2_encode_encryption_context() -> Vec<u8> {
    let data_len = pad_to_64bit(4);
    let mut buf = vec![0; pad_to_64bit(8 + data_len)];
    write_u16_le(&mut buf, 0, SMB2_ENCRYPTION_CAP);
    write_u16_le(&mut buf, 2, data_len as u16);
    write_u16_le(&mut buf, 8, 1);
    write_u16_le(&mut buf, 10, SMB2_ENCRYPTION_AES_128_CCM);
    buf
}

/// Builds a NEGOTIATE request PDU skeleton.
///
/// # Errors
///
/// Returns [`NegotiateError::OffsetOutOfRange`] if the calculated context offset
/// cannot be represented in the SMB2 wire field.
pub fn smb2_cmd_negotiate_async(
    req: &mut Smb2NegotiateRequest,
    dialect: DialectRevision,
    salt: &[u8; SMB2_SALT_SIZE],
) -> NegotiateResult<NegotiatePdu> {
    let mut fixed_len = pad_to_32bit(
        SMB2_NEGOTIATE_REQUEST_SIZE + req.dialects.len() * core::mem::size_of::<u16>(),
    );
    if dialect.supports_negotiate_contexts() && fixed_len & 0x04 != 0 {
        fixed_len += 4;
    }

    let mut fixed = vec![0; fixed_len];
    let mut output_vectors = Vec::new();
    if dialect.supports_negotiate_contexts() {
        req.negotiate_context_offset = checked_wire_offset(fixed_len)?;
        output_vectors.push(smb2_encode_preauth_context(salt));
        output_vectors.push(smb2_encode_encryption_context());
    }

    write_u16_le(&mut fixed, 0, SMB2_NEGOTIATE_REQUEST_SIZE as u16);
    write_u16_le(&mut fixed, 2, req.dialects.len() as u16);
    write_u16_le(&mut fixed, 4, req.security_mode);
    write_u32_le(&mut fixed, 8, req.capabilities);
    fixed[12..12 + SMB2_GUID_SIZE].copy_from_slice(&req.client_guid);
    write_u32_le(&mut fixed, 28, req.negotiate_context_offset);
    write_u16_le(&mut fixed, 32, output_vectors.len() as u16);
    for (index, dialect) in req.dialects.iter().enumerate() {
        write_u16_le(
            &mut fixed,
            36 + index * core::mem::size_of::<u16>(),
            dialect.0,
        );
    }

    output_vectors.insert(0, fixed);
    Ok(NegotiatePdu::new(output_vectors))
}

/// Builds a NEGOTIATE reply PDU skeleton.
///
/// # Errors
///
/// Returns [`NegotiateError::OffsetOutOfRange`] if a calculated offset cannot be
/// represented in the SMB2 wire field.
pub fn smb2_cmd_negotiate_reply_async(
    rep: &mut Smb2NegotiateReply,
    salt: &[u8; SMB2_SALT_SIZE],
) -> NegotiateResult<NegotiatePdu> {
    let mut fixed_len = pad_to_32bit(SMB2_NEGOTIATE_REPLY_FIXED_SIZE);
    if rep.dialect_revision.supports_negotiate_contexts() && fixed_len & 0x04 != 0 {
        fixed_len += 4;
    }

    let mut fixed = vec![0; fixed_len];
    let mut output_vectors = Vec::new();
    let security_len = pad_to_64bit(rep.security_buffer.len());
    if !rep.security_buffer.is_empty() {
        let mut security = vec![0; security_len];
        security[..rep.security_buffer.len()].copy_from_slice(&rep.security_buffer);
        output_vectors.push(security);
    }

    if rep.dialect_revision.supports_negotiate_contexts() {
        output_vectors.push(smb2_encode_preauth_context(salt));
        output_vectors.push(smb2_encode_encryption_context());
    }

    rep.security_buffer_offset = checked_wire_offset(fixed_len)? as u16;
    rep.negotiate_context_offset = checked_wire_offset(fixed_len + security_len)?;
    write_u16_le(&mut fixed, 0, SMB2_NEGOTIATE_REPLY_SIZE as u16);
    write_u16_le(&mut fixed, 2, rep.security_mode);
    write_u16_le(&mut fixed, 4, rep.dialect_revision.0);
    write_u16_le(&mut fixed, 6, rep.negotiate_contexts.len() as u16);
    fixed[8..8 + SMB2_GUID_SIZE].copy_from_slice(&rep.server_guid);
    write_u32_le(&mut fixed, 24, rep.capabilities);
    write_u32_le(&mut fixed, 28, rep.max_transact_size);
    write_u32_le(&mut fixed, 32, rep.max_read_size);
    write_u32_le(&mut fixed, 36, rep.max_write_size);
    write_u64_le(&mut fixed, 40, rep.system_time);
    write_u64_le(&mut fixed, 48, rep.server_start_time);
    write_u16_le(&mut fixed, 56, rep.security_buffer_offset);
    write_u16_le(&mut fixed, 58, rep.security_buffer.len() as u16);
    write_u32_le(&mut fixed, 60, rep.negotiate_context_offset);

    output_vectors.insert(0, fixed);
    Ok(NegotiatePdu::new(output_vectors))
}

/// Parses the fixed NEGOTIATE reply fields and returns the expected variable length.
///
/// # Errors
///
/// Returns an error when the fixed buffer is malformed or references invalid ranges.
pub fn smb2_process_negotiate_fixed(
    fixed: &[u8],
    spl: usize,
) -> NegotiateResult<(Smb2NegotiateReply, usize)> {
    if fixed.len() != SMB2_NEGOTIATE_REPLY_FIXED_SIZE {
        return Err(NegotiateError::UnexpectedStructureSize);
    }
    let struct_size = read_u16_le(fixed, 0)?;
    if struct_size != SMB2_NEGOTIATE_REPLY_SIZE as u16 {
        return Err(NegotiateError::UnexpectedStructureSize);
    }

    let security_buffer_offset = read_u16_le(fixed, 56)?;
    let security_buffer_length = read_u16_le(fixed, 58)?;
    if security_buffer_length != 0
        && usize::from(security_buffer_offset) + usize::from(security_buffer_length) > spl
    {
        return Err(NegotiateError::SecurityBufferOutOfBounds);
    }
    if security_buffer_length != 0
        && usize::from(security_buffer_offset) < SMB2_HEADER_SIZE + SMB2_NEGOTIATE_REPLY_FIXED_SIZE
    {
        return Err(NegotiateError::SecurityBufferOverlapsHeader);
    }

    let dialect_revision = DialectRevision(read_u16_le(fixed, 4)?);
    let variable_len = if security_buffer_length == 0 {
        0
    } else if dialect_revision.0 >= SMB2_VERSION_0311 {
        spl.saturating_sub(SMB2_HEADER_SIZE + SMB2_NEGOTIATE_REPLY_FIXED_SIZE)
    } else {
        usize::from(security_buffer_offset) - SMB2_HEADER_SIZE - SMB2_NEGOTIATE_REPLY_FIXED_SIZE
            + usize::from(security_buffer_length)
    };

    Ok((
        Smb2NegotiateReply {
            security_mode: read_u16_le(fixed, 2)?,
            dialect_revision,
            server_guid: read_guid(fixed, 8)?,
            capabilities: read_u32_le(fixed, 24)?,
            max_transact_size: read_u32_le(fixed, 28)?,
            max_read_size: read_u32_le(fixed, 32)?,
            max_write_size: read_u32_le(fixed, 36)?,
            system_time: read_u64_le(fixed, 40)?,
            server_start_time: read_u64_le(fixed, 48)?,
            security_buffer_offset,
            security_buffer: Vec::new(),
            negotiate_context_offset: read_u32_le(fixed, 60)?,
            negotiate_contexts: Vec::with_capacity(usize::from(read_u16_le(fixed, 6)?)),
            cipher: None,
        },
        variable_len,
    ))
}

/// Parses the variable NEGOTIATE reply bytes into security buffer and contexts.
///
/// # Errors
///
/// Returns an error when context offsets or records are malformed.
pub fn smb2_process_negotiate_variable(
    rep: &mut Smb2NegotiateReply,
    variable: &[u8],
    context_count: u16,
) -> NegotiateResult<()> {
    let security_offset = usize::from(rep.security_buffer_offset)
        .saturating_sub(SMB2_HEADER_SIZE + SMB2_NEGOTIATE_REPLY_FIXED_SIZE);
    if security_offset < variable.len() {
        rep.security_buffer = variable[security_offset..].to_vec();
    }

    if rep.dialect_revision.0 < SMB2_VERSION_0311 || context_count == 0 {
        return Ok(());
    }

    let context_offset = usize::try_from(rep.negotiate_context_offset)
        .map_err(|_| NegotiateError::OffsetOutOfRange)?
        .saturating_sub(SMB2_HEADER_SIZE + SMB2_NEGOTIATE_REPLY_FIXED_SIZE);
    parse_negotiate_contexts(
        variable,
        context_offset,
        context_count,
        &mut rep.negotiate_contexts,
    )?;
    if let Some(cipher) = rep
        .negotiate_contexts
        .iter()
        .find_map(parse_encryption_context)
    {
        rep.cipher = Some(cipher);
    }
    Ok(())
}

/// Parses the fixed NEGOTIATE request fields and returns the expected variable length.
///
/// # Errors
///
/// Returns an error when the fixed buffer is malformed.
pub fn smb2_process_negotiate_request_fixed(
    fixed: &[u8],
    spl: usize,
) -> NegotiateResult<(Smb2NegotiateRequest, usize)> {
    if fixed.len() < SMB2_NEGOTIATE_REQUEST_SIZE {
        return Err(NegotiateError::UnexpectedStructureSize);
    }
    let struct_size = read_u16_le(fixed, 0)?;
    if struct_size != SMB2_NEGOTIATE_REQUEST_SIZE as u16 {
        return Err(NegotiateError::UnexpectedStructureSize);
    }

    let dialect_count = usize::from(read_u16_le(fixed, 2)?);
    let negotiate_context_count = read_u16_le(fixed, 32)?;
    let variable_len = if negotiate_context_count > 0 {
        spl.saturating_sub(SMB2_HEADER_SIZE + SMB2_NEGOTIATE_REQUEST_SIZE)
    } else {
        dialect_count * core::mem::size_of::<u16>()
    };

    Ok((
        Smb2NegotiateRequest {
            security_mode: read_u16_le(fixed, 4)?,
            capabilities: read_u32_le(fixed, 8)?,
            client_guid: read_guid(fixed, 12)?,
            dialects: Vec::with_capacity(dialect_count.min(SMB2_NEGOTIATE_MAX_DIALECTS)),
            negotiate_context_offset: read_u32_le(fixed, 28)?,
            negotiate_contexts: Vec::with_capacity(usize::from(negotiate_context_count)),
        },
        variable_len,
    ))
}

/// Parses the variable NEGOTIATE request bytes into dialects and contexts.
///
/// # Errors
///
/// Returns an error when dialect or context records are malformed.
pub fn smb2_process_negotiate_request_variable(
    req: &mut Smb2NegotiateRequest,
    variable: &[u8],
    dialect_count: u16,
    context_count: u16,
) -> NegotiateResult<()> {
    for index in 0..usize::from(dialect_count).min(SMB2_NEGOTIATE_MAX_DIALECTS) {
        req.dialects
            .push(DialectRevision(read_u16_le(variable, index * 2)?));
    }

    if context_count == 0 || !req.has_smb_0311() {
        return Ok(());
    }

    let context_offset = usize::try_from(req.negotiate_context_offset)
        .map_err(|_| NegotiateError::OffsetOutOfRange)?
        .saturating_sub(SMB2_HEADER_SIZE + SMB2_NEGOTIATE_REQUEST_SIZE);
    parse_negotiate_contexts(
        variable,
        context_offset,
        context_count,
        &mut req.negotiate_contexts,
    )
}

fn parse_encryption_context(context: &NegotiateContext) -> Option<u16> {
    if context.context_type != NegotiateContextType::Encryption || context.data.len() < 4 {
        return None;
    }
    read_u16_le(&context.data, 2).ok()
}

fn parse_negotiate_contexts(
    input: &[u8],
    mut offset: usize,
    count: u16,
    output: &mut Vec<NegotiateContext>,
) -> NegotiateResult<()> {
    for _ in 0..count {
        if offset > input.len() {
            return Err(NegotiateError::BufferTooShort);
        }
        let raw_type = read_u16_le(input, offset)?;
        let len = usize::from(read_u16_le(input, offset + 2)?);
        let context_type = NegotiateContextType::from_raw(raw_type)
            .ok_or(NegotiateError::UnknownNegotiateContext(raw_type))?;
        let data_start = offset + 8;
        let data_end = data_start + len;
        let data = input
            .get(data_start..data_end)
            .ok_or(NegotiateError::BufferTooShort)?
            .to_vec();
        output.push(NegotiateContext { context_type, data });
        offset += pad_to_64bit(len + 8);
    }
    Ok(())
}

const fn pad_to_32bit(value: usize) -> usize {
    (value + 3) & !3
}

const fn pad_to_64bit(value: usize) -> usize {
    (value + 7) & !7
}

fn checked_wire_offset(payload_offset: usize) -> NegotiateResult<u32> {
    let offset = SMB2_HEADER_SIZE + payload_offset;
    u32::try_from(offset).map_err(|_| NegotiateError::OffsetOutOfRange)
}

fn read_guid(input: &[u8], offset: usize) -> NegotiateResult<[u8; SMB2_GUID_SIZE]> {
    let bytes = input
        .get(offset..offset + SMB2_GUID_SIZE)
        .ok_or(NegotiateError::BufferTooShort)?;
    let mut guid = [0; SMB2_GUID_SIZE];
    guid.copy_from_slice(bytes);
    Ok(guid)
}

fn read_u16_le(input: &[u8], offset: usize) -> NegotiateResult<u16> {
    let bytes = input
        .get(offset..offset + core::mem::size_of::<u16>())
        .ok_or(NegotiateError::BufferTooShort)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(input: &[u8], offset: usize) -> NegotiateResult<u32> {
    let bytes = input
        .get(offset..offset + core::mem::size_of::<u32>())
        .ok_or(NegotiateError::BufferTooShort)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_le(input: &[u8], offset: usize) -> NegotiateResult<u64> {
    let bytes = input
        .get(offset..offset + core::mem::size_of::<u64>())
        .ok_or(NegotiateError::BufferTooShort)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn write_u16_le(output: &mut [u8], offset: usize, value: u16) {
    if let Some(bytes) = output.get_mut(offset..offset + core::mem::size_of::<u16>()) {
        bytes.copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u32_le(output: &mut [u8], offset: usize, value: u32) {
    if let Some(bytes) = output.get_mut(offset..offset + core::mem::size_of::<u32>()) {
        bytes.copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u64_le(output: &mut [u8], offset: usize, value: u64) {
    if let Some(bytes) = output.get_mut(offset..offset + core::mem::size_of::<u64>()) {
        bytes.copy_from_slice(&value.to_le_bytes());
    }
}
