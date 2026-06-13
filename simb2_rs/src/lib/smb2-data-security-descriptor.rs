//! Security descriptor encoders/decoders migrated from `lib/smb2-data-security-descriptor.c`.

use core::fmt;

/// Number of identifier-authority bytes carried by an SMB2 SID.
pub const SID_ID_AUTH_LEN: usize = 6;

/// Number of bytes used by ACE object-type GUID fields in the legacy C layout.
pub const SMB2_OBJECT_TYPE_SIZE: usize = 16;

/// Object ACE flag indicating that an object-type GUID is present on the wire.
pub const SMB2_ACE_OBJECT_TYPE_PRESENT: u32 = 0x0000_0001;

/// Object ACE flag indicating that an inherited-object-type GUID is present on the wire.
pub const SMB2_ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x0000_0002;

/// ACL revision accepted by the legacy decoder for ordinary ACLs.
pub const SMB2_ACL_REVISION: u8 = 0x02;

/// ACL revision accepted by the legacy decoder for directory-service ACLs.
pub const SMB2_ACL_REVISION_DS: u8 = 0x04;

/// SMB2 access-allowed ACE type value.
pub const SMB2_ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;

/// SMB2 access-denied ACE type value.
pub const SMB2_ACCESS_DENIED_ACE_TYPE: u8 = 0x01;

/// SMB2 system-audit ACE type value.
pub const SMB2_SYSTEM_AUDIT_ACE_TYPE: u8 = 0x02;

/// SMB2 access-allowed object ACE type value.
pub const SMB2_ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;

/// SMB2 access-denied object ACE type value.
pub const SMB2_ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;

/// SMB2 system-audit object ACE type value.
pub const SMB2_SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8 = 0x07;

/// SMB2 access-allowed callback ACE type value.
pub const SMB2_ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x09;

/// SMB2 access-denied callback ACE type value.
pub const SMB2_ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 0x10;

/// SMB2 system mandatory-label ACE type value.
pub const SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;

/// SMB2 system resource-attribute ACE type value.
pub const SMB2_SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: u8 = 0x12;

/// SMB2 system scoped-policy-ID ACE type value.
pub const SMB2_SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;

/// Error returned by security descriptor decode skeletons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityDescriptorDecodeError {
    /// The caller provided fewer bytes than the legacy structure header requires.
    BufferTooShort {
        /// Minimum byte count needed by the operation.
        needed: usize,
        /// Actual byte count supplied by the caller.
        actual: usize,
    },
    /// The wire revision does not match the revision accepted by the C decoder.
    UnsupportedRevision {
        /// Name of the structure whose revision was checked.
        structure: &'static str,
        /// Revision value found in the input buffer.
        revision: u8,
    },
    /// The Rust migration has not implemented the full legacy protocol logic yet.
    ProtocolLogicPending(&'static str),
    /// A declared SID, ACE, ACL, or descriptor offset/size is malformed.
    Malformed(&'static str),
}

impl fmt::Display for SecurityDescriptorDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { needed, actual } => {
                write!(f, "buffer too short: need {needed} bytes, got {actual}")
            }
            Self::UnsupportedRevision {
                structure,
                revision,
            } => write!(f, "unsupported {structure} revision {revision}"),
            Self::ProtocolLogicPending(operation) => {
                write!(f, "{operation} protocol logic is not implemented yet")
            }
            Self::Malformed(operation) => write!(f, "malformed {operation}"),
        }
    }
}

impl std::error::Error for SecurityDescriptorDecodeError {}

/// Convenient result type for security descriptor decode skeletons.
pub type DecodeResult<T> = Result<T, SecurityDescriptorDecodeError>;

/// Error returned by security descriptor encode/decode helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityDescriptorCodecError {
    /// Decode failed.
    Decode(SecurityDescriptorDecodeError),
    /// A variable-length field cannot be represented in the SMB2 wire width.
    LengthOutOfRange(&'static str),
    /// A length or offset calculation overflowed.
    LengthOverflow(&'static str),
    /// A typed descriptor contains inconsistent count or size fields.
    Malformed(&'static str),
}

impl fmt::Display for SecurityDescriptorCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(f, "security descriptor decode failed: {error}"),
            Self::LengthOutOfRange(field) => write!(f, "{field} length is out of range"),
            Self::LengthOverflow(field) => write!(f, "{field} length calculation overflowed"),
            Self::Malformed(field) => write!(f, "malformed {field}"),
        }
    }
}

impl std::error::Error for SecurityDescriptorCodecError {}

impl From<SecurityDescriptorDecodeError> for SecurityDescriptorCodecError {
    fn from(error: SecurityDescriptorDecodeError) -> Self {
        Self::Decode(error)
    }
}

/// Convenient result type for security descriptor encode/decode helpers.
pub type CodecResult<T> = Result<T, SecurityDescriptorCodecError>;

/// Rust representation of `struct smb2_sid` from `include/smb2/smb2.h`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2Sid {
    /// SID revision byte preserved from the wire.
    pub revision: u8,
    /// Number of sub-authority values present in [`Self::sub_auth`].
    pub sub_auth_count: u8,
    /// Six-byte identifier authority field.
    pub id_auth: [u8; SID_ID_AUTH_LEN],
    /// Variable-length sub-authority values.
    pub sub_auth: Vec<u32>,
}

impl Smb2Sid {
    /// Creates an empty SID container with all fields set to their neutral values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a SID container from explicit field values.
    #[must_use]
    pub fn from_parts(revision: u8, id_auth: [u8; SID_ID_AUTH_LEN], sub_auth: Vec<u32>) -> Self {
        let sub_auth_count = saturating_u8_len(sub_auth.len());

        Self {
            revision,
            sub_auth_count,
            id_auth,
            sub_auth,
        }
    }
}

/// Rust representation of `struct smb2_ace` from `include/smb2/smb2.h`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2Ace {
    /// Raw ACE type byte.
    pub ace_type: u8,
    /// Raw ACE flags byte.
    pub ace_flags: u8,
    /// ACE size from the wire header.
    pub ace_size: u16,
    /// Access mask used by ACE variants that carry a mask.
    pub mask: u32,
    /// Object ACE flags used by object ACE variants.
    pub flags: u32,
    /// SID decoded from ACE payload variants that carry a SID.
    pub sid: Option<Smb2Sid>,
    /// Object type bytes for object ACE variants.
    pub object_type: [u8; SMB2_OBJECT_TYPE_SIZE],
    /// Inherited object type bytes for object ACE variants.
    pub inherited_object_type: [u8; SMB2_OBJECT_TYPE_SIZE],
    /// Application or attribute data carried by callback/resource ACE variants.
    pub application_data: Vec<u8>,
    /// Raw payload retained for ACE variants that are not yet decoded.
    pub raw_data: Vec<u8>,
}

impl Smb2Ace {
    /// Creates an empty ACE container with all fields set to their neutral values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds an ACE container from the common ACE header fields.
    #[must_use]
    pub fn from_header(ace_type: u8, ace_flags: u8, ace_size: u16) -> Self {
        Self {
            ace_type,
            ace_flags,
            ace_size,
            ..Self::default()
        }
    }
}

/// Rust representation of `struct smb2_acl` from `include/smb2/smb2.h`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2Acl {
    /// ACL revision byte preserved from the wire.
    pub revision: u8,
    /// Number of ACE entries present in [`Self::aces`].
    pub ace_count: u16,
    /// ACE entries decoded from the ACL body.
    pub aces: Vec<Smb2Ace>,
}

impl Smb2Acl {
    /// Creates an empty ACL container with all fields set to their neutral values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds an ACL container from a revision and decoded ACE entries.
    #[must_use]
    pub fn from_aces(revision: u8, aces: Vec<Smb2Ace>) -> Self {
        let ace_count = saturating_u16_len(aces.len());

        Self {
            revision,
            ace_count,
            aces,
        }
    }
}

/// Rust representation of `struct smb2_security_descriptor` from `include/smb2/smb2.h`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2SecurityDescriptor {
    /// Security descriptor revision byte preserved from the wire.
    pub revision: u8,
    /// Security descriptor control flags from the wire header.
    pub control: u16,
    /// Optional owner SID.
    pub owner: Option<Smb2Sid>,
    /// Optional group SID.
    pub group: Option<Smb2Sid>,
    /// Optional discretionary ACL.
    pub dacl: Option<Smb2Acl>,
    /// Optional system ACL.
    pub sacl: Option<Smb2Acl>,
}

impl Smb2SecurityDescriptor {
    /// Creates an empty security descriptor container with all fields set to neutral values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a security descriptor container from the fixed header fields.
    #[must_use]
    pub fn from_header(revision: u8, control: u16) -> Self {
        Self {
            revision,
            control,
            ..Self::default()
        }
    }

    /// Encodes this self-relative security descriptor to SMB2 wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SecurityDescriptorCodecError`] if an offset/length cannot fit in the wire format,
    /// or if child SID/ACL data is malformed.
    pub fn encode(&self) -> CodecResult<Vec<u8>> {
        smb2_encode_security_descriptor(self)
    }
}

/// Decodes a SID corresponding to the C `decode_sid` helper.
///
/// # Errors
///
/// Returns [`SecurityDescriptorDecodeError`] when the buffer is shorter than the SID.
pub fn decode_sid(input: &[u8]) -> DecodeResult<Smb2Sid> {
    require_len(input, 8)?;

    let revision = input[0];
    let sub_auth_count = input[1];
    let sub_auth_len = usize::from(sub_auth_count)
        .checked_mul(4)
        .ok_or(SecurityDescriptorDecodeError::Malformed("sid"))?;
    let sid_len = 8usize
        .checked_add(sub_auth_len)
        .ok_or(SecurityDescriptorDecodeError::Malformed("sid"))?;
    require_len(input, sid_len)?;

    let mut id_auth = [0; SID_ID_AUTH_LEN];
    id_auth.copy_from_slice(slice_at(input, 2, SID_ID_AUTH_LEN)?);
    let mut sub_auth = Vec::with_capacity(usize::from(sub_auth_count));
    for index in 0..usize::from(sub_auth_count) {
        sub_auth.push(read_u32_le(input, 8 + index * 4)?);
    }

    Ok(Smb2Sid {
        revision,
        sub_auth_count,
        id_auth,
        sub_auth,
    })
}

/// Decodes an ACE corresponding to the C `decode_ace` helper.
///
/// # Errors
///
/// Returns [`SecurityDescriptorDecodeError`] when the ACE header or variant payload is malformed.
pub fn decode_ace(input: &[u8]) -> DecodeResult<Smb2Ace> {
    require_len(input, 4)?;
    let ace_type = input[0];
    let ace_flags = input[1];
    let ace_size = read_u16_le(input, 2)?;
    if ace_size < 4 {
        return Err(SecurityDescriptorDecodeError::Malformed("ace"));
    }
    let ace_len = usize::from(ace_size);
    require_len(input, ace_len)?;
    let payload = slice_at(input, 4, ace_len - 4)?;
    let mut ace = Smb2Ace::from_header(ace_type, ace_flags, ace_size);

    match ace_type {
        SMB2_ACCESS_ALLOWED_ACE_TYPE
        | SMB2_ACCESS_DENIED_ACE_TYPE
        | SMB2_SYSTEM_AUDIT_ACE_TYPE
        | SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE
        | SMB2_SYSTEM_SCOPED_POLICY_ID_ACE_TYPE => {
            require_len(payload, 4)?;
            ace.mask = read_u32_le(payload, 0)?;
            ace.sid = Some(decode_sid(slice_at(payload, 4, payload.len() - 4)?)?);
        }
        SMB2_ACCESS_ALLOWED_OBJECT_ACE_TYPE
        | SMB2_ACCESS_DENIED_OBJECT_ACE_TYPE
        | SMB2_SYSTEM_AUDIT_OBJECT_ACE_TYPE => {
            require_len(payload, 8)?;
            ace.mask = read_u32_le(payload, 0)?;
            ace.flags = read_u32_le(payload, 4)?;

            let mut offset = 8usize;
            if ace.flags & SMB2_ACE_OBJECT_TYPE_PRESENT != 0 {
                ace.object_type
                    .copy_from_slice(slice_at(payload, offset, SMB2_OBJECT_TYPE_SIZE)?);
                offset = offset
                    .checked_add(SMB2_OBJECT_TYPE_SIZE)
                    .ok_or(SecurityDescriptorDecodeError::Malformed("ace"))?;
            }
            if ace.flags & SMB2_ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                ace.inherited_object_type.copy_from_slice(slice_at(
                    payload,
                    offset,
                    SMB2_OBJECT_TYPE_SIZE,
                )?);
                offset = offset
                    .checked_add(SMB2_OBJECT_TYPE_SIZE)
                    .ok_or(SecurityDescriptorDecodeError::Malformed("ace"))?;
            }
            ace.sid = Some(decode_sid(slice_at(
                payload,
                offset,
                payload.len() - offset,
            )?)?);
        }
        SMB2_ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        | SMB2_ACCESS_DENIED_CALLBACK_ACE_TYPE
        | SMB2_SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => {
            require_len(payload, 4)?;
            ace.mask = read_u32_le(payload, 0)?;
            let sid_start = 4;
            let sid = decode_sid(slice_at(payload, sid_start, payload.len() - sid_start)?)?;
            let sid_len = 8usize
                .checked_add(usize::from(sid.sub_auth_count) * 4)
                .ok_or(SecurityDescriptorDecodeError::Malformed("sid"))?;
            let app_start = sid_start
                .checked_add(sid_len)
                .ok_or(SecurityDescriptorDecodeError::Malformed("ace"))?;
            ace.sid = Some(sid);
            if app_start < payload.len() {
                ace.application_data = payload[app_start..].to_vec();
            }
        }
        _ => {
            ace.raw_data = payload.to_vec();
        }
    }

    Ok(ace)
}

/// Decodes an ACL corresponding to the C `decode_acl` helper.
///
/// # Errors
///
/// Returns [`SecurityDescriptorDecodeError`] when the ACL header or ACE list is malformed.
pub fn decode_acl(input: &[u8]) -> DecodeResult<Smb2Acl> {
    require_len(input, 8)?;

    let revision = input[0];
    let acl_size = usize::from(read_u16_le(input, 2)?);
    let ace_count = read_u16_le(input, 4)?;
    require_len(input, acl_size)?;

    let mut aces = Vec::with_capacity(usize::from(ace_count));
    let mut offset = 8usize;
    for _ in 0..usize::from(ace_count) {
        if offset >= acl_size {
            return Err(SecurityDescriptorDecodeError::Malformed("acl"));
        }
        let ace = decode_ace(slice_at(input, offset, acl_size - offset)?)?;
        let step = usize::from(ace.ace_size);
        offset = offset
            .checked_add(step)
            .ok_or(SecurityDescriptorDecodeError::Malformed("acl"))?;
        if offset > acl_size {
            return Err(SecurityDescriptorDecodeError::Malformed("acl"));
        }
        aces.push(ace);
    }

    Ok(Smb2Acl {
        revision,
        ace_count,
        aces,
    })
}

/// Decodes a self-relative security descriptor corresponding to C `smb2_decode_security_descriptor`.
///
/// # Errors
///
/// Returns [`SecurityDescriptorDecodeError`] when the buffer is shorter than the fixed security
/// descriptor header, or when a referenced SID/ACL is malformed.
pub fn smb2_decode_security_descriptor(input: &[u8]) -> DecodeResult<Smb2SecurityDescriptor> {
    require_len(input, 20)?;

    let revision = input[0];
    let control = read_u16_le(input, 2)?;
    let owner_offset = read_u32_le(input, 4)? as usize;
    let group_offset = read_u32_le(input, 8)? as usize;
    let sacl_offset = read_u32_le(input, 12)? as usize;
    let dacl_offset = read_u32_le(input, 16)? as usize;

    Ok(Smb2SecurityDescriptor {
        revision,
        control,
        owner: decode_optional_sid(input, owner_offset)?,
        group: decode_optional_sid(input, group_offset)?,
        dacl: decode_optional_acl(input, dacl_offset)?,
        sacl: decode_optional_acl(input, sacl_offset)?,
    })
}

/// Encodes a self-relative security descriptor corresponding to C security descriptor wire layout.
///
/// # Errors
///
/// Returns [`SecurityDescriptorCodecError`] if an offset/length cannot fit in the wire format, or
/// if any nested SID, ACE, or ACL is malformed.
pub fn smb2_encode_security_descriptor(input: &Smb2SecurityDescriptor) -> CodecResult<Vec<u8>> {
    let mut sections = Vec::new();
    let owner = encode_optional_sid(input.owner.as_ref())?;
    let group = encode_optional_sid(input.group.as_ref())?;
    let sacl = encode_optional_acl(input.sacl.as_ref())?;
    let dacl = encode_optional_acl(input.dacl.as_ref())?;

    let mut cursor = 20usize;
    let owner_offset = append_section(&mut sections, &mut cursor, owner)?;
    let group_offset = append_section(&mut sections, &mut cursor, group)?;
    let sacl_offset = append_section(&mut sections, &mut cursor, sacl)?;
    let dacl_offset = append_section(&mut sections, &mut cursor, dacl)?;

    let mut out = vec![0; cursor];
    write_u8_codec(&mut out, 0, input.revision)?;
    write_u8_codec(&mut out, 1, 0)?;
    write_u16_le_codec(&mut out, 2, input.control)?;
    write_u32_le_codec(&mut out, 4, usize_to_u32(owner_offset, "owner offset")?)?;
    write_u32_le_codec(&mut out, 8, usize_to_u32(group_offset, "group offset")?)?;
    write_u32_le_codec(&mut out, 12, usize_to_u32(sacl_offset, "sacl offset")?)?;
    write_u32_le_codec(&mut out, 16, usize_to_u32(dacl_offset, "dacl offset")?)?;

    for (offset, bytes) in sections {
        write_bytes_codec(&mut out, offset, &bytes)?;
    }

    Ok(out)
}

fn encode_optional_sid(input: Option<&Smb2Sid>) -> CodecResult<Option<Vec<u8>>> {
    input.map(encode_sid).transpose()
}

fn encode_optional_acl(input: Option<&Smb2Acl>) -> CodecResult<Option<Vec<u8>>> {
    input.map(encode_acl).transpose()
}

fn append_section(
    sections: &mut Vec<(usize, Vec<u8>)>,
    cursor: &mut usize,
    section: Option<Vec<u8>>,
) -> CodecResult<usize> {
    let Some(bytes) = section else {
        return Ok(0);
    };
    let offset = *cursor;
    *cursor = cursor
        .checked_add(bytes.len())
        .ok_or(SecurityDescriptorCodecError::LengthOverflow("descriptor"))?;
    sections.push((offset, bytes));
    Ok(offset)
}

fn encode_sid(input: &Smb2Sid) -> CodecResult<Vec<u8>> {
    if usize::from(input.sub_auth_count) != input.sub_auth.len() {
        return Err(SecurityDescriptorCodecError::Malformed("sid"));
    }
    let sub_auth_bytes = input
        .sub_auth
        .len()
        .checked_mul(4)
        .ok_or(SecurityDescriptorCodecError::LengthOverflow("sid"))?;
    let sid_len = 8usize
        .checked_add(sub_auth_bytes)
        .ok_or(SecurityDescriptorCodecError::LengthOverflow("sid"))?;
    let mut out = vec![0; sid_len];
    write_u8_codec(&mut out, 0, input.revision)?;
    write_u8_codec(&mut out, 1, input.sub_auth_count)?;
    write_bytes_codec(&mut out, 2, &input.id_auth)?;
    for (index, value) in input.sub_auth.iter().enumerate() {
        write_u32_le_codec(&mut out, 8 + index * 4, *value)?;
    }
    Ok(out)
}

fn encode_acl(input: &Smb2Acl) -> CodecResult<Vec<u8>> {
    if usize::from(input.ace_count) != input.aces.len() {
        return Err(SecurityDescriptorCodecError::Malformed("acl"));
    }
    let mut ace_bytes = Vec::with_capacity(input.aces.len());
    let mut acl_size = 8usize;
    for ace in &input.aces {
        let bytes = encode_ace(ace)?;
        acl_size = acl_size
            .checked_add(bytes.len())
            .ok_or(SecurityDescriptorCodecError::LengthOverflow("acl"))?;
        ace_bytes.push(bytes);
    }
    let mut out = vec![0; acl_size];
    write_u8_codec(&mut out, 0, input.revision)?;
    write_u8_codec(&mut out, 1, 0)?;
    write_u16_le_codec(&mut out, 2, usize_to_u16(acl_size, "acl size")?)?;
    write_u16_le_codec(&mut out, 4, input.ace_count)?;
    write_u16_le_codec(&mut out, 6, 0)?;
    let mut offset = 8usize;
    for bytes in ace_bytes {
        write_bytes_codec(&mut out, offset, &bytes)?;
        offset = offset
            .checked_add(bytes.len())
            .ok_or(SecurityDescriptorCodecError::LengthOverflow("acl"))?;
    }
    Ok(out)
}

fn encode_ace(input: &Smb2Ace) -> CodecResult<Vec<u8>> {
    let payload = encode_ace_payload(input)?;
    let ace_size = 4usize
        .checked_add(payload.len())
        .ok_or(SecurityDescriptorCodecError::LengthOverflow("ace"))?;
    if input.ace_size != 0 && usize::from(input.ace_size) != ace_size {
        return Err(SecurityDescriptorCodecError::Malformed("ace"));
    }
    let mut out = vec![0; ace_size];
    write_u8_codec(&mut out, 0, input.ace_type)?;
    write_u8_codec(&mut out, 1, input.ace_flags)?;
    write_u16_le_codec(&mut out, 2, usize_to_u16(ace_size, "ace size")?)?;
    write_bytes_codec(&mut out, 4, &payload)?;
    Ok(out)
}

fn encode_ace_payload(input: &Smb2Ace) -> CodecResult<Vec<u8>> {
    match input.ace_type {
        SMB2_ACCESS_ALLOWED_ACE_TYPE
        | SMB2_ACCESS_DENIED_ACE_TYPE
        | SMB2_SYSTEM_AUDIT_ACE_TYPE
        | SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE
        | SMB2_SYSTEM_SCOPED_POLICY_ID_ACE_TYPE => {
            let sid = input
                .sid
                .as_ref()
                .ok_or(SecurityDescriptorCodecError::Malformed("ace sid"))?;
            let sid_bytes = encode_sid(sid)?;
            let mut out = vec![0; 4 + sid_bytes.len()];
            write_u32_le_codec(&mut out, 0, input.mask)?;
            write_bytes_codec(&mut out, 4, &sid_bytes)?;
            Ok(out)
        }
        SMB2_ACCESS_ALLOWED_OBJECT_ACE_TYPE
        | SMB2_ACCESS_DENIED_OBJECT_ACE_TYPE
        | SMB2_SYSTEM_AUDIT_OBJECT_ACE_TYPE => {
            let sid = input
                .sid
                .as_ref()
                .ok_or(SecurityDescriptorCodecError::Malformed("ace sid"))?;
            let sid_bytes = encode_sid(sid)?;
            let mut payload_len = 8usize
                .checked_add(sid_bytes.len())
                .ok_or(SecurityDescriptorCodecError::LengthOverflow("ace"))?;
            if input.flags & SMB2_ACE_OBJECT_TYPE_PRESENT != 0 {
                payload_len = payload_len
                    .checked_add(SMB2_OBJECT_TYPE_SIZE)
                    .ok_or(SecurityDescriptorCodecError::LengthOverflow("ace"))?;
            }
            if input.flags & SMB2_ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                payload_len = payload_len
                    .checked_add(SMB2_OBJECT_TYPE_SIZE)
                    .ok_or(SecurityDescriptorCodecError::LengthOverflow("ace"))?;
            }

            let mut out = vec![0; payload_len];
            write_u32_le_codec(&mut out, 0, input.mask)?;
            write_u32_le_codec(&mut out, 4, input.flags)?;
            let mut offset = 8usize;
            if input.flags & SMB2_ACE_OBJECT_TYPE_PRESENT != 0 {
                write_bytes_codec(&mut out, offset, &input.object_type)?;
                offset = offset
                    .checked_add(SMB2_OBJECT_TYPE_SIZE)
                    .ok_or(SecurityDescriptorCodecError::LengthOverflow("ace"))?;
            }
            if input.flags & SMB2_ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                write_bytes_codec(&mut out, offset, &input.inherited_object_type)?;
                offset = offset
                    .checked_add(SMB2_OBJECT_TYPE_SIZE)
                    .ok_or(SecurityDescriptorCodecError::LengthOverflow("ace"))?;
            }
            write_bytes_codec(&mut out, offset, &sid_bytes)?;
            Ok(out)
        }
        SMB2_ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        | SMB2_ACCESS_DENIED_CALLBACK_ACE_TYPE
        | SMB2_SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => {
            let sid = input
                .sid
                .as_ref()
                .ok_or(SecurityDescriptorCodecError::Malformed("ace sid"))?;
            let sid_bytes = encode_sid(sid)?;
            let base_len = 4usize
                .checked_add(sid_bytes.len())
                .and_then(|len| len.checked_add(input.application_data.len()))
                .ok_or(SecurityDescriptorCodecError::LengthOverflow("ace"))?;
            let mut out = vec![0; base_len];
            write_u32_le_codec(&mut out, 0, input.mask)?;
            write_bytes_codec(&mut out, 4, &sid_bytes)?;
            write_bytes_codec(&mut out, 4 + sid_bytes.len(), &input.application_data)?;
            Ok(out)
        }
        _ => Ok(input.raw_data.clone()),
    }
}

fn decode_optional_sid(input: &[u8], offset: usize) -> DecodeResult<Option<Smb2Sid>> {
    if offset == 0 {
        return Ok(None);
    }
    if offset.checked_add(8).is_none_or(|end| end > input.len()) {
        return Ok(None);
    }
    Ok(Some(decode_sid(&input[offset..])?))
}

fn decode_optional_acl(input: &[u8], offset: usize) -> DecodeResult<Option<Smb2Acl>> {
    if offset == 0 {
        return Ok(None);
    }
    if offset.checked_add(8).is_none_or(|end| end > input.len()) {
        return Ok(None);
    }
    Ok(Some(decode_acl(&input[offset..])?))
}

fn require_len(input: &[u8], needed: usize) -> DecodeResult<()> {
    if input.len() < needed {
        return Err(SecurityDescriptorDecodeError::BufferTooShort {
            needed,
            actual: input.len(),
        });
    }

    Ok(())
}

fn slice_at(input: &[u8], offset: usize, len: usize) -> DecodeResult<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(SecurityDescriptorDecodeError::Malformed("offset"))?;
    input
        .get(offset..end)
        .ok_or(SecurityDescriptorDecodeError::BufferTooShort {
            needed: end,
            actual: input.len(),
        })
}

fn read_u16_le(input: &[u8], offset: usize) -> DecodeResult<u16> {
    let bytes = slice_at(input, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(input: &[u8], offset: usize) -> DecodeResult<u32> {
    let bytes = slice_at(input, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u8_codec(input: &mut [u8], offset: usize, value: u8) -> CodecResult<()> {
    let Some(slot) = input.get_mut(offset) else {
        return Err(SecurityDescriptorCodecError::Malformed("offset"));
    };
    *slot = value;
    Ok(())
}

fn write_u16_le_codec(input: &mut [u8], offset: usize, value: u16) -> CodecResult<()> {
    write_bytes_codec(input, offset, &value.to_le_bytes())
}

fn write_u32_le_codec(input: &mut [u8], offset: usize, value: u32) -> CodecResult<()> {
    write_bytes_codec(input, offset, &value.to_le_bytes())
}

fn write_bytes_codec(input: &mut [u8], offset: usize, value: &[u8]) -> CodecResult<()> {
    let end = offset
        .checked_add(value.len())
        .ok_or(SecurityDescriptorCodecError::LengthOverflow("offset"))?;
    let Some(dst) = input.get_mut(offset..end) else {
        return Err(SecurityDescriptorCodecError::Malformed("offset"));
    };
    dst.copy_from_slice(value);
    Ok(())
}

fn usize_to_u16(value: usize, field: &'static str) -> CodecResult<u16> {
    u16::try_from(value).map_err(|_| SecurityDescriptorCodecError::LengthOutOfRange(field))
}

fn usize_to_u32(value: usize, field: &'static str) -> CodecResult<u32> {
    u32::try_from(value).map_err(|_| SecurityDescriptorCodecError::LengthOutOfRange(field))
}

fn saturating_u8_len(len: usize) -> u8 {
    if len > usize::from(u8::MAX) {
        u8::MAX
    } else {
        len as u8
    }
}

fn saturating_u16_len(len: usize) -> u16 {
    if len > usize::from(u16::MAX) {
        u16::MAX
    } else {
        len as u16
    }
}
