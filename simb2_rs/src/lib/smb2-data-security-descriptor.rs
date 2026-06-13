//! Security descriptor encoders/decoders migrated from `lib/smb2-data-security-descriptor.c`.

use core::fmt;

/// Number of identifier-authority bytes carried by an SMB2 SID.
pub const SID_ID_AUTH_LEN: usize = 6;

/// Number of bytes used by ACE object-type GUID fields in the legacy C layout.
pub const SMB2_OBJECT_TYPE_SIZE: usize = 16;

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
        }
    }
}

impl std::error::Error for SecurityDescriptorDecodeError {}

/// Convenient result type for security descriptor decode skeletons.
pub type DecodeResult<T> = Result<T, SecurityDescriptorDecodeError>;

/// Rust representation of `struct smb2_sid` from `include/smb2/smb2.h`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smb2Sid {
    /// SID revision. The legacy decoder currently accepts revision `1`.
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
    /// ACL revision. The legacy decoder accepts [`SMB2_ACL_REVISION`] and [`SMB2_ACL_REVISION_DS`].
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
    /// Security descriptor revision. The legacy decoder currently accepts revision `1`.
    pub revision: u8,
    /// Security descriptor control flags from the wire header.
    pub control: u16,
    /// Optional owner SID.
    pub owner: Option<Smb2Sid>,
    /// Optional group SID.
    pub group: Option<Smb2Sid>,
    /// Optional discretionary ACL.
    pub dacl: Option<Smb2Acl>,
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
}

/// Creates a SID decode skeleton corresponding to the C `decode_sid` helper.
///
/// The function only validates the fixed SID header and revision. Full sub-authority parsing is
/// intentionally left for the protocol implementation pass.
///
/// # Errors
///
/// Returns [`SecurityDescriptorDecodeError`] when the buffer is shorter than a SID header, when the
/// revision is unsupported, or when full protocol parsing would be required.
pub fn decode_sid(input: &[u8]) -> DecodeResult<Smb2Sid> {
    require_len(input, 8)?;

    let revision = input[0];
    if revision != 1 {
        return Err(SecurityDescriptorDecodeError::UnsupportedRevision {
            structure: "sid",
            revision,
        });
    }

    Err(SecurityDescriptorDecodeError::ProtocolLogicPending(
        "decode_sid",
    ))
}

/// Creates an ACE decode skeleton corresponding to the C `decode_ace` helper.
///
/// The function only validates the fixed ACE header length. Type-specific ACE payload parsing is
/// intentionally left for the protocol implementation pass.
///
/// # Errors
///
/// Returns [`SecurityDescriptorDecodeError`] when the buffer is shorter than an ACE header or when
/// full protocol parsing would be required.
pub fn decode_ace(input: &[u8]) -> DecodeResult<Smb2Ace> {
    require_len(input, 4)?;

    Err(SecurityDescriptorDecodeError::ProtocolLogicPending(
        "decode_ace",
    ))
}

/// Creates an ACL decode skeleton corresponding to the C `decode_acl` helper.
///
/// The function only validates the fixed ACL header and accepted revision values. ACE iteration is
/// intentionally left for the protocol implementation pass.
///
/// # Errors
///
/// Returns [`SecurityDescriptorDecodeError`] when the buffer is shorter than an ACL header, when the
/// revision is unsupported, or when full protocol parsing would be required.
pub fn decode_acl(input: &[u8]) -> DecodeResult<Smb2Acl> {
    require_len(input, 8)?;

    let revision = input[0];
    if revision != SMB2_ACL_REVISION && revision != SMB2_ACL_REVISION_DS {
        return Err(SecurityDescriptorDecodeError::UnsupportedRevision {
            structure: "acl",
            revision,
        });
    }

    Err(SecurityDescriptorDecodeError::ProtocolLogicPending(
        "decode_acl",
    ))
}

/// Creates a security descriptor decode skeleton corresponding to C `smb2_decode_security_descriptor`.
///
/// The function validates the fixed security descriptor header and revision. Owner, group, SACL, and
/// DACL offset handling is intentionally left for the protocol implementation pass.
///
/// # Errors
///
/// Returns [`SecurityDescriptorDecodeError`] when the buffer is shorter than the fixed security
/// descriptor header, when the revision is unsupported, or when full protocol parsing would be
/// required.
pub fn smb2_decode_security_descriptor(input: &[u8]) -> DecodeResult<Smb2SecurityDescriptor> {
    require_len(input, 20)?;

    let revision = input[0];
    if revision != 1 {
        return Err(SecurityDescriptorDecodeError::UnsupportedRevision {
            structure: "security descriptor",
            revision,
        });
    }

    Err(SecurityDescriptorDecodeError::ProtocolLogicPending(
        "smb2_decode_security_descriptor",
    ))
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
