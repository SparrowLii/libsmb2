//! SPNEGO wrapper migrated from `lib/spnego-wrapper.c`.
//!
//! This module mirrors the responsibilities and public shape of the legacy C
//! wrapper. It provides stable Rust data structures for the GSS-SPNEGO and
//! NTLMSSP wrapping paths, but it intentionally does not implement the complete
//! ASN.1 BER/SPNEGO encoder or decoder yet.

/// Kerberos mechanism bit reported by SPNEGO mechanism parsing.
pub const SPNEGO_MECHANISM_KRB5: u32 = 0x0001;

/// NTLMSSP mechanism bit reported by SPNEGO mechanism parsing.
pub const SPNEGO_MECHANISM_NTLMSSP: u32 = 0x0002;

/// Object identifier for the GSS-SPNEGO mechanism.
pub const OID_GSS_MECH_SPNEGO: OidValue = OidValue::new(&[1, 3, 6, 1, 5, 5, 2]);

/// Object identifier for the Kerberos V5 SPNEGO mechanism.
pub const OID_SPNEGO_MECH_KRB5: OidValue = OidValue::new(&[1, 2, 840, 113554, 1, 2, 2]);

/// Microsoft legacy Kerberos SPNEGO mechanism object identifier.
pub const OID_SPNEGO_MECH_MS_KRB5: OidValue = OidValue::new(&[1, 2, 840, 48018, 1, 2, 2]);

/// Object identifier for the NTLMSSP SPNEGO mechanism.
pub const OID_SPNEGO_MECH_NTLMSSP: OidValue = OidValue::new(&[1, 3, 6, 1, 4, 1, 311, 2, 2, 10]);

/// Result type used by SPNEGO wrapper skeleton APIs.
pub type SpnegoResult<T> = core::result::Result<T, SpnegoError>;

/// Errors returned by SPNEGO wrapper skeleton helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpnegoError {
    /// The supplied blob is too short for the requested SPNEGO operation.
    BufferTooShort,
    /// The supplied blob does not match a supported SPNEGO wrapper shape.
    InvalidBlob,
    /// The requested operation depends on ASN.1 BER/SPNEGO logic not migrated yet.
    ProtocolLogicNotImplemented,
}

/// Borrowed ASN.1 object identifier value used by SPNEGO mechanism metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OidValue {
    elements: &'static [u32],
}

impl OidValue {
    /// Creates an object identifier value from static elements.
    #[must_use]
    pub const fn new(elements: &'static [u32]) -> Self {
        Self { elements }
    }

    /// Returns the object identifier elements.
    #[must_use]
    pub const fn elements(&self) -> &'static [u32] {
        self.elements
    }

    /// Returns the object identifier element count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.elements.len()
    }

    /// Returns whether the object identifier has no elements.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}

/// Mechanism set accumulated while parsing SPNEGO mechanism lists.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpnegoMechanisms {
    bits: u32,
}

impl SpnegoMechanisms {
    /// Creates an empty mechanism set.
    #[must_use]
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates a mechanism set from raw legacy bit values.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Returns the raw legacy mechanism bits.
    #[must_use]
    pub const fn bits(&self) -> u32 {
        self.bits
    }

    /// Returns whether the Kerberos mechanism bit is present.
    #[must_use]
    pub const fn contains_krb5(&self) -> bool {
        self.bits & SPNEGO_MECHANISM_KRB5 != 0
    }

    /// Returns whether the NTLMSSP mechanism bit is present.
    #[must_use]
    pub const fn contains_ntlmssp(&self) -> bool {
        self.bits & SPNEGO_MECHANISM_NTLMSSP != 0
    }

    /// Adds a mechanism bit to this set.
    pub fn insert_bits(&mut self, bits: u32) {
        self.bits |= bits;
    }
}

/// SPNEGO negotiate result values mirrored from `NegTokenTarg.negResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpnegoNegResult {
    /// Authentication completed successfully.
    AcceptCompleted,
    /// Authentication is accepted but requires another token exchange.
    AcceptIncomplete,
    /// Authentication was rejected.
    Reject,
}

impl SpnegoNegResult {
    /// Returns the DER enumerated value used by the legacy C encoder.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::AcceptCompleted => 0,
            Self::AcceptIncomplete => 1,
            Self::Reject => 3,
        }
    }
}

/// High-level SPNEGO blob shape selected by `smb2_spnego_unwrap_blob`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpnegoBlobKind {
    /// Raw NTLMSSP token without SPNEGO wrapping.
    RawNtlmssp,
    /// GSS-API initial-context token containing SPNEGO data.
    GssApi,
    /// Raw SPNEGO target token.
    NegTokenTarg,
    /// Blob type not recognized by the skeleton classifier.
    Unknown,
}

/// Owned SPNEGO or NTLMSSP blob used by wrapper construction APIs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpnegoBlob {
    bytes: Vec<u8>,
    kind: Option<SpnegoBlobKind>,
}

impl SpnegoBlob {
    /// Creates an empty blob with no classified kind.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            kind: None,
        }
    }

    /// Creates a blob from existing bytes and a classified kind.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>, kind: SpnegoBlobKind) -> Self {
        Self {
            bytes,
            kind: Some(kind),
        }
    }

    /// Returns the blob bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the classified blob kind, when known.
    #[must_use]
    pub const fn kind(&self) -> Option<SpnegoBlobKind> {
        self.kind
    }

    /// Consumes the blob and returns its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Output of a SPNEGO unwrap operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwrappedSpnego<'a> {
    /// Token bytes selected by the unwrap operation.
    pub token: &'a [u8],
    /// Mechanism bits discovered while parsing the SPNEGO mechanism list.
    pub mechanisms: SpnegoMechanisms,
    /// The classified input blob kind.
    pub kind: SpnegoBlobKind,
}

/// Encoder/decoder facade corresponding to `lib/spnego-wrapper.c`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpnegoWrapper;

impl SpnegoWrapper {
    /// Creates a SPNEGO wrapper facade.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Skeleton for `smb2_spnego_create_negotiate_reply_blob`.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::ProtocolLogicNotImplemented`] until the ASN.1 BER
    /// NegTokenInit encoder is migrated.
    pub const fn create_negotiate_reply_blob(
        &self,
        _allow_ntlmssp: bool,
    ) -> SpnegoResult<SpnegoBlob> {
        Err(SpnegoError::ProtocolLogicNotImplemented)
    }

    /// Skeleton for `smb2_spnego_wrap_gssapi`.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::ProtocolLogicNotImplemented`] until GSS-API
    /// SPNEGO wrapping is migrated.
    pub const fn wrap_gssapi(&self, _ntlmssp_token: &[u8]) -> SpnegoResult<SpnegoBlob> {
        Err(SpnegoError::ProtocolLogicNotImplemented)
    }

    /// Skeleton for `smb2_spnego_wrap_ntlmssp_challenge`.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::ProtocolLogicNotImplemented`] until NegTokenTarg
    /// challenge wrapping is migrated.
    pub const fn wrap_ntlmssp_challenge(&self, _ntlmssp_token: &[u8]) -> SpnegoResult<SpnegoBlob> {
        Err(SpnegoError::ProtocolLogicNotImplemented)
    }

    /// Skeleton for `smb2_spnego_wrap_ntlmssp_auth`.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::ProtocolLogicNotImplemented`] until NegTokenTarg
    /// authenticate-token wrapping is migrated.
    pub const fn wrap_ntlmssp_auth(&self, _ntlmssp_token: &[u8]) -> SpnegoResult<SpnegoBlob> {
        Err(SpnegoError::ProtocolLogicNotImplemented)
    }

    /// Skeleton for `smb2_spnego_wrap_authenticate_result`.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::ProtocolLogicNotImplemented`] until NegTokenTarg
    /// result encoding is migrated.
    pub const fn wrap_authenticate_result(
        &self,
        _result: SpnegoNegResult,
    ) -> SpnegoResult<SpnegoBlob> {
        Err(SpnegoError::ProtocolLogicNotImplemented)
    }

    /// Skeleton for `smb2_spnego_unwrap_targ`.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::ProtocolLogicNotImplemented`] until raw
    /// NegTokenTarg parsing is migrated.
    pub const fn unwrap_targ<'a>(&self, _spnego: &'a [u8]) -> SpnegoResult<UnwrappedSpnego<'a>> {
        Err(SpnegoError::ProtocolLogicNotImplemented)
    }

    /// Skeleton for `smb2_spnego_unwrap_gssapi`.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::ProtocolLogicNotImplemented`] until GSS-API
    /// NegTokenInit parsing is migrated.
    pub const fn unwrap_gssapi<'a>(
        &self,
        _spnego: &'a [u8],
        _suppress_errors: bool,
    ) -> SpnegoResult<UnwrappedSpnego<'a>> {
        Err(SpnegoError::ProtocolLogicNotImplemented)
    }

    /// Classifies and unwraps a raw NTLMSSP, GSS-API, or raw SPNEGO blob.
    ///
    /// Raw NTLMSSP detection is implemented as the same dispatch shortcut used
    /// by the C entry point. Full SPNEGO ASN.1 parsing is intentionally deferred.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::BufferTooShort`] for inputs shorter than the legacy
    /// minimum, [`SpnegoError::InvalidBlob`] for unknown blob types, or
    /// [`SpnegoError::ProtocolLogicNotImplemented`] for recognized SPNEGO forms
    /// whose BER parsing is not migrated yet.
    pub fn unwrap_blob<'a>(
        &self,
        spnego: &'a [u8],
        suppress_errors: bool,
    ) -> SpnegoResult<UnwrappedSpnego<'a>> {
        match classify_blob(spnego)? {
            SpnegoBlobKind::RawNtlmssp => Ok(UnwrappedSpnego {
                token: spnego,
                mechanisms: SpnegoMechanisms::empty(),
                kind: SpnegoBlobKind::RawNtlmssp,
            }),
            SpnegoBlobKind::GssApi => self.unwrap_gssapi(spnego, suppress_errors),
            SpnegoBlobKind::NegTokenTarg => self.unwrap_targ(spnego),
            SpnegoBlobKind::Unknown => Err(SpnegoError::InvalidBlob),
        }
    }
}

/// Compares two SPNEGO object identifiers using the C helper's equality rules.
#[must_use]
pub fn oid_compare(a: &OidValue, b: &OidValue) -> core::cmp::Ordering {
    a.elements.cmp(b.elements)
}

/// Classifies a SPNEGO input buffer using the legacy entry-point dispatch bytes.
///
/// # Errors
///
/// Returns [`SpnegoError::BufferTooShort`] when fewer than 7 bytes are available.
pub fn classify_blob(spnego: &[u8]) -> SpnegoResult<SpnegoBlobKind> {
    if spnego.len() < 7 {
        return Err(SpnegoError::BufferTooShort);
    }
    if spnego.len() > 7 && spnego.get(0..8) == Some(b"NTLMSSP\0".as_slice()) {
        return Ok(SpnegoBlobKind::RawNtlmssp);
    }

    match spnego[0] {
        0x60 => Ok(SpnegoBlobKind::GssApi),
        0xa0..=0xa2 => Ok(SpnegoBlobKind::NegTokenTarg),
        _ => Ok(SpnegoBlobKind::Unknown),
    }
}
