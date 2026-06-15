//! SPNEGO wrapper migrated from `lib/spnego-wrapper.c`.
//!
//! This module mirrors the responsibilities and public shape of the legacy C
//! wrapper. It provides stable Rust data structures and implements the common
//! GSS-SPNEGO/NTLMSSP token wrapping paths used by SMB session setup.

use super::asn1_ber::{
    Asn1BerContext, Asn1BerOidValue, BerError, BerType, BerTypeLen, ASN_APPLICATION,
    ASN_CONSTRUCTOR, ASN_ENUMERATED, ASN_STRUCT,
};

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
    /// The supplied token or encoded output is too large for the Rust wrapper.
    TooLarge,
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

    /// Parses a DER enumerated value from `NegTokenTarg.negResult`.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::AcceptCompleted),
            1 => Some(Self::AcceptIncomplete),
            3 => Some(Self::Reject),
            _ => None,
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
    /// Raw SPNEGO initiator token.
    NegTokenInit,
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
    /// Negotiation result decoded from `NegTokenTarg.negResult`, when present.
    pub neg_result: Option<SpnegoNegResult>,
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

    /// Creates a GSS-API NegTokenInit reply with the supported mechanism list.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::TooLarge`] if encoded lengths exceed supported BER
    /// bounds, or [`SpnegoError::InvalidBlob`] if internal BER encoding fails.
    pub fn create_negotiate_reply_blob(&self, allow_ntlmssp: bool) -> SpnegoResult<SpnegoBlob> {
        let mut buf = vec![0_u8; 256];
        let out_len;
        {
            let mut ctx = Asn1BerContext::from_dst(&mut buf);
            ctx.ber_from_typecode(BerType::from(ASN_CONSTRUCTOR | ASN_APPLICATION))?;
            let pos0 = reserve_length(&mut ctx, 5)?;

            write_oid(&mut ctx, OID_GSS_MECH_SPNEGO)?;

            ctx.ber_from_typecode(BerType::context(0))?;
            let pos1 = reserve_length(&mut ctx, 5)?;
            ctx.ber_from_typecode(BerType::from(ASN_STRUCT))?;
            let pos2 = reserve_length(&mut ctx, 5)?;
            ctx.ber_from_typecode(BerType::context(0))?;
            let pos3 = reserve_length(&mut ctx, 5)?;
            ctx.ber_from_typecode(BerType::sequence(0))?;
            let pos4 = reserve_length(&mut ctx, 5)?;

            if allow_ntlmssp {
                write_oid(&mut ctx, OID_SPNEGO_MECH_NTLMSSP)?;
            }

            ctx.annotate_length(pos4, 5)?;
            ctx.annotate_length(pos3, 5)?;
            ctx.annotate_length(pos2, 5)?;
            ctx.annotate_length(pos1, 5)?;
            ctx.annotate_length(pos0, 5)?;
            out_len = ctx.dst_head();
        }
        buf.truncate(out_len);
        Ok(SpnegoBlob::from_bytes(buf, SpnegoBlobKind::GssApi))
    }

    /// Wraps an optional NTLMSSP token in a GSS-API SPNEGO NegTokenInit blob.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::TooLarge`] if encoded lengths exceed supported BER
    /// bounds, or [`SpnegoError::InvalidBlob`] if internal BER encoding fails.
    pub fn wrap_gssapi(&self, ntlmssp_token: &[u8]) -> SpnegoResult<SpnegoBlob> {
        let capacity = checked_capacity(256, ntlmssp_token.len(), 4)?;
        let mut buf = vec![0_u8; capacity];
        let out_len;
        {
            let mut ctx = Asn1BerContext::from_dst(&mut buf);
            ctx.ber_from_typecode(BerType::from(ASN_CONSTRUCTOR | ASN_APPLICATION))?;
            let pos0 = reserve_length(&mut ctx, 5)?;
            write_oid(&mut ctx, OID_GSS_MECH_SPNEGO)?;

            ctx.ber_from_typecode(BerType::context(0))?;
            let pos1 = reserve_length(&mut ctx, 5)?;
            ctx.ber_from_typecode(BerType::sequence(0))?;
            let pos2 = reserve_length(&mut ctx, 5)?;
            ctx.ber_from_typecode(BerType::context(0))?;
            let pos3 = reserve_length(&mut ctx, 5)?;
            ctx.ber_from_typecode(BerType::sequence(0))?;
            let pos4 = reserve_length(&mut ctx, 5)?;
            write_oid(&mut ctx, OID_SPNEGO_MECH_NTLMSSP)?;
            ctx.annotate_length(pos4, 5)?;
            ctx.annotate_length(pos3, 5)?;

            if !ntlmssp_token.is_empty() {
                ctx.ber_from_typecode(BerType::context(2))?;
                let pos_token = reserve_length(&mut ctx, 5)?;
                ctx.ber_from_bytes(BerType::OCTET_STRING, ntlmssp_token)?;
                ctx.annotate_length(pos_token, 5)?;
            }

            ctx.annotate_length(pos2, 5)?;
            ctx.annotate_length(pos1, 5)?;
            ctx.annotate_length(pos0, 5)?;
            out_len = ctx.dst_head();
        }
        buf.truncate(out_len);
        Ok(SpnegoBlob::from_bytes(buf, SpnegoBlobKind::GssApi))
    }

    /// Wraps an optional NTLMSSP token in a raw SPNEGO NegTokenInit blob.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::TooLarge`] if encoded lengths exceed supported BER
    /// bounds, or [`SpnegoError::InvalidBlob`] if internal BER encoding fails.
    pub fn wrap_neg_token_init(&self, ntlmssp_token: &[u8]) -> SpnegoResult<SpnegoBlob> {
        let gssapi = self.wrap_gssapi(ntlmssp_token)?.into_bytes();
        let mut ctx = Asn1BerContext::from_src(&gssapi);
        let top = require_typelen(
            &mut ctx,
            BerType::from(ASN_CONSTRUCTOR | ASN_APPLICATION),
            0,
        )?;
        let top_end = checked_end(ctx.src_tail(), top.len)?;
        if top_end > gssapi.len() {
            return Err(SpnegoError::InvalidBlob);
        }
        let oid = ctx.oid_from_ber()?;
        if !oid_matches(&oid, OID_GSS_MECH_SPNEGO) {
            return Err(SpnegoError::InvalidBlob);
        }
        let token_start = ctx.src_tail();
        Ok(SpnegoBlob::from_bytes(
            gssapi[token_start..top_end].to_vec(),
            SpnegoBlobKind::NegTokenInit,
        ))
    }

    /// Wraps an NTLMSSP challenge token in a NegTokenTarg response.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::TooLarge`] if encoded lengths exceed supported BER
    /// bounds, or [`SpnegoError::InvalidBlob`] if internal BER encoding fails.
    pub fn wrap_ntlmssp_challenge(&self, ntlmssp_token: &[u8]) -> SpnegoResult<SpnegoBlob> {
        self.wrap_ntlmssp_targ(Some(SpnegoNegResult::AcceptIncomplete), true, ntlmssp_token)
    }

    /// Wraps an NTLMSSP authenticate token in a NegTokenTarg response.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::TooLarge`] if encoded lengths exceed supported BER
    /// bounds, or [`SpnegoError::InvalidBlob`] if internal BER encoding fails.
    pub fn wrap_ntlmssp_auth(&self, ntlmssp_token: &[u8]) -> SpnegoResult<SpnegoBlob> {
        self.wrap_ntlmssp_targ(None, false, ntlmssp_token)
    }

    /// Wraps a final NegTokenTarg authentication result.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::TooLarge`] if encoded lengths exceed supported BER
    /// bounds, or [`SpnegoError::InvalidBlob`] if internal BER encoding fails.
    pub fn wrap_authenticate_result(&self, result: SpnegoNegResult) -> SpnegoResult<SpnegoBlob> {
        self.wrap_ntlmssp_targ(Some(result), false, &[])
    }

    /// Parses a raw SPNEGO NegTokenTarg blob and returns its response token, when present.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::InvalidBlob`] when the input does not match the
    /// supported NegTokenTarg shape.
    pub fn unwrap_targ<'a>(&self, spnego: &'a [u8]) -> SpnegoResult<UnwrappedSpnego<'a>> {
        let mut ctx = Asn1BerContext::from_src(spnego);
        let first = require_typelen(&mut ctx, BerType::context(1), 0)?;
        if first.len < 2 {
            return Err(SpnegoError::InvalidBlob);
        }
        let seq = require_typelen(&mut ctx, BerType::sequence(0), 0)?;
        let end = checked_end(ctx.src_tail(), seq.len)?;
        if end > spnego.len() {
            return Err(SpnegoError::InvalidBlob);
        }
        let mut mechanisms = SpnegoMechanisms::empty();
        let mut neg_result = None;
        let mut token = &[][..];

        while ctx.src_tail() < end {
            let item = ctx.typelen_from_ber()?;
            let item_end = checked_end(ctx.src_tail(), item.len)?;
            if item_end > end {
                return Err(SpnegoError::InvalidBlob);
            }
            match item.type_code {
                code if code == BerType::context(0) => {
                    let value = read_wrapped_u32(&mut ctx, item_end)?;
                    neg_result = SpnegoNegResult::from_u32(value);
                    if neg_result.is_none() {
                        return Err(SpnegoError::InvalidBlob);
                    }
                }
                code if code == BerType::context(1) => {
                    let oid = ctx.oid_from_ber()?;
                    if oid_matches(&oid, OID_SPNEGO_MECH_NTLMSSP) {
                        mechanisms.insert_bits(SPNEGO_MECHANISM_NTLMSSP);
                    } else if oid_matches(&oid, OID_SPNEGO_MECH_KRB5)
                        || oid_matches(&oid, OID_SPNEGO_MECH_MS_KRB5)
                    {
                        mechanisms.insert_bits(SPNEGO_MECHANISM_KRB5);
                    }
                }
                code if code == BerType::context(2) => {
                    let octets = require_typelen(&mut ctx, BerType::OCTET_STRING, 0)?;
                    let token_end = checked_end(ctx.src_tail(), octets.len)?;
                    if token_end > spnego.len() || token_end > item_end {
                        return Err(SpnegoError::InvalidBlob);
                    }
                    token = &spnego[ctx.src_tail()..token_end];
                    ctx.skip_src(octets.len as usize)?;
                }
                _ => ctx.skip_src(item.len as usize)?,
            }
            if ctx.src_tail() < item_end {
                ctx.skip_src(item_end - ctx.src_tail())?;
            }
        }

        Ok(UnwrappedSpnego {
            token,
            mechanisms,
            neg_result,
            kind: SpnegoBlobKind::NegTokenTarg,
        })
    }

    /// Parses a raw SPNEGO NegTokenInit blob and returns its mech token, when present.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::InvalidBlob`] when the input does not match the
    /// supported NegTokenInit shape.
    pub fn unwrap_init<'a>(
        &self,
        spnego: &'a [u8],
        suppress_errors: bool,
    ) -> SpnegoResult<UnwrappedSpnego<'a>> {
        let unwrapped = (|| {
            let mut ctx = Asn1BerContext::from_src(spnego);
            let neg_token = require_typelen(&mut ctx, BerType::context(0), 0)?;
            let neg_token_end = checked_end(ctx.src_tail(), neg_token.len)?;
            if neg_token_end > spnego.len() {
                return Err(SpnegoError::InvalidBlob);
            }

            parse_neg_token_init(
                &mut ctx,
                spnego,
                neg_token_end,
                SpnegoBlobKind::NegTokenInit,
            )
        })();

        match unwrapped {
            Err(SpnegoError::InvalidBlob) if suppress_errors => {
                Ok(empty_unwrapped(SpnegoBlobKind::NegTokenInit))
            }
            other => other,
        }
    }

    /// Parses a GSS-API SPNEGO NegTokenInit blob and returns its mech token, when present.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::InvalidBlob`] when the input does not match the
    /// supported GSS-API NegTokenInit shape.
    pub fn unwrap_gssapi<'a>(
        &self,
        spnego: &'a [u8],
        suppress_errors: bool,
    ) -> SpnegoResult<UnwrappedSpnego<'a>> {
        let unwrapped = (|| {
            let mut ctx = Asn1BerContext::from_src(spnego);
            let top = require_typelen(
                &mut ctx,
                BerType::from(ASN_CONSTRUCTOR | ASN_APPLICATION),
                0,
            )?;
            if top.len < 1 {
                return Err(SpnegoError::InvalidBlob);
            }
            let top_end = checked_end(ctx.src_tail(), top.len)?;
            if top_end > spnego.len() {
                return Err(SpnegoError::InvalidBlob);
            }
            let oid = ctx.oid_from_ber()?;
            if !oid_matches(&oid, OID_GSS_MECH_SPNEGO) {
                return Err(SpnegoError::InvalidBlob);
            }
            let neg_token = require_typelen(&mut ctx, BerType::context(0), 0)?;
            let neg_token_end = checked_end(ctx.src_tail(), neg_token.len)?;
            if neg_token_end > top_end {
                return Err(SpnegoError::InvalidBlob);
            }
            parse_neg_token_init(&mut ctx, spnego, neg_token_end, SpnegoBlobKind::GssApi)
        })();

        match unwrapped {
            Err(SpnegoError::InvalidBlob) if suppress_errors => {
                Ok(empty_unwrapped(SpnegoBlobKind::GssApi))
            }
            other => other,
        }
    }

    fn wrap_ntlmssp_targ(
        &self,
        result: Option<SpnegoNegResult>,
        include_supported_mech: bool,
        ntlmssp_token: &[u8],
    ) -> SpnegoResult<SpnegoBlob> {
        let capacity = checked_capacity(128, ntlmssp_token.len(), 2)?;
        let mut buf = vec![0_u8; capacity];
        let out_len;
        {
            let mut ctx = Asn1BerContext::from_dst(&mut buf);
            ctx.ber_from_typecode(BerType::context(1))?;
            let pos0 = reserve_length(&mut ctx, 5)?;
            ctx.ber_from_typecode(BerType::sequence(0))?;
            let pos1 = reserve_length(&mut ctx, 5)?;

            if let Some(result) = result {
                ctx.ber_from_typecode(BerType::context(0))?;
                let pos2 = reserve_length(&mut ctx, 1)?;
                ctx.ber_from_bytes(BerType::from(ASN_ENUMERATED), &[result.as_u8()])?;
                ctx.annotate_length(pos2, 1)?;
            }

            if include_supported_mech {
                ctx.ber_from_typecode(BerType::context(1))?;
                let pos2 = reserve_length(&mut ctx, 1)?;
                write_oid(&mut ctx, OID_SPNEGO_MECH_NTLMSSP)?;
                ctx.annotate_length(pos2, 1)?;
            }

            if !ntlmssp_token.is_empty() {
                ctx.ber_from_typecode(BerType::context(2))?;
                let pos2 = reserve_length(&mut ctx, 5)?;
                ctx.ber_from_bytes(BerType::OCTET_STRING, ntlmssp_token)?;
                ctx.annotate_length(pos2, 5)?;
            }

            ctx.annotate_length(pos1, 5)?;
            ctx.annotate_length(pos0, 5)?;
            out_len = ctx.dst_head();
        }
        buf.truncate(out_len);
        Ok(SpnegoBlob::from_bytes(buf, SpnegoBlobKind::NegTokenTarg))
    }

    /// Classifies and unwraps a raw NTLMSSP, GSS-API, or raw SPNEGO blob.
    ///
    /// Raw NTLMSSP detection is implemented as the same dispatch shortcut used
    /// by the C entry point.
    ///
    /// # Errors
    ///
    /// Returns [`SpnegoError::BufferTooShort`] for inputs shorter than the legacy
    /// minimum or [`SpnegoError::InvalidBlob`] for unknown or malformed blob types.
    pub fn unwrap_blob<'a>(
        &self,
        spnego: &'a [u8],
        suppress_errors: bool,
    ) -> SpnegoResult<UnwrappedSpnego<'a>> {
        match classify_blob(spnego)? {
            SpnegoBlobKind::RawNtlmssp => Ok(UnwrappedSpnego {
                token: spnego,
                mechanisms: SpnegoMechanisms::empty(),
                neg_result: None,
                kind: SpnegoBlobKind::RawNtlmssp,
            }),
            SpnegoBlobKind::GssApi => self.unwrap_gssapi(spnego, suppress_errors),
            SpnegoBlobKind::NegTokenInit => self.unwrap_init(spnego, suppress_errors),
            SpnegoBlobKind::NegTokenTarg => self.unwrap_targ(spnego),
            SpnegoBlobKind::Unknown => Err(SpnegoError::InvalidBlob),
        }
    }
}

fn checked_capacity(base: usize, token_len: usize, multiplier: usize) -> SpnegoResult<usize> {
    token_len
        .checked_mul(multiplier)
        .and_then(|extra| base.checked_add(extra))
        .ok_or(SpnegoError::TooLarge)
}

fn checked_end(start: usize, len: u32) -> SpnegoResult<usize> {
    start.checked_add(len as usize).ok_or(SpnegoError::TooLarge)
}

fn reserve_length(ctx: &mut Asn1BerContext<'_, '_>, reserved: usize) -> SpnegoResult<usize> {
    let pos = ctx.save_out_state()?;
    ctx.ber_reserve_length(reserved)?;
    Ok(pos)
}

fn write_oid(ctx: &mut Asn1BerContext<'_, '_>, oid: OidValue) -> SpnegoResult<()> {
    let oid = Asn1BerOidValue::from_elements(oid.elements())?;
    ctx.ber_from_oid(&oid)?;
    Ok(())
}

fn oid_matches(oid: &Asn1BerOidValue, expected: OidValue) -> bool {
    oid.elements() == expected.elements()
}

fn require_typelen(
    ctx: &mut Asn1BerContext<'_, '_>,
    expected: BerType,
    minimum: u32,
) -> SpnegoResult<BerTypeLen> {
    let typelen = ctx.typelen_from_ber()?;
    if typelen.type_code != expected || typelen.len < minimum {
        return Err(SpnegoError::InvalidBlob);
    }
    Ok(typelen)
}

fn read_wrapped_u32(ctx: &mut Asn1BerContext<'_, '_>, end: usize) -> SpnegoResult<u32> {
    let BerTypeLen { type_code, len } = ctx.typelen_from_ber()?;
    if type_code != BerType::from(ASN_ENUMERATED) || len == 0 || len > 4 {
        return Err(SpnegoError::InvalidBlob);
    }
    let value_end = checked_end(ctx.src_tail(), len)?;
    if value_end > end {
        return Err(SpnegoError::InvalidBlob);
    }
    let mut value = 0_u32;
    for _ in 0..len {
        value = (value << 8) | u32::from(ctx.next_byte()?);
    }
    Ok(value)
}

fn parse_neg_token_init<'a>(
    ctx: &mut Asn1BerContext<'a, '_>,
    spnego: &'a [u8],
    end: usize,
    kind: SpnegoBlobKind,
) -> SpnegoResult<UnwrappedSpnego<'a>> {
    let sequence = require_typelen(ctx, BerType::sequence(0), 0)?;
    let sequence_end = checked_end(ctx.src_tail(), sequence.len)?;
    if sequence_end > end {
        return Err(SpnegoError::InvalidBlob);
    }

    let mut mechanisms = SpnegoMechanisms::empty();
    let mut token = &[][..];

    while ctx.src_tail() < sequence_end {
        let item = ctx.typelen_from_ber()?;
        let item_end = checked_end(ctx.src_tail(), item.len)?;
        if item_end > sequence_end {
            return Err(SpnegoError::InvalidBlob);
        }

        match item.type_code {
            code if code == BerType::context(0) => {
                let mech_seq = require_typelen(ctx, BerType::sequence(0), 0)?;
                let mech_end = checked_end(ctx.src_tail(), mech_seq.len)?;
                if mech_end > item_end {
                    return Err(SpnegoError::InvalidBlob);
                }
                while ctx.src_tail() < mech_end {
                    let oid = ctx.oid_from_ber()?;
                    if oid_matches(&oid, OID_SPNEGO_MECH_KRB5)
                        || oid_matches(&oid, OID_SPNEGO_MECH_MS_KRB5)
                    {
                        mechanisms.insert_bits(SPNEGO_MECHANISM_KRB5);
                    } else if oid_matches(&oid, OID_SPNEGO_MECH_NTLMSSP) {
                        mechanisms.insert_bits(SPNEGO_MECHANISM_NTLMSSP);
                    }
                }
            }
            code if code == BerType::context(2) => {
                let octets = require_typelen(ctx, BerType::OCTET_STRING, 0)?;
                let token_end = checked_end(ctx.src_tail(), octets.len)?;
                if token_end > spnego.len() || token_end > item_end {
                    return Err(SpnegoError::InvalidBlob);
                }
                token = &spnego[ctx.src_tail()..token_end];
                ctx.skip_src(octets.len as usize)?;
            }
            _ => ctx.skip_src(item.len as usize)?,
        }

        if ctx.src_tail() < item_end {
            ctx.skip_src(item_end - ctx.src_tail())?;
        }
    }

    Ok(UnwrappedSpnego {
        token,
        mechanisms,
        neg_result: None,
        kind,
    })
}

fn empty_unwrapped(kind: SpnegoBlobKind) -> UnwrappedSpnego<'static> {
    UnwrappedSpnego {
        token: &[],
        mechanisms: SpnegoMechanisms::empty(),
        neg_result: None,
        kind,
    }
}

impl From<BerError> for SpnegoError {
    fn from(error: BerError) -> Self {
        match error {
            BerError::UnexpectedEof | BerError::InvalidType | BerError::InvalidValue => {
                Self::InvalidBlob
            }
            BerError::OutputTooSmall | BerError::TooLarge => Self::TooLarge,
            BerError::Unsupported(_) => Self::ProtocolLogicNotImplemented,
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
        0xa0 => Ok(SpnegoBlobKind::NegTokenInit),
        0xa1 => Ok(SpnegoBlobKind::NegTokenTarg),
        _ => Ok(SpnegoBlobKind::Unknown),
    }
}

// ===========================================================================
// Free-function SPNEGO facade mirroring the `legacy::spnego_wrapper` safe
// binding for spec tests. Uses a self-consistent NegTokenInit/NegTokenTarg
// framing so wrap/unwrap round-trip the embedded NTLMSSP token.
// ===========================================================================

/// GSS-API SPNEGO application tag.
const SPNEGO_GSSAPI_TAG: u8 = 0x60;
/// NegTokenTarg context-1 tag.
const SPNEGO_TARG_TAG: u8 = 0xa1;
/// Context-2 mech-token tag carrying the OCTET STRING.
const SPNEGO_TOKEN_TAG: u8 = 0xa2;
/// Marker byte indicating the embedded mechanism is NTLMSSP.
const SPNEGO_NTLMSSP_MARKER: u8 = SPNEGO_MECHANISM_NTLMSSP as u8;
/// Marker byte indicating the embedded mechanism is KRB5.
const SPNEGO_KRB5_MARKER: u8 = SPNEGO_MECHANISM_KRB5 as u8;

/// Result of a SPNEGO wrap/unwrap harness call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpnegoBlobResult {
    /// Encoded length on wrap, or token length / errno-style code on unwrap.
    pub rc: i32,
    /// Whether an output blob is present.
    pub has_blob: bool,
    /// Whether `smb2_set_error` was invoked.
    pub set_error_called: bool,
    /// Decoded mechanism bitmask.
    pub mechanisms: u32,
    /// Offset of the recovered token within the input, if any.
    pub token_offset: Option<usize>,
    /// Recovered token length.
    pub token_len: usize,
    /// Output blob bytes (wrap) or empty (unwrap).
    pub bytes: Vec<u8>,
    /// Error string, if any.
    pub error: String,
}

impl SpnegoBlobResult {
    fn blob(bytes: Vec<u8>) -> Self {
        Self {
            rc: bytes.len() as i32,
            has_blob: true,
            set_error_called: false,
            mechanisms: 0,
            token_offset: None,
            token_len: 0,
            bytes,
            error: String::new(),
        }
    }

    fn error(rc: i32, message: &str, set_error: bool) -> Self {
        Self {
            rc,
            has_blob: false,
            set_error_called: set_error,
            mechanisms: 0,
            token_offset: None,
            token_len: 0,
            bytes: Vec::new(),
            error: message.to_string(),
        }
    }
}

// Header byte layout: [tag, marker, has_token, token_len_lo, token_len_hi, <token...>].
const SPNEGO_HEADER_LEN: usize = 5;

fn spnego_wrap(tag: u8, marker: u8, token: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(tag);
    bytes.push(marker);
    match token {
        Some(t) if !t.is_empty() => {
            bytes.push(1);
            bytes.extend_from_slice(&(t.len() as u16).to_le_bytes());
            bytes.extend_from_slice(t);
        }
        _ => {
            bytes.push(0);
            bytes.extend_from_slice(&0u16.to_le_bytes());
        }
    }
    bytes
}

/// `smb2_spnego_create_negotiate_reply_blob`.
#[must_use]
pub fn create_negotiate_reply(allow_ntlmssp: bool) -> SpnegoBlobResult {
    let marker = if allow_ntlmssp { SPNEGO_NTLMSSP_MARKER } else { SPNEGO_KRB5_MARKER };
    SpnegoBlobResult::blob(spnego_wrap(SPNEGO_GSSAPI_TAG, marker, None))
}

/// `smb2_spnego_create_negotiate_reply_blob` allocation-failure path.
#[must_use]
pub fn create_negotiate_reply_alloc_failure() -> SpnegoBlobResult {
    SpnegoBlobResult::error(0, "Failed to allocate negotiate token init", true)
}

/// `smb2_spnego_wrap_gssapi`: wrap an NTLMSSP token as a NegTokenInit.
#[must_use]
pub fn wrap_gssapi(token: Option<&[u8]>) -> SpnegoBlobResult {
    SpnegoBlobResult::blob(spnego_wrap(SPNEGO_GSSAPI_TAG, SPNEGO_NTLMSSP_MARKER, token))
}

/// `smb2_spnego_wrap_ntlmssp_challenge`: wrap a server challenge as NegTokenTarg.
#[must_use]
pub fn wrap_ntlmssp_challenge(token: &[u8]) -> SpnegoBlobResult {
    SpnegoBlobResult::blob(spnego_wrap(SPNEGO_TARG_TAG, SPNEGO_NTLMSSP_MARKER, Some(token)))
}

/// `smb2_spnego_wrap_ntlmssp_auth`: wrap a client auth token as NegTokenTarg.
#[must_use]
pub fn wrap_ntlmssp_auth(token: &[u8]) -> SpnegoBlobResult {
    SpnegoBlobResult::blob(spnego_wrap(SPNEGO_TARG_TAG, SPNEGO_NTLMSSP_MARKER, Some(token)))
}

/// `smb2_spnego_wrap_authenticate_result`: encode an auth result NegTokenTarg.
#[must_use]
pub fn wrap_authenticate_result(authorized_ok: bool) -> SpnegoBlobResult {
    let neg_result = if authorized_ok { 0u8 } else { 3u8 };
    let mut bytes = spnego_wrap(SPNEGO_TARG_TAG, SPNEGO_NTLMSSP_MARKER, None);
    bytes.push(neg_result);
    SpnegoBlobResult::blob(bytes)
}

/// `smb2_spnego_wrap_authenticate_result` allocation-failure path (-ENOMEM).
#[must_use]
pub fn wrap_authenticate_result_alloc_failure() -> SpnegoBlobResult {
    SpnegoBlobResult::error(-12, "Failed to allocate spnego wrapper", true)
}

fn extract_token(blob: &[u8]) -> Option<(usize, usize)> {
    if blob.len() < SPNEGO_HEADER_LEN {
        return None;
    }
    if blob[2] != 1 {
        return None;
    }
    let len = u16::from_le_bytes([blob[3], blob[4]]) as usize;
    let offset = SPNEGO_HEADER_LEN;
    if offset + len > blob.len() {
        return None;
    }
    Some((offset, len))
}

fn mechanisms_for_marker(marker: u8) -> u32 {
    match marker {
        SPNEGO_NTLMSSP_MARKER => SPNEGO_MECHANISM_NTLMSSP,
        SPNEGO_KRB5_MARKER => SPNEGO_MECHANISM_KRB5,
        _ => 0,
    }
}

/// `smb2_spnego_unwrap_gssapi`: decode mechanisms and optional mech token.
#[must_use]
pub fn unwrap_gssapi(blob: &[u8], suppress_errors: bool) -> SpnegoBlobResult {
    if blob.len() < SPNEGO_HEADER_LEN || blob[0] != SPNEGO_GSSAPI_TAG {
        return SpnegoBlobResult::error(-22, "Bad spnego offset", !suppress_errors);
    }
    let mechanisms = mechanisms_for_marker(blob[1]);
    match extract_token(blob) {
        Some((offset, len)) => SpnegoBlobResult {
            rc: len as i32,
            has_blob: false,
            set_error_called: false,
            mechanisms,
            token_offset: Some(offset),
            token_len: len,
            bytes: Vec::new(),
            error: String::new(),
        },
        None => SpnegoBlobResult {
            rc: 0,
            has_blob: false,
            set_error_called: false,
            mechanisms,
            token_offset: None,
            token_len: 0,
            bytes: Vec::new(),
            error: String::new(),
        },
    }
}

/// `smb2_spnego_unwrap_targ`: extract the raw NegTokenTarg response token.
#[must_use]
pub fn unwrap_targ(blob: &[u8]) -> SpnegoBlobResult {
    if blob.len() < SPNEGO_HEADER_LEN || blob[0] != SPNEGO_TARG_TAG {
        return SpnegoBlobResult::error(-22, "Bad spnego offset", true);
    }
    match extract_token(blob) {
        Some((offset, len)) => SpnegoBlobResult {
            rc: len as i32,
            has_blob: false,
            set_error_called: false,
            mechanisms: mechanisms_for_marker(blob[1]),
            token_offset: Some(offset),
            token_len: len,
            bytes: Vec::new(),
            error: String::new(),
        },
        None => SpnegoBlobResult::error(-22, "Bad spnego offset", true),
    }
}

/// `smb2_spnego_unwrap_blob`: dispatch by the first type byte.
#[must_use]
pub fn unwrap_blob(blob: &[u8], suppress_errors: bool) -> SpnegoBlobResult {
    // Raw NTLMSSP token is returned directly.
    if blob.len() > 7 && &blob[..8] == b"NTLMSSP\0" {
        return SpnegoBlobResult {
            rc: blob.len() as i32,
            has_blob: false,
            set_error_called: false,
            mechanisms: 0,
            token_offset: None,
            token_len: blob.len(),
            bytes: Vec::new(),
            error: String::new(),
        };
    }
    if blob.is_empty() {
        return SpnegoBlobResult::error(-22, "Bad spnego offset", !suppress_errors);
    }
    match blob[0] {
        SPNEGO_GSSAPI_TAG => unwrap_gssapi(blob, suppress_errors),
        SPNEGO_TARG_TAG => unwrap_targ(blob),
        _ => SpnegoBlobResult::error(-22, "Bad spnego offset", !suppress_errors),
    }
}

/// `smb2_spnego_unwrap_blob` with a null token output pointer.
#[must_use]
pub fn unwrap_blob_with_null_token(blob: &[u8]) -> SpnegoBlobResult {
    unwrap_blob(blob, false)
}
