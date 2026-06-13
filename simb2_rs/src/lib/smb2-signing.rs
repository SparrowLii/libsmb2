//! SMB2 signing helpers migrated from `lib/smb2-signing.c`.
//!
//! The legacy C file owns SMB2/SMB3 signature calculation, signature flagging on
//! outgoing PDUs, and a currently-empty signature verification hook. This Rust
//! module mirrors those responsibilities as migration-safe data structures and
//! method skeletons without implementing the full HMAC-SHA256 or AES-CMAC
//! protocol logic.

use crate::include::libsmb2_private::{
    Context, IoVec, Pdu, SMB2_HEADER_SIZE, SMB2_KEY_SIZE, SMB2_SIGNATURE_SIZE,
};
use crate::lib::pdu::{smb2_set_uint32, Smb2Command, SMB2_FLAGS_SERVER_TO_REDIR};

/// AES-128 key length used by the SMB3 AES-CMAC signing path.
pub const AES128_KEY_LEN: usize = 16;

/// AES block size used by the SMB3 AES-CMAC signing path.
pub const AES_BLOCK_SIZE: usize = 16;

/// SMB2.1 dialect threshold used to select HMAC-SHA256 versus AES-CMAC.
pub const SMB2_VERSION_0210: u16 = 0x0210;

/// Header flag indicating that an SMB2 packet carries a signature.
pub const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;

/// Offset of the 16-byte signature field inside an SMB2 header.
pub const SMB2_SIGNATURE_OFFSET: usize = 48;

/// Fixed-size SMB2 signing key.
pub type SigningKey = [u8; SMB2_KEY_SIZE];

/// Fixed-size SMB2 or SMB3 packet signature.
pub type Signature = [u8; SMB2_SIGNATURE_SIZE];

/// Fixed-size SMB3 AES-CMAC output block.
pub type AesCmac = [u8; AES_BLOCK_SIZE];

/// Signing algorithm selected by the negotiated dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// SMB2.0.2/2.1 HMAC-SHA256 truncated to the SMB2 signature field.
    HmacSha256Truncated,
    /// SMB3 AES-CMAC-128 truncated to the SMB2 signature field.
    AesCmac128,
}

impl SigningAlgorithm {
    /// Selects the legacy signing algorithm for a negotiated dialect.
    #[must_use]
    pub const fn for_dialect(dialect: u16) -> Self {
        if dialect > SMB2_VERSION_0210 {
            Self::AesCmac128
        } else {
            Self::HmacSha256Truncated
        }
    }
}

/// Minimal signing state needed by `lib/smb2-signing.c` responsibilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2SigningContext {
    /// Negotiated SMB dialect.
    pub dialect: u16,
    /// Session id; zero means the legacy sender must not sign the PDU.
    pub session_id: u64,
    /// Session key size observed after authentication.
    pub session_key_size: usize,
    /// Signing key material used by the selected signing algorithm.
    pub signing_key: SigningKey,
}

impl Smb2SigningContext {
    /// Creates signing state from the fields used by the legacy C signer.
    #[must_use]
    pub const fn new(
        dialect: u16,
        session_id: u64,
        session_key_size: usize,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            dialect,
            session_id,
            session_key_size,
            signing_key,
        }
    }

    /// Creates signing state from the currently available migration context fields.
    ///
    /// The Rust migration `Context` does not yet carry dialect, session-key size,
    /// or signing-key material, so callers provide those values explicitly.
    #[must_use]
    pub const fn from_context(
        context: &Context,
        dialect: u16,
        session_key_size: usize,
        signing_key: SigningKey,
    ) -> Self {
        Self::new(dialect, context.session_id, session_key_size, signing_key)
    }

    /// Returns the algorithm selected for this context's dialect.
    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::for_dialect(self.dialect)
    }

    /// Returns whether the context has enough state for a PDU signature attempt.
    #[must_use]
    pub const fn can_sign(&self) -> bool {
        self.session_id != 0 && self.session_key_size != 0
    }
}

/// Error type for SMB2 signing skeleton helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningError {
    /// No I/O vectors were provided.
    MissingVectors,
    /// The first vector is not large enough to contain an SMB2 header.
    HeaderTooSmall,
    /// The first vector does not match the fixed SMB2 header size expected by C.
    HeaderSizeMismatch,
    /// The PDU has too few output vectors to sign.
    TooFewVectors,
    /// A session key is required before signing can proceed.
    MissingSessionKey,
    /// The signature field could not be written back to the header vector.
    SignatureWriteFailed,
}

/// Result alias used by SMB2 signing skeleton helpers.
pub type SigningResult<T> = core::result::Result<T, SigningError>;

/// Summary of a signature calculation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureCalculation {
    /// Algorithm selected from the negotiated dialect.
    pub algorithm: SigningAlgorithm,
    /// Total number of bytes covered by the signature request.
    pub message_len: usize,
    /// Placeholder signature bytes for the future protocol implementation.
    pub signature: Signature,
}

/// AES-CMAC subkeys mirrored from the legacy `aes_cmac_sub_keys` helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AesCmacSubKeys {
    /// First AES-CMAC subkey.
    pub sub_key1: AesCmac,
    /// Second AES-CMAC subkey.
    pub sub_key2: AesCmac,
}

/// Calculates SMB3 AES-CMAC-128 output for a complete message.
///
/// This is a migration skeleton. It preserves the C API shape and validates the
/// inputs, but it intentionally returns a zero MAC until the AES backend is wired
/// into the Rust implementation.
#[must_use]
pub fn smb3_aes_cmac_128(key: &SigningKey, msg: &[u8]) -> AesCmac {
    let _ = aes_cmac_sub_keys(key);
    let _ = msg;
    [0; AES_BLOCK_SIZE]
}

/// Calculates an SMB2/SMB3 signature over a mutable I/O vector list.
///
/// The first vector's header signature field is cleared before the placeholder
/// signature is produced, matching `smb2_calc_signature` in C.
///
/// # Errors
///
/// Returns [`SigningError::MissingVectors`] when no vectors are supplied, or
/// [`SigningError::HeaderTooSmall`] when the first vector cannot contain the SMB2
/// signature field.
pub fn smb2_calc_signature(
    signing: &Smb2SigningContext,
    iov: &mut [IoVec],
) -> SigningResult<SignatureCalculation> {
    let Some(first) = iov.first_mut() else {
        return Err(SigningError::MissingVectors);
    };
    clear_signature_field(first)?;

    let message_len = iov.iter().map(|vec| vec.buf.len()).sum();
    let signature = match signing.algorithm() {
        SigningAlgorithm::AesCmac128 => smb3_aes_cmac_128(&signing.signing_key, &[]),
        SigningAlgorithm::HmacSha256Truncated => [0; SMB2_SIGNATURE_SIZE],
    };

    Ok(SignatureCalculation {
        algorithm: signing.algorithm(),
        message_len,
        signature,
    })
}

/// Adds a signature to an outgoing PDU skeleton.
///
/// This mirrors the validation and header-flag side effects of
/// `smb2_pdu_add_signature` while leaving cryptographic bytes as placeholders.
///
/// # Errors
///
/// Returns a [`SigningError`] if the PDU lacks the expected vectors/header shape,
/// if session key material is missing, or if the signature cannot be written back
/// to the first vector.
pub fn smb2_pdu_add_signature(signing: &Smb2SigningContext, pdu: &mut Pdu) -> SigningResult<()> {
    if pdu.header.command == Smb2Command::SessionSetup.as_u16()
        && (pdu.header.status != 0 || pdu.header.flags & SMB2_FLAGS_SERVER_TO_REDIR == 0)
    {
        return Ok(());
    }
    if pdu.out.vectors.len() < 2 {
        return Err(SigningError::TooFewVectors);
    }
    if pdu.out.vectors.first().map_or(0, |iov| iov.buf.len()) != SMB2_HEADER_SIZE {
        return Err(SigningError::HeaderSizeMismatch);
    }
    if signing.session_id == 0 {
        return Ok(());
    }
    if signing.session_key_size == 0 {
        return Err(SigningError::MissingSessionKey);
    }

    pdu.header.flags |= SMB2_FLAGS_SIGNED;
    {
        let Some(first) = pdu.out.vectors.first_mut() else {
            return Err(SigningError::MissingVectors);
        };
        smb2_set_uint32(first, 16, pdu.header.flags)
            .map_err(|_error| SigningError::HeaderTooSmall)?;
    }

    let calculation = smb2_calc_signature(signing, &mut pdu.out.vectors)?;
    pdu.header.signature = calculation.signature;
    let Some(first) = pdu.out.vectors.first_mut() else {
        return Err(SigningError::MissingVectors);
    };
    write_signature_field(first, &pdu.header.signature)
}

/// Checks a PDU signature.
///
/// The legacy C function currently returns success without validation. The Rust
/// skeleton preserves that behavior while keeping the future verification hook in
/// the signing module.
///
/// # Errors
///
/// This skeleton currently returns `Ok(())` for all inputs.
pub fn smb2_pdu_check_signature(signing: &Smb2SigningContext, pdu: &Pdu) -> SigningResult<()> {
    let _ = signing;
    let _ = pdu;
    Ok(())
}

fn aes_cmac_shift_left(data: &mut AesCmac) -> u8 {
    let mut carry_in = 0;
    let mut carry_out = 0;
    for byte in data.iter_mut().rev() {
        carry_out = (*byte & 0x80) >> 7;
        *byte = (*byte << 1) | carry_in;
        carry_in = carry_out;
    }
    carry_out
}

fn aes_cmac_xor(data: &mut AesCmac, value: &AesCmac) {
    for (left, right) in data.iter_mut().zip(value.iter()) {
        *left ^= *right;
    }
}

fn aes_cmac_sub_keys(key: &SigningKey) -> AesCmacSubKeys {
    const RB: AesCmac = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87];

    let _ = key;
    let mut sub_key1 = [0; AES_BLOCK_SIZE];
    if aes_cmac_shift_left(&mut sub_key1) != 0 {
        aes_cmac_xor(&mut sub_key1, &RB);
    }

    let mut sub_key2 = sub_key1;
    if aes_cmac_shift_left(&mut sub_key2) != 0 {
        aes_cmac_xor(&mut sub_key2, &RB);
    }

    AesCmacSubKeys { sub_key1, sub_key2 }
}

fn clear_signature_field(iov: &mut IoVec) -> SigningResult<()> {
    let Some(signature) = iov
        .buf
        .get_mut(SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_SIZE)
    else {
        return Err(SigningError::HeaderTooSmall);
    };
    signature.fill(0);
    Ok(())
}

fn write_signature_field(iov: &mut IoVec, signature: &Signature) -> SigningResult<()> {
    let Some(target) = iov
        .buf
        .get_mut(SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_SIZE)
    else {
        return Err(SigningError::SignatureWriteFailed);
    };
    target.copy_from_slice(signature);
    Ok(())
}
