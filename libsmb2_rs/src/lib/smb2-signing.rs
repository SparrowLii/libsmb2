//! SMB2 signing helpers migrated from `lib/smb2-signing.c`.
//!
//! The legacy C file owns SMB2/SMB3 signature calculation, signature flagging on
//! outgoing PDUs, and a currently-empty signature verification hook. This Rust
//! module mirrors those responsibilities as migration-safe data structures and
//! local HMAC-SHA256/AES-CMAC signing helpers. Network I/O remains outside this
//! module.

use super::aes::{Aes128Key, AesBlock, AesError};
use super::hmac::{hmac, HmacContext, HmacError, ShaVersion};
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

/// SMB3 preauth hash size used by SMB 3.1.1 key derivation.
pub const SMB2_PREAUTH_HASH_SIZE: usize = 64;

const SMB2_VERSION_0302: u16 = 0x0302;
const SMB2AESCMAC_LABEL: &[u8] = b"SMB2AESCMAC\0";
const SMB_SIGN_CONTEXT: &[u8] = b"SmbSign\0";
const SMB2AESCCM_LABEL: &[u8] = b"SMB2AESCCM\0";
const SERVER_IN_CONTEXT: &[u8] = b"ServerIn \0";
const SERVER_OUT_CONTEXT: &[u8] = b"ServerOut\0";
const SMB_SIGNING_KEY_LABEL: &[u8] = b"SMBSigningKey\0";
const SMB_C2S_CIPHER_KEY_LABEL: &[u8] = b"SMBC2SCipherKey\0";
const SMB_S2C_CIPHER_KEY_LABEL: &[u8] = b"SMBS2CCipherKey\0";

/// SMB signing and sealing key material derived from an authenticated session key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionDerivedKeys {
    /// Signing key used by SMB2 HMAC-SHA256 or SMB3 AES-CMAC signing.
    pub signing_key: SigningKey,
    /// Client-to-server sealing key used for outbound SMB3 AES-CCM.
    pub serverin_key: SigningKey,
    /// Server-to-client sealing key used for inbound SMB3 AES-CCM.
    pub serverout_key: SigningKey,
}

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
    /// The supplied signing key material is empty or all zeroes.
    InvalidSigningKey,
    /// SMB 3.1.1 key derivation requires a preauth integrity hash.
    MissingPreauthHash,
    /// The received PDU signature does not match the recomputed signature.
    SignatureMismatch,
    /// The signature field could not be written back to the header vector.
    SignatureWriteFailed,
    /// HMAC-SHA256 failed while signing or deriving keys.
    Hmac(HmacError),
    /// AES-128 block encryption failed while calculating AES-CMAC.
    Aes(AesError),
}

impl From<HmacError> for SigningError {
    fn from(value: HmacError) -> Self {
        Self::Hmac(value)
    }
}

impl From<AesError> for SigningError {
    fn from(value: AesError) -> Self {
        Self::Aes(value)
    }
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
    /// Signature bytes produced by the selected signing algorithm.
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
/// This preserves the C API shape while using the migrated AES-128 block helper
/// to calculate CMAC subkeys and message authentication blocks.
pub fn smb3_aes_cmac_128(key: &SigningKey, msg: &[u8]) -> SigningResult<AesCmac> {
    validate_signing_key(key)?;

    let sub_keys = aes_cmac_sub_keys(key)?;
    let block_count = if msg.is_empty() {
        1
    } else {
        msg.len().div_ceil(AES_BLOCK_SIZE)
    };
    let last_complete = !msg.is_empty() && msg.len().is_multiple_of(AES_BLOCK_SIZE);
    let mut mac = [0; AES_BLOCK_SIZE];

    for block in msg
        .chunks(AES_BLOCK_SIZE)
        .take(block_count.saturating_sub(1))
    {
        aes_cmac_xor_slice(&mut mac, block);
        mac = aes128_encrypt_block(key, mac)?;
    }

    let last_offset = AES_BLOCK_SIZE * block_count.saturating_sub(1);
    let mut last = [0; AES_BLOCK_SIZE];
    if last_complete {
        let Some(block) = msg.get(last_offset..last_offset + AES_BLOCK_SIZE) else {
            return Err(SigningError::HeaderTooSmall);
        };
        last.copy_from_slice(block);
        aes_cmac_xor(&mut last, &sub_keys.sub_key1);
    } else {
        let tail = msg.get(last_offset..).ok_or(SigningError::HeaderTooSmall)?;
        last[..tail.len()].copy_from_slice(tail);
        if tail.len() < AES_BLOCK_SIZE {
            last[tail.len()] = 0x80;
        }
        aes_cmac_xor(&mut last, &sub_keys.sub_key2);
    }

    aes_cmac_xor(&mut mac, &last);
    aes128_encrypt_block(key, mac)
}

/// Derives SMB signing and sealing keys from session key metadata.
///
/// # Errors
///
/// Returns [`SigningError::Hmac`] when the HMAC-SHA256 counter-mode KDF fails.
pub fn derive_session_keys(
    dialect: u16,
    session_key: &[u8],
    preauth_hash: Option<&[u8; SMB2_PREAUTH_HASH_SIZE]>,
) -> SigningResult<SessionDerivedKeys> {
    if session_key.is_empty() {
        return Err(SigningError::MissingSessionKey);
    }

    let mut keys = SessionDerivedKeys {
        signing_key: [0; SMB2_KEY_SIZE],
        serverin_key: [0; SMB2_KEY_SIZE],
        serverout_key: [0; SMB2_KEY_SIZE],
    };

    if dialect <= SMB2_VERSION_0210 {
        let len = session_key.len().min(SMB2_KEY_SIZE);
        keys.signing_key[..len].copy_from_slice(&session_key[..len]);
        return Ok(keys);
    }

    if dialect <= SMB2_VERSION_0302 {
        keys.signing_key = smb2_derive_key(session_key, SMB2AESCMAC_LABEL, SMB_SIGN_CONTEXT)?;
        keys.serverin_key = smb2_derive_key(session_key, SMB2AESCCM_LABEL, SERVER_IN_CONTEXT)?;
        keys.serverout_key = smb2_derive_key(session_key, SMB2AESCCM_LABEL, SERVER_OUT_CONTEXT)?;
    } else {
        let Some(preauth_hash) = preauth_hash else {
            return Err(SigningError::MissingPreauthHash);
        };
        keys.signing_key = smb2_derive_key(session_key, SMB_SIGNING_KEY_LABEL, preauth_hash)?;
        keys.serverin_key = smb2_derive_key(session_key, SMB_C2S_CIPHER_KEY_LABEL, preauth_hash)?;
        keys.serverout_key = smb2_derive_key(session_key, SMB_S2C_CIPHER_KEY_LABEL, preauth_hash)?;
    }

    Ok(keys)
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
    if signing.session_key_size == 0 {
        return Err(SigningError::MissingSessionKey);
    }
    validate_signing_key(&signing.signing_key)?;

    let Some(first) = iov.first_mut() else {
        return Err(SigningError::MissingVectors);
    };
    clear_signature_field(first)?;

    let message_len = iov.iter().map(|vec| vec.buf.len()).sum();
    let signature = match signing.algorithm() {
        SigningAlgorithm::AesCmac128 => {
            let msg = collect_iov_message(iov, message_len);
            smb3_aes_cmac_128(&signing.signing_key, &msg)?
        }
        SigningAlgorithm::HmacSha256Truncated => hmac_sha256_truncated(iov, &signing.signing_key)?,
    };

    Ok(SignatureCalculation {
        algorithm: signing.algorithm(),
        message_len,
        signature,
    })
}

/// Adds a signature to an outgoing PDU skeleton.
///
/// This mirrors the validation, header-flag side effects, and cryptographic
/// signature calculation of `smb2_pdu_add_signature`.
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
pub fn smb2_pdu_check_signature(signing: &Smb2SigningContext, pdu: &Pdu) -> SigningResult<()> {
    let Some(first) = pdu.input.vectors.first() else {
        return Err(SigningError::MissingVectors);
    };
    let Some(expected) = first
        .buf
        .get(SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_SIZE)
    else {
        return Err(SigningError::HeaderTooSmall);
    };
    let mut expected_signature = [0; SMB2_SIGNATURE_SIZE];
    expected_signature.copy_from_slice(expected);

    let mut vectors = pdu.input.vectors.clone();
    let actual = smb2_calc_signature(signing, &mut vectors)?.signature;
    if signatures_equal(&actual, &expected_signature) {
        Ok(())
    } else {
        Err(SigningError::SignatureMismatch)
    }
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

fn aes_cmac_sub_keys(key: &SigningKey) -> SigningResult<AesCmacSubKeys> {
    const RB: AesCmac = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87];

    let mut sub_key1 = aes128_encrypt_block(key, [0; AES_BLOCK_SIZE])?;
    if aes_cmac_shift_left(&mut sub_key1) != 0 {
        aes_cmac_xor(&mut sub_key1, &RB);
    }

    let mut sub_key2 = sub_key1;
    if aes_cmac_shift_left(&mut sub_key2) != 0 {
        aes_cmac_xor(&mut sub_key2, &RB);
    }

    Ok(AesCmacSubKeys { sub_key1, sub_key2 })
}

fn aes128_encrypt_block(key: &SigningKey, block: AesCmac) -> SigningResult<AesCmac> {
    Ok(super::aes::aes128_ecb_encrypt(AesBlock::new(block), Aes128Key::new(*key))?.into_bytes())
}

fn aes_cmac_xor_slice(data: &mut AesCmac, value: &[u8]) {
    for (left, right) in data.iter_mut().zip(value.iter()) {
        *left ^= *right;
    }
}

fn hmac_sha256_truncated(iov: &[IoVec], key: &SigningKey) -> SigningResult<Signature> {
    validate_signing_key(key)?;

    let mut ctx = HmacContext::new(ShaVersion::Sha256, key)?;
    for vec in iov {
        ctx.input(&vec.buf)?;
    }
    let digest = ctx.result()?;
    let mut signature = [0; SMB2_SIGNATURE_SIZE];
    signature.copy_from_slice(&digest.as_bytes()[..SMB2_SIGNATURE_SIZE]);
    Ok(signature)
}

fn collect_iov_message(iov: &[IoVec], message_len: usize) -> Vec<u8> {
    let mut msg = Vec::with_capacity(message_len);
    for vec in iov {
        msg.extend_from_slice(&vec.buf);
    }
    msg
}

fn signatures_equal(left: &Signature, right: &Signature) -> bool {
    left.iter()
        .zip(right.iter())
        .fold(0, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn smb2_derive_key(session_key: &[u8], label: &[u8], context: &[u8]) -> SigningResult<SigningKey> {
    let mut input_key = [0; SMB2_KEY_SIZE];
    let key_len = session_key.len().min(SMB2_KEY_SIZE);
    input_key[..key_len].copy_from_slice(&session_key[..key_len]);

    let mut text = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
    text.extend_from_slice(&1_u32.to_be_bytes());
    text.extend_from_slice(label);
    text.push(0);
    text.extend_from_slice(context);
    text.extend_from_slice(&(SMB2_KEY_SIZE as u32 * 8).to_be_bytes());

    let digest = hmac(ShaVersion::Sha256, &text, &input_key)?;
    let mut key = [0; SMB2_KEY_SIZE];
    key.copy_from_slice(&digest.as_bytes()[..SMB2_KEY_SIZE]);
    Ok(key)
}

fn validate_signing_key(key: &SigningKey) -> SigningResult<()> {
    if key.iter().all(|byte| *byte == 0) {
        Err(SigningError::InvalidSigningKey)
    } else {
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::include::libsmb2_private::{IoVectors, Smb2Header};
    use crate::include::smb2::smb2::Command;

    fn signing_context() -> Smb2SigningContext {
        Smb2SigningContext::new(
            SMB2_VERSION_0210,
            0x1122_3344,
            SMB2_KEY_SIZE,
            [0x42; SMB2_KEY_SIZE],
        )
    }

    fn header_with_signature(signature: Signature) -> Vec<u8> {
        let mut header = vec![0_u8; SMB2_HEADER_SIZE];
        header[SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_SIZE]
            .copy_from_slice(&signature);
        header
    }

    #[test]
    fn calc_signature_clears_header_signature_before_hashing() {
        let signing = signing_context();
        let mut with_signature = vec![
            IoVec::new(header_with_signature([0xaa; SMB2_SIGNATURE_SIZE])),
            IoVec::new(b"payload".to_vec()),
        ];
        let mut already_clear = vec![
            IoVec::new(header_with_signature([0; SMB2_SIGNATURE_SIZE])),
            IoVec::new(b"payload".to_vec()),
        ];

        let left = smb2_calc_signature(&signing, &mut with_signature).unwrap();
        let right = smb2_calc_signature(&signing, &mut already_clear).unwrap();

        assert_eq!(left.signature, right.signature);
        assert_eq!(
            &with_signature[0].buf
                [SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_SIZE],
            &[0; SMB2_SIGNATURE_SIZE]
        );
    }

    #[test]
    fn pdu_add_signature_sets_flag_and_writes_signature_field() {
        let signing = signing_context();
        let mut header = Smb2Header::for_command(Command::Echo);
        header.session_id = signing.session_id;
        let mut pdu = Pdu::from_parts(
            header,
            IoVectors {
                done: 0,
                total_size: 0,
                vectors: vec![
                    IoVec::new(vec![0; SMB2_HEADER_SIZE]),
                    IoVec::new(b"payload".to_vec()),
                ],
            },
            None,
        );

        smb2_pdu_add_signature(&signing, &mut pdu).unwrap();

        assert_eq!(pdu.header.flags & SMB2_FLAGS_SIGNED, SMB2_FLAGS_SIGNED);
        assert_ne!(pdu.header.signature, [0; SMB2_SIGNATURE_SIZE]);
        assert_eq!(
            &pdu.out.vectors[0].buf
                [SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_SIZE],
            &pdu.header.signature
        );
    }

    #[test]
    fn pdu_check_signature_accepts_valid_signature_and_rejects_tamper() {
        let signing = signing_context();
        let mut vectors = vec![
            IoVec::new(header_with_signature([0; SMB2_SIGNATURE_SIZE])),
            IoVec::new(b"payload".to_vec()),
        ];
        let signature = smb2_calc_signature(&signing, &mut vectors)
            .unwrap()
            .signature;
        vectors[0].buf[SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_SIZE]
            .copy_from_slice(&signature);

        let mut pdu = Pdu::from_parts(
            Smb2Header::for_command(Command::Echo),
            IoVectors::new(),
            None,
        );
        pdu.input = IoVectors {
            done: 0,
            total_size: vectors.iter().map(IoVec::len).sum(),
            vectors,
        };
        assert_eq!(smb2_pdu_check_signature(&signing, &pdu), Ok(()));

        pdu.input.vectors[1].buf[0] ^= 1;
        assert_eq!(
            smb2_pdu_check_signature(&signing, &pdu),
            Err(SigningError::SignatureMismatch)
        );
    }

    #[test]
    fn signing_rejects_missing_or_zero_key_material() {
        assert_eq!(
            derive_session_keys(SMB2_VERSION_0210, &[], None),
            Err(SigningError::MissingSessionKey)
        );

        let mut vectors = vec![IoVec::new(vec![0; SMB2_HEADER_SIZE])];
        let signing =
            Smb2SigningContext::new(SMB2_VERSION_0210, 1, SMB2_KEY_SIZE, [0; SMB2_KEY_SIZE]);
        assert_eq!(
            smb2_calc_signature(&signing, &mut vectors),
            Err(SigningError::InvalidSigningKey)
        );
    }
}
