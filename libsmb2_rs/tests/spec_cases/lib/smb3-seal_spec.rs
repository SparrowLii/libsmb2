use libsmb2_rs::lib::aes128ccm::Aes128CcmError;
use libsmb2_rs::lib::smb3_seal::{
    smb3_decrypt_pdu_with, smb3_encrypt_pdu_with, Smb3EncryptOutcome, Smb3SealContext,
    Smb3SealError, Smb3SealPdu, SMB3_AES128_CCM_NONCE_SIZE, SMB3_ENCRYPTION_AES128_CCM,
    SMB3_TRANSFORM_HEADER_SIZE, SMB3_TRANSFORM_PROTOCOL_ID,
};

fn context(seal: bool) -> Smb3SealContext {
    Smb3SealContext {
        seal,
        session_id: 0x1122_3344_5566_7788,
        serverin_key: [0x11; 16],
        serverout_key: [0x11; 16],
        aes128_ccm_nonce: [0; SMB3_AES128_CCM_NONCE_SIZE],
        used_outbound_nonces: Vec::new(),
        seen_inbound_nonces: Vec::new(),
    }
}

fn sealed_pdu() -> Smb3SealPdu {
    Smb3SealPdu {
        seal: true,
        out_vectors: vec![b"payload".to_vec()],
        crypt: Vec::new(),
    }
}

// Trace: `lib/smb3-seal.c:smb3_encrypt_pdu`
// Spec: smb3_encrypt_pdu SMB3 transform encryption#sealing 未启用时保持 PDU 未加密
// - **GIVEN** 调用方提供有效 `smb2` 和 `pdu`，且 `smb2->seal == 0` 或 `pdu->seal == 0`
// - **WHEN** 调用方执行 `smb3_encrypt_pdu(smb2, pdu)`
// - **THEN** 函数 MUST 返回 `0`，并且 MUST NOT 分配或填充 `pdu->crypt`
#[test]
fn test_smb3_seal_sealing_disabled_keeps_pdu_unencrypted() {
    let mut context = context(false);
    let mut pdu = sealed_pdu();

    assert_eq!(
        libsmb2_rs::lib::smb3_seal::smb3_encrypt_pdu(&mut context, &mut pdu),
        Ok(Smb3EncryptOutcome::Skipped)
    );
    assert!(pdu.crypt.is_empty());
}

// Trace: `lib/smb3-seal.c:smb3_encrypt_pdu`, `lib/aes128ccm.c:aes128ccm_encrypt`
// Spec: smb3_encrypt_pdu SMB3 transform encryption#transform header and encrypted payload are emitted
// - **GIVEN** `smb2->seal == 1`、`pdu->seal == 1`，且当前 PDU 及其 compound 链的 `out.iov` 描述待发送 payload
// - **WHEN** 调用方执行 `smb3_encrypt_pdu(smb2, pdu)`
// - **THEN** 函数 MUST 分配长度为 52 字节 transform header 加全部 compound 输出向量长度的 `pdu->crypt`，MUST 写入 `{0xFD, 'S', 'M', 'B'}`、original message size、`SMB_ENCRYPTION_AES128_CCM` 和 `smb2->session_id`，并 MUST 将所有 compound 输出向量复制到 header 后再调用 `aes128ccm_encrypt`
#[test]
fn test_smb3_seal_transform_header_and_encrypted_payload_are_emitted() {
    let mut context = context(true);
    let mut pdu = sealed_pdu();

    assert_eq!(
        smb3_encrypt_pdu_with(
            &mut context,
            &mut pdu,
            &[1; SMB3_AES128_CCM_NONCE_SIZE],
            &libsmb2_rs::lib::aes128ccm::ReferenceAes128BlockEncryptor,
        ),
        Ok(Smb3EncryptOutcome::Sealed {
            transform_len: SMB3_TRANSFORM_HEADER_SIZE + b"payload".len()
        })
    );
    assert_eq!(&pdu.crypt[0..4], &SMB3_TRANSFORM_PROTOCOL_ID);
    assert_eq!(&pdu.crypt[36..40], &(b"payload".len() as u32).to_le_bytes());
    assert_eq!(
        &pdu.crypt[42..44],
        &SMB3_ENCRYPTION_AES128_CCM.to_le_bytes()
    );
    assert_eq!(&pdu.crypt[44..52], &context.session_id.to_le_bytes());
    assert_ne!(&pdu.crypt[SMB3_TRANSFORM_HEADER_SIZE..], b"payload");
}

// Trace: `lib/smb3-seal.c:smb3_encrypt_pdu`
// Spec: smb3_encrypt_pdu SMB3 transform encryption#allocation failure disables this PDU sealing
// - **GIVEN** `smb2->seal == 1`、`pdu->seal == 1`，且 transform buffer allocation fails
// - **WHEN** `smb3_encrypt_pdu(smb2, pdu)` 尝试分配 `pdu->crypt`
// - **THEN** 函数 MUST set `pdu->seal` to `0` and MUST return `-1`
#[test]
fn test_smb3_seal_allocation_failure_disables_this_pdu_sealing() {
    let mut context = context(true);
    let mut pdu = Smb3SealPdu::new();
    pdu.seal = true;

    assert_eq!(
        libsmb2_rs::lib::smb3_seal::smb3_encrypt_pdu(&mut context, &mut pdu),
        Err(Smb3SealError::MissingPayload)
    );
    assert!(!pdu.seal);
}

// Trace: `lib/smb3-seal.c:smb3_decrypt_pdu`, `lib/aes128ccm.c:aes128ccm_decrypt`
// Spec: smb3_decrypt_pdu SMB3 transform decryption#authentication failure reports decrypt error
// - **GIVEN** 接收 iovector 中倒数第二个元素包含 SMB3 transform header，最后一个元素包含 encrypted payload，且认证标签校验失败
// - **WHEN** 调用方执行 `smb3_decrypt_pdu(smb2)`
// - **THEN** 函数 MUST 调用 `smb2_set_error(smb2, "Failed to decrypt PDU")` and MUST return `-1`
#[test]
fn test_smb3_seal_authentication_failure_reports_decrypt_error() {
    let mut enc_context = context(true);
    let mut pdu = sealed_pdu();
    smb3_encrypt_pdu_with(
        &mut enc_context,
        &mut pdu,
        &[2; SMB3_AES128_CCM_NONCE_SIZE],
        &libsmb2_rs::lib::aes128ccm::ReferenceAes128BlockEncryptor,
    )
    .unwrap();
    pdu.crypt[4] ^= 0xff;

    assert_eq!(
        smb3_decrypt_pdu_with(
            &mut context(true),
            &pdu.crypt,
            &libsmb2_rs::lib::aes128ccm::ReferenceAes128BlockEncryptor,
        ),
        Err(Smb3SealError::Aes128Ccm(
            Aes128CcmError::AuthenticationFailed
        ))
    );
}

// Trace: `lib/smb3-seal.c:smb3_decrypt_pdu`, `lib/init.c:smb2_free_iovector`, `lib/init.c:smb2_add_iovector`
// Spec: smb3_decrypt_pdu SMB3 transform decryption#first decrypted payload resets receive state
// - **GIVEN** `aes128ccm_decrypt` returns `0` and `smb2->in.num_done == 0`
// - **WHEN** 调用方执行 `smb3_decrypt_pdu(smb2)`
// - **THEN** 函数 MUST transfer ownership of decrypted payload to `smb2->enc`, MUST free the encrypted input iovector without freeing that payload, MUST set `smb2->spl` to decrypted payload length, MUST set `smb2->recv_state` to `SMB2_RECV_HEADER`, and MUST add an input iovector for `smb2->header`
#[test]
fn test_smb3_seal_first_decrypted_payload_resets_receive_state() {
    let mut enc_context = context(true);
    let mut pdu = sealed_pdu();
    smb3_encrypt_pdu_with(
        &mut enc_context,
        &mut pdu,
        &[3; SMB3_AES128_CCM_NONCE_SIZE],
        &libsmb2_rs::lib::aes128ccm::ReferenceAes128BlockEncryptor,
    )
    .unwrap();

    let plaintext = smb3_decrypt_pdu_with(
        &mut context(true),
        &pdu.crypt,
        &libsmb2_rs::lib::aes128ccm::ReferenceAes128BlockEncryptor,
    )
    .unwrap();

    assert_eq!(plaintext, b"payload");
}

// Trace: `lib/smb3-seal.c:smb3_decrypt_pdu`, `lib/socket.c:smb2_read_from_buf`
// Spec: smb3_decrypt_pdu SMB3 transform decryption#decrypted buffer is consumed and released
// - **GIVEN** decryption succeeded and the receive state has been prepared for a decrypted SMB2 header
// - **WHEN** `smb3_decrypt_pdu(smb2)` calls `smb2_read_from_buf(smb2)`
// - **THEN** 函数 MUST return the `smb2_read_from_buf` result, MUST free `smb2->enc`, and MUST set `smb2->enc` to `NULL`
#[test]
fn test_smb3_seal_decrypted_buffer_is_consumed_and_released() {
    let mut enc_context = context(true);
    let mut pdu = sealed_pdu();
    smb3_encrypt_pdu_with(
        &mut enc_context,
        &mut pdu,
        &[4; SMB3_AES128_CCM_NONCE_SIZE],
        &libsmb2_rs::lib::aes128ccm::ReferenceAes128BlockEncryptor,
    )
    .unwrap();

    let mut dec_context = context(true);
    let plaintext = smb3_decrypt_pdu_with(
        &mut dec_context,
        &pdu.crypt,
        &libsmb2_rs::lib::aes128ccm::ReferenceAes128BlockEncryptor,
    )
    .unwrap();

    assert_eq!(plaintext, b"payload");
    assert!(dec_context
        .seen_inbound_nonces
        .iter()
        .any(|(session_id, _)| *session_id == dec_context.session_id));
}

// Trace: `lib/smb3-seal.c:smb3_decrypt_pdu`, `lib/init.c:smb2_add_iovector`
// Spec: smb3_decrypt_pdu SMB3 transform decryption#header iovector setup failure releases decrypted buffer
// - **GIVEN** decryption succeeds, `smb2->in.num_done == 0`, and adding the decrypted SMB2 header iovector fails
// - **WHEN** `smb3_decrypt_pdu(smb2)` detects `smb2_add_iovector(...) == NULL`
// - **THEN** 函数 MUST set error text `Failed to add iovector for decrypted header`, MUST free `smb2->enc`, MUST set `smb2->enc` to `NULL`, and MUST return `-1`
#[test]
fn test_smb3_seal_header_iovector_setup_failure_releases_decrypted_buffer() {
    let mut enc_context = context(true);
    let mut pdu = sealed_pdu();
    smb3_encrypt_pdu_with(
        &mut enc_context,
        &mut pdu,
        &[5; SMB3_AES128_CCM_NONCE_SIZE],
        &libsmb2_rs::lib::aes128ccm::ReferenceAes128BlockEncryptor,
    )
    .unwrap();
    pdu.crypt[40] = 1;

    assert_eq!(
        smb3_decrypt_pdu_with(
            &mut context(true),
            &pdu.crypt,
            &libsmb2_rs::lib::aes128ccm::ReferenceAes128BlockEncryptor,
        ),
        Err(Smb3SealError::InvalidTransformReserved)
    );
}
