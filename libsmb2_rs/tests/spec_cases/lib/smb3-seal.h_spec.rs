use libsmb2_rs::lib::aes128ccm::{Aes128CcmError, ReferenceAes128BlockEncryptor};
use libsmb2_rs::lib::smb3_seal::{
    smb3_decrypt_pdu_with, smb3_encrypt_pdu, smb3_encrypt_pdu_with, Smb3EncryptOutcome,
    Smb3SealContext, Smb3SealError, Smb3SealPdu, SMB3_AES128_CCM_NONCE_SIZE,
    SMB3_TRANSFORM_HEADER_SIZE, SMB3_TRANSFORM_PROTOCOL_ID,
};

fn context(seal: bool) -> Smb3SealContext {
    Smb3SealContext {
        seal,
        session_id: 0x99,
        serverin_key: [0x44; 16],
        serverout_key: [0x44; 16],
        aes128_ccm_nonce: [0; SMB3_AES128_CCM_NONCE_SIZE],
        used_outbound_nonces: Vec::new(),
        seen_inbound_nonces: Vec::new(),
    }
}

fn pdu() -> Smb3SealPdu {
    Smb3SealPdu {
        seal: true,
        out_vectors: vec![b"data".to_vec()],
        crypt: Vec::new(),
    }
}

// Trace: `lib/smb3-seal.h:smb3_encrypt_pdu`, `lib/smb3-seal.c:smb3_encrypt_pdu`
// Spec: smb3_encrypt_pdu SMB3 outbound transform sealing#sealing disabled is a no-op
// - **GIVEN** 调用方提供 `struct smb2_context *smb2` 和 `struct smb2_pdu *pdu`，且 `smb2->seal` 或 `pdu->seal` 为 0
// - **WHEN** 调用 `smb3_encrypt_pdu(smb2, pdu)`
// - **THEN** 函数返回 0，并保持未执行 SMB3 transform 加密分配路径
#[test]
fn test_smb3_seal_h_sealing_disabled_is_a_no_op() {
    let mut context = context(false);
    let mut pdu = pdu();

    assert_eq!(
        smb3_encrypt_pdu(&mut context, &mut pdu),
        Ok(Smb3EncryptOutcome::Skipped)
    );
    assert!(pdu.crypt.is_empty());
}

// Trace: `lib/smb3-seal.h:smb3_encrypt_pdu`, `lib/smb3-seal.c:smb3_encrypt_pdu`
// Spec: smb3_encrypt_pdu SMB3 outbound transform sealing#transform buffer allocation failure disables pdu sealing
// - **GIVEN** `smb2->seal` 和 `pdu->seal` 均启用，且 transform 缓冲区分配失败
// - **WHEN** 调用 `smb3_encrypt_pdu(smb2, pdu)`
// - **THEN** 函数 MUST 将 `pdu->seal` 置为 0，并返回 -1
#[test]
fn test_smb3_seal_h_transform_buffer_allocation_failure_disables_pdu_sealing() {
    let mut context = context(true);
    let mut pdu = Smb3SealPdu::new();
    pdu.seal = true;

    assert_eq!(
        smb3_encrypt_pdu(&mut context, &mut pdu),
        Err(Smb3SealError::MissingPayload)
    );
    assert!(!pdu.seal);
}

// Trace: `lib/smb3-seal.h:smb3_encrypt_pdu`, `lib/smb3-seal.c:smb3_encrypt_pdu`, `lib/pdu.c:smb2_queue_pdu`
// Spec: smb3_encrypt_pdu SMB3 outbound transform sealing#enabled sealing emits AES-128-CCM transform payload
// - **GIVEN** `smb2->seal` 和 `pdu->seal` 均启用，且 PDU 及 compound PDU 的输出 iovec 可用于计算明文长度
// - **WHEN** 调用 `smb3_encrypt_pdu(smb2, pdu)`
// - **THEN** 函数 MUST 创建以 52 字节 transform header 开头的 `pdu->crypt` 缓冲区，写入 `0xFD 'S' 'M' 'B'` protocol id、随机 nonce 字节、原始消息大小、`SMB_ENCRYPTION_AES128_CCM` 算法、`smb2->session_id`，并通过 AES-128-CCM 生成认证标签后设置 `pdu->crypt_len`
#[test]
fn test_smb3_seal_h_enabled_sealing_emits_aes_128_ccm_transform_payload() {
    let mut context = context(true);
    let mut pdu = pdu();

    assert_eq!(
        smb3_encrypt_pdu_with(
            &mut context,
            &mut pdu,
            &[6; SMB3_AES128_CCM_NONCE_SIZE],
            &ReferenceAes128BlockEncryptor
        ),
        Ok(Smb3EncryptOutcome::Sealed {
            transform_len: SMB3_TRANSFORM_HEADER_SIZE + b"data".len()
        })
    );
    assert_eq!(&pdu.crypt[0..4], &SMB3_TRANSFORM_PROTOCOL_ID);
    assert_ne!(&pdu.crypt[4..20], &[0; 16]);
    assert_eq!(&pdu.crypt[36..40], &(b"data".len() as u32).to_le_bytes());
}

// Trace: `lib/smb3-seal.h:smb3_decrypt_pdu`, `lib/smb3-seal.c:smb3_decrypt_pdu`
// Spec: smb3_decrypt_pdu SMB3 inbound transform unsealing#decryption failure reports error
// - **GIVEN** `smb2->in` 包含 SMB3 transform header iovec 和密文 payload iovec，且 AES-128-CCM 解密返回失败
// - **WHEN** 调用 `smb3_decrypt_pdu(smb2)`
// - **THEN** 函数 MUST 设置错误消息 `Failed to decrypt PDU` 并返回 -1
#[test]
fn test_smb3_seal_h_decryption_failure_reports_error() {
    let mut enc_context = context(true);
    let mut pdu = pdu();
    smb3_encrypt_pdu_with(
        &mut enc_context,
        &mut pdu,
        &[7; SMB3_AES128_CCM_NONCE_SIZE],
        &ReferenceAes128BlockEncryptor,
    )
    .unwrap();
    pdu.crypt[4] ^= 1;

    assert_eq!(
        smb3_decrypt_pdu_with(
            &mut context(true),
            &pdu.crypt,
            &ReferenceAes128BlockEncryptor
        ),
        Err(Smb3SealError::Aes128Ccm(
            Aes128CcmError::AuthenticationFailed
        ))
    );
}

// Trace: `lib/smb3-seal.h:smb3_decrypt_pdu`, `lib/smb3-seal.c:smb3_decrypt_pdu`, `lib/socket.c:smb2_read_data`
// Spec: smb3_decrypt_pdu SMB3 inbound transform unsealing#first decrypted fragment resets receive parser
// - **GIVEN** AES-128-CCM 解密成功，且 `smb2->in.num_done` 为 0
// - **WHEN** 调用 `smb3_decrypt_pdu(smb2)`
// - **THEN** 函数 MUST 将解密 payload 转移到 `smb2->enc`，释放旧输入 iovector，将 `smb2->spl` 设置为解密 payload 长度，将 `smb2->recv_state` 设置为 `SMB2_RECV_HEADER`，并添加用于解析 SMB2 header 的 iovector
#[test]
fn test_smb3_seal_h_first_decrypted_fragment_resets_receive_parser() {
    let mut enc_context = context(true);
    let mut pdu = pdu();
    smb3_encrypt_pdu_with(
        &mut enc_context,
        &mut pdu,
        &[8; SMB3_AES128_CCM_NONCE_SIZE],
        &ReferenceAes128BlockEncryptor,
    )
    .unwrap();

    let plaintext = smb3_decrypt_pdu_with(
        &mut context(true),
        &pdu.crypt,
        &ReferenceAes128BlockEncryptor,
    )
    .unwrap();

    assert_eq!(plaintext, b"data");
}

// Trace: `lib/smb3-seal.h:smb3_decrypt_pdu`, `lib/smb3-seal.c:smb3_decrypt_pdu`
// Spec: smb3_decrypt_pdu SMB3 inbound transform unsealing#decrypted payload is parsed and released
// - **GIVEN** AES-128-CCM 解密成功，且接收解析器已准备从 `smb2->enc` 读取解密 payload
// - **WHEN** `smb3_decrypt_pdu(smb2)` 调用 `smb2_read_from_buf(smb2)` 完成解析
// - **THEN** 函数 MUST 释放 `smb2->enc`，将 `smb2->enc` 置为 `NULL`，并返回 `smb2_read_from_buf` 的结果
#[test]
fn test_smb3_seal_h_decrypted_payload_is_parsed_and_released() {
    let mut enc_context = context(true);
    let mut pdu = pdu();
    smb3_encrypt_pdu_with(
        &mut enc_context,
        &mut pdu,
        &[9; SMB3_AES128_CCM_NONCE_SIZE],
        &ReferenceAes128BlockEncryptor,
    )
    .unwrap();
    let mut dec_context = context(true);

    let plaintext =
        smb3_decrypt_pdu_with(&mut dec_context, &pdu.crypt, &ReferenceAes128BlockEncryptor)
            .unwrap();

    assert_eq!(plaintext, b"data");
    assert_eq!(dec_context.seen_inbound_nonces.len(), 1);
}
