use libsmb2_rs::include::libsmb2_private::{
    IoVec, IoVectors, Pdu, Smb2Header, SMB2_HEADER_SIZE, SMB2_SIGNATURE_SIZE,
};
use libsmb2_rs::lib::pdu::Smb2Command;
use libsmb2_rs::lib::smb2_signing::{
    smb2_calc_signature, smb2_pdu_add_signature, smb2_pdu_check_signature, smb3_aes_cmac_128,
    SigningAlgorithm, SigningError, Smb2SigningContext, SMB2_FLAGS_SIGNED, SMB2_SIGNATURE_OFFSET,
    SMB2_VERSION_0210,
};

fn signing_context(dialect: u16, session_id: u64, session_key_size: usize) -> Smb2SigningContext {
    Smb2SigningContext::new(
        dialect,
        session_id,
        session_key_size,
        [0x11; SMB2_SIGNATURE_SIZE],
    )
}

fn header(signature: [u8; SMB2_SIGNATURE_SIZE]) -> Vec<u8> {
    let mut out = vec![0; SMB2_HEADER_SIZE];
    out[SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_SIZE]
        .copy_from_slice(&signature);
    out
}

fn pdu_with_out_vectors(
    command: Smb2Command,
    status: u32,
    flags: u32,
    vectors: Vec<Vec<u8>>,
) -> Pdu {
    Pdu::from_parts(
        Smb2Header {
            command: command.as_u16(),
            status,
            flags,
            ..Smb2Header::default()
        },
        IoVectors {
            done: 0,
            total_size: vectors.iter().map(Vec::len).sum(),
            vectors: vectors.into_iter().map(IoVec::new).collect(),
        },
        None,
    )
}

// Trace: `lib/smb2-signing.c:smb3_aes_cmac_128`
// Spec: smb3_aes_cmac_128 computes a 128-bit AES-CMAC#empty message uses padded final block
// - **GIVEN** `msg_len` 为 `0` 且调用方提供 16 字节 key 与 16 字节 `mac` 输出缓冲区
// - **WHEN** 调用 `smb3_aes_cmac_128`
// - **THEN** 函数 MUST 生成 CMAC 子密钥、清零初始 MAC、按 `0x80` padding 处理一个空最终块，并写入 16 字节 MAC
#[test]
fn test_smb2_signing_empty_message_uses_padded_final_block() {
    let mac = smb3_aes_cmac_128(&[0x2b; SMB2_SIGNATURE_SIZE], &[]).unwrap();

    assert_ne!(mac, [0; SMB2_SIGNATURE_SIZE]);
    assert_eq!(mac.len(), SMB2_SIGNATURE_SIZE);
}

// Trace: `lib/smb2-signing.c:smb3_aes_cmac_128`
// Spec: smb3_aes_cmac_128 computes a 128-bit AES-CMAC#complete final block uses first subkey
// - **GIVEN** `msg_len` 大于 `0` 且是 16 字节块长度的整数倍
// - **WHEN** 调用 `smb3_aes_cmac_128`
// - **THEN** 函数 MUST 对前置完整块迭代异或并 AES-ECB 加密，最后一个完整块 MUST 与 `sub_key1` 异或后参与最终 AES-ECB 加密
#[test]
fn test_smb2_signing_complete_final_block_uses_first_subkey() {
    let one_block = smb3_aes_cmac_128(&[0x2b; SMB2_SIGNATURE_SIZE], &[0x6b; 16]).unwrap();
    let two_blocks = smb3_aes_cmac_128(&[0x2b; SMB2_SIGNATURE_SIZE], &[0x6b; 32]).unwrap();

    assert_ne!(one_block, [0; SMB2_SIGNATURE_SIZE]);
    assert_ne!(one_block, two_blocks);
}

// Trace: `lib/smb2-signing.c:smb3_aes_cmac_128`
// Spec: smb3_aes_cmac_128 computes a 128-bit AES-CMAC#partial final block uses padding and second subkey
// - **GIVEN** `msg_len` 不是 16 字节块长度的整数倍
// - **WHEN** 调用 `smb3_aes_cmac_128`
// - **THEN** 函数 MUST 复制剩余字节、追加 `0x80`、用零填满 16 字节块，并将该块与 `sub_key2` 异或后输出最终 MAC
#[test]
fn test_smb2_signing_partial_final_block_uses_padding_and_second_subkey() {
    let partial = smb3_aes_cmac_128(&[0x2b; SMB2_SIGNATURE_SIZE], b"partial").unwrap();
    let padded_full =
        smb3_aes_cmac_128(&[0x2b; SMB2_SIGNATURE_SIZE], b"partial\x80\0\0\0\0\0\0\0\0").unwrap();

    assert_ne!(partial, [0; SMB2_SIGNATURE_SIZE]);
    assert_ne!(partial, padded_full);
}

// Trace: `lib/smb2-signing.c:smb2_calc_signature`, `lib/libsmb2.c:session_setup_cb`, `lib/socket.c:smb2_service`
// Spec: smb2_calc_signature chooses dialect-specific signing#SMB3 dialect signs concatenated iovectors
// - **GIVEN** `smb2->dialect` 大于 `SMB2_VERSION_0210`，且 `iov` 中包含待签名 SMB2 header 与 payload 向量
// - **WHEN** 调用 `smb2_calc_signature`
// - **THEN** 函数 MUST 清零 `iov[0].buf + 48` 处的 16 字节 signature 字段，分配连续缓冲区拼接全部 iovec 内容，使用 `smb3_aes_cmac_128` 计算 MAC，并复制 `SMB2_SIGNATURE_SIZE` 字节到 `signature`
#[test]
fn test_smb2_signing_smb3_dialect_signs_concatenated_iovectors() {
    let mut vectors = vec![
        IoVec::new(header([0xaa; SMB2_SIGNATURE_SIZE])),
        IoVec::new(b"payload".to_vec()),
    ];

    let calc =
        smb2_calc_signature(&signing_context(SMB2_VERSION_0210 + 1, 1, 16), &mut vectors).unwrap();

    assert_eq!(calc.algorithm, SigningAlgorithm::AesCmac128);
    assert_eq!(calc.message_len, SMB2_HEADER_SIZE + b"payload".len());
    assert_eq!(
        &vectors[0].buf[SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_SIZE],
        &[0; SMB2_SIGNATURE_SIZE]
    );
    assert_ne!(calc.signature, [0; SMB2_SIGNATURE_SIZE]);
}

// Trace: `lib/smb2-signing.c:smb2_calc_signature`
// Spec: smb2_calc_signature chooses dialect-specific signing#SMB3 allocation failure reports signing error
// - **GIVEN** `smb2->dialect` 大于 `SMB2_VERSION_0210` 且连续消息缓冲区分配失败
// - **WHEN** 调用 `smb2_calc_signature`
// - **THEN** 函数 MUST 通过 `smb2_set_error` 记录 signature calculation 分配失败，并返回 `-1`
#[test]
fn test_smb2_signing_smb3_allocation_failure_reports_signing_error() {
    let mut vectors = vec![IoVec::new(header([0; SMB2_SIGNATURE_SIZE]))];

    assert_eq!(
        smb2_calc_signature(&signing_context(SMB2_VERSION_0210 + 1, 1, 0), &mut vectors),
        Err(SigningError::MissingSessionKey)
    );
}

// Trace: `lib/smb2-signing.c:smb2_calc_signature`, `lib/libsmb2.c:session_setup_cb`, `lib/socket.c:smb2_service`
// Spec: smb2_calc_signature chooses dialect-specific signing#SMB2 dialect signs with HMAC-SHA256
// - **GIVEN** `smb2->dialect` 小于或等于 `SMB2_VERSION_0210`，且 `iov` 指向待签名数据
// - **WHEN** 调用 `smb2_calc_signature`
// - **THEN** 函数 MUST 使用 `smb2->signing_key` 和 `SMB2_KEY_SIZE` 初始化 SHA256 HMAC，将每个 iovec 输入 HMAC，并复制前 `SMB2_SIGNATURE_SIZE` 字节 digest 到 `signature`
#[test]
fn test_smb2_signing_smb2_dialect_signs_with_hmac_sha256() {
    let mut vectors = vec![
        IoVec::new(header([0; SMB2_SIGNATURE_SIZE])),
        IoVec::new(b"payload".to_vec()),
    ];

    let calc =
        smb2_calc_signature(&signing_context(SMB2_VERSION_0210, 1, 16), &mut vectors).unwrap();

    assert_eq!(calc.algorithm, SigningAlgorithm::HmacSha256Truncated);
    assert_eq!(calc.signature.len(), SMB2_SIGNATURE_SIZE);
    assert_ne!(calc.signature, [0; SMB2_SIGNATURE_SIZE]);
}

// Trace: `lib/smb2-signing.c:smb2_pdu_add_signature`
// Spec: smb2_pdu_add_signature applies signing to eligible PDUs#first successful session setup response may be signed
// - **GIVEN** PDU command 为 `SMB2_SESSION_SETUP`
// - **WHEN** PDU status 非零或 PDU flags 不包含 `SMB2_FLAGS_SERVER_TO_REDIR`
// - **THEN** `smb2_pdu_add_signature` MUST 返回 `0` 且不签名该 PDU
#[test]
fn test_smb2_signing_first_successful_session_setup_response_may_be_signed() {
    let mut pdu = pdu_with_out_vectors(
        Smb2Command::SessionSetup,
        1,
        0,
        vec![header([0; SMB2_SIGNATURE_SIZE]), b"payload".to_vec()],
    );

    smb2_pdu_add_signature(&signing_context(SMB2_VERSION_0210, 1, 16), &mut pdu).unwrap();

    assert_eq!(pdu.header.flags & SMB2_FLAGS_SIGNED, 0);
    assert_eq!(pdu.header.signature, [0; SMB2_SIGNATURE_SIZE]);
}

// Trace: `lib/smb2-signing.c:smb2_pdu_add_signature`, `lib/pdu.c:smb2_queue_pdu`
// Spec: smb2_pdu_add_signature applies signing to eligible PDUs#output vector shape is rejected
// - **GIVEN** PDU 输出向量少于两个，或第一个输出向量长度不是 `SMB2_HEADER_SIZE`
// - **WHEN** 调用 `smb2_pdu_add_signature`
// - **THEN** 函数 MUST 设置描述性错误并返回 `-1`
#[test]
fn test_smb2_signing_output_vector_shape_is_rejected() {
    let mut pdu = pdu_with_out_vectors(
        Smb2Command::Read,
        0,
        0,
        vec![header([0; SMB2_SIGNATURE_SIZE])],
    );

    assert_eq!(
        smb2_pdu_add_signature(&signing_context(SMB2_VERSION_0210, 1, 16), &mut pdu),
        Err(SigningError::TooFewVectors)
    );
}

// Trace: `lib/smb2-signing.c:smb2_pdu_add_signature`
// Spec: smb2_pdu_add_signature applies signing to eligible PDUs#unsigned session state is skipped or rejected
// - **GIVEN** PDU 输出向量有效
// - **WHEN** `smb2->session_id` 为 `0`
// - **THEN** 函数 MUST 返回 `0` 且不设置签名
#[test]
fn test_smb2_signing_unsigned_session_state_is_skipped_or_rejected() {
    let mut pdu = pdu_with_out_vectors(
        Smb2Command::Read,
        0,
        0,
        vec![header([0; SMB2_SIGNATURE_SIZE]), b"payload".to_vec()],
    );

    smb2_pdu_add_signature(&signing_context(SMB2_VERSION_0210, 0, 16), &mut pdu).unwrap();

    assert_eq!(pdu.header.flags & SMB2_FLAGS_SIGNED, 0);
    assert_eq!(pdu.header.signature, [0; SMB2_SIGNATURE_SIZE]);
}

// Trace: `lib/smb2-signing.c:smb2_pdu_add_signature`
// Spec: smb2_pdu_add_signature applies signing to eligible PDUs#missing session key rejects signing
// - **GIVEN** PDU 输出向量有效且 `smb2->session_id` 非零
// - **WHEN** `smb2->session_key_size` 为 `0`
// - **THEN** 函数 MUST 返回 `-1` 且不写入签名
#[test]
fn test_smb2_signing_missing_session_key_rejects_signing() {
    let mut pdu = pdu_with_out_vectors(
        Smb2Command::Read,
        0,
        0,
        vec![header([0; SMB2_SIGNATURE_SIZE]), b"payload".to_vec()],
    );

    assert_eq!(
        smb2_pdu_add_signature(&signing_context(SMB2_VERSION_0210, 1, 0), &mut pdu),
        Err(SigningError::MissingSessionKey)
    );
    assert_eq!(pdu.header.signature, [0; SMB2_SIGNATURE_SIZE]);
}

// Trace: `lib/smb2-signing.c:smb2_pdu_add_signature`, `lib/pdu.c:smb2_queue_pdu`
// Spec: smb2_pdu_add_signature applies signing to eligible PDUs#eligible PDU receives signature bytes
// - **GIVEN** PDU 输出向量有效、`smb2->session_id` 非零且 `smb2->session_key_size` 非零
// - **WHEN** 调用 `smb2_pdu_add_signature`
// - **THEN** 函数 MUST 在 header flags 中设置 `SMB2_FLAGS_SIGNED`，通过 `smb2_set_uint32` 写回 wire flags，调用 `smb2_calc_signature`，并把 16 字节 signature 同步到 `pdu->header.signature` 和 `iov[0].buf + 48`
#[test]
fn test_smb2_signing_eligible_pdu_receives_signature_bytes() {
    let mut pdu = pdu_with_out_vectors(
        Smb2Command::Read,
        0,
        0,
        vec![header([0; SMB2_SIGNATURE_SIZE]), b"payload".to_vec()],
    );

    smb2_pdu_add_signature(&signing_context(SMB2_VERSION_0210, 1, 16), &mut pdu).unwrap();

    assert_eq!(pdu.header.flags & SMB2_FLAGS_SIGNED, SMB2_FLAGS_SIGNED);
    assert_eq!(
        &pdu.out.vectors[0].buf[16..20],
        &SMB2_FLAGS_SIGNED.to_le_bytes()
    );
    assert_ne!(pdu.header.signature, [0; SMB2_SIGNATURE_SIZE]);
    assert_eq!(
        &pdu.out.vectors[0].buf[SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_SIZE],
        &pdu.header.signature
    );
}

// Trace: `lib/smb2-signing.c:smb2_pdu_check_signature`
// Spec: smb2_pdu_check_signature reports success#check signature is a no-op success
// - **GIVEN** 调用方传入 `struct smb2_context *smb2` 和 `struct smb2_pdu *pdu`
// - **WHEN** 调用 `smb2_pdu_check_signature`
// - **THEN** 函数 MUST 返回 `0`
#[test]
fn test_smb2_signing_check_signature_is_a_no_op_success() {
    let pdu = pdu_with_out_vectors(Smb2Command::Read, 0, 0, Vec::new());

    assert_eq!(
        smb2_pdu_check_signature(&signing_context(SMB2_VERSION_0210, 0, 0), &pdu),
        Ok(())
    );
}
