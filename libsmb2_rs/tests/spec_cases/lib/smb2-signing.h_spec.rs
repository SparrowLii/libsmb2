use libsmb2_rs::include::libsmb2_private::{
    IoVec, IoVectors, Pdu, Smb2Header, SMB2_HEADER_SIZE, SMB2_SIGNATURE_SIZE,
};
use libsmb2_rs::lib::pdu::{Smb2Command, SMB2_FLAGS_SERVER_TO_REDIR};
use libsmb2_rs::lib::smb2_signing::{
    smb2_pdu_add_signature, smb2_pdu_check_signature, SigningError, Smb2SigningContext,
    SMB2_FLAGS_SIGNED, SMB2_SIGNATURE_OFFSET, SMB2_VERSION_0210,
};

fn signing_context(session_id: u64, session_key_size: usize) -> Smb2SigningContext {
    Smb2SigningContext::new(
        SMB2_VERSION_0210,
        session_id,
        session_key_size,
        [0x22; SMB2_SIGNATURE_SIZE],
    )
}

fn header() -> Vec<u8> {
    vec![0; SMB2_HEADER_SIZE]
}

fn pdu(command: Smb2Command, status: u32, flags: u32, vectors: Vec<Vec<u8>>) -> Pdu {
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

// Trace: `lib/smb2-signing.h:smb2_pdu_add_signature`, `lib/smb2-signing.c:smb2_pdu_add_signature`, `lib/pdu.c:smb2_queue_pdu`
// Spec: smb2_pdu_add_signature declares outbound PDU signing entry#declaration is available for queue-time signing
// - **GIVEN** C 或 C++ 翻译单元包含 `lib/smb2-signing.h` 且可见 `struct smb2_context` 与 `struct smb2_pdu` 类型
// - **WHEN** 调用方按 `int smb2_pdu_add_signature(struct smb2_context *smb2, struct smb2_pdu *pdu);` 声明编译调用
// - **THEN** 头文件 SHALL 提供该函数原型，并保留 `int` 返回类型与两个指针参数的 ABI
#[test]
fn test_smb2_signing_h_declaration_is_available_for_queue_time_signing() {
    let mut pdu = pdu(Smb2Command::Read, 0, 0, vec![header(), b"payload".to_vec()]);

    assert_eq!(
        smb2_pdu_add_signature(&signing_context(0, 16), &mut pdu),
        Ok(())
    );
}

// Trace: `lib/smb2-signing.h:smb2_pdu_add_signature`, `lib/smb2-signing.c:smb2_pdu_add_signature`, `lib/smb2-signing.c:smb2_calc_signature`
// Spec: smb2_pdu_add_signature declares outbound PDU signing entry#implementation signs eligible outbound PDUs
// - **GIVEN** 调用方传入具有至少两个输出 iovec、首个 iovec 长度为 `SMB2_HEADER_SIZE`、非零 `session_id` 且非零 `session_key_size` 的 PDU
// - **WHEN** `smb2_pdu_add_signature` 被调用且底层签名计算成功
// - **THEN** 系统 MUST 设置 `SMB2_FLAGS_SIGNED` 标志，更新输出 SMB2 头部 flags 字段，将计算出的 16 字节签名复制到 `pdu->header.signature` 和输出缓冲区偏移 48，并返回 `0`
#[test]
fn test_smb2_signing_h_implementation_signs_eligible_outbound_pdus() {
    let mut pdu = pdu(Smb2Command::Read, 0, 0, vec![header(), b"payload".to_vec()]);

    smb2_pdu_add_signature(&signing_context(1, 16), &mut pdu).unwrap();

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

// Trace: `lib/smb2-signing.h:smb2_pdu_add_signature`, `lib/smb2-signing.c:smb2_pdu_add_signature`
// Spec: smb2_pdu_add_signature declares outbound PDU signing entry#implementation skips unsigned session setup and anonymous sessions
// - **GIVEN** PDU 是非成功或非 server-to-redir 的 `SMB2_SESSION_SETUP`，或 SMB2 上下文的 `session_id` 为 `0`
// - **WHEN** `smb2_pdu_add_signature` 被调用
// - **THEN** 系统 MUST 返回 `0` 且不要求写入签名字段；这些路径表示签名被跳过而非签名失败
#[test]
fn test_smb2_signing_h_implementation_skips_unsigned_session_setup_and_anonymous_sessions() {
    let mut setup = pdu(
        Smb2Command::SessionSetup,
        1,
        SMB2_FLAGS_SERVER_TO_REDIR,
        vec![header(), b"payload".to_vec()],
    );
    let mut anonymous = pdu(Smb2Command::Read, 0, 0, vec![header(), b"payload".to_vec()]);

    smb2_pdu_add_signature(&signing_context(1, 16), &mut setup).unwrap();
    smb2_pdu_add_signature(&signing_context(0, 16), &mut anonymous).unwrap();

    assert_eq!(setup.header.signature, [0; SMB2_SIGNATURE_SIZE]);
    assert_eq!(anonymous.header.signature, [0; SMB2_SIGNATURE_SIZE]);
}

// Trace: `lib/smb2-signing.h:smb2_pdu_add_signature`, `lib/smb2-signing.c:smb2_pdu_add_signature`, `lib/init.c:smb2_set_error`
// Spec: smb2_pdu_add_signature declares outbound PDU signing entry#implementation reports signing precondition failures
// - **GIVEN** PDU 输出 iovec 少于两个、首个 iovec 长度不是 `SMB2_HEADER_SIZE`、会话密钥大小为 `0`，或签名计算分配失败
// - **WHEN** `smb2_pdu_add_signature` 被调用
// - **THEN** 系统 MUST 返回 `-1`；对 iovec 数量和头部长度错误，系统 SHALL 通过 `smb2_set_error` 记录错误文本
#[test]
fn test_smb2_signing_h_implementation_reports_signing_precondition_failures() {
    let mut too_few = pdu(Smb2Command::Read, 0, 0, vec![header()]);
    let mut bad_key = pdu(Smb2Command::Read, 0, 0, vec![header(), b"payload".to_vec()]);

    assert_eq!(
        smb2_pdu_add_signature(&signing_context(1, 16), &mut too_few),
        Err(SigningError::TooFewVectors)
    );
    assert_eq!(
        smb2_pdu_add_signature(&signing_context(1, 0), &mut bad_key),
        Err(SigningError::MissingSessionKey)
    );
}

// Trace: `lib/smb2-signing.h:smb2_pdu_check_signature`, `lib/smb2-signing.c:smb2_pdu_check_signature`
// Spec: smb2_pdu_check_signature declares inbound PDU signature check entry#declaration is available for inbound signature checks
// - **GIVEN** C 或 C++ 翻译单元包含 `lib/smb2-signing.h` 且可见 `struct smb2_context` 与 `struct smb2_pdu` 类型
// - **WHEN** 调用方按 `int smb2_pdu_check_signature(struct smb2_context *smb2, struct smb2_pdu *pdu);` 声明编译调用
// - **THEN** 头文件 SHALL 提供该函数原型，并保留 `int` 返回类型与两个指针参数的 ABI
#[test]
fn test_smb2_signing_h_declaration_is_available_for_inbound_signature_checks() {
    let pdu = pdu(Smb2Command::Read, 0, 0, Vec::new());

    assert_eq!(
        smb2_pdu_check_signature(&signing_context(0, 0), &pdu),
        Ok(())
    );
}

// Trace: `lib/smb2-signing.h:smb2_pdu_check_signature`, `lib/smb2-signing.c:smb2_pdu_check_signature`
// Spec: smb2_pdu_check_signature declares inbound PDU signature check entry#current implementation accepts all PDUs
// - **GIVEN** 调用方传入任意 `smb2` 与 `pdu` 指针组合
// - **WHEN** `smb2_pdu_check_signature` 被调用
// - **THEN** 当前实现 MUST 返回 `0`，且不会读取、修改或验证签名字段
#[test]
fn test_smb2_signing_h_current_implementation_accepts_all_pdus() {
    let pdu = pdu(Smb2Command::Read, 0, 0, Vec::new());

    assert_eq!(
        smb2_pdu_check_signature(&signing_context(0, 0), &pdu),
        Ok(())
    );
}
