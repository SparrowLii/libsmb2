use libsmb2_rs::lib::smb2_cmd_negotiate::{
    self as negotiate, DialectRevision, NegotiateContextType, NegotiateError, Smb2NegotiateReply,
    Smb2NegotiateRequest,
};

fn guid() -> [u8; 16] {
    [0x22; 16]
}
fn salt() -> [u8; 32] {
    [0x33; 32]
}

// Trace: `lib/smb2-cmd-negotiate.c:smb2_cmd_negotiate_async`, `lib/smb2-cmd-negotiate.c:smb2_encode_negotiate_request`
// Spec: smb2_cmd_negotiate_async builds negotiate request PDU#request PDU construction succeeds
// - **GIVEN** 调用方提供 `smb2_context`、`smb2_negotiate_request`、回调和回调数据，且 PDU、请求缓冲区、context iovector 与最终 padding 均可成功建立
// - **WHEN** 调用 `smb2_cmd_negotiate_async`
// - **THEN** 返回的 PDU 使用 `SMB2_NEGOTIATE` command，输出缓冲区包含 request fixed fields、client GUID、dialects，并根据版本条件包含 preauth 与 encryption negotiate contexts
#[test]
fn test_smb2_cmd_negotiate_request_pdu_construction_succeeds() {
    let mut req = Smb2NegotiateRequest::new(1, 2, guid(), vec![DialectRevision(0x0311)]);
    let pdu =
        negotiate::smb2_cmd_negotiate_async(&mut req, DialectRevision(0x0311), &salt()).unwrap();
    assert_eq!(pdu.output_vectors.len(), 3);
    assert_eq!(&pdu.output_vectors[0][12..28], &guid());
    assert_eq!(req.negotiate_context_offset, 104);
}

// Trace: `lib/smb2-cmd-negotiate.c:smb2_cmd_negotiate_reply_async`, `lib/smb2-cmd-negotiate.c:smb2_encode_negotiate_reply`
// Spec: smb2_cmd_negotiate_reply_async builds negotiate reply PDU#reply PDU construction succeeds
// - **GIVEN** 调用方提供 reply 数据，且 fixed reply、可选 security buffer、negotiate contexts 与 64-bit padding 都可成功编码
// - **WHEN** 调用 `smb2_cmd_negotiate_reply_async`
// - **THEN** 返回的 PDU 包含 reply fixed fields、server GUID、capabilities、大小限制、时间字段、security buffer offset/length，并在 dialect 条件匹配时追加 preauth 与 encryption contexts
#[test]
fn test_smb2_cmd_negotiate_reply_pdu_construction_succeeds() {
    let mut rep = Smb2NegotiateReply::empty();
    rep.dialect_revision = DialectRevision(0x0311);
    rep.server_guid = guid();
    rep.security_buffer = vec![1, 2, 3];
    let pdu = negotiate::smb2_cmd_negotiate_reply_async(&mut rep, &salt()).unwrap();
    assert_eq!(pdu.output_vectors.len(), 4);
    assert_eq!(&pdu.output_vectors[0][8..24], &guid());
    assert_eq!(rep.security_buffer_offset, 128);
}

// Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_fixed`
// Spec: smb2_process_negotiate_fixed parses negotiate reply fixed payload#fixed reply payload is valid
// - **GIVEN** 输入 iovec 的 structure size 等于 `SMB2_NEGOTIATE_REPLY_SIZE` 且 wire fixed 长度匹配，并且 reply payload 分配成功
// - **WHEN** 调用 `smb2_process_negotiate_fixed`
// - **THEN** 系统 MUST 将 `pdu->payload` 设置为新分配的 reply，填充 security mode、dialect、server GUID、capabilities、大小限制、时间和 security buffer 元数据，并按 security buffer 与 SMB 3.1.1 条件返回 variable 字节数
#[test]
fn test_smb2_cmd_negotiate_fixed_reply_payload_is_valid() {
    let mut rep = Smb2NegotiateReply::empty();
    rep.dialect_revision = DialectRevision(0x0202);
    rep.security_buffer = vec![1, 2, 3, 4];
    let fixed = negotiate::smb2_cmd_negotiate_reply_async(&mut rep, &salt())
        .unwrap()
        .output_vectors[0]
        .clone();
    let (parsed, variable_len) = negotiate::smb2_process_negotiate_fixed(&fixed, 132).unwrap();
    assert_eq!(parsed.dialect_revision, DialectRevision(0x0202));
    assert_eq!(variable_len, 4);
}

// Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_fixed`
// Spec: smb2_process_negotiate_fixed parses negotiate reply fixed payload#fixed reply rejects invalid size or buffer range
// - **GIVEN** fixed reply size 不匹配、security buffer 超出 PDU 长度，或 security buffer 与 reply header 重叠
// - **WHEN** 调用 `smb2_process_negotiate_fixed`
// - **THEN** 系统 MUST 设置错误信息并返回 `-1`；若已分配 reply payload，系统 MUST 清空 `pdu->payload` 并释放该 payload
#[test]
fn test_smb2_cmd_negotiate_fixed_reply_rejects_invalid_size_or_buffer_range() {
    assert_eq!(
        negotiate::smb2_process_negotiate_fixed(&[0; 63], 64),
        Err(NegotiateError::UnexpectedStructureSize)
    );
}

// Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_variable`
// Spec: smb2_process_negotiate_variable parses negotiate reply variable payload#reply variable parsing without contexts
// - **GIVEN** reply payload 已由 fixed parser 建立，且 dialect 小于 `SMB2_VERSION_0311` 或 `negotiate_context_count` 为 0
// - **WHEN** 调用 `smb2_process_negotiate_variable`
// - **THEN** 系统 MUST 设置 `rep->security_buffer` 指向 variable iovec 的 security buffer 位置并返回 `0`，不解析 negotiate contexts
#[test]
fn test_smb2_cmd_negotiate_reply_variable_parsing_without_contexts() {
    let mut rep = Smb2NegotiateReply::empty();
    rep.dialect_revision = DialectRevision(0x0202);
    rep.security_buffer_offset = 128;
    negotiate::smb2_process_negotiate_variable(&mut rep, &[9, 8, 7], 0).unwrap();
    assert_eq!(rep.negotiate_contexts.len(), 0);
}

// Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_variable`, `lib/smb2-cmd-negotiate.c:smb2_parse_negotiate_contexts`
// Spec: smb2_process_negotiate_variable parses negotiate reply variable payload#reply variable context parsing validates offset and type
// - **GIVEN** reply dialect 至少为 `SMB2_VERSION_0311` 且 `negotiate_context_count` 非零
// - **WHEN** 调用 `smb2_process_negotiate_variable`
// - **THEN** 系统 MUST 校验 context offset 位于 variable iovec 范围内，解析已知 context 类型，在 encryption context 中填充 `rep->cypher`，并对未知 context 类型或越界 context 返回 `-1`
#[test]
fn test_smb2_cmd_negotiate_reply_variable_context_parsing_validates_offset_and_type() {
    let mut rep = Smb2NegotiateReply::empty();
    rep.dialect_revision = DialectRevision(0x0311);
    rep.negotiate_context_offset = 128;
    let ctx = negotiate::smb2_encode_encryption_context();
    negotiate::smb2_process_negotiate_variable(&mut rep, &ctx, 1).unwrap();
    assert_eq!(
        rep.negotiate_contexts[0].context_type,
        NegotiateContextType::Encryption
    );
    assert!(negotiate::smb2_process_negotiate_variable(&mut rep, &[0xff], 1).is_err());
}

// Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_request_fixed`
// Spec: smb2_process_negotiate_request_fixed parses negotiate request fixed payload#fixed request payload is valid
// - **GIVEN** 输入 iovec 的 structure size 等于 `SMB2_NEGOTIATE_REQUEST_SIZE` 且 wire fixed 长度匹配，并且 request payload 分配成功
// - **WHEN** 调用 `smb2_process_negotiate_request_fixed`
// - **THEN** 系统 MUST 将 `pdu->payload` 设置为 request，填充 dialect count、security mode、capabilities、client GUID、negotiate context offset/count，并在 context count 非零时返回 fixed part 后剩余字节数，否则返回 dialect 列表字节数
#[test]
fn test_smb2_cmd_negotiate_fixed_request_payload_is_valid() {
    let mut req = Smb2NegotiateRequest::new(1, 2, guid(), vec![DialectRevision(0x0202)]);
    let fixed = negotiate::smb2_cmd_negotiate_async(&mut req, DialectRevision(0x0202), &salt())
        .unwrap()
        .output_vectors[0]
        .clone();
    let (parsed, variable_len) =
        negotiate::smb2_process_negotiate_request_fixed(&fixed, 102).unwrap();
    assert_eq!(parsed.security_mode, 1);
    assert_eq!(parsed.capabilities, 2);
    assert_eq!(variable_len, 2);
}

// Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_request_fixed`
// Spec: smb2_process_negotiate_request_fixed parses negotiate request fixed payload#fixed request rejects invalid size
// - **GIVEN** fixed request structure size 或 iovec fixed 长度不匹配，或 request payload 分配失败
// - **WHEN** 调用 `smb2_process_negotiate_request_fixed`
// - **THEN** 系统 MUST 设置错误信息并返回 `-1`，且不会设置有效 request payload
#[test]
fn test_smb2_cmd_negotiate_fixed_request_rejects_invalid_size() {
    assert_eq!(
        negotiate::smb2_process_negotiate_request_fixed(&[0; 2], 64),
        Err(NegotiateError::UnexpectedStructureSize)
    );
}

// Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_request_variable`
// Spec: smb2_process_negotiate_request_variable parses dialects and SMB 3.1.1 request contexts#request variable parsing without SMB 3.1.1 contexts
// - **GIVEN** request payload 已由 fixed parser 建立，但 context count 为 0 或读取到的 dialect 列表不包含 `0x0311`
// - **WHEN** 调用 `smb2_process_negotiate_request_variable`
// - **THEN** 系统 MUST 填充可容纳范围内的 dialect entries 并返回 `0`，不解释 negotiate contexts
#[test]
fn test_smb2_cmd_negotiate_request_variable_parsing_without_smb_3_1_1_contexts() {
    let mut req = Smb2NegotiateRequest::new(0, 0, guid(), Vec::new());
    negotiate::smb2_process_negotiate_request_variable(&mut req, &0x0202_u16.to_le_bytes(), 1, 0)
        .unwrap();
    assert_eq!(req.dialects, vec![DialectRevision(0x0202)]);
}

// Trace: `lib/smb2-cmd-negotiate.c:smb2_process_negotiate_request_variable`, `lib/smb2-cmd-negotiate.c:smb2_parse_negotiate_request_contexts`
// Spec: smb2_process_negotiate_request_variable parses dialects and SMB 3.1.1 request contexts#request variable context parsing validates offset and type
// - **GIVEN** request payload 声明 context count 非零且 dialect 列表包含 `0x0311`
// - **WHEN** 调用 `smb2_process_negotiate_request_variable`
// - **THEN** 系统 MUST 校验 context offset 位于 variable iovec 范围内，接受已知 request context 类型和 Samba reserved context，并对未知 context 类型或越界 context 返回 `-1`
#[test]
fn test_smb2_cmd_negotiate_request_variable_context_parsing_validates_offset_and_type() {
    let mut req = Smb2NegotiateRequest::new(0, 0, guid(), Vec::new());
    req.negotiate_context_offset = 108;
    let mut variable = 0x0311_u16.to_le_bytes().to_vec();
    variable.extend_from_slice(&[0; 6]);
    variable.extend_from_slice(&negotiate::smb2_encode_encryption_context());
    negotiate::smb2_process_negotiate_request_variable(&mut req, &variable, 1, 1).unwrap();
    assert_eq!(
        req.negotiate_contexts[0].context_type,
        NegotiateContextType::Encryption
    );
}
