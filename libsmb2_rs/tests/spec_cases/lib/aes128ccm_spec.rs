use libsmb2_sys::legacy::aes128ccm;

fn ccm_vector_1() -> ([u8; 16], [u8; 7], [u8; 8], [u8; 4]) {
    (
        [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f,
        ],
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16],
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
        [0x20, 0x21, 0x22, 0x23],
    )
}

// Trace: `lib/aes128ccm.c:aes128ccm_encrypt`, `tests/aes128ccm-test.c:test_1`, `tests/aes128ccm-test.c:test_2`
// Spec: aes128ccm_encrypt AES-128-CCM payload encryption and tag generation#已知向量生成密文和标签
// - **GIVEN** 调用方提供 16 字节 AES key、nonce、AAD、明文 payload、可写 payload 缓冲区和可写 tag 缓冲区
// - **WHEN** 调用方执行 `aes128ccm_encrypt(key, nonce, nlen, aad, alen, p, plen, m, mlen)`
// - **THEN** payload 缓冲区 MUST 被原地转换为 AES-128-CCM 密文，tag 缓冲区 MUST 包含与输入 key、nonce、AAD、payload 和 `mlen` 对应的认证标签
#[test]
fn test_aes128ccm_known_vector_generates_ciphertext_and_tag() {
    let (mut key, mut nonce, mut aad, plaintext) = ccm_vector_1();
    let mut payload = plaintext;

    let mac = aes128ccm::encrypt(&mut key, &mut nonce, &mut aad, &mut payload, 4).unwrap();

    assert_eq!(payload, [0x71, 0x62, 0x01, 0x5b]);
    assert_eq!(mac, [0x4d, 0xac, 0x25, 0x5d]);
}

// Trace: `lib/aes128ccm.c:aes128ccm_encrypt`, `lib/smb3-seal.c:smb3_encrypt_pdu`
// Spec: aes128ccm_encrypt AES-128-CCM payload encryption and tag generation#SMB3 sealing 使用 11 字节 nonce、32 字节 AAD 和 16 字节标签
// - **GIVEN** SMB3 transform header 已包含随机 nonce、AAD 字段和待加密 PDU payload
// - **WHEN** `smb3_encrypt_pdu` 调用 `aes128ccm_encrypt` 并传入 `nlen == 11`、`alen == 32`、`mlen == 16`
// - **THEN** 函数 MUST 加密 transform header 后的 payload，并 MUST 在 transform header signature 字段写入 16 字节认证标签
#[test]
fn test_aes128ccm_smb3_sealing_uses_11_byte_nonce_32_byte_aad_16_byte_tag() {
    let mut key = [0x55; 16];
    let mut nonce = [0x10; 11];
    let mut aad = [0x20; 32];
    let plaintext = [0x30; 24];
    let mut payload = plaintext;

    let mac = aes128ccm::encrypt(&mut key, &mut nonce, &mut aad, &mut payload, 16).unwrap();

    assert_ne!(payload, plaintext);
    assert_eq!(mac.len(), 16);
}

// Trace: `lib/aes128ccm.c:aes128ccm_decrypt`, `tests/aes128ccm-test.c:test_1`, `tests/aes128ccm-test.c:test_2`
// Spec: aes128ccm_decrypt AES-128-CCM payload decryption and tag verification#有效标签恢复明文并返回零
// - **GIVEN** payload 缓冲区包含由 `aes128ccm_encrypt` 使用相同 key、nonce、AAD 和 tag 长度生成的密文，`m` 指向对应认证标签
// - **WHEN** 调用方执行 `aes128ccm_decrypt(key, nonce, nlen, aad, alen, p, plen, m, mlen)`
// - **THEN** payload 缓冲区 MUST 被原地恢复为原始明文，并且返回值 MUST 为 `0`
#[test]
fn test_aes128ccm_valid_tag_restores_plaintext() {
    let (mut key, mut nonce, mut aad, plaintext) = ccm_vector_1();
    let mut payload = plaintext;
    let mut mac = aes128ccm::encrypt(&mut key, &mut nonce, &mut aad, &mut payload, 4).unwrap();

    aes128ccm::decrypt(&mut key, &mut nonce, &mut aad, &mut payload, &mut mac).unwrap();

    assert_eq!(payload, plaintext);
}

// Trace: `lib/aes128ccm.c:aes128ccm_decrypt`, `lib/smb3-seal.c:smb3_decrypt_pdu`
// Spec: aes128ccm_decrypt AES-128-CCM payload decryption and tag verification#认证标签不匹配时返回非零比较结果
// - **GIVEN** payload、key、nonce、AAD 或 tag 与用于生成 `m` 的输入不匹配
// - **WHEN** 调用方执行 `aes128ccm_decrypt(key, nonce, nlen, aad, alen, p, plen, m, mlen)`
// - **THEN** 函数 MUST 返回 `memcmp(tmp, m, mlen)` 的非零比较结果，调用方 MUST 将非零结果视为认证或解密失败
#[test]
fn test_aes128ccm_tag_mismatch_returns_authentication_failure() {
    let (mut key, mut nonce, mut aad, plaintext) = ccm_vector_1();
    let mut payload = plaintext;
    let mut mac = aes128ccm::encrypt(&mut key, &mut nonce, &mut aad, &mut payload, 4).unwrap();
    mac[0] ^= 0xff;

    let err =
        aes128ccm::decrypt(&mut key, &mut nonce, &mut aad, &mut payload, &mut mac).unwrap_err();

    assert_eq!(err, aes128ccm::Error::AuthenticationFailed);
}
