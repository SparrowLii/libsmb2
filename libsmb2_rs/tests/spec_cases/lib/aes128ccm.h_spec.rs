use libsmb2_sys::legacy::aes128ccm;

// Trace: `lib/aes128ccm.h:aes128ccm_encrypt`, `lib/aes128ccm.c:aes128ccm_encrypt`, `tests/aes128ccm-test.c:test_1`
// Spec: aes128ccm_encrypt 原地加密并生成认证标签#RFC 样例 4 字节认证标签
// - **GIVEN** 调用方提供 16 字节 key、7 字节 nonce、8 字节 AAD、4 字节 payload、4 字节认证标签缓冲区和可写 payload 缓冲区
// - **WHEN** 调用 `aes128ccm_encrypt` 处理该输入
// - **THEN** payload 后接认证标签的输出 MUST 匹配测试向量 `71 62 01 5b 4d ac 25 5d`
#[test]
fn test_aes128ccm_h_rfc_sample_4_byte_authentication_tag() {
    let mut key = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];
    let mut nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
    let mut aad = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let mut payload = [0x20, 0x21, 0x22, 0x23];

    let mac = aes128ccm::encrypt(&mut key, &mut nonce, &mut aad, &mut payload, 4).unwrap();

    assert_eq!(
        [payload.as_slice(), mac.as_slice()].concat(),
        [0x71, 0x62, 0x01, 0x5b, 0x4d, 0xac, 0x25, 0x5d]
    );
}

// Trace: `lib/aes128ccm.h:aes128ccm_encrypt`, `lib/aes128ccm.c:aes128ccm_encrypt`, `tests/aes128ccm-test.c:test_2`
// Spec: aes128ccm_encrypt 原地加密并生成认证标签#多块 AAD 和 payload 的 8 字节认证标签
// - **GIVEN** 调用方提供 16 字节 key、12 字节 nonce、20 字节 AAD、24 字节 payload、8 字节认证标签缓冲区和可写 payload 缓冲区
// - **WHEN** 调用 `aes128ccm_encrypt` 处理该输入
// - **THEN** payload 后接认证标签的输出 MUST 匹配测试向量 `e3 b2 01 a9 f5 b7 1a 7a 9b 1c ea ec cd 97 e7 0b 61 76 aa d9 a4 42 8a a5 48 43 92 fb c1 b0 99 51`
#[test]
fn test_aes128ccm_h_multi_block_aad_and_payload_8_byte_authentication_tag() {
    let mut key = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];
    let mut nonce = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    ];
    let mut aad = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13,
    ];
    let mut payload = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];

    let mac = aes128ccm::encrypt(&mut key, &mut nonce, &mut aad, &mut payload, 8).unwrap();

    assert_eq!(
        [payload.as_slice(), mac.as_slice()].concat(),
        [
            0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a, 0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97,
            0xe7, 0x0b, 0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5, 0x48, 0x43, 0x92, 0xfb,
            0xc1, 0xb0, 0x99, 0x51,
        ]
    );
}

// Trace: `lib/aes128ccm.h:aes128ccm_decrypt`, `lib/aes128ccm.c:aes128ccm_decrypt`, `tests/aes128ccm-test.c:test_1`, `tests/aes128ccm-test.c:test_2`
// Spec: aes128ccm_decrypt 原地解密并校验认证标签#加密输出可成功解密
// - **GIVEN** 调用方先使用相同 key、nonce、AAD、payload 和 tag 长度生成 AES-128-CCM 密文与认证标签
// - **WHEN** 调用 `aes128ccm_decrypt` 处理该密文和认证标签
// - **THEN** 返回值 MUST 为 `0`，并且 payload 缓冲区 MUST 恢复为原始明文
#[test]
fn test_aes128ccm_h_encrypted_output_decrypts_successfully() {
    let mut key = [0x40; 16];
    let mut nonce = [0x11; 12];
    let mut aad = [0x22; 20];
    let plaintext = [0x33; 24];
    let mut payload = plaintext;
    let mut mac = aes128ccm::encrypt(&mut key, &mut nonce, &mut aad, &mut payload, 8).unwrap();

    aes128ccm::decrypt(&mut key, &mut nonce, &mut aad, &mut payload, &mut mac).unwrap();

    assert_eq!(payload, plaintext);
}

// Trace: `lib/aes128ccm.h:aes128ccm_encrypt`, `lib/smb3-seal.c:smb3_encrypt_pdu`
// Spec: aes128ccm_encrypt 原地加密并生成认证标签#SMB3 transform header sealing
// - **GIVEN** SMB3 sealing passes an 11 字节 nonce、32 字节 AAD、明文 transform payload、16 字节 tag 缓冲区和 server input key
// - **WHEN** `smb3_encrypt_pdu` 调用 `aes128ccm_encrypt`
// - **THEN** 该接口 MUST 在 transform payload 缓冲区中产生密文，并 MUST 在 transform header 的 signature 字段写入 16 字节认证标签
#[test]
fn test_aes128ccm_h_smb3_transform_header_sealing() {
    let mut key = [0x44; 16];
    let mut nonce = [0x55; 11];
    let mut aad = [0x66; 32];
    let plaintext = [0x77; 16];
    let mut payload = plaintext;

    let mac = aes128ccm::encrypt(&mut key, &mut nonce, &mut aad, &mut payload, 16).unwrap();

    assert_ne!(payload, plaintext);
    assert_eq!(mac.len(), 16);
}

// Trace: `lib/aes128ccm.h:aes128ccm_decrypt`, `lib/smb3-seal.c:smb3_decrypt_pdu`
// Spec: aes128ccm_decrypt 原地解密并校验认证标签#SMB3 transform header unsealing
// - **GIVEN** SMB3 unsealing提供 transform header 中的 11 字节 nonce、32 字节 AAD、密文 payload、16 字节 signature 和 server output key
// - **WHEN** `smb3_decrypt_pdu` 调用 `aes128ccm_decrypt`
// - **THEN** 返回值 MUST 为 `0` 才允许上层继续解析解密后的 payload；非零返回值 MUST 被调用方视为解密失败
#[test]
fn test_aes128ccm_h_smb3_transform_header_unsealing() {
    let mut key = [0x44; 16];
    let mut nonce = [0x55; 11];
    let mut aad = [0x66; 32];
    let plaintext = [0x77; 16];
    let mut payload = plaintext;
    let mut mac = aes128ccm::encrypt(&mut key, &mut nonce, &mut aad, &mut payload, 16).unwrap();

    aes128ccm::decrypt(&mut key, &mut nonce, &mut aad, &mut payload, &mut mac).unwrap();

    assert_eq!(payload, plaintext);
}
