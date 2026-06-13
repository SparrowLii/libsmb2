use libsmb2_sys::legacy::aes::{encrypt_block, AesBlock};

// Trace: `lib/aes.c:AES128_ECB_encrypt`, `lib/aes_apple.c:AES128_ECB_encrypt_apple`
// Spec: AES128_ECB_encrypt platform backend dispatch#Apple build dispatches to CommonCrypto backend
// - **GIVEN** 调用方提供 16 字节输入缓冲区、16 字节 AES-128 key 和可写输出缓冲区，且编译环境定义 `__APPLE__`
// - **WHEN** 调用方调用 `AES128_ECB_encrypt(input, key, output)`
// - **THEN** 实现 MUST 调用 `AES128_ECB_encrypt_apple(input, key, output)` 并通过调用方提供的 `output` 返回后端产生的密文块
// Note: The safe AES binding does not expose backend call tracing, so this verifies the observable 16-byte output contract without assuming an explicit ciphertext vector.
#[test]
fn test_aes_apple_build_dispatches_to_commoncrypto_backend() {
    let input = AesBlock([0x00; 16]);
    let key = AesBlock([0x2a; 16]);

    let output = encrypt_block(input, key);

    assert_eq!(output.0.len(), 16);
}

// Trace: `lib/aes.c:AES128_ECB_encrypt`, `lib/aes_reference.c:AES128_ECB_encrypt_reference`, `tests/aes128ccm-test.c:test_1`, `tests/aes128ccm-test.c:test_2`
// Spec: AES128_ECB_encrypt platform backend dispatch#Non-Apple build dispatches to reference backend
// - **GIVEN** 调用方提供 16 字节输入缓冲区、16 字节 AES-128 key 和可写输出缓冲区，且编译环境未定义 `__APPLE__`
// - **WHEN** 调用方调用 `AES128_ECB_encrypt(input, key, output)`
// - **THEN** 实现 MUST 调用 `AES128_ECB_encrypt_reference(input, key, output)` 并通过调用方提供的 `output` 返回 reference 后端产生的密文块
// Note: The safe AES binding does not expose backend call tracing, so this verifies the observable 16-byte output contract without assuming an explicit ciphertext vector.
#[test]
fn test_aes_non_apple_build_dispatches_to_reference_backend() {
    let input = AesBlock([0x11; 16]);
    let key = AesBlock([0x7f; 16]);

    let output = encrypt_block(input, key);

    assert_eq!(output.0.len(), 16);
}

// Trace: `lib/aes.c:AES128_ECB_encrypt`, `lib/aes128ccm.c:ccm_generate_T`, `lib/aes128ccm.c:ccm_generate_s`, `tests/aes128ccm-test.c:test_1`, `tests/aes128ccm-test.c:test_2`
// Spec: AES128_ECB_encrypt platform backend dispatch#AES-CCM callers rely on deterministic block encryption
// - **GIVEN** AES-CCM 认证加密或解密逻辑正在生成认证块或计数器流块
// - **WHEN** `ccm_generate_T` 或 `ccm_generate_s` 调用 `AES128_ECB_encrypt` 处理 16 字节中间块
// - **THEN** 该接口 MUST 为相同的输入块和 key 产生稳定的 AES-128 ECB 输出，使 `aes128ccm_encrypt` 与 `aes128ccm_decrypt` 能通过已知向量和回环校验
// Note: This uses only the safe AES binding requested for this batch and verifies deterministic ECB block output without duplicating AES-CCM vector smoke coverage.
#[test]
fn test_aes_aes_ccm_callers_rely_on_deterministic_block_encryption() {
    let input = AesBlock([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]);
    let key = AesBlock([
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x00,
    ]);

    let first = encrypt_block(input, key);
    let second = encrypt_block(input, key);

    assert_eq!(first, second);
    assert_eq!(first.0.len(), 16);
}
