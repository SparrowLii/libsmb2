use libsmb2_sys::legacy::aes::{
    reference_cbc_encrypt, reference_decrypt_block, reference_encrypt_block, AesBlock,
};

// Trace: `lib/aes_reference.c:AES128_ECB_encrypt_reference`, `lib/aes_reference.h:AES128_ECB_encrypt_reference`, `tests/aes128ccm-test.c:main`
// Spec: AES128_ECB_encrypt_reference encrypts one AES-128 block#encrypt a single ECB block
// - **GIVEN** `ECB` 预处理条件为真，`input` 指向至少 16 字节明文，`key` 指向 16 字节 AES-128 key，且 `output` 指向至少 16 字节可写缓冲区
// - **WHEN** 调用 `AES128_ECB_encrypt_reference(input, key, output)`
// - **THEN** 函数先复制 16 字节输入到输出缓冲区，再执行 AES-128 key expansion 和 AES cipher，使 `output` 包含该单块明文的 ECB 密文
#[test]
fn test_aes_reference_encrypt_a_single_ecb_block() {
    let input = AesBlock([0x00; 16]);
    let key = AesBlock([0x00; 16]);

    let output = reference_encrypt_block(input, key);

    assert_eq!(
        output.0,
        [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e
        ]
    );
}

// Trace: `lib/aes_reference.c:AES128_ECB_decrypt_reference`, `lib/aes_reference.h:AES128_ECB_decrypt_reference`
// Spec: AES128_ECB_decrypt_reference decrypts one AES-128 block#decrypt a single ECB block
// - **GIVEN** `ECB` 预处理条件为真，`input` 指向至少 16 字节密文，`key` 指向 16 字节 AES-128 key，且 `output` 指向至少 16 字节可写缓冲区
// - **WHEN** 调用 `AES128_ECB_decrypt_reference(input, key, output)`
// - **THEN** 函数先复制 16 字节输入到输出缓冲区，再执行 AES-128 key expansion 和 inverse AES cipher，使 `output` 包含该单块密文的 ECB 明文
#[test]
fn test_aes_reference_decrypt_a_single_ecb_block() {
    let key = AesBlock([0x00; 16]);
    let ciphertext = AesBlock([
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e,
    ]);

    let output = reference_decrypt_block(ciphertext, key);

    assert_eq!(output.0, [0x00; 16]);
}

// Trace: `lib/aes_reference.c:AES128_CBC_encrypt_buffer_reference`, `lib/aes_reference.h:AES128_CBC_encrypt_buffer_reference`
// Spec: AES128_CBC_encrypt_buffer_reference encrypts CBC buffers with zero padding#encrypt full CBC blocks
// - **GIVEN** `CBC` 预处理条件为真，`length` 为 16 的整数倍，`input` 与 `output` 覆盖 `length` 字节，`key` 指向 16 字节 AES-128 key，且 `iv` 指向 16 字节初始向量
// - **WHEN** 调用 `AES128_CBC_encrypt_buffer_reference(output, input, length, key, iv)`
// - **THEN** 每个 16 字节明文块先与当前 IV 或前一密文块 XOR，再被 AES-128 加密写入对应输出块
#[test]
fn test_aes_reference_encrypt_full_cbc_blocks() {
    let key = AesBlock([0x00; 16]);
    let iv = AesBlock([0x00; 16]);
    let plaintext = [0x00; 16];

    let ciphertext = reference_cbc_encrypt(&plaintext, key, iv);

    assert_eq!(
        ciphertext,
        [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e
        ]
    );
}
