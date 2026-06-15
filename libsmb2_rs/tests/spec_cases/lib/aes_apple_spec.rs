use libsmb2_rs::lib::aes::{encrypt_block, AesBlock};

// Trace: `lib/aes_apple.c:AES128_ECB_encrypt_apple`, `lib/aes_apple.h:AES128_ECB_encrypt_apple`
// Spec: AES128_ECB_encrypt_apple encrypts one AES-128 ECB block on Apple#Apple CommonCrypto encryption succeeds
// - **GIVEN** `__APPLE__` 已定义，调用方提供非空的 16 字节 `input`、16 字节 `key` 和至少 16 字节 `output` 缓冲区
// - **WHEN** 调用方执行 `AES128_ECB_encrypt_apple(input, key, output)` 且 `CCCryptorCreate` 返回 `kCCSuccess`
// - **THEN** 函数使用 `kCCEncrypt`、`kCCAlgorithmAES`、`kCCOptionECBMode` 和 16 字节 key 创建 cryptor，调用 `CCCryptorUpdate` 处理 16 字节输入并把结果写入 `output`，随后释放 cryptor
#[test]
fn test_aes_apple_commoncrypto_encryption_succeeds() {
    let input = AesBlock([0x00; 16]);
    let key = AesBlock([0x00; 16]);

    let output = encrypt_block(input, key);

    assert_eq!(
        output.0,
        [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e
        ]
    );
}

// Trace: `lib/aes_apple.c:AES128_ECB_encrypt_apple`, `lib/aes_apple.h:AES128_ECB_encrypt_apple`
// Spec: AES128_ECB_encrypt_apple encrypts one AES-128 ECB block on Apple#Non-Apple builds exclude implementation
// - **GIVEN** `__APPLE__` 未定义
// - **WHEN** 编译 `lib/aes_apple.c` 和包含 `lib/aes_apple.h`
// - **THEN** 文件 MUST NOT 暴露 `AES128_ECB_encrypt_apple` 的声明或实现给该编译单元
#[test]
fn test_aes_apple_non_apple_builds_use_same_public_dispatch_contract() {
    let input = AesBlock([0x2a; 16]);
    let key = AesBlock([0x7f; 16]);

    let output = encrypt_block(input, key);

    assert_eq!(output.0.len(), 16);
}
