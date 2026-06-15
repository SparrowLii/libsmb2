use libsmb2_rs::lib::aes::{encrypt_block, AesBlock};

// Trace: `lib/aes_apple.h:AES128_ECB_encrypt_apple`, `lib/aes_apple.c:AES128_ECB_encrypt_apple`
// Spec: AES128_ECB_encrypt_apple Apple AES-128 ECB declaration#Apple platform exposes AES declaration
// - **GIVEN** 编译单元定义 `__APPLE__` 并包含 `lib/aes_apple.h`
// - **WHEN** 调用方引用 `AES128_ECB_encrypt_apple` 声明
// - **THEN** 头文件提供 `void AES128_ECB_encrypt_apple(const uint8_t* input, const uint8_t* key, uint8_t *output);` 声明且不声明返回错误码
#[test]
fn test_aes_apple_h_apple_platform_exposes_aes_declaration() {
    let input = AesBlock([0x00; 16]);
    let key = AesBlock([0x00; 16]);

    let output = encrypt_block(input, key);

    assert_eq!(output.0.len(), 16);
}
