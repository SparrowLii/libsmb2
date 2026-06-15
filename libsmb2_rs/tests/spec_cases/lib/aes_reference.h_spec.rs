use libsmb2_rs::lib::aes_reference::{
    cbc_decrypt, cbc_encrypt, default_cbc_declarations_enabled, default_cbc_value,
    ecb_decrypt_block, ecb_encrypt_block, external_ecb_declarations_enabled_when_disabled,
    external_ecb_value_when_disabled, RefAesBlock as AesBlock,
};

// Trace: `lib/aes_reference.h:CBC`
// Spec: CBC compile-time declaration switch#默认关闭 CBC declarations
// - **GIVEN** 调用方包含 `lib/aes_reference.h` 前未定义 `CBC`
// - **WHEN** 预处理器处理 `CBC` 相关声明区域
// - **THEN** 头文件提供 `CBC` 的默认值 `0`，且不会声明 CBC encrypt/decrypt reference 函数
#[test]
fn test_aes_reference_h_default_cbc_declarations_disabled() {
    assert_eq!(default_cbc_value(), 0);
    assert!(!default_cbc_declarations_enabled());
}

// Trace: `lib/aes_reference.h:CBC`
// Spec: CBC compile-time declaration switch#外部开启 CBC declarations
// - **GIVEN** 调用方包含 `lib/aes_reference.h` 前将 `CBC` 定义为真值
// - **WHEN** 预处理器处理 `#if defined(CBC) && CBC` 区域
// - **THEN** 头文件 MUST 暴露 `AES128_CBC_encrypt_buffer_reference` 和 `AES128_CBC_decrypt_buffer_reference` 声明
#[test]
fn test_aes_reference_h_external_cbc_declarations_enabled() {
    let key = AesBlock([0x00; 16]);
    let iv = AesBlock([0x00; 16]);
    let plaintext = [0x00; 16];

    let ciphertext = cbc_encrypt(&plaintext, key, iv);
    let decrypted = cbc_decrypt(&ciphertext, key, iv);

    assert_eq!(decrypted, plaintext);
}

// Trace: `lib/aes_reference.h:ECB`
// Spec: ECB compile-time declaration switch#默认开启 ECB declarations
// - **GIVEN** 调用方包含 `lib/aes_reference.h` 前未定义 `ECB`
// - **WHEN** 预处理器处理 `ECB` 相关声明区域
// - **THEN** 头文件提供 `ECB` 的默认值 `1`，并声明 ECB encrypt/decrypt reference 函数
#[test]
fn test_aes_reference_h_default_ecb_declarations_enabled() {
    let key = AesBlock([0x00; 16]);
    let plaintext = AesBlock([0x00; 16]);

    let ciphertext = ecb_encrypt_block(plaintext, key);
    let decrypted = ecb_decrypt_block(ciphertext, key);

    assert_eq!(decrypted, plaintext);
}

// Trace: `lib/aes_reference.h:ECB`
// Spec: ECB compile-time declaration switch#外部关闭 ECB declarations
// - **GIVEN** 调用方包含 `lib/aes_reference.h` 前将 `ECB` 定义为 `0`
// - **WHEN** 预处理器处理 `#if defined(ECB) && ECB` 区域
// - **THEN** 头文件 MUST NOT 暴露 `AES128_ECB_encrypt_reference` 或 `AES128_ECB_decrypt_reference` 声明
#[test]
fn test_aes_reference_h_external_ecb_declarations_disabled() {
    assert_eq!(external_ecb_value_when_disabled(), 0);
    assert!(!external_ecb_declarations_enabled_when_disabled());
}

// Trace: `lib/aes_reference.h:AES128_ECB_encrypt_reference`, `lib/aes_reference.c:AES128_ECB_encrypt_reference`
// Spec: AES128_ECB_encrypt_reference ECB block encryption declaration#声明 ECB encrypt reference function
// - **GIVEN** `ECB` 编译期开关为真且 `uint8_t` 可用
// - **WHEN** 调用方包含 `lib/aes_reference.h`
// - **THEN** 调用方可见 `AES128_ECB_encrypt_reference` 的三参数 `void` 声明，且该声明不返回错误码或状态值
#[test]
fn test_aes_reference_h_ecb_encrypt_reference_function_declared() {
    let key = AesBlock([0x00; 16]);
    let plaintext = AesBlock([0x00; 16]);

    let ciphertext = ecb_encrypt_block(plaintext, key);

    assert_eq!(
        ciphertext.0,
        [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e
        ]
    );
}

// Trace: `lib/aes_reference.h:AES128_ECB_decrypt_reference`, `lib/aes_reference.c:AES128_ECB_decrypt_reference`
// Spec: AES128_ECB_decrypt_reference ECB block decryption declaration#声明 ECB decrypt reference function
// - **GIVEN** `ECB` 编译期开关为真且 `uint8_t` 可用
// - **WHEN** 调用方包含 `lib/aes_reference.h`
// - **THEN** 调用方可见 `AES128_ECB_decrypt_reference` 的三参数 `void` 声明，且该声明不返回错误码或状态值
#[test]
fn test_aes_reference_h_ecb_decrypt_reference_function_declared() {
    let key = AesBlock([0x00; 16]);
    let ciphertext = AesBlock([
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e,
    ]);

    let plaintext = ecb_decrypt_block(ciphertext, key);

    assert_eq!(plaintext.0, [0x00; 16]);
}

// Trace: `lib/aes_reference.h:AES128_CBC_encrypt_buffer_reference`, `lib/aes_reference.c:AES128_CBC_encrypt_buffer_reference`
// Spec: AES128_CBC_encrypt_buffer_reference CBC buffer encryption declaration#声明 CBC encrypt buffer reference function
// - **GIVEN** `CBC` 编译期开关为真且 `uint32_t` 与 `uint8_t` 可用
// - **WHEN** 调用方包含 `lib/aes_reference.h`
// - **THEN** 调用方可见 `AES128_CBC_encrypt_buffer_reference` 的五参数 `void` 声明，且该声明不返回错误码或状态值
#[test]
fn test_aes_reference_h_cbc_encrypt_buffer_reference_function_declared() {
    let key = AesBlock([0x00; 16]);
    let iv = AesBlock([0x00; 16]);
    let plaintext = [0x00; 16];

    let ciphertext = cbc_encrypt(&plaintext, key, iv);

    assert_eq!(ciphertext.len(), 16);
}

// Trace: `lib/aes_reference.h:AES128_CBC_decrypt_buffer_reference`, `lib/aes_reference.c:AES128_CBC_decrypt_buffer_reference`
// Spec: AES128_CBC_decrypt_buffer_reference CBC buffer decryption declaration#声明 CBC decrypt buffer reference function
// - **GIVEN** `CBC` 编译期开关为真且 `uint32_t` 与 `uint8_t` 可用
// - **WHEN** 调用方包含 `lib/aes_reference.h`
// - **THEN** 调用方可见 `AES128_CBC_decrypt_buffer_reference` 的五参数 `void` 声明，且该声明不返回错误码或状态值
#[test]
fn test_aes_reference_h_cbc_decrypt_buffer_reference_function_declared() {
    let key = AesBlock([0x00; 16]);
    let iv = AesBlock([0x00; 16]);
    let ciphertext = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e,
    ];

    let plaintext = cbc_decrypt(&ciphertext, key, iv);

    assert_eq!(plaintext, [0x00; 16]);
}
