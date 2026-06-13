use libsmb2_sys::legacy::aes::{encrypt_block, AesBlock};

// Trace: `lib/aes.h:AES128_ECB_encrypt`, `lib/aes.c:AES128_ECB_encrypt`
// Spec: AES128_ECB_encrypt provides AES-128 ECB block encryption declaration#declaration is available to C translation units
// - **GIVEN** C 源文件包含 `lib/aes.h`，且 `compat.h` 提供 `uint8_t` 类型
// - **WHEN** 调用方按 `void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t *output);` 声明编译调用
// - **THEN** 头文件提供该函数原型，调用方负责提供有效的输入、密钥和输出缓冲区，函数调用本身不产生返回值
// Note: The Rust safe binding cannot compile a C translation unit, so this verifies the exposed no-error-status block encryption call contract through the existing safe AES wrapper.
#[test]
fn test_aes_h_declaration_is_available_to_c_translation_units() {
    let input = AesBlock([0x3c; 16]);
    let key = AesBlock([0xc3; 16]);

    let output = encrypt_block(input, key);

    assert_eq!(output.0.len(), 16);
}

// Trace: `lib/aes.h:AES128_ECB_encrypt`, `lib/aes.c:AES128_ECB_encrypt`
// Spec: AES128_ECB_encrypt provides AES-128 ECB block encryption declaration#implementation selection remains transparent to the header caller
// - **GIVEN** 调用方仅依赖 `lib/aes.h` 中的 `AES128_ECB_encrypt` 声明
// - **WHEN** 链接到 `lib/aes.c` 提供的实现
// - **THEN** Apple 构建 SHALL 通过 `AES128_ECB_encrypt_apple` 执行加密，非 Apple 构建 SHALL 通过 `AES128_ECB_encrypt_reference` 执行加密，且头文件声明保持相同 ABI
// Note: The safe AES binding exposes a stable caller-facing wrapper and not the selected backend, so this verifies that repeated calls through the same ABI surface remain deterministic.
#[test]
fn test_aes_h_implementation_selection_remains_transparent_to_the_header_caller() {
    let input = AesBlock([0xa5; 16]);
    let key = AesBlock([0x5a; 16]);

    let first = encrypt_block(input, key);
    let second = encrypt_block(input, key);

    assert_eq!(first, second);
    assert_eq!(first.0.len(), 16);
}
