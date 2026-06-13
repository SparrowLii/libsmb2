use libsmb2_sys::legacy::unicode;

// Trace: `include/smb2/libsmb2.h:smb2_unicode_api`, `lib/unicode.c:smb2_utf8_to_utf16`
// Spec: smb2_unicode_api convert UTF encodings#UTF-8 转 UTF-16LE
// - **GIVEN** 调用方提供有效 UTF-8 字符串
// - **WHEN** 调用方调用 `smb2_utf8_to_utf16(utf8)`
// - **THEN** 成功时 MUST 返回包含 UTF-16 code unit 长度和 little-endian code units 的 `struct smb2_utf16 *`，失败时 MUST 返回 `NULL`
#[test]
fn test_libsmb2_utf8_to_utf16le() {
    assert_eq!(
        unicode::utf8_to_utf16_units("Aé你"),
        Some(vec![0x0041, 0x00e9, 0x4f60])
    );
}

// Trace: `include/smb2/libsmb2.h:smb2_unicode_api`, `lib/unicode.c:smb2_utf16_to_utf8`
// Spec: smb2_unicode_api convert UTF encodings#UTF-16LE 转 UTF-8
// - **GIVEN** 调用方提供 UTF-16LE code unit 指针和长度
// - **WHEN** 调用方调用 `smb2_utf16_to_utf8(str, len)`
// - **THEN** 成功时 MUST 返回可由 `free()` 释放的 UTF-8 字符串
#[test]
fn test_libsmb2_utf16le_to_utf8() {
    assert_eq!(
        unicode::utf16_units_to_utf8(&[0x0041, 0x00e9, 0x4f60]),
        Some(String::from("Aé你"))
    );
}
