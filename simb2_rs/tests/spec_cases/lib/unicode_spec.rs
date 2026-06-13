use libsmb2_sys::legacy::unicode;

// Trace: `lib/unicode.c:smb2_utf8_to_utf16`, `include/smb2/libsmb2.h:smb2_utf8_to_utf16`
// Spec: smb2_utf8_to_utf16 valid UTF-8 conversion#ASCII and multibyte conversion
// - **GIVEN** 调用方提供以 NUL 结束且 UTF-8 编码合法的 `utf8` 字符串
// - **WHEN** 调用 `smb2_utf8_to_utf16(const char *utf8)`
// - **THEN** 返回值为新分配的 `struct smb2_utf16 *`，`len` 等于转换后 UTF-16 code unit 数量，`val` 中每个 code unit 以 little-endian 形式存储
#[test]
fn test_unicode_ascii_and_multibyte_conversion() {
    assert_eq!(
        unicode::utf8_to_utf16_units("Aé你"),
        Some(vec![0x0041, 0x00e9, 0x4f60])
    );
}

// Trace: `lib/unicode.c:smb2_utf8_to_utf16`, `include/smb2/libsmb2.h:smb2_utf8_to_utf16`
// Spec: smb2_utf8_to_utf16 valid UTF-8 conversion#Supplementary plane conversion
// - **GIVEN** 调用方提供包含 UTF-8 四字节合法 codepoint 且 codepoint 小于 `0x110000` 的输入字符串
// - **WHEN** 调用 `smb2_utf8_to_utf16(const char *utf8)`
// - **THEN** 返回的 `val` MUST 使用两个 little-endian UTF-16 surrogate code units 表示该 codepoint，并将 `len` 增加两个 code units
#[test]
fn test_unicode_supplementary_plane_conversion() {
    assert_eq!(unicode::utf8_to_utf16_units("😀"), Some(vec![0xd83d, 0xde00]));
}

// Trace: `lib/unicode.c:smb2_utf16_to_utf8`, `include/smb2/libsmb2.h:smb2_utf16_to_utf8`
// Spec: smb2_utf16_to_utf8 UTF-16LE conversion#BMP conversion
// - **GIVEN** 调用方提供 `utf16_len` 个 little-endian UTF-16 code units，且每个 code unit 位于 ASCII、二字节 UTF-8 或三字节 UTF-8 可表示的 BMP 范围
// - **WHEN** 调用 `smb2_utf16_to_utf8(const uint16_t *str, size_t len)`
// - **THEN** 返回值为新分配的 UTF-8 字符串，内容按 code unit 值转换，且最后一个字节 MUST 为 NUL 终止符
#[test]
fn test_unicode_bmp_conversion() {
    assert_eq!(
        unicode::utf16_units_to_utf8(&[0x0041, 0x00e9, 0x4f60]),
        Some(String::from("Aé你"))
    );
}

// Trace: `lib/unicode.c:smb2_utf16_to_utf8`, `lib/unicode.c:utf16_size`
// Spec: smb2_utf16_to_utf8 UTF-16LE conversion#Surrogate pair conversion
// - **GIVEN** 输入包含 high surrogate 后紧跟合法 low surrogate 的 UTF-16LE pair
// - **WHEN** 调用 `smb2_utf16_to_utf8(const uint16_t *str, size_t len)`
// - **THEN** 函数 MUST 将 surrogate pair 合成为 codepoint，并输出对应的 UTF-8 四字节序列
#[test]
fn test_unicode_surrogate_pair_conversion() {
    assert_eq!(
        unicode::utf16_units_to_utf8(&[0xd83d, 0xde00]),
        Some(String::from("😀"))
    );
}

// Trace: `lib/unicode.c:smb2_utf16_to_utf8`, `lib/unicode.c:utf16_size`
// Spec: smb2_utf16_to_utf8 UTF-16LE conversion#Invalid surrogate replacement
// - **GIVEN** 输入以 high surrogate 结尾、high surrogate 后未跟合法 low surrogate，或输入包含孤立 low surrogate
// - **WHEN** 调用 `smb2_utf16_to_utf8(const uint16_t *str, size_t len)`
// - **THEN** 函数 MUST 在输出中写入 UTF-8 replacement character `0xef 0xbf 0xbd` 表示无效 surrogate 单元
#[test]
fn test_unicode_invalid_surrogate_replacement() {
    assert_eq!(unicode::utf16_units_to_utf8(&[0xd83d]), Some(String::from("�")));
    assert_eq!(unicode::utf16_units_to_utf8(&[0xde00]), Some(String::from("�")));
}
