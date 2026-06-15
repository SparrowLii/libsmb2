use libsmb2_rs::lib::hmac_md5;

// Trace: `lib/hmac-md5.c:smb2_hmac_md5`, `lib/hmac-md5.h:smb2_hmac_md5`, `tests/ntlmssp_generate_blob.c:main`
// Spec: smb2_hmac_md5 compute RFC2104 MD5 HMAC#短密钥直接参与内外层 MD5
// - **GIVEN** 调用方提供长度不超过 64 字节的 `key`、`key_len`、`text`、`text_len` 和至少 16 字节的 `digest` 输出缓冲区
// - **WHEN** 调用方调用 `smb2_hmac_md5`
// - **THEN** 实现 MUST 用原始密钥填充 64 字节内外层 pad，分别应用 `0x36` 和 `0x5c` 异或，并按 `MD5(K XOR opad, MD5(K XOR ipad, text))` 生成 16 字节摘要
#[test]
fn test_hmac_md5_short_key_directly_participates_in_inner_and_outer_md5() {
    let key = [0x0b; 16];
    let text = b"Hi There";

    let digest = hmac_md5::digest(text, &key);

    assert_eq!(
        digest,
        [
            0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b,
            0xfc, 0x9d,
        ]
    );
}

// Trace: `lib/hmac-md5.c:smb2_hmac_md5`, `lib/md5.c:MD5Init`, `lib/md5.c:MD5Update`, `lib/md5.c:MD5Final`
// Spec: smb2_hmac_md5 compute RFC2104 MD5 HMAC#长密钥先折叠为 MD5 摘要
// - **GIVEN** 调用方提供长度大于 64 字节的 `key` 和对应 `key_len`
// - **WHEN** 调用方调用 `smb2_hmac_md5`
// - **THEN** 实现 MUST 先对原始密钥执行 MD5，将临时 16 字节摘要作为 HMAC 密钥，再执行内外层 HMAC-MD5 计算
#[test]
fn test_hmac_md5_long_key_is_folded_to_md5_digest_first() {
    let key = [0xaa; 80];
    let text = b"Test Using Larger Than Block-Size Key - Hash Key First";

    let digest = hmac_md5::digest(text, &key);

    assert_eq!(
        digest,
        [
            0x6b, 0x1a, 0xb7, 0xfe, 0x4b, 0xd7, 0xbf, 0x8f, 0x0b, 0x62, 0xe6, 0xce, 0x61, 0xb9,
            0xd0, 0xcd,
        ]
    );
}
