use libsmb2_sys::legacy::hmac_md5;

// Trace: `lib/hmac-md5.h:smb2_hmac_md5`, `lib/hmac-md5.c:smb2_hmac_md5`
// Spec: smb2_hmac_md5 computes RFC2104-compatible MD5 HMAC#key length within block size
// - **GIVEN** 调用方提供不超过 64 字节的 `key`、对应 `key_len`、`text`、`text_len` 和至少 16 字节的 `digest` 缓冲区
// - **WHEN** 调用方调用 `smb2_hmac_md5(text, text_len, key, key_len, digest)`
// - **THEN** 实现使用原始 key 构造 ipad/opad，并将内部 MD5 和外部 MD5 的最终 16 字节结果写入 `digest`
#[test]
fn test_hmac_md5_h_key_length_within_block_size() {
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

// Trace: `lib/hmac-md5.h:smb2_hmac_md5`, `lib/hmac-md5.c:smb2_hmac_md5`
// Spec: smb2_hmac_md5 computes RFC2104-compatible MD5 HMAC#key length exceeds block size
// - **GIVEN** 调用方提供大于 64 字节的 `key` 和有效 `digest` 缓冲区
// - **WHEN** 调用方调用 `smb2_hmac_md5(text, text_len, key, key_len, digest)`
// - **THEN** 实现 MUST 先对 key 执行 MD5 压缩为 16 字节临时 key，再基于该临时 key 计算 HMAC-MD5 摘要
#[test]
fn test_hmac_md5_h_key_length_exceeds_block_size() {
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
