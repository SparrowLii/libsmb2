use libsmb2_sys::legacy::sha;

// Trace: `lib/hmac.c:hmac`, `lib/sha.h:hmac`
// Spec: hmac one-shot digest calculation#One-shot HMAC succeeds through reset input result sequence
// - **GIVEN** 调用方提供有效 `whichSha`、消息缓冲区、key 缓冲区和至少 `USHAMaxHashSize` 可写 digest 缓冲区
// - **WHEN** 调用方调用 `hmac(whichSha, text, text_len, key, key_len, digest)`
// - **THEN** 实现 MUST 创建本地 `HMACContext`，依次执行 `hmacReset`、`hmacInput` 和 `hmacResult`，并在全部步骤成功时返回 `shaSuccess`
#[test]
fn test_hmac_one_shot_hmac_succeeds_through_reset_input_result_sequence() {
    let key = [0x0b; 20];
    let text = b"Hi There";

    let digest = sha::hmac_sha256(text, &key);

    assert_eq!(
        digest,
        [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ]
    );
}

// Trace: `lib/hmac.c:hmacReset`, `lib/usha.c:USHAReset`, `lib/usha.c:USHAInput`, `lib/usha.c:USHAResult`
// Spec: hmacReset context initialization and key padding#Long key is hashed before pad construction
// - **GIVEN** 调用方传入的 `key_len` 大于 `USHABlockSize(whichSha)` 返回的 block size
// - **WHEN** `hmacReset` 初始化 HMAC context
// - **THEN** 该接口 MUST 使用 `USHAReset`、`USHAInput` 和 `USHAResult` 将 key 压缩为所选 SHA 的 hash 输出，并把后续 HMAC key 长度设置为 `USHAHashSize(whichSha)`
#[test]
fn test_hmac_long_key_is_hashed_before_pad_construction() {
    let key = [0xaa; 131];
    let text = b"Test Using Larger Than Block-Size Key - Hash Key First";

    let digest = sha::hmac_sha256(text, &key);

    assert_eq!(
        digest,
        [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54,
        ]
    );
}

// Trace: `lib/hmac.c:hmacReset`, `lib/sha.h:HMACContext`
// Spec: hmacReset context initialization and key padding#Pads and inner hash state are initialized
// - **GIVEN** 调用方传入非 NULL context，且 key 长度不超过所选 SHA block size或已被压缩
// - **WHEN** `hmacReset` 构造 HMAC 初始状态
// - **THEN** 该接口 MUST 将 key 字节分别 XOR `0x36` 和 `0x5c` 形成 inner pad 与 `ctx->k_opad`，用 `0x36`/`0x5c` 填充剩余 block 字节，并以 inner pad 作为 `ctx->shaContext` 的首段输入
#[test]
fn test_hmac_pads_and_inner_hash_state_are_initialized() {
    let key = b"Jefe";
    let text = b"what do ya want for nothing?";

    let digest = sha::hmac_sha256(text, key);

    assert_eq!(
        digest,
        [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ]
    );
}
