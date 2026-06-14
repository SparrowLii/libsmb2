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

// Trace: `lib/hmac.c:hmac`, `lib/hmac.c:hmacReset`, `lib/hmac.c:hmacInput`, `lib/hmac.c:hmacResult`
// Spec: hmac one-shot digest calculation#One-shot HMAC propagates the first SHA error
// - **GIVEN** `hmacReset`、`hmacInput` 或 `hmacResult` 中任一步骤返回非零 SHA 错误码
// - **WHEN** 调用方调用 `hmac(whichSha, text, text_len, key, key_len, digest)`
// - **THEN** 该接口 MUST 通过短路求值返回该非零错误码，并不继续执行后续 HMAC 阶段
#[test]
fn test_hmac_one_shot_hmac_propagates_the_first_sha_error() {
    let status = sha::hmac_bad_param_status(b"message", b"key");

    assert_eq!(status, sha::SHA_NULL);
}

// Trace: `lib/hmac.c:hmacReset`, `lib/sha.h:hmacReset`
// Spec: hmacReset context initialization and key padding#Null HMAC context is rejected
// - **GIVEN** 调用方传入 `ctx == NULL`
// - **WHEN** 调用方调用 `hmacReset(ctx, whichSha, key, key_len)`
// - **THEN** 该接口 MUST 返回 `shaNull` 且不访问 context 字段
#[test]
fn test_hmac_null_hmac_context_is_rejected() {
    assert_eq!(sha::hmac_reset_null_sha256(b"key"), sha::SHA_NULL);
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

// Trace: `lib/hmac.c:hmacInput`, `lib/sha.h:hmacInput`
// Spec: hmacInput message streaming#Null HMAC context input is rejected
// - **GIVEN** 调用方传入 `ctx == NULL`
// - **WHEN** 调用方调用 `hmacInput(ctx, text, text_len)`
// - **THEN** 该接口 MUST 返回 `shaNull` 且不调用 `USHAInput`
#[test]
fn test_hmac_null_hmac_context_input_is_rejected() {
    assert_eq!(sha::hmac_input_null(b"message"), sha::SHA_NULL);
}

// Trace: `lib/hmac.c:hmacInput`, `lib/usha.c:USHAInput`, `lib/libsmb2.c:smb2_derive_key`, `lib/smb2-signing.c:smb2_calc_signature`
// Spec: hmacInput message streaming#Message bytes are forwarded to inner SHA context
// - **GIVEN** 调用方已通过 `hmacReset` 初始化 context，并提供消息片段指针和长度
// - **WHEN** 调用方调用 `hmacInput(ctx, text, text_len)`
// - **THEN** 该接口 MUST 调用 `USHAInput(&ctx->shaContext, text, text_len)`，并返回底层 SHA 输入结果
#[test]
fn test_hmac_message_bytes_are_forwarded_to_inner_sha_context() {
    let key = [0x0b; 20];
    let text = b"Hi There";

    let (status, digest) = sha::hmac_sha256_streaming(text, &key);

    assert_eq!(status, sha::SHA_SUCCESS);
    assert_eq!(digest, sha::hmac_sha256(text, &key));
}

// Trace: `lib/hmac.c:hmacFinalBits`, `lib/sha.h:hmacFinalBits`
// Spec: hmacFinalBits final bit streaming#Null HMAC context final bits are rejected
// - **GIVEN** 调用方传入 `ctx == NULL`
// - **WHEN** 调用方调用 `hmacFinalBits(ctx, bits, bitcount)`
// - **THEN** 该接口 MUST 返回 `shaNull` 且不调用 `USHAFinalBits`
#[test]
fn test_hmac_null_hmac_context_final_bits_are_rejected() {
    assert_eq!(sha::hmac_final_bits_null(0b1000_0000, 1), sha::SHA_NULL);
}

// Trace: `lib/hmac.c:hmacFinalBits`, `lib/usha.c:USHAFinalBits`
// Spec: hmacFinalBits final bit streaming#Final bits are forwarded to inner SHA context
// - **GIVEN** 调用方已通过 `hmacReset` 初始化 context，并提供位于 byte 高位部分的 final bits 和 bit count
// - **WHEN** 调用方调用 `hmacFinalBits(ctx, bits, bitcount)`
// - **THEN** 该接口 MUST 调用 `USHAFinalBits(&ctx->shaContext, bits, bitcount)`，并返回底层 SHA final bits 结果
#[test]
fn test_hmac_final_bits_are_forwarded_to_inner_sha_context() {
    let (status, digest) = sha::hmac_sha256_final_bits(b"key", 0b1000_0000, 1);

    assert_eq!(status, sha::SHA_SUCCESS);
    assert_ne!(digest, [0; 32]);
}

// Trace: `lib/hmac.c:hmacResult`, `lib/sha.h:hmacResult`
// Spec: hmacResult outer digest completion#Null HMAC context result is rejected
// - **GIVEN** 调用方传入 `ctx == NULL`
// - **WHEN** 调用方调用 `hmacResult(ctx, digest)`
// - **THEN** 该接口 MUST 返回 `shaNull` 且不访问 context 字段或 digest 缓冲区
#[test]
fn test_hmac_null_hmac_context_result_is_rejected() {
    assert_eq!(sha::hmac_result_null(), sha::SHA_NULL);
}

// Trace: `lib/hmac.c:hmacResult`, `lib/usha.c:USHAResult`, `lib/usha.c:USHAReset`, `lib/usha.c:USHAInput`, `lib/libsmb2.c:smb2_derive_key`, `lib/smb2-signing.c:smb2_calc_signature`, `tests/prog_cat.c:pr_cb`, `tests/prog_cat_cancel.c:pr_cb`
// Spec: hmacResult outer digest completion#HMAC result writes final digest through outer SHA pass
// - **GIVEN** 调用方已通过 `hmacReset` 初始化 context 并通过 `hmacInput` 输入全部消息片段，且提供可写 digest 缓冲区
// - **WHEN** 调用方调用 `hmacResult(ctx, digest)`
// - **THEN** 该接口 MUST 先用 `USHAResult` 把 inner hash 写入 `digest` 临时缓冲区，再用 `ctx->k_opad`、`ctx->blockSize` 和 `ctx->hashSize` 执行 outer SHA，并把最终 HMAC digest 写回同一 `digest` 缓冲区
#[test]
fn test_hmac_hmac_result_writes_final_digest_through_outer_sha_pass() {
    let key = b"Jefe";
    let text = b"what do ya want for nothing?";

    let (status, digest) = sha::hmac_sha256_streaming(text, key);

    assert_eq!(status, sha::SHA_SUCCESS);
    assert_eq!(digest, sha::hmac_sha256(text, key));
}
