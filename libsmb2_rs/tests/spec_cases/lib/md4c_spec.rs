use libsmb2_sys::legacy::md4;

// Trace: `lib/md4c.c:MD4Init`
// Spec: MD4Init initialize context state#initialize fresh context
// - **GIVEN** 调用方提供一个可写的 `MD4_CTX *context`
// - **WHEN** 调用方执行 `MD4Init(context)`
// - **THEN** `context->count[0]` 和 `context->count[1]` 均为 `0`，且 `state` 被设置为 `0x67452301`、`0xefcdab89`、`0x98badcfe`、`0x10325476`
#[test]
fn test_md4c_initialize_fresh_context() {
    let context = md4::initial_context();

    assert_eq!(context.count, [0, 0]);
    assert_eq!(
        context.state,
        [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476]
    );
}

// Trace: `lib/md4c.c:MD4Update`
// Spec: MD4Update absorb message bytes#update with partial block
// - **GIVEN** 调用方已经通过 `MD4Init` 初始化 `context`，且输入长度不足以填满当前 64 字节块
// - **WHEN** 调用方执行 `MD4Update(context, input, inputLen)`
// - **THEN** 系统更新 `context->count` 的 bit 长度，并把剩余输入字节保存在 `context->buffer` 中供后续 update 或 final 使用
#[test]
fn test_md4c_update_with_partial_block() {
    let updated = md4::snapshot_after_update(b"abc");

    assert_eq!(updated.count, [24, 0]);
    assert_eq!(&updated.buffer[..3], b"abc");
}

// Trace: `lib/md4c.c:MD4Update`, `lib/md4c.c:MD4Transform`
// Spec: MD4Update absorb message bytes#update with complete blocks
// - **GIVEN** 调用方已经通过 `MD4Init` 初始化 `context`，且输入长度足以填满一个或多个 64 字节块
// - **WHEN** 调用方执行 `MD4Update(context, input, inputLen)`
// - **THEN** 系统对已满的 64 字节块执行 MD4 block transform，并只把未满 64 字节的尾部输入保存在 `context->buffer`
#[test]
fn test_md4c_update_with_complete_blocks() {
    let initial = md4::initial_context();
    let updated = md4::snapshot_after_update(&[b'a'; 65]);

    assert_eq!(updated.count, [520, 0]);
    assert_ne!(updated.state, initial.state);
    assert_eq!(updated.buffer[0], b'a');
}

// Trace: `lib/md4c.c:MD4Final`, `lib/md4c.c:Encode`, `lib/md4c.c:MD4_memset`
// Spec: MD4Final produce digest and clear context#finalize digest
// - **GIVEN** 调用方已经通过 `MD4Init` 和零次或多次 `MD4Update` 准备 `context`，并提供可写的 `digest[16]`
// - **WHEN** 调用方执行 `MD4Final(digest, context)`
// - **THEN** 系统写入 16 字节摘要到 `digest`，并将 `context` 字节清零
#[test]
fn test_md4c_finalize_digest() {
    let (digest, context) = md4::digest_with_final_context(b"abc");

    assert_eq!(
        digest,
        [
            0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6,
            0x72, 0x9d
        ]
    );
    assert!(context.is_zeroed());
}
