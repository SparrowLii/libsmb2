use libsmb2_sys::legacy::md4;

// Trace: `lib/md4.h:MD4_CTX`, `lib/md4c.c:MD4Init`
// Spec: MD4_CTX expose MD4 context storage#Context layout is visible to callers
// - **GIVEN** 调用方包含 `lib/md4.h` 并需要执行 MD4 生命周期
// - **WHEN** 调用方声明一个 `MD4_CTX` 对象
// - **THEN** 该对象提供 4 个 `uint32_t` 状态字、2 个 `uint32_t` 计数字和 64 字节缓冲区供 `MD4Init`、`MD4Update` 与 `MD4Final` 操作
#[test]
fn test_md4_h_context_layout_is_visible_to_callers() {
    assert_eq!(md4::context_layout(), (4, 2, 64));
}

// Trace: `lib/md4.h:MD4Init`, `lib/md4c.c:MD4Init`
// Spec: MD4Init initialize MD4 context#New context starts from MD4 constants
// - **GIVEN** 调用方提供一个可写的 `MD4_CTX` 指针
// - **WHEN** 调用方执行 `MD4Init(context)`
// - **THEN** `context->count[0]` 和 `context->count[1]` 为 0，`context->state` 被设置为 MD4 初始常量 `0x67452301`、`0xefcdab89`、`0x98badcfe`、`0x10325476`
#[test]
fn test_md4_h_new_context_starts_from_md4_constants() {
    let context = md4::initial_context();

    assert_eq!(context.count, [0, 0]);
    assert_eq!(
        context.state,
        [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476]
    );
}

// Trace: `lib/md4.h:MD4Update`, `lib/md4c.c:MD4Update`, `lib/ntlmssp.c:NTOWFv1`
// Spec: MD4Update process incremental input#Input updates count and buffered state
// - **GIVEN** 调用方已使用 `MD4Init` 初始化 `MD4_CTX`，并提供 `input` 与 `inputLen`
// - **WHEN** 调用方执行 `MD4Update(context, input, inputLen)`
// - **THEN** 上下文累计 bit 计数按 `inputLen * 8` 更新，完整 64 字节块被转换进 `state`，剩余字节被保存在 `buffer` 中
#[test]
fn test_md4_h_input_updates_count_and_buffered_state() {
    let updated = md4::snapshot_after_update(b"abc");

    assert_eq!(updated.count, [24, 0]);
    assert_eq!(&updated.buffer[..3], b"abc");
}

// Trace: `lib/md4.h:MD4Final`, `lib/md4c.c:MD4Final`, `lib/ntlmssp.c:NTOWFv1`
// Spec: MD4Final emit digest and clear context#Finalization writes digest and zeroizes context
// - **GIVEN** 调用方已完成一个或多个 `MD4Update` 调用并提供 16 字节 digest 输出缓冲区
// - **WHEN** 调用方执行 `MD4Final(digest, context)`
// - **THEN** `digest` 接收 16 字节 MD4 摘要，`context` 在摘要写出后被置零以清除内部状态
#[test]
fn test_md4_h_finalization_writes_digest_and_zeroizes_context() {
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
