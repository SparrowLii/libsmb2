use libsmb2_sys::legacy::md5;

// Trace: `lib/md5.c:byteSwap`, `lib/md5.h:WORDS_BIGENDIAN`
// Spec: byteSwap platform word normalization#Little-endian builds do not alter buffers
// - **GIVEN** `WORDS_BIGENDIAN` 未定义且 MD5 处理路径调用 `byteSwap(ctx->in, 16)` 或 `byteSwap(ctx->buf, 4)`
// - **WHEN** 预处理器展开 `byteSwap(buf,words)`
// - **THEN** 该宏 MUST 展开为空操作，使小端平台直接使用已有字节布局
#[test]
fn test_md5_little_endian_builds_do_not_alter_buffers() {
    assert!(!md5::words_bigendian_enabled());
    assert_eq!(md5::snapshot_after_update(b"abc").buffered_bytes(), b"abc");
}

// Trace: `lib/md5.c:MD5Init`, `lib/md5.h:struct MD5Context`
// Spec: MD5Init initializes digest context#New context starts with MD5 constants
// - **GIVEN** 调用方提供可写的 `struct MD5Context *context`
// - **WHEN** 调用方调用 `MD5Init(context)`
// - **THEN** 实现 MUST 设置 `buf` 为 `0x67452301`, `0xefcdab89`, `0x98badcfe`, `0x10325476`，并将 `bytes[0]` 与 `bytes[1]` 置为 0
#[test]
fn test_md5_new_context_starts_with_md5_constants() {
    let context = md5::initial_context();

    assert_eq!(context.bytes, [0, 0]);
    assert_eq!(
        context.buf,
        [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476]
    );
}

// Trace: `lib/md5.c:MD5Update`, `lib/md5.c:MD5Transform`
// Spec: MD5Update accumulates message bytes#Short update is buffered without transform
// - **GIVEN** `context` 已通过 `MD5Init` 初始化且当前输入块剩余空间大于 `len`
// - **WHEN** 调用方调用 `MD5Update(context, buf, len)`
// - **THEN** 实现 MUST 把 `len` 个字节复制到 `context->in` 的当前偏移，更新 `bytes[0]`/`bytes[1]` 字节计数，并返回而不调用 `MD5Transform`
#[test]
fn test_md5_short_update_is_buffered_without_transform() {
    let initial = md5::initial_context();
    let updated = md5::snapshot_after_update(b"abc");

    assert_eq!(updated.bytes, [3, 0]);
    assert_eq!(updated.buffered_bytes(), b"abc");
    assert_eq!(updated.buf, initial.buf);
}

// Trace: `lib/md5.c:MD5Update`, `lib/md5.c:byteSwap`, `lib/md5.c:MD5Transform`
// Spec: MD5Update accumulates message bytes#Complete blocks are transformed
// - **GIVEN** `context` 已累积部分数据或调用方传入至少补齐一个 64 字节块的数据
// - **WHEN** 调用方调用 `MD5Update(context, buf, len)`
// - **THEN** 实现 MUST 补齐首个块、按平台需要执行 `byteSwap`、调用 `MD5Transform(context->buf, context->in)`，并继续处理后续每个完整 64 字节块
#[test]
fn test_md5_complete_blocks_are_transformed() {
    let initial = md5::initial_context();
    let updated = md5::snapshot_after_update(&[b'a'; 64]);

    assert_eq!(updated.bytes, [64, 0]);
    assert_ne!(updated.buf, initial.buf);
}

// Trace: `lib/md5.c:MD5Final`, `lib/md5.c:MD5Transform`
// Spec: MD5Final emits digest and clears context#Finalization writes digest bytes
// - **GIVEN** `context` 已通过 `MD5Init` 和零次或多次 `MD5Update` 累积消息数据，且调用方提供 16 字节 `digest` 缓冲区
// - **WHEN** 调用方调用 `MD5Final(digest, context)`
// - **THEN** 实现 MUST 添加 `0x80` 起始 padding、追加以 bit 为单位的低 64 位消息长度、执行最终 `MD5Transform`，并把 16 字节状态复制到 `digest`
#[test]
fn test_md5_finalization_writes_digest_bytes() {
    assert_eq!(
        md5::digest_with_final_context(b"abc").0,
        [
            0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
            0x7f, 0x72
        ]
    );
}

// Trace: `lib/md5.c:MD5Final`, `lib/md5.h:struct MD5Context`
// Spec: MD5Final emits digest and clears context#Finalization erases context storage
// - **GIVEN** `MD5Final` 已完成 digest 写出
// - **WHEN** 函数返回给调用方
// - **THEN** 实现 MUST 使用零字节覆盖整个 `struct MD5Context` 存储，避免保留中间状态
#[test]
fn test_md5_finalization_erases_context_storage() {
    assert!(md5::digest_with_final_context(b"abc").1.is_zeroed());
}

// Trace: `lib/md5.c:MD5Transform`, `lib/md5.c:MD5STEP`
// Spec: MD5Transform applies MD5 compression round#Transform mutates state with one prepared block
// - **GIVEN** 调用方传入 4 个 `UWORD32` 状态字 `buf` 和 16 个已按平台字节序规范化的 `UWORD32` 输入字 `in`
// - **WHEN** 调用方调用 `MD5Transform(buf, in)`
// - **THEN** 实现 MUST 以 `buf[0..3]` 初始化 `a`, `b`, `c`, `d`，按源码常量和移位执行 64 个 MD5STEP 操作，并把最终 `a`, `b`, `c`, `d` 分别累加到 `buf[0..3]`
#[test]
fn test_md5_transform_mutates_state_with_one_prepared_block() {
    let block = [0x8063_6261, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0];

    assert_eq!(
        md5::transform(md5::initial_context().buf, block),
        [0x9850_0190, 0xb04f_d23c, 0x7d3f_96d6, 0x727f_e128]
    );
}
