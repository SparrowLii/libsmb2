use libsmb2_rs::lib::md5;

// Trace: `lib/md5.h:UWORD32`
// Spec: UWORD32 32-bit word typedef#默认平台公开 MD5 32 位字类型
// - **GIVEN** 编译环境未定义 `PS2_IOP_PLATFORM` 且未预先定义 `UWORD32_DEFINED`
// - **WHEN** 调用方包含 `lib/md5.h`
// - **THEN** `UWORD32` 可作为 `uint32_t` 兼容的公开类型用于 MD5 状态和块参数
#[test]
fn test_md5_h_default_platform_exposes_md5_32_bit_word_type() {
    let context = md5::initial_context();

    assert_eq!(context.buf.len(), 4);
    assert_eq!(std::mem::size_of_val(&context.buf[0]), 4);
}

// Trace: `lib/md5.h:md5byte`
// Spec: md5byte byte alias#输入缓冲区使用 md5byte 类型
// - **GIVEN** 调用方包含 `lib/md5.h`
// - **WHEN** 调用方声明传给 `MD5Update` 的输入缓冲区
// - **THEN** `md5byte` 展开为 `unsigned char` 并与函数声明保持一致
#[test]
fn test_md5_h_input_buffer_uses_md5byte_type() {
    assert_eq!(md5::snapshot_after_update(b"abc").buffered_bytes(), b"abc");
}

// Trace: `lib/md5.h:MD5Context`, `lib/md5.c:MD5Init`, `lib/md5.c:MD5Update`, `lib/md5.c:MD5Final`
// Spec: MD5Context caller-owned digest state#调用方分配可跨阶段传递的上下文
// - **GIVEN** 调用方需要计算一段或多段输入的 MD5 摘要
// - **WHEN** 调用方声明 `struct MD5Context` 并按生命周期传入 MD5 接口
// - **THEN** 上下文提供状态字、字节计数和输入缓冲区用于实现累积摘要状态
#[test]
fn test_md5_h_caller_allocates_context_across_lifecycle() {
    assert_eq!(md5::context_layout(), (4, 2, 16));
}

// Trace: `lib/md5.h:MD5Init`, `lib/md5.c:MD5Init`
// Spec: MD5Init initialize digest context#初始化新摘要计算
// - **GIVEN** 调用方提供一个可写的 `struct MD5Context *context`
// - **WHEN** 调用方调用 `MD5Init(context)`
// - **THEN** 上下文状态字被设置为 MD5 初始常量且 `bytes` 计数被清零
#[test]
fn test_md5_h_initialize_new_digest_calculation() {
    let context = md5::initial_context();

    assert_eq!(context.bytes, [0, 0]);
    assert_eq!(
        context.buf,
        [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476]
    );
}

// Trace: `lib/md5.h:MD5Update`, `lib/md5.c:MD5Update`
// Spec: MD5Update append bytes to digest context#追加不足一个块的输入
// - **GIVEN** 已调用 `MD5Init` 的上下文和长度小于当前块剩余容量的输入缓冲区
// - **WHEN** 调用方调用 `MD5Update(context, buf, len)`
// - **THEN** 上下文字节计数增加 `len` 且输入字节保留在内部块缓冲区等待后续输入或 final
#[test]
fn test_md5_h_append_input_shorter_than_one_block() {
    let updated = md5::snapshot_after_update(b"abc");

    assert_eq!(updated.bytes, [3, 0]);
    assert_eq!(updated.buffered_bytes(), b"abc");
}

// Trace: `lib/md5.h:MD5Update`, `lib/md5.c:MD5Update`, `lib/md5.c:MD5Transform`
// Spec: MD5Update append bytes to digest context#追加包含完整块的输入
// - **GIVEN** 已调用 `MD5Init` 的上下文和足以填满至少一个 64 字节块的输入缓冲区
// - **WHEN** 调用方调用 `MD5Update(context, buf, len)`
// - **THEN** 实现对每个完整 64 字节块调用 `MD5Transform`，并保留剩余字节用于后续处理
#[test]
fn test_md5_h_append_input_containing_complete_block() {
    let initial = md5::initial_context();
    let updated = md5::snapshot_after_update(&[b'a'; 65]);

    assert_eq!(updated.bytes, [65, 0]);
    assert_ne!(updated.buf, initial.buf);
    assert_eq!(updated.buffered_bytes(), b"a");
}

// Trace: `lib/md5.h:MD5Final`, `lib/md5.c:MD5Final`
// Spec: MD5Final produce 16-byte digest and clear context#完成摘要计算
// - **GIVEN** 已通过 `MD5Init` 初始化并通过零次或多次 `MD5Update` 累积输入的上下文
// - **WHEN** 调用方调用 `MD5Final(digest, context)`
// - **THEN** `digest` 包含 16 字节 MD5 摘要且上下文对象内容被置零
#[test]
fn test_md5_h_complete_digest_calculation() {
    let (digest, context) = md5::digest_with_final_context(b"abc");

    assert_eq!(
        digest,
        [
            0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
            0x7f, 0x72
        ]
    );
    assert!(context.is_zeroed());
}

// Trace: `lib/md5.h:MD5Transform`, `lib/md5.c:MD5Transform`
// Spec: MD5Transform transform one MD5 block#转换一个 512-bit 块
// - **GIVEN** 调用方提供四字 MD5 状态缓冲区和 16 字输入块
// - **WHEN** 调用方调用 `MD5Transform(buf, in)`
// - **THEN** 实现执行四轮 MD5 step 运算并更新 `buf[0]` 到 `buf[3]`
#[test]
fn test_md5_h_transform_one_512_bit_block() {
    let block = [0x8063_6261, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0];

    assert_eq!(
        md5::transform(md5::initial_context().buf, block),
        [0x9850_0190, 0xb04f_d23c, 0x7d3f_96d6, 0x727f_e128]
    );
}
