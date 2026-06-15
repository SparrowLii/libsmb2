use libsmb2_rs::lib::sha::{self, Sha1Context};

// Trace: `lib/sha1.c:SHA1Reset`, `lib/sha.h:SHA1Reset`
// Spec: SHA1Reset context initialization#reset rejects null context
// - **GIVEN** 调用方没有提供 SHA-1 上下文指针
// - **WHEN** 调用 `SHA1Reset(NULL)`
// - **THEN** 函数返回 `shaNull`
#[test]
fn test_sha1_reset_rejects_null_context() {
    assert_eq!(Sha1Context::reset_null(), sha::SHA_NULL);
}

// Trace: `lib/sha1.c:SHA1Reset`, `lib/sha.h:SHA1Context`
// Spec: SHA1Reset context initialization#reset prepares initial FIPS hash state
// - **GIVEN** 调用方提供可写的 `SHA1Context`
// - **WHEN** 调用 `SHA1Reset(context)`
// - **THEN** 函数返回 `shaSuccess`，将长度、消息块索引、Computed 和 Corrupted 清零，并写入 FIPS-180-2 section 5.3.1 的五个初始哈希常量
#[test]
fn test_sha1_reset_prepares_initial_fips_hash_state() {
    let mut context = Sha1Context::zeroed();

    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    let state = context.state();
    assert_eq!(state.length_low, 0);
    assert_eq!(state.length_high, 0);
    assert_eq!(state.message_block_index, 0);
    assert_eq!(state.computed, 0);
    assert_eq!(state.corrupted, 0);
    assert_eq!(
        &state.intermediate_hash[..5],
        &[
            0x6745_2301,
            0xefcd_ab89,
            0x98ba_dcfe,
            0x1032_5476,
            0xc3d2_e1f0
        ]
    );
}

// Trace: `lib/sha1.c:SHA1Input`, `lib/sha.h:SHA1Input`
// Spec: SHA1Input incremental octet processing#input accepts zero length without dereferencing pointers
// - **GIVEN** 调用方传入任意 `context` 和 `message_array` 指针组合且 `length` 为 0
// - **WHEN** 调用 `SHA1Input(context, message_array, 0)`
// - **THEN** 函数返回 `shaSuccess`，并且源码路径在空指针检查前完成零长度返回
#[test]
fn test_sha1_input_accepts_zero_length_without_dereferencing_pointers() {
    assert_eq!(Sha1Context::input_zero_nulls(), sha::SHA_SUCCESS);
}

// Trace: `lib/sha1.c:SHA1Input`, `lib/sha.h:SHA1Input`
// Spec: SHA1Input incremental octet processing#input rejects null active parameters
// - **GIVEN** `length` 大于 0 且 `context` 或 `message_array` 为空
// - **WHEN** 调用 `SHA1Input(context, message_array, length)`
// - **THEN** 函数返回 `shaNull`
#[test]
fn test_sha1_input_rejects_null_active_parameters() {
    let mut context = Sha1Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);

    assert_eq!(Sha1Context::input_null_context(b"abc"), sha::SHA_NULL);
    assert_eq!(context.input_null_message(3), sha::SHA_NULL);
}

// Trace: `lib/sha1.c:SHA1Input`, `lib/sha.h:SHA1Context`
// Spec: SHA1Input incremental octet processing#input rejects updates after digest computation
// - **GIVEN** `context->Computed` 已经为非零
// - **WHEN** 调用 `SHA1Input(context, message_array, length)` 且 `length` 大于 0
// - **THEN** 函数将 `context->Corrupted` 置为 `shaStateError` 并返回 `shaStateError`
#[test]
fn test_sha1_input_rejects_updates_after_digest_computation() {
    let mut context = Sha1Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    context.set_computed(1);

    assert_eq!(context.input(b"x"), sha::SHA_STATE_ERROR);
    assert_eq!(context.state().corrupted, sha::SHA_STATE_ERROR);
}

// Trace: `lib/sha1.c:SHA1Input`, `lib/sha.h:SHA1Context`
// Spec: SHA1Input incremental octet processing#input preserves existing corrupted state
// - **GIVEN** `context->Corrupted` 已经为非零且 `context->Computed` 为 0
// - **WHEN** 调用 `SHA1Input(context, message_array, length)` 且参数非空、`length` 大于 0
// - **THEN** 函数返回现有 `context->Corrupted` 值，不处理新的输入字节
#[test]
fn test_sha1_input_preserves_existing_corrupted_state() {
    let mut context = Sha1Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    context.set_corrupted(sha::SHA_BAD_PARAM);

    assert_eq!(context.input(b"x"), sha::SHA_BAD_PARAM);
    assert_eq!(context.state().message_block_index, 0);
}

// Trace: `lib/sha1.c:SHA1Input`, `lib/sha1.c:SHA1ProcessMessageBlock`, `lib/sha.h:SHA1_Message_Block_Size`
// Spec: SHA1Input incremental octet processing#input processes bytes and message blocks
// - **GIVEN** `context` 已经由 `SHA1Reset` 初始化且输入指针非空
// - **WHEN** 调用 `SHA1Input(context, message_array, length)` 且输入使消息块索引达到 `SHA1_Message_Block_Size`
// - **THEN** 函数 MUST 将每个字节写入消息块、按 8 bit 累加长度，并在完整 64 字节块到达时调用内部压缩处理后继续接收后续字节
#[test]
fn test_sha1_input_processes_bytes_and_message_blocks() {
    let mut context = Sha1Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);

    assert_eq!(context.input(&[b'a'; 65]), sha::SHA_SUCCESS);
    let state = context.state();
    assert_eq!(state.length_low, 520);
    assert_eq!(state.message_block_index, 1);
}

// Trace: `lib/sha1.c:SHA1FinalBits`, `lib/sha.h:SHA1FinalBits`
// Spec: SHA1FinalBits final partial-bit processing#final bits accepts zero length as no-op
// - **GIVEN** 调用方传入任意 `context` 且 `length` 为 0
// - **WHEN** 调用 `SHA1FinalBits(context, message_bits, 0)`
// - **THEN** 函数返回 `shaSuccess`，并且源码路径在空上下文检查前完成零长度返回
#[test]
fn test_sha1_final_bits_accepts_zero_length_as_no_op() {
    assert_eq!(Sha1Context::final_bits_null(0xff, 0), sha::SHA_SUCCESS);
}

// Trace: `lib/sha1.c:SHA1FinalBits`, `lib/sha.h:SHA1FinalBits`
// Spec: SHA1FinalBits final partial-bit processing#final bits rejects null context
// - **GIVEN** `length` 大于 0 且上下文指针为空
// - **WHEN** 调用 `SHA1FinalBits(NULL, message_bits, length)`
// - **THEN** 函数返回 `shaNull`
#[test]
fn test_sha1_final_bits_rejects_null_context() {
    assert_eq!(Sha1Context::final_bits_null(0x80, 1), sha::SHA_NULL);
}

// Trace: `lib/sha1.c:SHA1FinalBits`, `lib/sha.h:SHA1Context`
// Spec: SHA1FinalBits final partial-bit processing#final bits rejects invalid state or length
// - **GIVEN** `context->Computed` 已经为非零，或 `length` 大于等于 8
// - **WHEN** 调用 `SHA1FinalBits(context, message_bits, length)`
// - **THEN** 函数将 `context->Corrupted` 置为 `shaStateError` 并返回 `shaStateError`
#[test]
fn test_sha1_final_bits_rejects_invalid_state_or_length() {
    let mut context = Sha1Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);

    assert_eq!(context.final_bits(0xff, 8), sha::SHA_STATE_ERROR);
    assert_eq!(context.state().corrupted, sha::SHA_STATE_ERROR);
}

// Trace: `lib/sha1.c:SHA1FinalBits`, `lib/sha.h:SHA1Context`
// Spec: SHA1FinalBits final partial-bit processing#final bits propagates existing corruption
// - **GIVEN** `context->Corrupted` 已经为非零且上下文尚未 computed
// - **WHEN** 调用 `SHA1FinalBits(context, message_bits, length)` 且 `length` 在 1 到 7 之间
// - **THEN** 函数返回现有 `context->Corrupted` 值，不执行最终 padding
#[test]
fn test_sha1_final_bits_propagates_existing_corruption() {
    let mut context = Sha1Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    context.set_corrupted(sha::SHA_BAD_PARAM);

    assert_eq!(context.final_bits(0x80, 1), sha::SHA_BAD_PARAM);
    assert_eq!(context.state().computed, 0);
}

// Trace: `lib/sha1.c:SHA1FinalBits`, `lib/sha1.c:SHA1Finalize`, `lib/sha1.c:SHA1PadMessage`
// Spec: SHA1FinalBits final partial-bit processing#final bits masks high bits and finalizes digest
// - **GIVEN** `context` 有效、未 computed、未 corrupted，且 `length` 在 1 到 7 之间
// - **WHEN** 调用 `SHA1FinalBits(context, message_bits, length)`
// - **THEN** 函数 MUST 将消息长度增加 `length` bit，保留 `message_bits` 的高 `length` 位并追加标记 bit，然后执行 SHA-1 padding、清空消息块和长度字段、设置 `context->Computed`，并返回 `shaSuccess`
#[test]
fn test_sha1_final_bits_masks_high_bits_and_finalizes_digest() {
    let mut context = Sha1Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);

    assert_eq!(context.final_bits(0x80, 1), sha::SHA_SUCCESS);
    let state = context.state();
    assert_eq!(state.computed, 1);
    assert_eq!(state.length_low, 0);
    assert_eq!(state.length_high, 0);
}

// Trace: `lib/sha1.c:SHA1Result`, `lib/sha.h:SHA1Result`
// Spec: SHA1Result digest output#result rejects null parameters
// - **GIVEN** `context` 或 `Message_Digest` 为空
// - **WHEN** 调用 `SHA1Result(context, Message_Digest)`
// - **THEN** 函数返回 `shaNull`
#[test]
fn test_sha1_result_rejects_null_parameters() {
    let mut context = Sha1Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);

    assert_eq!(Sha1Context::result_null_context(), sha::SHA_NULL);
    assert_eq!(context.result_null_output(), sha::SHA_NULL);
}

// Trace: `lib/sha1.c:SHA1Result`, `lib/sha.h:SHA1Context`
// Spec: SHA1Result digest output#result returns existing corrupted state
// - **GIVEN** `context->Corrupted` 已经为非零且输出缓冲区非空
// - **WHEN** 调用 `SHA1Result(context, Message_Digest)`
// - **THEN** 函数返回现有 `context->Corrupted` 值，不写出新的摘要字节
#[test]
fn test_sha1_result_returns_existing_corrupted_state() {
    let mut context = Sha1Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    context.set_corrupted(sha::SHA_BAD_PARAM);

    let (code, output) = context.result();
    assert_eq!(code, sha::SHA_BAD_PARAM);
    assert_eq!(output, [0; 20]);
}

// Trace: `lib/sha1.c:SHA1Result`, `lib/sha1.c:SHA1Finalize`, `lib/sha.h:SHA1HashSize`
// Spec: SHA1Result digest output#result finalizes an unfinished context
// - **GIVEN** `context` 有效、未 corrupted、`context->Computed` 为 0 且输出缓冲区可写
// - **WHEN** 调用 `SHA1Result(context, Message_Digest)`
// - **THEN** 函数 MUST 使用 `0x80` 作为整字节消息的 padding 起始字节终结上下文，随后写出 `SHA1HashSize` 个摘要字节并返回 `shaSuccess`
#[test]
fn test_sha1_result_finalizes_an_unfinished_context() {
    let mut context = Sha1Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.input(b"abc"), sha::SHA_SUCCESS);

    let (code, output) = context.result();
    assert_eq!(code, sha::SHA_SUCCESS);
    assert_eq!(output.len(), 20);
    assert_eq!(context.state().computed, 1);
}

// Trace: `lib/sha1.c:SHA1Result`, `lib/sha.h:SHA1HashSize`
// Spec: SHA1Result digest output#result emits digest in big-endian hash-word order
// - **GIVEN** `context->Intermediate_Hash` 包含已计算的五个 32-bit SHA-1 hash words 且 `context->Computed` 为非零
// - **WHEN** 调用 `SHA1Result(context, Message_Digest)`
// - **THEN** 函数 MUST 按每个 hash word 的高字节到低字节顺序填充 `Message_Digest[0]` 到 `Message_Digest[19]`，并返回 `shaSuccess`
#[test]
fn test_sha1_result_emits_digest_in_big_endian_hash_word_order() {
    let mut context = Sha1Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    context.set_intermediate_hash_sha1([
        0x0102_0304,
        0x1112_1314,
        0x2122_2324,
        0x3132_3334,
        0x4142_4344,
    ]);
    context.set_computed(1);

    let (code, output) = context.result();
    assert_eq!(code, sha::SHA_SUCCESS);
    assert_eq!(
        output,
        [
            0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32,
            0x33, 0x34, 0x41, 0x42, 0x43, 0x44,
        ]
    );
}
