use libsmb2_rs::lib::sha::{self, Sha224Context, Sha256Context};

// Trace: `lib/sha224-256.c:SHA224Reset`, `lib/sha224-256.c:SHA224_256Reset`
// Spec: SHA224Reset initialize SHA-224 context#成功初始化 SHA-224 上下文
// - **GIVEN** 调用方提供非空 `SHA224Context` 指针且编译启用 `USE_SHA224`
// - **WHEN** 调用 `SHA224Reset(context)`
// - **THEN** 函数返回 `shaSuccess`，清零长度和块索引，设置 SHA-224 初始哈希值，并将 `Computed` 与 `Corrupted` 置为 0
#[test]
fn test_sha224_256_success_initialize_sha_224_context() {
    let mut context = Sha224Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    let state = context.state();
    assert_eq!(state.length_low, 0);
    assert_eq!(state.length_high, 0);
    assert_eq!(state.message_block_index, 0);
    assert_eq!(state.computed, 0);
    assert_eq!(state.corrupted, 0);
}

// Trace: `lib/sha224-256.c:SHA224Reset`, `lib/sha224-256.c:SHA224_256Reset`
// Spec: SHA224Reset initialize SHA-224 context#拒绝空 SHA-224 上下文
// - **GIVEN** 编译启用 `USE_SHA224` 且调用方传入空 `context`
// - **WHEN** 调用 `SHA224Reset(context)`
// - **THEN** 函数返回 `shaNull` 且不写入上下文状态
#[test]
fn test_sha224_256_reject_null_sha_224_context() {
    assert_eq!(Sha224Context::reset_null(), sha::SHA_NULL);
}

// Trace: `lib/sha224-256.c:SHA224Input`, `lib/sha224-256.c:SHA256Input`
// Spec: SHA224Input append SHA-224 octets#SHA-224 输入复用共享输入逻辑
// - **GIVEN** 已通过 `SHA224Reset` 初始化的上下文和非空消息缓冲区
// - **WHEN** 调用 `SHA224Input(context, message_array, length)` 且 `length` 大于 0
// - **THEN** 函数按字节追加消息、按 8 bit 累加长度、在 64 字节块满时处理消息块，并返回共享输入逻辑产生的错误码
#[test]
fn test_sha224_256_sha_224_input_reuses_shared_input_logic() {
    let mut context = Sha224Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.input(&[b'a'; 65]), sha::SHA_SUCCESS);
    let state = context.state();
    assert_eq!(state.length_low, 520);
    assert_eq!(state.message_block_index, 1);
}

// Trace: `lib/sha224-256.c:SHA224FinalBits`, `lib/sha224-256.c:SHA256FinalBits`
// Spec: SHA224FinalBits append SHA-224 trailing bits#SHA-224 final bits 复用共享最终化逻辑
// - **GIVEN** 已通过 `SHA224Reset` 初始化且尚未计算摘要的上下文
// - **WHEN** 调用 `SHA224FinalBits(context, message_bits, length)` 且 `length` 位于 1 到 7
// - **THEN** 函数累加尾部 bit 长度，按高位有效 bit 加入终止标记并最终化上下文，返回共享 final bits 逻辑产生的错误码
#[test]
fn test_sha224_256_sha_224_final_bits_reuses_shared_finalization_logic() {
    let mut context = Sha224Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.final_bits(0x80, 1), sha::SHA_SUCCESS);
    assert_eq!(context.state().computed, 1);
}

// Trace: `lib/sha224-256.c:SHA224Result`, `lib/sha224-256.c:SHA224_256ResultN`
// Spec: SHA224Result return 224-bit digest#输出 SHA-224 摘要
// - **GIVEN** 已通过 SHA-224 输入路径填充的上下文和非空 `Message_Digest` 缓冲区
// - **WHEN** 调用 `SHA224Result(context, Message_Digest)`
// - **THEN** 函数在需要时最终化上下文，按 big-endian 字节顺序写入 `SHA224HashSize` 个摘要字节，并返回 `shaSuccess`
#[test]
fn test_sha224_256_output_sha_224_digest() {
    let mut context = Sha224Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.input(b"abc"), sha::SHA_SUCCESS);
    let (code, digest) = context.result();
    assert_eq!(code, sha::SHA_SUCCESS);
    assert_eq!(digest.len(), 28);
    assert_eq!(context.state().computed, 1);
}

// Trace: `lib/sha224-256.c:SHA256Reset`, `lib/sha224-256.c:SHA224_256Reset`
// Spec: SHA256Reset initialize SHA-256 context#成功初始化 SHA-256 上下文
// - **GIVEN** 调用方提供非空 `SHA256Context` 指针
// - **WHEN** 调用 `SHA256Reset(context)`
// - **THEN** 函数返回 `shaSuccess`，清零长度和块索引，设置 SHA-256 初始哈希值，并将 `Computed` 与 `Corrupted` 置为 0
#[test]
fn test_sha224_256_success_initialize_sha_256_context() {
    let mut context = Sha256Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    let state = context.state();
    assert_eq!(state.length_low, 0);
    assert_eq!(state.length_high, 0);
    assert_eq!(state.message_block_index, 0);
    assert_eq!(state.computed, 0);
    assert_eq!(state.corrupted, 0);
}

// Trace: `lib/sha224-256.c:SHA256Reset`, `lib/sha224-256.c:SHA224_256Reset`
// Spec: SHA256Reset initialize SHA-256 context#拒绝空 SHA-256 上下文
// - **GIVEN** 调用方传入空 `context`
// - **WHEN** 调用 `SHA256Reset(context)`
// - **THEN** 函数返回 `shaNull` 且不写入上下文状态
#[test]
fn test_sha224_256_reject_null_sha_256_context() {
    assert_eq!(Sha256Context::reset_null(), sha::SHA_NULL);
}

// Trace: `lib/sha224-256.c:SHA256Input`
// Spec: SHA256Input append SHA-256 octets#零长度输入直接成功
// - **GIVEN** 任意 `context` 和 `message_array` 参数组合
// - **WHEN** 调用 `SHA256Input(context, message_array, 0)`
// - **THEN** 函数返回 `shaSuccess`，且不检查空指针、不修改上下文状态
#[test]
fn test_sha224_256_zero_length_input_succeeds_immediately() {
    assert_eq!(Sha256Context::input_zero_nulls(), sha::SHA_SUCCESS);
}

// Trace: `lib/sha224-256.c:SHA256Input`
// Spec: SHA256Input append SHA-256 octets#拒绝非零长度空参数
// - **GIVEN** `length` 大于 0，且 `context` 或 `message_array` 为空
// - **WHEN** 调用 `SHA256Input(context, message_array, length)`
// - **THEN** 函数返回 `shaNull`，且不执行消息块追加
#[test]
fn test_sha224_256_reject_nonzero_length_null_parameters() {
    let mut context = Sha256Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(Sha256Context::input_null_context(b"abc"), sha::SHA_NULL);
    assert_eq!(context.input_null_message(3), sha::SHA_NULL);
}

// Trace: `lib/sha224-256.c:SHA256Input`
// Spec: SHA256Input append SHA-256 octets#拒绝 Result 或 FinalBits 后输入
// - **GIVEN** `context->Computed` 已经为非零
// - **WHEN** 调用 `SHA256Input(context, message_array, length)` 且 `length` 大于 0
// - **THEN** 函数将 `context->Corrupted` 设置为 `shaStateError` 并返回 `shaStateError`
#[test]
fn test_sha224_256_reject_input_after_result_or_final_bits() {
    let mut context = Sha256Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    context.set_computed(1);
    assert_eq!(context.input(b"x"), sha::SHA_STATE_ERROR);
    assert_eq!(context.state().corrupted, sha::SHA_STATE_ERROR);
}

// Trace: `lib/sha224-256.c:SHA256Input`
// Spec: SHA256Input append SHA-256 octets#传播已损坏上下文状态
// - **GIVEN** `context->Corrupted` 已经为非零且 `context->Computed` 为 0
// - **WHEN** 调用 `SHA256Input(context, message_array, length)` 且 `length` 大于 0
// - **THEN** 函数返回现有 `context->Corrupted` 值且不追加输入字节
#[test]
fn test_sha224_256_propagate_corrupted_context_state() {
    let mut context = Sha256Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    context.set_corrupted(sha::SHA_BAD_PARAM);
    assert_eq!(context.input(b"x"), sha::SHA_BAD_PARAM);
    assert_eq!(context.state().message_block_index, 0);
}

// Trace: `lib/sha224-256.c:SHA256FinalBits`
// Spec: SHA256FinalBits append SHA-256 trailing bits#零长度 final bits 直接成功
// - **GIVEN** 任意 `context` 参数
// - **WHEN** 调用 `SHA256FinalBits(context, message_bits, 0)`
// - **THEN** 函数返回 `shaSuccess`，且不检查空指针、不修改上下文状态
#[test]
fn test_sha224_256_zero_length_final_bits_succeeds_immediately() {
    assert_eq!(Sha256Context::final_bits_null(0xff, 0), sha::SHA_SUCCESS);
}

// Trace: `lib/sha224-256.c:SHA256FinalBits`
// Spec: SHA256FinalBits append SHA-256 trailing bits#拒绝空上下文 final bits
// - **GIVEN** `context` 为空且 `length` 大于 0
// - **WHEN** 调用 `SHA256FinalBits(context, message_bits, length)`
// - **THEN** 函数返回 `shaNull` 且不执行最终化
#[test]
fn test_sha224_256_reject_null_context_final_bits() {
    assert_eq!(Sha256Context::final_bits_null(0x80, 1), sha::SHA_NULL);
}

// Trace: `lib/sha224-256.c:SHA256FinalBits`
// Spec: SHA256FinalBits append SHA-256 trailing bits#拒绝非法 final bits 状态或长度
// - **GIVEN** 上下文已计算摘要，或 `length` 大于等于 8
// - **WHEN** 调用 `SHA256FinalBits(context, message_bits, length)`
// - **THEN** 函数将 `context->Corrupted` 设置为 `shaStateError` 并返回 `shaStateError`
#[test]
fn test_sha224_256_reject_invalid_final_bits_state_or_length() {
    let mut context = Sha256Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.final_bits(0xff, 8), sha::SHA_STATE_ERROR);
    assert_eq!(context.state().corrupted, sha::SHA_STATE_ERROR);
}

// Trace: `lib/sha224-256.c:SHA256FinalBits`, `lib/sha224-256.c:SHA224_256Finalize`
// Spec: SHA256FinalBits append SHA-256 trailing bits#接受 1 到 7 个高位尾部 bit
// - **GIVEN** 上下文未计算、未损坏，且 `length` 位于 1 到 7
// - **WHEN** 调用 `SHA256FinalBits(context, message_bits, length)`
// - **THEN** 函数仅保留 `message_bits` 的高位 `length` 个 bit，添加终止 bit，最终化上下文并返回 `shaSuccess`
#[test]
fn test_sha224_256_accept_one_to_seven_high_order_trailing_bits() {
    let mut context = Sha256Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.final_bits(0x80, 1), sha::SHA_SUCCESS);
    assert_eq!(context.state().computed, 1);
}

// Trace: `lib/sha224-256.c:SHA256Result`, `lib/sha224-256.c:SHA224_256ResultN`
// Spec: SHA256Result return 256-bit digest#输出 SHA-256 摘要
// - **GIVEN** 已通过 SHA-256 输入路径填充的上下文和非空 `Message_Digest` 缓冲区
// - **WHEN** 调用 `SHA256Result(context, Message_Digest)`
// - **THEN** 函数在需要时最终化上下文，按 big-endian 字节顺序写入 `SHA256HashSize` 个摘要字节，并返回 `shaSuccess`
#[test]
fn test_sha224_256_output_sha_256_digest() {
    let mut context = Sha256Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.input(b"abc"), sha::SHA_SUCCESS);
    let (code, digest) = context.result();
    assert_eq!(code, sha::SHA_SUCCESS);
    assert_eq!(digest.len(), 32);
    assert_eq!(context.state().computed, 1);
}

// Trace: `lib/sha224-256.c:SHA256Result`, `lib/sha224-256.c:SHA224_256ResultN`
// Spec: SHA256Result return 256-bit digest#拒绝空上下文或输出缓冲区
// - **GIVEN** `context` 为空或 `Message_Digest` 为空
// - **WHEN** 调用 `SHA256Result(context, Message_Digest)`
// - **THEN** 函数返回 `shaNull` 且不写入摘要输出
#[test]
fn test_sha224_256_reject_null_context_or_output_buffer() {
    let mut context = Sha256Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(Sha256Context::result_null_context(), sha::SHA_NULL);
    assert_eq!(context.result_null_output(), sha::SHA_NULL);
}

// Trace: `lib/sha224-256.c:SHA256Result`, `lib/sha224-256.c:SHA224_256ResultN`
// Spec: SHA256Result return 256-bit digest#传播已损坏上下文结果
// - **GIVEN** `context->Corrupted` 已经为非零且 `Message_Digest` 非空
// - **WHEN** 调用 `SHA256Result(context, Message_Digest)`
// - **THEN** 函数返回现有 `context->Corrupted` 值且不最终化上下文
#[test]
fn test_sha224_256_propagate_corrupted_context_result() {
    let mut context = Sha256Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    context.set_corrupted(sha::SHA_BAD_PARAM);
    let (code, output) = context.result();
    assert_eq!(code, sha::SHA_BAD_PARAM);
    assert_eq!(output, [0; 32]);
}
