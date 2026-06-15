use libsmb2_rs::lib::sha::{self, Sha384Context, Sha512Context};

// Trace: `lib/sha384-512.c:SHA384Reset`, `lib/sha384-512.c:SHA384_512Reset`, `lib/sha.h:SHA384Context`
// Spec: SHA384Reset initialize SHA-384 context#reset valid SHA-384 context
// - **GIVEN** 调用方提供一个可写的 `SHA384Context`。
// - **WHEN** 调用方调用 `SHA384Reset(context)`。
// - **THEN** 函数返回 `shaSuccess`，上下文准备好接收新的 SHA-384 输入。
#[test]
fn test_sha384_512_reset_valid_sha_384_context() {
    let mut context = Sha384Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.state().computed, 0);
}

// Trace: `lib/sha384-512.c:SHA384Reset`, `lib/sha384-512.c:SHA384_512Reset`
// Spec: SHA384Reset initialize SHA-384 context#reject null SHA-384 context
// - **GIVEN** 调用方没有提供有效上下文。
// - **WHEN** 调用方调用 `SHA384Reset(NULL)`。
// - **THEN** 函数返回 `shaNull`，且不解引用空指针。
#[test]
fn test_sha384_512_reject_null_sha_384_context() {
    assert_eq!(Sha384Context::reset_null(), sha::SHA_NULL);
}

// Trace: `lib/sha384-512.c:SHA384Input`, `lib/sha384-512.c:SHA512Input`
// Spec: SHA384Input accept SHA-384 octet input#input zero SHA-384 bytes
// - **GIVEN** 调用方传入任意上下文指针和 `length == 0`。
// - **WHEN** 调用方调用 `SHA384Input(context, bytes, 0)`。
// - **THEN** 函数返回 `shaSuccess`，且不要求 `context` 或 `bytes` 非空。
#[test]
fn test_sha384_512_input_zero_sha_384_bytes() {
    assert_eq!(Sha384Context::input_zero_nulls(), sha::SHA_SUCCESS);
}

// Trace: `lib/sha384-512.c:SHA384Input`, `lib/sha384-512.c:SHA512Input`, `lib/sha384-512.c:SHA384_512ProcessMessageBlock`
// Spec: SHA384Input accept SHA-384 octet input#input nonzero SHA-384 bytes
// - **GIVEN** 调用方已通过 `SHA384Reset` 初始化上下文并提供非空消息缓冲区。
// - **WHEN** 调用方调用 `SHA384Input(context, bytes, bytecount)` 且 `bytecount > 0`。
// - **THEN** 函数按字节追加消息、按 8 bit 累计长度，并在 1024-bit 消息块填满时处理该块。
#[test]
fn test_sha384_512_input_nonzero_sha_384_bytes() {
    let mut context = Sha384Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.input(&[b'a'; 129]), sha::SHA_SUCCESS);
    let state = context.state();
    assert_eq!(state.length_low, 1032);
    assert_eq!(state.message_block_index, 1);
}

// Trace: `lib/sha384-512.c:SHA384Input`, `lib/sha384-512.c:SHA512Input`
// Spec: SHA384Input accept SHA-384 octet input#reject invalid SHA-384 input state
// - **GIVEN** 调用方提供空上下文、空消息缓冲区、已计算完成的上下文或已损坏的上下文之一。
// - **WHEN** 调用方调用 `SHA384Input(context, bytes, bytecount)` 且 `bytecount > 0`。
// - **THEN** 函数返回 `shaNull`、`shaStateError` 或上下文已有的 `Corrupted` 错误码；若上下文已完成，函数将 `Corrupted` 设置为 `shaStateError`。
#[test]
fn test_sha384_512_reject_invalid_sha_384_input_state() {
    let mut context = Sha384Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    context.set_computed(1);
    assert_eq!(Sha384Context::input_null_context(b"abc"), sha::SHA_NULL);
    assert_eq!(context.input(b"abc"), sha::SHA_STATE_ERROR);
}

// Trace: `lib/sha384-512.c:SHA384FinalBits`, `lib/sha384-512.c:SHA512FinalBits`
// Spec: SHA384FinalBits finalize SHA-384 partial-byte input#finalize SHA-384 with no final bits
// - **GIVEN** 调用方传入任意上下文指针并指定 `bitcount == 0`。
// - **WHEN** 调用方调用 `SHA384FinalBits(context, bits, 0)`。
// - **THEN** 函数返回 `shaSuccess`，且不要求 `context` 非空。
#[test]
fn test_sha384_512_finalize_sha_384_with_no_final_bits() {
    assert_eq!(Sha384Context::final_bits_null(0xff, 0), sha::SHA_SUCCESS);
}

// Trace: `lib/sha384-512.c:SHA384FinalBits`, `lib/sha384-512.c:SHA512FinalBits`, `lib/sha384-512.c:SHA384_512Finalize`
// Spec: SHA384FinalBits finalize SHA-384 partial-byte input#finalize SHA-384 with one to seven bits
// - **GIVEN** 调用方提供未完成且未损坏的 SHA-384 上下文，并将最终 bit 放在 `bits` 的高位部分。
// - **WHEN** 调用方调用 `SHA384FinalBits(context, bits, bitcount)` 且 `1 <= bitcount <= 7`。
// - **THEN** 函数累计最终 bit 长度，使用被掩码保留的高位 bit 加终止标记构造填充字节，完成摘要终结，并返回 `shaSuccess`。
#[test]
fn test_sha384_512_finalize_sha_384_with_one_to_seven_bits() {
    let mut context = Sha384Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.final_bits(0x80, 1), sha::SHA_SUCCESS);
    assert_eq!(context.state().computed, 1);
}

// Trace: `lib/sha384-512.c:SHA384FinalBits`, `lib/sha384-512.c:SHA512FinalBits`
// Spec: SHA384FinalBits finalize SHA-384 partial-byte input#reject invalid SHA-384 final bits
// - **GIVEN** 调用方提供空上下文、已完成上下文、已损坏上下文或 `bitcount >= 8` 之一。
// - **WHEN** 调用方调用 `SHA384FinalBits(context, bits, bitcount)`。
// - **THEN** 函数返回 `shaNull`、`shaStateError` 或上下文已有的 `Corrupted` 错误码；已完成上下文或过大 bitcount 会将 `Corrupted` 设置为 `shaStateError`。
#[test]
fn test_sha384_512_reject_invalid_sha_384_final_bits() {
    let mut context = Sha384Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(Sha384Context::final_bits_null(0x80, 1), sha::SHA_NULL);
    assert_eq!(context.final_bits(0xff, 8), sha::SHA_STATE_ERROR);
}

// Trace: `lib/sha384-512.c:SHA384Result`, `lib/sha384-512.c:SHA384_512ResultN`, `lib/sha384-512.c:SHA384_512Finalize`
// Spec: SHA384Result produce 384-bit digest#produce SHA-384 digest
// - **GIVEN** 调用方已初始化 SHA-384 上下文并输入零个或多个字节和可选最终 bit。
// - **WHEN** 调用方调用 `SHA384Result(context, Message_Digest)` 且输出缓冲区可写至少 `SHA384HashSize` 字节。
// - **THEN** 函数返回 `shaSuccess`，将摘要按高位字节优先顺序写入 `Message_Digest[0..47]`，并在需要时终结上下文。
#[test]
fn test_sha384_512_produce_sha_384_digest() {
    let mut context = Sha384Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.input(b"abc"), sha::SHA_SUCCESS);
    let (code, digest) = context.result();
    assert_eq!(code, sha::SHA_SUCCESS);
    assert_eq!(digest.len(), 48);
    assert_eq!(context.state().computed, 1);
}

// Trace: `lib/sha384-512.c:SHA384Result`, `lib/sha384-512.c:SHA384_512ResultN`
// Spec: SHA384Result produce 384-bit digest#reject invalid SHA-384 result request
// - **GIVEN** 调用方提供空上下文、空输出缓冲区或已损坏上下文之一。
// - **WHEN** 调用方调用 `SHA384Result(context, Message_Digest)`。
// - **THEN** 函数返回 `shaNull` 或上下文已有的 `Corrupted` 错误码，且不生成新的成功摘要。
#[test]
fn test_sha384_512_reject_invalid_sha_384_result_request() {
    let mut context = Sha384Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    context.set_corrupted(sha::SHA_BAD_PARAM);
    assert_eq!(Sha384Context::result_null_context(), sha::SHA_NULL);
    assert_eq!(context.result_null_output(), sha::SHA_NULL);
    let (code, output) = context.result();
    assert_eq!(code, sha::SHA_BAD_PARAM);
    assert_eq!(output, [0; 48]);
}

// Trace: `lib/sha384-512.c:SHA512Reset`, `lib/sha384-512.c:SHA384_512Reset`, `lib/sha.h:SHA512Context`
// Spec: SHA512Reset initialize SHA-512 context#reset valid SHA-512 context
// - **GIVEN** 调用方提供一个可写的 `SHA512Context`。
// - **WHEN** 调用方调用 `SHA512Reset(context)`。
// - **THEN** 函数返回 `shaSuccess`，上下文准备好接收新的 SHA-512 输入。
#[test]
fn test_sha384_512_reset_valid_sha_512_context() {
    let mut context = Sha512Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.state().computed, 0);
}

// Trace: `lib/sha384-512.c:SHA512Reset`, `lib/sha384-512.c:SHA384_512Reset`
// Spec: SHA512Reset initialize SHA-512 context#reject null SHA-512 context
// - **GIVEN** 调用方没有提供有效上下文。
// - **WHEN** 调用方调用 `SHA512Reset(NULL)`。
// - **THEN** 函数返回 `shaNull`，且不解引用空指针。
#[test]
fn test_sha384_512_reject_null_sha_512_context() {
    assert_eq!(Sha512Context::reset_null(), sha::SHA_NULL);
}

// Trace: `lib/sha384-512.c:SHA512Input`
// Spec: SHA512Input accept SHA-512 octet input#input zero SHA-512 bytes
// - **GIVEN** 调用方传入任意上下文指针和 `length == 0`。
// - **WHEN** 调用方调用 `SHA512Input(context, bytes, 0)`。
// - **THEN** 函数返回 `shaSuccess`，且不要求 `context` 或 `bytes` 非空。
#[test]
fn test_sha384_512_input_zero_sha_512_bytes() {
    assert_eq!(Sha512Context::input_zero_nulls(), sha::SHA_SUCCESS);
}

// Trace: `lib/sha384-512.c:SHA512Input`, `lib/sha384-512.c:SHA384_512ProcessMessageBlock`
// Spec: SHA512Input accept SHA-512 octet input#input nonzero SHA-512 bytes
// - **GIVEN** 调用方已通过 `SHA512Reset` 初始化上下文并提供非空消息缓冲区。
// - **WHEN** 调用方调用 `SHA512Input(context, bytes, bytecount)` 且 `bytecount > 0`。
// - **THEN** 函数逐字节写入 `Message_Block`，累计 bit 长度，并在块索引达到 `SHA512_Message_Block_Size` 时调用压缩处理。
#[test]
fn test_sha384_512_input_nonzero_sha_512_bytes() {
    let mut context = Sha512Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.input(&[b'a'; 129]), sha::SHA_SUCCESS);
    let state = context.state();
    assert_eq!(state.length_low, 1032);
    assert_eq!(state.message_block_index, 1);
}

// Trace: `lib/sha384-512.c:SHA512Input`
// Spec: SHA512Input accept SHA-512 octet input#reject invalid SHA-512 input state
// - **GIVEN** 调用方提供空上下文、空消息缓冲区、已计算完成的上下文或已损坏的上下文之一。
// - **WHEN** 调用方调用 `SHA512Input(context, bytes, bytecount)` 且 `bytecount > 0`。
// - **THEN** 函数返回 `shaNull`、`shaStateError` 或上下文已有的 `Corrupted` 错误码；若上下文已完成，函数将 `Corrupted` 设置为 `shaStateError`。
#[test]
fn test_sha384_512_reject_invalid_sha_512_input_state() {
    let mut context = Sha512Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    context.set_computed(1);
    assert_eq!(Sha512Context::input_null_context(b"abc"), sha::SHA_NULL);
    assert_eq!(context.input(b"abc"), sha::SHA_STATE_ERROR);
}

// Trace: `lib/sha384-512.c:SHA512FinalBits`
// Spec: SHA512FinalBits finalize SHA-512 partial-byte input#finalize SHA-512 with no final bits
// - **GIVEN** 调用方传入任意上下文指针并指定 `length == 0`。
// - **WHEN** 调用方调用 `SHA512FinalBits(context, message_bits, 0)`。
// - **THEN** 函数返回 `shaSuccess`，且不要求 `context` 非空。
#[test]
fn test_sha384_512_finalize_sha_512_with_no_final_bits() {
    assert_eq!(Sha512Context::final_bits_null(0xff, 0), sha::SHA_SUCCESS);
}

// Trace: `lib/sha384-512.c:SHA512FinalBits`, `lib/sha384-512.c:SHA384_512Finalize`
// Spec: SHA512FinalBits finalize SHA-512 partial-byte input#finalize SHA-512 with one to seven bits
// - **GIVEN** 调用方提供未完成且未损坏的 SHA-512 上下文，并将最终 bit 放在 `message_bits` 的高位部分。
// - **WHEN** 调用方调用 `SHA512FinalBits(context, message_bits, length)` 且 `1 <= length <= 7`。
// - **THEN** 函数累计最终 bit 长度，使用被掩码保留的高位 bit 加终止标记构造填充字节，完成摘要终结，并返回 `shaSuccess`。
#[test]
fn test_sha384_512_finalize_sha_512_with_one_to_seven_bits() {
    let mut context = Sha512Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.final_bits(0x80, 1), sha::SHA_SUCCESS);
    assert_eq!(context.state().computed, 1);
}

// Trace: `lib/sha384-512.c:SHA512FinalBits`
// Spec: SHA512FinalBits finalize SHA-512 partial-byte input#reject invalid SHA-512 final bits
// - **GIVEN** 调用方提供空上下文、已完成上下文、已损坏上下文或 `length >= 8` 之一。
// - **WHEN** 调用方调用 `SHA512FinalBits(context, message_bits, length)`。
// - **THEN** 函数返回 `shaNull`、`shaStateError` 或上下文已有的 `Corrupted` 错误码；已完成上下文或过大 length 会将 `Corrupted` 设置为 `shaStateError`。
#[test]
fn test_sha384_512_reject_invalid_sha_512_final_bits() {
    let mut context = Sha512Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(Sha512Context::final_bits_null(0x80, 1), sha::SHA_NULL);
    assert_eq!(context.final_bits(0xff, 8), sha::SHA_STATE_ERROR);
}

// Trace: `lib/sha384-512.c:SHA512Result`, `lib/sha384-512.c:SHA384_512ResultN`, `lib/sha384-512.c:SHA384_512Finalize`
// Spec: SHA512Result produce 512-bit digest#produce SHA-512 digest
// - **GIVEN** 调用方已初始化 SHA-512 上下文并输入零个或多个字节和可选最终 bit。
// - **WHEN** 调用方调用 `SHA512Result(context, Message_Digest)` 且输出缓冲区可写至少 `SHA512HashSize` 字节。
// - **THEN** 函数返回 `shaSuccess`，将摘要按高位字节优先顺序写入 `Message_Digest[0..63]`，并在需要时终结上下文。
#[test]
fn test_sha384_512_produce_sha_512_digest() {
    let mut context = Sha512Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    assert_eq!(context.input(b"abc"), sha::SHA_SUCCESS);
    let (code, digest) = context.result();
    assert_eq!(code, sha::SHA_SUCCESS);
    assert_eq!(digest.len(), 64);
    assert_eq!(context.state().computed, 1);
}

// Trace: `lib/sha384-512.c:SHA512Result`, `lib/sha384-512.c:SHA384_512ResultN`
// Spec: SHA512Result produce 512-bit digest#reject invalid SHA-512 result request
// - **GIVEN** 调用方提供空上下文、空输出缓冲区或已损坏上下文之一。
// - **WHEN** 调用方调用 `SHA512Result(context, Message_Digest)`。
// - **THEN** 函数返回 `shaNull` 或上下文已有的 `Corrupted` 错误码，且不生成新的成功摘要。
#[test]
fn test_sha384_512_reject_invalid_sha_512_result_request() {
    let mut context = Sha512Context::zeroed();
    assert_eq!(context.reset(), sha::SHA_SUCCESS);
    context.set_corrupted(sha::SHA_BAD_PARAM);
    assert_eq!(Sha512Context::result_null_context(), sha::SHA_NULL);
    assert_eq!(context.result_null_output(), sha::SHA_NULL);
    let (code, output) = context.result();
    assert_eq!(code, sha::SHA_BAD_PARAM);
    assert_eq!(output, [0; 64]);
}
