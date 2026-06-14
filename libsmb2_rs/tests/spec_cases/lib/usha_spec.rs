use libsmb2_sys::legacy::sha;

// Trace: `lib/usha.c:USHAReset`, `lib/sha.h:USHAReset`
// Spec: USHAReset unified reset dispatch#non-null context dispatches reset
// - **GIVEN** 调用方提供非空 `USHAContext *` 和当前编译配置支持的 `SHAversion`
// - **WHEN** 调用方执行 `USHAReset(ctx, whichSha)`
// - **THEN** `ctx->whichSha` 被设置为 `whichSha`，返回值为对应 `SHA1Reset`、`SHA224Reset`、`SHA256Reset`、`SHA384Reset` 或 `SHA512Reset` 的返回码
#[test]
fn test_usha_non_null_context_dispatches_reset() {
    assert_eq!(
        sha::usha_reset_to(sha::sha_version_sha256()),
        (sha::SHA_SUCCESS, sha::sha_version_sha256())
    );
}

// Trace: `lib/usha.c:USHAReset`, `lib/sha.h:USHAReset`
// Spec: USHAReset unified reset dispatch#null context returns shaNull
// - **GIVEN** 调用方提供 `ctx == NULL`
// - **WHEN** 调用方执行 `USHAReset(ctx, whichSha)`
// - **THEN** 函数返回 `shaNull` 且不调用任何 SHA reset 后端
#[test]
fn test_usha_null_context_returns_sha_null() {
    assert_eq!(
        sha::usha_reset_null(sha::sha_version_sha256()),
        sha::SHA_NULL
    );
}

// Trace: `lib/usha.c:USHAInput`, `lib/sha.h:USHAInput`
// Spec: USHAInput unified input dispatch#non-null context dispatches input
// - **GIVEN** 调用方提供非空 `USHAContext *`，其 `whichSha` 对应当前编译配置支持的 SHA 算法
// - **WHEN** 调用方执行 `USHAInput(ctx, bytes, bytecount)`
// - **THEN** 函数将 `bytes` 和 `bytecount` 原样传递给对应 SHA input 后端，并返回该后端返回码
#[test]
fn test_usha_non_null_context_dispatches_input() {
    assert_eq!(sha::usha_input_zero_length_after_reset(), sha::SHA_SUCCESS);
}

// Trace: `lib/usha.c:USHAInput`, `lib/sha.h:USHAInput`
// Spec: USHAInput unified input dispatch#unsupported context algorithm returns shaBadParam
// - **GIVEN** 调用方提供非空 `USHAContext *`，其 `whichSha` 不匹配当前编译配置中的任何 input case
// - **WHEN** 调用方执行 `USHAInput(ctx, bytes, bytecount)`
// - **THEN** 函数返回 `shaBadParam`
#[test]
fn test_usha_unsupported_context_algorithm_returns_sha_bad_param() {
    assert_eq!(sha::usha_input_unsupported(), sha::SHA_BAD_PARAM);
}

// Trace: `lib/usha.c:USHAFinalBits`, `lib/sha.h:USHAFinalBits`
// Spec: USHAFinalBits final-bit dispatch#supported algorithm dispatches final bits
// - **GIVEN** 调用方提供非空 `USHAContext *`，其 `whichSha` 对应当前编译配置支持的 SHA 算法
// - **WHEN** 调用方执行 `USHAFinalBits(ctx, bits, bitcount)`
// - **THEN** 函数调用对应 SHA final-bits 后端并返回该后端返回码
#[test]
fn test_usha_supported_algorithm_dispatches_final_bits() {
    assert_eq!(sha::usha_final_bits_after_reset(0x80, 1), sha::SHA_SUCCESS);
}

// Trace: `lib/usha.c:USHAFinalBits`, `lib/sha.h:USHAFinalBits`
// Spec: USHAFinalBits final-bit dispatch#null context returns shaNull
// - **GIVEN** 调用方提供 `ctx == NULL`
// - **WHEN** 调用方执行 `USHAFinalBits(ctx, bits, bitcount)`
// - **THEN** 函数返回 `shaNull` 且不调用任何 SHA final-bits 后端
#[test]
fn test_usha_final_bits_null_context_returns_sha_null() {
    assert_eq!(sha::usha_final_bits_null(0x80, 1), sha::SHA_NULL);
}

// Trace: `lib/usha.c:USHAResult`, `lib/sha.h:USHAResult`
// Spec: USHAResult digest dispatch#supported algorithm writes digest through backend
// - **GIVEN** 调用方提供非空 `USHAContext *`，其 `whichSha` 对应当前编译配置支持的 SHA 算法，并提供 `Message_Digest` 输出缓冲区
// - **WHEN** 调用方执行 `USHAResult(ctx, Message_Digest)`
// - **THEN** 函数调用对应 SHA result 后端并返回该后端返回码
#[test]
fn test_usha_supported_algorithm_writes_digest_through_backend() {
    let (digest, code) = sha::usha_result_sha256_empty();
    assert_eq!(code, sha::SHA_SUCCESS);
    assert_eq!(digest, sha::sha256(b""));
}

// Trace: `lib/usha.c:USHAResult`, `lib/sha.h:USHAResult`
// Spec: USHAResult digest dispatch#unsupported result algorithm returns shaBadParam
// - **GIVEN** 调用方提供非空 `USHAContext *`，其 `whichSha` 不匹配当前编译配置中的任何 result case
// - **WHEN** 调用方执行 `USHAResult(ctx, Message_Digest)`
// - **THEN** 函数返回 `shaBadParam`
#[test]
fn test_usha_unsupported_result_algorithm_returns_sha_bad_param() {
    assert_eq!(sha::usha_result_unsupported(), sha::SHA_BAD_PARAM);
}

// Trace: `lib/usha.c:USHABlockSize`, `lib/sha.h:USHABlockSize`
// Spec: USHABlockSize block-size lookup#supported algorithm returns configured block size
// - **GIVEN** 调用方提供当前编译配置支持的 `SHAversion`
// - **WHEN** 调用方执行 `USHABlockSize(whichSha)`
// - **THEN** 函数返回对应的 `SHA1_Message_Block_Size`、`SHA224_Message_Block_Size`、`SHA256_Message_Block_Size`、`SHA384_Message_Block_Size` 或 `SHA512_Message_Block_Size`
#[test]
fn test_usha_supported_algorithm_returns_configured_block_size() {
    assert_eq!(
        sha::usha_block_size(sha::sha_version_sha256()),
        sha::sha256_message_block_size()
    );
    assert_eq!(
        sha::usha_block_size(sha::sha_version_sha384()),
        sha::sha384_message_block_size()
    );
    assert_eq!(
        sha::usha_block_size(sha::sha_version_sha512()),
        sha::sha512_message_block_size()
    );
}

// Trace: `lib/usha.c:USHABlockSize`, `lib/sha.h:USHABlockSize`
// Spec: USHABlockSize block-size lookup#unsupported algorithm defaults to SHA512 block size
// - **GIVEN** 调用方提供不匹配当前编译配置中任何 case 的 `whichSha`
// - **WHEN** 调用方执行 `USHABlockSize(whichSha)`
// - **THEN** 函数返回 `SHA512_Message_Block_Size`
#[test]
fn test_usha_unsupported_algorithm_defaults_to_sha512_block_size() {
    assert_eq!(
        sha::usha_block_size(sha::sha_version_unsupported()),
        sha::sha512_message_block_size()
    );
}

// Trace: `lib/usha.c:USHAHashSize`, `lib/sha.h:USHAHashSize`
// Spec: USHAHashSize hash-size lookup#supported algorithm returns digest byte size
// - **GIVEN** 调用方提供当前编译配置支持的 `SHAversion`
// - **WHEN** 调用方执行 `USHAHashSize(whichSha)`
// - **THEN** 函数返回对应的 `SHA1HashSize`、`SHA224HashSize`、`SHA256HashSize`、`SHA384HashSize` 或 `SHA512HashSize`
#[test]
fn test_usha_supported_algorithm_returns_digest_byte_size() {
    assert_eq!(
        sha::usha_hash_size(sha::sha_version_sha256()),
        sha::sha256_hash_size()
    );
    assert_eq!(
        sha::usha_hash_size(sha::sha_version_sha384()),
        sha::sha384_hash_size()
    );
    assert_eq!(
        sha::usha_hash_size(sha::sha_version_sha512()),
        sha::sha512_hash_size()
    );
}

// Trace: `lib/usha.c:USHAHashSize`, `lib/sha.h:USHAHashSize`
// Spec: USHAHashSize hash-size lookup#unsupported algorithm defaults to SHA512 byte size
// - **GIVEN** 调用方提供不匹配当前编译配置中任何 case 的 `whichSha`
// - **WHEN** 调用方执行 `USHAHashSize(whichSha)`
// - **THEN** 函数返回 `SHA512HashSize`
#[test]
fn test_usha_unsupported_algorithm_defaults_to_sha512_byte_size() {
    assert_eq!(
        sha::usha_hash_size(sha::sha_version_unsupported()),
        sha::sha512_hash_size()
    );
}

// Trace: `lib/usha.c:USHAHashSizeBits`, `lib/sha.h:USHAHashSizeBits`
// Spec: USHAHashSizeBits hash-size-bits lookup#supported algorithm returns digest bit size
// - **GIVEN** 调用方提供当前编译配置支持的 `SHAversion`
// - **WHEN** 调用方执行 `USHAHashSizeBits(whichSha)`
// - **THEN** 函数返回对应的 `SHA1HashSizeBits`、`SHA224HashSizeBits`、`SHA256HashSizeBits`、`SHA384HashSizeBits` 或 `SHA512HashSizeBits`
#[test]
fn test_usha_supported_algorithm_returns_digest_bit_size() {
    assert_eq!(
        sha::usha_hash_size_bits(sha::sha_version_sha256()),
        sha::sha256_hash_size_bits()
    );
    assert_eq!(
        sha::usha_hash_size_bits(sha::sha_version_sha384()),
        sha::sha384_hash_size_bits()
    );
    assert_eq!(
        sha::usha_hash_size_bits(sha::sha_version_sha512()),
        sha::sha512_hash_size_bits()
    );
}

// Trace: `lib/usha.c:USHAHashSizeBits`, `lib/sha.h:USHAHashSizeBits`
// Spec: USHAHashSizeBits hash-size-bits lookup#unsupported algorithm defaults to SHA512 bit size
// - **GIVEN** 调用方提供不匹配当前编译配置中任何 case 的 `whichSha`
// - **WHEN** 调用方执行 `USHAHashSizeBits(whichSha)`
// - **THEN** 函数返回 `SHA512HashSizeBits`
#[test]
fn test_usha_unsupported_algorithm_defaults_to_sha512_bit_size() {
    assert_eq!(
        sha::usha_hash_size_bits(sha::sha_version_unsupported()),
        sha::sha512_hash_size_bits()
    );
}
