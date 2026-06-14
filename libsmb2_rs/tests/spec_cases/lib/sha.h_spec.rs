use libsmb2_sys::legacy::sha;

fn success() -> i32 {
    sha::sha_error_codes().success
}

// Trace: `lib/sha.h:USE_SHA1`, `lib/sha.h:SHA1Context`, `lib/sha.h:SHA1Reset`
// Spec: USE_SHA1 conditional SHA-1 API surface#SHA-1 declarations follow compile-time switch
// - **GIVEN** 编译单元包含 `lib/sha.h`
// - **WHEN** `USE_SHA1` 未定义或定义为 0
// - **THEN** 头文件不声明 `SHA1Context`、`SHA1`、`SHA1Reset`、`SHA1Input`、`SHA1FinalBits` 或 `SHA1Result`
#[test]
fn test_sha_h_sha_1_declarations_follow_compile_time_switch() {
    let surface = sha::sha_header_surface();

    assert!(!surface.use_sha1_default);
    assert!(!surface.sha1_declared);
}

// Trace: `lib/sha.h:USE_SHA224`, `lib/sha.h:SHA224Context`, `lib/sha.h:SHA224Reset`
// Spec: USE_SHA224 conditional SHA-224 API surface#SHA-224 declarations follow compile-time switch
// - **GIVEN** 编译单元包含 `lib/sha.h`
// - **WHEN** `USE_SHA224` 未定义或定义为 0
// - **THEN** 头文件不声明 `SHA224Context`、`SHA224`、`SHA224Reset`、`SHA224Input`、`SHA224FinalBits` 或 `SHA224Result`
#[test]
fn test_sha_h_sha_224_declarations_follow_compile_time_switch() {
    let surface = sha::sha_header_surface();

    assert!(!surface.use_sha224_default);
    assert!(!surface.sha224_declared);
}

// Trace: `lib/sha.h:USE_SHA384_SHA512`, `lib/sha.h:SHA384Context`, `lib/sha.h:SHA512Reset`
// Spec: USE_SHA384_SHA512 conditional SHA-384 and SHA-512 API surface#SHA-384 and SHA-512 declarations are enabled by default
// - **GIVEN** 编译单元包含 `lib/sha.h` 且未预定义 `USE_SHA384_SHA512`
// - **WHEN** 预处理头文件
// - **THEN** `SHA384Context`、`SHA512Context`、`SHA384Reset` 和 `SHA512Reset` 对调用方可见
#[test]
fn test_sha_h_sha_384_and_sha_512_declarations_are_enabled_by_default() {
    let surface = sha::sha_header_surface();

    assert!(surface.use_sha384_sha512_default);
    assert!(surface.sha384_declared);
    assert!(surface.sha512_declared);
}

// Trace: `lib/sha.h:shaSuccess`
// Spec: shaSuccess success return code#success code is zero
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方比较 SHA 系列接口返回值和 `shaSuccess`
// - **THEN** `shaSuccess` 的值为 0
#[test]
fn test_sha_h_success_code_is_zero() {
    assert_eq!(sha::sha_error_codes().success, 0);
}

// Trace: `lib/sha.h:shaNull`, `lib/sha1.c:SHA1Reset`, `lib/hmac.c:hmacReset`
// Spec: shaNull null pointer return code#null error code is part of public enum
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方引用 `shaNull`
// - **THEN** 该枚举常量可用于区分空指针参数错误
#[test]
fn test_sha_h_null_error_code_is_part_of_public_enum() {
    assert_ne!(sha::sha_error_codes().null, sha::sha_error_codes().success);
}

// Trace: `lib/sha.h:shaInputTooLong`, `lib/sha224-256.c:SHA224_256AddLength`, `lib/sha384-512.c:SHA384_512AddLength`
// Spec: shaInputTooLong input length error code#input-too-long error code is part of public enum
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方引用 `shaInputTooLong`
// - **THEN** 该枚举常量可用于表达输入数据过长错误类别
#[test]
fn test_sha_h_input_too_long_error_code_is_part_of_public_enum() {
    let codes = sha::sha_error_codes();

    assert_ne!(codes.input_too_long, codes.success);
    assert_ne!(codes.input_too_long, codes.null);
}

// Trace: `lib/sha.h:shaStateError`, `lib/sha224-256.c:SHA256Input`
// Spec: shaStateError state error return code#state error code is part of public enum
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方引用 `shaStateError`
// - **THEN** 该枚举常量可用于识别 SHA context 状态错误
#[test]
fn test_sha_h_state_error_code_is_part_of_public_enum() {
    let codes = sha::sha_error_codes();

    assert_ne!(codes.state_error, codes.success);
    assert_ne!(codes.state_error, codes.null);
}

// Trace: `lib/sha.h:shaBadParam`, `lib/usha.c:USHAReset`
// Spec: shaBadParam bad parameter return code#bad parameter code is part of public enum
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方引用 `shaBadParam`
// - **THEN** 该枚举常量可用于识别非法算法选择
#[test]
fn test_sha_h_bad_parameter_code_is_part_of_public_enum() {
    let codes = sha::sha_error_codes();

    assert_ne!(codes.bad_param, codes.success);
    assert_ne!(codes.bad_param, codes.null);
}

// Trace: `lib/sha.h:SHA1Context`, `lib/sha1.c:SHA1Reset`
// Spec: SHA1Context public SHA-1 context layout#SHA-1 context is caller-owned state
// - **GIVEN** `USE_SHA1` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方定义 `SHA1Context context`
// - **THEN** 该类型可由 `SHA1Reset` 初始化并由 SHA-1 输入和结果函数持续更新
#[test]
fn test_sha_h_sha_1_context_is_caller_owned_state() {
    assert!(sha::sha1_context_layout().size > 0);
    assert_eq!(sha::sha1(b"abc").len(), sha::SHA1_HASH_SIZE);
}

// Trace: `lib/sha.h:SHA256Context`, `lib/sha224-256.c:SHA256Reset`
// Spec: SHA256Context public SHA-256 context layout#SHA-256 context is caller-owned state
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方定义 `SHA256Context context`
// - **THEN** 该类型可由 `SHA256Reset` 初始化并由 SHA-256 输入和结果函数持续更新
#[test]
fn test_sha_h_sha_256_context_is_caller_owned_state() {
    assert!(sha::sha256_context_layout().size > 0);
    assert_eq!(sha::sha256(b"abc").len(), sha::SHA256_HASH_SIZE);
}

// Trace: `lib/sha.h:SHA512Context`, `lib/sha384-512.c:SHA512Reset`
// Spec: SHA512Context public SHA-512 context layout#SHA-512 context layout follows compile branch
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** `USE_32BIT_ONLY` 启用或未启用
// - **THEN** `SHA512Context` 均提供消息块索引、消息块、`Computed` 和 `Corrupted` 字段，并可被 SHA-512/SHA-384 实现使用
#[test]
fn test_sha_h_sha_512_context_layout_follows_compile_branch() {
    assert!(sha::sha512_context_layout().size > 0);
    assert_eq!(sha::sha512(b"abc").len(), sha::SHA512_HASH_SIZE);
}

// Trace: `lib/sha.h:SHA224Context`, `lib/sha224-256.c:SHA224Reset`
// Spec: SHA224Context SHA-256-backed context alias#SHA-224 context aliases SHA-256 context
// - **GIVEN** `USE_SHA224` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方定义 `SHA224Context context`
// - **THEN** 该对象具有 `SHA256Context` 布局并可传递给 SHA-224 wrapper 函数
#[test]
fn test_sha_h_sha_224_context_aliases_sha_256_context() {
    assert!(sha::sha224_context_matches_sha256());
    assert_eq!(sha::sha224(b"abc").len(), sha::SHA224_HASH_SIZE);
}

// Trace: `lib/sha.h:SHA384Context`, `lib/sha384-512.c:SHA384Reset`
// Spec: SHA384Context SHA-512-backed context alias#SHA-384 context aliases SHA-512 context
// - **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方定义 `SHA384Context context`
// - **THEN** 该对象具有 `SHA512Context` 布局并可传递给 SHA-384 wrapper 函数
#[test]
fn test_sha_h_sha_384_context_aliases_sha_512_context() {
    assert!(sha::sha384_context_matches_sha512());
    assert_eq!(sha::sha384(b"abc").len(), sha::SHA384_HASH_SIZE);
}

// Trace: `lib/sha.h:SHAversion`, `lib/usha.c:USHAReset`
// Spec: SHAversion algorithm selector#algorithm enum follows enabled algorithms
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 预处理 `SHAversion` 定义
// - **THEN** `SHA256` 始终可见，其他算法枚举成员按对应 `USE_*` 宏可见
#[test]
fn test_sha_h_algorithm_enum_follows_enabled_algorithms() {
    assert_eq!(sha::usha_reset_to_sha256(), success());
}

// Trace: `lib/sha.h:USHAContext`, `lib/usha.c:USHAReset`
// Spec: USHAContext unified SHA context union#unified context stores selected SHA state
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方定义 `USHAContext ctx` 并通过 `USHAReset` 设置算法
// - **THEN** `ctx.whichSha` 记录算法，`ctx.ctx` union 保存对应 SHA 实现上下文
#[test]
fn test_sha_h_unified_context_stores_selected_sha_state() {
    assert_eq!(sha::usha_reset_to_sha256(), success());
}

// Trace: `lib/sha.h:HMACContext`, `lib/hmac.c:hmacReset`
// Spec: HMACContext streaming HMAC context#HMAC context carries stream state
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方定义 `HMACContext ctx` 并调用 `hmacReset`
// - **THEN** 该 context 可被 `hmacInput`、`hmacFinalBits` 和 `hmacResult` 持续使用
#[test]
fn test_sha_h_hmac_context_carries_stream_state() {
    assert!(sha::hmac_context_layout().size > 0);
    assert_eq!(
        sha::hmac_streaming_sha256(b"Hi There", &[0x0b; 20]).1,
        success()
    );
}

// Trace: `lib/sha.h:SHA1Reset`, `lib/sha1.c:SHA1Reset`
// Spec: SHA1Reset declaration contract#SHA-1 reset declaration is visible when enabled
// - **GIVEN** `USE_SHA1` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA1Reset` 的调用
// - **THEN** 声明接受 `SHA1Context *` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_1_reset_declaration_is_visible_when_enabled() {
    assert_eq!(sha::sha1(b"").len(), sha::SHA1_HASH_SIZE);
}

// Trace: `lib/sha.h:SHA1Input`, `lib/sha1.c:SHA1Input`
// Spec: SHA1Input declaration contract#SHA-1 input declaration is visible when enabled
// - **GIVEN** `USE_SHA1` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA1Input` 的调用
// - **THEN** 声明接受 `SHA1Context *`、`const uint8_t *` 和 `size_t` 长度并返回 SHA 错误码
#[test]
fn test_sha_h_sha_1_input_declaration_is_visible_when_enabled() {
    assert_ne!(sha::sha1(b"abc"), sha::sha1(b""));
}

// Trace: `lib/sha.h:SHA1FinalBits`, `lib/sha1.c:SHA1FinalBits`
// Spec: SHA1FinalBits declaration contract#SHA-1 final bits declaration is visible when enabled
// - **GIVEN** `USE_SHA1` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA1FinalBits` 的调用
// - **THEN** 声明接受 `SHA1Context *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_1_final_bits_declaration_is_visible_when_enabled() {
    assert_eq!(sha::sha1_final_bits_zero_length_after_reset(), success());
}

// Trace: `lib/sha.h:SHA1Result`, `lib/sha1.c:SHA1Result`
// Spec: SHA1Result declaration contract#SHA-1 result declaration is visible when enabled
// - **GIVEN** `USE_SHA1` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA1Result` 的调用
// - **THEN** 声明接受 `SHA1Context *` 和 `uint8_t Message_Digest[SHA1HashSize]` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_1_result_declaration_is_visible_when_enabled() {
    assert_eq!(sha::sha1(b"abc").len(), sha::SHA1_HASH_SIZE);
}

// Trace: `lib/sha.h:SHA224Reset`, `lib/sha224-256.c:SHA224Reset`
// Spec: SHA224Reset declaration contract#SHA-224 reset declaration is visible when enabled
// - **GIVEN** `USE_SHA224` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA224Reset` 的调用
// - **THEN** 声明接受 `SHA224Context *` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_224_reset_declaration_is_visible_when_enabled() {
    assert_eq!(sha::sha224(b"").len(), sha::SHA224_HASH_SIZE);
}

// Trace: `lib/sha.h:SHA224Input`, `lib/sha224-256.c:SHA224Input`
// Spec: SHA224Input declaration contract#SHA-224 input declaration is visible when enabled
// - **GIVEN** `USE_SHA224` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA224Input` 的调用
// - **THEN** 声明接受 `SHA224Context *`、`const uint8_t *` 和 `size_t` 长度并返回 SHA 错误码
#[test]
fn test_sha_h_sha_224_input_declaration_is_visible_when_enabled() {
    assert_ne!(sha::sha224(b"abc"), sha::sha224(b""));
}

// Trace: `lib/sha.h:SHA224FinalBits`, `lib/sha224-256.c:SHA224FinalBits`
// Spec: SHA224FinalBits declaration contract#SHA-224 final bits declaration is visible when enabled
// - **GIVEN** `USE_SHA224` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA224FinalBits` 的调用
// - **THEN** 声明接受 `SHA224Context *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_224_final_bits_declaration_is_visible_when_enabled() {
    assert_eq!(sha::sha224_final_bits_zero_length_after_reset(), success());
}

// Trace: `lib/sha.h:SHA224Result`, `lib/sha224-256.c:SHA224Result`
// Spec: SHA224Result declaration contract#SHA-224 result declaration is visible when enabled
// - **GIVEN** `USE_SHA224` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA224Result` 的调用
// - **THEN** 声明接受 `SHA224Context *` 和 `uint8_t Message_Digest[SHA224HashSize]` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_224_result_declaration_is_visible_when_enabled() {
    assert_eq!(sha::sha224(b"abc").len(), sha::SHA224_HASH_SIZE);
}

// Trace: `lib/sha.h:SHA256Reset`, `lib/sha224-256.c:SHA256Reset`
// Spec: SHA256Reset declaration contract#SHA-256 reset declaration is always visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA256Reset` 的调用
// - **THEN** 声明接受 `SHA256Context *` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_256_reset_declaration_is_always_visible() {
    assert_eq!(sha::sha256(b"").len(), sha::SHA256_HASH_SIZE);
}

// Trace: `lib/sha.h:SHA256Input`, `lib/sha224-256.c:SHA256Input`
// Spec: SHA256Input declaration contract#SHA-256 input declaration is always visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA256Input` 的调用
// - **THEN** 声明接受 `SHA256Context *`、`const uint8_t *` 和 `size_t` 长度并返回 SHA 错误码
#[test]
fn test_sha_h_sha_256_input_declaration_is_always_visible() {
    assert_ne!(sha::sha256(b"abc"), sha::sha256(b""));
}

// Trace: `lib/sha.h:SHA256FinalBits`, `lib/sha224-256.c:SHA256FinalBits`
// Spec: SHA256FinalBits declaration contract#SHA-256 final bits declaration is always visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA256FinalBits` 的调用
// - **THEN** 声明接受 `SHA256Context *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_256_final_bits_declaration_is_always_visible() {
    assert_eq!(sha::sha256_final_bits_zero_length_after_reset(), success());
}

// Trace: `lib/sha.h:SHA256Result`, `lib/sha224-256.c:SHA256Result`
// Spec: SHA256Result declaration contract#SHA-256 result declaration is always visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA256Result` 的调用
// - **THEN** 声明接受 `SHA256Context *` 和 `uint8_t Message_Digest[SHA256HashSize]` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_256_result_declaration_is_always_visible() {
    assert_eq!(sha::sha256(b"abc").len(), sha::SHA256_HASH_SIZE);
}

// Trace: `lib/sha.h:SHA384Reset`, `lib/sha384-512.c:SHA384Reset`
// Spec: SHA384Reset declaration contract#SHA-384 reset declaration is visible when enabled
// - **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA384Reset` 的调用
// - **THEN** 声明接受 `SHA384Context *` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_384_reset_declaration_is_visible_when_enabled() {
    assert_eq!(sha::sha384(b"").len(), sha::SHA384_HASH_SIZE);
}

// Trace: `lib/sha.h:SHA384Input`, `lib/sha384-512.c:SHA384Input`
// Spec: SHA384Input declaration contract#SHA-384 input declaration is visible when enabled
// - **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA384Input` 的调用
// - **THEN** 声明接受 `SHA384Context *`、`const uint8_t *` 和 `size_t` 长度并返回 SHA 错误码
#[test]
fn test_sha_h_sha_384_input_declaration_is_visible_when_enabled() {
    assert_ne!(sha::sha384(b"abc"), sha::sha384(b""));
}

// Trace: `lib/sha.h:SHA384FinalBits`, `lib/sha384-512.c:SHA384FinalBits`
// Spec: SHA384FinalBits declaration contract#SHA-384 final bits declaration is visible when enabled
// - **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA384FinalBits` 的调用
// - **THEN** 声明接受 `SHA384Context *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_384_final_bits_declaration_is_visible_when_enabled() {
    assert_eq!(sha::sha384_final_bits_zero_length_after_reset(), success());
}

// Trace: `lib/sha.h:SHA384Result`, `lib/sha384-512.c:SHA384Result`
// Spec: SHA384Result declaration contract#SHA-384 result declaration is visible when enabled
// - **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA384Result` 的调用
// - **THEN** 声明接受 `SHA384Context *` 和 `uint8_t Message_Digest[SHA384HashSize]` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_384_result_declaration_is_visible_when_enabled() {
    assert_eq!(sha::sha384(b"abc").len(), sha::SHA384_HASH_SIZE);
}

// Trace: `lib/sha.h:SHA512Reset`, `lib/sha384-512.c:SHA512Reset`
// Spec: SHA512Reset declaration contract#SHA-512 reset declaration is visible when enabled
// - **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA512Reset` 的调用
// - **THEN** 声明接受 `SHA512Context *` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_512_reset_declaration_is_visible_when_enabled() {
    assert_eq!(sha::sha512(b"").len(), sha::SHA512_HASH_SIZE);
}

// Trace: `lib/sha.h:SHA512Input`, `lib/sha384-512.c:SHA512Input`
// Spec: SHA512Input declaration contract#SHA-512 input declaration is visible when enabled
// - **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA512Input` 的调用
// - **THEN** 声明接受 `SHA512Context *`、`const uint8_t *` 和 `size_t` 长度并返回 SHA 错误码
#[test]
fn test_sha_h_sha_512_input_declaration_is_visible_when_enabled() {
    assert_ne!(sha::sha512(b"abc"), sha::sha512(b""));
}

// Trace: `lib/sha.h:SHA512FinalBits`, `lib/sha384-512.c:SHA512FinalBits`
// Spec: SHA512FinalBits declaration contract#SHA-512 final bits declaration is visible when enabled
// - **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA512FinalBits` 的调用
// - **THEN** 声明接受 `SHA512Context *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_512_final_bits_declaration_is_visible_when_enabled() {
    assert_eq!(sha::sha512_final_bits_zero_length_after_reset(), success());
}

// Trace: `lib/sha.h:SHA512Result`, `lib/sha384-512.c:SHA512Result`
// Spec: SHA512Result declaration contract#SHA-512 result declaration is visible when enabled
// - **GIVEN** `USE_SHA384_SHA512` 启用且调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `SHA512Result` 的调用
// - **THEN** 声明接受 `SHA512Context *` 和 `uint8_t Message_Digest[SHA512HashSize]` 并返回 SHA 错误码
#[test]
fn test_sha_h_sha_512_result_declaration_is_visible_when_enabled() {
    assert_eq!(sha::sha512(b"abc").len(), sha::SHA512_HASH_SIZE);
}

// Trace: `lib/sha.h:USHAReset`, `lib/usha.c:USHAReset`
// Spec: USHAReset declaration contract#unified SHA reset declaration is visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `USHAReset` 的调用
// - **THEN** 声明接受 `USHAContext *` 和 `SHAversion` 并返回 SHA 错误码
#[test]
fn test_sha_h_unified_sha_reset_declaration_is_visible() {
    assert_eq!(sha::usha_reset_to_sha256(), success());
}

// Trace: `lib/sha.h:USHAInput`, `lib/usha.c:USHAInput`
// Spec: USHAInput declaration contract#unified SHA input declaration is visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `USHAInput` 的调用
// - **THEN** 声明接受 `USHAContext *`、`const uint8_t *` 和 `size_t` 长度并返回 SHA 错误码
#[test]
fn test_sha_h_unified_sha_input_declaration_is_visible() {
    assert_eq!(sha::usha_input_zero_length_after_reset(), success());
}

// Trace: `lib/sha.h:USHAFinalBits`, `lib/usha.c:USHAFinalBits`
// Spec: USHAFinalBits declaration contract#unified SHA final bits declaration is visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `USHAFinalBits` 的调用
// - **THEN** 声明接受 `USHAContext *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码
#[test]
fn test_sha_h_unified_sha_final_bits_declaration_is_visible() {
    assert_eq!(sha::usha_final_bits_zero_length_after_reset(), success());
}

// Trace: `lib/sha.h:USHAResult`, `lib/usha.c:USHAResult`
// Spec: USHAResult declaration contract#unified SHA result declaration is visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `USHAResult` 的调用
// - **THEN** 声明接受 `USHAContext *` 和 `uint8_t Message_Digest[USHAMaxHashSize]` 并返回 SHA 错误码
#[test]
fn test_sha_h_unified_sha_result_declaration_is_visible() {
    let (digest, code) = sha::usha_result_sha256_empty();

    assert_eq!(code, success());
    assert_eq!(digest, sha::sha256(b""));
}

// Trace: `lib/sha.h:USHABlockSize`, `lib/usha.c:USHABlockSize`
// Spec: USHABlockSize declaration contract#unified block-size query declaration is visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `USHABlockSize` 的调用
// - **THEN** 声明接受 `enum SHAversion` 并返回 `int` block size
#[test]
fn test_sha_h_unified_block_size_query_declaration_is_visible() {
    assert_eq!(sha::usha_block_size_sha256(), 64);
}

// Trace: `lib/sha.h:USHAHashSize`, `lib/usha.c:USHAHashSize`
// Spec: USHAHashSize declaration contract#unified hash-size query declaration is visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `USHAHashSize` 的调用
// - **THEN** 声明接受 `enum SHAversion` 并返回 `int` digest size
#[test]
fn test_sha_h_unified_hash_size_query_declaration_is_visible() {
    assert_eq!(sha::usha_hash_size(sha::sha_version_sha256()), 32);
}

// Trace: `lib/sha.h:USHAHashSizeBits`, `lib/usha.c:USHAHashSizeBits`
// Spec: USHAHashSizeBits declaration contract#unified hash-size-bits query declaration is visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `USHAHashSizeBits` 的调用
// - **THEN** 声明接受 `enum SHAversion` 并返回 `int` digest bit size
#[test]
fn test_sha_h_unified_hash_size_bits_query_declaration_is_visible() {
    assert_eq!(sha::usha_hash_size_bits(sha::sha_version_sha256()), 256);
}

// Trace: `lib/sha.h:hmac`, `lib/hmac.c:hmac`
// Spec: hmac declaration contract#one-shot HMAC declaration is visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `hmac` 的调用
// - **THEN** 声明接受 `SHAversion`、消息指针和长度、key 指针和长度、`uint8_t digest[USHAMaxHashSize]` 并返回 SHA 错误码
#[test]
fn test_sha_h_one_shot_hmac_declaration_is_visible() {
    assert_eq!(
        sha::hmac_bad_param_status(b"text", b"key"),
        sha::SHA_BAD_PARAM
    );
}

// Trace: `lib/sha.h:hmacReset`, `lib/hmac.c:hmacReset`
// Spec: hmacReset declaration contract#streaming HMAC reset declaration is visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `hmacReset` 的调用
// - **THEN** 声明接受 `HMACContext *`、`enum SHAversion`、key 指针和 key 长度并返回 SHA 错误码
#[test]
fn test_sha_h_streaming_hmac_reset_declaration_is_visible() {
    assert_eq!(sha::hmac_reset_null_sha256(b"key"), sha::SHA_NULL);
}

// Trace: `lib/sha.h:hmacInput`, `lib/hmac.c:hmacInput`
// Spec: hmacInput declaration contract#streaming HMAC input declaration is visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `hmacInput` 的调用
// - **THEN** 声明接受 `HMACContext *`、消息指针和消息长度并返回 SHA 错误码
#[test]
fn test_sha_h_streaming_hmac_input_declaration_is_visible() {
    assert_eq!(sha::hmac_input_null(b"data"), sha::SHA_NULL);
}

// Trace: `lib/sha.h:hmacFinalBits`, `lib/hmac.c:hmacFinalBits`
// Spec: hmacFinalBits declaration contract#streaming HMAC final bits declaration is visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `hmacFinalBits` 的调用
// - **THEN** 声明接受 `HMACContext *`、`uint8_t bits` 和 `size_t bitcount` 并返回 SHA 错误码
#[test]
fn test_sha_h_streaming_hmac_final_bits_declaration_is_visible() {
    assert_eq!(sha::hmac_final_bits_null(0x80, 1), sha::SHA_NULL);
}

// Trace: `lib/sha.h:hmacResult`, `lib/hmac.c:hmacResult`
// Spec: hmacResult declaration contract#streaming HMAC result declaration is visible
// - **GIVEN** 调用方包含 `lib/sha.h`
// - **WHEN** 调用方编译对 `hmacResult` 的调用
// - **THEN** 声明接受 `HMACContext *` 和 digest 输出指针并返回 SHA 错误码
#[test]
fn test_sha_h_streaming_hmac_result_declaration_is_visible() {
    assert_eq!(sha::hmac_result_null(), sha::SHA_NULL);
}
