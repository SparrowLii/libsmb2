use libsmb2_sys::legacy::sha;

// Trace: `lib/sha-private.h:SHA_Ch`
// Spec: SHA_Ch choice function macro#默认 choice 公式展开
// - **GIVEN** 编译包含 `lib/sha-private.h` 且未定义 `USE_MODIFIED_MACROS`
// - **WHEN** 包含方使用 `SHA_Ch(x,y,z)` 组合三个输入字
// - **THEN** 宏展开结果按 FIPS choice 公式选择 `x` 为 1 时的 `y` 位和 `x` 为 0 时的 `z` 位
#[test]
fn test_sha_private_choice_formula() {
    let x = 0b1010_u32;
    let y = 0b1100_u32;
    let z = 0b0011_u32;

    assert_eq!(sha::sha_choice_default(x, y, z), 0b1001);
}

// Trace: `lib/sha-private.h:SHA_Ch`
// Spec: SHA_Ch choice function macro#修改宏 choice 公式展开
// - **GIVEN** 编译包含 `lib/sha-private.h` 且定义了 `USE_MODIFIED_MACROS`
// - **WHEN** 包含方使用 `SHA_Ch(x,y,z)` 组合三个输入字
// - **THEN** 宏展开结果使用等价的 `((x) & ((y) ^ (z))) ^ (z)` 形式表达相同 choice 位语义
#[test]
fn test_sha_private_modified_choice_formula() {
    let x = 0x0f0f_f0f0;
    let y = 0x1234_5678;
    let z = 0x9abc_def0;

    assert_eq!(sha::sha_choice_modified(x, y, z), (x & (y ^ z)) ^ z);
    assert_eq!(
        sha::sha_choice_modified(x, y, z),
        sha::sha_choice_default(x, y, z)
    );
}

// Trace: `lib/sha-private.h:SHA_Maj`
// Spec: SHA_Maj majority function macro#默认 majority 公式展开
// - **GIVEN** 编译包含 `lib/sha-private.h` 且未定义 `USE_MODIFIED_MACROS`
// - **WHEN** 包含方使用 `SHA_Maj(x,y,z)` 组合三个输入字
// - **THEN** 宏展开结果按 FIPS majority 公式为每个位返回三个输入中的多数值
#[test]
fn test_sha_private_majority_formula() {
    let x = 0b1010_u32;
    let y = 0b1100_u32;
    let z = 0b0110_u32;

    assert_eq!(sha::sha_majority_default(x, y, z), 0b1110);
}

// Trace: `lib/sha-private.h:SHA_Maj`
// Spec: SHA_Maj majority function macro#修改宏 majority 公式展开
// - **GIVEN** 编译包含 `lib/sha-private.h` 且定义了 `USE_MODIFIED_MACROS`
// - **WHEN** 包含方使用 `SHA_Maj(x,y,z)` 组合三个输入字
// - **THEN** 宏展开结果使用等价的 `((x) & ((y) | (z))) | ((y) & (z))` 形式表达相同 majority 位语义
#[test]
fn test_sha_private_modified_majority_formula() {
    let x = 0x0f0f_f0f0;
    let y = 0x1234_5678;
    let z = 0x9abc_def0;

    assert_eq!(sha::sha_majority_modified(x, y, z), (x & (y | z)) | (y & z));
    assert_eq!(
        sha::sha_majority_modified(x, y, z),
        sha::sha_majority_default(x, y, z)
    );
}

// Trace: `lib/sha-private.h:SHA_Parity`
// Spec: SHA_Parity parity function macro#parity 公式展开
// - **GIVEN** 编译包含 `lib/sha-private.h`
// - **WHEN** 包含方使用 `SHA_Parity(x, y, z)` 组合三个输入字
// - **THEN** 宏展开结果对三个输入执行逐位 XOR
#[test]
fn test_sha_private_parity_formula() {
    let x = 0x0f0f_f0f0;
    let y = 0x1234_5678;
    let z = 0x9abc_def0;

    assert_eq!(sha::sha_parity(x, y, z), x ^ y ^ z);
}
