use libsmb2_rs::include::asprintf;

// Trace: `include/asprintf.h:_vscprintf_so`
// Spec: _vscprintf_so computes formatted output length#non-Xbox length calculation uses a copied va_list
// - **GIVEN** 编译条件未定义 `_XBOX` 和 `__MINGW32__`，且 `_vscprintf` 未预先定义
// - **WHEN** 调用 `_vscprintf_so(format, pargs)` 计算格式化字符串长度
// - **THEN** 函数基于 `va_copy` 创建的参数副本调用 `vsnprintf(NULL, 0, format, argcopy)`，结束副本并返回 `vsnprintf` 的返回值
// Note: safe binding uses a C shim to construct and reuse `va_list` without exposing raw FFI to Rust tests.
#[test]
fn test_asprintf_non_xbox_length_calculation_uses_a_copied_va_list() {
    assert_eq!(asprintf::vscprintf_two_ints("%d:%02d", 7, 5), 4);
    assert_eq!(asprintf::vscprintf_reuse_after_length("%d:%02d", 7, 5), 4);
}

// Trace: `include/asprintf.h:vasprintf`
// Spec: vasprintf allocates and formats an owned buffer#successful allocation and formatting
// - **GIVEN** `vasprintf` 未预定义，长度计算返回非负值，且 `malloc((size_t)len + 1)` 成功
// - **WHEN** 调用 `vasprintf(strp, fmt, ap)` 生成格式化字符串
// - **THEN** 函数分配 `len + 1` 字节，调用平台对应的格式化函数写入缓冲区，将缓冲区地址赋给 `*strp`，并返回格式化结果 `r`
// Note: safe binding returns the owned C buffer as a Rust `String` and frees the C allocation after observation.
#[test]
fn test_asprintf_successful_allocation_and_formatting() {
    let result = asprintf::vasprintf_two_ints("%d:%02d", 7, 5).unwrap();

    assert_eq!(result.rc, 4);
    assert_eq!(result.text, "7:05");
}

// Trace: `include/asprintf.h:vasprintf`
// Spec: vasprintf allocates and formats an owned buffer#length calculation or allocation failure
// - **GIVEN** `vasprintf` 未预定义，且长度计算返回 `-1` 或 `malloc` 返回 `NULL`
// - **WHEN** 调用 `vasprintf(strp, fmt, ap)`
// - **THEN** 函数返回 `-1`，且在 `malloc` 失败路径不会向 `*strp` 写入新缓冲区
// Note: safe binding exposes separate source-backed harnesses for length and allocation failure branches.
#[test]
fn test_asprintf_length_calculation_or_allocation_failure() {
    let length_failure = asprintf::vasprintf_length_failure_preserves_output();
    assert_eq!(length_failure.rc, -1);
    assert!(!length_failure.wrote_new_buffer);

    let allocation_failure = asprintf::vasprintf_alloc_failure_preserves_output();
    assert_eq!(allocation_failure.rc, -1);
    assert!(!allocation_failure.wrote_new_buffer);
}

// Trace: `include/asprintf.h:vasprintf`
// Spec: vasprintf allocates and formats an owned buffer#formatting failure releases allocated storage
// - **GIVEN** `vasprintf` 未预定义，长度计算和 `malloc` 成功，但最终格式化调用返回 `-1`
// - **WHEN** 调用 `vasprintf(strp, fmt, ap)`
// - **THEN** 函数释放已分配缓冲区并返回 `-1`
// Note: safe binding counts the source `free(str)` path in a C shim and exposes only safe result data.
#[test]
fn test_asprintf_formatting_failure_releases_allocated_storage() {
    let result = asprintf::vasprintf_format_failure_releases_storage();

    assert_eq!(result.rc, -1);
    assert!(result.released_allocated_storage);
}

// Trace: `include/asprintf.h:asprintf`, `tests/prog_ls.c:161`, `tests/prog_ls.c:166`
// Spec: asprintf wraps vasprintf with varargs lifecycle#varargs forwarding to vasprintf
// - **GIVEN** `asprintf` 未预定义，调用方传入输出指针数组、格式字符串和可变参数
// - **WHEN** 调用 `asprintf(strp, fmt, ...)`
// - **THEN** 函数初始化 `va_list`，调用 `vasprintf(strp, fmt, ap)`，结束 `va_list`，并返回 `vasprintf` 的返回值
// Note: safe binding calls the C varargs wrapper and observes the returned length and owned buffer.
#[test]
fn test_asprintf_varargs_forwarding_to_vasprintf() {
    let result = asprintf::asprintf_two_ints("%d:%02d", 7, 5).unwrap();

    assert_eq!(result.rc, 4);
    assert_eq!(result.text, "7:05");
}

// Trace: `include/asprintf.h:inline`
// Spec: inline macro maps Xbox inline spelling#Xbox compile condition rewrites inline keyword
// - **GIVEN** 编译条件定义 `_XBOX`
// - **WHEN** 预处理 `include/asprintf.h`
// - **THEN** 头文件定义 `inline` 为 `__inline`，后续 `static inline` 函数声明使用该映射
// Note: safe binding exposes a C preprocessor observation of the `_XBOX` inline mapping.
#[test]
fn test_asprintf_xbox_compile_condition_rewrites_inline_keyword() {
    assert!(asprintf::xbox_inline_maps_to_inline());
}
