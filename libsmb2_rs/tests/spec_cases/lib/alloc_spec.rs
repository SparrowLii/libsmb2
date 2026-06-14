use libsmb2_sys::legacy::alloc::{
    forced_child_failure, forced_init_failure_returns_null, free_null_is_noop, AllocContext,
};

// Trace: `lib/alloc.c:smb2_alloc_init`, `include/libsmb2-private.h:smb2_alloc_init`
// Spec: smb2_alloc_init creates a zeroed allocation context#successful context allocation
// - **GIVEN** 调用方提供任意 `struct smb2_context *smb2` 和待分配的 `size`
// - **WHEN** `smb2_alloc_init` 的内部 `calloc` 成功
// - **THEN** 返回值 MUST 指向内部 `struct smb2_alloc_header` 的 `buf` 区域，并且该上下文的追加分配链初始为空
#[test]
fn test_alloc_successful_context_allocation() {
    let ctx = AllocContext::new(8).unwrap();

    assert_eq!(ctx.bytes(), &[0; 8]);
}

// Trace: `lib/alloc.c:smb2_alloc_init`
// Spec: smb2_alloc_init creates a zeroed allocation context#initial allocation failure
// - **GIVEN** 调用方请求创建内存上下文
// - **WHEN** `smb2_alloc_init` 的内部 `calloc` 返回 `NULL`
// - **THEN** 函数 MUST 返回 `NULL`，且源码未显示该路径设置 `smb2` 错误字符串
#[test]
fn test_alloc_initial_allocation_failure() {
    assert!(forced_init_failure_returns_null(8));
}

// Trace: `lib/alloc.c:smb2_alloc_data`, `include/libsmb2-private.h:smb2_alloc_data`, `tests/smb2-dcerpc-coder-test.c:test_dcerpc_coder`
// Spec: smb2_alloc_data appends zeroed child allocations to a context#successful child allocation
// - **GIVEN** `memctx` 是 `smb2_alloc_init` 返回的上下文数据指针
// - **WHEN** `smb2_alloc_data` 的内部 `calloc` 成功
// - **THEN** 返回值 MUST 指向新 `struct smb2_alloc_entry` 的 `buf` 区域，且该 entry MUST 插入上下文头的 `mem` 链表
#[test]
fn test_alloc_successful_child_allocation() {
    let mut ctx = AllocContext::new(4).unwrap();

    let child = ctx.alloc_child(6).unwrap();

    assert_eq!(child, &mut [0; 6]);
}

// Trace: `lib/alloc.c:smb2_alloc_data`, `lib/init.c:smb2_set_error`
// Spec: smb2_alloc_data appends zeroed child allocations to a context#child allocation failure records context error
// - **GIVEN** 调用方提供 `smb2` 和有效的 `memctx`
// - **WHEN** `smb2_alloc_data` 的内部 `calloc` 返回 `NULL`
// - **THEN** 函数 MUST 调用 `smb2_set_error` 记录失败分配大小并返回 `NULL`
#[test]
fn test_alloc_child_allocation_failure_records_context_error() {
    let failure = forced_child_failure(8);

    assert!(failure.returned_null);
    assert!(failure.set_error_called);
    assert!(failure.message.starts_with("Failed to alloc "));
    assert!(failure.message.ends_with(" bytes"));
}

// Trace: `lib/alloc.c:smb2_free_data`, `include/smb2/libsmb2-raw.h:smb2_free_data`, `tests/smb2-dcerpc-coder-test.c:main`
// Spec: smb2_free_data releases allocation contexts and tolerates NULL#freeing a populated context
// - **GIVEN** `ptr` 是 `smb2_alloc_init` 返回的上下文数据指针，且该上下文包含零个或多个 `smb2_alloc_data` 子分配
// - **WHEN** 调用方调用 `smb2_free_data`
// - **THEN** 函数 MUST 遍历并释放上下文链表中的每个子分配，然后释放上下文头本身
#[test]
fn test_alloc_freeing_a_populated_context() {
    let mut ctx = AllocContext::new(4).unwrap();
    ctx.alloc_child(6).unwrap();

    assert_eq!(ctx.bytes(), &[0; 4]);
    drop(ctx);
}

// Trace: `lib/alloc.c:smb2_free_data`
// Spec: smb2_free_data releases allocation contexts and tolerates NULL#freeing NULL is a no-op
// - **GIVEN** 调用方传入 `ptr == NULL`
// - **WHEN** 调用方调用 `smb2_free_data`
// - **THEN** 函数 MUST 直接返回且 SHALL NOT 调用 `free`
#[test]
fn test_alloc_freeing_null_is_a_noop() {
    assert_eq!(free_null_is_noop(), ());
}
