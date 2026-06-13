use libsmb2_sys::{include::portable_endian, legacy::compat};

// Trace: `lib/compat.h:191`, `lib/compat.h:355`, `lib/compat.h:500`, `lib/compat.h:751`, `lib/compat.c:463`
// Spec: struct pollfd provides fallback poll descriptor layout#caller prepares poll descriptors
// - **GIVEN** 平台使用 `lib/compat.h` 中的 fallback `struct pollfd`
// - **WHEN** 调用方设置 `fd` 和 `events` 后调用 `poll`
// - **THEN** 兼容 poll 实现 MUST 能读取 `fd`/`events` 并通过 `revents` 返回事件位
#[test]
fn test_compat_h_caller_prepares_poll_descriptors() {
    assert!(compat::POLLFD_LAYOUT.has_fd);
    assert!(compat::POLLFD_LAYOUT.has_events);
    assert!(compat::POLLFD_LAYOUT.has_revents);
}

// Trace: `lib/compat.h:212`, `lib/compat.h:508`, `lib/compat.h:651`, `lib/compat.c:381`, `lib/compat.c:424`
// Spec: struct iovec provides fallback scatter-gather layout#compatibility vector I/O reads iovec entries
// - **GIVEN** 平台使用 `lib/compat.h` 中的 fallback `struct iovec`
// - **WHEN** 调用方将 iovec 数组传入 `writev` 或 `readv`
// - **THEN** 兼容实现 MUST 能读取每个元素的 base 指针和长度以聚合写入或拆分读取结果
#[test]
fn test_compat_h_compatibility_vector_i_o_reads_iovec_entries() {
    assert!(compat::IOVEC_LAYOUT.has_base);
    assert!(compat::IOVEC_LAYOUT.has_len);
}

// Trace: `lib/compat.h:308`, `lib/compat.h:461`, `lib/compat.c:590`
// Spec: be64toh provides selected platform endian conversion compatibility#caller converts big-endian 64-bit value
// - **GIVEN** 平台定义 `NEED_BE64TOH` 且调用方传入 64 位 big-endian 值
// - **WHEN** 调用 `be64toh(x)`
// - **THEN** 兼容实现 MUST 转换低 32 位和高 32 位并组合为 host-order 64 位结果
#[test]
fn test_compat_h_caller_converts_big_endian_64_bit_value() {
    let host_value = 0x0102_0304_0506_0708_u64;
    let network_order = host_value.to_be();

    assert_eq!(portable_endian::be64_to_host(network_order), host_value);
}

// Trace: `lib/compat.h:785`
// Spec: O_RDONLY supplies missing read-only open flag#platform lacks O_RDONLY
// - **GIVEN** 预处理到 `lib/compat.h` 末尾且 `O_RDONLY` 未定义
// - **WHEN** 调用方使用 `O_RDONLY`
// - **THEN** 宏值 MUST 展开为 `00000000`
#[test]
fn test_compat_h_platform_lacks_o_rdonly() {
    assert_eq!(compat::O_RDONLY_FALLBACK, 0o00000000);
}

// Trace: `lib/compat.h:789`
// Spec: O_WRONLY supplies missing write-only open flag#platform lacks O_WRONLY
// - **GIVEN** 预处理到 `lib/compat.h` 末尾且 `O_WRONLY` 未定义
// - **WHEN** 调用方使用 `O_WRONLY`
// - **THEN** 宏值 MUST 展开为 `00000001`
#[test]
fn test_compat_h_platform_lacks_o_wronly() {
    assert_eq!(compat::O_WRONLY_FALLBACK, 0o00000001);
}

// Trace: `lib/compat.h:793`
// Spec: O_RDWR supplies missing read-write open flag#platform lacks O_RDWR
// - **GIVEN** 预处理到 `lib/compat.h` 末尾且 `O_RDWR` 未定义
// - **WHEN** 调用方使用 `O_RDWR`
// - **THEN** 宏值 MUST 展开为 `00000002`
#[test]
fn test_compat_h_platform_lacks_o_rdwr() {
    assert_eq!(compat::O_RDWR_FALLBACK, 0o00000002);
}

// Trace: `lib/compat.h:797`
// Spec: O_DSYNC supplies missing synchronized data write flag#platform lacks O_DSYNC
// - **GIVEN** 预处理到 `lib/compat.h` 末尾且 `O_DSYNC` 未定义
// - **WHEN** 调用方使用 `O_DSYNC`
// - **THEN** 宏值 MUST 展开为 `040000`
#[test]
fn test_compat_h_platform_lacks_o_dsync() {
    assert_eq!(compat::O_DSYNC_FALLBACK, 0o040000);
}

// Trace: `lib/compat.h:801`, `lib/compat.h:805`
// Spec: O_SYNC supplies missing synchronized write flag#platform lacks O_SYNC
// - **GIVEN** 预处理到 `lib/compat.h` 末尾且 `O_SYNC` 未定义
// - **WHEN** 调用方使用 `O_SYNC`
// - **THEN** 宏值 MUST 展开为 `__O_SYNC` 与 `O_DSYNC` 的按位或表达式
#[test]
fn test_compat_h_platform_lacks_o_sync() {
    assert_eq!(
        compat::O_SYNC_FALLBACK,
        compat::__O_SYNC_FALLBACK | compat::O_DSYNC_FALLBACK
    );
}

// Trace: `lib/compat.h:809`
// Spec: O_ACCMODE supplies missing access-mode mask#platform lacks O_ACCMODE
// - **GIVEN** 预处理到 `lib/compat.h` 末尾且 `O_ACCMODE` 未定义
// - **WHEN** 调用方使用 `O_ACCMODE` 提取 open 访问模式
// - **THEN** 宏值 MUST 展开为 `O_RDWR`、`O_WRONLY` 和 `O_RDONLY` 的按位或表达式
#[test]
fn test_compat_h_platform_lacks_o_accmode() {
    assert_eq!(
        compat::O_ACCMODE_FALLBACK,
        compat::O_RDWR_FALLBACK | compat::O_WRONLY_FALLBACK | compat::O_RDONLY_FALLBACK
    );
}

// Trace: `lib/compat.h:813`
// Spec: ENOMEM supplies missing allocation error code#platform lacks ENOMEM
// - **GIVEN** 预处理到 `lib/compat.h` 末尾且 `ENOMEM` 未定义
// - **WHEN** 兼容代码或调用方引用 `ENOMEM`
// - **THEN** 宏值 MUST 展开为 `12`
#[test]
fn test_compat_h_platform_lacks_enomem() {
    assert_eq!(compat::ENOMEM_FALLBACK, 12);
}

// Trace: `lib/compat.h:817`, `lib/compat.c:384`, `lib/compat.c:428`
// Spec: EINVAL supplies missing invalid-argument error code#platform lacks EINVAL
// - **GIVEN** 预处理到 `lib/compat.h` 末尾且 `EINVAL` 未定义
// - **WHEN** 兼容代码或调用方引用 `EINVAL`
// - **THEN** 宏值 MUST 展开为 `22`
#[test]
fn test_compat_h_platform_lacks_einval() {
    assert_eq!(compat::EINVAL_FALLBACK, 22);
}

// Trace: `lib/compat.h:821`
// Spec: typeof maps to GNU typeof spelling#compiler exposes only __typeof__
// - **GIVEN** 编译器提供 `__typeof__` 但未预定义 `typeof`
// - **WHEN** 调用方源码使用 `typeof(expr)`
// - **THEN** 预处理结果 MUST 使用 `__typeof__(expr)` 拼写
#[test]
fn test_compat_h_compiler_exposes_only_typeof() {
    assert_eq!(compat::TYPEOF_COMPAT_SPELLING, "__typeof__");
}
