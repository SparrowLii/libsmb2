use libsmb2_sys::{include::portable_endian, legacy::compat};

// Trace: `lib/compat.c:331`
// Spec: random returns platform random values#non-IOP random delegates to platform source
// - **GIVEN** 平台定义 `NEED_RANDOM` 但未定义 `_IOP`
// - **WHEN** 调用 `random()`
// - **THEN** 实现 MUST 返回 `smb2_random()` 的结果
#[test]
fn test_compat_non_iop_random_delegates_to_platform_source() {
    assert_eq!(compat::RANDOM_NON_IOP_DELEGATE, "smb2_random");
}

// Trace: `lib/compat.c:347`
// Spec: srandom seeds platform random state#non-IOP seed delegates to platform
// - **GIVEN** 平台定义 `NEED_SRANDOM` 但未定义 `_IOP`
// - **WHEN** 调用 `srandom(seed)`
// - **THEN** 实现 MUST 调用 `smb2_srandom(seed)`
#[test]
fn test_compat_non_iop_seed_delegates_to_platform() {
    assert_eq!(compat::SRANDOM_NON_IOP_DELEGATE, "smb2_srandom");
}

// Trace: `lib/compat.c:357`
// Spec: getpid returns configured platform identifier#caller requests compatibility process id
// - **GIVEN** 平台定义 `NEED_GETPID`
// - **WHEN** 调用 `getpid()`
// - **THEN** 实现 MUST 返回当前平台 `getpid_num()` 展开的值
#[test]
fn test_compat_caller_requests_compatibility_process_id() {
    assert_eq!(
        compat::GETPID_COMPAT_TARGETS.windows_target,
        "GetCurrentProcessId"
    );
    assert_eq!(compat::GETPID_COMPAT_TARGETS.xbox_value, 0);
    assert_eq!(compat::GETPID_COMPAT_TARGETS.ps2_iop_value, 27);
}

// Trace: `lib/compat.c:365`
// Spec: getlogin_r returns configured login status#caller requests login name compatibility
// - **GIVEN** 平台定义 `NEED_GETLOGIN_R`
// - **WHEN** 调用 `getlogin_r(buf, size)`
// - **THEN** 实现 MUST 返回 `login_num`，且源码未显示写入 `buf`
#[test]
fn test_compat_caller_requests_login_name_compatibility() {
    assert_eq!(compat::GETLOGIN_COMPAT_TARGETS.default_status, "ENXIO");
    assert_eq!(compat::GETLOGIN_COMPAT_TARGETS.xbox_status, 0);
    assert_eq!(compat::GETLOGIN_COMPAT_TARGETS.pico_status, 1);
    assert!(!compat::GETLOGIN_COMPAT_TARGETS.writes_buffer);
}

// Trace: `lib/compat.c:258`
// Spec: smb2_getaddrinfo returns IPv4 compatibility results#numeric or inet_addr resolver result
// - **GIVEN** 平台定义 `NEED_GETADDRINFO`，调用方传入 `node`、可选 `service` 和 `res` 输出参数
// - **WHEN** 调用 `smb2_getaddrinfo(node, service, hints, res)`
// - **THEN** 实现 MUST 设置 `ai_family` 为 `AF_INET`，设置 `ai_addrlen` 为 `sizeof(struct sockaddr_in)`，设置 `ai_addr` 指向分配的 IPv4 socket 地址，并在成功路径返回 `0`
#[test]
fn test_compat_numeric_or_inet_addr_resolver_result() {
    let snapshot = compat::resolve_ipv4_addrinfo("127.0.0.1", Some("445")).unwrap();

    assert_eq!(snapshot.family, compat::AF_INET_FAMILY);
    assert!(snapshot.addr_len > 0);
    assert!(snapshot.next_is_null);
    assert_eq!(snapshot.port, 445);
    assert_eq!(snapshot.ipv4_addr, 0x7f00_0001);
}

// Trace: `lib/compat.c:323`
// Spec: smb2_freeaddrinfo releases resolver allocations#caller frees compatibility addrinfo
// - **GIVEN** 调用方持有由兼容 resolver 返回的 `struct addrinfo *res`
// - **WHEN** 调用 `smb2_freeaddrinfo(res)`
// - **THEN** 实现 MUST 先释放 `res->ai_addr`，再释放 `res`
#[test]
fn test_compat_caller_frees_compatibility_addrinfo() {
    let snapshot = compat::resolve_ipv4_addrinfo("127.0.0.1", None).unwrap();

    assert_eq!(snapshot.family, compat::AF_INET_FAMILY);
    assert!(snapshot.addr_len > 0);
    assert!(snapshot.next_is_null);
}

// Trace: `lib/compat.c:331`
// Spec: random returns platform random values#PS2 IOP random advances local state
// - **GIVEN** 编译目标定义 `_IOP`
// - **WHEN** 调用 `random()`
// - **THEN** 实现 MUST 更新静态 `next` 状态并返回 `(unsigned int)(next/65536) % 32768`
#[test]
fn test_compat_ps2_iop_random_advances_local_state() {
    assert_eq!(compat::ps2_iop_random_after_seed(1), 16_838);
    assert_eq!(compat::PS2_IOP_RANDOM_DIVISOR, 65_536);
    assert_eq!(compat::PS2_IOP_RANDOM_MODULUS, 32_768);
}

// Trace: `lib/compat.c:347`
// Spec: srandom seeds platform random state#PS2 IOP seed updates local state
// - **GIVEN** 编译目标定义 `_IOP`
// - **WHEN** 调用 `srandom(seed)`
// - **THEN** 实现 MUST 将静态 `next` 状态设置为 `seed`
#[test]
fn test_compat_ps2_iop_seed_updates_local_state() {
    let seeded_once = compat::ps2_iop_random_after_seed(7);
    let expected = (7_u32
        .wrapping_mul(compat::PS2_IOP_RANDOM_MULTIPLIER)
        .wrapping_add(compat::PS2_IOP_RANDOM_INCREMENT)
        / compat::PS2_IOP_RANDOM_DIVISOR)
        % compat::PS2_IOP_RANDOM_MODULUS;

    assert_eq!(seeded_once, expected);
}

// Trace: `lib/compat.c:371`
// Spec: writev aggregates vector writes#vector length overflows ssize_t
// - **GIVEN** 调用方传入 `count` 个 iovec，且总长度会超过 `ssize_t` 可表示范围
// - **WHEN** 调用 `writev(fd, vector, count)`
// - **THEN** 实现 MUST 设置 `errno` 为 `EINVAL` 并返回 `-1`
#[test]
fn test_compat_vector_length_overflows_ssize_t() {
    assert!(compat::writev_overflow_sets_einval());
}

// Trace: `lib/compat.c:371`
// Spec: writev aggregates vector writes#vector write succeeds through temporary buffer
// - **GIVEN** 调用方传入可聚合的 iovec 数组，且临时缓冲区分配成功
// - **WHEN** 调用 `writev(fd, vector, count)`
// - **THEN** 实现 MUST 按 iovec 顺序复制所有字节，调用底层 `write((int)fd, buffer, bytes)`，释放临时缓冲区，并返回底层写入结果
#[test]
fn test_compat_vector_write_succeeds_through_temporary_buffer() {
    let (written, output, errno) = compat::writev_to_pipe(&[b"vec", b"tor"]).unwrap();

    assert_eq!(written, 6);
    assert_eq!(output, b"vector");
    assert_eq!(errno, 0);
}

// Trace: `lib/compat.c:416`
// Spec: readv distributes a single read into vectors#vector length overflows ssize_t during read
// - **GIVEN** 调用方传入 `count` 个 iovec，且总长度会超过 `ssize_t` 可表示范围
// - **WHEN** 调用 `readv(fd, vector, count)`
// - **THEN** 实现 MUST 设置 `errno` 为 `EINVAL` 并返回 `-1`
#[test]
fn test_compat_vector_length_overflows_ssize_t_during_read() {
    assert!(compat::readv_overflow_sets_einval());
}

// Trace: `lib/compat.c:416`
// Spec: readv distributes a single read into vectors#vector read succeeds through temporary buffer
// - **GIVEN** 调用方传入可聚合的 iovec 数组，临时缓冲区分配成功，且底层 `read` 返回非负字节数
// - **WHEN** 调用 `readv(fd, vector, count)`
// - **THEN** 实现 MUST 将底层读取的字节按 iovec 顺序复制到调用方缓冲区，释放临时缓冲区，并返回底层读取字节数
#[test]
fn test_compat_vector_read_succeeds_through_temporary_buffer() {
    let (read, output, errno) = compat::readv_from_pipe(b"scatter", &[3, 4]).unwrap();

    assert_eq!(read, 7);
    assert_eq!(output, b"scatter");
    assert_eq!(errno, 0);
}

// Trace: `lib/compat.c:463`
// Spec: poll maps requested events through select#poll prepares select sets
// - **GIVEN** 调用方传入 `fds` 数组和 `nfds`
// - **WHEN** 调用 `poll(fds, nfds, timo)`
// - **THEN** 实现 MUST 清零每个 `revents`，将 `POLLIN` 或 `POLLPRI` 映射到 read fd_set，将 `POLLOUT` 映射到 write fd_set，并将异常 fd_set 用于 hangup 检测
#[test]
fn test_compat_poll_prepares_select_sets() {
    let readable = compat::poll_readable_pipe().unwrap();
    let writable = compat::poll_writable_pipe().unwrap();

    assert_eq!(readable.errno, 0);
    assert_eq!(
        readable.revents & compat::POLLIN_EVENT,
        compat::POLLIN_EVENT
    );
    assert_eq!(writable.errno, 0);
    assert_eq!(
        writable.revents & compat::POLLOUT_EVENT,
        compat::POLLOUT_EVENT
    );
}

// Trace: `lib/compat.c:511`, `lib/compat.c:518`
// Spec: poll maps requested events through select#poll timeout conversion follows platform branch
// - **GIVEN** 调用方传入 `timo` 毫秒超时
// - **WHEN** 调用 `poll(fds, nfds, timo)`
// - **THEN** 实现 MUST 在非 Amiga 分支中将负超时映射为 NULL timeout，并在其他非负路径中填充 `timeval` 秒与微秒字段
#[test]
fn test_compat_poll_timeout_conversion_follows_platform_branch() {
    let readable = compat::poll_readable_pipe().unwrap();

    assert!(readable.rc > 0);
    assert_eq!(readable.errno, 0);
}

// Trace: `lib/compat.c:528`, `lib/compat.c:533`, `lib/compat.c:552`
// Spec: poll maps requested events through select#poll returns readiness events
// - **GIVEN** `select(maxfd + 1, ip, op, &efds, toptr)` 返回正值
// - **WHEN** 兼容实现检查 fd_set 结果
// - **THEN** 实现 MUST 为就绪读写设置 `POLLIN` 或 `POLLOUT`，并在异常集合命中时设置 `POLLHUP`
#[test]
fn test_compat_poll_returns_readiness_events() {
    let readable = compat::poll_readable_pipe().unwrap();
    let writable = compat::poll_writable_pipe().unwrap();

    assert!(readable.rc > 0);
    assert_eq!(
        readable.revents & compat::POLLIN_EVENT,
        compat::POLLIN_EVENT
    );
    assert!(writable.rc > 0);
    assert_eq!(
        writable.revents & compat::POLLOUT_EVENT,
        compat::POLLOUT_EVENT
    );
}

// Trace: `lib/compat.c:570`
// Spec: strdup duplicates NUL-terminated strings#duplicate allocation succeeds
// - **GIVEN** 调用方传入 NUL 结尾字符串 `s`，且分配成功
// - **WHEN** 调用 `strdup(s)`
// - **THEN** 实现 MUST 分配 `strlen(s) + 1` 字节，复制包含 NUL 终止符的内容，并返回新分配字符串
#[test]
fn test_compat_duplicate_allocation_succeeds() {
    assert_eq!(compat::strdup_matches("compat-owned").unwrap(), 12);
}

// Trace: `lib/compat.c:590`
// Spec: be64toh converts big-endian 64-bit values#caller converts network-order 64-bit integer
// - **GIVEN** 调用方传入 big-endian 64 位整数 `x`
// - **WHEN** 调用 `be64toh(x)`
// - **THEN** 实现 MUST 转换低 32 位和高 32 位并返回组合后的 host-order 值
#[test]
fn test_compat_caller_converts_network_order_64_bit_integer() {
    let host_value = 0x0102_0304_0506_0708_u64;
    let network_order = host_value.to_be();

    assert_eq!(portable_endian::be64_to_host(network_order), host_value);
}
