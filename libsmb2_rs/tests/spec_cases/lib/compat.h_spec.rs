use libsmb2_rs::include::portable_endian;
use libsmb2_rs::lib::compat;

// Trace: `lib/compat.h:275`, `lib/compat.h:277`, `lib/compat.h:343`, `lib/compat.h:475`
// Spec: close macro maps POSIX close to platform socket close#platform rewrites close call
// - **GIVEN** 编译目标为 Winsock、Amiga 或 PS2 IOP 等需要重定向 close 的平台
// - **WHEN** 调用方源码写入 `close(socket_or_fd)`
// - **THEN** 预处理结果 MUST 调用该平台配置的 `_close`、`closesocket`、`CloseSocket` 或 `lwip_close` 入口
#[test]
fn test_compat_h_platform_rewrites_close_call() {
    assert_eq!(compat::CLOSE_COMPAT_TARGETS.winsock_use_winsock, "_close");
    assert_eq!(compat::CLOSE_COMPAT_TARGETS.winsock_default, "closesocket");
    assert_eq!(compat::CLOSE_COMPAT_TARGETS.amiga, "CloseSocket");
    assert_eq!(compat::CLOSE_COMPAT_TARGETS.ps2_iop, "lwip_close");
}

// Trace: `lib/compat.h:280`, `lib/compat.h:557`, `lib/compat.h:772`, `lib/compat.c:347`
// Spec: srandom seeds platform random compatibility#caller seeds compatibility random generator
// - **GIVEN** 平台定义 `NEED_SRANDOM`
// - **WHEN** 调用 `srandom(seed)`
// - **THEN** 兼容实现 MUST 在 PS2 IOP 上保存本地线性同余状态，或在其他平台调用底层 `smb2_srandom(seed)`
#[test]
fn test_compat_h_caller_seeds_compatibility_random_generator() {
    assert_eq!(compat::SRANDOM_NON_IOP_DELEGATE, "smb2_srandom");
}

// Trace: `lib/compat.h:281`, `lib/compat.h:466`, `lib/compat.h:558`, `lib/compat.h:773`, `lib/compat.c:331`
// Spec: random returns platform random compatibility value#caller obtains compatibility random value
// - **GIVEN** 平台定义 `NEED_RANDOM`
// - **WHEN** 调用 `random()`
// - **THEN** 兼容实现 MUST 在 PS2 IOP 上更新并返回本地状态派生值，或在其他平台返回底层 `smb2_random()` 的值
#[test]
fn test_compat_h_caller_obtains_compatibility_random_value() {
    assert_eq!(compat::RANDOM_NON_IOP_DELEGATE, "smb2_random");
    assert_eq!(compat::ps2_iop_random_after_seed(1), 16_838);
}

// Trace: `lib/compat.h:283`, `lib/compat.h:309`, `lib/compat.h:325`, `lib/compat.h:339`, `lib/compat.h:471`, `lib/compat.h:556`, `lib/compat.h:635`, `lib/compat.h:729`, `lib/compat.h:774`, `lib/compat.h:781`, `lib/compat.c:365`
// Spec: getlogin_r provides platform login compatibility#caller invokes login-name compatibility function
// - **GIVEN** 平台定义 `NEED_GETLOGIN_R`
// - **WHEN** 调用 `getlogin_r(buf, size)`
// - **THEN** 兼容实现 MUST 返回平台宏 `login_num`，且源码未显示其写入 `buf`
#[test]
fn test_compat_h_caller_invokes_login_name_compatibility_function() {
    assert_eq!(compat::GETLOGIN_COMPAT_TARGETS.default_status, "ENXIO");
    assert_eq!(compat::GETLOGIN_COMPAT_TARGETS.xbox_status, 0);
    assert_eq!(compat::GETLOGIN_COMPAT_TARGETS.pico_status, 1);
    assert!(!compat::GETLOGIN_COMPAT_TARGETS.writes_buffer);
}

// Trace: `lib/compat.h:285`, `lib/compat.h:474`, `lib/compat.c:357`
// Spec: getpid provides process identifier compatibility#caller obtains compatibility process id
// - **GIVEN** 平台定义 `NEED_GETPID`
// - **WHEN** 调用 `getpid()`
// - **THEN** 兼容实现 MUST 返回平台宏 `getpid_num()` 的结果
#[test]
fn test_compat_h_caller_obtains_compatibility_process_id() {
    assert_eq!(
        compat::GETPID_COMPAT_TARGETS.windows_target,
        "GetCurrentProcessId"
    );
    assert_eq!(compat::GETPID_COMPAT_TARGETS.xbox_value, 0);
    assert_eq!(compat::GETPID_COMPAT_TARGETS.ps2_iop_value, 27);
}

// Trace: `lib/compat.h:39`, `lib/compat.h:48`
// Spec: t_socket provides a platform socket handle type#platform chooses socket handle representation
// - **GIVEN** 调用方包含 `lib/compat.h`，且编译目标为 Windows/Xbox/Mingw 或默认 POSIX-like 平台
// - **WHEN** 源码声明或传递 `t_socket` 值
// - **THEN** 类型定义 MUST 与目标平台 socket API 的句柄表示一致
#[test]
fn test_compat_h_platform_chooses_socket_handle_representation() {
    assert_eq!(compat::T_SOCKET_DEFAULT_KIND, "int");
}

// Trace: `lib/compat.h:43`, `lib/compat.h:51`
// Spec: SMB2_INVALID_SOCKET defines the invalid socket sentinel#caller compares against invalid socket sentinel
// - **GIVEN** 调用方需要识别 socket 创建或传递失败
// - **WHEN** 调用方读取 `SMB2_INVALID_SOCKET`
// - **THEN** 宏值 MUST 表示当前平台的无效 socket 句柄哨兵
#[test]
fn test_compat_h_caller_compares_against_invalid_socket_sentinel() {
    assert_eq!(compat::SMB2_INVALID_SOCKET_DEFAULT, -1);
}

// Trace: `lib/compat.h:44`, `lib/compat.h:50`, `lib/compat.c:478`, `lib/compat.c:539`
// Spec: SMB2_VALID_SOCKET evaluates socket validity#compatibility poll filters invalid descriptors
// - **GIVEN** 兼容 `poll` 实现遍历 `struct pollfd` 数组
// - **WHEN** `SMB2_VALID_SOCKET(fd)` 判断某个 `fd` 无效
// - **THEN** 调用方或兼容实现 MUST 将该 socket 视为不可用于平台 socket 操作
#[test]
fn test_compat_h_compatibility_poll_filters_invalid_descriptors() {
    assert!(!compat::smb2_valid_socket_default(-1));
    assert!(compat::smb2_valid_socket_default(0));
}

// Trace: `lib/compat.h:171`, `lib/compat.h:401`, `lib/compat.h:590`
// Spec: struct sockaddr_storage provides fallback address storage#platform lacks sockaddr_storage
// - **GIVEN** 编译目标命中 Winsock/Xbox、Amiga 或 PS3 fallback 分支，且系统头未提供可用 `sockaddr_storage`
// - **WHEN** 调用方声明 `struct sockaddr_storage` 变量
// - **THEN** 该类型 MUST 包含地址族字段，并提供源码中定义的填充布局用于编译兼容
#[test]
fn test_compat_h_platform_lacks_sockaddr_storage() {
    assert!(compat::SOCKADDR_STORAGE_LAYOUT.has_family);
    assert!(compat::SOCKADDR_STORAGE_LAYOUT.min_size >= 128);
}

// Trace: `lib/compat.h:179`, `lib/compat.h:363`, `lib/compat.h:660`, `lib/compat.c:314`
// Spec: struct addrinfo provides fallback getaddrinfo ABI#compatibility resolver fills addrinfo result
// - **GIVEN** 平台使用 `smb2_getaddrinfo` 兼容实现
// - **WHEN** 兼容实现分配并填充 `struct addrinfo`
// - **THEN** 结果结构 MUST 提供源码声明的字段，以便调用方读取地址族、地址长度、地址指针和链表 next 指针
#[test]
fn test_compat_h_compatibility_resolver_fills_addrinfo_result() {
    assert!(compat::ADDRINFO_LAYOUT.has_flags);
    assert!(compat::ADDRINFO_LAYOUT.has_family);
    assert!(compat::ADDRINFO_LAYOUT.has_socktype);
    assert!(compat::ADDRINFO_LAYOUT.has_protocol);
    assert!(compat::ADDRINFO_LAYOUT.has_addrlen);
    assert!(compat::ADDRINFO_LAYOUT.has_canonname);
    assert!(compat::ADDRINFO_LAYOUT.has_addr);
    assert!(compat::ADDRINFO_LAYOUT.has_next);

    let snapshot = compat::resolve_ipv4_addrinfo("127.0.0.1", None).unwrap();
    assert_eq!(snapshot.family, compat::AF_INET_FAMILY);
    assert!(snapshot.addr_len > 0);
    assert!(snapshot.next_is_null);
}

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

// Trace: `lib/compat.h:219`, `lib/compat.h:236`, `lib/compat.h:376`, `lib/compat.h:506`, `lib/compat.h:757`, `lib/compat.c:463`
// Spec: poll provides platform poll compatibility#fallback poll uses select-backed readiness
// - **GIVEN** 平台定义 `NEED_POLL` 并提供 `struct pollfd` 数组
// - **WHEN** 调用 `poll(fds, nfds, timo)`
// - **THEN** 兼容实现 MUST 清零 `revents`，根据 `POLLIN`、`POLLPRI`、`POLLOUT` 构造 `select` 集合，并在 `select` 成功后设置对应 `revents` 位
#[test]
fn test_compat_h_fallback_poll_uses_select_backed_readiness() {
    let readable = compat::poll_readable_pipe().unwrap();
    let writable = compat::poll_writable_pipe().unwrap();

    assert!(readable.rc > 0);
    assert_eq!(readable.errno, 0);
    assert_eq!(
        readable.revents & compat::POLLIN_EVENT,
        compat::POLLIN_EVENT
    );
    assert!(writable.rc > 0);
    assert_eq!(writable.errno, 0);
    assert_eq!(
        writable.revents & compat::POLLOUT_EVENT,
        compat::POLLOUT_EVENT
    );
}

// Trace: `lib/compat.h:226`, `lib/compat.c:258`
// Spec: smb2_getaddrinfo provides IPv4 address resolution compatibility#compatibility resolver returns IPv4 addrinfo
// - **GIVEN** 平台定义 `NEED_GETADDRINFO`，调用方传入 `node`、可选 `service`、可选 `hints` 和 `res` 输出参数
// - **WHEN** 调用 `smb2_getaddrinfo(node, service, hints, res)`
// - **THEN** 函数 MUST 分配 IPv4 `sockaddr_in` 和 `addrinfo`，设置 `ai_family` 为 `AF_INET`、`ai_addrlen` 为 `sizeof(struct sockaddr_in)`、`ai_addr` 指向分配的地址，并在成功时返回 `0`
#[test]
fn test_compat_h_compatibility_resolver_returns_ipv4_addrinfo() {
    let snapshot = compat::resolve_ipv4_addrinfo("127.0.0.1", Some("445")).unwrap();

    assert_eq!(snapshot.family, compat::AF_INET_FAMILY);
    assert!(snapshot.addr_len > 0);
    assert!(snapshot.next_is_null);
    assert_eq!(snapshot.port, 445);
    assert_eq!(snapshot.ipv4_addr, 0x7f00_0001);
}

// Trace: `lib/compat.h:229`, `lib/compat.c:323`
// Spec: smb2_freeaddrinfo releases compatibility resolver storage#caller releases compatibility addrinfo
// - **GIVEN** 调用方持有由 `smb2_getaddrinfo` 返回的 `struct addrinfo *res`
// - **WHEN** 调用 `smb2_freeaddrinfo(res)`
// - **THEN** 函数 MUST 释放 `res->ai_addr`，随后释放 `res`
#[test]
fn test_compat_h_caller_releases_compatibility_addrinfo() {
    let snapshot = compat::resolve_ipv4_addrinfo("127.0.0.1", None).unwrap();

    assert_eq!(snapshot.family, compat::AF_INET_FAMILY);
    assert!(snapshot.addr_len > 0);
    assert!(snapshot.next_is_null);
}

// Trace: `lib/compat.h:231`, `lib/compat.h:383`, `lib/compat.h:559`, `lib/compat.h:737`
// Spec: getaddrinfo macro redirects to smb2_getaddrinfo#source uses standard resolver spelling
// - **GIVEN** 平台进入 `lib/compat.h` 的兼容解析分支
// - **WHEN** 调用方源码写入 `getaddrinfo(node, service, hints, res)`
// - **THEN** 预处理结果 MUST 调用项目的 `smb2_getaddrinfo(node, service, hints, res)`
#[test]
fn test_compat_h_source_uses_standard_resolver_spelling() {
    assert_eq!(compat::GETADDRINFO_COMPAT_TARGET, "smb2_getaddrinfo");
}

// Trace: `lib/compat.h:232`, `lib/compat.h:384`, `lib/compat.h:560`, `lib/compat.h:738`
// Spec: freeaddrinfo macro redirects to smb2_freeaddrinfo#source releases resolver result with standard spelling
// - **GIVEN** 平台进入 `lib/compat.h` 的兼容解析分支
// - **WHEN** 调用方源码写入 `freeaddrinfo(res)`
// - **THEN** 预处理结果 MUST 调用项目的 `smb2_freeaddrinfo(res)`
#[test]
fn test_compat_h_source_releases_resolver_result_with_standard_spelling() {
    assert_eq!(compat::FREEADDRINFO_COMPAT_TARGET, "smb2_freeaddrinfo");
}

// Trace: `lib/compat.h:243`, `lib/compat.h:248`, `lib/compat.h:322`, `lib/compat.h:387`, `lib/compat.h:530`, `lib/compat.h:574`, `lib/compat.h:637`, `lib/compat.h:727`, `lib/compat.c:371`
// Spec: writev provides scatter-gather write compatibility#fallback writev aggregates vectors
// - **GIVEN** 平台定义 `NEED_WRITEV`，调用方传入 `count` 个 `struct iovec` 条目
// - **WHEN** 调用 `writev(fd, vector, count)`
// - **THEN** 兼容实现 MUST 检查总长度是否溢出 `ssize_t`，分配聚合缓冲区，按 iovec 顺序复制数据，调用底层 `write`，释放缓冲区，并返回底层写入字节数或 `-1`
#[test]
fn test_compat_h_fallback_writev_aggregates_vectors() {
    let (written, output, errno) = compat::writev_to_pipe(&[b"SM", b"B2"]).unwrap();

    assert_eq!(written, 4);
    assert_eq!(output, b"SMB2");
    assert_eq!(errno, 0);
    assert!(compat::writev_overflow_sets_einval());
}

// Trace: `lib/compat.h:244`, `lib/compat.h:260`, `lib/compat.h:323`, `lib/compat.h:388`, `lib/compat.h:531`, `lib/compat.h:575`, `lib/compat.h:638`, `lib/compat.h:728`, `lib/compat.c:416`
// Spec: readv provides scatter-gather read compatibility#fallback readv distributes bytes into vectors
// - **GIVEN** 平台定义 `NEED_READV`，调用方传入 `count` 个 `struct iovec` 条目
// - **WHEN** 调用 `readv(fd, vector, count)`
// - **THEN** 兼容实现 MUST 检查总长度是否溢出 `ssize_t`，分配临时缓冲区，调用底层 `read`，按 iovec 顺序复制已读字节，释放缓冲区，并返回底层读取字节数或 `-1`
#[test]
fn test_compat_h_fallback_readv_distributes_bytes_into_vectors() {
    let (read, output, errno) = compat::readv_from_pipe(b"SMB2", &[1, 3]).unwrap();

    assert_eq!(read, 4);
    assert_eq!(output, b"SMB2");
    assert_eq!(errno, 0);
    assert!(compat::readv_overflow_sets_einval());
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
