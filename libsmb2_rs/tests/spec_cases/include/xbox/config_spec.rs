use libsmb2_rs::include::config::XBOX_CONFIG;

// Trace: `include/xbox/config.h:HAVE_FCNTL_H`
// Spec: HAVE_FCNTL_H declares fcntl header availability#fcntl 头能力可见
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码读取 `HAVE_FCNTL_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<fcntl.h>` 可用
#[test]
fn test_config_xbox_fcntl_header_availability() {
    assert_eq!(XBOX_CONFIG.have_fcntl_h, Some(1));
}

// Trace: `include/xbox/config.h:HAVE_GSSAPI_GSSAPI_H`
// Spec: HAVE_GSSAPI_GSSAPI_H declares GSSAPI header absence#GSSAPI 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_GSSAPI_GSSAPI_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_gssapi_header_absence() {
    assert_eq!(XBOX_CONFIG.have_gssapi_gssapi_h, None);
}

// Trace: `include/xbox/config.h:HAVE_INTTYPES_H`
// Spec: HAVE_INTTYPES_H declares inttypes header absence#inttypes 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_INTTYPES_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_inttypes_header_absence() {
    assert_eq!(XBOX_CONFIG.have_inttypes_h, None);
}

// Trace: `include/xbox/config.h:HAVE_LIBKRB5`, `lib/spnego-wrapper.c:HAVE_LIBKRB5`
// Spec: HAVE_LIBKRB5 declares Kerberos library absence#Kerberos 条件编译保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 认证相关源码检查 `HAVE_LIBKRB5` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义，依赖该宏的 Kerberos 条件路径不由该配置启用
#[test]
fn test_config_xbox_kerberos_library_absence() {
    assert_eq!(XBOX_CONFIG.have_libkrb5, None);
}

// Trace: `include/xbox/config.h:HAVE_LIBNSL`
// Spec: HAVE_LIBNSL declares nsl library absence#nsl 链接能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 构建或源码检查 `HAVE_LIBNSL` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_nsl_library_absence() {
    assert_eq!(XBOX_CONFIG.have_libnsl, None);
}

// Trace: `include/xbox/config.h:HAVE_LIBSOCKET`
// Spec: HAVE_LIBSOCKET declares socket library absence#socket 链接库能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 构建或源码检查 `HAVE_LIBSOCKET` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_socket_library_absence() {
    assert_eq!(XBOX_CONFIG.have_libsocket, None);
}

// Trace: `include/xbox/config.h:HAVE_LINGER`, `lib/socket.c:HAVE_LINGER`
// Spec: HAVE_LINGER declares system linger support#socket 源码不定义兼容 linger 结构
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** `lib/socket.c` 检查 `#if !defined(HAVE_LINGER)`
// - **THEN** 源码 SHALL 不启用本地 `struct linger` 兼容定义
#[test]
fn test_config_xbox_linger_header_availability() {
    assert_eq!(XBOX_CONFIG.have_linger, Some(1));
}

// Trace: `include/xbox/config.h:HAVE_NETDB_H`
// Spec: HAVE_NETDB_H declares netdb header absence#netdb 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_NETDB_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_netdb_header_absence() {
    assert_eq!(XBOX_CONFIG.have_netdb_h, None);
}

// Trace: `include/xbox/config.h:HAVE_NETINET_IN_H`
// Spec: HAVE_NETINET_IN_H declares netinet in header absence#netinet in 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_NETINET_IN_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_netinet_in_header_absence() {
    assert_eq!(XBOX_CONFIG.have_netinet_in_h, None);
}

// Trace: `include/xbox/config.h:HAVE_NETINET_TCP_H`
// Spec: HAVE_NETINET_TCP_H declares netinet tcp header absence#netinet tcp 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_NETINET_TCP_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_netinet_tcp_header_absence() {
    assert_eq!(XBOX_CONFIG.have_netinet_tcp_h, None);
}

// Trace: `include/xbox/config.h:HAVE_POLL_H`
// Spec: HAVE_POLL_H declares poll header absence#poll 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_POLL_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_poll_header_absence() {
    assert_eq!(XBOX_CONFIG.have_poll_h, None);
}

// Trace: `include/xbox/config.h:HAVE_SOCKADDR_LEN`
// Spec: HAVE_SOCKADDR_LEN declares sockaddr length member absence#地址结构布局不声明 sa_len
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_SOCKADDR_LEN` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_sockaddr_length_member_absence() {
    assert_eq!(XBOX_CONFIG.have_sockaddr_len, None);
}

// Trace: `include/xbox/config.h:HAVE_SOCKADDR_STORAGE`
// Spec: HAVE_SOCKADDR_STORAGE declares sockaddr_storage availability#socket 路径可使用通用地址存储
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码读取 `HAVE_SOCKADDR_STORAGE`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `sockaddr_storage` 可用
#[test]
fn test_config_xbox_sockaddr_storage_availability() {
    assert_eq!(XBOX_CONFIG.have_sockaddr_storage, Some(1));
}

// Trace: `include/xbox/config.h:HAVE_STDINT_H`
// Spec: HAVE_STDINT_H declares stdint header absence#stdint 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_STDINT_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_stdint_header_absence() {
    assert_eq!(XBOX_CONFIG.have_stdint_h, None);
}

// Trace: `include/xbox/config.h:HAVE_STDIO_H`
// Spec: HAVE_STDIO_H declares stdio header availability#标准 I/O 头能力可见
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码读取 `HAVE_STDIO_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<stdio.h>` 可用
#[test]
fn test_config_xbox_stdio_header_availability() {
    assert_eq!(XBOX_CONFIG.have_stdio_h, Some(1));
}

// Trace: `include/xbox/config.h:HAVE_STDLIB_H`
// Spec: HAVE_STDLIB_H declares stdlib header availability#标准库头能力可见
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码读取 `HAVE_STDLIB_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<stdlib.h>` 可用
#[test]
fn test_config_xbox_stdlib_header_availability() {
    assert_eq!(XBOX_CONFIG.have_stdlib_h, Some(1));
}

// Trace: `include/xbox/config.h:HAVE_STRINGS_H`
// Spec: HAVE_STRINGS_H declares strings header absence#strings 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_STRINGS_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_strings_header_absence() {
    assert_eq!(XBOX_CONFIG.have_strings_h, None);
}

// Trace: `include/xbox/config.h:HAVE_STRING_H`
// Spec: HAVE_STRING_H declares string header availability#C 字符串头能力可见
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码读取 `HAVE_STRING_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<string.h>` 可用
#[test]
fn test_config_xbox_string_header_availability() {
    assert_eq!(XBOX_CONFIG.have_string_h, Some(1));
}

// Trace: `include/xbox/config.h:HAVE_SYS_ERRNO_H`
// Spec: HAVE_SYS_ERRNO_H declares sys errno header absence#sys errno 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_ERRNO_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_sys_errno_header_absence() {
    assert_eq!(XBOX_CONFIG.have_sys_errno_h, None);
}

// Trace: `include/xbox/config.h:HAVE_SYS_FCNTL_H`
// Spec: HAVE_SYS_FCNTL_H declares sys fcntl header absence#sys fcntl 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_FCNTL_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_sys_fcntl_header_absence() {
    assert_eq!(XBOX_CONFIG.have_sys_fcntl_h, None);
}

// Trace: `include/xbox/config.h:CONFIGURE_OPTION_TCP_LINGER`, `lib/socket.c:connect_async_ai`, `lib/socket.c:smb2_accept_connection_async`
// Spec: CONFIGURE_OPTION_TCP_LINGER controls Xbox socket linger policy#Xbox 配置保留默认 linger 行为
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** `lib/socket.c` 在连接或接受 socket 的路径中检查 `#if 0 == CONFIGURE_OPTION_TCP_LINGER`
// - **THEN** Xbox 配置取值 `1` SHALL 使该条件为假，源码不编译设置 `SO_REUSEADDR` 和零秒 `SO_LINGER` 的分支
#[test]
fn test_config_xbox_linger() {
    assert_eq!(XBOX_CONFIG.configure_option_tcp_linger, Some(1));
}

// Trace: `include/xbox/config.h:HAVE_ARPA_INET_H`
// Spec: HAVE_ARPA_INET_H declares arpa inet header absence#arpa inet 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_ARPA_INET_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_arpa_inet_header_absence() {
    assert_eq!(XBOX_CONFIG.have_arpa_inet_h, None);
}

// Trace: `include/xbox/config.h:HAVE_DLFCN_H`
// Spec: HAVE_DLFCN_H declares dlfcn header absence#dlfcn 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_DLFCN_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_dlfcn_header_absence() {
    assert_eq!(XBOX_CONFIG.have_dlfcn_h, None);
}

// Trace: `include/xbox/config.h:HAVE_ERRNO_H`
// Spec: HAVE_ERRNO_H declares errno header availability#errno 头能力可见
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码读取 `HAVE_ERRNO_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<errno.h>` 可用
#[test]
fn test_config_xbox_errno_header_availability() {
    assert_eq!(XBOX_CONFIG.have_errno_h, Some(1));
}

// Trace: `include/xbox/config.h:HAVE_SYS_IOCTL_H`
// Spec: HAVE_SYS_IOCTL_H declares sys ioctl header absence#sys ioctl 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_IOCTL_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_sys_ioctl_header_absence() {
    assert_eq!(XBOX_CONFIG.have_sys_ioctl_h, None);
}

// Trace: `include/xbox/config.h:HAVE_SYS_POLL_H`
// Spec: HAVE_SYS_POLL_H declares sys poll header absence#sys poll 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_POLL_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_sys_poll_header_absence() {
    assert_eq!(XBOX_CONFIG.have_sys_poll_h, None);
}

// Trace: `include/xbox/config.h:HAVE_SYS_SOCKET_H`
// Spec: HAVE_SYS_SOCKET_H declares sys socket header absence#sys socket 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_SOCKET_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_sys_socket_header_absence() {
    assert_eq!(XBOX_CONFIG.have_sys_socket_h, None);
}

// Trace: `include/xbox/config.h:HAVE_SYS_STAT_H`
// Spec: HAVE_SYS_STAT_H declares sys stat header availability#文件状态头能力可见
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码读取 `HAVE_SYS_STAT_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<sys/stat.h>` 可用
#[test]
fn test_config_xbox_sys_stat_header_availability() {
    assert_eq!(XBOX_CONFIG.have_sys_stat_h, Some(1));
}

// Trace: `include/xbox/config.h:HAVE_SYS_TIME_H`
// Spec: HAVE_SYS_TIME_H declares sys time header absence#sys time 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_TIME_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_sys_time_header_absence() {
    assert_eq!(XBOX_CONFIG.have_sys_time_h, None);
}

// Trace: `include/xbox/config.h:HAVE_SYS_TYPES_H`
// Spec: HAVE_SYS_TYPES_H declares sys types header availability#系统基础类型头能力可见
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码读取 `HAVE_SYS_TYPES_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<sys/types.h>` 可用
#[test]
fn test_config_xbox_sys_types_header_availability() {
    assert_eq!(XBOX_CONFIG.have_sys_types_h, Some(1));
}

// Trace: `include/xbox/config.h:HAVE_SYS_UIO_H`
// Spec: HAVE_SYS_UIO_H declares sys uio header absence#sys uio 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_UIO_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_sys_uio_header_absence() {
    assert_eq!(XBOX_CONFIG.have_sys_uio_h, None);
}

// Trace: `include/xbox/config.h:HAVE_SYS_UNISTD_H`
// Spec: HAVE_SYS_UNISTD_H declares sys unistd header absence#sys unistd 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_UNISTD_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_sys_unistd_header_absence() {
    assert_eq!(XBOX_CONFIG.have_sys_unistd_h, None);
}

// Trace: `include/xbox/config.h:HAVE_SYS__IOVEC_H`
// Spec: HAVE_SYS__IOVEC_H declares sys iovec header absence#sys iovec 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_SYS__IOVEC_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_sys_iovec_header_absence() {
    assert_eq!(XBOX_CONFIG.have_sys_iovec_h, None);
}

// Trace: `include/xbox/config.h:HAVE_TIME_H`
// Spec: HAVE_TIME_H declares time header availability#time 头能力可见
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码读取 `HAVE_TIME_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<time.h>` 可用
#[test]
fn test_config_xbox_time_header_availability() {
    assert_eq!(XBOX_CONFIG.have_time_h, Some(1));
}

// Trace: `include/xbox/config.h:HAVE_UNISTD_H`
// Spec: HAVE_UNISTD_H declares unistd header absence#unistd 头能力保持禁用
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码检查 `HAVE_UNISTD_H` 是否定义
// - **THEN** 预处理器 SHALL 将该宏视为未定义
#[test]
fn test_config_xbox_unistd_header_absence() {
    assert_eq!(XBOX_CONFIG.have_unistd_h, None);
}

// Trace: `include/xbox/config.h:LT_OBJDIR`
// Spec: LT_OBJDIR exposes libtool object directory#读取 libtool 对象目录元数据
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码或诊断工具读取 `LT_OBJDIR`
// - **THEN** 该宏 SHALL 展开为字符串 `".libs/"`
#[test]
fn test_config_xbox_lt_objdir() {
    assert_eq!(XBOX_CONFIG.lt_objdir, ".libs/");
}

// Trace: `include/xbox/config.h:PACKAGE`
// Spec: PACKAGE exposes package short name#读取包短名
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码或诊断工具读取 `PACKAGE`
// - **THEN** 该宏 SHALL 展开为字符串 `"libsmb2"`
#[test]
fn test_config_xbox_package() {
    assert_eq!(XBOX_CONFIG.package, "libsmb2");
}

// Trace: `include/xbox/config.h:PACKAGE_BUGREPORT`
// Spec: PACKAGE_BUGREPORT exposes bug report contact#读取问题报告地址
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码或诊断工具读取 `PACKAGE_BUGREPORT`
// - **THEN** 该宏 SHALL 展开为字符串 `"ronniesahlberg@gmail.com"`
#[test]
fn test_config_xbox_package_bugreport() {
    assert_eq!(XBOX_CONFIG.package_bugreport, "ronniesahlberg@gmail.com");
}

// Trace: `include/xbox/config.h:PACKAGE_NAME`
// Spec: PACKAGE_NAME exposes package full name#读取包全名
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码或诊断工具读取 `PACKAGE_NAME`
// - **THEN** 该宏 SHALL 展开为字符串 `"libsmb2"`
#[test]
fn test_config_xbox_package_name() {
    assert_eq!(XBOX_CONFIG.package_name, "libsmb2");
}

// Trace: `include/xbox/config.h:PACKAGE_STRING`
// Spec: PACKAGE_STRING exposes package name and version#读取包名版本组合
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码或诊断工具读取 `PACKAGE_STRING`
// - **THEN** 该宏 SHALL 展开为字符串 `"libsmb2 4.0.0"`
#[test]
fn test_config_xbox_package_string() {
    assert_eq!(XBOX_CONFIG.package_string, "libsmb2 4.0.0");
}

// Trace: `include/xbox/config.h:PACKAGE_TARNAME`
// Spec: PACKAGE_TARNAME exposes distribution tar name#读取发行包名
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码或诊断工具读取 `PACKAGE_TARNAME`
// - **THEN** 该宏 SHALL 展开为字符串 `"libsmb2"`
#[test]
fn test_config_xbox_package_tarname() {
    assert_eq!(XBOX_CONFIG.package_tarname, "libsmb2");
}

// Trace: `include/xbox/config.h:PACKAGE_URL`
// Spec: PACKAGE_URL exposes package URL string#读取包主页元数据
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码或诊断工具读取 `PACKAGE_URL`
// - **THEN** 该宏 SHALL 展开为空字符串
#[test]
fn test_config_xbox_package_url() {
    assert_eq!(XBOX_CONFIG.package_url, "");
}

// Trace: `include/xbox/config.h:PACKAGE_VERSION`
// Spec: PACKAGE_VERSION exposes Xbox package version#读取包版本
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码或诊断工具读取 `PACKAGE_VERSION`
// - **THEN** 该宏 SHALL 展开为字符串 `"4.0.0"`
#[test]
fn test_config_xbox_package_version() {
    assert_eq!(XBOX_CONFIG.package_version, "4.0.0");
}

// Trace: `include/xbox/config.h:STDC_HEADERS`
// Spec: STDC_HEADERS declares C90 standard header availability#C90 标准头集合能力可见
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码读取 `STDC_HEADERS`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 C90 标准头集合可用
#[test]
fn test_config_xbox_stdc_headers() {
    assert_eq!(XBOX_CONFIG.stdc_headers, Some(1));
}

// Trace: `include/xbox/config.h:VERSION`
// Spec: VERSION exposes Xbox version string#读取版本号
// - **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
// - **WHEN** 源码或诊断工具读取 `VERSION`
// - **THEN** 该宏 SHALL 展开为字符串 `"4.0.0"`
#[test]
fn test_config_xbox_version() {
    assert_eq!(XBOX_CONFIG.version, "4.0.0");
}
