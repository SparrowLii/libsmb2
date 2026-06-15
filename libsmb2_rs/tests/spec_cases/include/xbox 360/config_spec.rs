use libsmb2_rs::include::config::XBOX_360_CONFIG;

// Trace: `include/xbox 360/config.h:CONFIGURE_OPTION_TCP_LINGER`, `lib/socket.c:connect_async_ai`, `lib/socket.c:smb2_accept_connection_async`
// Spec: CONFIGURE_OPTION_TCP_LINGER controls Xbox 360 socket linger policy#Xbox 360 配置保留默认 linger 行为
// - **GIVEN** Xbox 360 构建使用 `include/xbox 360/config.h` 作为 `config.h` 配置来源
// - **WHEN** `lib/socket.c` 在连接或接受 socket 的路径中检查 `#if 0 == CONFIGURE_OPTION_TCP_LINGER`
// - **THEN** Xbox 360 配置取值 `1` SHALL 使该条件为假，源码不编译设置 `SO_REUSEADDR` 和零秒 `SO_LINGER` 的分支
#[test]
fn test_config_xbox_360_linger() {
    assert_eq!(XBOX_360_CONFIG.configure_option_tcp_linger, Some(1));
}

// Trace: `include/xbox 360/config.h:HAVE_ARPA_INET_H`, `configure.ac:HAVE_ARPA_INET_H`
// Spec: HAVE_ARPA_INET_H declares arpa inet header absence#arpa inet header remains disabled
// - **GIVEN** 源码以配置宏判断网络地址头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_ARPA_INET_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_arpa_inet_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_arpa_inet_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_DLFCN_H`
// Spec: HAVE_DLFCN_H declares dlfcn header absence#dlfcn header remains disabled
// - **GIVEN** 源码以配置宏判断动态加载头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_DLFCN_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_dlfcn_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_dlfcn_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_ERRNO_H`, `configure.ac:HAVE_ERRNO_H`
// Spec: HAVE_ERRNO_H declares errno header availability#errno header capability is visible
// - **GIVEN** 源码以配置宏判断错误头能力
// - **WHEN** 读取 `HAVE_ERRNO_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<errno.h>` 可用
#[test]
fn test_config_xbox_360_errno_header_capability_is_visible() {
    assert_eq!(XBOX_360_CONFIG.have_errno_h, Some(1));
}

// Trace: `include/xbox 360/config.h:HAVE_FCNTL_H`, `configure.ac:HAVE_FCNTL_H`
// Spec: HAVE_FCNTL_H declares fcntl header availability#fcntl header capability is visible
// - **GIVEN** 源码以配置宏判断文件控制头能力
// - **WHEN** 读取 `HAVE_FCNTL_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<fcntl.h>` 可用
#[test]
fn test_config_xbox_360_fcntl_header_capability_is_visible() {
    assert_eq!(XBOX_360_CONFIG.have_fcntl_h, Some(1));
}

// Trace: `include/xbox 360/config.h:HAVE_GSSAPI_GSSAPI_H`, `configure.ac:HAVE_GSSAPI_GSSAPI_H`
// Spec: HAVE_GSSAPI_GSSAPI_H declares GSSAPI header absence#GSSAPI header capability remains disabled
// - **GIVEN** 源码以配置宏判断 GSSAPI 头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_GSSAPI_GSSAPI_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_gssapi_header_capability_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_gssapi_gssapi_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_INTTYPES_H`
// Spec: HAVE_INTTYPES_H declares inttypes header absence#inttypes header remains disabled
// - **GIVEN** 源码以配置宏判断整数格式头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_INTTYPES_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_inttypes_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_inttypes_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_LIBKRB5`, `configure.ac:HAVE_LIBKRB5`
// Spec: HAVE_LIBKRB5 declares Kerberos library absence#Kerberos library capability remains disabled
// - **GIVEN** 认证相关源码以配置宏判断 libkrb5 能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_LIBKRB5`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_kerberos_library_capability_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_libkrb5, None);
}

// Trace: `include/xbox 360/config.h:HAVE_LIBNSL`
// Spec: HAVE_LIBNSL declares nsl library absence#nsl link capability remains disabled
// - **GIVEN** 构建或源码以配置宏判断 `nsl` 库能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_LIBNSL`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_nsl_link_capability_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_libnsl, None);
}

// Trace: `include/xbox 360/config.h:HAVE_LIBSOCKET`
// Spec: HAVE_LIBSOCKET declares socket library absence#socket link capability remains disabled
// - **GIVEN** 构建或源码以配置宏判断 `socket` 库能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_LIBSOCKET`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_socket_link_capability_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_libsocket, None);
}

// Trace: `include/xbox 360/config.h:HAVE_LINGER`, `lib/socket.c:121`, `configure.ac:HAVE_LINGER`
// Spec: HAVE_LINGER declares system linger support#compatible linger structure is not selected
// - **GIVEN** socket 源码以配置宏判断 linger 结构能力
// - **WHEN** `lib/socket.c` 检查 `#if !defined(HAVE_LINGER)`
// - **THEN** 源码 SHALL 不启用本地 `struct linger` 兼容定义
#[test]
fn test_config_xbox_360_compatible_linger_structure_is_not_selected() {
    assert_eq!(XBOX_360_CONFIG.have_linger, Some(1));
}

// Trace: `include/xbox 360/config.h:HAVE_NETDB_H`
// Spec: HAVE_NETDB_H declares netdb header absence#netdb header remains disabled
// - **GIVEN** 源码以配置宏判断地址解析头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_NETDB_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_netdb_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_netdb_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_NETINET_IN_H`, `lib/socket.c:38`, `lib/md5.h:30`
// Spec: HAVE_NETINET_IN_H declares netinet in header absence#netinet in header remains disabled
// - **GIVEN** 源码以配置宏判断 IP socket 类型头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_NETINET_IN_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_netinet_in_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_netinet_in_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_NETINET_TCP_H`, `configure.ac:HAVE_NETINET_TCP_H`
// Spec: HAVE_NETINET_TCP_H declares netinet tcp header absence#netinet tcp header remains disabled
// - **GIVEN** 源码以配置宏判断 TCP 选项头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_NETINET_TCP_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_netinet_tcp_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_netinet_tcp_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_POLL_H`, `configure.ac:HAVE_POLL_H`
// Spec: HAVE_POLL_H declares poll header absence#poll header remains disabled
// - **GIVEN** 源码以配置宏判断 poll 头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_POLL_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_poll_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_poll_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_SOCKADDR_LEN`, `configure.ac:HAVE_SOCKADDR_LEN`
// Spec: HAVE_SOCKADDR_LEN declares sockaddr length member absence#sockaddr length member remains disabled
// - **GIVEN** socket 地址布局代码以配置宏判断 sockaddr 长度成员
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_SOCKADDR_LEN`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_sockaddr_length_member_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_sockaddr_len, None);
}

// Trace: `include/xbox 360/config.h:HAVE_SOCKADDR_STORAGE`, `configure.ac:HAVE_SOCKADDR_STORAGE`
// Spec: HAVE_SOCKADDR_STORAGE declares sockaddr storage absence#sockaddr storage capability remains disabled
// - **GIVEN** 源码以配置宏判断通用 socket 地址存储能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_SOCKADDR_STORAGE`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_sockaddr_storage_capability_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_sockaddr_storage, None);
}

// Trace: `include/xbox 360/config.h:HAVE_STDINT_H`, `lib/socket.c:86`, `lib/md5.h:37`
// Spec: HAVE_STDINT_H declares stdint header availability#stdint header capability is visible
// - **GIVEN** 源码以配置宏判断固定宽度整数头能力
// - **WHEN** 读取 `HAVE_STDINT_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<stdint.h>` 可用
#[test]
fn test_config_xbox_360_stdint_header_capability_is_visible() {
    assert_eq!(XBOX_360_CONFIG.have_stdint_h, Some(1));
}

// Trace: `include/xbox 360/config.h:HAVE_STDIO_H`, `lib/socket.c:54`
// Spec: HAVE_STDIO_H declares stdio header availability#stdio header capability is visible
// - **GIVEN** 源码以配置宏判断标准 I/O 头能力
// - **WHEN** 读取 `HAVE_STDIO_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<stdio.h>` 可用
#[test]
fn test_config_xbox_360_stdio_header_capability_is_visible() {
    assert_eq!(XBOX_360_CONFIG.have_stdio_h, Some(1));
}

// Trace: `include/xbox 360/config.h:HAVE_STDLIB_H`, `lib/socket.c:50`
// Spec: HAVE_STDLIB_H declares stdlib header availability#stdlib header capability is visible
// - **GIVEN** 源码以配置宏判断标准库头能力
// - **WHEN** 读取 `HAVE_STDLIB_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<stdlib.h>` 可用
#[test]
fn test_config_xbox_360_stdlib_header_capability_is_visible() {
    assert_eq!(XBOX_360_CONFIG.have_stdlib_h, Some(1));
}

// Trace: `include/xbox 360/config.h:HAVE_STRINGS_H`, `configure.ac:HAVE_STRINGS_H`
// Spec: HAVE_STRINGS_H declares strings header absence#strings header remains disabled
// - **GIVEN** 源码以配置宏判断 BSD 字符串头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_STRINGS_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_strings_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_strings_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_STRING_H`, `lib/socket.c:58`
// Spec: HAVE_STRING_H declares string header availability#string header capability is visible
// - **GIVEN** 源码以配置宏判断字符串头能力
// - **WHEN** 读取 `HAVE_STRING_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<string.h>` 可用
#[test]
fn test_config_xbox_360_string_header_capability_is_visible() {
    assert_eq!(XBOX_360_CONFIG.have_string_h, Some(1));
}

// Trace: `include/xbox 360/config.h:HAVE_SYS_ERRNO_H`, `configure.ac:HAVE_SYS_ERRNO_H`
// Spec: HAVE_SYS_ERRNO_H declares sys errno header absence#sys errno header remains disabled
// - **GIVEN** 源码以配置宏判断系统错误头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_SYS_ERRNO_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_sys_errno_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_sys_errno_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_SYS_FCNTL_H`, `configure.ac:HAVE_SYS_FCNTL_H`
// Spec: HAVE_SYS_FCNTL_H declares sys fcntl header absence#sys fcntl header remains disabled
// - **GIVEN** 源码以配置宏判断系统文件控制头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_SYS_FCNTL_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_sys_fcntl_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_sys_fcntl_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_SYS_IOCTL_H`, `configure.ac:HAVE_SYS_IOCTL_H`
// Spec: HAVE_SYS_IOCTL_H declares sys ioctl header absence#sys ioctl header remains disabled
// - **GIVEN** 源码以配置宏判断 ioctl 头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_SYS_IOCTL_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_sys_ioctl_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_sys_ioctl_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_SYS_POLL_H`, `configure.ac:HAVE_SYS_POLL_H`
// Spec: HAVE_SYS_POLL_H declares sys poll header absence#sys poll header remains disabled
// - **GIVEN** 源码以配置宏判断系统 poll 头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_SYS_POLL_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_sys_poll_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_sys_poll_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_SYS_SOCKET_H`, `configure.ac:HAVE_SYS_SOCKET_H`
// Spec: HAVE_SYS_SOCKET_H declares sys socket header absence#sys socket header remains disabled
// - **GIVEN** 源码以配置宏判断 socket API 头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_SYS_SOCKET_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_sys_socket_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_sys_socket_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_SYS_STAT_H`
// Spec: HAVE_SYS_STAT_H declares sys stat header availability#sys stat header capability is visible
// - **GIVEN** 源码以配置宏判断文件状态头能力
// - **WHEN** 读取 `HAVE_SYS_STAT_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<sys/stat.h>` 可用
#[test]
fn test_config_xbox_360_sys_stat_header_capability_is_visible() {
    assert_eq!(XBOX_360_CONFIG.have_sys_stat_h, Some(1));
}

// Trace: `include/xbox 360/config.h:HAVE_SYS_TIME_H`, `configure.ac:HAVE_SYS_TIME_H`
// Spec: HAVE_SYS_TIME_H declares sys time header absence#sys time header remains disabled
// - **GIVEN** 源码以配置宏判断系统时间头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_SYS_TIME_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_sys_time_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_sys_time_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_SYS_TYPES_H`, `lib/socket.c:66`
// Spec: HAVE_SYS_TYPES_H declares sys types header availability#sys types header capability is visible
// - **GIVEN** 源码以配置宏判断系统类型头能力
// - **WHEN** 读取 `HAVE_SYS_TYPES_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<sys/types.h>` 可用
#[test]
fn test_config_xbox_360_sys_types_header_capability_is_visible() {
    assert_eq!(XBOX_360_CONFIG.have_sys_types_h, Some(1));
}

// Trace: `include/xbox 360/config.h:HAVE_SYS_UIO_H`, `configure.ac:HAVE_SYS_UIO_H`
// Spec: HAVE_SYS_UIO_H declares sys uio header absence#sys uio header remains disabled
// - **GIVEN** 源码以配置宏判断 scatter/gather I/O 头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_SYS_UIO_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_sys_uio_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_sys_uio_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_SYS_UNISTD_H`, `configure.ac:HAVE_SYS_UNISTD_H`
// Spec: HAVE_SYS_UNISTD_H declares sys unistd header absence#sys unistd header remains disabled
// - **GIVEN** 源码以配置宏判断系统 POSIX 头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_SYS_UNISTD_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_sys_unistd_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_sys_unistd_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_SYS__IOVEC_H`, `configure.ac:HAVE_SYS__IOVEC_H`
// Spec: HAVE_SYS__IOVEC_H declares sys iovec header absence#sys iovec header remains disabled
// - **GIVEN** 源码以配置宏判断私有 iovec 头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_SYS__IOVEC_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_sys_iovec_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_sys_iovec_h, None);
}

// Trace: `include/xbox 360/config.h:HAVE_TIME_H`, `lib/timestamps.c:38`, `configure.ac:HAVE_TIME_H`
// Spec: HAVE_TIME_H declares time header availability#time header capability is visible
// - **GIVEN** 源码以配置宏判断标准时间头能力
// - **WHEN** 读取 `HAVE_TIME_H`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示 `<time.h>` 可用
#[test]
fn test_config_xbox_360_time_header_capability_is_visible() {
    assert_eq!(XBOX_360_CONFIG.have_time_h, Some(1));
}

// Trace: `include/xbox 360/config.h:HAVE_UNISTD_H`, `configure.ac:HAVE_UNISTD_H`
// Spec: HAVE_UNISTD_H declares unistd header absence#unistd header remains disabled
// - **GIVEN** 源码以配置宏判断 POSIX 头能力
// - **WHEN** 读取 Xbox 360 配置头中的 `HAVE_UNISTD_H`
// - **THEN** 该宏 SHALL 保持未定义状态
#[test]
fn test_config_xbox_360_unistd_header_remains_disabled() {
    assert_eq!(XBOX_360_CONFIG.have_unistd_h, None);
}

// Trace: `include/xbox 360/config.h:LT_OBJDIR`
// Spec: LT_OBJDIR exposes libtool object directory#libtool object directory metadata is readable
// - **GIVEN** 源码或诊断工具读取配置头元数据
// - **WHEN** 读取 `LT_OBJDIR`
// - **THEN** 该宏 SHALL 展开为字符串 `".libs/"`
#[test]
fn test_config_xbox_360_libtool_object_directory_metadata_is_readable() {
    assert_eq!(XBOX_360_CONFIG.lt_objdir, ".libs/");
}

// Trace: `include/xbox 360/config.h:PACKAGE`
// Spec: PACKAGE exposes package short name#package short name is readable
// - **GIVEN** 源码或诊断工具读取包元数据
// - **WHEN** 读取 `PACKAGE`
// - **THEN** 该宏 SHALL 展开为字符串 `"libsmb2"`
#[test]
fn test_config_xbox_360_package_short_name_is_readable() {
    assert_eq!(XBOX_360_CONFIG.package, "libsmb2");
}

// Trace: `include/xbox 360/config.h:PACKAGE_BUGREPORT`
// Spec: PACKAGE_BUGREPORT exposes bug report contact#bug report contact is readable
// - **GIVEN** 源码或诊断工具读取包元数据
// - **WHEN** 读取 `PACKAGE_BUGREPORT`
// - **THEN** 该宏 SHALL 展开为字符串 `"ronniesahlberg@gmail.com"`
#[test]
fn test_config_xbox_360_bug_report_contact_is_readable() {
    assert_eq!(
        XBOX_360_CONFIG.package_bugreport,
        "ronniesahlberg@gmail.com"
    );
}

// Trace: `include/xbox 360/config.h:PACKAGE_NAME`
// Spec: PACKAGE_NAME exposes package full name#package full name is readable
// - **GIVEN** 源码或诊断工具读取包元数据
// - **WHEN** 读取 `PACKAGE_NAME`
// - **THEN** 该宏 SHALL 展开为字符串 `"libsmb2"`
#[test]
fn test_config_xbox_360_package_full_name_is_readable() {
    assert_eq!(XBOX_360_CONFIG.package_name, "libsmb2");
}

// Trace: `include/xbox 360/config.h:PACKAGE_STRING`
// Spec: PACKAGE_STRING exposes package name and version#package string is readable
// - **GIVEN** 源码或诊断工具读取包元数据
// - **WHEN** 读取 `PACKAGE_STRING`
// - **THEN** 该宏 SHALL 展开为字符串 `"libsmb2 4.0.0"`
#[test]
fn test_config_xbox_360_package_string_is_readable() {
    assert_eq!(XBOX_360_CONFIG.package_string, "libsmb2 4.0.0");
}

// Trace: `include/xbox 360/config.h:PACKAGE_TARNAME`
// Spec: PACKAGE_TARNAME exposes distribution tar name#distribution tar name is readable
// - **GIVEN** 源码或诊断工具读取包元数据
// - **WHEN** 读取 `PACKAGE_TARNAME`
// - **THEN** 该宏 SHALL 展开为字符串 `"libsmb2"`
#[test]
fn test_config_xbox_360_distribution_tar_name_is_readable() {
    assert_eq!(XBOX_360_CONFIG.package_tarname, "libsmb2");
}

// Trace: `include/xbox 360/config.h:PACKAGE_URL`
// Spec: PACKAGE_URL exposes package URL string#package URL metadata is readable
// - **GIVEN** 源码或诊断工具读取包元数据
// - **WHEN** 读取 `PACKAGE_URL`
// - **THEN** 该宏 SHALL 展开为空字符串
#[test]
fn test_config_xbox_360_package_url_metadata_is_readable() {
    assert_eq!(XBOX_360_CONFIG.package_url, "");
}

// Trace: `include/xbox 360/config.h:PACKAGE_VERSION`
// Spec: PACKAGE_VERSION exposes Xbox 360 package version#package version is readable
// - **GIVEN** 源码或诊断工具读取包元数据
// - **WHEN** 读取 `PACKAGE_VERSION`
// - **THEN** 该宏 SHALL 展开为字符串 `"4.0.0"`
#[test]
fn test_config_xbox_360_package_version_is_readable() {
    assert_eq!(XBOX_360_CONFIG.package_version, "4.0.0");
}

// Trace: `include/xbox 360/config.h:STDC_HEADERS`, `lib/timestamps.c:46`, `lib/socket.c:18`
// Spec: STDC_HEADERS declares C90 standard header availability#standard header capability is visible
// - **GIVEN** 源码以配置宏判断 C90 标准头集合能力
// - **WHEN** 读取 `STDC_HEADERS`
// - **THEN** 该宏 SHALL 以定义值 `1` 表示标准头集合可用
#[test]
fn test_config_xbox_360_standard_header_capability_is_visible() {
    assert_eq!(XBOX_360_CONFIG.stdc_headers, Some(1));
}

// Trace: `include/xbox 360/config.h:VERSION`
// Spec: VERSION exposes Xbox 360 version string#version string is readable
// - **GIVEN** 源码或诊断工具读取版本元数据
// - **WHEN** 读取 `VERSION`
// - **THEN** 该宏 SHALL 展开为字符串 `"4.0.0"`
#[test]
fn test_config_xbox_360_version_string_is_readable() {
    assert_eq!(XBOX_360_CONFIG.version, "4.0.0");
}
