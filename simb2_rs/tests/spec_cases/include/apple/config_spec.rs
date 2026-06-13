use libsmb2_sys::include::config::APPLE_CONFIG;

// Trace: `include/apple/config.h:CONFIGURE_OPTION_TCP_LINGER`, `configure.ac:CONFIGURE_OPTION_TCP_LINGER`, `lib/socket.c:connect_async_ai`
// Spec: CONFIGURE_OPTION_TCP_LINGER Apple TCP linger option#Apple TCP linger is enabled
// - **GIVEN** 构建使用 `include/apple/config.h` 作为 `config.h` 配置来源
// - **WHEN** 源文件读取 `CONFIGURE_OPTION_TCP_LINGER`
// - **THEN** 预处理器得到数值 `1`，并且 `lib/socket.c` 中 `#if 0 == CONFIGURE_OPTION_TCP_LINGER` 的禁用 linger 分支不被选择
#[test]
fn test_config_apple_tcp_linger_is_enabled() {
    assert_eq!(APPLE_CONFIG.configure_option_tcp_linger, Some(1));
}

// Trace: `include/apple/config.h:HAVE_ARPA_INET_H`
// Spec: HAVE_ARPA_INET_H Apple arpa inet header availability#arpa inet header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_ARPA_INET_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择包含 `<arpa/inet.h>` 相关声明路径
#[test]
fn test_config_arpa_inet_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_arpa_inet_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_DLFCN_H`
// Spec: HAVE_DLFCN_H Apple dlfcn header availability#dlfcn header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_DLFCN_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择动态加载相关声明路径
#[test]
fn test_config_dlfcn_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_dlfcn_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_ERRNO_H`
// Spec: HAVE_ERRNO_H Apple errno header availability#errno header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_ERRNO_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择标准 errno 声明路径
#[test]
fn test_config_errno_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_errno_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_FCNTL_H`
// Spec: HAVE_FCNTL_H Apple fcntl header availability#fcntl header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_FCNTL_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择文件控制声明路径
#[test]
fn test_config_fcntl_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_fcntl_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_GSSAPI_GSSAPI_H`
// Spec: HAVE_GSSAPI_GSSAPI_H Apple GSSAPI header availability#GSSAPI header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_GSSAPI_GSSAPI_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择 GSSAPI 声明路径
#[test]
fn test_config_gssapi_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_gssapi_gssapi_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_INTTYPES_H`
// Spec: HAVE_INTTYPES_H Apple inttypes header availability#inttypes header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_INTTYPES_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择整数格式和类型声明路径
#[test]
fn test_config_inttypes_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_inttypes_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_LIBKRB5`, `configure.ac:HAVE_LIBKRB5`
// Spec: HAVE_LIBKRB5 Apple Kerberos library availability#Kerberos library is not configured
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_LIBKRB5` 是否定义
// - **THEN** 预处理器将该宏视为未定义，调用方不进入依赖该宏的 libkrb5 条件编译路径
#[test]
fn test_config_kerberos_library_is_not_configured() {
    assert_eq!(APPLE_CONFIG.have_libkrb5, None);
}

// Trace: `include/apple/config.h:HAVE_LIBNSL`
// Spec: HAVE_LIBNSL Apple nsl library availability#nsl library is not configured
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_LIBNSL` 是否定义
// - **THEN** 预处理器将该宏视为未定义
#[test]
fn test_config_nsl_library_is_not_configured() {
    assert_eq!(APPLE_CONFIG.have_libnsl, None);
}

// Trace: `include/apple/config.h:HAVE_LIBSOCKET`
// Spec: HAVE_LIBSOCKET Apple socket library availability#socket library is not configured
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_LIBSOCKET` 是否定义
// - **THEN** 预处理器将该宏视为未定义
#[test]
fn test_config_socket_library_is_not_configured() {
    assert_eq!(APPLE_CONFIG.have_libsocket, None);
}

// Trace: `include/apple/config.h:HAVE_LINGER`, `configure.ac:HAVE_LINGER`
// Spec: HAVE_LINGER Apple linger structure availability#linger structure is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** socket 相关源码检查 `HAVE_LINGER`
// - **THEN** 预处理器得到数值 `1`，调用方可使用 linger 结构相关声明
#[test]
fn test_config_linger_structure_is_available() {
    assert_eq!(APPLE_CONFIG.have_linger, Some(1));
}

// Trace: `include/apple/config.h:HAVE_NETDB_H`
// Spec: HAVE_NETDB_H Apple netdb header availability#netdb header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_NETDB_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择网络数据库声明路径
#[test]
fn test_config_netdb_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_netdb_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_NETINET_IN_H`
// Spec: HAVE_NETINET_IN_H Apple netinet in header availability#netinet in header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_NETINET_IN_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择 IP socket 结构声明路径
#[test]
fn test_config_netinet_in_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_netinet_in_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_NETINET_TCP_H`
// Spec: HAVE_NETINET_TCP_H Apple netinet tcp header availability#netinet tcp header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_NETINET_TCP_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择 TCP 选项声明路径
#[test]
fn test_config_netinet_tcp_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_netinet_tcp_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_POLL_H`
// Spec: HAVE_POLL_H Apple poll header availability#poll header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_POLL_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择 poll 声明路径
#[test]
fn test_config_poll_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_poll_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_SOCKADDR_LEN`, `configure.ac:HAVE_SOCKADDR_LEN`
// Spec: HAVE_SOCKADDR_LEN Apple sockaddr length member availability#sockaddr length member is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** socket 地址布局代码检查 `HAVE_SOCKADDR_LEN`
// - **THEN** 预处理器得到数值 `1`，调用方可按存在 `sa_len` 成员的地址结构布局处理
#[test]
fn test_config_sockaddr_length_member_is_available() {
    assert_eq!(APPLE_CONFIG.have_sockaddr_len, Some(1));
}

// Trace: `include/apple/config.h:HAVE_SOCKADDR_STORAGE`, `configure.ac:HAVE_SOCKADDR_STORAGE`
// Spec: HAVE_SOCKADDR_STORAGE Apple sockaddr storage availability#sockaddr storage is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** socket 地址存储代码检查 `HAVE_SOCKADDR_STORAGE`
// - **THEN** 预处理器得到数值 `1`，调用方可使用泛型 socket 地址存储结构
#[test]
fn test_config_sockaddr_storage_is_available() {
    assert_eq!(APPLE_CONFIG.have_sockaddr_storage, Some(1));
}

// Trace: `include/apple/config.h:HAVE_STDINT_H`
// Spec: HAVE_STDINT_H Apple stdint header availability#stdint header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_STDINT_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择固定宽度整数声明路径
#[test]
fn test_config_stdint_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_stdint_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_STDIO_H`
// Spec: HAVE_STDIO_H Apple stdio header availability#stdio header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_STDIO_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择标准 I/O 声明路径
#[test]
fn test_config_stdio_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_stdio_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_STDLIB_H`
// Spec: HAVE_STDLIB_H Apple stdlib header availability#stdlib header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_STDLIB_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择标准库声明路径
#[test]
fn test_config_stdlib_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_stdlib_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_STRINGS_H`
// Spec: HAVE_STRINGS_H Apple strings header availability#strings header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_STRINGS_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择 BSD 字符串声明路径
#[test]
fn test_config_strings_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_strings_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_STRING_H`
// Spec: HAVE_STRING_H Apple string header availability#string header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_STRING_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择 C 字符串声明路径
#[test]
fn test_config_string_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_string_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_SYS_ERRNO_H`
// Spec: HAVE_SYS_ERRNO_H Apple sys errno header availability#sys errno header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_SYS_ERRNO_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择系统 errno 声明路径
#[test]
fn test_config_sys_errno_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_sys_errno_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_SYS_FCNTL_H`
// Spec: HAVE_SYS_FCNTL_H Apple sys fcntl header availability#sys fcntl header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_SYS_FCNTL_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择系统文件控制声明路径
#[test]
fn test_config_sys_fcntl_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_sys_fcntl_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_SYS_IOCTL_H`
// Spec: HAVE_SYS_IOCTL_H Apple sys ioctl header availability#sys ioctl header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_SYS_IOCTL_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择系统 ioctl 声明路径
#[test]
fn test_config_sys_ioctl_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_sys_ioctl_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_SYS_POLL_H`
// Spec: HAVE_SYS_POLL_H Apple sys poll header availability#sys poll header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_SYS_POLL_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择系统 poll 声明路径
#[test]
fn test_config_sys_poll_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_sys_poll_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_SYS_SOCKET_H`
// Spec: HAVE_SYS_SOCKET_H Apple sys socket header availability#sys socket header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_SYS_SOCKET_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择 socket API 声明路径
#[test]
fn test_config_sys_socket_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_sys_socket_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_SYS_STAT_H`
// Spec: HAVE_SYS_STAT_H Apple sys stat header availability#sys stat header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_SYS_STAT_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择文件状态声明路径
#[test]
fn test_config_sys_stat_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_sys_stat_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_SYS_TIME_H`
// Spec: HAVE_SYS_TIME_H Apple sys time header availability#sys time header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_SYS_TIME_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择系统时间声明路径
#[test]
fn test_config_sys_time_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_sys_time_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_SYS_TYPES_H`
// Spec: HAVE_SYS_TYPES_H Apple sys types header availability#sys types header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_SYS_TYPES_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择系统基础类型声明路径
#[test]
fn test_config_sys_types_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_sys_types_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_SYS_UIO_H`
// Spec: HAVE_SYS_UIO_H Apple sys uio header availability#sys uio header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_SYS_UIO_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择 scatter/gather I/O 声明路径
#[test]
fn test_config_sys_uio_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_sys_uio_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_SYS_UNISTD_H`
// Spec: HAVE_SYS_UNISTD_H Apple sys unistd header availability#sys unistd header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_SYS_UNISTD_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择系统 POSIX 声明路径
#[test]
fn test_config_sys_unistd_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_sys_unistd_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_SYS__IOVEC_H`
// Spec: HAVE_SYS__IOVEC_H Apple private iovec header availability#private iovec header is not configured
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_SYS__IOVEC_H` 是否定义
// - **THEN** 预处理器将该宏视为未定义
#[test]
fn test_config_private_iovec_header_is_not_configured() {
    assert_eq!(APPLE_CONFIG.have_sys_iovec_h, None);
}

// Trace: `include/apple/config.h:HAVE_TIME_H`
// Spec: HAVE_TIME_H Apple time header availability#time header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_TIME_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择标准时间声明路径
#[test]
fn test_config_time_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_time_h, Some(1));
}

// Trace: `include/apple/config.h:HAVE_UNISTD_H`
// Spec: HAVE_UNISTD_H Apple unistd header availability#unistd header is available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `HAVE_UNISTD_H`
// - **THEN** 预处理器得到数值 `1`，调用方可选择 POSIX 声明路径
#[test]
fn test_config_unistd_header_is_available() {
    assert_eq!(APPLE_CONFIG.have_unistd_h, Some(1));
}

// Trace: `include/apple/config.h:LT_OBJDIR`
// Spec: LT_OBJDIR Apple libtool object directory#libtool object directory is exposed
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件或构建辅助代码读取 `LT_OBJDIR`
// - **THEN** 预处理器得到字符串 `".libs/"`
#[test]
fn test_config_libtool_object_directory_is_exposed() {
    assert_eq!(APPLE_CONFIG.lt_objdir, ".libs/");
}

// Trace: `include/apple/config.h:PACKAGE`
// Spec: PACKAGE Apple package short name#package short name is exposed
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件读取 `PACKAGE`
// - **THEN** 预处理器得到字符串 `"libsmb2"`
#[test]
fn test_config_package_short_name_is_exposed() {
    assert_eq!(APPLE_CONFIG.package, "libsmb2");
}

// Trace: `include/apple/config.h:PACKAGE_BUGREPORT`
// Spec: PACKAGE_BUGREPORT Apple package bug report address#package bug report address is exposed
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件读取 `PACKAGE_BUGREPORT`
// - **THEN** 预处理器得到字符串 `"ronniesahlberg@gmail.com"`
#[test]
fn test_config_package_bug_report_address_is_exposed() {
    assert_eq!(APPLE_CONFIG.package_bugreport, "ronniesahlberg@gmail.com");
}

// Trace: `include/apple/config.h:PACKAGE_NAME`
// Spec: PACKAGE_NAME Apple package full name#package full name is exposed
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件读取 `PACKAGE_NAME`
// - **THEN** 预处理器得到字符串 `"libsmb2"`
#[test]
fn test_config_package_full_name_is_exposed() {
    assert_eq!(APPLE_CONFIG.package_name, "libsmb2");
}

// Trace: `include/apple/config.h:PACKAGE_STRING`
// Spec: PACKAGE_STRING Apple package name and version#package string is exposed
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件读取 `PACKAGE_STRING`
// - **THEN** 预处理器得到字符串 `"libsmb2 4.0.0"`
#[test]
fn test_config_package_string_is_exposed() {
    assert_eq!(APPLE_CONFIG.package_string, "libsmb2 4.0.0");
}

// Trace: `include/apple/config.h:PACKAGE_TARNAME`
// Spec: PACKAGE_TARNAME Apple package tar name#package tar name is exposed
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件读取 `PACKAGE_TARNAME`
// - **THEN** 预处理器得到字符串 `"libsmb2"`
#[test]
fn test_config_package_tar_name_is_exposed() {
    assert_eq!(APPLE_CONFIG.package_tarname, "libsmb2");
}

// Trace: `include/apple/config.h:PACKAGE_URL`
// Spec: PACKAGE_URL Apple package URL#package URL is empty
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件读取 `PACKAGE_URL`
// - **THEN** 预处理器得到空字符串 `""`
#[test]
fn test_config_package_url_is_empty() {
    assert_eq!(APPLE_CONFIG.package_url, "");
}

// Trace: `include/apple/config.h:PACKAGE_VERSION`
// Spec: PACKAGE_VERSION Apple package version#package version is exposed
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件读取 `PACKAGE_VERSION`
// - **THEN** 预处理器得到字符串 `"4.0.0"`
#[test]
fn test_config_package_version_is_exposed() {
    assert_eq!(APPLE_CONFIG.package_version, "4.0.0");
}

// Trace: `include/apple/config.h:STDC_HEADERS`
// Spec: STDC_HEADERS Apple C90 standard headers availability#C90 standard headers are available
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件检查 `STDC_HEADERS`
// - **THEN** 预处理器得到数值 `1`，调用方可选择标准头兼容路径
#[test]
fn test_config_c90_standard_headers_are_available() {
    assert_eq!(APPLE_CONFIG.stdc_headers, Some(1));
}

// Trace: `include/apple/config.h:VERSION`
// Spec: VERSION Apple package version alias#version alias is exposed
// - **GIVEN** 构建使用 Apple 配置头
// - **WHEN** 源文件读取 `VERSION`
// - **THEN** 预处理器得到字符串 `"4.0.0"`
#[test]
fn test_config_version_alias_is_exposed() {
    assert_eq!(APPLE_CONFIG.version, "4.0.0");
}
