use libsmb2_rs::include::config::AMIGA_OS_CONFIG;

// Trace: `include/amiga_os/config.h:CONFIGURE_OPTION_TCP_LINGER`, `lib/socket.c:connect_async_ai`
// Spec: CONFIGURE_OPTION_TCP_LINGER TCP linger 编译配置#Amiga OS 构建读取 TCP linger 配置
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码以 `CONFIGURE_OPTION_TCP_LINGER` 计算 TCP socket linger 条件编译分支
// - **THEN** 预处理器应观察到该宏值为 `1`，并且 `lib/socket.c` 中 `#if 0 == CONFIGURE_OPTION_TCP_LINGER` 的禁用 linger 分支不应被该配置启用
#[test]
fn test_config_amiga_os_tcp_linger() {
    assert_eq!(AMIGA_OS_CONFIG.configure_option_tcp_linger, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_ARPA_INET_H`, `lib/socket.c:HAVE_ARPA_INET_H`
// Spec: HAVE_ARPA_INET_H arpa inet 头文件能力#条件包含 arpa inet 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_ARPA_INET_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_arpa_inet() {
    assert_eq!(AMIGA_OS_CONFIG.have_arpa_inet_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_DLFCN_H`
// Spec: HAVE_DLFCN_H dlfcn 头文件能力#条件检查 dlfcn 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_DLFCN_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_dlfcn_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_dlfcn_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_ERRNO_H`, `lib/spnego-wrapper.c:HAVE_ERRNO_H`
// Spec: HAVE_ERRNO_H errno 头文件能力#条件检查 errno 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_ERRNO_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_errno_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_errno_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_FCNTL_H`, `lib/socket.c:HAVE_FCNTL_H`
// Spec: HAVE_FCNTL_H fcntl 头文件能力#条件包含 fcntl 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_FCNTL_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_fcntl_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_fcntl_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_GSSAPI_GSSAPI_H`
// Spec: HAVE_GSSAPI_GSSAPI_H GSSAPI 头文件禁用配置#条件检查 GSSAPI 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_GSSAPI_GSSAPI_H`
// - **THEN** 预处理器应观察到该宏未定义
#[test]
fn test_config_amiga_os_have_gssapi_gssapi_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_gssapi_gssapi_h, None);
}

// Trace: `include/amiga_os/config.h:HAVE_INTTYPES_H`
// Spec: HAVE_INTTYPES_H inttypes 头文件能力#条件检查 inttypes 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_INTTYPES_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_inttypes_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_inttypes_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_LIBKRB5`, `lib/spnego-wrapper.c:HAVE_LIBKRB5`
// Spec: HAVE_LIBKRB5 krb5 库禁用配置#条件检查 krb5 库支持
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_LIBKRB5`
// - **THEN** 预处理器应观察到该宏未定义，并且 Kerberos 相关条件实现不由该配置启用
#[test]
fn test_config_amiga_os_have_libkrb5() {
    assert_eq!(AMIGA_OS_CONFIG.have_libkrb5, None);
}

// Trace: `include/amiga_os/config.h:HAVE_LIBNSL`
// Spec: HAVE_LIBNSL nsl 库禁用配置#条件检查 nsl 库支持
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_LIBNSL`
// - **THEN** 预处理器应观察到该宏未定义
#[test]
fn test_config_amiga_os_have_libnsl() {
    assert_eq!(AMIGA_OS_CONFIG.have_libnsl, None);
}

// Trace: `include/amiga_os/config.h:HAVE_LIBSOCKET`
// Spec: HAVE_LIBSOCKET socket 库禁用配置#条件检查 socket 库支持
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_LIBSOCKET`
// - **THEN** 预处理器应观察到该宏未定义
#[test]
fn test_config_amiga_os_have_libsocket() {
    assert_eq!(AMIGA_OS_CONFIG.have_libsocket, None);
}

// Trace: `include/amiga_os/config.h:HAVE_LINGER`, `lib/socket.c:HAVE_LINGER`
// Spec: HAVE_LINGER linger 类型禁用配置#socket 代码选择本地 linger 定义
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** `lib/socket.c` 检查 `#if !defined(HAVE_LINGER)`
// - **THEN** 预处理器应进入本地 `struct linger` 定义分支
#[test]
fn test_config_amiga_os_have_linger() {
    assert_eq!(AMIGA_OS_CONFIG.have_linger, None);
}

// Trace: `include/amiga_os/config.h:HAVE_NETDB_H`, `lib/socket.c:HAVE_NETDB_H`
// Spec: HAVE_NETDB_H netdb 头文件能力#条件包含 netdb 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_NETDB_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_netdb_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_netdb_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_NETINET_IN_H`, `lib/socket.c:HAVE_NETINET_IN_H`
// Spec: HAVE_NETINET_IN_H netinet in 头文件能力#条件包含 netinet in 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_NETINET_IN_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_netinet_in_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_netinet_in_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_NETINET_TCP_H`, `lib/socket.c:HAVE_NETINET_TCP_H`
// Spec: HAVE_NETINET_TCP_H netinet tcp 头文件能力#条件包含 netinet tcp 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_NETINET_TCP_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_netinet_tcp_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_netinet_tcp_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_POLL_H`, `lib/socket.c:HAVE_POLL_H`
// Spec: HAVE_POLL_H poll 头文件禁用配置#条件检查 poll 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_POLL_H`
// - **THEN** 预处理器应观察到该宏未定义
#[test]
fn test_config_amiga_os_have_poll_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_poll_h, None);
}

// Trace: `include/amiga_os/config.h:HAVE_SOCKADDR_LEN`
// Spec: HAVE_SOCKADDR_LEN sockaddr sa_len 结构能力#条件检查 sockaddr 长度成员
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_SOCKADDR_LEN`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_sockaddr_len() {
    assert_eq!(AMIGA_OS_CONFIG.have_sockaddr_len, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_SOCKADDR_STORAGE`
// Spec: HAVE_SOCKADDR_STORAGE sockaddr_storage 禁用配置#条件检查 sockaddr_storage 能力
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_SOCKADDR_STORAGE`
// - **THEN** 预处理器应观察到该宏未定义
#[test]
fn test_config_amiga_os_have_sockaddr_storage() {
    assert_eq!(AMIGA_OS_CONFIG.have_sockaddr_storage, None);
}

// Trace: `include/amiga_os/config.h:HAVE_STDINT_H`, `lib/socket.c:HAVE_STDINT_H`
// Spec: HAVE_STDINT_H stdint 头文件能力#条件包含 stdint 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_STDINT_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_stdint_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_stdint_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_STDIO_H`, `lib/socket.c:HAVE_STDIO_H`
// Spec: HAVE_STDIO_H stdio 头文件能力#条件包含 stdio 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_STDIO_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_stdio_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_stdio_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_STDLIB_H`, `lib/socket.c:HAVE_STDLIB_H`
// Spec: HAVE_STDLIB_H stdlib 头文件能力#条件包含 stdlib 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_STDLIB_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_stdlib_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_stdlib_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_STRINGS_H`
// Spec: HAVE_STRINGS_H strings 头文件能力#条件检查 strings 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_STRINGS_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_strings_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_strings_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_STRING_H`, `lib/socket.c:HAVE_STRING_H`
// Spec: HAVE_STRING_H string 头文件能力#条件包含 string 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_STRING_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_string_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_string_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_SYS_ERRNO_H`
// Spec: HAVE_SYS_ERRNO_H sys errno 头文件能力#条件检查 sys errno 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_ERRNO_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_sys_errno_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_sys_errno_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_SYS_FCNTL_H`, `lib/socket.c:HAVE_SYS_FCNTL_H`
// Spec: HAVE_SYS_FCNTL_H sys fcntl 头文件能力#条件包含 sys fcntl 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_FCNTL_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_sys_fcntl_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_sys_fcntl_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_SYS_IOCTL_H`, `lib/socket.c:HAVE_SYS_IOCTL_H`
// Spec: HAVE_SYS_IOCTL_H sys ioctl 头文件能力#条件包含 sys ioctl 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_IOCTL_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_sys_ioctl_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_sys_ioctl_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_SYS_POLL_H`, `lib/socket.c:HAVE_SYS_POLL_H`
// Spec: HAVE_SYS_POLL_H sys poll 头文件禁用配置#条件检查 sys poll 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_POLL_H`
// - **THEN** 预处理器应观察到该宏未定义
#[test]
fn test_config_amiga_os_have_sys_poll_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_sys_poll_h, None);
}

// Trace: `include/amiga_os/config.h:HAVE_SYS_SOCKET_H`, `lib/socket.c:HAVE_SYS_SOCKET_H`
// Spec: HAVE_SYS_SOCKET_H sys socket 头文件能力#条件包含 sys socket 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_SOCKET_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_sys_socket_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_sys_socket_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_SYS_STAT_H`, `lib/spnego-wrapper.c:HAVE_SYS_STAT_H`
// Spec: HAVE_SYS_STAT_H sys stat 头文件能力#条件检查 sys stat 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_STAT_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_sys_stat_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_sys_stat_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_SYS_TIME_H`, `lib/socket.c:HAVE_SYS_TIME_H`
// Spec: HAVE_SYS_TIME_H sys time 头文件能力#条件检查 sys time 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_TIME_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_sys_time_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_sys_time_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_SYS_TYPES_H`, `lib/socket.c:HAVE_SYS_TYPES_H`
// Spec: HAVE_SYS_TYPES_H sys types 头文件能力#条件检查 sys types 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_TYPES_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_sys_types_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_sys_types_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_SYS_UIO_H`, `lib/socket.c:HAVE_SYS_UIO_H`
// Spec: HAVE_SYS_UIO_H sys uio 头文件能力#条件包含 sys uio 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_UIO_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_sys_uio_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_sys_uio_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_SYS_UNISTD_H`, `lib/socket.c:HAVE_SYS_UNISTD_H`
// Spec: HAVE_SYS_UNISTD_H sys unistd 头文件能力#条件包含 sys unistd 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_SYS_UNISTD_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_sys_unistd_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_sys_unistd_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_SYS__IOVEC_H`, `lib/socket.c:HAVE_SYS__IOVEC_H`
// Spec: HAVE_SYS__IOVEC_H sys _iovec 头文件禁用配置#条件检查 sys _iovec 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_SYS__IOVEC_H`
// - **THEN** 预处理器应观察到该宏未定义
#[test]
fn test_config_amiga_os_have_sys_iovec_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_sys_iovec_h, None);
}

// Trace: `include/amiga_os/config.h:HAVE_TIME_H`, `lib/socket.c:HAVE_TIME_H`
// Spec: HAVE_TIME_H time 头文件能力#条件检查 time 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_TIME_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_time_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_time_h, Some(1));
}

// Trace: `include/amiga_os/config.h:HAVE_UNISTD_H`, `lib/socket.c:HAVE_UNISTD_H`
// Spec: HAVE_UNISTD_H unistd 头文件能力#条件包含 unistd 头文件
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `HAVE_UNISTD_H`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_have_unistd_h() {
    assert_eq!(AMIGA_OS_CONFIG.have_unistd_h, Some(1));
}

// Trace: `include/amiga_os/config.h:LT_OBJDIR`
// Spec: LT_OBJDIR libtool 对象目录#读取 libtool 对象目录配置
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码或构建辅助逻辑读取 `LT_OBJDIR`
// - **THEN** 预处理器应观察到该宏值为字符串 `".libs/"`
#[test]
fn test_config_amiga_os_lt_objdir() {
    assert_eq!(AMIGA_OS_CONFIG.lt_objdir, ".libs/");
}

// Trace: `include/amiga_os/config.h:PACKAGE`
// Spec: PACKAGE 包短名元数据#读取包短名
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码读取 `PACKAGE`
// - **THEN** 预处理器应观察到该宏值为字符串 `"libsmb2"`
#[test]
fn test_config_amiga_os_package() {
    assert_eq!(AMIGA_OS_CONFIG.package, "libsmb2");
}

// Trace: `include/amiga_os/config.h:PACKAGE_BUGREPORT`
// Spec: PACKAGE_BUGREPORT 包问题报告地址#读取包问题报告地址
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码读取 `PACKAGE_BUGREPORT`
// - **THEN** 预处理器应观察到该宏值为字符串 `"ronniesahlberg@gmail.com"`
#[test]
fn test_config_amiga_os_package_bugreport() {
    assert_eq!(
        AMIGA_OS_CONFIG.package_bugreport,
        "ronniesahlberg@gmail.com"
    );
}

// Trace: `include/amiga_os/config.h:PACKAGE_NAME`
// Spec: PACKAGE_NAME 包全名元数据#读取包全名
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码读取 `PACKAGE_NAME`
// - **THEN** 预处理器应观察到该宏值为字符串 `"libsmb2"`
#[test]
fn test_config_amiga_os_package_name() {
    assert_eq!(AMIGA_OS_CONFIG.package_name, "libsmb2");
}

// Trace: `include/amiga_os/config.h:PACKAGE_STRING`
// Spec: PACKAGE_STRING 包名版本组合元数据#读取包名版本组合
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码读取 `PACKAGE_STRING`
// - **THEN** 预处理器应观察到该宏值为字符串 `"libsmb2 4.0.0"`
#[test]
fn test_config_amiga_os_package_string() {
    assert_eq!(AMIGA_OS_CONFIG.package_string, "libsmb2 4.0.0");
}

// Trace: `include/amiga_os/config.h:PACKAGE_TARNAME`
// Spec: PACKAGE_TARNAME 包 tar 名称元数据#读取包 tar 名称
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码读取 `PACKAGE_TARNAME`
// - **THEN** 预处理器应观察到该宏值为字符串 `"libsmb2"`
#[test]
fn test_config_amiga_os_package_tarname() {
    assert_eq!(AMIGA_OS_CONFIG.package_tarname, "libsmb2");
}

// Trace: `include/amiga_os/config.h:PACKAGE_URL`
// Spec: PACKAGE_URL 包主页元数据#读取包主页
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码读取 `PACKAGE_URL`
// - **THEN** 预处理器应观察到该宏值为空字符串
#[test]
fn test_config_amiga_os_package_url() {
    assert_eq!(AMIGA_OS_CONFIG.package_url, "");
}

// Trace: `include/amiga_os/config.h:PACKAGE_VERSION`
// Spec: PACKAGE_VERSION 包版本元数据#读取包版本
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码读取 `PACKAGE_VERSION`
// - **THEN** 预处理器应观察到该宏值为字符串 `"4.0.0"`
#[test]
fn test_config_amiga_os_package_version() {
    assert_eq!(AMIGA_OS_CONFIG.package_version, "4.0.0");
}

// Trace: `include/amiga_os/config.h:STDC_HEADERS`, `lib/spnego-wrapper.c:STDC_HEADERS`
// Spec: STDC_HEADERS C90 标准头集合能力#条件检查 C90 标准头集合
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码检查 `STDC_HEADERS`
// - **THEN** 预处理器应观察到该宏已定义为 `1`
#[test]
fn test_config_amiga_os_stdc_headers() {
    assert_eq!(AMIGA_OS_CONFIG.stdc_headers, Some(1));
}

// Trace: `include/amiga_os/config.h:VERSION`
// Spec: VERSION 包版本号元数据#读取包版本号
// - **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
// - **WHEN** 源码读取 `VERSION`
// - **THEN** 预处理器应观察到该宏值为字符串 `"4.0.0"`
#[test]
fn test_config_amiga_os_version() {
    assert_eq!(AMIGA_OS_CONFIG.version, "4.0.0");
}
