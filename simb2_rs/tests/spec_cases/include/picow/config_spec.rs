use libsmb2_sys::include::config::PICOW_CONFIG;

// Trace: `include/picow/config.h:CONFIGURE_OPTION_TCP_LINGER`, `CMakeLists.txt:PICO_BOARD`, `lib/socket.c:CONFIGURE_OPTION_TCP_LINGER`
// Spec: CONFIGURE_OPTION_TCP_LINGER expose PICO TCP linger policy#PICO 配置启用 TCP linger
// - **GIVEN** PICO 构建通过 `CMakeLists.txt` 将 `include/picow` 加入 include 路径
// - **WHEN** 源码包含 `config.h` 并读取 `CONFIGURE_OPTION_TCP_LINGER`
// - **THEN** 预处理器得到数值 `1`，`lib/socket.c` 中依赖该宏的 `#if 0 == CONFIGURE_OPTION_TCP_LINGER` 分支不会代表该配置的关闭策略
#[test]
fn test_config_pico_tcp_linger() {
    assert_eq!(PICOW_CONFIG.configure_option_tcp_linger, Some(1));
}

// Trace: `include/picow/config.h:HAVE_DLFCN_H`
// Spec: HAVE_DLFCN_H expose dlfcn header availability#PICO 配置声明 dlfcn 可用
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器检查 `HAVE_DLFCN_H`
// - **THEN** 该宏以数值 `1` 存在，调用方可将 `<dlfcn.h>` 视为当前配置声明的可用头文件
#[test]
fn test_config_pico_dlfcn() {
    assert_eq!(PICOW_CONFIG.have_dlfcn_h, Some(1));
}

// Trace: `include/picow/config.h:HAVE_FCNTL_H`
// Spec: HAVE_FCNTL_H expose fcntl header availability#PICO 配置声明 fcntl 可用
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器检查 `HAVE_FCNTL_H`
// - **THEN** 该宏以数值 `1` 存在，调用方可将 `<fcntl.h>` 视为当前配置声明的可用头文件
#[test]
fn test_config_pico_fcntl() {
    assert_eq!(PICOW_CONFIG.have_fcntl_h, Some(1));
}

// Trace: `include/picow/config.h:HAVE_SOCKADDR_STORAGE`, `configure.ac:HAVE_SOCKADDR_STORAGE`
// Spec: HAVE_SOCKADDR_STORAGE expose sockaddr_storage availability#PICO 配置声明 sockaddr_storage 可用
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器检查 `HAVE_SOCKADDR_STORAGE`
// - **THEN** 该宏以数值 `1` 存在，调用方可将 `sockaddr_storage` 视为当前配置声明的可用结构能力
#[test]
fn test_config_pico_sockaddr_storage() {
    assert_eq!(PICOW_CONFIG.have_sockaddr_storage, Some(1));
}

// Trace: `include/picow/config.h:HAVE_STDINT_H`
// Spec: HAVE_STDINT_H expose stdint header availability#PICO 配置声明 stdint 可用
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器检查 `HAVE_STDINT_H`
// - **THEN** 该宏以数值 `1` 存在，调用方可将 `<stdint.h>` 视为当前配置声明的可用头文件
#[test]
fn test_config_pico_stdint() {
    assert_eq!(PICOW_CONFIG.have_stdint_h, Some(1));
}

// Trace: `include/picow/config.h:HAVE_STDIO_H`
// Spec: HAVE_STDIO_H expose stdio header availability#PICO 配置声明 stdio 可用
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器检查 `HAVE_STDIO_H`
// - **THEN** 该宏以数值 `1` 存在，调用方可将 `<stdio.h>` 视为当前配置声明的可用头文件
#[test]
fn test_config_pico_stdio() {
    assert_eq!(PICOW_CONFIG.have_stdio_h, Some(1));
}

// Trace: `include/picow/config.h:HAVE_STDLIB_H`
// Spec: HAVE_STDLIB_H expose stdlib header availability#PICO 配置声明 stdlib 可用
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器检查 `HAVE_STDLIB_H`
// - **THEN** 该宏以数值 `1` 存在，调用方可将 `<stdlib.h>` 视为当前配置声明的可用头文件
#[test]
fn test_config_pico_stdlib() {
    assert_eq!(PICOW_CONFIG.have_stdlib_h, Some(1));
}

// Trace: `include/picow/config.h:HAVE_SYS_STAT_H`
// Spec: HAVE_SYS_STAT_H expose sys/stat header availability#PICO 配置声明 sys/stat 可用
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器检查 `HAVE_SYS_STAT_H`
// - **THEN** 该宏以数值 `1` 存在，调用方可将 `<sys/stat.h>` 视为当前配置声明的可用头文件
#[test]
fn test_config_pico_sys_stat() {
    assert_eq!(PICOW_CONFIG.have_sys_stat_h, Some(1));
}

// Trace: `include/picow/config.h:HAVE_SYS_TYPES_H`
// Spec: HAVE_SYS_TYPES_H expose sys/types header availability#PICO 配置声明 sys/types 可用
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器检查 `HAVE_SYS_TYPES_H`
// - **THEN** 该宏以数值 `1` 存在，调用方可将 `<sys/types.h>` 视为当前配置声明的可用头文件
#[test]
fn test_config_pico_sys_types() {
    assert_eq!(PICOW_CONFIG.have_sys_types_h, Some(1));
}

// Trace: `include/picow/config.h:HAVE_TIME_H`
// Spec: HAVE_TIME_H expose time header availability#PICO 配置声明 time 可用
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器检查 `HAVE_TIME_H`
// - **THEN** 该宏以数值 `1` 存在，调用方可将 `<time.h>` 视为当前配置声明的可用头文件
#[test]
fn test_config_pico_time() {
    assert_eq!(PICOW_CONFIG.have_time_h, Some(1));
}

// Trace: `include/picow/config.h:HAVE_UNISTD_H`
// Spec: HAVE_UNISTD_H expose unistd header availability#PICO 配置声明 unistd 可用
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器检查 `HAVE_UNISTD_H`
// - **THEN** 该宏以数值 `1` 存在，调用方可将 `<unistd.h>` 视为当前配置声明的可用头文件
#[test]
fn test_config_pico_unistd() {
    assert_eq!(PICOW_CONFIG.have_unistd_h, Some(1));
}

// Trace: `include/picow/config.h:LT_OBJDIR`
// Spec: LT_OBJDIR expose libtool object directory#PICO 配置声明 libtool 目录
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器展开 `LT_OBJDIR`
// - **THEN** 展开结果为字符串 `".libs/"`
#[test]
fn test_config_pico_libtool() {
    assert_eq!(PICOW_CONFIG.lt_objdir, ".libs/");
}

// Trace: `include/picow/config.h:PACKAGE`
// Spec: PACKAGE expose package short name#PICO 配置声明包短名
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器展开 `PACKAGE`
// - **THEN** 展开结果为字符串 `"libsmb2"`
#[test]
fn test_config_pico() {
    assert_eq!(PICOW_CONFIG.package, "libsmb2");
}

// Trace: `include/picow/config.h:PACKAGE_BUGREPORT`
// Spec: PACKAGE_BUGREPORT expose bug report address#PICO 配置声明 bug report 地址
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器展开 `PACKAGE_BUGREPORT`
// - **THEN** 展开结果为字符串 `"ronniesahlberg@gmail.com"`
#[test]
fn test_config_pico_bug_report() {
    assert_eq!(PICOW_CONFIG.package_bugreport, "ronniesahlberg@gmail.com");
}

// Trace: `include/picow/config.h:PACKAGE_NAME`
// Spec: PACKAGE_NAME expose package full name#PICO 配置声明包全名
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器展开 `PACKAGE_NAME`
// - **THEN** 展开结果为字符串 `"libsmb2"`
#[test]
fn test_config_pico_2() {
    assert_eq!(PICOW_CONFIG.package_name, "libsmb2");
}

// Trace: `include/picow/config.h:PACKAGE_STRING`
// Spec: PACKAGE_STRING expose package name and version#PICO 配置声明包组合字符串
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器展开 `PACKAGE_STRING`
// - **THEN** 展开结果为字符串 `"libsmb2 4.0.0"`
#[test]
fn test_config_pico_3() {
    assert_eq!(PICOW_CONFIG.package_string, "libsmb2 4.0.0");
}

// Trace: `include/picow/config.h:PACKAGE_TARNAME`
// Spec: PACKAGE_TARNAME expose tar package name#PICO 配置声明 tar 包名
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器展开 `PACKAGE_TARNAME`
// - **THEN** 展开结果为字符串 `"libsmb2"`
#[test]
fn test_config_pico_tar() {
    assert_eq!(PICOW_CONFIG.package_tarname, "libsmb2");
}

// Trace: `include/picow/config.h:PACKAGE_URL`
// Spec: PACKAGE_URL expose package URL value#PICO 配置声明空 URL
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器展开 `PACKAGE_URL`
// - **THEN** 展开结果为空字符串 `""`
#[test]
fn test_config_pico_url() {
    assert_eq!(PICOW_CONFIG.package_url, "");
}

// Trace: `include/picow/config.h:PACKAGE_VERSION`
// Spec: PACKAGE_VERSION expose package version#PICO 配置声明包版本
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器展开 `PACKAGE_VERSION`
// - **THEN** 展开结果为字符串 `"4.0.0"`
#[test]
fn test_config_pico_4() {
    assert_eq!(PICOW_CONFIG.package_version, "4.0.0");
}

// Trace: `include/picow/config.h:STDC_HEADERS`
// Spec: STDC_HEADERS expose C90 standard header set availability#PICO 配置声明标准头集合可用
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器检查 `STDC_HEADERS`
// - **THEN** 该宏以数值 `1` 存在，调用方可将 C90 标准头文件集合视为当前配置声明的可用能力
#[test]
fn test_config_pico_5() {
    assert_eq!(PICOW_CONFIG.stdc_headers, Some(1));
}

// Trace: `include/picow/config.h:VERSION`
// Spec: VERSION expose package version alias#PICO 配置声明版本别名
// - **GIVEN** 源码在 PICO 构建中包含 `config.h`
// - **WHEN** 预处理器展开 `VERSION`
// - **THEN** 展开结果为字符串 `"4.0.0"`
#[test]
fn test_config_pico_6() {
    assert_eq!(PICOW_CONFIG.version, "4.0.0");
}
