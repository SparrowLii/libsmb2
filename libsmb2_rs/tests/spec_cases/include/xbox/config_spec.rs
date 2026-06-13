use libsmb2_sys::include::config::XBOX_CONFIG;

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
