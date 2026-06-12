# include/apple/config.h Specification

## Source Context

- Source: `include/apple/config.h`
- Related Headers: `config.h.in`, `configure.ac`
- Related Tests: `none`
- Related Dependencies: GitNexus `context` found config macros in `include/apple/config.h` with no indexed incoming callers; source search shows many C files include `config.h`, and `lib/socket.c` uses `CONFIGURE_OPTION_TCP_LINGER` in TCP socket branches.
- Build/Compile Context: Autotools `AC_CONFIG_HEADERS([config.h])` generates `config.h`; `configure.ac` defines `CONFIGURE_OPTION_TCP_LINGER`, `HAVE_SOCKADDR_LEN`, `HAVE_SOCKADDR_STORAGE`, and `HAVE_LINGER`; top-level CMake includes generated binary config headers for normal builds and records project package values separately.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| CONFIGURE_OPTION_TCP_LINGER | macro | #define CONFIGURE_OPTION_TCP_LINGER 1 | Include | Apple 配置头公开 TCP linger 构建开关，调用方可观察到 socket 编译分支差异。 |
| HAVE_ARPA_INET_H | macro | #define HAVE_ARPA_INET_H 1 | Include | Apple 配置头公开可用系统头探测结果，影响条件编译。 |
| HAVE_DLFCN_H | macro | #define HAVE_DLFCN_H 1 | Include | Apple 配置头公开可用系统头探测结果，影响条件编译。 |
| HAVE_ERRNO_H | macro | #define HAVE_ERRNO_H 1 | Include | Apple 配置头公开可用系统头探测结果，影响错误处理相关包含路径。 |
| HAVE_FCNTL_H | macro | #define HAVE_FCNTL_H 1 | Include | Apple 配置头公开可用系统头探测结果，影响文件控制相关包含路径。 |
| HAVE_GSSAPI_GSSAPI_H | macro | #define HAVE_GSSAPI_GSSAPI_H 1 | Include | Apple 配置头公开 GSSAPI 头可用性，影响认证功能条件编译。 |
| HAVE_INTTYPES_H | macro | #define HAVE_INTTYPES_H 1 | Include | Apple 配置头公开整数类型头可用性，影响固定宽度整数声明路径。 |
| HAVE_LIBKRB5 | macro | /* #undef HAVE_LIBKRB5 */ | Include | Apple 配置头公开 libkrb5 不可用状态，影响 Kerberos 认证条件编译。 |
| HAVE_LIBNSL | macro | /* #undef HAVE_LIBNSL */ | Include | Apple 配置头公开 nsl 库不可用状态，影响链接和平台兼容路径。 |
| HAVE_LIBSOCKET | macro | /* #undef HAVE_LIBSOCKET */ | Include | Apple 配置头公开 socket 库不可用状态，影响链接和平台兼容路径。 |
| HAVE_LINGER | macro | #define HAVE_LINGER 1 | Include | Apple 配置头公开 `struct linger` 可用性，影响 socket linger 结构使用。 |
| HAVE_NETDB_H | macro | #define HAVE_NETDB_H 1 | Include | Apple 配置头公开网络数据库头可用性，影响地址解析包含路径。 |
| HAVE_NETINET_IN_H | macro | #define HAVE_NETINET_IN_H 1 | Include | Apple 配置头公开 IPv4/IPv6 socket 头可用性，影响网络结构声明路径。 |
| HAVE_NETINET_TCP_H | macro | #define HAVE_NETINET_TCP_H 1 | Include | Apple 配置头公开 TCP socket 头可用性，影响 TCP 选项声明路径。 |
| HAVE_POLL_H | macro | #define HAVE_POLL_H 1 | Include | Apple 配置头公开 poll 头可用性，影响事件轮询条件编译。 |
| HAVE_SOCKADDR_LEN | macro | #define HAVE_SOCKADDR_LEN 1 | Include | Apple 配置头公开 `struct sockaddr.sa_len` 成员可用性，影响 socket 地址布局假设。 |
| HAVE_SOCKADDR_STORAGE | macro | #define HAVE_SOCKADDR_STORAGE 1 | Include | Apple 配置头公开 `struct sockaddr_storage` 可用性，影响泛型 socket 地址存储。 |
| HAVE_STDINT_H | macro | #define HAVE_STDINT_H 1 | Include | Apple 配置头公开标准整数头可用性，影响固定宽度整数声明路径。 |
| HAVE_STDIO_H | macro | #define HAVE_STDIO_H 1 | Include | Apple 配置头公开标准 I/O 头可用性，影响 I/O 声明路径。 |
| HAVE_STDLIB_H | macro | #define HAVE_STDLIB_H 1 | Include | Apple 配置头公开标准库头可用性，影响分配和转换声明路径。 |
| HAVE_STRINGS_H | macro | #define HAVE_STRINGS_H 1 | Include | Apple 配置头公开 BSD strings 头可用性，影响字符串兼容声明路径。 |
| HAVE_STRING_H | macro | #define HAVE_STRING_H 1 | Include | Apple 配置头公开 C string 头可用性，影响字符串声明路径。 |
| HAVE_SYS_ERRNO_H | macro | #define HAVE_SYS_ERRNO_H 1 | Include | Apple 配置头公开系统 errno 头可用性，影响错误码声明路径。 |
| HAVE_SYS_FCNTL_H | macro | #define HAVE_SYS_FCNTL_H 1 | Include | Apple 配置头公开系统 fcntl 头可用性，影响文件控制声明路径。 |
| HAVE_SYS_IOCTL_H | macro | #define HAVE_SYS_IOCTL_H 1 | Include | Apple 配置头公开 ioctl 头可用性，影响设备控制声明路径。 |
| HAVE_SYS_POLL_H | macro | #define HAVE_SYS_POLL_H 1 | Include | Apple 配置头公开系统 poll 头可用性，影响事件轮询声明路径。 |
| HAVE_SYS_SOCKET_H | macro | #define HAVE_SYS_SOCKET_H 1 | Include | Apple 配置头公开 socket 头可用性，影响 socket API 声明路径。 |
| HAVE_SYS_STAT_H | macro | #define HAVE_SYS_STAT_H 1 | Include | Apple 配置头公开 stat 头可用性，影响文件状态声明路径。 |
| HAVE_SYS_TIME_H | macro | #define HAVE_SYS_TIME_H 1 | Include | Apple 配置头公开系统时间头可用性，影响时间结构声明路径。 |
| HAVE_SYS_TYPES_H | macro | #define HAVE_SYS_TYPES_H 1 | Include | Apple 配置头公开系统类型头可用性，影响基础类型声明路径。 |
| HAVE_SYS_UIO_H | macro | #define HAVE_SYS_UIO_H 1 | Include | Apple 配置头公开 scatter/gather I/O 头可用性，影响 `readv`/`writev` 声明路径。 |
| HAVE_SYS_UNISTD_H | macro | #define HAVE_SYS_UNISTD_H 1 | Include | Apple 配置头公开系统 unistd 头可用性，影响 POSIX 声明路径。 |
| HAVE_SYS__IOVEC_H | macro | /* #undef HAVE_SYS__IOVEC_H */ | Include | Apple 配置头公开私有 iovec 头不可用状态，影响备用包含路径。 |
| HAVE_TIME_H | macro | #define HAVE_TIME_H 1 | Include | Apple 配置头公开 time 头可用性，影响时间 API 声明路径。 |
| HAVE_UNISTD_H | macro | #define HAVE_UNISTD_H 1 | Include | Apple 配置头公开 unistd 头可用性，影响 POSIX API 声明路径。 |
| LT_OBJDIR | macro | #define LT_OBJDIR ".libs/" | Include | Apple 配置头公开 libtool 未安装库目录，影响构建产物路径假设。 |
| PACKAGE | macro | #define PACKAGE "libsmb2" | Include | Apple 配置头公开包短名，影响包标识字符串。 |
| PACKAGE_BUGREPORT | macro | #define PACKAGE_BUGREPORT "ronniesahlberg@gmail.com" | Include | Apple 配置头公开错误报告地址，影响包元数据。 |
| PACKAGE_NAME | macro | #define PACKAGE_NAME "libsmb2" | Include | Apple 配置头公开包全名，影响包元数据。 |
| PACKAGE_STRING | macro | #define PACKAGE_STRING "libsmb2 4.0.0" | Include | Apple 配置头公开包名和版本组合，影响包元数据。 |
| PACKAGE_TARNAME | macro | #define PACKAGE_TARNAME "libsmb2" | Include | Apple 配置头公开 tar 包名，影响包元数据。 |
| PACKAGE_URL | macro | #define PACKAGE_URL "" | Include | Apple 配置头公开包主页为空字符串，影响包元数据。 |
| PACKAGE_VERSION | macro | #define PACKAGE_VERSION "4.0.0" | Include | Apple 配置头公开包版本，影响包元数据。 |
| STDC_HEADERS | macro | #define STDC_HEADERS 1 | Include | Apple 配置头公开 C90 标准头集合可用性，影响兼容条件编译。 |
| VERSION | macro | #define VERSION "4.0.0" | Include | Apple 配置头公开版本号，影响包元数据。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| CONFIGURE_OPTION_TCP_LINGER | macro | include/apple/config.h:5 | Apple 配置将 TCP linger 构建选项设为启用。 |
| HAVE_ARPA_INET_H | macro | include/apple/config.h:8 | Apple 配置公开系统头、库和结构成员探测结果。 |
| PACKAGE | macro | include/apple/config.h:113 | Apple 配置公开包名、版本、URL 和报告地址。 |
| LT_OBJDIR | macro | include/apple/config.h:110 | Apple 配置公开 libtool 对象目录。 |
| STDC_HEADERS | macro | include/apple/config.h:136 | Apple 配置公开 C90 标准头集合可用性。 |

## ADDED Requirements

### Requirement: CONFIGURE_OPTION_TCP_LINGER Apple TCP linger option
系统 MUST 将 Apple 配置中的 `CONFIGURE_OPTION_TCP_LINGER` 暴露为数值 `1`，使包含该配置头的编译单元按启用 TCP linger 的构建契约解释该开关。

#### Scenario: Apple TCP linger is enabled
- **GIVEN** 构建使用 `include/apple/config.h` 作为 `config.h` 配置来源
- **WHEN** 源文件读取 `CONFIGURE_OPTION_TCP_LINGER`
- **THEN** 预处理器得到数值 `1`，并且 `lib/socket.c` 中 `#if 0 == CONFIGURE_OPTION_TCP_LINGER` 的禁用 linger 分支不被选择

Trace: `include/apple/config.h:CONFIGURE_OPTION_TCP_LINGER`, `configure.ac:CONFIGURE_OPTION_TCP_LINGER`, `lib/socket.c:connect_async_ai`

### Requirement: HAVE_ARPA_INET_H Apple arpa inet header availability
系统 MUST 将 `HAVE_ARPA_INET_H` 暴露为数值 `1`，表示 Apple 配置提供 `<arpa/inet.h>`。

#### Scenario: arpa inet header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_ARPA_INET_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择包含 `<arpa/inet.h>` 相关声明路径

Trace: `include/apple/config.h:HAVE_ARPA_INET_H`

### Requirement: HAVE_DLFCN_H Apple dlfcn header availability
系统 MUST 将 `HAVE_DLFCN_H` 暴露为数值 `1`，表示 Apple 配置提供 `<dlfcn.h>`。

#### Scenario: dlfcn header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_DLFCN_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择动态加载相关声明路径

Trace: `include/apple/config.h:HAVE_DLFCN_H`

### Requirement: HAVE_ERRNO_H Apple errno header availability
系统 MUST 将 `HAVE_ERRNO_H` 暴露为数值 `1`，表示 Apple 配置提供 `<errno.h>`。

#### Scenario: errno header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_ERRNO_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择标准 errno 声明路径

Trace: `include/apple/config.h:HAVE_ERRNO_H`

### Requirement: HAVE_FCNTL_H Apple fcntl header availability
系统 MUST 将 `HAVE_FCNTL_H` 暴露为数值 `1`，表示 Apple 配置提供 `<fcntl.h>`。

#### Scenario: fcntl header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_FCNTL_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择文件控制声明路径

Trace: `include/apple/config.h:HAVE_FCNTL_H`

### Requirement: HAVE_GSSAPI_GSSAPI_H Apple GSSAPI header availability
系统 MUST 将 `HAVE_GSSAPI_GSSAPI_H` 暴露为数值 `1`，表示 Apple 配置提供 `<gssapi/gssapi.h>`。

#### Scenario: GSSAPI header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_GSSAPI_GSSAPI_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择 GSSAPI 声明路径

Trace: `include/apple/config.h:HAVE_GSSAPI_GSSAPI_H`

### Requirement: HAVE_INTTYPES_H Apple inttypes header availability
系统 MUST 将 `HAVE_INTTYPES_H` 暴露为数值 `1`，表示 Apple 配置提供 `<inttypes.h>`。

#### Scenario: inttypes header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_INTTYPES_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择整数格式和类型声明路径

Trace: `include/apple/config.h:HAVE_INTTYPES_H`

### Requirement: HAVE_LIBKRB5 Apple Kerberos library availability
系统 MUST NOT 定义 `HAVE_LIBKRB5`，表示 Apple 配置不声明可使用 `gssapi_krb5` 库。

#### Scenario: Kerberos library is not configured
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_LIBKRB5` 是否定义
- **THEN** 预处理器将该宏视为未定义，调用方不进入依赖该宏的 libkrb5 条件编译路径

Trace: `include/apple/config.h:HAVE_LIBKRB5`, `configure.ac:HAVE_LIBKRB5`

### Requirement: HAVE_LIBNSL Apple nsl library availability
系统 MUST NOT 定义 `HAVE_LIBNSL`，表示 Apple 配置不声明需要或提供 `nsl` 库。

#### Scenario: nsl library is not configured
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_LIBNSL` 是否定义
- **THEN** 预处理器将该宏视为未定义

Trace: `include/apple/config.h:HAVE_LIBNSL`

### Requirement: HAVE_LIBSOCKET Apple socket library availability
系统 MUST NOT 定义 `HAVE_LIBSOCKET`，表示 Apple 配置不声明需要或提供单独的 `socket` 库。

#### Scenario: socket library is not configured
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_LIBSOCKET` 是否定义
- **THEN** 预处理器将该宏视为未定义

Trace: `include/apple/config.h:HAVE_LIBSOCKET`

### Requirement: HAVE_LINGER Apple linger structure availability
系统 MUST 将 `HAVE_LINGER` 暴露为数值 `1`，表示 Apple 配置提供 `struct linger.l_linger` 成员。

#### Scenario: linger structure is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** socket 相关源码检查 `HAVE_LINGER`
- **THEN** 预处理器得到数值 `1`，调用方可使用 linger 结构相关声明

Trace: `include/apple/config.h:HAVE_LINGER`, `configure.ac:HAVE_LINGER`

### Requirement: HAVE_NETDB_H Apple netdb header availability
系统 MUST 将 `HAVE_NETDB_H` 暴露为数值 `1`，表示 Apple 配置提供 `<netdb.h>`。

#### Scenario: netdb header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_NETDB_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择网络数据库声明路径

Trace: `include/apple/config.h:HAVE_NETDB_H`

### Requirement: HAVE_NETINET_IN_H Apple netinet in header availability
系统 MUST 将 `HAVE_NETINET_IN_H` 暴露为数值 `1`，表示 Apple 配置提供 `<netinet/in.h>`。

#### Scenario: netinet in header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_NETINET_IN_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择 IP socket 结构声明路径

Trace: `include/apple/config.h:HAVE_NETINET_IN_H`

### Requirement: HAVE_NETINET_TCP_H Apple netinet tcp header availability
系统 MUST 将 `HAVE_NETINET_TCP_H` 暴露为数值 `1`，表示 Apple 配置提供 `<netinet/tcp.h>`。

#### Scenario: netinet tcp header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_NETINET_TCP_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择 TCP 选项声明路径

Trace: `include/apple/config.h:HAVE_NETINET_TCP_H`

### Requirement: HAVE_POLL_H Apple poll header availability
系统 MUST 将 `HAVE_POLL_H` 暴露为数值 `1`，表示 Apple 配置提供 `<poll.h>`。

#### Scenario: poll header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_POLL_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择 poll 声明路径

Trace: `include/apple/config.h:HAVE_POLL_H`

### Requirement: HAVE_SOCKADDR_LEN Apple sockaddr length member availability
系统 MUST 将 `HAVE_SOCKADDR_LEN` 暴露为数值 `1`，表示 Apple 配置提供 `struct sockaddr.sa_len` 成员。

#### Scenario: sockaddr length member is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** socket 地址布局代码检查 `HAVE_SOCKADDR_LEN`
- **THEN** 预处理器得到数值 `1`，调用方可按存在 `sa_len` 成员的地址结构布局处理

Trace: `include/apple/config.h:HAVE_SOCKADDR_LEN`, `configure.ac:HAVE_SOCKADDR_LEN`

### Requirement: HAVE_SOCKADDR_STORAGE Apple sockaddr storage availability
系统 MUST 将 `HAVE_SOCKADDR_STORAGE` 暴露为数值 `1`，表示 Apple 配置提供 `struct sockaddr_storage`。

#### Scenario: sockaddr storage is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** socket 地址存储代码检查 `HAVE_SOCKADDR_STORAGE`
- **THEN** 预处理器得到数值 `1`，调用方可使用泛型 socket 地址存储结构

Trace: `include/apple/config.h:HAVE_SOCKADDR_STORAGE`, `configure.ac:HAVE_SOCKADDR_STORAGE`

### Requirement: HAVE_STDINT_H Apple stdint header availability
系统 MUST 将 `HAVE_STDINT_H` 暴露为数值 `1`，表示 Apple 配置提供 `<stdint.h>`。

#### Scenario: stdint header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_STDINT_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择固定宽度整数声明路径

Trace: `include/apple/config.h:HAVE_STDINT_H`

### Requirement: HAVE_STDIO_H Apple stdio header availability
系统 MUST 将 `HAVE_STDIO_H` 暴露为数值 `1`，表示 Apple 配置提供 `<stdio.h>`。

#### Scenario: stdio header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_STDIO_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择标准 I/O 声明路径

Trace: `include/apple/config.h:HAVE_STDIO_H`

### Requirement: HAVE_STDLIB_H Apple stdlib header availability
系统 MUST 将 `HAVE_STDLIB_H` 暴露为数值 `1`，表示 Apple 配置提供 `<stdlib.h>`。

#### Scenario: stdlib header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_STDLIB_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择标准库声明路径

Trace: `include/apple/config.h:HAVE_STDLIB_H`

### Requirement: HAVE_STRINGS_H Apple strings header availability
系统 MUST 将 `HAVE_STRINGS_H` 暴露为数值 `1`，表示 Apple 配置提供 `<strings.h>`。

#### Scenario: strings header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_STRINGS_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择 BSD 字符串声明路径

Trace: `include/apple/config.h:HAVE_STRINGS_H`

### Requirement: HAVE_STRING_H Apple string header availability
系统 MUST 将 `HAVE_STRING_H` 暴露为数值 `1`，表示 Apple 配置提供 `<string.h>`。

#### Scenario: string header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_STRING_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择 C 字符串声明路径

Trace: `include/apple/config.h:HAVE_STRING_H`

### Requirement: HAVE_SYS_ERRNO_H Apple sys errno header availability
系统 MUST 将 `HAVE_SYS_ERRNO_H` 暴露为数值 `1`，表示 Apple 配置提供 `<sys/errno.h>`。

#### Scenario: sys errno header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_SYS_ERRNO_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择系统 errno 声明路径

Trace: `include/apple/config.h:HAVE_SYS_ERRNO_H`

### Requirement: HAVE_SYS_FCNTL_H Apple sys fcntl header availability
系统 MUST 将 `HAVE_SYS_FCNTL_H` 暴露为数值 `1`，表示 Apple 配置提供 `<sys/fcntl.h>`。

#### Scenario: sys fcntl header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_SYS_FCNTL_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择系统文件控制声明路径

Trace: `include/apple/config.h:HAVE_SYS_FCNTL_H`

### Requirement: HAVE_SYS_IOCTL_H Apple sys ioctl header availability
系统 MUST 将 `HAVE_SYS_IOCTL_H` 暴露为数值 `1`，表示 Apple 配置提供 `<sys/ioctl.h>`。

#### Scenario: sys ioctl header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_SYS_IOCTL_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择系统 ioctl 声明路径

Trace: `include/apple/config.h:HAVE_SYS_IOCTL_H`

### Requirement: HAVE_SYS_POLL_H Apple sys poll header availability
系统 MUST 将 `HAVE_SYS_POLL_H` 暴露为数值 `1`，表示 Apple 配置提供 `<sys/poll.h>`。

#### Scenario: sys poll header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_SYS_POLL_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择系统 poll 声明路径

Trace: `include/apple/config.h:HAVE_SYS_POLL_H`

### Requirement: HAVE_SYS_SOCKET_H Apple sys socket header availability
系统 MUST 将 `HAVE_SYS_SOCKET_H` 暴露为数值 `1`，表示 Apple 配置提供 `<sys/socket.h>`。

#### Scenario: sys socket header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_SYS_SOCKET_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择 socket API 声明路径

Trace: `include/apple/config.h:HAVE_SYS_SOCKET_H`

### Requirement: HAVE_SYS_STAT_H Apple sys stat header availability
系统 MUST 将 `HAVE_SYS_STAT_H` 暴露为数值 `1`，表示 Apple 配置提供 `<sys/stat.h>`。

#### Scenario: sys stat header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_SYS_STAT_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择文件状态声明路径

Trace: `include/apple/config.h:HAVE_SYS_STAT_H`

### Requirement: HAVE_SYS_TIME_H Apple sys time header availability
系统 MUST 将 `HAVE_SYS_TIME_H` 暴露为数值 `1`，表示 Apple 配置提供 `<sys/time.h>`。

#### Scenario: sys time header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_SYS_TIME_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择系统时间声明路径

Trace: `include/apple/config.h:HAVE_SYS_TIME_H`

### Requirement: HAVE_SYS_TYPES_H Apple sys types header availability
系统 MUST 将 `HAVE_SYS_TYPES_H` 暴露为数值 `1`，表示 Apple 配置提供 `<sys/types.h>`。

#### Scenario: sys types header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_SYS_TYPES_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择系统基础类型声明路径

Trace: `include/apple/config.h:HAVE_SYS_TYPES_H`

### Requirement: HAVE_SYS_UIO_H Apple sys uio header availability
系统 MUST 将 `HAVE_SYS_UIO_H` 暴露为数值 `1`，表示 Apple 配置提供 `<sys/uio.h>`。

#### Scenario: sys uio header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_SYS_UIO_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择 scatter/gather I/O 声明路径

Trace: `include/apple/config.h:HAVE_SYS_UIO_H`

### Requirement: HAVE_SYS_UNISTD_H Apple sys unistd header availability
系统 MUST 将 `HAVE_SYS_UNISTD_H` 暴露为数值 `1`，表示 Apple 配置提供 `<sys/unistd.h>`。

#### Scenario: sys unistd header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_SYS_UNISTD_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择系统 POSIX 声明路径

Trace: `include/apple/config.h:HAVE_SYS_UNISTD_H`

### Requirement: HAVE_SYS__IOVEC_H Apple private iovec header availability
系统 MUST NOT 定义 `HAVE_SYS__IOVEC_H`，表示 Apple 配置不声明 `<sys/_iovec.h>` 可用。

#### Scenario: private iovec header is not configured
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_SYS__IOVEC_H` 是否定义
- **THEN** 预处理器将该宏视为未定义

Trace: `include/apple/config.h:HAVE_SYS__IOVEC_H`

### Requirement: HAVE_TIME_H Apple time header availability
系统 MUST 将 `HAVE_TIME_H` 暴露为数值 `1`，表示 Apple 配置提供 `<time.h>`。

#### Scenario: time header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_TIME_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择标准时间声明路径

Trace: `include/apple/config.h:HAVE_TIME_H`

### Requirement: HAVE_UNISTD_H Apple unistd header availability
系统 MUST 将 `HAVE_UNISTD_H` 暴露为数值 `1`，表示 Apple 配置提供 `<unistd.h>`。

#### Scenario: unistd header is available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `HAVE_UNISTD_H`
- **THEN** 预处理器得到数值 `1`，调用方可选择 POSIX 声明路径

Trace: `include/apple/config.h:HAVE_UNISTD_H`

### Requirement: LT_OBJDIR Apple libtool object directory
系统 MUST 将 `LT_OBJDIR` 暴露为字符串 `".libs/"`，表示 libtool 未安装库子目录。

#### Scenario: libtool object directory is exposed
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件或构建辅助代码读取 `LT_OBJDIR`
- **THEN** 预处理器得到字符串 `".libs/"`

Trace: `include/apple/config.h:LT_OBJDIR`

### Requirement: PACKAGE Apple package short name
系统 MUST 将 `PACKAGE` 暴露为字符串 `"libsmb2"`，表示 Apple 配置的包短名。

#### Scenario: package short name is exposed
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件读取 `PACKAGE`
- **THEN** 预处理器得到字符串 `"libsmb2"`

Trace: `include/apple/config.h:PACKAGE`

### Requirement: PACKAGE_BUGREPORT Apple package bug report address
系统 MUST 将 `PACKAGE_BUGREPORT` 暴露为字符串 `"ronniesahlberg@gmail.com"`，表示 Apple 配置的错误报告地址。

#### Scenario: package bug report address is exposed
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件读取 `PACKAGE_BUGREPORT`
- **THEN** 预处理器得到字符串 `"ronniesahlberg@gmail.com"`

Trace: `include/apple/config.h:PACKAGE_BUGREPORT`

### Requirement: PACKAGE_NAME Apple package full name
系统 MUST 将 `PACKAGE_NAME` 暴露为字符串 `"libsmb2"`，表示 Apple 配置的包全名。

#### Scenario: package full name is exposed
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件读取 `PACKAGE_NAME`
- **THEN** 预处理器得到字符串 `"libsmb2"`

Trace: `include/apple/config.h:PACKAGE_NAME`

### Requirement: PACKAGE_STRING Apple package name and version
系统 MUST 将 `PACKAGE_STRING` 暴露为字符串 `"libsmb2 4.0.0"`，表示 Apple 配置的包名和版本组合。

#### Scenario: package string is exposed
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件读取 `PACKAGE_STRING`
- **THEN** 预处理器得到字符串 `"libsmb2 4.0.0"`

Trace: `include/apple/config.h:PACKAGE_STRING`

### Requirement: PACKAGE_TARNAME Apple package tar name
系统 MUST 将 `PACKAGE_TARNAME` 暴露为字符串 `"libsmb2"`，表示 Apple 配置的 tar 包名。

#### Scenario: package tar name is exposed
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件读取 `PACKAGE_TARNAME`
- **THEN** 预处理器得到字符串 `"libsmb2"`

Trace: `include/apple/config.h:PACKAGE_TARNAME`

### Requirement: PACKAGE_URL Apple package URL
系统 MUST 将 `PACKAGE_URL` 暴露为空字符串 `""`，表示 Apple 配置未设置包主页。

#### Scenario: package URL is empty
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件读取 `PACKAGE_URL`
- **THEN** 预处理器得到空字符串 `""`

Trace: `include/apple/config.h:PACKAGE_URL`

### Requirement: PACKAGE_VERSION Apple package version
系统 MUST 将 `PACKAGE_VERSION` 暴露为字符串 `"4.0.0"`，表示 Apple 配置的包版本。

#### Scenario: package version is exposed
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件读取 `PACKAGE_VERSION`
- **THEN** 预处理器得到字符串 `"4.0.0"`

Trace: `include/apple/config.h:PACKAGE_VERSION`

### Requirement: STDC_HEADERS Apple C90 standard headers availability
系统 MUST 将 `STDC_HEADERS` 暴露为数值 `1`，表示 Apple 配置声明 C90 标准头集合可用。

#### Scenario: C90 standard headers are available
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件检查 `STDC_HEADERS`
- **THEN** 预处理器得到数值 `1`，调用方可选择标准头兼容路径

Trace: `include/apple/config.h:STDC_HEADERS`

### Requirement: VERSION Apple package version alias
系统 MUST 将 `VERSION` 暴露为字符串 `"4.0.0"`，表示 Apple 配置的版本号别名。

#### Scenario: version alias is exposed
- **GIVEN** 构建使用 Apple 配置头
- **WHEN** 源文件读取 `VERSION`
- **THEN** 预处理器得到字符串 `"4.0.0"`

Trace: `include/apple/config.h:VERSION`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | Apple 手写配置头中的 `PACKAGE_VERSION` 和 `VERSION` 为 `4.0.0`，但 `configure.ac` 和顶层 CMake 当前项目版本为 `6.1.0`；该平台配置是否应保留旧版本值？ | PACKAGE_VERSION`, `VERSION`, `PACKAGE_STRING | 源码证据显示版本值不一致，需要维护者确认发布/平台配置策略。 |
