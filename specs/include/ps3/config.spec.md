# include/ps3/config.h Specification

## Source Context

- Source: `include/ps3/config.h`
- Related Headers: `config.h.in`, `configure.ac`
- Related Tests: `none`
- Related Dependencies: GitNexus `context "CONFIGURE_OPTION_TCP_LINGER" --file "include/ps3/config.h" --content --repo libsmb2` located `Macro:include/ps3/config.h:CONFIGURE_OPTION_TCP_LINGER` with no indexed incoming callers; GitNexus `context "HAVE_NETINET_IN_H" --file "include/ps3/config.h" --content --repo libsmb2` located the PS3 header macro; source search shows core files include `config.h` under `HAVE_CONFIG_H`, `lib/socket.c` uses `CONFIGURE_OPTION_TCP_LINGER`, and `lib/compat.c`/`lib/compat.h` contain `PS3_PPU_PLATFORM` compatibility branches.
- Build/Compile Context: `configure.ac` generates `config.h` and defines Autoconf probes for TCP linger, headers, libraries, package metadata, and structure members; PS3 selection is not described in the checked CMake paths, so this file is treated as a platform-supplied generated configuration header.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| CONFIGURE_OPTION_TCP_LINGER | macro | #define CONFIGURE_OPTION_TCP_LINGER 1 | Include | PS3 配置公开 TCP linger 构建开关，影响 socket 编译分支。 |
| HAVE_ARPA_INET_H | macro | /* #undef HAVE_ARPA_INET_H */ | Include | PS3 配置显式声明 `<arpa/inet.h>` 不可用，影响网络地址头条件编译。 |
| HAVE_DLFCN_H | macro | /* #undef HAVE_DLFCN_H */ | Include | PS3 配置显式声明 `<dlfcn.h>` 不可用，属于平台能力契约。 |
| HAVE_ERRNO_H | macro | #define HAVE_ERRNO_H 1 | Include | PS3 配置声明 `<errno.h>` 可用，影响错误处理头条件编译。 |
| HAVE_FCNTL_H | macro | #define HAVE_FCNTL_H 1 | Include | PS3 配置声明 `<fcntl.h>` 可用，影响文件控制头条件编译。 |
| HAVE_GSSAPI_GSSAPI_H | macro | /* #undef HAVE_GSSAPI_GSSAPI_H */ | Include | PS3 配置显式声明 GSSAPI 头不可用，影响认证能力条件编译。 |
| HAVE_INTTYPES_H | macro | /* #undef HAVE_INTTYPES_H */ | Include | PS3 配置显式声明 `<inttypes.h>` 不可用，影响整数格式头条件编译。 |
| HAVE_LIBKRB5 | macro | /* #undef HAVE_LIBKRB5 */ | Include | PS3 配置显式声明 libkrb5 不可用，影响 Kerberos 认证条件编译。 |
| HAVE_LIBNSL | macro | /* #undef HAVE_LIBNSL */ | Include | PS3 配置显式声明 `nsl` 库不可用，属于链接能力契约。 |
| HAVE_LIBSOCKET | macro | /* #undef HAVE_LIBSOCKET */ | Include | PS3 配置显式声明 `socket` 库不可用，属于链接能力契约。 |
| HAVE_LINGER | macro | #define HAVE_LINGER 1 | Include | PS3 配置声明系统提供 `struct linger`，影响本地兼容结构定义。 |
| HAVE_NETDB_H | macro | /* #undef HAVE_NETDB_H */ | Include | PS3 配置显式声明 `<netdb.h>` 不可用，影响地址解析头条件编译。 |
| HAVE_NETINET_IN_H | macro | #define HAVE_NETINET_IN_H 1 | Include | PS3 配置声明 `<netinet/in.h>` 可用，影响 socket 类型条件编译。 |
| HAVE_NETINET_TCP_H | macro | /* #undef HAVE_NETINET_TCP_H */ | Include | PS3 配置显式声明 `<netinet/tcp.h>` 不可用，影响 TCP 选项头条件编译。 |
| HAVE_POLL_H | macro | /* #undef HAVE_POLL_H */ | Include | PS3 配置显式声明 `<poll.h>` 不可用，影响 poll 头选择。 |
| HAVE_SOCKADDR_LEN | macro | /* #undef HAVE_SOCKADDR_LEN */ | Include | PS3 配置显式声明 sockaddr 不含 `sa_len` 成员，影响地址结构布局假设。 |
| HAVE_SOCKADDR_STORAGE | macro | /* #undef HAVE_SOCKADDR_STORAGE */ | Include | PS3 配置显式声明 `sockaddr_storage` 不可用，影响通用 socket 地址存储假设。 |
| HAVE_STDINT_H | macro | #define HAVE_STDINT_H 1 | Include | PS3 配置声明 `<stdint.h>` 可用，影响固定宽度整数头条件编译。 |
| HAVE_STDIO_H | macro | #define HAVE_STDIO_H 1 | Include | PS3 配置声明 `<stdio.h>` 可用，影响标准 I/O 头条件编译。 |
| HAVE_STDLIB_H | macro | #define HAVE_STDLIB_H 1 | Include | PS3 配置声明 `<stdlib.h>` 可用，影响分配和转换头条件编译。 |
| HAVE_STRINGS_H | macro | /* #undef HAVE_STRINGS_H */ | Include | PS3 配置显式声明 `<strings.h>` 不可用，影响 BSD 字符串头条件编译。 |
| HAVE_STRING_H | macro | #define HAVE_STRING_H 1 | Include | PS3 配置声明 `<string.h>` 可用，影响字符串和内存操作头条件编译。 |
| HAVE_SYS_ERRNO_H | macro | /* #undef HAVE_SYS_ERRNO_H */ | Include | PS3 配置显式声明 `<sys/errno.h>` 不可用，影响系统 errno 头选择。 |
| HAVE_SYS_FCNTL_H | macro | /* #undef HAVE_SYS_FCNTL_H */ | Include | PS3 配置显式声明 `<sys/fcntl.h>` 不可用，影响系统 fcntl 头选择。 |
| HAVE_SYS_IOCTL_H | macro | /* #undef HAVE_SYS_IOCTL_H */ | Include | PS3 配置显式声明 `<sys/ioctl.h>` 不可用，影响 ioctl 头条件编译。 |
| HAVE_SYS_POLL_H | macro | /* #undef HAVE_SYS_POLL_H */ | Include | PS3 配置显式声明 `<sys/poll.h>` 不可用，影响系统 poll 头选择。 |
| HAVE_SYS_SOCKET_H | macro | /* #undef HAVE_SYS_SOCKET_H */ | Include | PS3 配置显式声明 `<sys/socket.h>` 不可用，影响 socket API 头条件编译。 |
| HAVE_SYS_STAT_H | macro | /* #undef HAVE_SYS_STAT_H */ | Include | PS3 配置显式声明 `<sys/stat.h>` 不可用，影响文件状态头条件编译。 |
| HAVE_SYS_TIME_H | macro | /* #undef HAVE_SYS_TIME_H */ | Include | PS3 配置显式声明 `<sys/time.h>` 不可用，影响时间头条件编译。 |
| HAVE_SYS_TYPES_H | macro | #define HAVE_SYS_TYPES_H 1 | Include | PS3 配置声明 `<sys/types.h>` 可用，影响系统类型头条件编译。 |
| HAVE_SYS_UIO_H | macro | /* #undef HAVE_SYS_UIO_H */ | Include | PS3 配置显式声明 `<sys/uio.h>` 不可用，影响 scatter/gather I/O 头条件编译。 |
| HAVE_SYS_UNISTD_H | macro | /* #undef HAVE_SYS_UNISTD_H */ | Include | PS3 配置显式声明 `<sys/unistd.h>` 不可用，影响系统 unistd 头选择。 |
| HAVE_SYS__IOVEC_H | macro | /* #undef HAVE_SYS__IOVEC_H */ | Include | PS3 配置显式声明 `<sys/_iovec.h>` 不可用，影响 iovec 头选择。 |
| HAVE_TIME_H | macro | #define HAVE_TIME_H 1 | Include | PS3 配置声明 `<time.h>` 可用，影响时间头条件编译。 |
| HAVE_UNISTD_H | macro | #define HAVE_UNISTD_H 1 | Include | PS3 配置声明 `<unistd.h>` 可用，影响 POSIX API 头条件编译。 |
| LT_OBJDIR | macro | #define LT_OBJDIR ".libs/" | Include | PS3 配置公开 libtool 对象目录字符串，属于生成配置头元数据。 |
| PACKAGE | macro | #define PACKAGE "libsmb2" | Include | PS3 配置公开包短名，属于包元数据契约。 |
| PACKAGE_BUGREPORT | macro | #define PACKAGE_BUGREPORT "ronniesahlberg@gmail.com" | Include | PS3 配置公开错误报告地址，属于包元数据契约。 |
| PACKAGE_NAME | macro | #define PACKAGE_NAME "libsmb2" | Include | PS3 配置公开包全名，属于包元数据契约。 |
| PACKAGE_STRING | macro | #define PACKAGE_STRING "libsmb2 4.0.0" | Include | PS3 配置公开包名和版本组合，属于包元数据契约。 |
| PACKAGE_TARNAME | macro | #define PACKAGE_TARNAME "libsmb2" | Include | PS3 配置公开发行包名，属于包元数据契约。 |
| PACKAGE_URL | macro | #define PACKAGE_URL "" | Include | PS3 配置公开包主页为空字符串，属于包元数据契约。 |
| PACKAGE_VERSION | macro | #define PACKAGE_VERSION "4.0.0" | Include | PS3 配置公开包版本，属于包元数据契约。 |
| STDC_HEADERS | macro | #define STDC_HEADERS 1 | Include | PS3 配置声明 C90 标准头集合可用，影响标准头条件编译。 |
| VERSION | macro | #define VERSION "4.0.0" | Include | PS3 配置公开版本号别名，属于包元数据契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| CONFIGURE_OPTION_TCP_LINGER | macro | include/ps3/config.h:5 | 取值为 `1`，表示 PS3 配置允许 TCP socket linger；`lib/socket.c` 只在该值为 `0` 时编译设置 `SO_REUSEADDR` 和零秒 `SO_LINGER` 的分支。 |
| HAVE_ARPA_INET_H | macro | include/ps3/config.h:8 | 平台能力宏以定义或 `#undef` 注释形式记录 PS3 可用头文件、库和结构能力；同类宏详见 Interface Summary。 |
| PACKAGE | macro | include/ps3/config.h:113 | 包元数据宏声明 PS3 配置头中的包名、版本、URL 和联系信息；同类宏详见 Interface Summary。 |
| LT_OBJDIR | macro | include/ps3/config.h:110 | 取值为 `".libs/"`，保留 Autoconf/libtool 对象目录元数据。 |
| STDC_HEADERS | macro | include/ps3/config.h:136 | 取值为 `1`，保留 Autoconf 标准头兼容信号。 |

## ADDED Requirements

### Requirement: CONFIGURE_OPTION_TCP_LINGER controls PS3 socket linger policy
系统 MUST 在 PS3 配置头中将 `CONFIGURE_OPTION_TCP_LINGER` 暴露为值 `1`，使包含 `config.h` 的 socket 源码看到 PS3 配置允许 TCP linger 的编译时策略。

#### Scenario: PS3 配置保留默认 linger 行为
- **GIVEN** PS3 构建使用 `include/ps3/config.h` 作为 `config.h` 配置来源
- **WHEN** `lib/socket.c` 在连接或接受 socket 的路径中检查 `#if 0 == CONFIGURE_OPTION_TCP_LINGER`
- **THEN** PS3 配置取值 `1` SHALL 使该条件为假，源码不编译设置 `SO_REUSEADDR` 和零秒 `SO_LINGER` 的分支

Trace: `include/ps3/config.h:CONFIGURE_OPTION_TCP_LINGER`, `lib/socket.c:connect_async_ai`, `lib/socket.c:smb2_accept_connection_async`

### Requirement: HAVE_ARPA_INET_H declares arpa inet header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_ARPA_INET_H`，以声明 `<arpa/inet.h>` 在该配置中不可用。

#### Scenario: arpa inet header remains disabled
- **GIVEN** 源码以配置宏判断网络地址头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_ARPA_INET_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_ARPA_INET_H`, `configure.ac:HAVE_ARPA_INET_H`

### Requirement: HAVE_DLFCN_H declares dlfcn header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_DLFCN_H`，以声明 `<dlfcn.h>` 在该配置中不可用。

#### Scenario: dlfcn header remains disabled
- **GIVEN** 源码以配置宏判断动态加载头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_DLFCN_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_DLFCN_H`

### Requirement: HAVE_ERRNO_H declares errno header availability
系统 MUST 在 PS3 配置头中定义 `HAVE_ERRNO_H` 为 `1`，表示 `<errno.h>` 对错误处理条件编译可用。

#### Scenario: errno header capability is visible
- **GIVEN** 源码以配置宏判断错误头能力
- **WHEN** 读取 `HAVE_ERRNO_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<errno.h>` 可用

Trace: `include/ps3/config.h:HAVE_ERRNO_H`, `configure.ac:HAVE_ERRNO_H`

### Requirement: HAVE_FCNTL_H declares fcntl header availability
系统 MUST 在 PS3 配置头中定义 `HAVE_FCNTL_H` 为 `1`，表示 `<fcntl.h>` 对条件编译使用方可用。

#### Scenario: fcntl header capability is visible
- **GIVEN** 源码以配置宏判断文件控制头能力
- **WHEN** 读取 `HAVE_FCNTL_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<fcntl.h>` 可用

Trace: `include/ps3/config.h:HAVE_FCNTL_H`, `configure.ac:HAVE_FCNTL_H`

### Requirement: HAVE_GSSAPI_GSSAPI_H declares GSSAPI header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_GSSAPI_GSSAPI_H`，以声明 `<gssapi/gssapi.h>` 在该配置中不可用。

#### Scenario: GSSAPI header capability remains disabled
- **GIVEN** 源码以配置宏判断 GSSAPI 头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_GSSAPI_GSSAPI_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_GSSAPI_GSSAPI_H`, `configure.ac:HAVE_GSSAPI_GSSAPI_H`

### Requirement: HAVE_INTTYPES_H declares inttypes header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_INTTYPES_H`，以声明 `<inttypes.h>` 在该配置中不可用。

#### Scenario: inttypes header remains disabled
- **GIVEN** 源码以配置宏判断整数格式头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_INTTYPES_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_INTTYPES_H`

### Requirement: HAVE_LIBKRB5 declares Kerberos library absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_LIBKRB5`，以声明 libkrb5 支持在该配置中不可用。

#### Scenario: Kerberos library capability remains disabled
- **GIVEN** 认证相关源码以配置宏判断 libkrb5 能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_LIBKRB5`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_LIBKRB5`, `configure.ac:HAVE_LIBKRB5`

### Requirement: HAVE_LIBNSL declares nsl library absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_LIBNSL`，以声明 `nsl` 链接库在该配置中不可用。

#### Scenario: nsl link capability remains disabled
- **GIVEN** 构建或源码以配置宏判断 `nsl` 库能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_LIBNSL`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_LIBNSL`

### Requirement: HAVE_LIBSOCKET declares socket library absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_LIBSOCKET`，以声明单独的 `socket` 链接库在该配置中不可用。

#### Scenario: socket link capability remains disabled
- **GIVEN** 构建或源码以配置宏判断 `socket` 库能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_LIBSOCKET`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_LIBSOCKET`

### Requirement: HAVE_LINGER declares system linger support
系统 MUST 在 PS3 配置头中定义 `HAVE_LINGER` 为 `1`，表示平台提供 `struct linger`。

#### Scenario: compatible linger structure is not selected
- **GIVEN** socket 源码以配置宏判断 linger 结构能力
- **WHEN** `lib/socket.c` 检查 `#if !defined(HAVE_LINGER)`
- **THEN** 源码 SHALL 不启用本地 `struct linger` 兼容定义

Trace: `include/ps3/config.h:HAVE_LINGER`, `lib/socket.c:121`, `configure.ac:HAVE_LINGER`

### Requirement: HAVE_NETDB_H declares netdb header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_NETDB_H`，以声明 `<netdb.h>` 在该配置中不可用。

#### Scenario: netdb header remains disabled
- **GIVEN** 源码以配置宏判断地址解析头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_NETDB_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_NETDB_H`

### Requirement: HAVE_NETINET_IN_H declares netinet in header availability
系统 MUST 在 PS3 配置头中定义 `HAVE_NETINET_IN_H` 为 `1`，表示 `<netinet/in.h>` 对 socket 类型条件编译可用。

#### Scenario: netinet in header capability is visible
- **GIVEN** 源码以配置宏判断 IP socket 类型头能力
- **WHEN** 读取 `HAVE_NETINET_IN_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<netinet/in.h>` 可用

Trace: `include/ps3/config.h:HAVE_NETINET_IN_H`, `lib/socket.c:38`, `lib/md5.h:30`

### Requirement: HAVE_NETINET_TCP_H declares netinet tcp header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_NETINET_TCP_H`，以声明 `<netinet/tcp.h>` 在该配置中不可用。

#### Scenario: netinet tcp header remains disabled
- **GIVEN** 源码以配置宏判断 TCP 选项头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_NETINET_TCP_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_NETINET_TCP_H`, `configure.ac:HAVE_NETINET_TCP_H`

### Requirement: HAVE_POLL_H declares poll header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_POLL_H`，以声明 `<poll.h>` 在该配置中不可用。

#### Scenario: poll header remains disabled
- **GIVEN** 源码以配置宏判断 poll 头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_POLL_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_POLL_H`, `configure.ac:HAVE_POLL_H`

### Requirement: HAVE_SOCKADDR_LEN declares sockaddr length member absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_SOCKADDR_LEN`，以声明 sockaddr 结构没有 `sa_len` 成员。

#### Scenario: sockaddr length member remains disabled
- **GIVEN** socket 地址布局代码以配置宏判断 sockaddr 长度成员
- **WHEN** 读取 PS3 配置头中的 `HAVE_SOCKADDR_LEN`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_SOCKADDR_LEN`, `configure.ac:HAVE_SOCKADDR_LEN`

### Requirement: HAVE_SOCKADDR_STORAGE declares sockaddr storage absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_SOCKADDR_STORAGE`，以声明该配置不公开 `sockaddr_storage` 可用性。

#### Scenario: sockaddr storage capability remains disabled
- **GIVEN** 源码以配置宏判断通用 socket 地址存储能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_SOCKADDR_STORAGE`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_SOCKADDR_STORAGE`, `configure.ac:HAVE_SOCKADDR_STORAGE`

### Requirement: HAVE_STDINT_H declares stdint header availability
系统 MUST 在 PS3 配置头中定义 `HAVE_STDINT_H` 为 `1`，表示 `<stdint.h>` 对固定宽度整数条件编译可用。

#### Scenario: stdint header capability is visible
- **GIVEN** 源码以配置宏判断固定宽度整数头能力
- **WHEN** 读取 `HAVE_STDINT_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<stdint.h>` 可用

Trace: `include/ps3/config.h:HAVE_STDINT_H`, `lib/socket.c:86`, `lib/md5.h:37`

### Requirement: HAVE_STDIO_H declares stdio header availability
系统 MUST 在 PS3 配置头中定义 `HAVE_STDIO_H` 为 `1`，表示 `<stdio.h>` 对条件编译使用方可用。

#### Scenario: stdio header capability is visible
- **GIVEN** 源码以配置宏判断标准 I/O 头能力
- **WHEN** 读取 `HAVE_STDIO_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<stdio.h>` 可用

Trace: `include/ps3/config.h:HAVE_STDIO_H`, `lib/socket.c:54`

### Requirement: HAVE_STDLIB_H declares stdlib header availability
系统 MUST 在 PS3 配置头中定义 `HAVE_STDLIB_H` 为 `1`，表示 `<stdlib.h>` 对条件编译使用方可用。

#### Scenario: stdlib header capability is visible
- **GIVEN** 源码以配置宏判断标准库头能力
- **WHEN** 读取 `HAVE_STDLIB_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<stdlib.h>` 可用

Trace: `include/ps3/config.h:HAVE_STDLIB_H`, `lib/socket.c:50`

### Requirement: HAVE_STRINGS_H declares strings header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_STRINGS_H`，以声明 `<strings.h>` 在该配置中不可用。

#### Scenario: strings header remains disabled
- **GIVEN** 源码以配置宏判断 BSD 字符串头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_STRINGS_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_STRINGS_H`, `configure.ac:HAVE_STRINGS_H`

### Requirement: HAVE_STRING_H declares string header availability
系统 MUST 在 PS3 配置头中定义 `HAVE_STRING_H` 为 `1`，表示 `<string.h>` 对条件编译使用方可用。

#### Scenario: string header capability is visible
- **GIVEN** 源码以配置宏判断字符串头能力
- **WHEN** 读取 `HAVE_STRING_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<string.h>` 可用

Trace: `include/ps3/config.h:HAVE_STRING_H`, `lib/socket.c:58`

### Requirement: HAVE_SYS_ERRNO_H declares sys errno header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_SYS_ERRNO_H`，以声明 `<sys/errno.h>` 在该配置中不可用。

#### Scenario: sys errno header remains disabled
- **GIVEN** 源码以配置宏判断系统错误头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_SYS_ERRNO_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_SYS_ERRNO_H`, `configure.ac:HAVE_SYS_ERRNO_H`

### Requirement: HAVE_SYS_FCNTL_H declares sys fcntl header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_SYS_FCNTL_H`，以声明 `<sys/fcntl.h>` 在该配置中不可用。

#### Scenario: sys fcntl header remains disabled
- **GIVEN** 源码以配置宏判断系统文件控制头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_SYS_FCNTL_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_SYS_FCNTL_H`, `configure.ac:HAVE_SYS_FCNTL_H`

### Requirement: HAVE_SYS_IOCTL_H declares sys ioctl header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_SYS_IOCTL_H`，以声明 `<sys/ioctl.h>` 在该配置中不可用。

#### Scenario: sys ioctl header remains disabled
- **GIVEN** 源码以配置宏判断 ioctl 头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_SYS_IOCTL_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_SYS_IOCTL_H`, `configure.ac:HAVE_SYS_IOCTL_H`

### Requirement: HAVE_SYS_POLL_H declares sys poll header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_SYS_POLL_H`，以声明 `<sys/poll.h>` 在该配置中不可用。

#### Scenario: sys poll header remains disabled
- **GIVEN** 源码以配置宏判断系统 poll 头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_SYS_POLL_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_SYS_POLL_H`, `configure.ac:HAVE_SYS_POLL_H`

### Requirement: HAVE_SYS_SOCKET_H declares sys socket header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_SYS_SOCKET_H`，以声明 `<sys/socket.h>` 在该配置中不可用。

#### Scenario: sys socket header remains disabled
- **GIVEN** 源码以配置宏判断 socket API 头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_SYS_SOCKET_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_SYS_SOCKET_H`, `configure.ac:HAVE_SYS_SOCKET_H`

### Requirement: HAVE_SYS_STAT_H declares sys stat header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_SYS_STAT_H`，以声明 `<sys/stat.h>` 在该配置中不可用。

#### Scenario: sys stat header remains disabled
- **GIVEN** 源码以配置宏判断文件状态头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_SYS_STAT_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_SYS_STAT_H`

### Requirement: HAVE_SYS_TIME_H declares sys time header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_SYS_TIME_H`，以声明 `<sys/time.h>` 在该配置中不可用。

#### Scenario: sys time header remains disabled
- **GIVEN** 源码以配置宏判断系统时间头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_SYS_TIME_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_SYS_TIME_H`, `configure.ac:HAVE_SYS_TIME_H`

### Requirement: HAVE_SYS_TYPES_H declares sys types header availability
系统 MUST 在 PS3 配置头中定义 `HAVE_SYS_TYPES_H` 为 `1`，表示 `<sys/types.h>` 对条件编译使用方可用。

#### Scenario: sys types header capability is visible
- **GIVEN** 源码以配置宏判断系统类型头能力
- **WHEN** 读取 `HAVE_SYS_TYPES_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<sys/types.h>` 可用

Trace: `include/ps3/config.h:HAVE_SYS_TYPES_H`, `lib/socket.c:66`

### Requirement: HAVE_SYS_UIO_H declares sys uio header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_SYS_UIO_H`，以声明 `<sys/uio.h>` 在该配置中不可用。

#### Scenario: sys uio header remains disabled
- **GIVEN** 源码以配置宏判断 scatter/gather I/O 头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_SYS_UIO_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_SYS_UIO_H`, `configure.ac:HAVE_SYS_UIO_H`

### Requirement: HAVE_SYS_UNISTD_H declares sys unistd header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_SYS_UNISTD_H`，以声明 `<sys/unistd.h>` 在该配置中不可用。

#### Scenario: sys unistd header remains disabled
- **GIVEN** 源码以配置宏判断系统 POSIX 头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_SYS_UNISTD_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_SYS_UNISTD_H`, `configure.ac:HAVE_SYS_UNISTD_H`

### Requirement: HAVE_SYS__IOVEC_H declares sys iovec header absence
系统 MUST NOT 在 PS3 配置头中定义 `HAVE_SYS__IOVEC_H`，以声明 `<sys/_iovec.h>` 在该配置中不可用。

#### Scenario: sys iovec header remains disabled
- **GIVEN** 源码以配置宏判断私有 iovec 头能力
- **WHEN** 读取 PS3 配置头中的 `HAVE_SYS__IOVEC_H`
- **THEN** 该宏 SHALL 保持未定义状态

Trace: `include/ps3/config.h:HAVE_SYS__IOVEC_H`, `configure.ac:HAVE_SYS__IOVEC_H`

### Requirement: HAVE_TIME_H declares time header availability
系统 MUST 在 PS3 配置头中定义 `HAVE_TIME_H` 为 `1`，表示 `<time.h>` 对时间源码条件编译可用。

#### Scenario: time header capability is visible
- **GIVEN** 源码以配置宏判断标准时间头能力
- **WHEN** 读取 `HAVE_TIME_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<time.h>` 可用

Trace: `include/ps3/config.h:HAVE_TIME_H`, `lib/timestamps.c:38`, `configure.ac:HAVE_TIME_H`

### Requirement: HAVE_UNISTD_H declares unistd header availability
系统 MUST 在 PS3 配置头中定义 `HAVE_UNISTD_H` 为 `1`，表示 `<unistd.h>` 对 POSIX API 条件编译可用。

#### Scenario: unistd header capability is visible
- **GIVEN** 源码以配置宏判断 POSIX 头能力
- **WHEN** 读取 `HAVE_UNISTD_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<unistd.h>` 可用

Trace: `include/ps3/config.h:HAVE_UNISTD_H`, `lib/socket.c:78`, `configure.ac:HAVE_UNISTD_H`

### Requirement: LT_OBJDIR exposes libtool object directory
系统 MUST 在 PS3 配置头中定义 `LT_OBJDIR` 为字符串 `".libs/"`，保留生成配置头的 libtool 对象目录元数据。

#### Scenario: libtool object directory metadata is readable
- **GIVEN** 源码或诊断工具读取配置头元数据
- **WHEN** 读取 `LT_OBJDIR`
- **THEN** 该宏 SHALL 展开为字符串 `".libs/"`

Trace: `include/ps3/config.h:LT_OBJDIR`

### Requirement: PACKAGE exposes package short name
系统 MUST 在 PS3 配置头中定义 `PACKAGE` 为字符串 `"libsmb2"`，表示包短名。

#### Scenario: package short name is readable
- **GIVEN** 源码或诊断工具读取包元数据
- **WHEN** 读取 `PACKAGE`
- **THEN** 该宏 SHALL 展开为字符串 `"libsmb2"`

Trace: `include/ps3/config.h:PACKAGE`

### Requirement: PACKAGE_BUGREPORT exposes bug report contact
系统 MUST 在 PS3 配置头中定义 `PACKAGE_BUGREPORT` 为字符串 `"ronniesahlberg@gmail.com"`，表示问题报告地址。

#### Scenario: bug report contact is readable
- **GIVEN** 源码或诊断工具读取包元数据
- **WHEN** 读取 `PACKAGE_BUGREPORT`
- **THEN** 该宏 SHALL 展开为字符串 `"ronniesahlberg@gmail.com"`

Trace: `include/ps3/config.h:PACKAGE_BUGREPORT`

### Requirement: PACKAGE_NAME exposes package full name
系统 MUST 在 PS3 配置头中定义 `PACKAGE_NAME` 为字符串 `"libsmb2"`，表示包全名。

#### Scenario: package full name is readable
- **GIVEN** 源码或诊断工具读取包元数据
- **WHEN** 读取 `PACKAGE_NAME`
- **THEN** 该宏 SHALL 展开为字符串 `"libsmb2"`

Trace: `include/ps3/config.h:PACKAGE_NAME`

### Requirement: PACKAGE_STRING exposes package name and version
系统 MUST 在 PS3 配置头中定义 `PACKAGE_STRING` 为字符串 `"libsmb2 4.0.0"`，表示包名和版本组合。

#### Scenario: package string is readable
- **GIVEN** 源码或诊断工具读取包元数据
- **WHEN** 读取 `PACKAGE_STRING`
- **THEN** 该宏 SHALL 展开为字符串 `"libsmb2 4.0.0"`

Trace: `include/ps3/config.h:PACKAGE_STRING`

### Requirement: PACKAGE_TARNAME exposes distribution tar name
系统 MUST 在 PS3 配置头中定义 `PACKAGE_TARNAME` 为字符串 `"libsmb2"`，表示发行包名。

#### Scenario: distribution tar name is readable
- **GIVEN** 源码或诊断工具读取包元数据
- **WHEN** 读取 `PACKAGE_TARNAME`
- **THEN** 该宏 SHALL 展开为字符串 `"libsmb2"`

Trace: `include/ps3/config.h:PACKAGE_TARNAME`

### Requirement: PACKAGE_URL exposes package URL string
系统 MUST 在 PS3 配置头中定义 `PACKAGE_URL` 为空字符串，表示该配置未声明主页 URL。

#### Scenario: package URL metadata is readable
- **GIVEN** 源码或诊断工具读取包元数据
- **WHEN** 读取 `PACKAGE_URL`
- **THEN** 该宏 SHALL 展开为空字符串

Trace: `include/ps3/config.h:PACKAGE_URL`

### Requirement: PACKAGE_VERSION exposes PS3 package version
系统 MUST 在 PS3 配置头中定义 `PACKAGE_VERSION` 为字符串 `"4.0.0"`，表示该配置头记录的包版本。

#### Scenario: package version is readable
- **GIVEN** 源码或诊断工具读取包元数据
- **WHEN** 读取 `PACKAGE_VERSION`
- **THEN** 该宏 SHALL 展开为字符串 `"4.0.0"`

Trace: `include/ps3/config.h:PACKAGE_VERSION`

### Requirement: STDC_HEADERS declares C90 standard header availability
系统 MUST 在 PS3 配置头中定义 `STDC_HEADERS` 为 `1`，表示 C90 标准头集合可用。

#### Scenario: standard header capability is visible
- **GIVEN** 源码以配置宏判断 C90 标准头集合能力
- **WHEN** 读取 `STDC_HEADERS`
- **THEN** 该宏 SHALL 以定义值 `1` 表示标准头集合可用

Trace: `include/ps3/config.h:STDC_HEADERS`, `lib/timestamps.c:46`, `lib/socket.c:18`

### Requirement: VERSION exposes PS3 version string
系统 MUST 在 PS3 配置头中定义 `VERSION` 为字符串 `"4.0.0"`，表示该配置头记录的版本号。

#### Scenario: version string is readable
- **GIVEN** 源码或诊断工具读取版本元数据
- **WHEN** 读取 `VERSION`
- **THEN** 该宏 SHALL 展开为字符串 `"4.0.0"`

Trace: `include/ps3/config.h:VERSION`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | PS3 配置头中的 `PACKAGE_VERSION`/`VERSION` 为 `4.0.0`，而顶层 CMake 项目版本和 `configure.ac` 当前项目版本为 `6.1.0`；该差异是否为有意保留的 PS3 固定配置版本？ | PACKAGE_VERSION, VERSION, PACKAGE_STRING | 源码证据确认存在版本差异，但未发现说明该差异的测试或文档。 |
| Q-002 | GitNexus `impact "CONFIGURE_OPTION_TCP_LINGER" --include-tests --repo libsmb2` 因多个平台 `config.h` 中同名宏而返回 ambiguous；PS3 单宏的完整上游影响是否仅限源码搜索发现的 `lib/socket.c` 分支仍待确认。 | CONFIGURE_OPTION_TCP_LINGER | GitNexus 已定位当前文件宏 context，但 impact 无法按文件消歧。 |
