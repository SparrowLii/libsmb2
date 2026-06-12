# include/xbox/config.h Specification

## Source Context

- Source: `include/xbox/config.h`
- Related Headers: `config.h.in`, `configure.ac`
- Related Tests: `none`
- Related Dependencies: GitNexus `context "CONFIGURE_OPTION_TCP_LINGER" --file "include/xbox/config.h" --content --repo libsmb2` located `Macro:include/xbox/config.h:CONFIGURE_OPTION_TCP_LINGER` with no indexed incoming/outgoing/processes; GitNexus `impact "CONFIGURE_OPTION_TCP_LINGER" --include-tests --repo libsmb2` is ambiguous across platform config headers.
- Build/Compile Context: Xbox platform configuration header generated from Autotools `config.h.in`; `PROJECT_CONTEXT.md` records `configure.ac` config header generation and compile-time feature macros including `CONFIGURE_OPTION_TCP_LINGER`, `HAVE_SOCKADDR_STORAGE`, and `HAVE_LINGER`.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| CONFIGURE_OPTION_TCP_LINGER | macro | #define CONFIGURE_OPTION_TCP_LINGER 1 | Include | Xbox 配置头公开 TCP linger 构建开关，`lib/socket.c` 可据此选择 socket 关闭策略分支。 |
| HAVE_ARPA_INET_H | macro | /* #undef HAVE_ARPA_INET_H */ | Include | Xbox 配置显式声明 `<arpa/inet.h>` 不可用，影响网络头条件包含。 |
| HAVE_DLFCN_H | macro | /* #undef HAVE_DLFCN_H */ | Include | Xbox 配置显式声明 `<dlfcn.h>` 不可用，属于可观察的系统头能力宏。 |
| HAVE_ERRNO_H | macro | #define HAVE_ERRNO_H 1 | Include | Xbox 配置声明 `<errno.h>` 可用，供错误处理源码条件包含。 |
| HAVE_FCNTL_H | macro | #define HAVE_FCNTL_H 1 | Include | Xbox 配置声明 `<fcntl.h>` 可用，供文件控制源码条件包含。 |
| HAVE_GSSAPI_GSSAPI_H | macro | /* #undef HAVE_GSSAPI_GSSAPI_H */ | Include | Xbox 配置显式声明 GSSAPI 头不可用，影响认证条件能力。 |
| HAVE_INTTYPES_H | macro | /* #undef HAVE_INTTYPES_H */ | Include | Xbox 配置显式声明 `<inttypes.h>` 不可用，影响固定宽度整数格式头路径。 |
| HAVE_LIBKRB5 | macro | /* #undef HAVE_LIBKRB5 */ | Include | Xbox 配置显式声明 krb5 库不可用，影响 Kerberos 条件编译。 |
| HAVE_LIBNSL | macro | /* #undef HAVE_LIBNSL */ | Include | Xbox 配置显式声明 `nsl` 库不可用，属于链接能力契约。 |
| HAVE_LIBSOCKET | macro | /* #undef HAVE_LIBSOCKET */ | Include | Xbox 配置显式声明单独 `socket` 库不可用，属于链接能力契约。 |
| HAVE_LINGER | macro | #define HAVE_LINGER 1 | Include | Xbox 配置声明系统提供 linger 能力，影响本地兼容结构定义分支。 |
| HAVE_NETDB_H | macro | /* #undef HAVE_NETDB_H */ | Include | Xbox 配置显式声明 `<netdb.h>` 不可用，影响地址解析头条件包含。 |
| HAVE_NETINET_IN_H | macro | /* #undef HAVE_NETINET_IN_H */ | Include | Xbox 配置显式声明 `<netinet/in.h>` 不可用，影响网络结构头条件包含。 |
| HAVE_NETINET_TCP_H | macro | /* #undef HAVE_NETINET_TCP_H */ | Include | Xbox 配置显式声明 `<netinet/tcp.h>` 不可用，影响 TCP 选项头条件包含。 |
| HAVE_POLL_H | macro | /* #undef HAVE_POLL_H */ | Include | Xbox 配置显式声明 `<poll.h>` 不可用，影响 poll 头条件包含。 |
| HAVE_SOCKADDR_LEN | macro | /* #undef HAVE_SOCKADDR_LEN */ | Include | Xbox 配置显式声明 sockaddr 不含 `sa_len` 成员，影响地址结构布局假设。 |
| HAVE_SOCKADDR_STORAGE | macro | #define HAVE_SOCKADDR_STORAGE 1 | Include | Xbox 配置声明 `sockaddr_storage` 可用，影响 socket 地址存储能力。 |
| HAVE_STDINT_H | macro | /* #undef HAVE_STDINT_H */ | Include | Xbox 配置显式声明 `<stdint.h>` 不可用，影响标准整数头路径。 |
| HAVE_STDIO_H | macro | #define HAVE_STDIO_H 1 | Include | Xbox 配置声明 `<stdio.h>` 可用，供标准 I/O 源码条件包含。 |
| HAVE_STDLIB_H | macro | #define HAVE_STDLIB_H 1 | Include | Xbox 配置声明 `<stdlib.h>` 可用，供分配和转换源码条件包含。 |
| HAVE_STRINGS_H | macro | /* #undef HAVE_STRINGS_H */ | Include | Xbox 配置显式声明 `<strings.h>` 不可用，影响 BSD 字符串头路径。 |
| HAVE_STRING_H | macro | #define HAVE_STRING_H 1 | Include | Xbox 配置声明 `<string.h>` 可用，供字符串操作源码条件包含。 |
| HAVE_SYS_ERRNO_H | macro | /* #undef HAVE_SYS_ERRNO_H */ | Include | Xbox 配置显式声明 `<sys/errno.h>` 不可用，影响系统 errno 头路径。 |
| HAVE_SYS_FCNTL_H | macro | /* #undef HAVE_SYS_FCNTL_H */ | Include | Xbox 配置显式声明 `<sys/fcntl.h>` 不可用，影响系统 fcntl 头路径。 |
| HAVE_SYS_IOCTL_H | macro | /* #undef HAVE_SYS_IOCTL_H */ | Include | Xbox 配置显式声明 `<sys/ioctl.h>` 不可用，影响 ioctl 头路径。 |
| HAVE_SYS_POLL_H | macro | /* #undef HAVE_SYS_POLL_H */ | Include | Xbox 配置显式声明 `<sys/poll.h>` 不可用，影响系统 poll 头路径。 |
| HAVE_SYS_SOCKET_H | macro | /* #undef HAVE_SYS_SOCKET_H */ | Include | Xbox 配置显式声明 `<sys/socket.h>` 不可用，影响 socket API 头路径。 |
| HAVE_SYS_STAT_H | macro | #define HAVE_SYS_STAT_H 1 | Include | Xbox 配置声明 `<sys/stat.h>` 可用，供文件状态源码条件包含。 |
| HAVE_SYS_TIME_H | macro | /* #undef HAVE_SYS_TIME_H */ | Include | Xbox 配置显式声明 `<sys/time.h>` 不可用，影响时间头路径。 |
| HAVE_SYS_TYPES_H | macro | #define HAVE_SYS_TYPES_H 1 | Include | Xbox 配置声明 `<sys/types.h>` 可用，供系统基础类型源码条件包含。 |
| HAVE_SYS_UIO_H | macro | /* #undef HAVE_SYS_UIO_H */ | Include | Xbox 配置显式声明 `<sys/uio.h>` 不可用，影响 scatter/gather I/O 头路径。 |
| HAVE_SYS_UNISTD_H | macro | /* #undef HAVE_SYS_UNISTD_H */ | Include | Xbox 配置显式声明 `<sys/unistd.h>` 不可用，影响 POSIX 头路径。 |
| HAVE_SYS__IOVEC_H | macro | /* #undef HAVE_SYS__IOVEC_H */ | Include | Xbox 配置显式声明 `<sys/_iovec.h>` 不可用，影响备用 iovec 头路径。 |
| HAVE_TIME_H | macro | #define HAVE_TIME_H 1 | Include | Xbox 配置声明 `<time.h>` 可用，供时间源码条件包含。 |
| HAVE_UNISTD_H | macro | /* #undef HAVE_UNISTD_H */ | Include | Xbox 配置显式声明 `<unistd.h>` 不可用，影响 POSIX API 头路径。 |
| LT_OBJDIR | macro | #define LT_OBJDIR ".libs/" | Include | Xbox 配置公开 libtool 未安装对象目录字符串。 |
| PACKAGE | macro | #define PACKAGE "libsmb2" | Include | Xbox 配置公开包短名，属于 Autotools 包元数据。 |
| PACKAGE_BUGREPORT | macro | #define PACKAGE_BUGREPORT "ronniesahlberg@gmail.com" | Include | Xbox 配置公开包问题报告地址，属于包元数据。 |
| PACKAGE_NAME | macro | #define PACKAGE_NAME "libsmb2" | Include | Xbox 配置公开包全名，属于包元数据。 |
| PACKAGE_STRING | macro | #define PACKAGE_STRING "libsmb2 4.0.0" | Include | Xbox 配置公开包名和版本组合，属于包元数据。 |
| PACKAGE_TARNAME | macro | #define PACKAGE_TARNAME "libsmb2" | Include | Xbox 配置公开发行包名，属于包元数据。 |
| PACKAGE_URL | macro | #define PACKAGE_URL "" | Include | Xbox 配置公开空主页 URL 字符串，属于包元数据。 |
| PACKAGE_VERSION | macro | #define PACKAGE_VERSION "4.0.0" | Include | Xbox 配置公开包版本字符串，且与当前项目上下文版本存在差异。 |
| STDC_HEADERS | macro | #define STDC_HEADERS 1 | Include | Xbox 配置声明 C90 标准头集合可用，影响标准头兼容条件。 |
| VERSION | macro | #define VERSION "4.0.0" | Include | Xbox 配置公开版本号字符串，且与当前项目上下文版本存在差异。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| CONFIGURE_OPTION_TCP_LINGER | macro | include/xbox/config.h:5 | 取值为 `1`，表示 Xbox 配置允许 TCP socket linger；`lib/socket.c` 只在该值为 `0` 时启用禁用 linger 的分支。 |
| HAVE_ARPA_INET_H | macro | include/xbox/config.h:8 | 平台能力宏以定义或 `#undef` 注释形式记录 Xbox 可用头文件、库和结构能力；同类宏详见 Interface Summary。 |
| HAVE_LINGER | macro | include/xbox/config.h:35 | 取值为 `1`，声明系统 linger 能力可用。 |
| HAVE_SOCKADDR_STORAGE | macro | include/xbox/config.h:53 | 取值为 `1`，声明 `sockaddr_storage` 能力可用。 |
| PACKAGE | macro | include/xbox/config.h:113 | 包元数据宏声明 Xbox 配置头中的包名、版本和联系信息；同类宏详见 Interface Summary。 |
| STDC_HEADERS | macro | include/xbox/config.h:136 | 取值为 `1`，保留 Autoconf 标准头兼容信号。 |

## ADDED Requirements

### Requirement: CONFIGURE_OPTION_TCP_LINGER controls Xbox socket linger policy
系统 MUST 在 Xbox 配置头中将 `CONFIGURE_OPTION_TCP_LINGER` 暴露为值 `1`，使包含 `config.h` 的 socket 源码看到 Xbox 配置允许 TCP linger 的编译时策略。

#### Scenario: Xbox 配置保留默认 linger 行为
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** `lib/socket.c` 在连接或接受 socket 的路径中检查 `#if 0 == CONFIGURE_OPTION_TCP_LINGER`
- **THEN** Xbox 配置取值 `1` SHALL 使该条件为假，源码不编译设置 `SO_REUSEADDR` 和零秒 `SO_LINGER` 的分支

Trace: `include/xbox/config.h:CONFIGURE_OPTION_TCP_LINGER`, `lib/socket.c:connect_async_ai`, `lib/socket.c:smb2_accept_connection_async`

### Requirement: HAVE_ARPA_INET_H declares arpa inet header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_ARPA_INET_H`，以声明 `<arpa/inet.h>` 在该配置中不可用。

#### Scenario: arpa inet 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_ARPA_INET_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_ARPA_INET_H`

### Requirement: HAVE_DLFCN_H declares dlfcn header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_DLFCN_H`，以声明 `<dlfcn.h>` 在该配置中不可用。

#### Scenario: dlfcn 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_DLFCN_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_DLFCN_H`

### Requirement: HAVE_ERRNO_H declares errno header availability
系统 MUST 在 Xbox 配置头中定义 `HAVE_ERRNO_H` 为 `1`，表示 `<errno.h>` 对错误处理条件编译可用。

#### Scenario: errno 头能力可见
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码读取 `HAVE_ERRNO_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<errno.h>` 可用

Trace: `include/xbox/config.h:HAVE_ERRNO_H`

### Requirement: HAVE_FCNTL_H declares fcntl header availability
系统 MUST 在 Xbox 配置头中定义 `HAVE_FCNTL_H` 为 `1`，表示 `<fcntl.h>` 对条件编译使用方可用。

#### Scenario: fcntl 头能力可见
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码读取 `HAVE_FCNTL_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<fcntl.h>` 可用

Trace: `include/xbox/config.h:HAVE_FCNTL_H`

### Requirement: HAVE_GSSAPI_GSSAPI_H declares GSSAPI header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_GSSAPI_GSSAPI_H`，以声明 `<gssapi/gssapi.h>` 在该配置中不可用。

#### Scenario: GSSAPI 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_GSSAPI_GSSAPI_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_GSSAPI_GSSAPI_H`

### Requirement: HAVE_INTTYPES_H declares inttypes header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_INTTYPES_H`，以声明 `<inttypes.h>` 在该配置中不可用。

#### Scenario: inttypes 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_INTTYPES_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_INTTYPES_H`

### Requirement: HAVE_LIBKRB5 declares Kerberos library absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_LIBKRB5`，以声明 libkrb5 支持在该配置中不可用。

#### Scenario: Kerberos 条件编译保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 认证相关源码检查 `HAVE_LIBKRB5` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义，依赖该宏的 Kerberos 条件路径不由该配置启用

Trace: `include/xbox/config.h:HAVE_LIBKRB5`, `lib/spnego-wrapper.c:HAVE_LIBKRB5`

### Requirement: HAVE_LIBNSL declares nsl library absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_LIBNSL`，以声明 `nsl` 链接库在该配置中不可用。

#### Scenario: nsl 链接能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 构建或源码检查 `HAVE_LIBNSL` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_LIBNSL`

### Requirement: HAVE_LIBSOCKET declares socket library absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_LIBSOCKET`，以声明单独的 `socket` 链接库在该配置中不可用。

#### Scenario: socket 链接库能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 构建或源码检查 `HAVE_LIBSOCKET` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_LIBSOCKET`

### Requirement: HAVE_LINGER declares system linger support
系统 MUST 在 Xbox 配置头中定义 `HAVE_LINGER` 为 `1`，表示平台提供 `struct linger`。

#### Scenario: socket 源码不定义兼容 linger 结构
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** `lib/socket.c` 检查 `#if !defined(HAVE_LINGER)`
- **THEN** 源码 SHALL 不启用本地 `struct linger` 兼容定义

Trace: `include/xbox/config.h:HAVE_LINGER`, `lib/socket.c:HAVE_LINGER`

### Requirement: HAVE_NETDB_H declares netdb header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_NETDB_H`，以声明 `<netdb.h>` 在该配置中不可用。

#### Scenario: netdb 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_NETDB_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_NETDB_H`

### Requirement: HAVE_NETINET_IN_H declares netinet in header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_NETINET_IN_H`，以声明 `<netinet/in.h>` 在该配置中不可用。

#### Scenario: netinet in 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_NETINET_IN_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_NETINET_IN_H`

### Requirement: HAVE_NETINET_TCP_H declares netinet tcp header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_NETINET_TCP_H`，以声明 `<netinet/tcp.h>` 在该配置中不可用。

#### Scenario: netinet tcp 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_NETINET_TCP_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_NETINET_TCP_H`

### Requirement: HAVE_POLL_H declares poll header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_POLL_H`，以声明 `<poll.h>` 在该配置中不可用。

#### Scenario: poll 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_POLL_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_POLL_H`

### Requirement: HAVE_SOCKADDR_LEN declares sockaddr length member absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_SOCKADDR_LEN`，以声明 sockaddr 结构没有 `sa_len` 成员。

#### Scenario: 地址结构布局不声明 sa_len
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_SOCKADDR_LEN` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_SOCKADDR_LEN`

### Requirement: HAVE_SOCKADDR_STORAGE declares sockaddr_storage availability
系统 MUST 在 Xbox 配置头中定义 `HAVE_SOCKADDR_STORAGE` 为 `1`，表示 `sockaddr_storage` 类型可用。

#### Scenario: socket 路径可使用通用地址存储
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码读取 `HAVE_SOCKADDR_STORAGE`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `sockaddr_storage` 可用

Trace: `include/xbox/config.h:HAVE_SOCKADDR_STORAGE`

### Requirement: HAVE_STDINT_H declares stdint header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_STDINT_H`，以声明 `<stdint.h>` 在该配置中不可用。

#### Scenario: stdint 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_STDINT_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_STDINT_H`

### Requirement: HAVE_STDIO_H declares stdio header availability
系统 MUST 在 Xbox 配置头中定义 `HAVE_STDIO_H` 为 `1`，表示 `<stdio.h>` 对条件编译使用方可用。

#### Scenario: 标准 I/O 头能力可见
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码读取 `HAVE_STDIO_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<stdio.h>` 可用

Trace: `include/xbox/config.h:HAVE_STDIO_H`

### Requirement: HAVE_STDLIB_H declares stdlib header availability
系统 MUST 在 Xbox 配置头中定义 `HAVE_STDLIB_H` 为 `1`，表示 `<stdlib.h>` 对条件编译使用方可用。

#### Scenario: 标准库头能力可见
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码读取 `HAVE_STDLIB_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<stdlib.h>` 可用

Trace: `include/xbox/config.h:HAVE_STDLIB_H`

### Requirement: HAVE_STRINGS_H declares strings header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_STRINGS_H`，以声明 `<strings.h>` 在该配置中不可用。

#### Scenario: strings 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_STRINGS_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_STRINGS_H`

### Requirement: HAVE_STRING_H declares string header availability
系统 MUST 在 Xbox 配置头中定义 `HAVE_STRING_H` 为 `1`，表示 `<string.h>` 对条件编译使用方可用。

#### Scenario: C 字符串头能力可见
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码读取 `HAVE_STRING_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<string.h>` 可用

Trace: `include/xbox/config.h:HAVE_STRING_H`

### Requirement: HAVE_SYS_ERRNO_H declares sys errno header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_SYS_ERRNO_H`，以声明 `<sys/errno.h>` 在该配置中不可用。

#### Scenario: sys errno 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_SYS_ERRNO_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_SYS_ERRNO_H`

### Requirement: HAVE_SYS_FCNTL_H declares sys fcntl header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_SYS_FCNTL_H`，以声明 `<sys/fcntl.h>` 在该配置中不可用。

#### Scenario: sys fcntl 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_SYS_FCNTL_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_SYS_FCNTL_H`

### Requirement: HAVE_SYS_IOCTL_H declares sys ioctl header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_SYS_IOCTL_H`，以声明 `<sys/ioctl.h>` 在该配置中不可用。

#### Scenario: sys ioctl 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_SYS_IOCTL_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_SYS_IOCTL_H`

### Requirement: HAVE_SYS_POLL_H declares sys poll header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_SYS_POLL_H`，以声明 `<sys/poll.h>` 在该配置中不可用。

#### Scenario: sys poll 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_SYS_POLL_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_SYS_POLL_H`

### Requirement: HAVE_SYS_SOCKET_H declares sys socket header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_SYS_SOCKET_H`，以声明 `<sys/socket.h>` 在该配置中不可用。

#### Scenario: sys socket 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_SYS_SOCKET_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_SYS_SOCKET_H`

### Requirement: HAVE_SYS_STAT_H declares sys stat header availability
系统 MUST 在 Xbox 配置头中定义 `HAVE_SYS_STAT_H` 为 `1`，表示 `<sys/stat.h>` 对条件编译使用方可用。

#### Scenario: 文件状态头能力可见
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码读取 `HAVE_SYS_STAT_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<sys/stat.h>` 可用

Trace: `include/xbox/config.h:HAVE_SYS_STAT_H`

### Requirement: HAVE_SYS_TIME_H declares sys time header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_SYS_TIME_H`，以声明 `<sys/time.h>` 在该配置中不可用。

#### Scenario: sys time 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_SYS_TIME_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_SYS_TIME_H`

### Requirement: HAVE_SYS_TYPES_H declares sys types header availability
系统 MUST 在 Xbox 配置头中定义 `HAVE_SYS_TYPES_H` 为 `1`，表示 `<sys/types.h>` 对条件编译使用方可用。

#### Scenario: 系统基础类型头能力可见
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码读取 `HAVE_SYS_TYPES_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<sys/types.h>` 可用

Trace: `include/xbox/config.h:HAVE_SYS_TYPES_H`

### Requirement: HAVE_SYS_UIO_H declares sys uio header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_SYS_UIO_H`，以声明 `<sys/uio.h>` 在该配置中不可用。

#### Scenario: sys uio 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_SYS_UIO_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_SYS_UIO_H`

### Requirement: HAVE_SYS_UNISTD_H declares sys unistd header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_SYS_UNISTD_H`，以声明 `<sys/unistd.h>` 在该配置中不可用。

#### Scenario: sys unistd 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_SYS_UNISTD_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_SYS_UNISTD_H`

### Requirement: HAVE_SYS__IOVEC_H declares sys iovec header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_SYS__IOVEC_H`，以声明 `<sys/_iovec.h>` 在该配置中不可用。

#### Scenario: sys iovec 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_SYS__IOVEC_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_SYS__IOVEC_H`

### Requirement: HAVE_TIME_H declares time header availability
系统 MUST 在 Xbox 配置头中定义 `HAVE_TIME_H` 为 `1`，表示 `<time.h>` 对条件编译使用方可用。

#### Scenario: time 头能力可见
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码读取 `HAVE_TIME_H`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 `<time.h>` 可用

Trace: `include/xbox/config.h:HAVE_TIME_H`

### Requirement: HAVE_UNISTD_H declares unistd header absence
系统 MUST NOT 在 Xbox 配置头中定义 `HAVE_UNISTD_H`，以声明 `<unistd.h>` 在该配置中不可用。

#### Scenario: unistd 头能力保持禁用
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码检查 `HAVE_UNISTD_H` 是否定义
- **THEN** 预处理器 SHALL 将该宏视为未定义

Trace: `include/xbox/config.h:HAVE_UNISTD_H`

### Requirement: LT_OBJDIR exposes libtool object directory
系统 MUST 在 Xbox 配置头中定义 `LT_OBJDIR` 为字符串 `".libs/"`，表示 libtool 未安装对象目录名称。

#### Scenario: 读取 libtool 对象目录元数据
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码或诊断工具读取 `LT_OBJDIR`
- **THEN** 该宏 SHALL 展开为字符串 `".libs/"`

Trace: `include/xbox/config.h:LT_OBJDIR`

### Requirement: PACKAGE exposes package short name
系统 MUST 在 Xbox 配置头中定义 `PACKAGE` 为字符串 `"libsmb2"`，表示包短名。

#### Scenario: 读取包短名
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码或诊断工具读取 `PACKAGE`
- **THEN** 该宏 SHALL 展开为字符串 `"libsmb2"`

Trace: `include/xbox/config.h:PACKAGE`

### Requirement: PACKAGE_BUGREPORT exposes bug report contact
系统 MUST 在 Xbox 配置头中定义 `PACKAGE_BUGREPORT` 为字符串 `"ronniesahlberg@gmail.com"`，表示问题报告地址。

#### Scenario: 读取问题报告地址
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码或诊断工具读取 `PACKAGE_BUGREPORT`
- **THEN** 该宏 SHALL 展开为字符串 `"ronniesahlberg@gmail.com"`

Trace: `include/xbox/config.h:PACKAGE_BUGREPORT`

### Requirement: PACKAGE_NAME exposes package full name
系统 MUST 在 Xbox 配置头中定义 `PACKAGE_NAME` 为字符串 `"libsmb2"`，表示包全名。

#### Scenario: 读取包全名
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码或诊断工具读取 `PACKAGE_NAME`
- **THEN** 该宏 SHALL 展开为字符串 `"libsmb2"`

Trace: `include/xbox/config.h:PACKAGE_NAME`

### Requirement: PACKAGE_STRING exposes package name and version
系统 MUST 在 Xbox 配置头中定义 `PACKAGE_STRING` 为字符串 `"libsmb2 4.0.0"`，表示包名和版本组合。

#### Scenario: 读取包名版本组合
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码或诊断工具读取 `PACKAGE_STRING`
- **THEN** 该宏 SHALL 展开为字符串 `"libsmb2 4.0.0"`

Trace: `include/xbox/config.h:PACKAGE_STRING`

### Requirement: PACKAGE_TARNAME exposes distribution tar name
系统 MUST 在 Xbox 配置头中定义 `PACKAGE_TARNAME` 为字符串 `"libsmb2"`，表示发行包名。

#### Scenario: 读取发行包名
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码或诊断工具读取 `PACKAGE_TARNAME`
- **THEN** 该宏 SHALL 展开为字符串 `"libsmb2"`

Trace: `include/xbox/config.h:PACKAGE_TARNAME`

### Requirement: PACKAGE_URL exposes package URL string
系统 MUST 在 Xbox 配置头中定义 `PACKAGE_URL` 为空字符串，表示该配置未声明主页 URL。

#### Scenario: 读取包主页元数据
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码或诊断工具读取 `PACKAGE_URL`
- **THEN** 该宏 SHALL 展开为空字符串

Trace: `include/xbox/config.h:PACKAGE_URL`

### Requirement: PACKAGE_VERSION exposes Xbox package version
系统 MUST 在 Xbox 配置头中定义 `PACKAGE_VERSION` 为字符串 `"4.0.0"`，表示该配置头记录的包版本。

#### Scenario: 读取包版本
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码或诊断工具读取 `PACKAGE_VERSION`
- **THEN** 该宏 SHALL 展开为字符串 `"4.0.0"`

Trace: `include/xbox/config.h:PACKAGE_VERSION`

### Requirement: STDC_HEADERS declares C90 standard header availability
系统 MUST 在 Xbox 配置头中定义 `STDC_HEADERS` 为 `1`，表示 C90 标准头集合可用。

#### Scenario: C90 标准头集合能力可见
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码读取 `STDC_HEADERS`
- **THEN** 该宏 SHALL 以定义值 `1` 表示 C90 标准头集合可用

Trace: `include/xbox/config.h:STDC_HEADERS`

### Requirement: VERSION exposes Xbox version string
系统 MUST 在 Xbox 配置头中定义 `VERSION` 为字符串 `"4.0.0"`，表示该配置头记录的版本号。

#### Scenario: 读取版本号
- **GIVEN** Xbox 目标构建包含 `include/xbox/config.h`
- **WHEN** 源码或诊断工具读取 `VERSION`
- **THEN** 该宏 SHALL 展开为字符串 `"4.0.0"`

Trace: `include/xbox/config.h:VERSION`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | Xbox 配置头中的 `PACKAGE_VERSION`/`VERSION` 为 `4.0.0`，而 `PROJECT_CONTEXT.md` 记录当前 CMake/Autotools 项目版本为 `6.1.0`；该差异是否为有意保留的 Xbox 固定配置版本？ | PACKAGE_VERSION, VERSION, PACKAGE_STRING | 源码证据确认存在版本差异，但未发现说明该差异的测试或文档。 |
| Q-002 | GitNexus `impact "CONFIGURE_OPTION_TCP_LINGER" --include-tests --repo libsmb2` 因多个平台 `config.h` 中同名宏而返回 ambiguous；Xbox 单宏的完整上游影响是否仅限源码回读发现的 `lib/socket.c` 分支仍待确认。 | CONFIGURE_OPTION_TCP_LINGER | GitNexus 已定位当前文件宏 context，但 impact 无法按文件消歧。 |
