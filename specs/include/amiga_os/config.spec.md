# include/amiga_os/config.h Specification

## Source Context

- Source: `include/amiga_os/config.h`
- Related Headers: `none`
- Related Tests: `none`
- Related Dependencies: `lib/socket.c` 条件引用多个 `HAVE_*` 宏和 `CONFIGURE_OPTION_TCP_LINGER`；GitNexus `context -r libsmb2 "CONFIGURE_OPTION_TCP_LINGER" --file "include/amiga_os/config.h" --content` 返回该宏定义但无 incoming/outgoing/processes。
- Build/Compile Context: Autotools 生成的 Amiga OS 平台配置头；`PROJECT_CONTEXT.md` 记录 `configure.ac` 生成 config header，并记录 `CONFIGURE_OPTION_TCP_LINGER`、`HAVE_SOCKADDR_LEN`、`HAVE_LINGER` 等 configure-time 条件。

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| CONFIGURE_OPTION_TCP_LINGER | macro | #define CONFIGURE_OPTION_TCP_LINGER 1 | Include | 对 socket 连接关闭 linger 行为提供平台编译期开关，`lib/socket.c` 以 `#if 0 == CONFIGURE_OPTION_TCP_LINGER` 条件使用。 |
| HAVE_ARPA_INET_H | macro | #define HAVE_ARPA_INET_H 1 | Include | 声明 Amiga OS 配置存在 `<arpa/inet.h>`，调用方可据此启用头文件包含。 |
| HAVE_DLFCN_H | macro | #define HAVE_DLFCN_H 1 | Include | 声明 Amiga OS 配置存在 `<dlfcn.h>`，属于可观察的配置能力宏。 |
| HAVE_ERRNO_H | macro | #define HAVE_ERRNO_H 1 | Include | 声明 Amiga OS 配置存在 `<errno.h>`，多个源码文件以该类宏控制系统头包含。 |
| HAVE_FCNTL_H | macro | #define HAVE_FCNTL_H 1 | Include | 声明 Amiga OS 配置存在 `<fcntl.h>`，`lib/socket.c` 等以该宏控制头文件包含。 |
| HAVE_GSSAPI_GSSAPI_H | macro | /* #undef HAVE_GSSAPI_GSSAPI_H */ | Include | 显式声明 Amiga OS 配置未启用 `<gssapi/gssapi.h>`，影响 Kerberos/GSSAPI 条件能力。 |
| HAVE_INTTYPES_H | macro | #define HAVE_INTTYPES_H 1 | Include | 声明 Amiga OS 配置存在 `<inttypes.h>`，属于编译能力宏。 |
| HAVE_LIBKRB5 | macro | /* #undef HAVE_LIBKRB5 */ | Include | 显式声明 Amiga OS 配置未启用 krb5 库，源码以该宏控制 Kerberos 相关实现。 |
| HAVE_LIBNSL | macro | /* #undef HAVE_LIBNSL */ | Include | 显式声明 Amiga OS 配置未启用 `nsl` 库，属于平台链接能力宏。 |
| HAVE_LIBSOCKET | macro | /* #undef HAVE_LIBSOCKET */ | Include | 显式声明 Amiga OS 配置未启用 `socket` 库，属于平台链接能力宏。 |
| HAVE_LINGER | macro | /* #undef HAVE_LINGER */ | Include | 显式声明 Amiga OS 配置缺少系统 linger 定义，`lib/socket.c` 会提供本地 `struct linger`。 |
| HAVE_NETDB_H | macro | #define HAVE_NETDB_H 1 | Include | 声明 Amiga OS 配置存在 `<netdb.h>`，`lib/socket.c` 以该宏控制头文件包含。 |
| HAVE_NETINET_IN_H | macro | #define HAVE_NETINET_IN_H 1 | Include | 声明 Amiga OS 配置存在 `<netinet/in.h>`，`lib/socket.c` 以该宏控制头文件包含。 |
| HAVE_NETINET_TCP_H | macro | #define HAVE_NETINET_TCP_H 1 | Include | 声明 Amiga OS 配置存在 `<netinet/tcp.h>`，`lib/socket.c` 以该宏控制 TCP 选项声明。 |
| HAVE_POLL_H | macro | /* #undef HAVE_POLL_H */ | Include | 显式声明 Amiga OS 配置缺少 `<poll.h>`，影响 poll 头文件条件包含。 |
| HAVE_SOCKADDR_LEN | macro | #define HAVE_SOCKADDR_LEN 1 | Include | 声明 Amiga OS `sockaddr` 结构具有 `sa_len` 成员，属于结构布局能力宏。 |
| HAVE_SOCKADDR_STORAGE | macro | /* #undef HAVE_SOCKADDR_STORAGE */ | Include | 显式声明 Amiga OS 配置缺少 `sockaddr_storage` 能力，属于 socket 数据模型能力宏。 |
| HAVE_STDINT_H | macro | #define HAVE_STDINT_H 1 | Include | 声明 Amiga OS 配置存在 `<stdint.h>`，多个源码文件以该宏控制标准整数类型包含。 |
| HAVE_STDIO_H | macro | #define HAVE_STDIO_H 1 | Include | 声明 Amiga OS 配置存在 `<stdio.h>`，属于编译能力宏。 |
| HAVE_STDLIB_H | macro | #define HAVE_STDLIB_H 1 | Include | 声明 Amiga OS 配置存在 `<stdlib.h>`，多个源码文件以该宏控制标准库包含。 |
| HAVE_STRINGS_H | macro | #define HAVE_STRINGS_H 1 | Include | 声明 Amiga OS 配置存在 `<strings.h>`，属于编译能力宏。 |
| HAVE_STRING_H | macro | #define HAVE_STRING_H 1 | Include | 声明 Amiga OS 配置存在 `<string.h>`，多个源码文件以该宏控制字符串函数声明。 |
| HAVE_SYS_ERRNO_H | macro | #define HAVE_SYS_ERRNO_H 1 | Include | 声明 Amiga OS 配置存在 `<sys/errno.h>`，属于系统头能力宏。 |
| HAVE_SYS_FCNTL_H | macro | #define HAVE_SYS_FCNTL_H 1 | Include | 声明 Amiga OS 配置存在 `<sys/fcntl.h>`，`lib/socket.c` 以该宏控制头文件包含。 |
| HAVE_SYS_IOCTL_H | macro | #define HAVE_SYS_IOCTL_H 1 | Include | 声明 Amiga OS 配置存在 `<sys/ioctl.h>`，`lib/socket.c` 以该宏控制 ioctl 声明。 |
| HAVE_SYS_POLL_H | macro | /* #undef HAVE_SYS_POLL_H */ | Include | 显式声明 Amiga OS 配置缺少 `<sys/poll.h>`，影响 poll 头文件条件包含。 |
| HAVE_SYS_SOCKET_H | macro | #define HAVE_SYS_SOCKET_H 1 | Include | 声明 Amiga OS 配置存在 `<sys/socket.h>`，`lib/socket.c` 以该宏控制 socket 声明。 |
| HAVE_SYS_STAT_H | macro | #define HAVE_SYS_STAT_H 1 | Include | 声明 Amiga OS 配置存在 `<sys/stat.h>`，多个源码文件以该宏控制系统状态类型包含。 |
| HAVE_SYS_TIME_H | macro | #define HAVE_SYS_TIME_H 1 | Include | 声明 Amiga OS 配置存在 `<sys/time.h>`，多个源码文件以该宏控制时间类型包含。 |
| HAVE_SYS_TYPES_H | macro | #define HAVE_SYS_TYPES_H 1 | Include | 声明 Amiga OS 配置存在 `<sys/types.h>`，多个源码文件以该宏控制系统基础类型包含。 |
| HAVE_SYS_UIO_H | macro | #define HAVE_SYS_UIO_H 1 | Include | 声明 Amiga OS 配置存在 `<sys/uio.h>`，`lib/socket.c` 以该宏控制 iovec 声明。 |
| HAVE_SYS_UNISTD_H | macro | #define HAVE_SYS_UNISTD_H 1 | Include | 声明 Amiga OS 配置存在 `<sys/unistd.h>`，多个源码文件以该宏控制 unistd 声明。 |
| HAVE_SYS__IOVEC_H | macro | /* #undef HAVE_SYS__IOVEC_H */ | Include | 显式声明 Amiga OS 配置缺少 `<sys/_iovec.h>`，`lib/socket.c` 以该宏控制备用 iovec 头包含。 |
| HAVE_TIME_H | macro | #define HAVE_TIME_H 1 | Include | 声明 Amiga OS 配置存在 `<time.h>`，多个源码文件以该宏控制时间函数声明。 |
| HAVE_UNISTD_H | macro | #define HAVE_UNISTD_H 1 | Include | 声明 Amiga OS 配置存在 `<unistd.h>`，多个源码文件以该宏控制 POSIX 声明。 |
| LT_OBJDIR | macro | #define LT_OBJDIR ".libs/" | Include | 声明 libtool 未安装对象目录名称，属于构建产物路径配置宏。 |
| PACKAGE | macro | #define PACKAGE "libsmb2" | Include | 声明包短名，属于 Autotools 包元数据宏。 |
| PACKAGE_BUGREPORT | macro | #define PACKAGE_BUGREPORT "ronniesahlberg@gmail.com" | Include | 声明包问题报告地址，属于 Autotools 包元数据宏。 |
| PACKAGE_NAME | macro | #define PACKAGE_NAME "libsmb2" | Include | 声明包全名，属于 Autotools 包元数据宏。 |
| PACKAGE_STRING | macro | #define PACKAGE_STRING "libsmb2 4.0.0" | Include | 声明包名和版本组合，属于 Autotools 包元数据宏。 |
| PACKAGE_TARNAME | macro | #define PACKAGE_TARNAME "libsmb2" | Include | 声明包 tar 名称，属于 Autotools 包元数据宏。 |
| PACKAGE_URL | macro | #define PACKAGE_URL "" | Include | 声明包主页为空字符串，属于 Autotools 包元数据宏。 |
| PACKAGE_VERSION | macro | #define PACKAGE_VERSION "4.0.0" | Include | 声明包版本字符串，属于 Autotools 包元数据宏；与 CMake/Autotools 当前项目上下文版本存在差异。 |
| STDC_HEADERS | macro | #define STDC_HEADERS 1 | Include | 声明 C90 标准头集合存在，多个源码文件以该宏控制标准定义包含。 |
| VERSION | macro | #define VERSION "4.0.0" | Include | 声明包版本号，属于 Autotools 包元数据宏；与项目上下文版本存在差异。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| CONFIGURE_OPTION_TCP_LINGER | macro | include/amiga_os/config.h:5 | Amiga OS 配置将 TCP linger 选项定义为启用。 |
| HAVE_ARPA_INET_H | macro | include/amiga_os/config.h:8 | 系统头、库、结构成员和平台能力探测宏代表项；定义值为 `1` 表示存在，`#undef` 表示不存在或未启用。 |
| LT_OBJDIR | macro | include/amiga_os/config.h:110 | libtool 未安装对象目录配置为 `.libs/`。 |
| PACKAGE | macro | include/amiga_os/config.h:113 | Autotools 包名、报告地址、URL 和版本元数据代表项。 |
| STDC_HEADERS | macro | include/amiga_os/config.h:136 | C90 标准头集合兼容宏定义为 `1`。 |
| VERSION | macro | include/amiga_os/config.h:139 | 包版本号定义为 `4.0.0`。 |

## ADDED Requirements

### Requirement: CONFIGURE_OPTION_TCP_LINGER TCP linger 编译配置
系统 MUST 将 `CONFIGURE_OPTION_TCP_LINGER` 暴露为值 `1` 的预处理宏，使包含该配置头的 Amiga OS 构建路径默认允许 TCP socket 在关闭后 linger。

#### Scenario: Amiga OS 构建读取 TCP linger 配置
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码以 `CONFIGURE_OPTION_TCP_LINGER` 计算 TCP socket linger 条件编译分支
- **THEN** 预处理器应观察到该宏值为 `1`，并且 `lib/socket.c` 中 `#if 0 == CONFIGURE_OPTION_TCP_LINGER` 的禁用 linger 分支不应被该配置启用

Trace: `include/amiga_os/config.h:CONFIGURE_OPTION_TCP_LINGER`, `lib/socket.c:connect_async_ai`

### Requirement: HAVE_ARPA_INET_H arpa inet 头文件能力
系统 MUST 将 `HAVE_ARPA_INET_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<arpa/inet.h>`。

#### Scenario: 条件包含 arpa inet 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_ARPA_INET_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_ARPA_INET_H`, `lib/socket.c:HAVE_ARPA_INET_H`

### Requirement: HAVE_DLFCN_H dlfcn 头文件能力
系统 MUST 将 `HAVE_DLFCN_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<dlfcn.h>`。

#### Scenario: 条件检查 dlfcn 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_DLFCN_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_DLFCN_H`

### Requirement: HAVE_ERRNO_H errno 头文件能力
系统 MUST 将 `HAVE_ERRNO_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<errno.h>`。

#### Scenario: 条件检查 errno 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_ERRNO_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_ERRNO_H`, `lib/spnego-wrapper.c:HAVE_ERRNO_H`

### Requirement: HAVE_FCNTL_H fcntl 头文件能力
系统 MUST 将 `HAVE_FCNTL_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<fcntl.h>`。

#### Scenario: 条件包含 fcntl 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_FCNTL_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_FCNTL_H`, `lib/socket.c:HAVE_FCNTL_H`

### Requirement: HAVE_GSSAPI_GSSAPI_H GSSAPI 头文件禁用配置
系统 MUST NOT 将 `HAVE_GSSAPI_GSSAPI_H` 定义为可用宏，表示 Amiga OS 配置未声明 `<gssapi/gssapi.h>` 可用。

#### Scenario: 条件检查 GSSAPI 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_GSSAPI_GSSAPI_H`
- **THEN** 预处理器应观察到该宏未定义

Trace: `include/amiga_os/config.h:HAVE_GSSAPI_GSSAPI_H`

### Requirement: HAVE_INTTYPES_H inttypes 头文件能力
系统 MUST 将 `HAVE_INTTYPES_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<inttypes.h>`。

#### Scenario: 条件检查 inttypes 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_INTTYPES_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_INTTYPES_H`

### Requirement: HAVE_LIBKRB5 krb5 库禁用配置
系统 MUST NOT 将 `HAVE_LIBKRB5` 定义为可用宏，表示 Amiga OS 配置未启用 krb5 库支持。

#### Scenario: 条件检查 krb5 库支持
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_LIBKRB5`
- **THEN** 预处理器应观察到该宏未定义，并且 Kerberos 相关条件实现不由该配置启用

Trace: `include/amiga_os/config.h:HAVE_LIBKRB5`, `lib/spnego-wrapper.c:HAVE_LIBKRB5`

### Requirement: HAVE_LIBNSL nsl 库禁用配置
系统 MUST NOT 将 `HAVE_LIBNSL` 定义为可用宏，表示 Amiga OS 配置未声明链接 `nsl` 库。

#### Scenario: 条件检查 nsl 库支持
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_LIBNSL`
- **THEN** 预处理器应观察到该宏未定义

Trace: `include/amiga_os/config.h:HAVE_LIBNSL`

### Requirement: HAVE_LIBSOCKET socket 库禁用配置
系统 MUST NOT 将 `HAVE_LIBSOCKET` 定义为可用宏，表示 Amiga OS 配置未声明链接 `socket` 库。

#### Scenario: 条件检查 socket 库支持
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_LIBSOCKET`
- **THEN** 预处理器应观察到该宏未定义

Trace: `include/amiga_os/config.h:HAVE_LIBSOCKET`

### Requirement: HAVE_LINGER linger 类型禁用配置
系统 MUST NOT 将 `HAVE_LINGER` 定义为可用宏，表示 Amiga OS 配置未声明系统 `struct linger` 可用。

#### Scenario: socket 代码选择本地 linger 定义
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** `lib/socket.c` 检查 `#if !defined(HAVE_LINGER)`
- **THEN** 预处理器应进入本地 `struct linger` 定义分支

Trace: `include/amiga_os/config.h:HAVE_LINGER`, `lib/socket.c:HAVE_LINGER`

### Requirement: HAVE_NETDB_H netdb 头文件能力
系统 MUST 将 `HAVE_NETDB_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<netdb.h>`。

#### Scenario: 条件包含 netdb 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_NETDB_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_NETDB_H`, `lib/socket.c:HAVE_NETDB_H`

### Requirement: HAVE_NETINET_IN_H netinet in 头文件能力
系统 MUST 将 `HAVE_NETINET_IN_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<netinet/in.h>`。

#### Scenario: 条件包含 netinet in 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_NETINET_IN_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_NETINET_IN_H`, `lib/socket.c:HAVE_NETINET_IN_H`

### Requirement: HAVE_NETINET_TCP_H netinet tcp 头文件能力
系统 MUST 将 `HAVE_NETINET_TCP_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<netinet/tcp.h>`。

#### Scenario: 条件包含 netinet tcp 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_NETINET_TCP_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_NETINET_TCP_H`, `lib/socket.c:HAVE_NETINET_TCP_H`

### Requirement: HAVE_POLL_H poll 头文件禁用配置
系统 MUST NOT 将 `HAVE_POLL_H` 定义为可用宏，表示 Amiga OS 配置未声明 `<poll.h>` 可用。

#### Scenario: 条件检查 poll 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_POLL_H`
- **THEN** 预处理器应观察到该宏未定义

Trace: `include/amiga_os/config.h:HAVE_POLL_H`, `lib/socket.c:HAVE_POLL_H`

### Requirement: HAVE_SOCKADDR_LEN sockaddr sa_len 结构能力
系统 MUST 将 `HAVE_SOCKADDR_LEN` 暴露为值 `1` 的预处理宏，表示 Amiga OS `sockaddr` 结构具有 `sa_len` 成员。

#### Scenario: 条件检查 sockaddr 长度成员
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_SOCKADDR_LEN`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_SOCKADDR_LEN`

### Requirement: HAVE_SOCKADDR_STORAGE sockaddr_storage 禁用配置
系统 MUST NOT 将 `HAVE_SOCKADDR_STORAGE` 定义为可用宏，表示 Amiga OS 配置未声明 `sockaddr_storage` 可用。

#### Scenario: 条件检查 sockaddr_storage 能力
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_SOCKADDR_STORAGE`
- **THEN** 预处理器应观察到该宏未定义

Trace: `include/amiga_os/config.h:HAVE_SOCKADDR_STORAGE`

### Requirement: HAVE_STDINT_H stdint 头文件能力
系统 MUST 将 `HAVE_STDINT_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<stdint.h>`。

#### Scenario: 条件包含 stdint 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_STDINT_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_STDINT_H`, `lib/socket.c:HAVE_STDINT_H`

### Requirement: HAVE_STDIO_H stdio 头文件能力
系统 MUST 将 `HAVE_STDIO_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<stdio.h>`。

#### Scenario: 条件包含 stdio 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_STDIO_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_STDIO_H`, `lib/socket.c:HAVE_STDIO_H`

### Requirement: HAVE_STDLIB_H stdlib 头文件能力
系统 MUST 将 `HAVE_STDLIB_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<stdlib.h>`。

#### Scenario: 条件包含 stdlib 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_STDLIB_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_STDLIB_H`, `lib/socket.c:HAVE_STDLIB_H`

### Requirement: HAVE_STRINGS_H strings 头文件能力
系统 MUST 将 `HAVE_STRINGS_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<strings.h>`。

#### Scenario: 条件检查 strings 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_STRINGS_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_STRINGS_H`

### Requirement: HAVE_STRING_H string 头文件能力
系统 MUST 将 `HAVE_STRING_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<string.h>`。

#### Scenario: 条件包含 string 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_STRING_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_STRING_H`, `lib/socket.c:HAVE_STRING_H`

### Requirement: HAVE_SYS_ERRNO_H sys errno 头文件能力
系统 MUST 将 `HAVE_SYS_ERRNO_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<sys/errno.h>`。

#### Scenario: 条件检查 sys errno 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_SYS_ERRNO_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_SYS_ERRNO_H`

### Requirement: HAVE_SYS_FCNTL_H sys fcntl 头文件能力
系统 MUST 将 `HAVE_SYS_FCNTL_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<sys/fcntl.h>`。

#### Scenario: 条件包含 sys fcntl 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_SYS_FCNTL_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_SYS_FCNTL_H`, `lib/socket.c:HAVE_SYS_FCNTL_H`

### Requirement: HAVE_SYS_IOCTL_H sys ioctl 头文件能力
系统 MUST 将 `HAVE_SYS_IOCTL_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<sys/ioctl.h>`。

#### Scenario: 条件包含 sys ioctl 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_SYS_IOCTL_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_SYS_IOCTL_H`, `lib/socket.c:HAVE_SYS_IOCTL_H`

### Requirement: HAVE_SYS_POLL_H sys poll 头文件禁用配置
系统 MUST NOT 将 `HAVE_SYS_POLL_H` 定义为可用宏，表示 Amiga OS 配置未声明 `<sys/poll.h>` 可用。

#### Scenario: 条件检查 sys poll 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_SYS_POLL_H`
- **THEN** 预处理器应观察到该宏未定义

Trace: `include/amiga_os/config.h:HAVE_SYS_POLL_H`, `lib/socket.c:HAVE_SYS_POLL_H`

### Requirement: HAVE_SYS_SOCKET_H sys socket 头文件能力
系统 MUST 将 `HAVE_SYS_SOCKET_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<sys/socket.h>`。

#### Scenario: 条件包含 sys socket 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_SYS_SOCKET_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_SYS_SOCKET_H`, `lib/socket.c:HAVE_SYS_SOCKET_H`

### Requirement: HAVE_SYS_STAT_H sys stat 头文件能力
系统 MUST 将 `HAVE_SYS_STAT_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<sys/stat.h>`。

#### Scenario: 条件检查 sys stat 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_SYS_STAT_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_SYS_STAT_H`, `lib/spnego-wrapper.c:HAVE_SYS_STAT_H`

### Requirement: HAVE_SYS_TIME_H sys time 头文件能力
系统 MUST 将 `HAVE_SYS_TIME_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<sys/time.h>`。

#### Scenario: 条件检查 sys time 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_SYS_TIME_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_SYS_TIME_H`, `lib/socket.c:HAVE_SYS_TIME_H`

### Requirement: HAVE_SYS_TYPES_H sys types 头文件能力
系统 MUST 将 `HAVE_SYS_TYPES_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<sys/types.h>`。

#### Scenario: 条件检查 sys types 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_SYS_TYPES_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_SYS_TYPES_H`, `lib/socket.c:HAVE_SYS_TYPES_H`

### Requirement: HAVE_SYS_UIO_H sys uio 头文件能力
系统 MUST 将 `HAVE_SYS_UIO_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<sys/uio.h>`。

#### Scenario: 条件包含 sys uio 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_SYS_UIO_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_SYS_UIO_H`, `lib/socket.c:HAVE_SYS_UIO_H`

### Requirement: HAVE_SYS_UNISTD_H sys unistd 头文件能力
系统 MUST 将 `HAVE_SYS_UNISTD_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<sys/unistd.h>`。

#### Scenario: 条件包含 sys unistd 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_SYS_UNISTD_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_SYS_UNISTD_H`, `lib/socket.c:HAVE_SYS_UNISTD_H`

### Requirement: HAVE_SYS__IOVEC_H sys _iovec 头文件禁用配置
系统 MUST NOT 将 `HAVE_SYS__IOVEC_H` 定义为可用宏，表示 Amiga OS 配置未声明 `<sys/_iovec.h>` 可用。

#### Scenario: 条件检查 sys _iovec 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_SYS__IOVEC_H`
- **THEN** 预处理器应观察到该宏未定义

Trace: `include/amiga_os/config.h:HAVE_SYS__IOVEC_H`, `lib/socket.c:HAVE_SYS__IOVEC_H`

### Requirement: HAVE_TIME_H time 头文件能力
系统 MUST 将 `HAVE_TIME_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<time.h>`。

#### Scenario: 条件检查 time 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_TIME_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_TIME_H`, `lib/socket.c:HAVE_TIME_H`

### Requirement: HAVE_UNISTD_H unistd 头文件能力
系统 MUST 将 `HAVE_UNISTD_H` 暴露为值 `1` 的预处理宏，表示 Amiga OS 配置提供 `<unistd.h>`。

#### Scenario: 条件包含 unistd 头文件
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `HAVE_UNISTD_H`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:HAVE_UNISTD_H`, `lib/socket.c:HAVE_UNISTD_H`

### Requirement: LT_OBJDIR libtool 对象目录
系统 MUST 将 `LT_OBJDIR` 暴露为字符串宏 `".libs/"`，表示 libtool 未安装对象目录名称。

#### Scenario: 读取 libtool 对象目录配置
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码或构建辅助逻辑读取 `LT_OBJDIR`
- **THEN** 预处理器应观察到该宏值为字符串 `".libs/"`

Trace: `include/amiga_os/config.h:LT_OBJDIR`

### Requirement: PACKAGE 包短名元数据
系统 MUST 将 `PACKAGE` 暴露为字符串宏 `"libsmb2"`。

#### Scenario: 读取包短名
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码读取 `PACKAGE`
- **THEN** 预处理器应观察到该宏值为字符串 `"libsmb2"`

Trace: `include/amiga_os/config.h:PACKAGE`

### Requirement: PACKAGE_BUGREPORT 包问题报告地址
系统 MUST 将 `PACKAGE_BUGREPORT` 暴露为字符串宏 `"ronniesahlberg@gmail.com"`。

#### Scenario: 读取包问题报告地址
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码读取 `PACKAGE_BUGREPORT`
- **THEN** 预处理器应观察到该宏值为字符串 `"ronniesahlberg@gmail.com"`

Trace: `include/amiga_os/config.h:PACKAGE_BUGREPORT`

### Requirement: PACKAGE_NAME 包全名元数据
系统 MUST 将 `PACKAGE_NAME` 暴露为字符串宏 `"libsmb2"`。

#### Scenario: 读取包全名
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码读取 `PACKAGE_NAME`
- **THEN** 预处理器应观察到该宏值为字符串 `"libsmb2"`

Trace: `include/amiga_os/config.h:PACKAGE_NAME`

### Requirement: PACKAGE_STRING 包名版本组合元数据
系统 MUST 将 `PACKAGE_STRING` 暴露为字符串宏 `"libsmb2 4.0.0"`。

#### Scenario: 读取包名版本组合
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码读取 `PACKAGE_STRING`
- **THEN** 预处理器应观察到该宏值为字符串 `"libsmb2 4.0.0"`

Trace: `include/amiga_os/config.h:PACKAGE_STRING`

### Requirement: PACKAGE_TARNAME 包 tar 名称元数据
系统 MUST 将 `PACKAGE_TARNAME` 暴露为字符串宏 `"libsmb2"`。

#### Scenario: 读取包 tar 名称
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码读取 `PACKAGE_TARNAME`
- **THEN** 预处理器应观察到该宏值为字符串 `"libsmb2"`

Trace: `include/amiga_os/config.h:PACKAGE_TARNAME`

### Requirement: PACKAGE_URL 包主页元数据
系统 MUST 将 `PACKAGE_URL` 暴露为空字符串宏 `""`。

#### Scenario: 读取包主页
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码读取 `PACKAGE_URL`
- **THEN** 预处理器应观察到该宏值为空字符串

Trace: `include/amiga_os/config.h:PACKAGE_URL`

### Requirement: PACKAGE_VERSION 包版本元数据
系统 MUST 将 `PACKAGE_VERSION` 暴露为字符串宏 `"4.0.0"`。

#### Scenario: 读取包版本
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码读取 `PACKAGE_VERSION`
- **THEN** 预处理器应观察到该宏值为字符串 `"4.0.0"`

Trace: `include/amiga_os/config.h:PACKAGE_VERSION`

### Requirement: STDC_HEADERS C90 标准头集合能力
系统 MUST 将 `STDC_HEADERS` 暴露为值 `1` 的预处理宏，表示 C90 标准头集合存在。

#### Scenario: 条件检查 C90 标准头集合
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码检查 `STDC_HEADERS`
- **THEN** 预处理器应观察到该宏已定义为 `1`

Trace: `include/amiga_os/config.h:STDC_HEADERS`, `lib/spnego-wrapper.c:STDC_HEADERS`

### Requirement: VERSION 包版本号元数据
系统 MUST 将 `VERSION` 暴露为字符串宏 `"4.0.0"`。

#### Scenario: 读取包版本号
- **GIVEN** Amiga OS 目标构建包含 `include/amiga_os/config.h`
- **WHEN** 源码读取 `VERSION`
- **THEN** 预处理器应观察到该宏值为字符串 `"4.0.0"`

Trace: `include/amiga_os/config.h:VERSION`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `include/amiga_os/config.h` 中 `PACKAGE_VERSION`、`PACKAGE_STRING` 和 `VERSION` 为 `4.0.0`，但 `PROJECT_CONTEXT.md` 记录 CMake/Autotools 当前项目版本为 `6.1.0`；是否应保持该平台头的历史生成值？ | PACKAGE_VERSION, PACKAGE_STRING, VERSION | 源码证据与项目上下文版本存在差异，worker 不修改源码或共享上下文。 |
