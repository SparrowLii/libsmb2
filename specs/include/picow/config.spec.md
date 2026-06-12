# include/picow/config.h Specification

## Source Context

- Source: `include/picow/config.h`
- Related Headers: `config.h.in`, `configure.ac`
- Related Tests: `none`
- Related Dependencies: GitNexus `context` resolved `CONFIGURE_OPTION_TCP_LINGER` in `include/picow/config.h`; no incoming callers, outgoing calls, or processes were reported for that macro. Source review shows `CMakeLists.txt` adds `include/picow` to include paths when `PICO_BOARD` is set and `lib/socket.c` conditionally reads `CONFIGURE_OPTION_TCP_LINGER` through `config.h`.
- Build/Compile Context: PICO builds use `PICO_BOARD` in `CMakeLists.txt`, add `include/picow` to include directories, define `NEED_BE64TOH`, `NEED_POLL`, and `NEED_GETLOGIN_R`, and build `libsmb2` as a static library.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| CONFIGURE_OPTION_TCP_LINGER | macro | #define CONFIGURE_OPTION_TCP_LINGER 1 | Include | PICO 配置头公开 TCP linger 编译期开关，`lib/socket.c` 依据该宏选择关闭 socket 时的 linger 行为。 |
| HAVE_DLFCN_H | macro | #define HAVE_DLFCN_H 1 | Include | PICO 配置头公开平台头文件可用性，依赖 `config.h` 的源码可按该宏选择是否使用 `<dlfcn.h>`。 |
| HAVE_FCNTL_H | macro | #define HAVE_FCNTL_H 1 | Include | PICO 配置头公开 `<fcntl.h>` 可用性，依赖 `config.h` 的源码可按该宏启用 fcntl 相关声明。 |
| HAVE_SOCKADDR_STORAGE | macro | #define HAVE_SOCKADDR_STORAGE 1 | Include | PICO 配置头公开 `sockaddr_storage` 可用性，网络地址处理代码可依据该宏选择结构能力。 |
| HAVE_STDINT_H | macro | #define HAVE_STDINT_H 1 | Include | PICO 配置头公开 `<stdint.h>` 可用性，多处源码在 `HAVE_CONFIG_H` 后按该宏包含定宽整数声明。 |
| HAVE_STDIO_H | macro | #define HAVE_STDIO_H 1 | Include | PICO 配置头公开 `<stdio.h>` 可用性，源码可按该宏包含标准 I/O 声明。 |
| HAVE_STDLIB_H | macro | #define HAVE_STDLIB_H 1 | Include | PICO 配置头公开 `<stdlib.h>` 可用性，源码可按该宏包含标准库声明。 |
| HAVE_SYS_STAT_H | macro | #define HAVE_SYS_STAT_H 1 | Include | PICO 配置头公开 `<sys/stat.h>` 可用性，源码可按该宏包含文件状态声明。 |
| HAVE_SYS_TYPES_H | macro | #define HAVE_SYS_TYPES_H 1 | Include | PICO 配置头公开 `<sys/types.h>` 可用性，源码可按该宏包含基础系统类型。 |
| HAVE_TIME_H | macro | #define HAVE_TIME_H 1 | Include | PICO 配置头公开 `<time.h>` 可用性，时间转换源码可按该宏包含时间声明。 |
| HAVE_UNISTD_H | macro | #define HAVE_UNISTD_H 1 | Include | PICO 配置头公开 `<unistd.h>` 可用性，源码可按该宏包含 POSIX 声明。 |
| LT_OBJDIR | macro | #define LT_OBJDIR ".libs/" | Include | PICO 配置头公开 libtool 对象目录字符串，依赖 Autotools 兼容宏的调用方可读取该值。 |
| PACKAGE | macro | #define PACKAGE "libsmb2" | Include | PICO 配置头公开包短名，调用方可读取编译期包标识。 |
| PACKAGE_BUGREPORT | macro | #define PACKAGE_BUGREPORT "ronniesahlberg@gmail.com" | Include | PICO 配置头公开 bug report 联系地址，调用方可读取编译期包元数据。 |
| PACKAGE_NAME | macro | #define PACKAGE_NAME "libsmb2" | Include | PICO 配置头公开包全名，调用方可读取编译期包元数据。 |
| PACKAGE_STRING | macro | #define PACKAGE_STRING "libsmb2 4.0.0" | Include | PICO 配置头公开包名和版本组合字符串，调用方可读取编译期版本文本。 |
| PACKAGE_TARNAME | macro | #define PACKAGE_TARNAME "libsmb2" | Include | PICO 配置头公开 tar 包名，调用方可读取编译期包元数据。 |
| PACKAGE_URL | macro | #define PACKAGE_URL "" | Include | PICO 配置头公开包 URL 字符串，调用方可读取空字符串作为当前配置值。 |
| PACKAGE_VERSION | macro | #define PACKAGE_VERSION "4.0.0" | Include | PICO 配置头公开包版本字符串，调用方可读取当前 PICO 配置的版本文本。 |
| STDC_HEADERS | macro | #define STDC_HEADERS 1 | Include | PICO 配置头公开 C90 标准头文件集合可用性，兼容代码可依据该宏选择标准头路径。 |
| VERSION | macro | #define VERSION "4.0.0" | Include | PICO 配置头公开版本号字符串，调用方可读取当前 PICO 配置的版本文本。 |
| HAVE_ARPA_INET_H | macro | /* #undef HAVE_ARPA_INET_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_ERRNO_H | macro | /* #undef HAVE_ERRNO_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_GSSAPI_GSSAPI_H | macro | /* #undef HAVE_GSSAPI_GSSAPI_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_INTTYPES_H | macro | /* #undef HAVE_INTTYPES_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_LIBKRB5 | macro | /* #undef HAVE_LIBKRB5 */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_LIBNSL | macro | /* #undef HAVE_LIBNSL */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_LIBSOCKET | macro | /* #undef HAVE_LIBSOCKET */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_LINGER | macro | /* #undef HAVE_LINGER */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_NETDB_H | macro | /* #undef HAVE_NETDB_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_NETINET_IN_H | macro | /* #undef HAVE_NETINET_IN_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_NETINET_TCP_H | macro | /* #undef HAVE_NETINET_TCP_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_POLL_H | macro | /* #undef HAVE_POLL_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_SOCKADDR_LEN | macro | /* #undef HAVE_SOCKADDR_LEN */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_STRINGS_H | macro | /* #undef HAVE_STRINGS_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_STRING_H | macro | /* #undef HAVE_STRING_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_SYS_ERRNO_H | macro | /* #undef HAVE_SYS_ERRNO_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_SYS_FCNTL_H | macro | /* #undef HAVE_SYS_FCNTL_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_SYS_IOCTL_H | macro | /* #undef HAVE_SYS_IOCTL_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_SYS_POLL_H | macro | /* #undef HAVE_SYS_POLL_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_SYS_SOCKET_H | macro | /* #undef HAVE_SYS_SOCKET_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_SYS_TIME_H | macro | /* #undef HAVE_SYS_TIME_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_SYS_UIO_H | macro | /* #undef HAVE_SYS_UIO_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_SYS_UNISTD_H | macro | /* #undef HAVE_SYS_UNISTD_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |
| HAVE_SYS__IOVEC_H | macro | /* #undef HAVE_SYS__IOVEC_H */ | Skip | 未定义的 autoheader 条目不向调用方提供可用宏契约。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| CONFIGURE_OPTION_TCP_LINGER | macro | include/picow/config.h:5 | TCP socket 关闭后是否允许 linger 的配置值。 |
| HAVE_DLFCN_H | macro | include/picow/config.h:11 | 声明 `<dlfcn.h>` 在该配置中可用。 |
| HAVE_FCNTL_H | macro | include/picow/config.h:17 | 声明 `<fcntl.h>` 在该配置中可用。 |
| HAVE_SOCKADDR_STORAGE | macro | include/picow/config.h:53 | 声明 `sockaddr_storage` 在该配置中可用。 |
| HAVE_STDINT_H | macro | include/picow/config.h:56 | 声明 `<stdint.h>` 在该配置中可用。 |
| HAVE_STDIO_H | macro | include/picow/config.h:59 | 声明 `<stdio.h>` 在该配置中可用。 |
| HAVE_STDLIB_H | macro | include/picow/config.h:62 | 声明 `<stdlib.h>` 在该配置中可用。 |
| HAVE_SYS_STAT_H | macro | include/picow/config.h:86 | 声明 `<sys/stat.h>` 在该配置中可用。 |
| HAVE_SYS_TYPES_H | macro | include/picow/config.h:92 | 声明 `<sys/types.h>` 在该配置中可用。 |
| HAVE_TIME_H | macro | include/picow/config.h:104 | 声明 `<time.h>` 在该配置中可用。 |
| HAVE_UNISTD_H | macro | include/picow/config.h:107 | 声明 `<unistd.h>` 在该配置中可用。 |
| LT_OBJDIR | macro | include/picow/config.h:110 | libtool 未安装对象目录值为 `.libs/`。 |
| PACKAGE | macro | include/picow/config.h:113 | 包短名为 `libsmb2`。 |
| PACKAGE_BUGREPORT | macro | include/picow/config.h:116 | bug report 联系地址为 `ronniesahlberg@gmail.com`。 |
| PACKAGE_NAME | macro | include/picow/config.h:119 | 包全名为 `libsmb2`。 |
| PACKAGE_STRING | macro | include/picow/config.h:122 | 包名和版本组合字符串为 `libsmb2 4.0.0`。 |
| PACKAGE_TARNAME | macro | include/picow/config.h:125 | tar 包名为 `libsmb2`。 |
| PACKAGE_URL | macro | include/picow/config.h:128 | 包 URL 当前为空字符串。 |
| PACKAGE_VERSION | macro | include/picow/config.h:131 | 包版本字符串为 `4.0.0`。 |
| STDC_HEADERS | macro | include/picow/config.h:136 | C90 标准头文件集合可用性为 `1`。 |
| VERSION | macro | include/picow/config.h:139 | 版本号字符串为 `4.0.0`。 |

## ADDED Requirements

### Requirement: CONFIGURE_OPTION_TCP_LINGER expose PICO TCP linger policy
系统 MUST 将 `CONFIGURE_OPTION_TCP_LINGER` 暴露为值 `1`，使包含该配置头的 PICO 构建代码获得允许 TCP sockets 在关闭后 linger 的编译期配置。

#### Scenario: PICO 配置启用 TCP linger
- **GIVEN** PICO 构建通过 `CMakeLists.txt` 将 `include/picow` 加入 include 路径
- **WHEN** 源码包含 `config.h` 并读取 `CONFIGURE_OPTION_TCP_LINGER`
- **THEN** 预处理器得到数值 `1`，`lib/socket.c` 中依赖该宏的 `#if 0 == CONFIGURE_OPTION_TCP_LINGER` 分支不会代表该配置的关闭策略

Trace: `include/picow/config.h:CONFIGURE_OPTION_TCP_LINGER`, `CMakeLists.txt:PICO_BOARD`, `lib/socket.c:CONFIGURE_OPTION_TCP_LINGER`

### Requirement: HAVE_DLFCN_H expose dlfcn header availability
系统 MUST 将 `HAVE_DLFCN_H` 暴露为值 `1`，使包含该配置头的代码获得 `<dlfcn.h>` 可用的编译期事实。

#### Scenario: PICO 配置声明 dlfcn 可用
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器检查 `HAVE_DLFCN_H`
- **THEN** 该宏以数值 `1` 存在，调用方可将 `<dlfcn.h>` 视为当前配置声明的可用头文件

Trace: `include/picow/config.h:HAVE_DLFCN_H`

### Requirement: HAVE_FCNTL_H expose fcntl header availability
系统 MUST 将 `HAVE_FCNTL_H` 暴露为值 `1`，使包含该配置头的代码获得 `<fcntl.h>` 可用的编译期事实。

#### Scenario: PICO 配置声明 fcntl 可用
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器检查 `HAVE_FCNTL_H`
- **THEN** 该宏以数值 `1` 存在，调用方可将 `<fcntl.h>` 视为当前配置声明的可用头文件

Trace: `include/picow/config.h:HAVE_FCNTL_H`

### Requirement: HAVE_SOCKADDR_STORAGE expose sockaddr_storage availability
系统 MUST 将 `HAVE_SOCKADDR_STORAGE` 暴露为值 `1`，使包含该配置头的网络代码获得 `sockaddr_storage` 可用的编译期事实。

#### Scenario: PICO 配置声明 sockaddr_storage 可用
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器检查 `HAVE_SOCKADDR_STORAGE`
- **THEN** 该宏以数值 `1` 存在，调用方可将 `sockaddr_storage` 视为当前配置声明的可用结构能力

Trace: `include/picow/config.h:HAVE_SOCKADDR_STORAGE`, `configure.ac:HAVE_SOCKADDR_STORAGE`

### Requirement: HAVE_STDINT_H expose stdint header availability
系统 MUST 将 `HAVE_STDINT_H` 暴露为值 `1`，使包含该配置头的代码获得 `<stdint.h>` 可用的编译期事实。

#### Scenario: PICO 配置声明 stdint 可用
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器检查 `HAVE_STDINT_H`
- **THEN** 该宏以数值 `1` 存在，调用方可将 `<stdint.h>` 视为当前配置声明的可用头文件

Trace: `include/picow/config.h:HAVE_STDINT_H`

### Requirement: HAVE_STDIO_H expose stdio header availability
系统 MUST 将 `HAVE_STDIO_H` 暴露为值 `1`，使包含该配置头的代码获得 `<stdio.h>` 可用的编译期事实。

#### Scenario: PICO 配置声明 stdio 可用
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器检查 `HAVE_STDIO_H`
- **THEN** 该宏以数值 `1` 存在，调用方可将 `<stdio.h>` 视为当前配置声明的可用头文件

Trace: `include/picow/config.h:HAVE_STDIO_H`

### Requirement: HAVE_STDLIB_H expose stdlib header availability
系统 MUST 将 `HAVE_STDLIB_H` 暴露为值 `1`，使包含该配置头的代码获得 `<stdlib.h>` 可用的编译期事实。

#### Scenario: PICO 配置声明 stdlib 可用
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器检查 `HAVE_STDLIB_H`
- **THEN** 该宏以数值 `1` 存在，调用方可将 `<stdlib.h>` 视为当前配置声明的可用头文件

Trace: `include/picow/config.h:HAVE_STDLIB_H`

### Requirement: HAVE_SYS_STAT_H expose sys/stat header availability
系统 MUST 将 `HAVE_SYS_STAT_H` 暴露为值 `1`，使包含该配置头的代码获得 `<sys/stat.h>` 可用的编译期事实。

#### Scenario: PICO 配置声明 sys/stat 可用
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器检查 `HAVE_SYS_STAT_H`
- **THEN** 该宏以数值 `1` 存在，调用方可将 `<sys/stat.h>` 视为当前配置声明的可用头文件

Trace: `include/picow/config.h:HAVE_SYS_STAT_H`

### Requirement: HAVE_SYS_TYPES_H expose sys/types header availability
系统 MUST 将 `HAVE_SYS_TYPES_H` 暴露为值 `1`，使包含该配置头的代码获得 `<sys/types.h>` 可用的编译期事实。

#### Scenario: PICO 配置声明 sys/types 可用
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器检查 `HAVE_SYS_TYPES_H`
- **THEN** 该宏以数值 `1` 存在，调用方可将 `<sys/types.h>` 视为当前配置声明的可用头文件

Trace: `include/picow/config.h:HAVE_SYS_TYPES_H`

### Requirement: HAVE_TIME_H expose time header availability
系统 MUST 将 `HAVE_TIME_H` 暴露为值 `1`，使包含该配置头的代码获得 `<time.h>` 可用的编译期事实。

#### Scenario: PICO 配置声明 time 可用
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器检查 `HAVE_TIME_H`
- **THEN** 该宏以数值 `1` 存在，调用方可将 `<time.h>` 视为当前配置声明的可用头文件

Trace: `include/picow/config.h:HAVE_TIME_H`

### Requirement: HAVE_UNISTD_H expose unistd header availability
系统 MUST 将 `HAVE_UNISTD_H` 暴露为值 `1`，使包含该配置头的代码获得 `<unistd.h>` 可用的编译期事实。

#### Scenario: PICO 配置声明 unistd 可用
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器检查 `HAVE_UNISTD_H`
- **THEN** 该宏以数值 `1` 存在，调用方可将 `<unistd.h>` 视为当前配置声明的可用头文件

Trace: `include/picow/config.h:HAVE_UNISTD_H`

### Requirement: LT_OBJDIR expose libtool object directory
系统 MUST 将 `LT_OBJDIR` 暴露为字符串 `".libs/"`，使 Autotools 兼容调用方获得未安装 libtool 对象目录的编译期文本。

#### Scenario: PICO 配置声明 libtool 目录
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器展开 `LT_OBJDIR`
- **THEN** 展开结果为字符串 `".libs/"`

Trace: `include/picow/config.h:LT_OBJDIR`

### Requirement: PACKAGE expose package short name
系统 MUST 将 `PACKAGE` 暴露为字符串 `"libsmb2"`，使调用方获得当前配置的包短名。

#### Scenario: PICO 配置声明包短名
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器展开 `PACKAGE`
- **THEN** 展开结果为字符串 `"libsmb2"`

Trace: `include/picow/config.h:PACKAGE`

### Requirement: PACKAGE_BUGREPORT expose bug report address
系统 MUST 将 `PACKAGE_BUGREPORT` 暴露为字符串 `"ronniesahlberg@gmail.com"`，使调用方获得当前配置的 bug report 联系地址。

#### Scenario: PICO 配置声明 bug report 地址
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器展开 `PACKAGE_BUGREPORT`
- **THEN** 展开结果为字符串 `"ronniesahlberg@gmail.com"`

Trace: `include/picow/config.h:PACKAGE_BUGREPORT`

### Requirement: PACKAGE_NAME expose package full name
系统 MUST 将 `PACKAGE_NAME` 暴露为字符串 `"libsmb2"`，使调用方获得当前配置的包全名。

#### Scenario: PICO 配置声明包全名
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器展开 `PACKAGE_NAME`
- **THEN** 展开结果为字符串 `"libsmb2"`

Trace: `include/picow/config.h:PACKAGE_NAME`

### Requirement: PACKAGE_STRING expose package name and version
系统 MUST 将 `PACKAGE_STRING` 暴露为字符串 `"libsmb2 4.0.0"`，使调用方获得当前 PICO 配置的包名和版本组合文本。

#### Scenario: PICO 配置声明包组合字符串
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器展开 `PACKAGE_STRING`
- **THEN** 展开结果为字符串 `"libsmb2 4.0.0"`

Trace: `include/picow/config.h:PACKAGE_STRING`

### Requirement: PACKAGE_TARNAME expose tar package name
系统 MUST 将 `PACKAGE_TARNAME` 暴露为字符串 `"libsmb2"`，使调用方获得当前配置的 tar 包名。

#### Scenario: PICO 配置声明 tar 包名
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器展开 `PACKAGE_TARNAME`
- **THEN** 展开结果为字符串 `"libsmb2"`

Trace: `include/picow/config.h:PACKAGE_TARNAME`

### Requirement: PACKAGE_URL expose package URL value
系统 MUST 将 `PACKAGE_URL` 暴露为空字符串 `""`，使调用方获得当前配置未设置包 URL 的编译期文本。

#### Scenario: PICO 配置声明空 URL
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器展开 `PACKAGE_URL`
- **THEN** 展开结果为空字符串 `""`

Trace: `include/picow/config.h:PACKAGE_URL`

### Requirement: PACKAGE_VERSION expose package version
系统 MUST 将 `PACKAGE_VERSION` 暴露为字符串 `"4.0.0"`，使调用方获得当前 PICO 配置的包版本文本。

#### Scenario: PICO 配置声明包版本
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器展开 `PACKAGE_VERSION`
- **THEN** 展开结果为字符串 `"4.0.0"`

Trace: `include/picow/config.h:PACKAGE_VERSION`

### Requirement: STDC_HEADERS expose C90 standard header set availability
系统 MUST 将 `STDC_HEADERS` 暴露为值 `1`，使兼容代码获得 C90 标准头文件集合存在的编译期事实。

#### Scenario: PICO 配置声明标准头集合可用
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器检查 `STDC_HEADERS`
- **THEN** 该宏以数值 `1` 存在，调用方可将 C90 标准头文件集合视为当前配置声明的可用能力

Trace: `include/picow/config.h:STDC_HEADERS`

### Requirement: VERSION expose package version alias
系统 MUST 将 `VERSION` 暴露为字符串 `"4.0.0"`，使调用方获得当前 PICO 配置的版本号文本。

#### Scenario: PICO 配置声明版本别名
- **GIVEN** 源码在 PICO 构建中包含 `config.h`
- **WHEN** 预处理器展开 `VERSION`
- **THEN** 展开结果为字符串 `"4.0.0"`

Trace: `include/picow/config.h:VERSION`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `include/picow/config.h` 中的 `PACKAGE_VERSION` 和 `VERSION` 为 `4.0.0`，但 `CMakeLists.txt` 和 `configure.ac` 当前声明项目版本为 `6.1.0`；PICO 配置头是否应保持该历史版本文本？ | PACKAGE_VERSION, VERSION, PACKAGE_STRING | 源码证据存在版本差异，worker 不修改源码或共享上下文。 |
| Q-002 | GitNexus `impact` 可按名称返回同名 `CONFIGURE_OPTION_TCP_LINGER` 候选，但当前 CLI 不接受 `--target-uid`，无法对 `include/picow/config.h` 的精确宏 UID 运行影响分析。 | CONFIGURE_OPTION_TCP_LINGER | GitNexus context 可精确定位该宏；impact 精确 UID 命令受 CLI 选项限制。 |
