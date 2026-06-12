# lib/compat.h Specification

## Source Context

- Source: `lib/compat.h`
- Related Headers: `windows.h`, `ws2tcpip.h`, `winsock2.h`, `xtl.h`, `winsockx.h`, `lwip/netdb.h`, `lwip/sockets.h`, `netdb.h`, `unistd.h`, `sys/types.h`, `sys/uio.h`, `proto/bsdsocket.h`, `ps2ip.h`, `netinet/in.h`, `network.h`, `esp_system.h`
- Related Tests: `none`
- Related Dependencies: GitNexus `context` located declarations for `smb2_getaddrinfo`, `poll`, `writev`, `readv`, and macro `SMB2_VALID_SOCKET`; `lib/compat.c` provides conditional implementations for `smb2_getaddrinfo`, `smb2_freeaddrinfo`, `writev`, `readv`, `poll`, `random`, `srandom`, `getlogin_r`, `getpid`, `gethostname`, `iop_connect`, `strdup`, and `be64toh` when matching `NEED_*` or platform macros are enabled.
- Build/Compile Context: C compatibility header selected by platform and feature macros including `_XBOX`, `_WINDOWS`, `__MINGW32__`, `__USE_WINSOCK__`, `XBOX_PLATFORM`, `PICO_PLATFORM`, `__DREAMCAST__`, `__amigaos4__`, `__AMIGA__`, `__AROS__`, `__PS2__`, `_EE`, `_IOP`, `__ps2sdk_iop__`, `PS3_PPU_PLATFORM`, `__vita__`, `__SWITCH__`, `__3DS__`, `__wii__`, `__gamecube__`, `__WIIU__`, `__NDS__`, `ESP_PLATFORM`, `__ANDROID__`, `HAVE_SOCKADDR_STORAGE`, `HAVE_ADDRINFO`, and socket/error feature defines.

## Interface Summary

| Interface | Kind | Signature | Decision | Reason |
| --- | --- | --- | --- | --- |
| t_socket | typedef | typedef SOCKET t_socket;` / `typedef int t_socket; | Include | 调用方通过该类型在 Windows/Xbox 与 POSIX/console 平台间统一 socket 句柄表示。 |
| SMB2_INVALID_SOCKET | macro | #define SMB2_INVALID_SOCKET INVALID_SOCKET` / `#define SMB2_INVALID_SOCKET -1 | Include | 公开跨平台无效 socket 哨兵值，供 socket 有效性检查和错误路径使用。 |
| SMB2_VALID_SOCKET | macro | #define SMB2_VALID_SOCKET(sock) ((sock) != SMB2_INVALID_SOCKET)` / `#define SMB2_VALID_SOCKET(sock) ((sock) >= 0) | Include | 公开跨平台 socket 有效性谓词，在兼容 poll 实现中用于过滤无效句柄。 |
| struct sockaddr_storage | type | struct sockaddr_storage { ... }; | Include | 在缺少系统 `sockaddr_storage` 的平台补齐可见地址存储类型。 |
| struct addrinfo | type | struct addrinfo { int ai_flags; int ai_family; int ai_socktype; int ai_protocol; size_t ai_addrlen; char *ai_canonname; struct sockaddr *ai_addr; struct addrinfo *ai_next; }; | Include | 在缺少系统 `addrinfo` 的平台补齐 getaddrinfo/freeaddrinfo 兼容 ABI。 |
| struct pollfd | type | struct pollfd { t_socket fd; short events; short revents; };` / `struct pollfd { int fd; short events; short revents; }; | Include | 在缺少系统 poll 的平台补齐 poll 文件描述符数组元素布局。 |
| struct iovec | type | struct iovec { unsigned long iov_len; void *iov_base; };` / `struct iovec { void *iov_base; size_t iov_len; }; | Include | 在缺少系统 iovec 的平台补齐 scatter/gather I/O 向量布局。 |
| poll | function/macro | int poll(struct pollfd *fds, unsigned int nfds, int timo);` / `#define poll WSAPoll | Include | 平台缺少 poll 时声明兼容函数，或在 Winsock2 可用时映射到 `WSAPoll`。 |
| smb2_getaddrinfo | function | int smb2_getaddrinfo(const char *node, const char*service, const struct addrinfo *hints, struct addrinfo **res); | Include | 在平台缺少 getaddrinfo 时声明 IPv4-only 兼容解析入口，并通过宏映射为 `getaddrinfo`。 |
| smb2_freeaddrinfo | function | void smb2_freeaddrinfo(struct addrinfo *res); | Include | 与 `smb2_getaddrinfo` 配套释放兼容分配的 `addrinfo` 链首节点。 |
| getaddrinfo | macro | #define getaddrinfo smb2_getaddrinfo | Include | 将调用方的标准 API 名称重定向到项目兼容实现。 |
| freeaddrinfo | macro | #define freeaddrinfo smb2_freeaddrinfo | Include | 将调用方的标准释放 API 名称重定向到项目兼容实现。 |
| writev | function | ssize_t writev(t_socket fd, const struct iovec* vector, int count);` / `ssize_t writev(int fd, const struct iovec *iov, int iovcnt); | Include | 在缺少 writev 或平台使用 Winsock/console API 时提供 scatter/gather 写兼容声明或 inline 包装。 |
| readv | function | ssize_t readv(t_socket fd, const struct iovec* vector, int count);` / `ssize_t readv(int fd, const struct iovec *iov, int iovcnt); | Include | 在缺少 readv 或平台使用 Winsock/console API 时提供 scatter/gather 读兼容声明或 inline 包装。 |
| close | macro | #define close closesocket` / `#define close CloseSocket` / `#define close(x) lwip_close(x) | Include | 将 POSIX `close` 调用映射到目标平台 socket close API。 |
| srandom | function | void srandom(unsigned int seed); | Include | 在缺少 `srandom` 的平台声明随机数种子兼容入口。 |
| random | function | int random(void);` / `long random(void); | Include | 在缺少 `random` 的平台声明随机数兼容入口。 |
| getlogin_r | function | int getlogin_r(char *buf, size_t size); | Include | 在缺少 `getlogin_r` 的平台声明登录名查询兼容入口。 |
| getpid | function | int getpid(); | Include | 在缺少 `getpid` 的平台声明进程 ID 兼容入口。 |
| be64toh | function | long long int be64toh(long long int x); | Include | 在 PICO/PS2 平台声明 64 位 big-endian 到 host-order 转换兼容入口。 |
| gethostname | function | int gethostname(char *name, size_t len); | Include | 在 Xbox/PS2 平台声明主机名兼容入口。 |
| iop_connect | function | int iop_connect(int sockfd, struct sockaddr *addr, socklen_t addrlen); | Include | 在 PS2 IOP 平台将 `connect` 映射到可设置 `errno` 的 lwIP 兼容包装。 |
| malloc | function | void *malloc(int size); | Include | 在 `__ps2sdk_iop__` 平台显式声明缺失的分配入口，供兼容实现和调用方编译。 |
| free | function | void free(void *ptr); | Include | 在 `__ps2sdk_iop__` 平台显式声明缺失的释放入口。 |
| calloc | function | void *calloc(size_t nmemb, size_t size); | Include | 在 `__ps2sdk_iop__` 平台显式声明缺失的清零分配入口。 |
| O_RDONLY | macro | #define O_RDONLY 00000000 | Include | 当系统头未定义时补齐只读 open 标志。 |
| O_WRONLY | macro | #define O_WRONLY 00000001 | Include | 当系统头未定义时补齐只写 open 标志。 |
| O_RDWR | macro | #define O_RDWR 00000002 | Include | 当系统头未定义时补齐读写 open 标志。 |
| O_DSYNC | macro | #define O_DSYNC 040000 | Include | 当系统头未定义时补齐同步数据写 open 标志。 |
| O_SYNC | macro | #define O_SYNC (__O_SYNC OR O_DSYNC) | Include | 当系统头未定义时基于 `__O_SYNC` 和 `O_DSYNC` 补齐同步写 open 标志。 |
| O_ACCMODE | macro | #define O_ACCMODE (O_RDWR OR O_WRONLY OR O_RDONLY) | Include | 当系统头未定义时补齐访问模式掩码。 |
| ENOMEM | macro | #define ENOMEM 12 | Include | 当系统头未定义时补齐内存不足错误码。 |
| EINVAL | macro | #define EINVAL 22 | Include | 当系统头未定义时补齐无效参数错误码。 |
| typeof | macro | #define typeof __typeof__ | Include | 当编译器未定义 `typeof` 拼写时映射到 GNU `__typeof__`。 |
| _COMPAT_H_ | macro | #define _COMPAT_H_ | Skip | include guard，无独立调用方可观察行为。 |
| WIN32_LEAN_AND_MEAN | macro | #define WIN32_LEAN_AND_MEAN | Skip | 平台头包含裁剪开关，仅影响 Windows SDK 头展开范围。 |
| snprintf | macro | #define snprintf _snprintf` / `#define snprintf(format, n, ...) sprintf(format, __VA_ARGS__) | Skip | 平台编译兼容别名，具体格式化行为由平台函数或 `lib/compat.c` 归属。 |
| read macro | macro | #define read(fd, buf, maxcount) _read(fd, buf, (unsigned int)maxcount)` / `#define read(a,b,c) lwip_recv(a,b,c,MSG_DONTWAIT) | Skip | 简单平台 API 重定向，无独立错误或资源语义。 |
| write macro | macro | #define write(fd, buf, maxcount) _write(fd, buf, (unsigned int)maxcount)` / `#define write(a,b,c) lwip_send(a,b,c,MSG_DONTWAIT) | Skip | 简单平台 API 重定向，无独立错误或资源语义。 |
| sockaddr_in6 | macro | #define sockaddr_in6 sockaddr_in | Skip | IPv6 类型降级别名，具体兼容限制在 Open Questions 记录。 |
| strncpy | macro | #define strncpy(a,b,c) strcpy(a,b) | Skip | Amiga 平台编译兼容别名，缺少独立安全契约证据。 |

## Data Model Summary

| Type/Macro | Kind | Definition | Notes |
| --- | --- | --- | --- |
| t_socket | typedef | lib/compat.h:39`, `lib/compat.h:48 | Windows/Xbox/Mingw 使用 `SOCKET`，其他平台默认使用 `int`。 |
| SMB2_INVALID_SOCKET | macro | lib/compat.h:43`, `lib/compat.h:51 | Windows/Xbox/Mingw 使用系统 `INVALID_SOCKET`，其他平台使用 `-1`。 |
| SMB2_VALID_SOCKET | macro | lib/compat.h:44`, `lib/compat.h:50 | Windows/Xbox/Mingw 比较无效哨兵，其他平台要求描述符非负。 |
| struct sockaddr_storage | struct | lib/compat.h:171`, `lib/compat.h:401`, `lib/compat.h:590 | 在 Winsock/Xbox、Amiga 或 PS3 等缺失系统类型的平台补齐地址存储结构。 |
| struct addrinfo | struct | lib/compat.h:179`, `lib/compat.h:363`, `lib/compat.h:660 | 在 Winsock/Xbox、Amiga 或 Nintendo legacy 平台补齐地址解析结果结构。 |
| struct pollfd | struct | lib/compat.h:191`, `lib/compat.h:355`, `lib/compat.h:500`, `lib/compat.h:751 | 在缺少 poll 的平台补齐 `fd`、`events`、`revents` 三字段布局。 |
| struct iovec | struct | lib/compat.h:212`, `lib/compat.h:508`, `lib/compat.h:651 | 在 Windows、PS2 或部分 Nintendo 平台补齐 scatter/gather buffer 描述。 |
| poll | function/macro | lib/compat.h:219`, `lib/compat.h:236`, `lib/compat.h:376`, `lib/compat.h:506`, `lib/compat.h:757 | 在缺少 poll 的平台声明兼容函数，或映射到 `WSAPoll`。 |
| writev | function | lib/compat.h:243`, `lib/compat.h:248`, `lib/compat.h:322`, `lib/compat.h:387`, `lib/compat.h:530`, `lib/compat.h:574`, `lib/compat.h:637`, `lib/compat.h:727 | 在缺少 writev 的平台声明或内联提供 scatter/gather 写入口。 |
| readv | function | lib/compat.h:244`, `lib/compat.h:260`, `lib/compat.h:323`, `lib/compat.h:388`, `lib/compat.h:531`, `lib/compat.h:575`, `lib/compat.h:638`, `lib/compat.h:728 | 在缺少 readv 的平台声明或内联提供 scatter/gather 读入口。 |
| POLLIN/POLLPRI/POLLOUT/POLLERR/POLLHUP | macro | lib/compat.h:150 | 在缺少 poll 事件常量的平台补齐标准事件位。 |
| SOL_TCP | macro | lib/compat.h:197`, `lib/compat.h:303`, `lib/compat.h:318`, `lib/compat.h:533`, `lib/compat.h:577`, `lib/compat.h:640`, `lib/compat.h:722`, `lib/compat.h:768 | 在缺少 `SOL_TCP` 的平台映射到 `IPPROTO_TCP` 或常量 `6`。 |
| TCP_NODELAY | macro | lib/compat.h:562`, `lib/compat.h:713 | 在 PS3/Nintendo 平台补齐 TCP_NODELAY 常量。 |
| EAI_AGAIN/EAI_FAIL/EAI_MEMORY/EAI_NONAME/EAI_SERVICE | macro | lib/compat.h:126 | 多个平台补齐 getaddrinfo 错误码常量。 |
| ENOMEM | macro | lib/compat.h:813 | 当系统头缺失时补齐内存不足错误码。 |
| EINVAL | macro | lib/compat.h:817 | 当系统头缺失时补齐无效参数错误码。 |
| O_RDONLY | macro | lib/compat.h:785 | 当系统头缺失时补齐只读 open flag 常量。 |
| O_WRONLY | macro | lib/compat.h:789 | 当系统头缺失时补齐只写 open flag 常量。 |
| O_RDWR | macro | lib/compat.h:793 | 当系统头缺失时补齐读写 open flag 常量。 |
| O_DSYNC | macro | lib/compat.h:797 | 当系统头缺失时补齐同步数据写 open flag 常量。 |
| O_SYNC | macro | lib/compat.h:805 | 当系统头缺失时补齐同步写 open flag 常量。 |
| O_ACCMODE | macro | lib/compat.h:809 | 当系统头缺失时补齐访问模式掩码。 |

## ADDED Requirements

### Requirement: t_socket provides a platform socket handle type
系统 MUST 在 Windows/Xbox/Mingw 构建中将 `t_socket` 定义为 `SOCKET`，并在其他未预定义 `T_SOCKET_DEFINED` 的平台中将 `t_socket` 定义为 `int`。

#### Scenario: platform chooses socket handle representation
- **GIVEN** 调用方包含 `lib/compat.h`，且编译目标为 Windows/Xbox/Mingw 或默认 POSIX-like 平台
- **WHEN** 源码声明或传递 `t_socket` 值
- **THEN** 类型定义 MUST 与目标平台 socket API 的句柄表示一致

Trace: `lib/compat.h:39`, `lib/compat.h:48`

### Requirement: SMB2_INVALID_SOCKET defines the invalid socket sentinel
系统 MUST 为每个目标平台提供 `SMB2_INVALID_SOCKET`，Windows/Xbox/Mingw 分支 SHALL 复用系统 `INVALID_SOCKET`，其他默认分支 SHALL 使用 `-1`。

#### Scenario: caller compares against invalid socket sentinel
- **GIVEN** 调用方需要识别 socket 创建或传递失败
- **WHEN** 调用方读取 `SMB2_INVALID_SOCKET`
- **THEN** 宏值 MUST 表示当前平台的无效 socket 句柄哨兵

Trace: `lib/compat.h:43`, `lib/compat.h:51`

### Requirement: SMB2_VALID_SOCKET evaluates socket validity
系统 MUST 提供 `SMB2_VALID_SOCKET(sock)`，Windows/Xbox/Mingw 分支 SHALL 判断 `sock != SMB2_INVALID_SOCKET`，其他默认分支 SHALL 判断 `sock >= 0`。

#### Scenario: compatibility poll filters invalid descriptors
- **GIVEN** 兼容 `poll` 实现遍历 `struct pollfd` 数组
- **WHEN** `SMB2_VALID_SOCKET(fd)` 判断某个 `fd` 无效
- **THEN** 调用方或兼容实现 MUST 将该 socket 视为不可用于平台 socket 操作

Trace: `lib/compat.h:44`, `lib/compat.h:50`, `lib/compat.c:478`, `lib/compat.c:539`

### Requirement: struct sockaddr_storage provides fallback address storage
系统 MUST 在缺少系统 `sockaddr_storage` 的受支持平台定义 `struct sockaddr_storage`，并保留地址族字段以及足够的填充或对齐字段用于 socket 地址存储。

#### Scenario: platform lacks sockaddr_storage
- **GIVEN** 编译目标命中 Winsock/Xbox、Amiga 或 PS3 fallback 分支，且系统头未提供可用 `sockaddr_storage`
- **WHEN** 调用方声明 `struct sockaddr_storage` 变量
- **THEN** 该类型 MUST 包含地址族字段，并提供源码中定义的填充布局用于编译兼容

Trace: `lib/compat.h:171`, `lib/compat.h:401`, `lib/compat.h:590`

### Requirement: struct addrinfo provides fallback getaddrinfo ABI
系统 MUST 在缺少系统 `addrinfo` 的平台定义 `struct addrinfo`，其字段 SHALL 包含 flags、family、socktype、protocol、addrlen、canonname、addr 和 next。

#### Scenario: compatibility resolver fills addrinfo result
- **GIVEN** 平台使用 `smb2_getaddrinfo` 兼容实现
- **WHEN** 兼容实现分配并填充 `struct addrinfo`
- **THEN** 结果结构 MUST 提供源码声明的字段，以便调用方读取地址族、地址长度、地址指针和链表 next 指针

Trace: `lib/compat.h:179`, `lib/compat.h:363`, `lib/compat.h:660`, `lib/compat.c:314`

### Requirement: struct pollfd provides fallback poll descriptor layout
系统 MUST 在缺少系统 poll 类型的平台定义 `struct pollfd`，并 SHALL 暴露 `fd`、`events` 和 `revents` 字段。

#### Scenario: caller prepares poll descriptors
- **GIVEN** 平台使用 `lib/compat.h` 中的 fallback `struct pollfd`
- **WHEN** 调用方设置 `fd` 和 `events` 后调用 `poll`
- **THEN** 兼容 poll 实现 MUST 能读取 `fd`/`events` 并通过 `revents` 返回事件位

Trace: `lib/compat.h:191`, `lib/compat.h:355`, `lib/compat.h:500`, `lib/compat.h:751`, `lib/compat.c:463`

### Requirement: struct iovec provides fallback scatter-gather layout
系统 MUST 在缺少系统 iovec 的平台定义 `struct iovec`，并 SHALL 暴露 buffer 指针和 buffer 长度字段供 `readv`/`writev` 兼容路径使用。

#### Scenario: compatibility vector I/O reads iovec entries
- **GIVEN** 平台使用 `lib/compat.h` 中的 fallback `struct iovec`
- **WHEN** 调用方将 iovec 数组传入 `writev` 或 `readv`
- **THEN** 兼容实现 MUST 能读取每个元素的 base 指针和长度以聚合写入或拆分读取结果

Trace: `lib/compat.h:212`, `lib/compat.h:508`, `lib/compat.h:651`, `lib/compat.c:381`, `lib/compat.c:424`

### Requirement: poll provides platform poll compatibility
系统 MUST 在 `_XBOX`、`__USE_WINSOCK__`、Amiga、PS2 或 Nintendo legacy 分支中声明兼容 `poll`，并在可使用 Winsock2 `WSAPoll` 的 Windows 分支中 SHALL 将 `poll` 映射为 `WSAPoll`。

#### Scenario: fallback poll uses select-backed readiness
- **GIVEN** 平台定义 `NEED_POLL` 并提供 `struct pollfd` 数组
- **WHEN** 调用 `poll(fds, nfds, timo)`
- **THEN** 兼容实现 MUST 清零 `revents`，根据 `POLLIN`、`POLLPRI`、`POLLOUT` 构造 `select` 集合，并在 `select` 成功后设置对应 `revents` 位

Trace: `lib/compat.h:219`, `lib/compat.h:236`, `lib/compat.h:376`, `lib/compat.h:506`, `lib/compat.h:757`, `lib/compat.c:463`

### Requirement: smb2_getaddrinfo provides IPv4 address resolution compatibility
系统 MUST 在缺少 getaddrinfo 的平台声明 `smb2_getaddrinfo`，并 SHALL 通过兼容实现分配 `struct addrinfo` 和 `struct sockaddr_in` 结果。

#### Scenario: compatibility resolver returns IPv4 addrinfo
- **GIVEN** 平台定义 `NEED_GETADDRINFO`，调用方传入 `node`、可选 `service`、可选 `hints` 和 `res` 输出参数
- **WHEN** 调用 `smb2_getaddrinfo(node, service, hints, res)`
- **THEN** 函数 MUST 分配 IPv4 `sockaddr_in` 和 `addrinfo`，设置 `ai_family` 为 `AF_INET`、`ai_addrlen` 为 `sizeof(struct sockaddr_in)`、`ai_addr` 指向分配的地址，并在成功时返回 `0`

Trace: `lib/compat.h:226`, `lib/compat.c:258`

### Requirement: smb2_freeaddrinfo releases compatibility resolver storage
系统 MUST 在缺少 freeaddrinfo 的平台声明 `smb2_freeaddrinfo`，并 SHALL 释放由兼容解析结果持有的 `ai_addr` 和 `addrinfo` 本体。

#### Scenario: caller releases compatibility addrinfo
- **GIVEN** 调用方持有由 `smb2_getaddrinfo` 返回的 `struct addrinfo *res`
- **WHEN** 调用 `smb2_freeaddrinfo(res)`
- **THEN** 函数 MUST 释放 `res->ai_addr`，随后释放 `res`

Trace: `lib/compat.h:229`, `lib/compat.c:323`

### Requirement: getaddrinfo macro redirects to smb2_getaddrinfo
系统 MUST 在兼容解析分支中将 `getaddrinfo` 宏定义为 `smb2_getaddrinfo`，使调用方源码可使用标准 API 名称。

#### Scenario: source uses standard resolver spelling
- **GIVEN** 平台进入 `lib/compat.h` 的兼容解析分支
- **WHEN** 调用方源码写入 `getaddrinfo(node, service, hints, res)`
- **THEN** 预处理结果 MUST 调用项目的 `smb2_getaddrinfo(node, service, hints, res)`

Trace: `lib/compat.h:231`, `lib/compat.h:383`, `lib/compat.h:559`, `lib/compat.h:737`

### Requirement: freeaddrinfo macro redirects to smb2_freeaddrinfo
系统 MUST 在兼容解析分支中将 `freeaddrinfo` 宏定义为 `smb2_freeaddrinfo`，使调用方源码可使用标准释放 API 名称。

#### Scenario: source releases resolver result with standard spelling
- **GIVEN** 平台进入 `lib/compat.h` 的兼容解析分支
- **WHEN** 调用方源码写入 `freeaddrinfo(res)`
- **THEN** 预处理结果 MUST 调用项目的 `smb2_freeaddrinfo(res)`

Trace: `lib/compat.h:232`, `lib/compat.h:384`, `lib/compat.h:560`, `lib/compat.h:738`

### Requirement: writev provides scatter-gather write compatibility
系统 MUST 在缺少可用 `writev` 的平台声明或内联提供 `writev`，并 SHALL 将多个 iovec 段按顺序作为单次写入语义处理。

#### Scenario: fallback writev aggregates vectors
- **GIVEN** 平台定义 `NEED_WRITEV`，调用方传入 `count` 个 `struct iovec` 条目
- **WHEN** 调用 `writev(fd, vector, count)`
- **THEN** 兼容实现 MUST 检查总长度是否溢出 `ssize_t`，分配聚合缓冲区，按 iovec 顺序复制数据，调用底层 `write`，释放缓冲区，并返回底层写入字节数或 `-1`

Trace: `lib/compat.h:243`, `lib/compat.h:248`, `lib/compat.h:322`, `lib/compat.h:387`, `lib/compat.h:530`, `lib/compat.h:574`, `lib/compat.h:637`, `lib/compat.h:727`, `lib/compat.c:371`

### Requirement: readv provides scatter-gather read compatibility
系统 MUST 在缺少可用 `readv` 的平台声明或内联提供 `readv`，并 SHALL 将单次底层读取结果按 iovec 顺序分散到调用方缓冲区。

#### Scenario: fallback readv distributes bytes into vectors
- **GIVEN** 平台定义 `NEED_READV`，调用方传入 `count` 个 `struct iovec` 条目
- **WHEN** 调用 `readv(fd, vector, count)`
- **THEN** 兼容实现 MUST 检查总长度是否溢出 `ssize_t`，分配临时缓冲区，调用底层 `read`，按 iovec 顺序复制已读字节，释放缓冲区，并返回底层读取字节数或 `-1`

Trace: `lib/compat.h:244`, `lib/compat.h:260`, `lib/compat.h:323`, `lib/compat.h:388`, `lib/compat.h:531`, `lib/compat.h:575`, `lib/compat.h:638`, `lib/compat.h:728`, `lib/compat.c:416`

### Requirement: close macro maps POSIX close to platform socket close
系统 MUST 在平台需要时将 `close` 映射到对应 socket close API，以保持调用方使用 POSIX close 拼写时可编译。

#### Scenario: platform rewrites close call
- **GIVEN** 编译目标为 Winsock、Amiga 或 PS2 IOP 等需要重定向 close 的平台
- **WHEN** 调用方源码写入 `close(socket_or_fd)`
- **THEN** 预处理结果 MUST 调用该平台配置的 `_close`、`closesocket`、`CloseSocket` 或 `lwip_close` 入口

Trace: `lib/compat.h:275`, `lib/compat.h:277`, `lib/compat.h:343`, `lib/compat.h:475`

### Requirement: srandom seeds platform random compatibility
系统 MUST 在缺少 `srandom` 的平台声明 `srandom(unsigned int seed)`，并 SHALL 在实现中把 seed 传递给平台随机数种子函数或 PS2 IOP 本地状态。

#### Scenario: caller seeds compatibility random generator
- **GIVEN** 平台定义 `NEED_SRANDOM`
- **WHEN** 调用 `srandom(seed)`
- **THEN** 兼容实现 MUST 在 PS2 IOP 上保存本地线性同余状态，或在其他平台调用底层 `smb2_srandom(seed)`

Trace: `lib/compat.h:280`, `lib/compat.h:557`, `lib/compat.h:772`, `lib/compat.c:347`

### Requirement: random returns platform random compatibility value
系统 MUST 在缺少 `random` 的平台声明 `random`，并 SHALL 返回平台随机数源或 PS2 IOP 本地线性同余生成值。

#### Scenario: caller obtains compatibility random value
- **GIVEN** 平台定义 `NEED_RANDOM`
- **WHEN** 调用 `random()`
- **THEN** 兼容实现 MUST 在 PS2 IOP 上更新并返回本地状态派生值，或在其他平台返回底层 `smb2_random()` 的值

Trace: `lib/compat.h:281`, `lib/compat.h:466`, `lib/compat.h:558`, `lib/compat.h:773`, `lib/compat.c:331`

### Requirement: getlogin_r provides platform login compatibility
系统 MUST 在缺少 `getlogin_r` 的平台声明 `getlogin_r(char *buf, size_t size)`，并 SHALL 返回平台配置的兼容错误或状态码。

#### Scenario: caller invokes login-name compatibility function
- **GIVEN** 平台定义 `NEED_GETLOGIN_R`
- **WHEN** 调用 `getlogin_r(buf, size)`
- **THEN** 兼容实现 MUST 返回平台宏 `login_num`，且源码未显示其写入 `buf`

Trace: `lib/compat.h:283`, `lib/compat.h:309`, `lib/compat.h:325`, `lib/compat.h:339`, `lib/compat.h:471`, `lib/compat.h:556`, `lib/compat.h:635`, `lib/compat.h:729`, `lib/compat.h:774`, `lib/compat.h:781`, `lib/compat.c:365`

### Requirement: getpid provides process identifier compatibility
系统 MUST 在缺少 `getpid` 的平台声明 `getpid()`，并 SHALL 返回平台配置的兼容进程标识值。

#### Scenario: caller obtains compatibility process id
- **GIVEN** 平台定义 `NEED_GETPID`
- **WHEN** 调用 `getpid()`
- **THEN** 兼容实现 MUST 返回平台宏 `getpid_num()` 的结果

Trace: `lib/compat.h:285`, `lib/compat.h:474`, `lib/compat.c:357`

### Requirement: be64toh provides selected platform endian conversion compatibility
系统 MUST 在 PICO 和 PS2 分支声明 `be64toh(long long int x)`，并在需要实现时 SHALL 通过 32 位网络序转换组合生成 host-order 64 位值。

#### Scenario: caller converts big-endian 64-bit value
- **GIVEN** 平台定义 `NEED_BE64TOH` 且调用方传入 64 位 big-endian 值
- **WHEN** 调用 `be64toh(x)`
- **THEN** 兼容实现 MUST 转换低 32 位和高 32 位并组合为 host-order 64 位结果

Trace: `lib/compat.h:308`, `lib/compat.h:461`, `lib/compat.c:590`

### Requirement: gethostname provides console hostname compatibility
系统 MUST 在 Xbox 或 PS2 平台声明 `gethostname(char *name, size_t len)`，并 SHALL 在兼容实现中写入平台固定主机名后返回 `0`。

#### Scenario: caller reads fixed console hostname
- **GIVEN** 编译目标为 Xbox 或 PS2 且使用兼容 `gethostname`
- **WHEN** 调用 `gethostname(name, len)`
- **THEN** 兼容实现 MUST 将平台固定字符串复制到 `name` 并返回 `0`

Trace: `lib/compat.h:123`, `lib/compat.h:462`, `lib/compat.c:39`, `lib/compat.c:103`

### Requirement: iop_connect maps PS2 IOP connect semantics
系统 MUST 在 PS2 IOP 分支声明 `iop_connect` 并将 `connect` 宏映射到该函数，以便 lwIP connect 失败时可传播 socket 错误。

#### Scenario: PS2 IOP connect failure stores socket error
- **GIVEN** 编译目标定义 `_IOP`，调用方源码使用 `connect(sockfd, addr, addrlen)`
- **WHEN** `iop_connect` 调用 `lwip_connect` 返回失败且 `getsockopt(SO_ERROR)` 提供错误值
- **THEN** 函数 MUST 将 `errno` 设置为该 socket 错误并返回 `lwip_connect` 的返回值

Trace: `lib/compat.h:514`, `lib/compat.h:516`, `lib/compat.c:140`

### Requirement: malloc declares missing PS2 SDK allocation entry
系统 MUST 在 `__ps2sdk_iop__` 分支声明 `malloc(int size)`，使依赖动态分配的兼容代码可编译。

#### Scenario: PS2 SDK lacks malloc declaration
- **GIVEN** 编译目标定义 `__ps2sdk_iop__`
- **WHEN** 源码包含 `lib/compat.h`
- **THEN** 头文件 MUST 暴露 `void *malloc(int size);` 声明

Trace: `lib/compat.h:522`

### Requirement: free declares missing PS2 SDK release entry
系统 MUST 在 `__ps2sdk_iop__` 分支声明 `free(void *ptr)`，使兼容代码可释放动态分配内存。

#### Scenario: PS2 SDK lacks free declaration
- **GIVEN** 编译目标定义 `__ps2sdk_iop__`
- **WHEN** 源码包含 `lib/compat.h`
- **THEN** 头文件 MUST 暴露 `void free(void *ptr);` 声明

Trace: `lib/compat.h:525`

### Requirement: calloc declares missing PS2 SDK zero-allocation entry
系统 MUST 在 `__ps2sdk_iop__` 分支声明 `calloc(size_t nmemb, size_t size)`，使兼容代码可请求清零分配。

#### Scenario: PS2 SDK lacks calloc declaration
- **GIVEN** 编译目标定义 `__ps2sdk_iop__`
- **WHEN** 源码包含 `lib/compat.h`
- **THEN** 头文件 MUST 暴露 `void *calloc(size_t nmemb, size_t size);` 声明

Trace: `lib/compat.h:527`

### Requirement: O_RDONLY supplies missing read-only open flag
系统 MUST 在系统头未定义 `O_RDONLY` 时将其定义为 `00000000`。

#### Scenario: platform lacks O_RDONLY
- **GIVEN** 预处理到 `lib/compat.h` 末尾且 `O_RDONLY` 未定义
- **WHEN** 调用方使用 `O_RDONLY`
- **THEN** 宏值 MUST 展开为 `00000000`

Trace: `lib/compat.h:785`

### Requirement: O_WRONLY supplies missing write-only open flag
系统 MUST 在系统头未定义 `O_WRONLY` 时将其定义为 `00000001`。

#### Scenario: platform lacks O_WRONLY
- **GIVEN** 预处理到 `lib/compat.h` 末尾且 `O_WRONLY` 未定义
- **WHEN** 调用方使用 `O_WRONLY`
- **THEN** 宏值 MUST 展开为 `00000001`

Trace: `lib/compat.h:789`

### Requirement: O_RDWR supplies missing read-write open flag
系统 MUST 在系统头未定义 `O_RDWR` 时将其定义为 `00000002`。

#### Scenario: platform lacks O_RDWR
- **GIVEN** 预处理到 `lib/compat.h` 末尾且 `O_RDWR` 未定义
- **WHEN** 调用方使用 `O_RDWR`
- **THEN** 宏值 MUST 展开为 `00000002`

Trace: `lib/compat.h:793`

### Requirement: O_DSYNC supplies missing synchronized data write flag
系统 MUST 在系统头未定义 `O_DSYNC` 时将其定义为 `040000`。

#### Scenario: platform lacks O_DSYNC
- **GIVEN** 预处理到 `lib/compat.h` 末尾且 `O_DSYNC` 未定义
- **WHEN** 调用方使用 `O_DSYNC`
- **THEN** 宏值 MUST 展开为 `040000`

Trace: `lib/compat.h:797`

### Requirement: O_SYNC supplies missing synchronized write flag
系统 MUST 在系统头未定义 `O_SYNC` 时将其定义为 `(__O_SYNC|O_DSYNC)`，并 SHALL 在 `__O_SYNC` 缺失时先将 `__O_SYNC` 定义为 `020000000`。

#### Scenario: platform lacks O_SYNC
- **GIVEN** 预处理到 `lib/compat.h` 末尾且 `O_SYNC` 未定义
- **WHEN** 调用方使用 `O_SYNC`
- **THEN** 宏值 MUST 展开为 `__O_SYNC` 与 `O_DSYNC` 的按位或表达式

Trace: `lib/compat.h:801`, `lib/compat.h:805`

### Requirement: O_ACCMODE supplies missing access-mode mask
系统 MUST 在系统头未定义 `O_ACCMODE` 时将其定义为 `(O_RDWR|O_WRONLY|O_RDONLY)`。

#### Scenario: platform lacks O_ACCMODE
- **GIVEN** 预处理到 `lib/compat.h` 末尾且 `O_ACCMODE` 未定义
- **WHEN** 调用方使用 `O_ACCMODE` 提取 open 访问模式
- **THEN** 宏值 MUST 展开为 `O_RDWR`、`O_WRONLY` 和 `O_RDONLY` 的按位或表达式

Trace: `lib/compat.h:809`

### Requirement: ENOMEM supplies missing allocation error code
系统 MUST 在系统头未定义 `ENOMEM` 时将其定义为 `12`。

#### Scenario: platform lacks ENOMEM
- **GIVEN** 预处理到 `lib/compat.h` 末尾且 `ENOMEM` 未定义
- **WHEN** 兼容代码或调用方引用 `ENOMEM`
- **THEN** 宏值 MUST 展开为 `12`

Trace: `lib/compat.h:813`

### Requirement: EINVAL supplies missing invalid-argument error code
系统 MUST 在系统头未定义 `EINVAL` 时将其定义为 `22`。

#### Scenario: platform lacks EINVAL
- **GIVEN** 预处理到 `lib/compat.h` 末尾且 `EINVAL` 未定义
- **WHEN** 兼容代码或调用方引用 `EINVAL`
- **THEN** 宏值 MUST 展开为 `22`

Trace: `lib/compat.h:817`, `lib/compat.c:384`, `lib/compat.c:428`

### Requirement: typeof maps to GNU typeof spelling
系统 MUST 在 `typeof` 未定义时将 `typeof` 映射为 `__typeof__`，以保持使用 GNU 类型推导拼写的源码可编译。

#### Scenario: compiler exposes only __typeof__
- **GIVEN** 编译器提供 `__typeof__` 但未预定义 `typeof`
- **WHEN** 调用方源码使用 `typeof(expr)`
- **THEN** 预处理结果 MUST 使用 `__typeof__(expr)` 拼写

Trace: `lib/compat.h:821`

## Open Questions

| ID | Question | Related Interface | Reason |
| --- | --- | --- | --- |
| Q-001 | `smb2_getaddrinfo` 的 `hints` 参数在兼容实现中未被读取，调用方是否依赖 `ai_socktype`、`ai_protocol` 或非 IPv4 解析约束？ | smb2_getaddrinfo | `lib/compat.c` 只分配 IPv4 `sockaddr_in` 并设置 `ai_family`/`ai_addrlen`/`ai_addr`，未使用 `hints`。 |
| Q-002 | `smb2_getaddrinfo` 在部分 malloc/calloc 失败路径未显式检查 NULL，目标平台是否保证分配成功或由外层避免内存压力？ | smb2_getaddrinfo | 源码显示分配后立即写入 `sin` 和 `*res` 字段，未见失败断言或测试证据。 |
| Q-003 | `getlogin_r` 兼容实现不写入 `buf`，调用方是否只检查返回码而不读取缓冲区内容？ | getlogin_r | `lib/compat.c` 返回 `login_num`，未使用 `buf` 或 `size`。 |
| Q-004 | `sockaddr_in6` 被映射为 `sockaddr_in` 的平台是否明确不支持 IPv6，或者只是为了编译通过的临时兼容？ | sockaddr_in6 | 头文件注释写明“just pretend they are the same so we compile”，未提供运行时 IPv6 行为证据。 |
